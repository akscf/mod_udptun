/**
 * Copyright (C) AlexandrinKS
 * https://akscf.me/
 **/
#include "mod_udptun.h"

static struct {
    switch_memory_pool_t    *pool;
    switch_mutex_t          *mutex;
    switch_mutex_t          *mutex_tunnels;
    switch_hash_t           *tunnels;
    char                    *shared_secret;
    char                    *pvtint_local_ip;
    char                    *pvtint_remote_ip;
    uint32_t                pvtint_port_in;
    uint32_t                pvtint_port_out;
    char                    *udptun_srv_ip;
    uint32_t                udptun_srv_port;
    uint32_t                buffer_max_size;
    uint32_t                active_threads;
    uint8_t                 fl_passthrough;
    uint8_t                 fl_auth_public_packets;
    uint8_t                 fl_encrypt_public_packets;
    uint8_t                 fl_shutdown;
    uint8_t                 fl_ready;
    switch_queue_t          *pvt_in_q;

} globals;

SWITCH_MODULE_LOAD_FUNCTION(mod_udptun_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_udptun_shutdown);
SWITCH_MODULE_DEFINITION(mod_udptun, mod_udptun_load, mod_udptun_shutdown, NULL);

static void *SWITCH_THREAD_FUNC inbound_tunnel_thread(switch_thread_t *thread, void *obj);
static void *SWITCH_THREAD_FUNC outbound_tunnel_thread(switch_thread_t *thread, void *obj);
static void *SWITCH_THREAD_FUNC pvtint_io_server_thread(switch_thread_t *thread, void *obj);
static void *SWITCH_THREAD_FUNC out_data_buffer_producer_thread(switch_thread_t *thread, void *obj);


// ---------------------------------------------------------------------------------------------------------------------------------------------
// helper functions
// ---------------------------------------------------------------------------------------------------------------------------------------------
static void launch_thread(switch_memory_pool_t *pool, switch_thread_start_t fun, void *data) {
    switch_threadattr_t *attr = NULL;
    switch_thread_t *thread = NULL;

    switch_mutex_lock(globals.mutex);
    globals.active_threads++;
    switch_mutex_unlock(globals.mutex);

    switch_threadattr_create(&attr, pool);
    switch_threadattr_detach_set(attr, 1);
    switch_threadattr_stacksize_set(attr, SWITCH_THREAD_STACKSIZE);
    switch_thread_create(&thread, attr, fun, data, pool);

    return;
}

static outbound_tunnel_t *tunnel_lookup(char *name) {
    outbound_tunnel_t *tunnel = NULL;

    if(!name) { return NULL; }

    switch_mutex_lock(globals.mutex_tunnels);
    tunnel = switch_core_hash_find(globals.tunnels, name);
    switch_mutex_unlock(globals.mutex_tunnels);

    return tunnel;
}

static uint32_t tunnel_sem_take(outbound_tunnel_t *tunnel) {
    uint32_t status = false;

    if(!tunnel) { return false; }

    switch_mutex_lock(tunnel->mutex);
    if(tunnel->fl_ready) {
        status = true;
        tunnel->tx_sem++;
    }
    switch_mutex_unlock(tunnel->mutex);

    return status;
}

static void tunnel_sem_release(outbound_tunnel_t *tunnel) {

    switch_assert(tunnel);

    switch_mutex_lock(tunnel->mutex);
    if(tunnel->tx_sem) {
        tunnel->tx_sem--;
    }
    switch_mutex_unlock(tunnel->mutex);
}

static switch_status_t create_outbound_tunnel(char *name, char *ip, char *port, uint8_t dynamic) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    uint32_t port_i = (port ? atoi(port) : 0);
    switch_memory_pool_t *pool_tmp = NULL;
    outbound_tunnel_t *tunnel = NULL;

    if(zstr(name)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid tunnel name\n");
        switch_goto_status(SWITCH_STATUS_FALSE, out);
    }
    if(zstr(ip)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid tunnel ip\n");
        switch_goto_status(SWITCH_STATUS_FALSE, out);
    }
    if(port_i <= 0 || port_i >= 0xffff) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid tunnel port\n");
        switch_goto_status(SWITCH_STATUS_FALSE, out);
    }

    switch_mutex_lock(globals.mutex_tunnels);
    if(switch_core_hash_find(globals.tunnels, name)) {
        switch_mutex_unlock(globals.mutex_tunnels);
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Tunnel '%s' already exists\n", name);
        switch_goto_status(SWITCH_STATUS_FALSE, out);
    }
    switch_mutex_unlock(globals.mutex_tunnels);

    if(switch_core_new_memory_pool(&pool_tmp) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", name);
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }
    if((tunnel = switch_core_alloc(pool_tmp, sizeof(outbound_tunnel_t))) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", name);
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }
    if((status = switch_mutex_init(&tunnel->mutex, SWITCH_MUTEX_NESTED, pool_tmp)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", name);
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }

    switch_queue_create(&tunnel->out_q, TUNNEL_QUEUE_SIZE, pool_tmp);

    tunnel->pool = pool_tmp;
    tunnel->name = switch_core_strdup(pool_tmp, name);
    tunnel->ip = switch_core_strdup(pool_tmp, ip);
    tunnel->port = port_i;
    tunnel->fl_dynamic = dynamic;

    switch_mutex_lock(globals.mutex_tunnels);
    switch_core_hash_insert(globals.tunnels, tunnel->name, tunnel);
    switch_mutex_unlock(globals.mutex_tunnels);

    launch_thread(tunnel->pool, outbound_tunnel_thread, tunnel);
out:
    if(status != SWITCH_STATUS_SUCCESS) {
        if(pool_tmp) {
            switch_core_destroy_memory_pool(&pool_tmp);
        }
    }
    return status;
}

static switch_status_t data_buffer_alloc(data_buffer_t **out, switch_byte_t *data, uint32_t data_len) {
    data_buffer_t *buf = NULL;

    switch_zmalloc(buf, sizeof(data_buffer_t));

    if(data_len) {
        switch_malloc(buf->data, data_len);
        buf->data_len = data_len;
        memcpy(buf->data, data, data_len);
    }

    *out = buf;
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t data_buffer_clone(data_buffer_t **dst, data_buffer_t *src) {
    data_buffer_t *buf = NULL;

    switch_assert(src);

    switch_zmalloc(buf, sizeof(data_buffer_t));

    buf->data_len = src->data_len;
    if(src->data_len) {
        switch_malloc(buf->data, src->data_len);
        memcpy(buf->data, src->data, src->data_len);
    }

    *dst = buf;
    return SWITCH_STATUS_SUCCESS;
}

static void data_buffer_free(data_buffer_t *buf) {
    if(buf) {
        switch_safe_free(buf->data);
        switch_safe_free(buf);
    }
}

static void flush_data_buffer_queue(switch_queue_t *queue) {
    void *data = NULL;

    if(!queue || !switch_queue_size(queue)) {
        return;
    }
    while(switch_queue_trypop(queue, &data) == SWITCH_STATUS_SUCCESS) {
        if(data) {
            data_buffer_free((data_buffer_t *)data);
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
static void *SWITCH_THREAD_FUNC inbound_tunnel_thread(switch_thread_t *thread, void *obj) {
    const uint32_t auth_buffer_len = (strlen(globals.shared_secret) + SALT_SIZE);
    const uint32_t recv_buffer_size = globals.buffer_max_size;
    switch_memory_pool_t *pool = globals.pool;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_byte_t *auth_buffer = NULL;
    switch_byte_t *recv_buffer = NULL;
    switch_pollfd_t *pollfd = NULL;
    switch_socket_t *server_socket = NULL, *client_socket = NULL;
    switch_sockaddr_t *saddr = NULL, *caddr = NULL, *to_addr = NULL, *from_addr = NULL;
    switch_byte_t *payload_ptr = NULL;
    tunnel_packet_hdr_t *phdr_ptr = NULL;
    cipher_ctx_t *cipher_ctx = NULL;
    char md5_hash[SWITCH_MD5_DIGEST_STRING_SIZE] = { 0 };
    switch_size_t bytes = 0;
    int fdr = 0;
    char ipbuf[48] = { 0 };
    const char *remote_ip_addr;

    if((recv_buffer = switch_core_alloc(pool, recv_buffer_size)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }

    if(globals.fl_auth_public_packets) {
        if((auth_buffer = switch_core_alloc(pool, auth_buffer_len)) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }
        memset((void *)auth_buffer, 0, SALT_SIZE);
        memcpy((void *)(auth_buffer + SALT_SIZE), globals.shared_secret, strlen(globals.shared_secret));
    }

    if(globals.fl_encrypt_public_packets) {
        if((cipher_ctx = switch_core_alloc(pool, sizeof(cipher_ctx_t))) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }
        cipher_init(cipher_ctx, globals.shared_secret, strlen(globals.shared_secret));
    }

    /* xconf client socket */
    if((status = switch_sockaddr_info_get(&caddr, globals.pvtint_local_ip, SWITCH_UNSPEC, 0, 0, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "pvtint_client: socket fail (switch_sockaddr_info_get) [#1]\n");
        goto out;
    }
    if((status = switch_sockaddr_info_get(&to_addr, globals.pvtint_remote_ip, SWITCH_UNSPEC, globals.pvtint_port_out, 0, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "pvtint_client: socket fail (switch_sockaddr_info_get) [#2]\n");
        goto out;
    }
    if((status = switch_socket_create(&client_socket, switch_sockaddr_get_family(caddr), SOCK_DGRAM, 0, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "pvtint_client: socket fail (switch_socket_create)\n");
        goto out;
    }
    if((status = switch_socket_bind(client_socket, caddr)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "pvtint_client: socket fail (switch_socket_bind)\n");
        goto out;
    }

    /* serevr socket */
    if((status = switch_sockaddr_info_get(&saddr, globals.udptun_srv_ip, SWITCH_UNSPEC, globals.udptun_srv_port, 0, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "udptun_srv: socket fail (switch_sockaddr_info_get) [#1]\n");
        goto out;
    }
    if((status = switch_socket_create(&server_socket, switch_sockaddr_get_family(saddr), SOCK_DGRAM, 0, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "udptun_srv: socket fail (switch_socket_create)\n");
        goto out;
    }
    if((status = switch_socket_opt_set(server_socket, SWITCH_SO_REUSEADDR, true)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "udptun_srv: socket fail (opt: SWITCH_SO_REUSEADDR)\n");
        goto out;
    }
    if((status = switch_socket_bind(server_socket, saddr)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "udptun_srv: socket fail (switch_socket_bind)\n");
        goto out;
    }
    if((status = switch_socket_create_pollset(&pollfd, server_socket, SWITCH_POLLIN | SWITCH_POLLERR, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "udptun_srv: socket fail (switch_socket_create_pollset)\n");
        goto out;
    }
    if((status = switch_socket_opt_set(server_socket, SWITCH_SO_NONBLOCK, true)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "udptun_srv: socket fail (opt: SWITCH_SO_NONBLOCK)\n");
        goto out;
    }

    switch_sockaddr_info_get(&from_addr, NULL, SWITCH_UNSPEC, 0, 0, pool);

    while(true) {
        if(globals.fl_shutdown) {
            break;
        }

        bytes = recv_buffer_size;
        if(switch_socket_recvfrom(from_addr, server_socket, 0, (void *)recv_buffer, &bytes) == SWITCH_STATUS_SUCCESS && bytes > sizeof(tunnel_packet_hdr_t)) {
            remote_ip_addr = switch_get_addr(ipbuf, sizeof(ipbuf), from_addr);

            if(!globals.fl_passthrough) {
                phdr_ptr = (void *)(recv_buffer);
                payload_ptr = (void *)(recv_buffer + sizeof(*phdr_ptr));

                if(phdr_ptr->magic != PACKET_MAGIC) {
                    goto sleep;
                }
                if(!phdr_ptr->payload_len || phdr_ptr->payload_len > recv_buffer_size) {
                    goto sleep;
                }

                if(globals.fl_auth_public_packets) {
                    memcpy(auth_buffer, (char *)phdr_ptr->auth_salt, SALT_SIZE);
                    switch_md5_string((char *)md5_hash, auth_buffer, auth_buffer_len);

                    if(strncmp((char *)md5_hash, (char *)phdr_ptr->auth_hash, sizeof(md5_hash)) !=0) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unauthorized packet (ip: %s)\n", remote_ip_addr);
                        goto sleep;
                    }
                }

                if((phdr_ptr->flags & PACKET_FLAGS_ENCRYPTED)) {
                    if(globals.fl_encrypt_public_packets) {
                        uint32_t psz = phdr_ptr->payload_len;
                        uint32_t pad = (psz % sizeof(int));

                        if(pad) { psz += sizeof(int) - pad; }
                        if(psz > recv_buffer_size) { psz = phdr_ptr->payload_len; }

                        cipher_decrypt(cipher_ctx, phdr_ptr->id, payload_ptr, psz);
                    } else {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Encrypted packet from '%s' was ignored! (encryption disabled)\n", remote_ip_addr);
                    }
                }

                bytes = phdr_ptr->payload_len;
                switch_socket_sendto(client_socket, to_addr, 0, (void *)payload_ptr, &bytes);
            } else {
                switch_socket_sendto(client_socket, to_addr, 0, (void *)recv_buffer, &bytes);
            }
        }
sleep:
        if(pollfd) {
            switch_poll(pollfd, 1, &fdr, 10000);
        } else {
            switch_yield(5000);
        }
    }

out:
    if(status != SWITCH_STATUS_SUCCESS) {
        globals.fl_shutdown = true;
    }
    if (server_socket) {
        switch_socket_close(server_socket);
    }
    if (client_socket) {
        switch_socket_close(client_socket);
    }

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    return NULL;
}

static void *SWITCH_THREAD_FUNC outbound_tunnel_thread(switch_thread_t *thread, void *obj) {
    volatile outbound_tunnel_t *_ref = (outbound_tunnel_t *) obj;
    outbound_tunnel_t *tunnel = (outbound_tunnel_t *) _ref;
    const uint32_t send_buffer_size = globals.buffer_max_size;
    switch_memory_pool_t *pool = tunnel->pool;
    switch_socket_t *socket = NULL;
    switch_sockaddr_t *loaddr = NULL, *to_addr = NULL;
    switch_status_t status;
    switch_size_t bytes = 0;
    void *pop = NULL;

    if((status = switch_sockaddr_info_get(&loaddr, globals.udptun_srv_ip, SWITCH_UNSPEC, 0, 0, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "outbound_tunnel: socket fail (switch_sockaddr_info_get) [#1]\n");
        goto out;
    }
    if((status = switch_sockaddr_info_get(&to_addr, tunnel->ip, SWITCH_UNSPEC, tunnel->port, 0, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "outbound_tunnel: socket fail (switch_sockaddr_info_get) [#2]\n");
        goto out;
    }
    if((status = switch_socket_create(&socket, switch_sockaddr_get_family(loaddr), SOCK_DGRAM, 0, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "outbound_tunnel: socket fail (switch_socket_create)\n");
        goto out;
    }
    if((status = switch_socket_bind(socket, loaddr)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "outbound_tunnel: socket fail (switch_socket_bind)\n");
        goto out;
    }

    tunnel->fl_ready = true;

    while(true) {
        if(globals.fl_shutdown || tunnel->fl_do_destroy) {
            break;
        }
        if(!globals.fl_ready) {
            switch_yield(100000);
            continue;
        }

        while(switch_queue_trypop(tunnel->out_q, &pop) == SWITCH_STATUS_SUCCESS) {
            data_buffer_t *ldtb = (data_buffer_t *)pop;

            if(ldtb && ldtb->data_len) {
                bytes = ldtb->data_len;
                switch_socket_sendto(socket, to_addr, 0, (void *)ldtb->data, &bytes);
                tunnel->pkts_out++;
            }

            data_buffer_free(ldtb);
        }

        switch_yield(5000);
    }
out:
    tunnel->fl_ready = false;
    tunnel->fl_destroyed = true;

    while(tunnel->tx_sem > 0) {
        switch_yield(100000);
    }

    if (socket) {
        switch_socket_close(socket);
    }

    switch_mutex_lock(globals.mutex_tunnels);
    switch_core_hash_delete(globals.tunnels, tunnel->name);
    switch_mutex_unlock(globals.mutex_tunnels);

    flush_data_buffer_queue(tunnel->out_q);
    switch_queue_term(tunnel->out_q);

    switch_mutex_destroy(tunnel->mutex);
    switch_core_destroy_memory_pool(&tunnel->pool);

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    return NULL;
}

static void *SWITCH_THREAD_FUNC pvtint_io_server_thread(switch_thread_t *thread, void *obj) {
    const uint32_t auth_buffer_len = (strlen(globals.shared_secret) + SALT_SIZE);
    const uint32_t recv_buffer_size = globals.buffer_max_size;
    const uint32_t send_buffer_size = globals.buffer_max_size;
    switch_memory_pool_t *pool = globals.pool;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_byte_t *recv_buffer = NULL;
    switch_byte_t *send_buffer = NULL;
    switch_byte_t *auth_buffer = NULL;
    switch_pollfd_t *pollfd = NULL;
    switch_socket_t *socket = NULL;
    switch_sockaddr_t *loaddr = NULL, *from_addr = NULL;
    tunnel_packet_hdr_t *phdr_ptr = NULL;
    switch_byte_t *payload_ptr = NULL;
    cipher_ctx_t *cipher_ctx = NULL;
    uint32_t send_len, packet_id = 0;
    switch_size_t bytes = 0;
    time_t salt_renew_time = 0;
    const char *remote_ip_addr;
    int fdr = 0;
    char ipbuf[48] = { 0 };

    if((recv_buffer = switch_core_alloc(pool, recv_buffer_size)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }
    if((send_buffer = switch_core_alloc(pool, send_buffer_size)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }

    if(globals.fl_auth_public_packets) {
        if((auth_buffer = switch_core_alloc(pool, auth_buffer_len)) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }
        switch_stun_random_string((char *)auth_buffer, SALT_SIZE, NULL);
        memcpy((void *)(auth_buffer + SALT_SIZE), globals.shared_secret, strlen(globals.shared_secret));
    }

    if(globals.fl_encrypt_public_packets) {
        if((cipher_ctx = switch_core_alloc(pool, sizeof(cipher_ctx_t))) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }
        cipher_init(cipher_ctx, globals.shared_secret, strlen(globals.shared_secret));
    }

    if((status = switch_sockaddr_info_get(&loaddr, globals.pvtint_local_ip, SWITCH_UNSPEC, globals.pvtint_port_in, 0, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "pvtint_io_srv: socket fail (switch_sockaddr_info_get) [#1]\n");
        goto out;
    }
    if((status = switch_socket_create(&socket, switch_sockaddr_get_family(loaddr), SOCK_DGRAM, 0, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "pvtint_io_srv: socket fail (switch_socket_create)\n");
        goto out;
    }
    if((status = switch_socket_opt_set(socket, SWITCH_SO_REUSEADDR, true)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "pvtint_io_srv: socket fail (opt: SWITCH_SO_REUSEADDR)\n");
        goto out;
    }
    if((status = switch_socket_bind(socket, loaddr)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "pvtint_io_srv: socket fail (switch_socket_bind)\n");
        goto out;
    }
    if((status = switch_socket_create_pollset(&pollfd, socket, SWITCH_POLLIN | SWITCH_POLLERR, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "pvtint_io_srv: socket fail (switch_socket_create_pollset)\n");
        goto out;
    }
    if((status = switch_socket_opt_set(socket, SWITCH_SO_NONBLOCK, true)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "pvtint_io_srv: socket fail (opt: SWITCH_SO_NONBLOCK)\n");
        goto out;
    }

    switch_sockaddr_info_get(&from_addr, NULL, SWITCH_UNSPEC, 0, 0, pool);

    while(true) {
        if(globals.fl_shutdown) {
            break;
        }

        if(globals.fl_auth_public_packets && !globals.fl_passthrough) {
            if(!salt_renew_time || salt_renew_time < switch_epoch_time_now(NULL)) {
                switch_stun_random_string((char *)auth_buffer, SALT_SIZE, NULL);
                salt_renew_time = (switch_epoch_time_now(NULL) + SALT_LIFE_TIME);
            }
        }

        bytes = recv_buffer_size;
        if(switch_socket_recvfrom(from_addr, socket, 0, (void *)recv_buffer, &bytes) == SWITCH_STATUS_SUCCESS && bytes > 0) {
            remote_ip_addr = switch_get_addr(ipbuf, sizeof(ipbuf), from_addr);
            send_len = 0;

            if(!globals.fl_passthrough) {
                send_len = (bytes + sizeof(tunnel_packet_hdr_t));

                if(send_len <= send_buffer_size) {
                    memset((void *)send_buffer, 0, send_len);

                    phdr_ptr = (void *)(send_buffer);
                    payload_ptr = (void *)(send_buffer + sizeof(*phdr_ptr));

                    phdr_ptr->magic = PACKET_MAGIC;
                    phdr_ptr->id = packet_id++;
                    phdr_ptr->flags = 0x0;
                    phdr_ptr->payload_len = bytes;

                    memcpy(payload_ptr, recv_buffer, bytes);

                    if(globals.fl_auth_public_packets) {
                        switch_md5_string((char *)phdr_ptr->auth_hash, auth_buffer, auth_buffer_len);
                        memcpy(phdr_ptr->auth_salt, auth_buffer, SALT_SIZE);
                    }

                    if(globals.fl_encrypt_public_packets) {
                        uint32_t psz = phdr_ptr->payload_len;
                        uint32_t pad = (psz % sizeof(int));

                        if(pad) { psz += sizeof(int) - pad; }
                        if(psz > send_buffer_size) { psz = phdr_ptr->payload_len; }

                        cipher_encrypt(cipher_ctx, phdr_ptr->id, payload_ptr, psz);
                        phdr_ptr->flags |= PACKET_FLAGS_ENCRYPTED;
                    }
                } else {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "packet is too long: %i  (max: %i, ip: %s)\n", send_len, send_buffer_size, remote_ip_addr);
                    send_len = 0;
                }
            } else {
                send_len = bytes;
                memcpy(send_buffer, recv_buffer, send_len);
            }
            if(send_len) {
                data_buffer_t *ldtb = NULL;

                data_buffer_alloc(&ldtb, send_buffer, send_len);
                if(switch_queue_trypush(globals.pvt_in_q, ldtb) != SWITCH_STATUS_SUCCESS) {
                    data_buffer_free(ldtb);
                }
            }
        }
        if(pollfd) {
            switch_poll(pollfd, 1, &fdr, 10000);
        } else {
            switch_yield(5000);
        }
    }

out:
    if(status != SWITCH_STATUS_SUCCESS) {
        globals.fl_shutdown = true;
    }
    if (socket) {
        switch_socket_close(socket);
    }

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    return NULL;
}

static void *SWITCH_THREAD_FUNC out_data_buffer_producer_thread(switch_thread_t *thread, void *obj) {
    switch_hash_index_t *hidx = NULL;
    void *pop = NULL;

    while(true) {
        if(globals.fl_shutdown) {
            break;
        }

        while(switch_queue_trypop(globals.pvt_in_q, &pop) == SWITCH_STATUS_SUCCESS) {
            data_buffer_t *dtb = (data_buffer_t *)pop;
            if(dtb && dtb->data_len) {

                switch_mutex_lock(globals.mutex_tunnels);
                for(hidx = switch_core_hash_first_iter(globals.tunnels, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
                    outbound_tunnel_t *tunnel = NULL;
                    const void *hkey = NULL; void *hval = NULL;

                    switch_core_hash_this(hidx, &hkey, NULL, &hval);
                    tunnel = (outbound_tunnel_t *)hval;

                    if(tunnel && tunnel->fl_ready) {
                        if(tunnel_sem_take(tunnel)) {
                            data_buffer_t *ldtb = NULL;

                            data_buffer_clone(&ldtb, dtb);
                            if(switch_queue_trypush(tunnel->out_q, ldtb) != SWITCH_STATUS_SUCCESS) {
                                data_buffer_free(ldtb);
                            }
                            tunnel_sem_release(tunnel);
                        }
                    }
                }
                switch_mutex_unlock(globals.mutex_tunnels);
            }
            data_buffer_free(dtb);
        }

        switch_yield(5000);
    }

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    return NULL;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
//
// ---------------------------------------------------------------------------------------------------------------------------------------------
static void event_handler_shutdown(switch_event_t *event) {
    if(!globals.fl_shutdown) {
        globals.fl_shutdown = 1;
    }
}

#define CMD_SYNTAX "conf - show config\nlist - show tunnels\n<name> add ip port - add a new tunnels\n<name> del - terminate tunnels\n"
SWITCH_STANDARD_API(udptun_cmd_function) {
   char *mycmd = NULL, *argv[10] = { 0 };
    int argc = 0;

    if (!zstr(cmd)) {
        mycmd = strdup(cmd);
        switch_assert(mycmd);
        argc = switch_separate_string(mycmd, ' ', argv, (sizeof(argv) / sizeof(argv[0])));
    }
    if(argc == 0) {
        goto usage;
    }
    if(argc == 1) {
        if(strcasecmp(argv[0], "conf") == 0) {
            stream->write_function(stream, "passthrough mode......: %s\n", globals.fl_passthrough ? "on" : "off");
            stream->write_function(stream, "outbound tunnel.......: %s:%i ==> {*}\n", globals.pvtint_local_ip, globals.pvtint_port_in);
            stream->write_function(stream, "inbound tunnel........: %s:%i ==> %s:%i\n", globals.udptun_srv_ip, globals.udptun_srv_port, globals.pvtint_remote_ip, globals.pvtint_port_out);
            stream->write_function(stream, "encryption............: %s\n", globals.fl_encrypt_public_packets ? "on" : "off");
            goto out;
        }
        if(strcasecmp(argv[0], "list") == 0) {
            switch_hash_index_t *hidx = NULL;
            uint32_t total = 0;

            stream->write_function(stream, "tunnels: \n");

            switch_mutex_lock(globals.mutex_tunnels);
            for (hidx = switch_core_hash_first_iter(globals.tunnels, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
                outbound_tunnel_t *tunnel = NULL;
                const void *hkey = NULL; void *hval = NULL;

                switch_core_hash_this(hidx, &hkey, NULL, &hval);
                tunnel = (outbound_tunnel_t *)hval;

                if(tunnel_sem_take(tunnel)) {
                    stream->write_function(stream, "%s [%s:%i] (type: %s, pkts-out: %i)\n", tunnel->name, tunnel->ip, tunnel->port, (tunnel->fl_dynamic ? "dynamic" : "static"), tunnel->pkts_out);
                    tunnel_sem_release(tunnel);
                    total++;
                }
            }
            switch_mutex_unlock(globals.mutex_tunnels);

            stream->write_function(stream, "total: %i\n", total);
            goto out;
        }
        goto usage;
    }
    /* tunnel commands */
    char *tunnel_name = (argc >= 1 ? argv[0] : NULL);
    char *tunnel_cmd =  (argc >= 2 ? argv[1] : NULL);

    if(!tunnel_name || !tunnel_cmd) {
        goto usage;
    }

    if(strcasecmp(tunnel_cmd, "add") == 0) {
        char *ip = (argc >= 3 ? argv[2] : NULL);
        char *port = (argc >= 4 ? argv[3] : NULL);

        if(create_outbound_tunnel(tunnel_name, ip, port, true) != SWITCH_STATUS_SUCCESS){
            stream->write_function(stream, "-ERR: couldn't create tunnel\n");
        } else {
            stream->write_function(stream, "+OK\n");
        }
        goto out;
    }

    if(strcasecmp(tunnel_cmd, "del") == 0) {
        outbound_tunnel_t *tunnel = tunnel_lookup(tunnel_name);
        if(tunnel_sem_take(tunnel)) {
            if(tunnel->fl_ready) {
                tunnel->fl_do_destroy = true;
            }
            tunnel_sem_release(tunnel);
            stream->write_function(stream, "+OK\n");
        } else {
            stream->write_function(stream, "-ERR: unknown tunnel '%s'\n", tunnel_name);
        }
        goto out;
    }

usage:
    stream->write_function(stream, "-USAGE:\n%s\n", CMD_SYNTAX);

out:
    switch_safe_free(mycmd);
    return SWITCH_STATUS_SUCCESS;
}


// ---------------------------------------------------------------------------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------------------------------------------------------------------------
#define CONFIG_NAME "udptun.conf"
SWITCH_MODULE_LOAD_FUNCTION(mod_udptun_load) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_xml_t cfg, xml, settings, param, xmltunnels, xmltunnel;
    switch_api_interface_t *commands_interface;

    memset(&globals, 0, sizeof (globals));
    switch_mutex_init(&globals.mutex, SWITCH_MUTEX_NESTED, pool);
    switch_mutex_init(&globals.mutex_tunnels, SWITCH_MUTEX_NESTED, pool);
    switch_core_hash_init(&globals.tunnels);

    switch_queue_create(&globals.pvt_in_q, IN_QUEUE_SIZE, pool);

    globals.pool = pool;
    globals.fl_shutdown = false;
    globals.fl_passthrough = false;
    globals.fl_auth_public_packets = false;
    globals.fl_encrypt_public_packets = false;
    globals.buffer_max_size = 4096;
    globals.pvtint_port_in = 65020;
    globals.pvtint_port_out = 65021;
    globals.udptun_srv_port = 65022;

    if((xml = switch_xml_open_cfg(CONFIG_NAME, &cfg, NULL)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't open: %s\n", CONFIG_NAME);
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }

    if((settings = switch_xml_child(cfg, "settings"))) {
        for (param = switch_xml_child(settings, "param"); param; param = param->next) {
            char *var = (char *) switch_xml_attr_soft(param, "name");
            char *val = (char *) switch_xml_attr_soft(param, "value");

            if(!strcasecmp(var, "auth-public-packets")) {
                globals.fl_auth_public_packets = (strcasecmp(val, "true") == 0 ? true : false);
            } else if(!strcasecmp(var, "encrypt-public-packets")) {
                globals.fl_encrypt_public_packets = (strcasecmp(val, "true") == 0 ? true : false);
            } else if(!strcasecmp(var, "passthrough_mode")) {
                globals.fl_passthrough = (strcasecmp(val, "true") == 0 ? true : false);
            } else if(!strcasecmp(var, "shared-secret")) {
                globals.shared_secret = switch_core_strdup(pool, val);
            } else if(!strcasecmp(var, "buffer-max-size")) {
                globals.buffer_max_size = atoi(val);
            } else if(!strcasecmp(var, "pvtint-local-ip")) {
                globals.pvtint_local_ip = switch_core_strdup(pool, val);
            } else if(!strcasecmp(var, "pvtint-remote-ip")) {
                globals.pvtint_remote_ip = switch_core_strdup(pool, val);
            } else if(!strcasecmp(var, "pvtint-port-in")) {
                globals.pvtint_port_in = atoi(val);
            } else if(!strcasecmp(var, "pvtint-port-out")) {
                globals.pvtint_port_out = atoi(val);
            } else if(!strcasecmp(var, "pubint-ip")) {
                globals.udptun_srv_ip = switch_core_strdup(pool, val);
            } else if(!strcasecmp(var, "pubint-port")) {
                globals.udptun_srv_port = atoi(val);
            }
        }
    }

    if(!globals.shared_secret || strlen(globals.shared_secret) < SHARED_SECRET_LEN_MIN || strlen(globals.shared_secret) > SHARED_SECRET_LEN_MAX) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid parameter: shared-secret\n");
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }
    if(!globals.pvtint_local_ip || !strlen(globals.pvtint_local_ip)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid parameter: pvtint-local-ip\n");
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }
    if(!globals.pvtint_remote_ip || !strlen(globals.pvtint_remote_ip)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid parameter: pvtint-remote-ip\n");
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }
    if(globals.pvtint_port_in <= 0 || globals.pvtint_port_in > 0xffff) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid parameter: pvtint-port-in\n");
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }
    if(globals.pvtint_port_out <= 0 || globals.pvtint_port_out > 0xffff) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid parameter: pvtint-port-out\n");
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }

    if(!globals.udptun_srv_ip || !strlen(globals.udptun_srv_ip)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid parameter: udptun-ip\n");
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }
    if(globals.udptun_srv_port <= 0 || globals.udptun_srv_port > 0xffff) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid parameter: udptun-port\n");
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }

    if((xmltunnels = switch_xml_child(cfg, "tunnels"))) {
        for (xmltunnel = switch_xml_child(xmltunnels, "tunnel"); xmltunnel; xmltunnel = xmltunnel->next) {
            char *name = (char *) switch_xml_attr_soft(xmltunnel, "name");
            char *port = (char *) switch_xml_attr_soft(xmltunnel, "port");
            char *ip = (char *) switch_xml_attr_soft(xmltunnel, "ip");

            if((status = create_outbound_tunnel(name, ip, port, false)) != SWITCH_STATUS_SUCCESS){
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't create outbound tunnel: %s\n", name);
                break;
            }
        }
    }
    if(status != SWITCH_STATUS_SUCCESS) {
        switch_goto_status(SWITCH_STATUS_FALSE, done);
    }

    *module_interface = switch_loadable_module_create_module_interface(pool, modname);
    SWITCH_ADD_API(commands_interface, "udptun", "cloning and tunneling udp traffic", udptun_cmd_function, CMD_SYNTAX);

    if(switch_event_bind(modname, SWITCH_EVENT_SHUTDOWN, SWITCH_EVENT_SUBCLASS_ANY, event_handler_shutdown, NULL) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't bind event handler!\n");
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }

    launch_thread(pool, out_data_buffer_producer_thread, NULL);
    launch_thread(pool, inbound_tunnel_thread, NULL);
    launch_thread(pool, pvtint_io_server_thread, NULL);

    globals.fl_ready = true;

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "udp-tun-%s ready\n", VERSION);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "passthrough mode.......: %s\n", (globals.fl_passthrough ? "on" : "off"));
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "outbound tunnels.......: %s:%i ==> {*}\n", globals.pvtint_local_ip, globals.pvtint_port_in);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "inbound tunnels........: %s:%i ==> %s:%i\n", globals.udptun_srv_ip, globals.udptun_srv_port, globals.pvtint_remote_ip, globals.pvtint_port_out);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "encryption.............: %s\n", globals.fl_encrypt_public_packets ? "on" : "off");

done:
    if(xml) {
        switch_xml_free(xml);
    }
    if(status != SWITCH_STATUS_SUCCESS) {
        globals.fl_shutdown = true;
        while(globals.active_threads > 0) {
            switch_yield(100000);
        }
        if(globals.tunnels) {
            switch_core_hash_destroy(&globals.tunnels);
        }
    }
    return status;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_udptun_shutdown) {
    switch_hash_index_t *hi = NULL;
    outbound_tunnel_t *tunnel = NULL;
    void *hval = NULL;

    switch_event_unbind_callback(event_handler_shutdown);

    globals.fl_shutdown = true;
    while(globals.active_threads > 0) {
        switch_yield(100000);
    }

    flush_data_buffer_queue(globals.pvt_in_q);
    switch_queue_term(globals.pvt_in_q);

    switch_mutex_lock(globals.mutex_tunnels);
    for(hi = switch_core_hash_first_iter(globals.tunnels, hi); hi; hi = switch_core_hash_next(&hi)) {
        switch_core_hash_this(hi, NULL, NULL, &hval);
        tunnel = (outbound_tunnel_t *) hval;
        if(tunnel_sem_take(tunnel)) {
            tunnel->fl_do_destroy = true;
            tunnel_sem_release(tunnel);
        }
    }
    switch_safe_free(hi);
    switch_core_hash_destroy(&globals.tunnels);
    switch_mutex_unlock(globals.mutex_tunnels);

    return SWITCH_STATUS_SUCCESS;
}

