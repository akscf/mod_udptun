/**
 * Copyright (C) AlexandrinKS
 * https://akscf.me/
 **/
#ifndef MOD_UDPTUN_H
#define MOD_UDPTUN_H

#include <switch.h>
#include <switch_stun.h>
#include <stdint.h>
#include "cipher.h"

#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif

#define VERSION                     "1.1"
#define PACKET_MAGIC                0xABACADAE
#define SALT_SIZE                   8
#define SALT_LIFE_TIME              900 // 15 min
#define SHARED_SECRET_LEN_MAX       32
#define SHARED_SECRET_LEN_MIN       4

#define PACKET_FLAGS_ENCRYPTED      0x1

typedef struct {
    uint8_t                 fl_ready;
    uint8_t                 fl_destroyed;
    uint8_t                 fl_do_destroy;
    uint8_t                 fl_dynamic;
    uint8_t                 fl_send_buf_rdy_wr;
    uint32_t                send_buffer_id;
    uint32_t                send_data_len;
    uint32_t                pkts_out;
    uint32_t                tx_sem;
    uint32_t                port;
    char                    *name;
    char                    *ip;
    switch_memory_pool_t    *pool;
    switch_mutex_t          *mutex;
    switch_byte_t           *send_buffer;
} outbound_tunnel_t;

typedef struct {
    uint32_t                magic;
    uint32_t                id;
    uint16_t                flags;
    uint32_t                payload_len;
    uint8_t                 auth_salt[SALT_SIZE];
    uint8_t                 auth_hash[SWITCH_MD5_DIGEST_STRING_SIZE];
} tunnel_packet_hdr_t;


#endif
