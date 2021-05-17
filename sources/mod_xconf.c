/**
 * Copyright (C) AlexandrinKS
 * https://akscf.me/
 **/
#include "mod_xconf.h"

globals_t globals;

SWITCH_MODULE_LOAD_FUNCTION(mod_xconf_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_xconf_shutdown);
SWITCH_MODULE_DEFINITION(mod_xconf, mod_xconf_load, mod_xconf_shutdown, NULL);

static void *SWITCH_THREAD_FUNC conference_audio_capture_thread(switch_thread_t *thread, void *obj);
static void *SWITCH_THREAD_FUNC conference_audio_produce_thread(switch_thread_t *thread, void *obj);
static void *SWITCH_THREAD_FUNC conference_group_listeners_control_thread(switch_thread_t *thread, void *obj);
static void *SWITCH_THREAD_FUNC conference_control_thread(switch_thread_t *thread, void *obj);
static void *SWITCH_THREAD_FUNC dm_client_thread(switch_thread_t *thread, void *obj);
static void *SWITCH_THREAD_FUNC dm_server_thread(switch_thread_t *thread, void *obj);

//---------------------------------------------------------------------------------------------------------------------------------------------------
static inline void mix_i16(int16_t *dst, int16_t *src, uint32_t len) {
    uint32_t i = 0;
    for(i = 0; i < len; i++) {
        dst[i] += src[i];
    }
}

static switch_status_t listener_join_to_group(member_group_t **group, conference_t *conference, member_t *member) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_hash_index_t *hidx = NULL;
    switch_memory_pool_t *pool_tmp = NULL;
    member_group_t *tmp_group = NULL;
    uint8_t fl_found = false;

    switch_assert(conference);
    switch_assert(member);

    if(!conference_sem_take(conference)) {
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }

    switch_mutex_lock(conference->mutex_listeners);
    for (hidx = switch_core_hash_first_iter(conference->listeners, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
        const void *hkey = NULL; void *hval = NULL;

        switch_core_hash_this(hidx, &hkey, NULL, &hval);
        tmp_group = (member_group_t *) hval;

        if(group_sem_take(tmp_group)) {
            if(tmp_group->fl_ready) {
                switch_mutex_lock(tmp_group->mutex);
                if(tmp_group->free > 0) {
                    tmp_group->free--;

                    switch_mutex_lock(tmp_group->mutex_members);
                    switch_core_inthash_insert(tmp_group->members, member->id, member);
                    switch_mutex_unlock(tmp_group->mutex_members);

                    member->group = tmp_group;
                    *group = tmp_group;
                    fl_found = true;
                }
                switch_mutex_unlock(tmp_group->mutex);
            }
            group_sem_release(tmp_group);
        }

        if(fl_found || globals.fl_shutdown || !conference->fl_ready) {
            break;
        }
    }
    switch_mutex_unlock(conference->mutex_listeners);

    if(globals.fl_shutdown || !conference->fl_ready) {
        goto out;
    }

    if(!fl_found) {
        if(switch_core_new_memory_pool(&pool_tmp) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference->name);
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }
        if((tmp_group = switch_core_alloc(pool_tmp, sizeof(member_group_t))) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference->name);
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }

        switch_mutex_init(&tmp_group->mutex, SWITCH_MUTEX_NESTED, pool_tmp);
        switch_mutex_init(&tmp_group->mutex_members, SWITCH_MUTEX_NESTED, pool_tmp);
        switch_queue_create(&tmp_group->audio_q, globals.local_queue_size, pool_tmp);
        switch_core_inthash_init(&tmp_group->members);

        tmp_group->id = conference_assign_group_id(conference);
        tmp_group->pool = pool_tmp;
        tmp_group->conference = conference;
        tmp_group->capacity = globals.listener_group_capacity;
        tmp_group->free = tmp_group->capacity;

        tmp_group->free--;
        switch_core_inthash_insert(tmp_group->members, member->id, member);

        member->group = tmp_group;
        *group = tmp_group;
        fl_found = true;

        launch_thread(pool_tmp, conference_group_listeners_control_thread, tmp_group);

        switch_mutex_lock(conference->mutex_listeners);
        switch_core_inthash_insert(conference->listeners, tmp_group->id, tmp_group);
        switch_mutex_unlock(conference->mutex_listeners);
    }
out:
    if(status != SWITCH_STATUS_SUCCESS) {
        if(pool_tmp) {
            switch_core_destroy_memory_pool(&pool_tmp);
        }
    }

    conference_sem_release(conference);

    return status;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
static void *SWITCH_THREAD_FUNC conference_audio_capture_thread(switch_thread_t *thread, void *obj) {
    volatile conference_t *_ref = (conference_t *) obj;
    conference_t *conference = (conference_t *) _ref;
    switch_status_t status;
    switch_byte_t *spk_buffer = NULL, *out_buffer = NULL, *mix_buffer = NULL, *net_buffer = NULL;
    switch_hash_index_t *hidx = NULL;
    switch_timer_t timer = { 0 };
    switch_frame_t *read_frame = NULL;
    void *pop = NULL;
    uint32_t mix_passes = 0, mix_buffer_len = 0, spk_buffer_len = 0, out_buffer_len = 0, net_buffer_len = 0, buf_out_seq = 0;
    uint8_t fl_has_audio_spk, fl_has_audio_net, fl_has_audio_mix;

    if(!conference_sem_take(conference)) {
        goto out;
    }

    if(switch_core_timer_init(&timer, "soft", conference->ptime, conference->samplerate, conference->pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: timer fail\n", conference->name);
        conference->fl_do_destroy = true;
        goto out;
    }
    if((spk_buffer = switch_core_alloc(conference->pool, AUDIO_BUFFER_SIZE)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference->name);
        conference->fl_do_destroy = true;
        goto out;
    }
    if((out_buffer = switch_core_alloc(conference->pool, AUDIO_BUFFER_SIZE)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference->name);
        conference->fl_do_destroy = true;
        goto out;
    }
    if((mix_buffer = switch_core_alloc(conference->pool, AUDIO_BUFFER_SIZE)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference->name);
        conference->fl_do_destroy = true;
        goto out;
    }
    if((net_buffer = switch_core_alloc(conference->pool, AUDIO_BUFFER_SIZE)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference->name);
        conference->fl_do_destroy = true;
        goto out;
    }

    while(true) {
        if(globals.fl_shutdown || conference->fl_do_destroy) {
            break;
        }
        if(!conference->fl_ready) {
            switch_yield(50000);
            continue;
        }
        mix_passes = 0;
        mix_buffer_len = 0;
        out_buffer_len = 0;
        spk_buffer_len = 0;
        net_buffer_len = 0;
        fl_has_audio_spk = false;
        fl_has_audio_mix = false;
        fl_has_audio_net = false;

        if(globals.fl_dm_enabled) {
            if(switch_queue_trypop(conference->audio_q_in, &pop) == SWITCH_STATUS_SUCCESS) {
                audio_tranfser_buffer_t *atbuf = (audio_tranfser_buffer_t *)pop;
                if(atbuf && atbuf->data_len) {
                    memcpy(net_buffer, atbuf->data, atbuf->data_len);
                    net_buffer_len = atbuf->data_len;

                    if(atbuf->channels != conference->channels) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s: wrong channels number (%i != %i)\n", conference->name, atbuf->channels, conference->channels);
                        fl_has_audio_net = false;
                    } else {
                        fl_has_audio_net = true;
                    }
                }
                audio_tranfser_buffer_free(atbuf);
            }
        }

        if(conference_flag_test(conference, CF_HAS_MIX) || conference_flag_test(conference, CF_PLAYBACK)) {
            if(switch_queue_trypop(conference->audio_mix_q_in, &pop) == SWITCH_STATUS_SUCCESS) {
                audio_tranfser_buffer_t *atbuf = (audio_tranfser_buffer_t *)pop;
                if(atbuf && atbuf->data_len) {
                    mix_buffer_len = atbuf->data_len;
                    memcpy(mix_buffer, atbuf->data, atbuf->data_len);
                    fl_has_audio_mix = true;
                }
                audio_tranfser_buffer_free(atbuf);
            }
        }

        if(conference->speakers_local) {
            switch_mutex_lock(conference->mutex_speakers);
            for(hidx = switch_core_hash_first_iter(conference->speakers, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
                const void *hkey = NULL; void *hval = NULL;
                member_t *speaker = NULL;

                switch_core_hash_this(hidx, &hkey, NULL, &hval);
                speaker = (member_t *) hval;

                if(member_sem_take(speaker)) {
                    if(member_can_speak(speaker)) {
                        status = switch_core_session_read_frame(speaker->session, &read_frame, SWITCH_IO_FLAG_NONE, 0);
                        if(SWITCH_READ_ACCEPTABLE(status) && read_frame->samples > 0 && !switch_test_flag(read_frame, SFF_CNG)) {
                            if(conference_flag_test(conference, CF_AUDIO_TRANSCODE)) {
                                uint32_t flags = 0;
                                uint32_t src_smprt = speaker->samplerate;
                                spk_buffer_len = AUDIO_BUFFER_SIZE;

                                if(switch_core_codec_ready(speaker->read_codec)) {
                                    if(switch_core_codec_decode(speaker->read_codec, NULL, read_frame->data, read_frame->datalen, speaker->samplerate, spk_buffer, &spk_buffer_len, &src_smprt, &flags) == SWITCH_STATUS_SUCCESS) {
                                        /* mux */
                                        if(speaker->channels != conference->channels) {
                                            uint32_t smps = (spk_buffer_len / 2 / speaker->channels);
                                            uint32_t tmp_sz = (smps * 2 * conference->channels);

                                            if(tmp_sz <= AUDIO_BUFFER_SIZE) {
                                                switch_mux_channels((int16_t *)spk_buffer, smps, speaker->channels, conference->channels);
                                                spk_buffer_len = tmp_sz;
                                            } else {
                                                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "MUX: new_len > AUDIO_BUFFER_SIZE (%i > %i)\n", tmp_sz, AUDIO_BUFFER_SIZE);
                                            }
                                        }

                                        /* gain */
                                        if(speaker->volume_out_lvl) {
                                            switch_change_sln_volume((int16_t *)spk_buffer, (spk_buffer_len / 2), speaker->volume_out_lvl);
                                        }

                                        /* vad */
                                        if(conference_flag_test(conference, CF_USE_VAD) && member_flag_test(speaker, MF_VAD)) {
                                            if(speaker->vad_hits < VAD_HITS_HALF) {
                                                int16_t *smpbuf = (int16_t *)spk_buffer;
                                                uint32_t smps = spk_buffer_len / sizeof(*smpbuf);
                                                uint32_t lvl = 0;

                                                for(int i = 0; i < smps; i++) { lvl += abs(smpbuf[i]); }
                                                speaker->vad_score = (lvl / smps);

                                                if(speaker->vad_score > speaker->vad_lvl) {
                                                    fl_has_audio_spk = true;
                                                    member_flag_set(speaker, MF_SPEAKING, true);
                                                    speaker->vad_hits = VAD_HITS_MAX;
                                                } else {
                                                    if(speaker->vad_hits) { speaker->vad_hits--; }
                                                    if(speaker->vad_hits) {
                                                        fl_has_audio_spk = true;
                                                    } else {
                                                        if(member_flag_test(speaker, MF_SPEAKING)) {
                                                            fl_has_audio_spk = false;
                                                            member_flag_set(speaker, MF_SPEAKING, false);
                                                            speaker->vad_silence_fade_in = 5;
                                                        }
                                                    }
                                                }
                                            } else {
                                                speaker->vad_hits--;
                                                if(speaker->vad_hits) {
                                                    fl_has_audio_spk = true;
                                                } else {
                                                    fl_has_audio_spk = false;
                                                    member_flag_set(speaker, MF_SPEAKING, false);
                                                    speaker->vad_silence_fade_in = 5;
                                                }
                                            }
                                        } else {
                                            fl_has_audio_spk = true;
                                        }

                                        /* agc */
                                        if(fl_has_audio_spk) {
                                            if(member_flag_test(speaker, MF_AGC) && speaker->agc) {
                                                switch_mutex_lock(speaker->mutex_agc);
                                                switch_agc_feed(speaker->agc, (int16_t *)spk_buffer, (spk_buffer_len / 2), speaker->channels);
                                                switch_mutex_unlock(speaker->mutex_agc);
                                            }
                                        }
                                    }
                                }
                            } else {
                                memcpy(spk_buffer, read_frame->data, read_frame->datalen);
                                spk_buffer_len = read_frame->datalen;
                                fl_has_audio_spk = true;
                                member_flag_set(speaker, MF_SPEAKING, true);
                            }
                        }
                    }
                    member_sem_release(speaker);
                }

                if(globals.fl_shutdown || conference->fl_do_destroy || conference->fl_destroyed) {
                    break;
                }

                if(fl_has_audio_spk) {
                    if(!mix_passes) {
                        out_buffer_len = spk_buffer_len;
                        memcpy(out_buffer, spk_buffer, out_buffer_len);
                    } else {
                        out_buffer_len = (spk_buffer_len < out_buffer_len ? spk_buffer_len : out_buffer_len);
                        mix_i16((int16_t *)out_buffer, (int16_t *)spk_buffer, out_buffer_len / 2);
                    }
                    mix_passes++;
                }
            } /* speakers iterator */
            switch_mutex_unlock(conference->mutex_speakers);
        }

        if(fl_has_audio_mix) {
            if(!mix_passes) {
                out_buffer_len = mix_buffer_len;
                memcpy(out_buffer, mix_buffer, out_buffer_len);
            } else {
                out_buffer_len = (mix_buffer_len < out_buffer_len ? mix_buffer_len : out_buffer_len);
                mix_i16((int16_t *)out_buffer, (int16_t *)mix_buffer, out_buffer_len / 2);
            }
            mix_passes++;
        }

        if(globals.fl_dm_enabled) {
            if(fl_has_audio_spk || fl_has_audio_mix) {
                audio_tranfser_buffer_t *atb = NULL;
                audio_tranfser_buffer_alloc(&atb, out_buffer, out_buffer_len);

                atb->conference_id = conference->id;
                atb->samplerate = conference->samplerate;
                atb->channels = conference->channels;
                atb->id = buf_out_seq;

                if(switch_queue_trypush(globals.dm_audio_queue_out, atb) != SWITCH_STATUS_SUCCESS) {
                    audio_tranfser_buffer_free(atb);
                }
            }
        }

        if(fl_has_audio_spk || fl_has_audio_mix || fl_has_audio_net) {
            audio_tranfser_buffer_t *atb = NULL;

            if(fl_has_audio_net) {
                if(!mix_passes) {
                    out_buffer_len = net_buffer_len;
                    memcpy(out_buffer, net_buffer, out_buffer_len);
                } else {
                    out_buffer_len = (net_buffer_len < out_buffer_len ? net_buffer_len : out_buffer_len);
                    mix_i16((int16_t *)out_buffer, (int16_t *)net_buffer, out_buffer_len / 2);
                }
            }

            audio_tranfser_buffer_alloc(&atb, out_buffer, out_buffer_len);
            atb->conference_id = conference->id;
            atb->samplerate = conference->samplerate;
            atb->channels = conference->channels;
            atb->id = buf_out_seq;

            if(switch_queue_trypush(conference->audio_q_out, atb) != SWITCH_STATUS_SUCCESS) {
                audio_tranfser_buffer_free(atb);
            }

            buf_out_seq++;
        }

        switch_core_timer_next(&timer);
    }
out:
    switch_core_timer_destroy(&timer);

    conference_sem_release(conference);

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    return NULL;
}

static void *SWITCH_THREAD_FUNC conference_audio_produce_thread(switch_thread_t *thread, void *obj) {
    volatile conference_t *_ref = (conference_t *) obj;
    conference_t *conference = (conference_t *) _ref;
    switch_hash_index_t *hidx = NULL;
    void *pop = NULL;

    if(!conference_sem_take(conference)) {
        goto out;
    }

    while(true) {
        if(globals.fl_shutdown || conference->fl_do_destroy) {
            break;
        }

        if(!conference->fl_ready) {
            switch_yield(50000);
            continue;
        }

        /* carrying audio to groups */
        while(switch_queue_trypop(conference->audio_q_out, &pop) == SWITCH_STATUS_SUCCESS) {
            audio_tranfser_buffer_t *atbuf = (audio_tranfser_buffer_t *)pop;

            if(atbuf && atbuf->data_len) {
                if(conference->members_local > 0) {

                    switch_mutex_lock(conference->mutex_listeners);
                    for (hidx = switch_core_hash_first_iter(conference->listeners, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
                        const void *hkey = NULL; void *hval = NULL;
                        member_group_t *group = NULL;

                        switch_core_hash_this(hidx, &hkey, NULL, &hval);
                        group = (member_group_t *) hval;

                        if(group_sem_take(group)) {
                            if(group->fl_ready && group->free != group->capacity) {
                                audio_tranfser_buffer_t *atb_cloned = NULL;

                                audio_tranfser_buffer_clone(&atb_cloned, atbuf);
                                if(switch_queue_trypush(group->audio_q, atb_cloned) != SWITCH_STATUS_SUCCESS) {
                                    audio_tranfser_buffer_free(atb_cloned);
                                }
                            }
                            group_sem_release(group);
                        }

                        if(globals.fl_shutdown || conference->fl_do_destroy) {
                            break;
                        }
                    }
                    switch_mutex_unlock(conference->mutex_listeners);
                }
            }
            audio_tranfser_buffer_free(atbuf);
        }
        switch_yield(10000);
    }
out:
    conference_sem_release(conference);

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    return NULL;
}

static void *SWITCH_THREAD_FUNC conference_group_listeners_control_thread(switch_thread_t *thread, void *obj) {
    volatile member_group_t *_ref = (member_group_t *) obj;
    member_group_t *group = (member_group_t *) _ref;
    conference_t *conference = (conference_t *) group->conference;
    const uint32_t audio_cache_size = (globals.audio_cache_size * sizeof(audio_cache_t));
    switch_byte_t *audio_cache = NULL;
    switch_byte_t *src_buffer = NULL, *enc_buffer = NULL;
    switch_timer_t timer = { 0 };
    switch_hash_index_t *hidx = NULL;
    uint32_t group_dlock_cnt = 0;
    uint32_t group_id = group->id;
    uint32_t src_buffer_len = 0;
    time_t term_timer = 0;
    void *pop = NULL;

    if(!conference_sem_take(conference)) {
        goto out;
    }
    if(switch_core_timer_init(&timer, "soft", conference->ptime, conference->samplerate, group->pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: timer fail\n", conference->name);
        group->fl_do_destroy = true;
        goto out;
    }
    if((enc_buffer = switch_core_alloc(group->pool, AUDIO_BUFFER_SIZE)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference->name);
        group->fl_do_destroy = true;
        goto out;
    }
    if((src_buffer = switch_core_alloc(group->pool, AUDIO_BUFFER_SIZE)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference->name);
        group->fl_do_destroy = true;
        goto out;
    }
    if(audio_cache_size) {
        if((audio_cache = switch_core_alloc(group->pool, audio_cache_size)) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference->name);
            group->fl_do_destroy = true;
            goto out;
        }
    }

    group->fl_ready = true;

    while(true) {
        if(globals.fl_shutdown || conference->fl_do_destroy || !conference->fl_ready) {
            break;
        }
        if(term_timer > 0) {
            if(group->free != group->capacity) {
                term_timer = 0;
            } else if(term_timer <= switch_epoch_time_now(NULL)) {
                group->fl_do_destroy = true;
                break;
            }
        }
        if(group->free == group->capacity) {
            if(conference->group_term_timer > 0 && term_timer == 0) {
                term_timer = (switch_epoch_time_now(NULL) + conference->group_term_timer);
            }
        }
        if(switch_queue_trypop(group->audio_q, &pop) == SWITCH_STATUS_SUCCESS) {
            audio_tranfser_buffer_t *atbuf = (audio_tranfser_buffer_t *) pop;

            if(atbuf || atbuf->data_len) {
                if(audio_cache_size) {
                    memset(audio_cache, 0x0, audio_cache_size);
                }

                /* copy to local buffer */
                memcpy(src_buffer, atbuf->data, atbuf->data_len);
                src_buffer_len = atbuf->data_len;

                /* foreach members */
                switch_mutex_lock(group->mutex_members);
                for (hidx = switch_core_hash_first_iter(group->members, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
                    const void *hkey = NULL; void *hval = NULL;
                    member_t *member = NULL;

                    if(globals.fl_shutdown || conference->fl_do_destroy || !conference->fl_ready) {
                        break;
                    }

                    switch_core_hash_this(hidx, &hkey, NULL, &hval);
                    member = (member_t *) hval;

                    if(member_sem_take(member)) {
                        if(member_can_hear(member)) {
                            if(conference_flag_test(conference, CF_AUDIO_TRANSCODE)) {
                                uint32_t flags = 0, cache_id = 0, skip_encode = false;
                                uint32_t enc_smprt = member->samplerate;
                                uint32_t enc_buffer_len = AUDIO_BUFFER_SIZE;
                                uint32_t cur_members_count = (group->capacity - group->free);

                                /* find in cache */
                                if(audio_cache_size && cur_members_count > 1) {
                                    uint32_t cname_len = 0;
                                    char cname_buf[128];

                                    cname_len = snprintf((char *)cname_buf, sizeof(cname_buf), "%s%X%X%X%X", member->codec_name, member->samplerate, member->channels, member->volume_in_lvl, atbuf->id);
                                    cache_id = make_id((char *)cname_buf, cname_len);

                                    for(int i = 0; i < globals.audio_cache_size; i++) {
                                        audio_cache_t *cache = (audio_cache_t *)(audio_cache + (i * sizeof(audio_cache_t)));
                                        if(cache->id == cache_id && cache->data_len > 0) {
                                            cache->ucnt++;
                                            enc_buffer_len = cache->data_len;
                                            memcpy(enc_buffer, cache->data, cache->data_len);
                                            skip_encode = true;
                                            break;
                                        }
                                    }
                                }
                                if(!skip_encode) {
                                    /* mux */
                                    if(member->channels != conference->channels) {
                                        uint32_t smps = (src_buffer_len / 2 / conference->channels);
                                        uint32_t tmp_sz = (smps * 2 * member->channels);

                                        if(tmp_sz <= AUDIO_BUFFER_SIZE) {
                                            switch_mux_channels((int16_t *)src_buffer, smps, conference->channels, member->channels);
                                            src_buffer_len = tmp_sz;
                                        } else {
                                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "MUX: new_len > AUDIO_BUFFER_SIZE (%i > %i)\n", tmp_sz, AUDIO_BUFFER_SIZE);
                                        }
                                    }

                                    /* gain */
                                    if(member->volume_in_lvl) {
                                        switch_change_sln_volume((int16_t *)src_buffer, (src_buffer_len / 2), member->volume_in_lvl);
                                    }

                                    /* encode */
                                    if(switch_core_codec_ready(member->write_codec)) {
                                        if(switch_core_codec_encode(member->write_codec, NULL, src_buffer, src_buffer_len, atbuf->samplerate, enc_buffer, &enc_buffer_len, &enc_smprt, &flags) == SWITCH_STATUS_SUCCESS) {
                                            if(audio_cache_size && cur_members_count > 1) {
                                                audio_cache_t *ex_cache = NULL;

                                                for(int i = 0; i < globals.audio_cache_size; i++) {
                                                    audio_cache_t *cache = (audio_cache_t *)(audio_cache + (i * sizeof(audio_cache_t)));
                                                    if(!cache->id && !cache->data_len) {
                                                        ex_cache = cache;
                                                        break;
                                                    }
                                                    if(!ex_cache || cache->ucnt < ex_cache->ucnt) {
                                                        ex_cache = cache;
                                                    }
                                                }
                                                if(ex_cache) {
                                                    ex_cache->id = cache_id;
                                                    ex_cache->ucnt = 0;
                                                    ex_cache->data_len = enc_buffer_len;
                                                    memcpy(ex_cache->data, enc_buffer, enc_buffer_len);
                                                }
                                            }
                                        }
                                    }
                                }
                                if(enc_buffer_len > 0) {
                                    if(member->fl_au_rdy_wr) {
                                        memcpy(member->au_buffer, enc_buffer, enc_buffer_len);

                                        switch_mutex_lock(member->mutex_audio);
                                        member->au_buffer_id = atbuf->id;
                                        member->au_data_len = enc_buffer_len;
                                        switch_mutex_unlock(member->mutex_audio);
                                    }
                                }
                            } else { /* transcoding | as-is */
                                if(member->fl_au_rdy_wr) {
                                    memcpy(member->au_buffer, src_buffer, src_buffer_len);

                                    switch_mutex_lock(member->mutex_audio);
                                    member->au_buffer_id = atbuf->id;
                                    member->au_data_len = src_buffer_len;
                                    switch_mutex_unlock(member->mutex_audio);
                                }
                            }
                        } /* test membr flags */
                        member_sem_release(member);
                    }
                } /* members iterator */
                switch_mutex_unlock(group->mutex_members);
            } /* audio buffer */
            audio_tranfser_buffer_free(atbuf);
        } /* trypop audio_q */

        switch_core_timer_next(&timer);
    }
out:
    switch_core_timer_destroy(&timer);

    group->fl_ready = false;
    group->fl_destroyed = true;

    while(group->tx_sem > 0) {
        switch_yield(100000);
        group_dlock_cnt++;
        if(group_dlock_cnt > 100) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s: Group '%i' locked! (lost '%i' semaphores)\n", conference->name, group_id, group->tx_sem);
            group_dlock_cnt = 0;
        }
    }

    switch_mutex_lock(conference->mutex_listeners);
    switch_core_inthash_delete(conference->listeners, group->id);
    switch_mutex_unlock(conference->mutex_listeners);

    flush_audio_queue(group->audio_q);
    switch_queue_term(group->audio_q);

    switch_core_inthash_destroy(&group->members);
    switch_core_destroy_memory_pool(&group->pool);

    conference_sem_release(conference);

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "group '%i' destroyed\n", group_id);

    return NULL;
}

static void *SWITCH_THREAD_FUNC conference_control_thread(switch_thread_t *thread, void *obj) {
    volatile conference_t *_ref = (conference_t *) obj;
    conference_t *conference = (conference_t *) _ref;
    const uint32_t conference_id = conference->id;
    char *conference_name = switch_mprintf("%s", conference->name);
    time_t term_timer = 0;
    uint32_t conf_dlock_cnt = 0;

    conference->fl_do_destroy = false;
    conference->fl_ready = true;

    while(true) {
        if(globals.fl_shutdown || conference->fl_do_destroy) {
            break;
        }

        if(term_timer > 0) {
            if(conference->speakers_local > 0 || conference->members_local > 0) {
                term_timer = 0;
            } else if(term_timer <= switch_epoch_time_now(NULL)) {
                conference->fl_do_destroy = true;
                break;
            }
        }

        if(conference->speakers_local == 0 && conference->members_local == 0) {
            if(conference->conf_term_timer > 0 && term_timer == 0) {
                term_timer = (switch_epoch_time_now(NULL) + conference->conf_term_timer);
            }
        }
        switch_yield(10000);
    }

    /* finish the conference */
    conference->fl_ready = false;
    conference->fl_destroyed = true;

    while(conference->tx_sem > 0) {
        switch_yield(100000);
        conf_dlock_cnt++;
        if(conf_dlock_cnt > 100) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s: Conference locked! (lost '%i' semaphores)\n", conference_name, conference->tx_sem);
            conf_dlock_cnt = 0;
        }
    }

    flush_audio_queue(conference->audio_q_in);
    flush_audio_queue(conference->audio_q_out);
    flush_audio_queue(conference->audio_mix_q_in);
    switch_queue_term(conference->audio_q_in);
    switch_queue_term(conference->audio_q_out);
    switch_queue_term(conference->audio_mix_q_in);

    flush_commands_queue(conference->commands_q_in);
    switch_queue_term(conference->commands_q_in);

    switch_core_inthash_destroy(&conference->listeners);
    switch_core_inthash_destroy(&conference->speakers);

    switch_core_hash_destroy(&conference->members_idx_hash);
    switch_core_destroy_memory_pool(&conference->pool);

    switch_mutex_lock(globals.mutex_conferences);
    switch_core_inthash_delete(globals.conferences_hash, conference_id);
    switch_mutex_unlock(globals.mutex_conferences);

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "conference '%s' destroyed\n", conference_name);

    switch_safe_free(conference_name);
    return NULL;
}

static switch_status_t init_client_socket(switch_socket_t **socket, switch_sockaddr_t **dst_addr, switch_memory_pool_t *pool) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_sockaddr_t *loaddr = NULL, *taddr = NULL;
    switch_socket_t *soc = NULL;

    switch_assert(pool);

    if((status = switch_sockaddr_info_get(&loaddr, globals.dm_local_ip, SWITCH_UNSPEC, 0, 0, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (cli) (switch_sockaddr_info_get) [#1]\n");
        goto out;
    }

    if(globals.dm_mode == DM_MODE_MILTICAST) {
        if((status = switch_sockaddr_info_get(&taddr, globals.dm_multicast_group, SWITCH_UNSPEC, globals.dm_port_out, 0, pool)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (cli) (switch_sockaddr_info_get) [#2]\n");
            goto out;
        }
        *dst_addr = taddr;
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "client socket: %s:%i (mcast-group: %s)\n", globals.dm_local_ip, globals.dm_port_out, globals.dm_multicast_group);
    }
    if(globals.dm_mode == DM_MODE_P2P) {
        if((status = switch_sockaddr_info_get(&taddr, globals.dm_remote_ip, SWITCH_UNSPEC, globals.dm_port_out, 0, pool)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (cli) (switch_sockaddr_info_get) [#2]\n");
            goto out;
        }
        *dst_addr = taddr;
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "client socket: %s:%i\n", globals.dm_remote_ip, globals.dm_port_out);
    }

    if((status = switch_socket_create(&soc, switch_sockaddr_get_family(loaddr), SOCK_DGRAM, 0, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (cli) (switch_socket_create)\n");
        goto out;
    }
    if((status = switch_socket_bind(soc, loaddr)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (cli) (switch_socket_bind)\n");
        goto out;
    }

    if(globals.dm_mode == DM_MODE_MILTICAST) {
        if((status = switch_mcast_interface(soc, loaddr)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (cli) (switch_mcast_interface)\n");
            goto out;
        }
        if((status = switch_mcast_join(soc, taddr, NULL, NULL)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (cli) (switch_mcast_join)\n");
            goto out;
        }
        if((status = switch_mcast_hops(soc, (uint8_t) DM_MULTICAST_TTL)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (cli) (switch_mcast_hops)\n");
            goto out;
        }
    }

out:
    if(soc) {
        *socket = soc;
    }
    return status;
}

static switch_status_t init_server_socket(switch_socket_t **socket, switch_memory_pool_t *pool) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_sockaddr_t *loaddr = NULL, *mcaddr = NULL;
    switch_socket_t *soc = NULL;

    switch_assert(pool);

    if(globals.dm_mode == DM_MODE_MILTICAST) {
        if((status = switch_sockaddr_info_get(&loaddr, NET_ANYADDR, SWITCH_UNSPEC, globals.dm_port_in, 0, pool)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (srv) (switch_sockaddr_info_get) [#1]\n");
            goto out;
        }
        if((status = switch_sockaddr_info_get(&mcaddr, globals.dm_multicast_group, SWITCH_UNSPEC, 0, 0, pool)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (srv) (switch_sockaddr_info_get) [#2]\n");
            goto out;
        }
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "server socket: %s:%i (mcast-group: %s)\n", NET_ANYADDR, globals.dm_port_in, globals.dm_multicast_group);
    }
    if(globals.dm_mode == DM_MODE_P2P) {
        if((status = switch_sockaddr_info_get(&loaddr, globals.dm_local_ip, SWITCH_UNSPEC, globals.dm_port_in, 0, pool)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (srv) (switch_sockaddr_info_get)\n");
            goto out;
        }
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "server socket: %s:%i\n", globals.dm_local_ip, globals.dm_port_in);
    }

    if((status = switch_socket_create(&soc, switch_sockaddr_get_family(loaddr), SOCK_DGRAM, 0, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (srv) (switch_socket_create)\n");
        goto out;
    }
    if((status = switch_socket_opt_set(soc, SWITCH_SO_REUSEADDR, true)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (srv) (opt: SWITCH_SO_REUSEADDR)\n");
        goto out;
    }
    if((status = switch_socket_bind(soc, loaddr)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (srv) (switch_socket_bind)\n");
        goto out;
    }

    if(globals.dm_mode == DM_MODE_MILTICAST) {
        if((status = switch_mcast_join(soc, mcaddr, NULL, NULL)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (srv) (switch_mcast_join)\n");
            goto out;
        }
    }

out:
    if(soc) {
        *socket = soc;
    }
    return status;
}

static void *SWITCH_THREAD_FUNC dm_client_thread(switch_thread_t *thread, void *obj) {
    const uint32_t dm_auth_buffer_len = (strlen(globals.dm_shared_secret) + DM_SALT_SIZE);
    const uint32_t send_buffer_size = DM_IO_BUFFER_SIZE;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_memory_pool_t *pool = NULL;
    switch_socket_t *socket = NULL;
    switch_sockaddr_t *dst_addr = NULL;
    switch_byte_t *send_buffer = NULL;       /* fixed size buffer */
    switch_byte_t *dm_auth_buffer = NULL;    /* keeps salt + secret */
    switch_byte_t *paylod_data_ptr = NULL;
    cipher_ctx_t *cipher_ctx = NULL;
    dm_packet_hdr_t *phdr_ptr = NULL;
    dm_payload_audio_hdr_t *ahdr_ptr = NULL;
    uint32_t packet_seq = 0, send_len = 0;
    time_t salt_renew_time = 0;
    switch_size_t bytes = 0;
    void *pop = NULL;

    if(switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }
    if((send_buffer = switch_core_alloc(pool, send_buffer_size)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }

    if(globals.fl_dm_auth_enabled) {
        if((dm_auth_buffer = switch_core_alloc(pool, dm_auth_buffer_len)) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }
        switch_stun_random_string((char *)dm_auth_buffer, DM_SALT_SIZE, NULL);
        memcpy((void *)(dm_auth_buffer + DM_SALT_SIZE), globals.dm_shared_secret, strlen(globals.dm_shared_secret));
    }

    if(globals.fl_dm_encrypt_payload) {
        if((cipher_ctx = switch_core_alloc(pool, sizeof(cipher_ctx_t))) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }
        cipher_init(cipher_ctx, globals.dm_shared_secret, strlen(globals.dm_shared_secret));
    }

    if((status = init_client_socket(&socket, &dst_addr, pool)) != SWITCH_STATUS_SUCCESS) {
        goto out;
    }

    while(true) {
        if(globals.fl_shutdown) {
            break;
        }

        if(globals.fl_dm_auth_enabled) {
            if(!salt_renew_time || salt_renew_time < switch_epoch_time_now(NULL)) {
                switch_stun_random_string((char *)dm_auth_buffer, DM_SALT_SIZE, NULL);
                salt_renew_time = (switch_epoch_time_now(NULL) + DM_SALT_LIFE_TIME);
            }
        }

        while(switch_queue_trypop(globals.dm_command_queue_out, &pop) == SWITCH_STATUS_SUCCESS) {
            /* todo, conference commands */
        }

        while(switch_queue_trypop(globals.dm_audio_queue_out, &pop) == SWITCH_STATUS_SUCCESS) {
            audio_tranfser_buffer_t *atbuf = (audio_tranfser_buffer_t *) pop;

            if(globals.fl_shutdown) { goto out; }

            if(atbuf || atbuf->data_len) {
                send_len = (sizeof(dm_packet_hdr_t) + sizeof(dm_payload_audio_hdr_t) + atbuf->data_len);

                if(send_len <= send_buffer_size) {
                    memset((void *)send_buffer, 0x0, send_len);

                    phdr_ptr = (void *)(send_buffer);
                    ahdr_ptr = (void *)(send_buffer + sizeof(*phdr_ptr));
                    paylod_data_ptr = (void *)(send_buffer + sizeof(*phdr_ptr) + sizeof(*ahdr_ptr));

                    /* set up packet hdr */
                    phdr_ptr->node_id = globals.dm_node_id;
                    phdr_ptr->packet_id = packet_seq;
                    phdr_ptr->packet_flags = 0x0;
                    phdr_ptr->payload_type = DM_PAYLOAD_AUDIO;
                    phdr_ptr->payload_len = (sizeof(dm_payload_audio_hdr_t) + atbuf->data_len);

                    /* sign packet */
                    if(globals.fl_dm_auth_enabled) {
                        switch_md5_string((char *)phdr_ptr->auth_hash, dm_auth_buffer, dm_auth_buffer_len);
                        memcpy(phdr_ptr->auth_salt, dm_auth_buffer, DM_SALT_SIZE);
                    }

                    /* payload */
                    ahdr_ptr->magic = DM_PAYLOAD_MAGIC;
                    ahdr_ptr->conference_id = atbuf->conference_id;
                    ahdr_ptr->samplerate = atbuf->samplerate;
                    ahdr_ptr->channels = atbuf->channels;
                    ahdr_ptr->data_len = atbuf->data_len;

                    memcpy(paylod_data_ptr, atbuf->data, atbuf->data_len);

                    /* encrypt payload */
                    if(globals.fl_dm_encrypt_payload) {
                        uint8_t *data_ptr = (void *)(ahdr_ptr);
                        uint32_t psz = phdr_ptr->payload_len;
                        uint32_t pad = (psz % sizeof(int));

                        if(pad) { psz += sizeof(int) - pad; }
                        if(psz > send_buffer_size) { psz = phdr_ptr->payload_len; }

                        cipher_encrypt(cipher_ctx, phdr_ptr->packet_id, data_ptr, psz);
                        dm_packet_flag_set(phdr_ptr, DMPF_ENCRYPTED, true);
                    }

                    bytes = send_len;
                    switch_socket_sendto(socket, dst_addr, 0, (void *)send_buffer, &bytes);

                    packet_seq++;
                }
            } else {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "packet is too long: %i  (max: %i)\n", send_len, send_buffer_size);
            }
            audio_tranfser_buffer_free(atbuf);
        }

        switch_yield(10000);
    }

out:
    if(status != SWITCH_STATUS_SUCCESS) {
        globals.fl_shutdown = true;
    }
    if (socket) {
        switch_socket_close(socket);
    }
    if(pool) {
        switch_core_destroy_memory_pool(&pool);
    }

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    return NULL;
}

static void *SWITCH_THREAD_FUNC dm_server_thread(switch_thread_t *thread, void *obj) {
    const uint32_t dm_auth_buffer_len = (strlen(globals.dm_shared_secret) + DM_SALT_SIZE);
    const uint32_t recv_buffer_size = DM_IO_BUFFER_SIZE;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_memory_pool_t *pool = NULL;
    switch_pollfd_t *pollfd = NULL;
    switch_socket_t *socket = NULL;
    switch_sockaddr_t *from_addr = NULL;
    switch_byte_t *recv_buffer = NULL;     /* fixed size buffer */
    switch_byte_t *dm_auth_buffer = NULL;  /* keeps salt + secret */
    switch_byte_t *paylod_data_ptr = NULL;
    switch_inthash_t *nodes_stats_map = NULL;
    cipher_ctx_t *cipher_ctx = NULL;
    char md5_hash[SWITCH_MD5_DIGEST_STRING_SIZE] = { 0 };
    dm_packet_hdr_t *phdr_ptr = NULL;
    dm_payload_audio_hdr_t *ahdr_ptr = NULL;
    conference_t *conference = NULL;
    node_stat_t *node_stat = NULL;
    switch_size_t bytes = 0;
    time_t check_seq_timer = 0;
    uint32_t nodes_count = 0;
    const char *ip_addr_remote;
    char ipbuf[48];
    int fdr = 0;

    if(switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }
    if(switch_core_inthash_init(&nodes_stats_map) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }
    if((recv_buffer = switch_core_alloc(pool, recv_buffer_size)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }

    if(globals.fl_dm_auth_enabled) {
        if((dm_auth_buffer = switch_core_alloc(pool, dm_auth_buffer_len)) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }
        memset((void *)dm_auth_buffer, 0x0, DM_SALT_SIZE);
        memcpy((void *)(dm_auth_buffer + DM_SALT_SIZE), globals.dm_shared_secret, strlen(globals.dm_shared_secret));
    }

    if(globals.fl_dm_encrypt_payload) {
        if((cipher_ctx = switch_core_alloc(pool, sizeof(cipher_ctx_t))) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }
        cipher_init(cipher_ctx, globals.dm_shared_secret, strlen(globals.dm_shared_secret));
    }

    if((status = init_server_socket(&socket, pool)) != SWITCH_STATUS_SUCCESS) {
        goto out;
    }
    if((status = switch_socket_create_pollset(&pollfd, socket, SWITCH_POLLIN | SWITCH_POLLERR, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (switch_socket_create_pollset)\n");
        goto out;
    }
    if((status = switch_socket_opt_set(socket, SWITCH_SO_NONBLOCK, true)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (opt: SWITCH_SO_NONBLOCK)\n");
        goto out;
    }

    switch_sockaddr_info_get(&from_addr, NULL, SWITCH_UNSPEC, 0, 0, pool);

    while(true) {
        if(globals.fl_shutdown) {
            break;
        }

        bytes = recv_buffer_size;
        if(switch_socket_recvfrom(from_addr, socket, 0, (void *)recv_buffer, &bytes) == SWITCH_STATUS_SUCCESS && bytes > sizeof(dm_packet_hdr_t)) {
            phdr_ptr = (void *)(recv_buffer);
            ip_addr_remote = switch_get_addr(ipbuf, sizeof(ipbuf), from_addr);

            if(globals.dm_node_id == phdr_ptr->node_id) {
                goto sleep;
            }

            if(!phdr_ptr->payload_len || phdr_ptr->payload_len > recv_buffer_size) {
                goto sleep;
            }

            /* check sign */
            if(globals.fl_dm_auth_enabled) {
                memcpy(dm_auth_buffer, (char *)phdr_ptr->auth_salt, DM_SALT_SIZE);
                switch_md5_string((char *)md5_hash, dm_auth_buffer, dm_auth_buffer_len);

                if(strncmp((char *)md5_hash, (char *)phdr_ptr->auth_hash, sizeof(md5_hash)) !=0) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unauthorized packet (ip: %s)\n", ip_addr_remote);
                    goto sleep;
                }
            }

            /* flush nodes state cache */
            if(globals.fl_dm_do_flush_status_cache) {
                dm_server_clean_nodes_status_cache(nodes_stats_map, true);
                globals.fl_dm_do_flush_status_cache = false;
                nodes_count = 0;
            }
            /* drop outdated packets */
            node_stat = switch_core_inthash_find(nodes_stats_map, phdr_ptr->node_id);
            if(!node_stat) {
                if(nodes_count > DM_MAX_NODES) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Too many nodes (max: %i)\n", DM_MAX_NODES);
                    goto sleep;
                }

                switch_zmalloc(node_stat, sizeof(node_stat_t));

                node_stat->node = phdr_ptr->node_id;
                node_stat->last_id = phdr_ptr->packet_id;
                node_stat->expiry = (switch_epoch_time_now(NULL) + DM_NODE_LIFETIME);

                switch_core_inthash_insert(nodes_stats_map, node_stat->node, node_stat);
                nodes_count++;

            } else {
                if(!node_stat->last_id || phdr_ptr->packet_id > node_stat->last_id) {
                    node_stat->last_id = phdr_ptr->packet_id;
                    node_stat->expiry = (switch_epoch_time_now(NULL) + DM_NODE_LIFETIME);
                } else {
                    goto sleep;
                }
            }

            /* decrypt payload */
            if(dm_packet_flag_test(phdr_ptr, DMPF_ENCRYPTED)) {
                if(globals.fl_dm_encrypt_payload) {
                    uint8_t *data_ptr = (void *)(recv_buffer + sizeof(*phdr_ptr));
                    uint32_t psz = phdr_ptr->payload_len;
                    uint32_t pad = (psz % sizeof(int));

                    if(pad) { psz += sizeof(int) - pad; }
                    if(psz > recv_buffer_size) { psz = phdr_ptr->payload_len; }

                    cipher_decrypt(cipher_ctx, phdr_ptr->packet_id, data_ptr, psz);
                } else {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Encrypted packet from '%s' was ignored! (encryption disabled)\n", ip_addr_remote);
                }
            }

            /* payload */
            if(phdr_ptr->payload_type == DM_PAYLOAD_AUDIO) {
                ahdr_ptr = (void *)(recv_buffer + sizeof(*phdr_ptr));
                paylod_data_ptr = (void *)(recv_buffer + sizeof(*phdr_ptr) + sizeof(*ahdr_ptr));

                if(ahdr_ptr->magic == DM_PAYLOAD_MAGIC) {
                    if(ahdr_ptr->data_len && ahdr_ptr->data_len < AUDIO_BUFFER_SIZE) {
                        conference = conference_lookup_by_id(ahdr_ptr->conference_id);
                        if(conference_sem_take(conference)) {
                            audio_tranfser_buffer_t *atbuf = NULL;
                            audio_tranfser_buffer_alloc(&atbuf, paylod_data_ptr, ahdr_ptr->data_len);

                            atbuf->conference_id = ahdr_ptr->conference_id;
                            atbuf->samplerate = ahdr_ptr->samplerate;
                            atbuf->channels = ahdr_ptr->channels;
                            atbuf->id = phdr_ptr->packet_id;

                            if(switch_queue_trypush(conference->audio_q_in, atbuf) != SWITCH_STATUS_SUCCESS) {
                                audio_tranfser_buffer_free(atbuf);
                            }
                            conference_sem_release(conference);
                        }
                    }
                } else {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Decryption fail! (ip: %s)\n", ip_addr_remote);
                }
            }
        }

sleep:
        if(nodes_count && check_seq_timer < switch_epoch_time_now(NULL)) {
            nodes_count -= dm_server_clean_nodes_status_cache(nodes_stats_map, false);
            if(nodes_count > DM_MAX_NODES) { nodes_count = 0; } /* overload */
            check_seq_timer = (switch_epoch_time_now(NULL) + DM_NODE_CHECK_INTERVAL);
        }

        if(pollfd) {
            switch_poll(pollfd, 1, &fdr, 10000);
        } else {
            switch_yield(10000);
        }
    }

out:
    if(status != SWITCH_STATUS_SUCCESS) {
        globals.fl_shutdown = true;
    }

    if (socket) {
        switch_socket_close(socket);
    }

    if(nodes_stats_map) {
        switch_hash_index_t *hidx = NULL;
        const void *hvar = NULL; void *hval = NULL;
        for (hidx = switch_core_hash_first_iter(nodes_stats_map, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
            switch_core_hash_this(hidx, &hvar, NULL, &hval);
            node_stat = (node_stat_t *)hval;
            if(node_stat) {
                switch_core_inthash_delete(nodes_stats_map, node_stat->node);
                switch_safe_free(node_stat);
            }
        }
        switch_safe_free(hidx);
        switch_core_inthash_destroy(&nodes_stats_map);
    }

    if(pool) {
        switch_core_destroy_memory_pool(&pool);
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

#define CMD_SYNTAX \
 "list - show all active conferences\n" \
 "dm-flush-status-cache - flush server status cache\n" \
 "<confname> term - terminate conferece\n" \
 "<confname> show [status|groups|members]\n" \
 "<confname> playback [stop] filename [async]\n" \
 "<confname> flags [+-][trans-audio|trans-video|video|asnd|vad|cng|agc]\n" \
 "<confname> member <uuid> kick\n" \
 "<confname> member <uuid> status\n" \
 "<confname> member <uuid> playback [stop] filename [async]\n" \
 "<confname> member <uuid> set agc level:lowlevel:factor:margin\n" \
 "<confname> member <uuid> flags [+-][speaker|admin|auth|mute|deaf|vad|agc|cng]\n"

SWITCH_STANDARD_API(xconf_cmd_function) {
    char *mycmd = NULL, *argv[10] = { 0 };
    char *conf_name = NULL, *conf_cmd = NULL, *what_name = NULL;
    conference_t *conference = NULL;
    int argc = 0;

    if (!zstr(cmd)) {
        mycmd = strdup(cmd);
        switch_assert(mycmd);
        argc = switch_separate_string(mycmd, ' ', argv, (sizeof(argv) / sizeof(argv[0])));
    }
    if(argc == 0) {
        goto usage;
    }
    if(globals.fl_shutdown) {
        goto out;
    }

    if(argc == 1) {
        if(strcasecmp(argv[0], "list") == 0) {
            switch_hash_index_t *hidx = NULL;
            uint32_t total = 0;

            stream->write_function(stream, "active conferences: \n");
            switch_mutex_lock(globals.mutex_conferences);

            for (hidx = switch_core_hash_first_iter(globals.conferences_hash, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
                const void *hkey = NULL; void *hval = NULL;

                switch_core_hash_this(hidx, &hkey, NULL, &hval);
                conference = (conference_t *)hval;

                if(conference_sem_take(conference)) {
                    stream->write_function(stream, "%s [0x%X / %iHz / %i / %ims] (local-members: %i, local-speakes: %i, total-members: %i, total-speakes: %i, type: %s)\n",
                        conference->name, conference->id, conference->samplerate, conference->channels, conference->ptime, conference->members_local, conference->speakers_local, conference->members_total, conference->speakers_total,
                        (conference_flag_test(conference, CF_USE_AUTH) ? "public" : "private")
                    );
                    conference_sem_release(conference);
                    total++;
                }
            }
            switch_mutex_unlock(globals.mutex_conferences);

            stream->write_function(stream, "total: %i\n", total);
            goto out;
        }
        if(strcasecmp(argv[0], "dm-flush-status-cache") == 0) {
            globals.fl_dm_do_flush_status_cache = true;
            stream->write_function(stream, "+OK\n");
            goto out;
        }
        goto usage;
    }

    /* conference commands */
    conf_name = (argc >= 1 ? argv[0] : NULL);
    conf_cmd =  (argc >= 2 ? argv[1] : NULL);
    what_name = (argc >= 3 ? argv[2] : NULL);

    if(!conf_name || !conf_cmd) {
        goto usage;
    }

    conference = conference_lookup_by_name(conf_name);
    if(!conference || !conference->fl_ready) {
        stream->write_function(stream, "-ERR: conference '%s' not exists\n", conf_name);
        goto out;
    }

    /* conference sub-command: show */
    if(strcasecmp(conf_cmd, "show") == 0) {
        if(!what_name) { goto usage; }

        if(strcasecmp(what_name, "status") == 0) {
            if(conference_sem_take(conference)) {
                conference_dump_status(conference, stream);
                conference_sem_release(conference);
            }
            goto out;
        }
        if(strcasecmp(what_name, "groups") == 0) {
            const void *hkey = NULL; void *hval = NULL;
            switch_hash_index_t *hidx = NULL;
            member_group_t *group = NULL;
            uint32_t total = 0;

            stream->write_function(stream, "conference groups:\n");
            if(conference_sem_take(conference)) {
                switch_mutex_lock(conference->mutex_listeners);
                for (hidx = switch_core_hash_first_iter(conference->listeners, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
                    switch_core_hash_this(hidx, &hkey, NULL, &hval);
                    group = (member_group_t *) hval;
                    if(group_sem_take(group)) {
                        stream->write_function(stream, "%03i - capacity: %i, free: %i\n", group->id, group->capacity, group->free);
                        group_sem_release(group);
                        total++;
                    }
                }
                switch_mutex_unlock(conference->mutex_listeners);
                conference_sem_release(conference);
            }

            stream->write_function(stream, "total: %i\n", total);
            goto out;
        }
        if(strcasecmp(what_name, "members") == 0) {
            const void *hkey = NULL; void *hval = NULL;
            const void *hkey2 = NULL; void *hval2 = NULL;
            switch_hash_index_t *hidx = NULL, *hidx2 = NULL;
            member_group_t *group = NULL;
            member_t *member = NULL;
            uint32_t total = 0;

            stream->write_function(stream, "conference members:\n");
            if(conference_sem_take(conference)) {
                switch_mutex_lock(conference->mutex_listeners);
                for (hidx = switch_core_hash_first_iter(conference->listeners, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {

                    switch_core_hash_this(hidx, &hkey, NULL, &hval);
                    group = (member_group_t *) hval;

                    if(group_sem_take(group)) {
                        switch_mutex_lock(group->mutex_members);
                        for (hidx2 = switch_core_hash_first_iter(group->members, hidx2); hidx2; hidx2 = switch_core_hash_next(&hidx2)) {

                            switch_core_hash_this(hidx2, &hkey2, NULL, &hval2);
                            member = (member_t *) hval2;

                            if(member_sem_take(member)) {
                                stream->write_function(stream, "[%s / %s] (group:%03i, media: %iHz/%i/%ims/%s, roles: %s/%s, authorized: %s)\n",
                                    member->session_id, member->caller_id, group->id, member->samplerate, member->channels, member->ptime, member->codec_name,
                                    (member_flag_test(member, MF_SPEAKER) ? "speaker" : "listener"),
                                    (member_flag_test(member, MF_ADMIN) ? "admin" : "user"),
                                    (member_flag_test(member, MF_AUTHORIZED) ? "yes" : "no")
                                );
                                member_sem_release(member);
                                total++;
                            }
                        } /* members iterator */
                        switch_mutex_unlock(group->mutex_members);
                        group_sem_release(group);
                    }
                } /* groups iterator */
                switch_mutex_unlock(conference->mutex_listeners);
                conference_sem_release(conference);
            }

            stream->write_function(stream, "total: %i\n", total);
            goto out;
        }
        goto usage;
    }
    /* playback a file in the conference */
    if(strcasecmp(conf_cmd, "playback") == 0) {
        char *filename = (argc >= 3 ? argv[2] : NULL);
        char *async = (argc >= 4 ? argv[3] : NULL);
        uint8_t fasync = ((async && strcasecmp(async, "async") == 0) ? true : false);

        if(!zstr(filename)) {
            if(strcasecmp(filename, "stop") == 0) {
                conference_playback_stop(conference);
            } else {
                conference_playback(conference, filename, fasync);
            }
        } else {
            stream->write_function(stream, "-ERR: Missing filename\n");
        }
        goto out;
    }
    /* set conference flags */
    if(strcasecmp(conf_cmd, "flags") == 0) {
        char *resp_err_str = NULL;

        if(argc <= 2) { goto usage; }
        if(conference_sem_take(conference)) {
            int flags_ok = 0;
            for(int i = 2; i < argc; i++) {
                uint8_t fl_op= (argv[i][0] == '+' ? true : false);
                char *fl_name = (char *)(argv[i] + 1);

                if(conference_parse_flags(conference, fl_name, fl_op) == SWITCH_STATUS_SUCCESS) {
                    flags_ok++;
                }
            }
            conference_sem_release(conference);

            if(!flags_ok) { resp_err_str = "Unsupported flags"; }
            if(!zstr(resp_err_str)) {
                stream->write_function(stream, "-ERR: %s\n", resp_err_str);
            } else {
                stream->write_function(stream, "+OK\n");
            }
        }
        goto out;
    }
    /* terminate the conference */
    if(strcasecmp(conf_cmd, "term") == 0) {
        if(conference_sem_take(conference)) {
            if(conference->fl_ready) {
                conference->fl_do_destroy = true;
    	    }
            conference_sem_release(conference);
        }
        stream->write_function(stream, "+OK\n");
        goto out;
    }
    /* member sub-commands */
    if(strcasecmp(conf_cmd, "member") == 0) {
        member_t *member = NULL;
        char *member_id = (argc >= 3 ? argv[2] : NULL);
        char *member_cmd = (argc >= 4 ? argv[3] : NULL);
        char *resp_err_str = NULL;
        uint8_t show_usage = false;

        if(!member_cmd || !member_id) {
            goto usage;
        }

        if(conference_sem_take(conference)) {
            switch_mutex_lock(conference->mutex);
            member = switch_core_hash_find(conference->members_idx_hash, member_id);
            switch_mutex_unlock(conference->mutex);

            if(!member) {
                stream->write_function(stream, "-ERR: member '%s' not found\n", member_id);
                conference_sem_release(conference);
                goto out;
            }
            if(member_sem_take(member)) {
                if(strcasecmp(member_cmd, "kick") == 0) {
                    member_flag_set(member, MF_KICK, true);

                } else if(strcasecmp(member_cmd, "status") == 0) {
                    member_dump_status(member, stream);

                } else if(strcasecmp(member_cmd, "set") == 0) {
                    char *set_type = (argc >= 5 ? argv[4] : NULL);
                    char *set_data = (argc >= 6 ? argv[5] : NULL);

                    if(strcasecmp(set_type, "agc") == 0) {
                        if(member_parse_agc_data(member, set_data) == SWITCH_STATUS_SUCCESS) {
                            switch_mutex_lock(member->mutex_agc);
                            if(member->agc) { switch_agc_set(member->agc, member->agc_lvl, member->agc_low_lvl, member->agc_margin, member->agc_change_factor, member->agc_period_len); }
                            switch_mutex_unlock(member->mutex_agc);
                        } else {
                            resp_err_str = "Malformed agc-data";
                        }
                    } else {
                        resp_err_str = "Unsupported type";
                    }
                } else if(strcasecmp(member_cmd, "playback") == 0) {
                    char *filename = (argc >= 5 ? argv[4] : NULL);
                    char *async = (argc >= 6 ? argv[5] : NULL);
                    uint8_t fasync = ((async && strcasecmp(async, "async") == 0) ? true : false);

                    if(!zstr(filename)) {
                        if(strcasecmp(filename, "stop") == 0) {
                            if(member_playback_stop(member) != SWITCH_STATUS_SUCCESS){
                                resp_err_str = "Couldn't stop playback";
                            }
                        } else {
                            if(member_playback(member, filename, fasync, NULL, 0) != SWITCH_STATUS_SUCCESS) {
                                resp_err_str = "Playback fail";
                            }
                        }
                    } else {
                        resp_err_str = "Missing filename";
                    }
                } else if(strcasecmp(member_cmd, "flags") == 0) {
                    int flags_ok = 0;
                    for(int i = 4; i < argc; i++) {
                        uint8_t fl_op = (argv[i][0] == '+' ? true : false);
                        char *fl_name = (char *)(argv[i] + 1);

                        if(member_parse_flags(member, fl_name, fl_op) == SWITCH_STATUS_SUCCESS) {
                            flags_ok++;
                        }
                    }
                    if(!flags_ok) { resp_err_str = "Unsupported flags"; }
                } else {
                    show_usage = true;
                }
                member_sem_release(member);
            }
            conference_sem_release(conference);
        } /* conf_sem_take */
        if(show_usage) { goto usage; }
        if(!zstr(resp_err_str)) { stream->write_function(stream, "-ERR: %s\n", resp_err_str); }
        else { stream->write_function(stream, "+OK\n"); }
        goto out;
    }

usage:
    stream->write_function(stream, "-USAGE:\n%s\n", CMD_SYNTAX);

out:
    switch_safe_free(mycmd);
    return SWITCH_STATUS_SUCCESS;
}

#define APP_SYNTAX "confName profileName [+-][trans-audio|trans-video|video|asnd|vad|cng|agc]"
SWITCH_STANDARD_APP(xconf_app_api) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_channel_t *channel = switch_core_session_get_channel(session);
    char *mycmd = NULL, *argv[10] = { 0 }; int argc = 0;
    const char *session_id = NULL;
    switch_memory_pool_t *pool_tmp = NULL;
    switch_memory_pool_t *seesion_pool = NULL;
    conference_t *conference = NULL;
    conference_profile_t *conf_profile  = NULL;
    member_t *member = NULL;
    member_group_t *group = NULL;
    controls_profile_t *ctl_profile = NULL;
    controls_profile_action_t *ctl_action = NULL;
    switch_codec_implementation_t read_impl = { 0 };
    switch_codec_implementation_t write_impl = { 0 };
    switch_frame_t write_frame = { 0 };
    switch_timer_t timer = { 0 };
    switch_byte_t *cn_buffer = NULL;
    char dtmf_cmd_buffer[DTMF_CMD_BUFFER_SIZE] = { 0 };
    char pin_code_buffer[PIN_CODE_BUFFER_SIZE] = { 0 };
    char *conference_name = NULL, *profile_name = NULL;
    uint8_t fl_play_welcome = true, fl_play_alone = true, fl_play_enter_pin = true;
    uint32_t member_dlock_cnt = 0;
    uint32_t au_buffer_id_local = 0, dtmf_buf_pos = 0;
    uint32_t member_flags_old = 0, cn_buffer_size = 0;
    uint32_t conference_id = 0, pin_code_len = 0;
    uint32_t auth_attempts = MEMBER_AUTH_ATTEMPTS;
    time_t dtmf_timer = 0, moh_check_timer = 0;

    if (!zstr(data)) {
        mycmd = strdup(data);
        switch_assert(mycmd);
        argc = switch_separate_string(mycmd, ' ', argv, (sizeof(argv) / sizeof(argv[0])));
    }
    if (argc < 2) {
        goto usage;
    }
    if(globals.fl_shutdown) {
        goto out;
    }
    conference_name = argv[0];
    profile_name = argv[1];
    conference_id = make_id((char *)conference_name, strlen(conference_name));

    /* ------------------------------------------------------------------------------------------------ */
    /* looking for a conference */
    switch_mutex_lock(globals.mutex_conferences);
    conference = switch_core_inthash_find(globals.conferences_hash, conference_id);
    if(!conference) {
        conf_profile = conference_profile_lookup(profile_name);
        if(!conf_profile) {
            switch_mutex_unlock(globals.mutex_conferences);
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unknown conference profile: '%s'\n", profile_name);
            switch_channel_set_variable(channel, SWITCH_CURRENT_APPLICATION_RESPONSE_VARIABLE, "Profile not found!");
            switch_goto_status(SWITCH_STATUS_SUCCESS, out);
        }

        if(switch_core_new_memory_pool(&pool_tmp) != SWITCH_STATUS_SUCCESS) {
            switch_mutex_unlock(globals.mutex_conferences);
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference_name);
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }

        if((conference = switch_core_alloc(pool_tmp, sizeof(conference_t))) == NULL) {
            switch_mutex_unlock(globals.mutex_conferences);
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference_name);
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }

        switch_mutex_init(&conference->mutex, SWITCH_MUTEX_NESTED, pool_tmp);
        switch_mutex_init(&conference->mutex_sequence, SWITCH_MUTEX_NESTED, pool_tmp);
        switch_mutex_init(&conference->mutex_listeners, SWITCH_MUTEX_NESTED, pool_tmp);
        switch_mutex_init(&conference->mutex_speakers, SWITCH_MUTEX_NESTED, pool_tmp);
        switch_mutex_init(&conference->mutex_flags, SWITCH_MUTEX_NESTED, pool_tmp);
        switch_mutex_init(&conference->mutex_playback, SWITCH_MUTEX_NESTED, pool_tmp);
        switch_queue_create(&conference->commands_q_in, globals.local_queue_size, pool_tmp);
        switch_queue_create(&conference->audio_q_in, globals.local_queue_size, pool_tmp);
        switch_queue_create(&conference->audio_mix_q_in, globals.local_queue_size, pool_tmp);
        switch_queue_create(&conference->audio_q_out, globals.local_queue_size, pool_tmp);
        switch_core_inthash_init(&conference->speakers);
        switch_core_inthash_init(&conference->listeners);
        switch_core_hash_init(&conference->members_idx_hash);

        conference->id = conference_id;
        conference->pool = pool_tmp;
        conference->name = switch_core_strdup(pool_tmp, conference_name);
        conference->admin_pin_code = (conf_profile->admin_pin_code ? switch_core_strdup(pool_tmp, conf_profile->admin_pin_code) : NULL);
        conference->user_pin_code = (conf_profile->user_pin_code ? switch_core_strdup(pool_tmp, conf_profile->user_pin_code) : NULL);
        conference->samplerate = conf_profile->samplerate;
        conference->channels = conf_profile->channels;
        conference->ptime = conf_profile->ptime;
        conference->conf_term_timer = conf_profile->conf_term_timer;
        conference->group_term_timer = conf_profile->group_term_timer;
        conference->vad_lvl = conf_profile->vad_level;
        conference->cng_lvl = conf_profile->cng_level;
        conference->user_controls = controls_profile_lookup(conf_profile->user_controls);
        conference->admin_controls = controls_profile_lookup(conf_profile->admin_controls);
        conference->playback_handle = switch_core_alloc(pool_tmp, sizeof(switch_file_handle_t));
        conference->agc_lvl = 0;
        conference->agc_low_lvl = 0;
        conference->agc_margin = 20;
        conference->agc_change_factor = 3;
        conference->flags = 0x0;
        conference->fl_ready = false;
        //
        conference->tts_engine = conf_profile->tts_engine;
        conference->tts_voice = conf_profile->tts_voice;
        //
        conference->sound_prefix_path = conf_profile->sound_prefix_path;
        conference->sound_moh = conf_profile->sound_moh;
        conference->sound_enter_pin_code = conf_profile->sound_enter_pin_code;
        conference->sound_bad_pin_code = conf_profile->sound_bad_pin_code;
        conference->sound_member_join = conf_profile->sound_member_join;
        conference->sound_member_leave = conf_profile->sound_member_leave;
        conference->sound_member_welcome = conf_profile->sound_member_welcome;
        conference->sound_member_bye = conf_profile->sound_member_bye;
        conference->sound_member_alone = conf_profile->sound_member_alone;
        conference->sound_member_kicked = conf_profile->sound_member_kicked;
        conference->sound_member_muted = conf_profile->sound_member_muted;
        conference->sound_member_unmuted = conf_profile->sound_member_unmuted;
        conference->sound_member_admin = conf_profile->sound_member_admin;
        conference->sound_member_unadmin = conf_profile->sound_member_unadmin;
        conference->sound_member_speaker = conf_profile->sound_member_speaker;
        conference->sound_member_unspeaker = conf_profile->sound_member_unspeaker;

        if(conf_profile->agc_data) {
            conference_parse_agc_data(conference, conf_profile->agc_data);
        }

        conference_flag_set(conference, CF_AUDIO_TRANSCODE, conf_profile->audio_transcode_enabled);
        conference_flag_set(conference, CF_VIDEO_TRANSCODE, conf_profile->video_transcode_enabled);
        conference_flag_set(conference, CF_ALONE_SOUND, conf_profile->alone_sound_enabled);
        conference_flag_set(conference, CF_USE_AUTH, conf_profile->pin_auth_enabled);
        conference_flag_set(conference, CF_USE_VAD, conf_profile->vad_enabled);
        conference_flag_set(conference, CF_USE_AGC, conf_profile->agc_enabled);
        conference_flag_set(conference, CF_USE_CNG, conf_profile->cng_enabled);

        launch_thread(pool_tmp, conference_control_thread, conference);
        launch_thread(pool_tmp, conference_audio_capture_thread, conference);
        launch_thread(pool_tmp, conference_audio_produce_thread, conference);

        switch_core_inthash_insert(globals.conferences_hash, conference_id, conference);

        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "--> conference '%s' created\n", conference->name);
    }
    switch_mutex_unlock(globals.mutex_conferences);

    /* ------------------------------------------------------------------------------------------------ */
    /* member */
    while(!conference->fl_ready) {
        if(conference->fl_destroyed || conference->fl_do_destroy) {
            goto out;
        }
        switch_yield(10000);
    }

    seesion_pool = switch_core_session_get_pool(session);
    if((member = switch_core_alloc(seesion_pool, sizeof(member_t))) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference_name);
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }

    member->fl_ready = false;
    member->pool = seesion_pool;
    member->session = session;
    member->id = conference_assign_member_id(conference);

    switch_core_session_get_read_impl(session, &read_impl);
    switch_core_session_get_write_impl(session, &write_impl);

    switch_mutex_init(&member->mutex, SWITCH_MUTEX_NESTED, seesion_pool);
    switch_mutex_init(&member->mutex_audio, SWITCH_MUTEX_NESTED, seesion_pool);
    switch_mutex_init(&member->mutex_flags, SWITCH_MUTEX_NESTED, seesion_pool);
    switch_mutex_init(&member->mutex_agc, SWITCH_MUTEX_NESTED, seesion_pool);
    switch_mutex_init(&member->mutex_playback, SWITCH_MUTEX_NESTED, seesion_pool);

    member->codec_name = switch_channel_get_variable(channel, "read_codec");
    member->session_id = switch_core_session_get_uuid(session);
    member->ptime = (read_impl.microseconds_per_packet / 1000);
    member->samplerate = read_impl.samples_per_second;
    member->channels = read_impl.number_of_channels;
    member->read_codec = switch_core_session_get_read_codec(session);
    member->write_codec = switch_core_session_get_write_codec(session);
    member->au_buffer = switch_core_session_alloc(session, AUDIO_BUFFER_SIZE);
    member->playback_handle = switch_core_session_alloc(session, sizeof(switch_file_handle_t));
    member->caller_id = switch_channel_get_variable(channel, "caller_id_number");
    member->flags = 0x0;
    member->fl_au_rdy_wr = true;

    session_id = member->session_id;
    write_frame.data = switch_core_session_alloc(session, AUDIO_BUFFER_SIZE);
    member->samples_ptime = (((read_impl.samples_per_second / 1000) * member->ptime) * read_impl.number_of_channels);

    /* comfort noises */
    cn_buffer_size = (member->samples_ptime * 2);
    cn_buffer = switch_core_session_alloc(session, cn_buffer_size);

    if(!member->read_codec || !member->write_codec) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: channel has no media\n", session_id);
        switch_channel_set_variable(channel, SWITCH_CURRENT_APPLICATION_RESPONSE_VARIABLE, "Channel has no media!");
        goto out;
    }
    if(member->au_buffer == NULL || member->playback_handle == NULL || write_frame.data == NULL || cn_buffer == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", session_id);
        switch_channel_set_variable(channel, SWITCH_CURRENT_APPLICATION_RESPONSE_VARIABLE, "Not enough memory!");
        goto out;
    }
    if(member->samples_ptime > AUDIO_BUFFER_SIZE) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "oops: samples_per_ptime > %i (hangup session: %s)\n", AUDIO_BUFFER_SIZE, session_id);
        switch_channel_set_variable(channel, SWITCH_CURRENT_APPLICATION_RESPONSE_VARIABLE, "Wrong buffer size!");
        goto out;
    }
    if(switch_core_timer_init(&timer, "soft", member->ptime, member->samplerate, seesion_pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: timer fail\n", session_id);
        switch_channel_set_variable(channel, SWITCH_CURRENT_APPLICATION_RESPONSE_VARIABLE, "Timer fail!");
        goto out;
    }

    /* flags */
    member_flag_set(member, MF_VAD, conference_flag_test(conference, CF_USE_VAD));
    member_flag_set(member, MF_AGC, conference_flag_test(conference, CF_USE_AGC));
    member_flag_set(member, MF_CNG, conference_flag_test(conference, CF_USE_CNG));
    member_flag_set(member, MF_AUTHORIZED, !conference_flag_test(conference, CF_USE_AUTH));

    for(int i = 2; i < argc; i++) {
        uint8_t fl_op = (argv[i][0] == '+' ? true : false);
        char *fl_name = (char *)(argv[i] + 1);

        member_parse_flags(member, fl_name, fl_op);
    }

    if(listener_join_to_group(&group, conference, member) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: couldn't find group for a new member (%s)\n", conference_name, session_id);
        goto out;
    }

    member->fl_ready = true;

    /* take semaphore's */
    conference_sem_take(conference);
    //group_sem_take(group);

    /* copy conf settings */
    member->user_controls = conference->user_controls;
    member->admin_controls = conference->admin_controls;
    member->vad_lvl = conference->vad_lvl;
    member->agc_lvl = conference->agc_lvl;
    member->agc_low_lvl = conference->agc_low_lvl;
    member->agc_margin = conference->agc_margin;
    member->agc_change_factor = conference->agc_change_factor;
    member->agc_period_len = ((1000 / member->ptime) * 2);

    /* agc */
    switch_agc_create(&member->agc, member->agc_lvl, member->agc_low_lvl, member->agc_margin, member->agc_change_factor, member->agc_period_len);
    switch_agc_set_token(member->agc, switch_channel_get_name(channel));

    /* increase membr counter */
    switch_mutex_lock(conference->mutex);
    switch_core_hash_insert(conference->members_idx_hash, member->session_id, member);
    conference->members_local++;
    switch_mutex_unlock(conference->mutex);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "member '%s' joined to '%s' [group: %03i, authorized: %i]\n", member->session_id, conference->name, group->id, member_flag_test(member, MF_AUTHORIZED));

    while(true) {
        if(!switch_channel_ready(channel) || globals.fl_shutdown || !conference->fl_ready) {
            break;
        }

        /* authorization */
        if(auth_attempts == 0 || member_flag_test(member, MF_KICK)) {
            break;
        }
        if(!member_flag_test(member, MF_AUTHORIZED)) {
            if(zstr(conference->admin_pin_code) || zstr(conference->user_pin_code)) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s: admin or user pin is empty\n", conference->name);
                break;
            }
            if(!pin_code_len) {
                pin_code_len = MAX(strlen(conference->admin_pin_code), strlen(conference->user_pin_code));
            }
            if(fl_play_enter_pin) {
                member_playback(member, conference->sound_enter_pin_code, false, pin_code_buffer, sizeof(pin_code_buffer));
                fl_play_enter_pin = false;
            }
            status = SWITCH_STATUS_FALSE;
            if(strlen(pin_code_buffer) < pin_code_len) {
                char *p = (pin_code_buffer + strlen(pin_code_buffer));
                char term = '\0';

                status = switch_ivr_collect_digits_count(session, p, sizeof(pin_code_buffer) - strlen(pin_code_buffer), pin_code_len - strlen(pin_code_buffer), "#", &term, 10000, 0, 0);
                if(status == SWITCH_STATUS_TIMEOUT) {
                    status = SWITCH_STATUS_SUCCESS;
                }
            } else {
                status = SWITCH_STATUS_SUCCESS;
            }
            if(status == SWITCH_STATUS_SUCCESS) {
                if(!zstr(pin_code_buffer)) {
                    if(strcmp(pin_code_buffer, conference->admin_pin_code) == 0) {
                        member_flag_set(member, MF_AUTHORIZED, true);
                        member_flag_set(member, MF_ADMIN, true);
                    } else if(strcmp(pin_code_buffer, conference->user_pin_code) == 0) {
                        member_flag_set(member, MF_AUTHORIZED, true);
                        member_flag_set(member, MF_ADMIN, false);
                    }
                }
                if(!member_flag_test(member, MF_AUTHORIZED)) {
                    auth_attempts--;
                    memset(pin_code_buffer, 0, sizeof(pin_code_buffer));
                    member_playback(member, conference->sound_bad_pin_code, false, NULL, 0);
                } else {
                    auth_attempts = MEMBER_AUTH_ATTEMPTS;
                    pin_code_len = 0;
                }
            }
            if(!member_flag_test(member, MF_AUTHORIZED)) {
                switch_yield(50000);
                continue;
            }
        }

        /* welcome sound */
        if(fl_play_welcome) {
            member_playback(member, conference->sound_member_welcome, false, NULL, 0);
            fl_play_welcome = false;
        }

        /* alone sound */
        if(conference_flag_test(conference, CF_ALONE_SOUND)) {
            if(conference->members_local == 1) {
                if(globals.fl_dm_enabled) {
                    if(conference->members_total <= 1) {
                        if(fl_play_alone) {
                            member_playback(member, conference->sound_member_alone, false, NULL, 0);
                            member_playback(member, conference->sound_moh, true, NULL, 0);
                            moh_check_timer = (switch_epoch_time_now(NULL) + MEMBER_MOH_CHECK_INTERVAL);
                            fl_play_alone = false;
                        }
                    }
                } else {
                    if(fl_play_alone) {
                        member_playback(member, conference->sound_member_alone, false, NULL, 0);
                        member_playback(member, conference->sound_moh, true, NULL, 0);
                        moh_check_timer = (switch_epoch_time_now(NULL) + MEMBER_MOH_CHECK_INTERVAL);
                        fl_play_alone = false;
                    }
                }
                if(!fl_play_alone && (moh_check_timer > 0 && moh_check_timer <= switch_epoch_time_now(NULL))) {
                    if(!zstr(conference->sound_moh)) {
                        if(!member_flag_test(member, MF_PLAYBACK)) {
                            fl_play_alone = true;
                        } else {
                            moh_check_timer = (switch_epoch_time_now(NULL) + MEMBER_MOH_CHECK_INTERVAL);
                        }
                    }
                }
            } else {
                if(!fl_play_alone) {
                    member_playback_stop(member);
                }
                moh_check_timer = 0;
                fl_play_alone = true;
            }
        }

        /* audio */
        if(member->au_data_len && au_buffer_id_local != member->au_buffer_id) {
            switch_mutex_lock(member->mutex_audio);
            member->fl_au_rdy_wr = false;
            switch_mutex_unlock(member->mutex_audio);

            write_frame.codec = member->write_codec;
            write_frame.buflen = member->au_data_len;
            write_frame.datalen = member->samples_ptime;
            write_frame.samples = member->samples_ptime;

            memcpy(write_frame.data, member->au_buffer, member->au_data_len);
            au_buffer_id_local = member->au_buffer_id;
            member->au_data_len = 0;

            switch_core_session_write_frame(session, &write_frame, SWITCH_IO_FLAG_NONE, 0);

            switch_mutex_lock(member->mutex_audio);
            member->fl_au_rdy_wr = true;
            switch_mutex_unlock(member->mutex_audio);
        } else {
            if(member_can_hear_cn(conference, member)) {
                uint32_t bytes = cn_buffer_size;

                if((member_generate_comfort_noises(conference, member, cn_buffer, &bytes) == SWITCH_STATUS_SUCCESS) && bytes > 0) {
                    write_frame.codec = member->write_codec;
                    write_frame.buflen = bytes;
                    write_frame.datalen = member->samples_ptime;
                    write_frame.samples = member->samples_ptime;

                    memcpy(write_frame.data, cn_buffer, bytes);
                    switch_core_session_write_frame(session, &write_frame, SWITCH_IO_FLAG_NONE, 0);
                }
            }
        }

        /* dtmf */
        if(dtmf_timer && dtmf_timer <= switch_epoch_time_now(NULL)) {
            if(dtmf_buf_pos >= 1) {
                dtmf_cmd_buffer[dtmf_buf_pos] = '\0';
                if((ctl_action = controls_profile_get_action(ctl_profile, (char *)dtmf_cmd_buffer)) != NULL) {
                    if(ctl_action->fnc(conference, member, ctl_action) != SWITCH_STATUS_SUCCESS) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "DTMF action fail\n");
                    }
                }
            }
            ctl_profile = NULL;
            ctl_action = NULL;
            dtmf_buf_pos = dtmf_timer = 0;
        }
        if(switch_channel_has_dtmf(channel)) {
            if(!ctl_profile) {
                ctl_profile = (member_flag_test(member, MF_ADMIN) ? member->admin_controls : member->user_controls);
            }
            if(ctl_profile && !ctl_profile->fl_destroyed) {
                uint8_t clr_buf = false;
                uint32_t dtmf_len = 0;
                char *p = (char *) dtmf_cmd_buffer;

                dtmf_len = switch_channel_dequeue_dtmf_string(channel, (p + dtmf_buf_pos), (DTMF_CMD_BUFFER_SIZE - dtmf_buf_pos));
                if(dtmf_len > 0) {
                    dtmf_buf_pos += dtmf_len;

                    if(!dtmf_timer && ctl_profile->digits_len_max > 1) {
                        dtmf_timer = switch_epoch_time_now(NULL) + 1; // delay 1s
                    }
                    if(dtmf_buf_pos >= ctl_profile->digits_len_max) {
                        dtmf_cmd_buffer[dtmf_buf_pos] = '\0';
                        ctl_action = controls_profile_get_action(ctl_profile, (char *)dtmf_cmd_buffer);
                        clr_buf = (ctl_action == NULL ? true : false);
                    }
                    if(clr_buf) {
                        clr_buf = false;
                        ctl_profile = NULL;
                        ctl_action = NULL;
                        dtmf_buf_pos = dtmf_timer = 0;
                    }
                    if(ctl_action) {
                        if(ctl_action->fnc(conference, member, ctl_action) != SWITCH_STATUS_SUCCESS) {
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "DTMF action fail\n");
                        }
                        ctl_profile = NULL;
                        ctl_action = NULL;
                        dtmf_buf_pos = dtmf_timer = 0;
                        memset((char *)dtmf_cmd_buffer, 0, DTMF_CMD_BUFFER_SIZE);
                    }
                }
            }
        }

        /* flags */
        if(member_flags_old != member->flags) {
            if(member_flag_test(member, MF_KICK)) {
                break;
            }
            switch_mutex_lock(member->mutex_flags);
            if(member_flag_test(member, MF_SPEAKER) != BIT_CHECK(member_flags_old, MF_SPEAKER)) {
                if(member_flag_test(member, MF_SPEAKER)) {
                    switch_mutex_lock(conference->mutex_speakers);
                    switch_core_inthash_insert(conference->speakers, member->id, member);
                    switch_mutex_unlock(conference->mutex_speakers);

                    switch_mutex_lock(conference->mutex);
                    conference->speakers_local++;
                    switch_mutex_unlock(conference->mutex);

                    member_playback(member, conference->sound_member_speaker, false, NULL, 0);
                } else {
                    switch_mutex_lock(conference->mutex_speakers);
                    switch_core_inthash_insert(conference->speakers, member->id, member);
                    switch_mutex_unlock(conference->mutex_speakers);

                    switch_mutex_lock(conference->mutex);
                    conference->speakers_local--;
                    switch_mutex_unlock(conference->mutex);

                    member_playback(member, conference->sound_member_unspeaker, false, NULL, 0);
                }
            }
            if(member_flag_test(member, MF_ADMIN) != BIT_CHECK(member_flags_old, MF_ADMIN)) {
                member_playback(member, (member_flag_test(member, MF_ADMIN) ? conference->sound_member_admin : conference->sound_member_unadmin), false, NULL, 0);
            }
            if(member_flag_test(member, MF_MUTED) != BIT_CHECK(member_flags_old, MF_MUTED)) {
                member_playback(member, (member_flag_test(member, MF_MUTED) ? conference->sound_member_muted : conference->sound_member_unmuted), false, NULL, 0);
            }
            /* update local */
            member_flags_old = member->flags;
            switch_mutex_unlock(member->mutex_flags);
        }

        switch_core_timer_next(&timer);
    }
    goto out;

usage:
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s\n", APP_SYNTAX);

out:
    switch_core_timer_destroy(&timer);

    if(conference->fl_ready && switch_channel_ready(channel)) {
        if(member_flag_test(member, MF_KICK)) {
            member_playback(member, conference->sound_member_kicked, false, NULL, 0);
        } else {
            member_playback(member, conference->sound_member_bye, false, NULL, 0);
        }
    }

    if(member && member->fl_ready) {
        switch_mutex_lock(member->mutex);
        member->fl_ready = false;
        member->fl_au_rdy_wr = false;
        member->fl_destroyed = true;
        switch_mutex_unlock(member->mutex);

        while(member->tx_sem > 0) {
            switch_yield(100000);
            member_dlock_cnt++;
            if(member_dlock_cnt > 100) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s: Member '%s' locked! (lost '%i' semaphores)\n", member->session_id, conference->name, member->tx_sem);
                member_dlock_cnt = 0;
            }
        }

        if(member_flag_test(member, MF_SPEAKER)) {
            switch_mutex_lock(conference->mutex_speakers);
            switch_core_inthash_delete(conference->speakers, member->id);
            switch_mutex_unlock(conference->mutex_speakers);

            switch_mutex_lock(conference->mutex);
            conference->speakers_local--;
            switch_mutex_unlock(conference->mutex);
        }

        if(group && group->fl_ready) {
            switch_mutex_lock(group->mutex_members);
            switch_core_inthash_delete(group->members, member->id);
            switch_mutex_unlock(group->mutex_members);

            switch_mutex_lock(group->mutex);
            if(group->free < group->capacity) {
                group->free++;
            }
            switch_mutex_unlock(group->mutex);
            //group_sem_release(group);
        }

        if(member->agc) {
            switch_agc_destroy(&member->agc);
        }

        switch_mutex_lock(conference->mutex);
        switch_core_hash_delete(conference->members_idx_hash, member->session_id);
        conference->members_local--;
        switch_mutex_unlock(conference->mutex);

        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "member '%s' left '%s'\n", member->session_id, conference->name);

        /* release semaphore */
        conference_sem_release(conference);
    }

    if(status != SWITCH_STATUS_SUCCESS) {
        if(pool_tmp) {
            switch_core_destroy_memory_pool(&pool_tmp);
        }
    }

    switch_safe_free(mycmd);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------------------------------------------------------------------------
#define CONFIG_NAME "xconf.conf"
SWITCH_MODULE_LOAD_FUNCTION(mod_xconf_load) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_xml_t cfg, xml, settings, param, dmsettings, conf_profiles_xml, conf_profile_xml, ctl_profiles_xml, ctl_profile_xml, ctl_xml;
    switch_api_interface_t *commands_interface;
    switch_application_interface_t *app_interface;

    memset(&globals, 0, sizeof (globals));

    switch_core_inthash_init(&globals.conferences_hash);
    switch_core_hash_init(&globals.conferences_profiles_hash);
    switch_core_hash_init(&globals.controls_profiles_hash);

    switch_mutex_init(&globals.mutex, SWITCH_MUTEX_NESTED, pool);
    switch_mutex_init(&globals.mutex_conferences, SWITCH_MUTEX_NESTED, pool);
    switch_mutex_init(&globals.mutex_conf_profiles, SWITCH_MUTEX_NESTED, pool);
    switch_mutex_init(&globals.mutex_controls_profiles, SWITCH_MUTEX_NESTED, pool);

    globals.dm_node_id = rand();
    globals.fl_dm_enabled = false;
    globals.fl_dm_auth_enabled = true;
    globals.fl_dm_encrypt_payload = true;
    globals.listener_group_capacity = 200;
    globals.audio_cache_size = 10; // (globals.listener_group_capacity / 2)
    globals.local_queue_size = 16;
    globals.dm_queue_size = 32;
    globals.dm_port_in = 65021;
    globals.dm_port_out = 65021;

    if((xml = switch_xml_open_cfg(CONFIG_NAME, &cfg, NULL)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't open: %s\n", CONFIG_NAME);
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }

    if((settings = switch_xml_child(cfg, "settings"))) {
        for (param = switch_xml_child(settings, "param"); param; param = param->next) {
            char *var = (char *) switch_xml_attr_soft(param, "name");
            char *val = (char *) switch_xml_attr_soft(param, "value");

            if(!strcasecmp(var, "listener-group-capacity")) {
                globals.listener_group_capacity = atoi(val);
            }
        }
    }

    if((dmsettings = switch_xml_child(cfg, "distributed-mode"))) {
        char *mode = (char *) switch_xml_attr_soft(dmsettings, "mode");
        char *enabled = (char *) switch_xml_attr_soft(dmsettings, "enabled");

        globals.fl_dm_enabled = (strcasecmp(enabled, "true") == 0 ? true : false);
        globals.dm_mode_name = switch_core_strdup(pool, mode);

        for (param = switch_xml_child(dmsettings, "param"); param; param = param->next) {
            char *var = (char *) switch_xml_attr_soft(param, "name");
            char *val = (char *) switch_xml_attr_soft(param, "value");

            if(!strcasecmp(var, "auth-packets")) {
                globals.fl_dm_auth_enabled = (strcasecmp(val, "true") == 0 ? true : false);
            } else if(!strcasecmp(var, "encrypt-payload")) {
                globals.fl_dm_encrypt_payload = (strcasecmp(val, "true") == 0 ? true : false);
            } else if(!strcasecmp(var, "shared-secret")) {
                globals.dm_shared_secret = switch_core_strdup(pool, val);
            } else if(!strcasecmp(var, "local-ip")) {
                globals.dm_local_ip = switch_core_strdup(pool, val);
            } else if(!strcasecmp(var, "remote-ip")) {
                globals.dm_remote_ip = switch_core_strdup(pool, val);
            } else if(!strcasecmp(var, "multicast-group")) {
                globals.dm_multicast_group = switch_core_strdup(pool, val);
            } else if(!strcasecmp(var, "port-in")) {
                globals.dm_port_in = atoi(val);
            } else if(!strcasecmp(var, "port-out")) {
                globals.dm_port_out = atoi(val);
            }
        }
    }

    if((ctl_profiles_xml = switch_xml_child(cfg, "controls-profiles"))) {
        for (ctl_profile_xml = switch_xml_child(ctl_profiles_xml, "profile"); ctl_profile_xml; ctl_profile_xml = ctl_profile_xml->next) {
            switch_memory_pool_t *tmp_pool = NULL;
            controls_profile_t *ctl_profile = NULL;

            char *name = (char *) switch_xml_attr_soft(ctl_profile_xml, "name");

            if(!name) { continue; }

            if(switch_core_hash_find(globals.controls_profiles_hash, name)) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Duplicated profile name: %s\n", name);
                continue;
            }

            /* create a new pool for each profile */
            if (switch_core_new_memory_pool(&tmp_pool) != SWITCH_STATUS_SUCCESS) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
                switch_goto_status(SWITCH_STATUS_GENERR, done);
            }

            if((ctl_profile = switch_core_alloc(tmp_pool, sizeof(controls_profile_t))) == NULL) {
                switch_core_destroy_memory_pool(&tmp_pool);
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
                switch_goto_status(SWITCH_STATUS_GENERR, done);
            }

            switch_core_hash_init(&ctl_profile->actions_hash);
            switch_mutex_init(&ctl_profile->mutex, SWITCH_MUTEX_NESTED, tmp_pool);

            ctl_profile->name = switch_core_strdup(tmp_pool, name);
            ctl_profile->pool = tmp_pool;
            ctl_profile->fl_destroyed = false;
            ctl_profile->digits_len_max = 0;
            ctl_profile->digits_len_min = 1;

            for (ctl_xml = switch_xml_child(ctl_profile_xml, "control"); ctl_xml; ctl_xml = ctl_xml->next) {
                controls_profile_action_t *profile_action = NULL;
                char *digits = (char *) switch_xml_attr_soft(ctl_xml, "digits");
                char *action = (char *) switch_xml_attr_soft(ctl_xml, "action");

                if(!digits || !action) { continue; }

                if(switch_core_hash_find(ctl_profile->actions_hash, digits)) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Duplicated action: %s (profile: %s)\n", digits, ctl_profile->name);
                    continue;
                }

                ctl_profile->digits_len_max = MAX(ctl_profile->digits_len_max, strlen(digits));
                if(ctl_profile->digits_len_max > DTMF_CMD_MAX_LEN) {
                    switch_core_destroy_memory_pool(&tmp_pool);
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "command is too long: '%s' (max: %i)\n", digits, DTMF_CMD_MAX_LEN);
                    switch_goto_status(SWITCH_STATUS_GENERR, done);
                }

                if((profile_action = switch_core_alloc(tmp_pool, sizeof(controls_profile_action_t))) == NULL) {
                    switch_core_destroy_memory_pool(&tmp_pool);
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
                    switch_goto_status(SWITCH_STATUS_GENERR, done);
                }

                profile_action->digits = switch_core_strdup(tmp_pool, digits);

                if(conf_action_parse(action, ctl_profile, profile_action) != SWITCH_STATUS_SUCCESS) {
                    switch_core_destroy_memory_pool(&tmp_pool);
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unsupported action: %s\n", action);
                    switch_goto_status(SWITCH_STATUS_GENERR, done);
                }

                /* add action into profile */
                switch_core_hash_insert(ctl_profile->actions_hash, profile_action->digits, profile_action);
            }

            /* add control profile */
            switch_core_hash_insert(globals.controls_profiles_hash, ctl_profile->name, ctl_profile);
        }
    }

    if((conf_profiles_xml = switch_xml_child(cfg, "conference-profiles"))) {
        for (conf_profile_xml = switch_xml_child(conf_profiles_xml, "profile"); conf_profile_xml; conf_profile_xml = conf_profile_xml->next) {
            conference_profile_t *conf_profile = NULL;
            char *name = (char *) switch_xml_attr_soft(conf_profile_xml, "name");

            if(!name) { continue; }

            if(switch_core_hash_find(globals.conferences_profiles_hash, name)) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Duplicated profile name: %s\n", name);
                continue;
            }

            if((conf_profile = switch_core_alloc(pool, sizeof(conference_profile_t))) == NULL) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
                switch_goto_status(SWITCH_STATUS_GENERR, done);
            }

            conf_profile->name = switch_core_strdup(pool, name);
            conf_profile->audio_transcode_enabled = true;
            conf_profile->video_transcode_enabled = true;
            conf_profile->pin_auth_enabled = false;
            conf_profile->alone_sound_enabled = true;
            conf_profile->vad_enabled = false;
            conf_profile->cng_enabled = false;
            conf_profile->agc_enabled = false;
            conf_profile->allow_video = false;
            conf_profile->channels = 1;
            conf_profile->ptime = 20;
            conf_profile->samplerate = 8000;
            conf_profile->conf_term_timer = 0;
            conf_profile->group_term_timer = 0;
            conf_profile->cng_level = 0;
            conf_profile->vad_level = 0;

            for (param = switch_xml_child(conf_profile_xml, "param"); param; param = param->next) {
                char *var = (char *) switch_xml_attr_soft(param, "name");
                char *val = (char *) switch_xml_attr_soft(param, "value");

                if(!strcasecmp(var, "audio-transcode-enable")) {
                    conf_profile->audio_transcode_enabled = (strcasecmp(val, "true") == 0 ? true : false);
                } else if(!strcasecmp(var, "video-transcode-enable")) {
                    conf_profile->video_transcode_enabled = (strcasecmp(val, "true") == 0 ? true : false);
                } else if(!strcasecmp(var, "allow-video")) {
                    conf_profile->allow_video = (strcasecmp(val, "true") == 0 ? true : false);
                } else if(!strcasecmp(var, "alone-sound-enable")) {
                    conf_profile->alone_sound_enabled = (strcasecmp(val, "true") == 0 ? true : false);
                } else if(!strcasecmp(var, "conference-term-timer")) {
                    conf_profile->conf_term_timer = atoi(val);
                } else if(!strcasecmp(var, "group-term-timer")) {
                    conf_profile->group_term_timer = atoi(val);
                } else if(!strcasecmp(var, "samplerate")) {
                    conf_profile->samplerate = atoi(val);
                } else if(!strcasecmp(var, "channels")) {
                    conf_profile->channels = atoi(val);
                } else if(!strcasecmp(var, "ptime")) {
                    conf_profile->ptime = atoi(val);
                } else if(!strcasecmp(var, "admin-controls")) {
                    conf_profile->admin_controls = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "user-controls")) {
                    conf_profile->user_controls = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "vad-enable")) {
                    conf_profile->vad_enabled = (strcasecmp(val, "true") == 0 ? true : false);
                } else if(!strcasecmp(var, "vad-level")) {
                    conf_profile->vad_level = atoi(val);
                } else if(!strcasecmp(var, "cng-enable")) {
                    conf_profile->cng_enabled = (strcasecmp(val, "true") == 0 ? true : false);
                } else if(!strcasecmp(var, "cng-level")) {
                    conf_profile->cng_level = atoi(val);
                } else if(!strcasecmp(var, "agc-enable")) {
                    conf_profile->agc_enabled = (strcasecmp(val, "true") == 0 ? true : false);
                } else if(!strcasecmp(var, "agc-data")) {
                    conf_profile->agc_data = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "pin-auth-enable")) {
                    conf_profile->pin_auth_enabled = (strcasecmp(val, "true") == 0 ? true : false);
                } else if(!strcasecmp(var, "admin-pin-code")) {
                    conf_profile->admin_pin_code = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "user-pin-code")) {
                    conf_profile->user_pin_code = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "sound-prefix")) {
                    conf_profile->sound_prefix_path = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "sound-moh")) {
                    conf_profile->sound_moh = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "sound-enter-pin-code")) {
                    conf_profile->sound_enter_pin_code = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "sound-bad-pin-code")) {
                    conf_profile->sound_bad_pin_code = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "sound-member-join")) {
                    conf_profile->sound_member_join = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "sound-member-leave")) {
                    conf_profile->sound_member_leave = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "sound-member-welcome")) {
                    conf_profile->sound_member_welcome = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "sound-member-bye")) {
                    conf_profile->sound_member_bye = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "sound-member-alone")) {
                    conf_profile->sound_member_alone = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "sound-member-kicked")) {
                    conf_profile->sound_member_kicked = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "sound-member-muted")) {
                    conf_profile->sound_member_muted = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "sound-member-unmuted")) {
                    conf_profile->sound_member_unmuted = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "sound-member-admin")) {
                    conf_profile->sound_member_admin = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "sound-member-unadmin")) {
                    conf_profile->sound_member_unadmin = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "sound-member-speaker")) {
                    conf_profile->sound_member_speaker = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "sound-member-unspeaker")) {
                    conf_profile->sound_member_unspeaker = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "tts-engine")) {
                    conf_profile->tts_engine = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "tts-voice")) {
                    conf_profile->tts_voice = switch_core_strdup(pool, val);
                }
            }

            if(conf_profile->vad_level) {
                if(conf_profile->vad_level < 0 || conf_profile->vad_level > 1800) {
                    conf_profile->vad_level = 300;
                }
            }
            if(conf_profile->cng_level) {
                if(conf_profile->cng_level < 0 || conf_profile->cng_level > 10000) {
                    conf_profile->cng_level = 1400;
                }
            }
            if(conf_profile->samplerate <= 0) {
                conf_profile->samplerate = 8000;
            }
            if(conf_profile->channels <= 0) {
                conf_profile->channels = 1;
            }
            if(conf_profile->ptime <= 0) {
                conf_profile->ptime = 20;
            }

            if(!zstr(conf_profile->admin_pin_code) && strlen(conf_profile->admin_pin_code) > PIN_CODE_MAX_LEN) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: admin pin is too long!\n", conf_profile->name);
                switch_goto_status(SWITCH_STATUS_GENERR, done);
            }
            if(!zstr(conf_profile->user_pin_code) && strlen(conf_profile->user_pin_code) > PIN_CODE_MAX_LEN) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: user pin is too long!\n", conf_profile->name);
                switch_goto_status(SWITCH_STATUS_GENERR, done);
            }

            if(zstr(conf_profile->sound_prefix_path)) {
                const char *val;
                if((val = switch_core_get_variable("sound_prefix")) && !zstr(val)) {
                    conf_profile->sound_prefix_path = switch_core_strdup(pool, val);
                }
            }
            /* put to map */
            switch_core_hash_insert(globals.conferences_profiles_hash, conf_profile->name, conf_profile);
        }
    }

    if(globals.fl_dm_enabled) {
        char *sys_uuid = NULL;

        if(!strcasecmp(globals.dm_mode_name, "multicast")) {
            globals.dm_mode = DM_MODE_MILTICAST;
            globals.fl_dm_enabled = true;
        } else if(!strcasecmp(globals.dm_mode_name, "p2p")) {
            globals.dm_mode = DM_MODE_P2P;
            globals.fl_dm_enabled = true;
        }

        if(!globals.dm_local_ip) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid parameter: local-ip\n");
            switch_goto_status(SWITCH_STATUS_GENERR, done);
        }
        if(!globals.dm_shared_secret || strlen(globals.dm_shared_secret) > DM_SHARED_SECRET_MAX_LEN) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid parameter: shared-secret\n");
            switch_goto_status(SWITCH_STATUS_GENERR, done);
        }
        if(globals.dm_port_in <= 0 || globals.dm_port_in > 0xffff) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid parameter: port-in!\n");
            switch_goto_status(SWITCH_STATUS_GENERR, done);
        }
        if(globals.dm_port_out <= 0 || globals.dm_port_out > 0xffff) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid parameter: port-out!\n");
            switch_goto_status(SWITCH_STATUS_GENERR, done);
        }

        if(globals.dm_mode == DM_MODE_MILTICAST) {
            if(!globals.dm_multicast_group) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Multicast mode requires parameter: multicast-group\n");
                switch_goto_status(SWITCH_STATUS_GENERR, done);
            }
        }

        if(globals.dm_mode == DM_MODE_P2P) {
            if(!globals.dm_remote_ip) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "P2P mode requires parameter: remote-ip\n");
                switch_goto_status(SWITCH_STATUS_GENERR, done);
            }
        }

        sys_uuid = switch_core_get_variable("core_uuid");
        if(sys_uuid) { globals.dm_node_id = make_id(sys_uuid, strlen(sys_uuid)); }

        switch_queue_create(&globals.dm_audio_queue_out, globals.dm_queue_size, pool);
        switch_queue_create(&globals.dm_command_queue_out, globals.dm_queue_size, pool);

        launch_thread(pool, dm_client_thread, NULL);
        launch_thread(pool, dm_server_thread, NULL);
    }

    *module_interface = switch_loadable_module_create_module_interface(pool, modname);
    SWITCH_ADD_API(commands_interface, "xconf", "manage conferences", xconf_cmd_function, CMD_SYNTAX);
    SWITCH_ADD_APP(app_interface, "xconf", "conferences app", "conferences app", xconf_app_api, APP_SYNTAX, SAF_NONE);

    if (switch_event_bind(modname, SWITCH_EVENT_SHUTDOWN, SWITCH_EVENT_SUBCLASS_ANY, event_handler_shutdown, NULL) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't bind event handler!\n");
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }

    globals.fl_shutdown = false;

    if(globals.fl_dm_enabled) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "xconf (%s) [distributed mode] [node-id: %X / %s / encryption: %s ]\n", XCONF_VERSION, globals.dm_node_id, globals.dm_mode_name, (globals.fl_dm_encrypt_payload ? "on" : "off"));
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "xconf (%s) [standalone mode]\n", XCONF_VERSION);
    }

done:
    if(xml) {
        switch_xml_free(xml);
    }
    return status;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_xconf_shutdown) {
    switch_hash_index_t *hidx = NULL;
    void *hval = NULL;

    switch_event_unbind_callback(event_handler_shutdown);

    globals.fl_shutdown = true;
    while (globals.active_threads > 0) {
        switch_yield(50000);
    }

    if(globals.fl_dm_enabled) {
        if(globals.dm_audio_queue_out) {
            flush_audio_queue(globals.dm_audio_queue_out);
        }
        if(globals.dm_command_queue_out) {
            flush_commands_queue(globals.dm_command_queue_out);
        }
    }

    /* conferences */
    switch_mutex_lock(globals.mutex_conferences);
    for(hidx = switch_core_hash_first_iter(globals.conferences_hash, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
        conference_t *conf = NULL;

        switch_core_hash_this(hidx, NULL, NULL, &hval);
        conf = (conference_t *) hval;

        if(conference_sem_take(conf)) {
            conf->fl_do_destroy = true;
            conference_sem_release(conf);
        }
    }
    switch_safe_free(hidx);
    switch_core_inthash_destroy(&globals.conferences_hash);
    switch_mutex_unlock(globals.mutex_conferences);

    /* controls */
    switch_mutex_lock(globals.mutex_controls_profiles);
    for(hidx = switch_core_hash_first_iter(globals.controls_profiles_hash, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
        controls_profile_t *profile = NULL;

        switch_core_hash_this(hidx, NULL, NULL, &hval);
        profile = (controls_profile_t *) hval;

        if(!profile->fl_destroyed) {
            switch_core_hash_delete(globals.controls_profiles_hash, profile->name);
            switch_core_destroy_memory_pool(&profile->pool);
        }
    }
    switch_safe_free(hidx);
    switch_core_hash_destroy(&globals.controls_profiles_hash);
    switch_mutex_unlock(globals.mutex_controls_profiles);

    /* conferences profiles */
    switch_mutex_lock(globals.mutex_conf_profiles);
    switch_core_hash_destroy(&globals.conferences_profiles_hash);
    switch_mutex_unlock(globals.mutex_conf_profiles);

    return SWITCH_STATUS_SUCCESS;
}

