/**
 * Copyright (C) AlexandrinKS
 * https://akscf.me/
 **/
#include "mod_xconf.h"
extern globals_t globals;

//---------------------------------------------------------------------------------------------------------------------------------------------------
typedef struct {
    member_t    *member;
    char        *path;
    void        *dtmf_buf;
    uint32_t    dtmf_buf_len;
    uint32_t    leadin;
} member_pb_thread_params_t;

static void *SWITCH_THREAD_FUNC member_playback_async_thread(switch_thread_t *thread, void *obj) {
    volatile member_pb_thread_params_t *_ref = (member_pb_thread_params_t *) obj;
    member_pb_thread_params_t *params = (member_pb_thread_params_t *) _ref;

    member_playback(params->member, params->path, false, params->dtmf_buf, params->dtmf_buf_len);

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    switch_safe_free(params->path);
    switch_safe_free(params);
    return NULL;
}

switch_status_t member_playback_stop(member_t *member) {
    switch_status_t  status = SWITCH_STATUS_SUCCESS;
    int x = 0;

    switch_assert(member);

    if(member_sem_take(member)) {
        if(member_flag_test(member, MF_PLAYBACK)) {
            if(member->playback_handle) {
                switch_mutex_lock(member->mutex_playback);
                switch_set_flag(member->playback_handle, SWITCH_FILE_DONE);
                switch_mutex_unlock(member->mutex_playback);

                while(member_flag_test(member, MF_PLAYBACK)) {
                    if(globals.fl_shutdown || member->fl_destroyed) {
                        break;
                    }
                    if(x > 1000) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Couldn't stop playback (member: %s)\n", member->session_id);
                        status = SWITCH_STATUS_FALSE;
                        break;
                    }
                    x++;
                    switch_yield(10000);
                }
            }
        }
        member_sem_release(member);
    }
    return status;
}

switch_status_t member_playback(member_t *member, char *path, uint8_t async, void *dtmf_buf, uint32_t dtmf_buf_len) {
    switch_status_t  status = SWITCH_STATUS_FALSE;
    switch_channel_t *channel = NULL;
    switch_input_args_t *ap = NULL;
    switch_input_args_t args = { 0 };
    conference_t *conference = NULL;
    char *expanded = NULL, *dpath = NULL;

    switch_assert(member);

    if(zstr(path)) {
        return SWITCH_STATUS_NOTFOUND;
    }

    if(async) {
        member_pb_thread_params_t *params = NULL;

        switch_zmalloc(params, sizeof(member_pb_thread_params_t));
        params->member = member;
        params->path = strdup(path);
        params->dtmf_buf = dtmf_buf;
        params->dtmf_buf_len = dtmf_buf_len;

        launch_thread(member->pool, member_playback_async_thread, params);
        return SWITCH_STATUS_SUCCESS;
    }

    if(dtmf_buf) {
        args.buf = dtmf_buf;
        args.buflen = dtmf_buf_len;
        ap = &args;
    }

    if(member_sem_take(member)) {
        channel = switch_core_session_get_channel(member->session);
        conference = ((member_group_t *) member->group)->conference;

        /* stop previous sound */
        if(member_flag_test(member, MF_PLAYBACK)) {
            if((status = member_playback_stop(member)) != SWITCH_STATUS_SUCCESS) {
                member_sem_release(member);
                goto done;
            }
        }

        /* set flags */
        switch_mutex_lock(member->mutex_playback);
        member_flag_set(member, MF_PLAYBACK, true);
        memset(member->playback_handle, 0, sizeof(switch_file_handle_t));
        switch_mutex_unlock(member->mutex_playback);

        for(int x = 0; x < 10; x++) {
            switch_frame_t *read_frame;
            status = switch_core_session_read_frame(member->session, &read_frame, SWITCH_IO_FLAG_NONE, 0);
            if (!SWITCH_READ_ACCEPTABLE(status)) { break; }
        }

        /* playback */
        if(conference_sem_take(conference)) {
            if((expanded = switch_channel_expand_variables(channel, path)) != path) {
                path = expanded;
            } else {
                expanded = NULL;
            }
            if(strncasecmp(path, "say:", 4) == 0) {
                if(conference->tts_engine && conference->tts_voice) {
                    member->playback_filename = path;
                    status = switch_ivr_speak_text(member->session, conference->tts_engine, conference->tts_voice, path + 4, ap);
                } else {
                    status = SWITCH_STATUS_FALSE;
                }
            } else if(strstr(path, "://") != NULL) {
                member->playback_filename = path;
                status = switch_ivr_play_file(member->session, member->playback_handle, path, ap);
            } else {
                if(switch_file_exists(path, NULL) == SWITCH_STATUS_SUCCESS) {
                    member->playback_filename = path;
                    status = switch_ivr_play_file(member->session, member->playback_handle, path, ap);
                } else {
                    if(!switch_is_file_path(path) && conference->sound_prefix_path) {
                        if(!(dpath = switch_mprintf("%s%s%s", conference->sound_prefix_path, SWITCH_PATH_SEPARATOR, path))) {
                            status = SWITCH_STATUS_MEMERR;
                        } else {
                            member->playback_filename = dpath;
                            status = switch_ivr_play_file(member->session, member->playback_handle, dpath, ap);
                            switch_safe_free(dpath);
                        }
                    }
                }
            }
            conference_sem_release(conference);
        }

        /* clear flags */
        switch_mutex_lock(member->mutex_playback);
        member_flag_set(member, MF_PLAYBACK, false);
        member->playback_filename = NULL;
        switch_mutex_unlock(member->mutex_playback);

        member_sem_release(member);
    }
done:
    switch_safe_free(expanded);
    return status;
}

//---------------------------------------------------------------------------------------------------------------------------------------------------
typedef struct {
    conference_t    *conference;
    char            *path;
} conference_pb_thread_params_t;

static void *SWITCH_THREAD_FUNC conference_playback_async_thread(switch_thread_t *thread, void *obj) {
    volatile conference_pb_thread_params_t *_ref = (conference_pb_thread_params_t *) obj;
    conference_pb_thread_params_t *params = (conference_pb_thread_params_t *) _ref;

    conference_playback(params->conference, params->path, false);

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    switch_safe_free(params->path);
    switch_safe_free(params);
    return NULL;
}

switch_status_t conference_playback_stop(conference_t *conference) {
    switch_status_t  status = SWITCH_STATUS_SUCCESS;
    int x = 0;

    switch_assert(conference);

    if(conference_sem_take(conference)) {
        if(conference_flag_test(conference, CF_PLAYBACK)) {
            if(conference->playback_handle) {
                switch_mutex_lock(conference->mutex_playback);
                switch_set_flag(conference->playback_handle, SWITCH_FILE_DONE);
                switch_mutex_unlock(conference->mutex_playback);

                while(conference_flag_test(conference, CF_PLAYBACK)) {
                    if(globals.fl_shutdown || conference->fl_destroyed) {
                        break;
                    }
                    if(x > 1000) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s: Couldn't stop playback\n", conference->name);
                        status = SWITCH_STATUS_FALSE;
                        break;
                    }
                    x++;
                    switch_yield(10000);
                }
            }
        }
        conference_sem_release(conference);
    }
    return status;
}

switch_status_t conference_playback(conference_t *conference, char *path, uint8_t async) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_timer_t timer = { 0 };
    switch_memory_pool_t *pool = NULL;
    uint8_t fl_tts = false, fl_brk_loop = false;
    switch_byte_t *file_buffer = NULL;
    switch_size_t samples_ptime = 0;
    switch_size_t samples_read = 0;
    char *dpath = NULL;

    switch_assert(conference);

    if(zstr(path)) {
        return SWITCH_STATUS_NOTFOUND;
    }

    if(async) {
        conference_pb_thread_params_t *params = NULL;

        switch_zmalloc(params, sizeof(conference_pb_thread_params_t));
        params->conference = conference;
        params->path = strdup(path);

        launch_thread(conference->pool, conference_playback_async_thread, params);
        return SWITCH_STATUS_SUCCESS;
    }

    if(conference_sem_take(conference)) {
        if(conference_flag_test(conference, MF_PLAYBACK)) {
            if((status = conference_playback_stop(conference)) != SWITCH_STATUS_SUCCESS) {
                conference_sem_release(conference);
                goto done;
            }
        }

        if(switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "pool fail\n");
            status = SWITCH_STATUS_MEMERR;
            conference_sem_release(conference);
            goto done;
        }

        file_buffer = switch_core_alloc(pool, SWITCH_RECOMMENDED_BUFFER_SIZE);
        if(file_buffer == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "mem fail\n");
            status = SWITCH_STATUS_MEMERR;
            conference_sem_release(conference);
            goto done;
        }

        samples_ptime = switch_samples_per_packet(conference->samplerate, conference->ptime);
        if(!samples_ptime) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "samples_ptime == 0\n");
            status = SWITCH_STATUS_FALSE;
            conference_sem_release(conference);
            goto done;
        }

        /* try to open file */
        switch_mutex_lock(conference->mutex_playback);
        if(strncasecmp(path, "say:", 4) == 0) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "not yet implemented\n");
            fl_tts = true;
            status = SWITCH_STATUS_FALSE;
        } else if(strstr(path, "://") != NULL) {
            status = SWITCH_STATUS_SUCCESS;
        } else {
            if(switch_file_exists(path, NULL) != SWITCH_STATUS_SUCCESS) {
                if(conference->sound_prefix_path) {
                    if(!(dpath = switch_mprintf("%s%s%s", conference->sound_prefix_path, SWITCH_PATH_SEPARATOR, path))) {
                        status = SWITCH_STATUS_MEMERR;
                    }
                } else {
                    status = SWITCH_STATUS_NOTFOUND;
                }
            }
        }
        if(status == SWITCH_STATUS_SUCCESS) {
            char *epname = (dpath ? dpath : path);

            memset(conference->playback_handle, 0 , sizeof(switch_file_handle_t));
            if(fl_tts) {
                //
                // todo
                //
            } else {
                status = switch_core_file_open(conference->playback_handle, epname, conference->channels, conference->samplerate, (SWITCH_FILE_FLAG_READ | SWITCH_FILE_DATA_SHORT), pool);
            }
            if(status == SWITCH_STATUS_SUCCESS) {
                conference->playback_filename = path;
                conference_flag_set(conference, CF_PLAYBACK, true);
            }
        }
        switch_mutex_unlock(conference->mutex_playback);

        /* playback */
        if(status == SWITCH_STATUS_SUCCESS) {
            if(switch_core_timer_init(&timer, "soft", conference->ptime, conference->samplerate, pool) != SWITCH_STATUS_SUCCESS) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: timer fail\n", conference->name);
                goto loop_out;
            }

            while(true) {
                if(!conference->fl_ready || conference->fl_destroyed || switch_test_flag(conference->playback_handle, SWITCH_FILE_DONE)) {
                    break;
                }
                samples_read = samples_ptime;
                switch_core_file_read(conference->playback_handle, file_buffer, &samples_read);
                if(samples_read <= 0)  { break; }
                else {
                    audio_tranfser_buffer_t *atb = NULL;

                    audio_tranfser_buffer_alloc(&atb, file_buffer, (uint32_t)(samples_read * 2));
                    atb->conference_id = conference->id;
                    atb->samplerate = conference->samplerate;
                    atb->channels = conference->channels;
                    atb->id = 0;

                    if(switch_queue_trypush(conference->audio_mix_q_in, atb) != SWITCH_STATUS_SUCCESS) {
                        audio_tranfser_buffer_free(atb);
                    }

                    if(fl_brk_loop) {
                        break;
                    }
                }
                switch_core_timer_next(&timer);
            }

            loop_out:
            switch_core_timer_destroy(&timer);

            switch_set_flag(conference->playback_handle, SWITCH_FILE_DONE);
            switch_core_file_close(conference->playback_handle);

            conference_flag_set(conference, CF_PLAYBACK, false);
        }
        conference_sem_release(conference);
        switch_safe_free(dpath);
    } /* conf sem */
done:
    if(pool) {
        switch_core_destroy_memory_pool(&pool);
    }
    return status;
}
