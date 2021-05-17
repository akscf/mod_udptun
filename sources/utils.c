/**
 * Copyright (C) AlexandrinKS
 * https://akscf.me/
 **/
#include "mod_xconf.h"
extern globals_t globals;

uint32_t make_id(char *name, uint32_t len) {
    return switch_crc32_8bytes((char *)name, len);
}

void launch_thread(switch_memory_pool_t *pool, switch_thread_start_t fun, void *data) {
    switch_threadattr_t *attr = NULL;
    switch_thread_t *thread = NULL;

    switch_threadattr_create(&attr, pool);
    switch_threadattr_detach_set(attr, 1);
    switch_threadattr_stacksize_set(attr, SWITCH_THREAD_STACKSIZE);
    switch_thread_create(&thread, attr, fun, data, pool);

    switch_mutex_lock(globals.mutex);
    globals.active_threads++;
    switch_mutex_unlock(globals.mutex);

    return;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------
controls_profile_t *controls_profile_lookup(char *name) {
    controls_profile_t *profile = NULL;

    if(!name || globals.fl_shutdown) { return NULL; }

    switch_mutex_lock(globals.mutex_controls_profiles);
    profile = switch_core_hash_find(globals.controls_profiles_hash, name);
    switch_mutex_unlock(globals.mutex_controls_profiles);

    return profile;
}

controls_profile_action_t *controls_profile_get_action(controls_profile_t *profile, char *digits) {
    controls_profile_action_t *action = NULL;

    if(!profile || !digits || profile->fl_destroyed || globals.fl_shutdown) { return NULL; }

    switch_mutex_lock(profile->mutex);
    action = switch_core_hash_find(profile->actions_hash, digits);
    switch_mutex_unlock(profile->mutex);

    return action;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------
inline int conference_flag_test(conference_t *confrence, int flag) {
    switch_assert(confrence);
    return BIT_CHECK(confrence->flags, flag);
}

inline void conference_flag_set(conference_t *confrence, int flag, int val) {
    switch_assert(confrence);

    switch_mutex_lock(confrence->mutex_flags);
    if(val) {
        BIT_SET(confrence->flags, flag);
    } else {
        BIT_CLEAR(confrence->flags, flag);
    }
    switch_mutex_unlock(confrence->mutex_flags);
}

conference_profile_t *conference_profile_lookup(char *name) {
    conference_profile_t *profile = NULL;

    if(!name || globals.fl_shutdown) { return NULL; }

    switch_mutex_lock(globals.mutex_conf_profiles);
    profile = switch_core_hash_find(globals.conferences_profiles_hash, name);
    switch_mutex_unlock(globals.mutex_conf_profiles);

    return profile;
}

conference_t *conference_lookup_by_name(char *name) {
    conference_t *conference = NULL;
    uint32_t id = 0;

    if(!name || globals.fl_shutdown) { return NULL; }
    id = make_id(name, strlen(name));

    switch_mutex_lock(globals.mutex_conferences);
    conference = switch_core_inthash_find(globals.conferences_hash, id);
    switch_mutex_unlock(globals.mutex_conferences);

    return conference;
}

conference_t *conference_lookup_by_id(uint32_t id) {
    conference_t *conference = NULL;

    if(globals.fl_shutdown) { return NULL; }

    switch_mutex_lock(globals.mutex_conferences);
    conference = switch_core_inthash_find(globals.conferences_hash, id);
    switch_mutex_unlock(globals.mutex_conferences);

    return conference;
}

uint32_t conference_assign_member_id(conference_t *conference) {
    uint32_t id = 0;
    switch_assert(conference);

    switch_mutex_lock(conference->mutex_sequence);
    id = conference->members_seq++;
    switch_mutex_unlock(conference->mutex_sequence);

    return id;
}

uint32_t conference_assign_group_id(conference_t *conference) {
    uint32_t id = 0;

    switch_assert(conference);

    switch_mutex_lock(conference->mutex_sequence);
    id = conference->groups_seq++;
    switch_mutex_unlock(conference->mutex_sequence);

    return id;
}

uint32_t conference_sem_take(conference_t *conference) {
    uint32_t status = false;

    if(!conference || globals.fl_shutdown) { return false; }

    switch_mutex_lock(conference->mutex);
    if(conference->fl_ready) {
        status = true;
        conference->tx_sem++;
    }
    switch_mutex_unlock(conference->mutex);

    return status;
}

void conference_sem_release(conference_t *conference) {
    switch_assert(conference);

    switch_mutex_lock(conference->mutex);
    if(conference->tx_sem) {
        conference->tx_sem--;
    }
    switch_mutex_unlock(conference->mutex);
}

switch_status_t conference_parse_flags(conference_t *conference, char *fl_name, uint8_t fl_op) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    switch_assert(conference);

    if(strcasecmp(fl_name, "trans-audio") == 0) {
        conference_flag_set(conference, CF_AUDIO_TRANSCODE, fl_op);
    } else if(strcasecmp(fl_name, "trans-video") == 0) {
        conference_flag_set(conference, CF_VIDEO_TRANSCODE, fl_op);
    } else if(strcasecmp(fl_name, "asnd") == 0) {
        conference_flag_set(conference, CF_ALONE_SOUND, fl_op);
    } else if(strcasecmp(fl_name, "video") == 0) {
        conference_flag_set(conference, CF_ALLOW_VIDEO, fl_op);
    } else if(strcasecmp(fl_name, "vad") == 0) {
        conference_flag_set(conference, CF_USE_VAD, fl_op);
    } else if(strcasecmp(fl_name, "cng") == 0) {
        conference_flag_set(conference, CF_USE_CNG, fl_op);
    } else if(strcasecmp(fl_name, "agc") == 0) {
        conference_flag_set(conference, CF_USE_AGC, fl_op);
    } else {
        status = SWITCH_STATUS_FALSE;
    }

    return status;
}

switch_status_t conference_parse_agc_data(conference_t *conference, const char *agc_data) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    char *agc_args[4] = { 0 };
    int iv;

    switch_assert(conference);
    switch_assert(agc_data);

    switch_split((char * )agc_data, ':', agc_args);
    if(agc_args[0]) {
        iv = atoi(agc_args[0]);
        if(iv > 0) { conference->agc_lvl = iv; }
    }
    if(agc_args[1]) {
        iv = atoi(agc_args[1]);
        if(iv > 0) { conference->agc_low_lvl = iv; }
    }
    if(agc_args[2]) {
        iv = atoi(agc_args[2]);
        if(iv > 0) { conference->agc_change_factor = iv; }
    }
    if(agc_args[3]) {
        iv = atoi(agc_args[3]);
        if(iv > 0) { conference->agc_margin = iv; }
    }
    return status;
}

void conference_dump_status(conference_t *conference, switch_stream_handle_t *stream) {
    stream->write_function(stream, "Node id..................: 0x%X\n", globals.dm_node_id);
    stream->write_function(stream, "Conference id............: 0x%X\n", conference->id);
    stream->write_function(stream, "Media....................: %iHz/%i/%i ms\n", conference->samplerate, conference->channels, conference->ptime);
    stream->write_function(stream, "Members (local/total)....: %i/%i\n", conference->members_local, conference->members_total);
    stream->write_function(stream, "Speakers (local/total)...: %i/%i\n", conference->speakers_local, conference->speakers_total);
    stream->write_function(stream, "Sounds path..............: %s\n", conference->sound_prefix_path);
    stream->write_function(stream, "Conf term timer..........: %i sec\n", conference->conf_term_timer);
    stream->write_function(stream, "Group term timer.........: %i sec\n", conference->group_term_timer);
    stream->write_function(stream, "VAD level................: %i\n", conference->vad_lvl);
    stream->write_function(stream, "CNG level................: %i\n", conference->cng_lvl);
    stream->write_function(stream, "AGC settings.............: %i:%i:%i:%i\n", conference->agc_lvl, conference->agc_low_lvl, conference->agc_change_factor, conference->agc_margin);
    stream->write_function(stream, "Admin pin................: %s\n", conference->admin_pin_code);
    stream->write_function(stream, "User pin.................: %s\n", conference->user_pin_code);
    stream->write_function(stream, "User controls............: %s\n", conference->user_controls ? conference->user_controls->name : "n/a");
    stream->write_function(stream, "Admin controls...........: %s\n", conference->admin_controls ? conference->admin_controls->name : "n/a");
    stream->write_function(stream, "Playback status..........: %s\n", conference_flag_test(conference, CF_PLAYBACK) ? "active" : "stopped");
    stream->write_function(stream, "Access mode..............: %s\n", conference_flag_test(conference, CF_USE_AUTH) ? "by pin" : "free");
    stream->write_function(stream, "flags....................: ---------\n");
    stream->write_function(stream, "  - audio trancode.......: %s\n", conference_flag_test(conference, CF_AUDIO_TRANSCODE) ? "on" : "off");
    stream->write_function(stream, "  - video trancode.......: %s\n", conference_flag_test(conference, CF_VIDEO_TRANSCODE) ? "on" : "off");
    stream->write_function(stream, "  - allow video..........: %s\n", conference_flag_test(conference, CF_ALLOW_VIDEO) ? "on" : "off");
    stream->write_function(stream, "  - alone sound..........: %s\n", conference_flag_test(conference, CF_ALONE_SOUND) ? "on" : "off");
    stream->write_function(stream, "  - vad..................: %s\n", conference_flag_test(conference, CF_USE_VAD) ? "on" : "off");
    stream->write_function(stream, "  - cng..................: %s\n", conference_flag_test(conference, CF_USE_CNG) ? "on" : "off");
    stream->write_function(stream, "  - agc..................: %s\n", conference_flag_test(conference, CF_USE_AGC) ? "on" : "off");
}

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
inline int member_flag_test(member_t *member, int flag) {
    switch_assert(member);
    return BIT_CHECK(member->flags, flag);
}

inline void member_flag_set(member_t *member, int flag, int value) {
    switch_assert(member);
    switch_mutex_lock(member->mutex_flags);
    if(value) {
        BIT_SET(member->flags, flag);
    } else {
        BIT_CLEAR(member->flags, flag);
    }
    switch_mutex_unlock(member->mutex_flags);
}

inline int member_can_hear(member_t *member) {
    return (member->fl_ready && !member_flag_test(member, MF_DEAF) && !member_flag_test(member, MF_PLAYBACK) && member_flag_test(member, MF_AUTHORIZED));
}

inline int member_can_hear_cn(conference_t *conference, member_t *member) {
    return (conference_flag_test(conference, CF_USE_CNG) && member_flag_test(member, MF_CNG) && !member_flag_test(member, MF_PLAYBACK));
}

inline int member_can_speak(member_t *member) {
    return (member->fl_ready && !member_flag_test(member, MF_MUTED) && member_flag_test(member, MF_AUTHORIZED));
}

uint32_t group_sem_take(member_group_t *group) {
    uint32_t status = false;

    if(!group || globals.fl_shutdown) { return false; }

    switch_mutex_lock(group->mutex);
    if(group->fl_ready) {
        status = true;
        group->tx_sem++;
    }
    switch_mutex_unlock(group->mutex);

    return status;
}

void group_sem_release(member_group_t *group) {
    switch_assert(group);

    switch_mutex_lock(group->mutex);
    if(group->tx_sem) {
        group->tx_sem--;
    }
    switch_mutex_unlock(group->mutex);
}

uint32_t member_sem_take(member_t *member) {
    uint32_t status = false;

    if(!member || globals.fl_shutdown) { return false; }

    switch_mutex_lock(member->mutex);
    if(member->fl_ready) {
        status = true;
        member->tx_sem++;
    }
    switch_mutex_unlock(member->mutex);

    return status;
}

void member_sem_release(member_t *member) {
    switch_assert(member);

    switch_mutex_lock(member->mutex);
    if(member->tx_sem) {
        member->tx_sem--;
    }
    switch_mutex_unlock(member->mutex);
}

switch_status_t member_parse_flags(member_t *member, char *fl_name, uint8_t fl_op) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    switch_assert(member);

    if(strcasecmp(fl_name, "speaker") == 0) {
        member_flag_set(member, MF_SPEAKER, fl_op);
    } else if(strcasecmp(fl_name, "admin") == 0) {
        member_flag_set(member, MF_ADMIN, fl_op);
    } else if(strcasecmp(fl_name, "mute") == 0) {
        member_flag_set(member, MF_MUTED, fl_op);
    } else if(strcasecmp(fl_name, "deaf") == 0) {
        member_flag_set(member, MF_DEAF, fl_op);
    } else if(strcasecmp(fl_name, "vad") == 0) {
        member_flag_set(member, MF_VAD, fl_op);
    } else if(strcasecmp(fl_name, "agc") == 0) {
        member_flag_set(member, MF_AGC, fl_op);
    } else if(strcasecmp(fl_name, "cng") == 0) {
        member_flag_set(member, MF_CNG, fl_op);
    } else if(strcasecmp(fl_name, "auth") == 0) {
        member_flag_set(member, MF_AUTHORIZED, fl_op);
    } else {
        status = SWITCH_STATUS_FALSE;
    }

    return status;
}

switch_status_t member_parse_agc_data(member_t *member, const char *agc_data) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    char *agc_args[4] = { 0 };
    int iv;

    switch_assert(member);
    switch_assert(agc_data);

    switch_split((char * )agc_data, ':', agc_args);
    if(agc_args[0]) {
        iv = atoi(agc_args[0]);
        if(iv > 0) { member->agc_lvl = iv; }
    }
    if(agc_args[1]) {
        iv = atoi(agc_args[1]);
        if(iv > 0) { member->agc_low_lvl = iv; }
    }
    if(agc_args[2]) {
        iv = atoi(agc_args[2]);
        if(iv > 0) { member->agc_change_factor = iv; }
    }
    if(agc_args[3]) {
        iv = atoi(agc_args[3]);
        if(iv > 0) { member->agc_margin = iv; }
    }
    return status;
}

switch_status_t member_generate_comfort_noises(conference_t *conference, member_t *member, switch_byte_t *buffer, uint32_t *buffer_size) {
    switch_byte_t tmp[AUDIO_BUFFER_SIZE] = { 0 };
    switch_status_t status = SWITCH_STATUS_FALSE;
    uint32_t data_len = member->samples_ptime * 2;
    uint32_t enc_smprt = member->samplerate;
    uint32_t enc_buffer_len = (uint32_t) *buffer_size;
    uint32_t flags = 0;

    if(conference->cng_lvl) {
        switch_generate_sln_silence((int16_t *)tmp, member->samples_ptime, member->channels, (conference->cng_lvl * (conference->samplerate / 8000)) );
        if(member->vad_silence_fade_in) {
            switch_change_sln_volume((int16_t *)tmp, (data_len / 2), (0 - member->vad_silence_fade_in));
            member->vad_silence_fade_in--;
        }
        if(switch_core_codec_ready(member->write_codec)) {
            status = switch_core_codec_encode(member->write_codec, NULL, tmp, data_len, member->samplerate, buffer, buffer_size, &enc_smprt, &flags);
        }
    }

    return status;
}

void member_dump_status(member_t *member, switch_stream_handle_t *stream) {
    stream->write_function(stream, "Group................: %03i\n", ((member_group_t *)member->group)->id);
    stream->write_function(stream, "Session id...........: %s\n", member->session_id);
    stream->write_function(stream, "Caller id............: %s\n", member->caller_id);
    stream->write_function(stream, "Media................: %iHz/%i/%ims/%s\n", member->samplerate, member->channels, member->ptime, member->codec_name);
    stream->write_function(stream, "Roles................: %s/%s\n", (member_flag_test(member, MF_ADMIN) ? "admin" : "user"), (member_flag_test(member, MF_SPEAKER) ? "speaker" : "listener"));
    stream->write_function(stream, "Gain in/out..........: %i/%i\n", member->volume_in_lvl, member->volume_out_lvl);
    stream->write_function(stream, "VAD level............: %i\n", member->vad_lvl);
    stream->write_function(stream, "AGC settings.........: %i:%i:%i:%i\n", member->agc_lvl, member->agc_low_lvl, member->agc_change_factor, member->agc_margin);
    stream->write_function(stream, "Auth status..........: %s\n", member_flag_test(member, MF_AUTHORIZED) ? "authorized" : "unauthorized");
    stream->write_function(stream, "Playback status......: %s\n", member_flag_test(member, MF_PLAYBACK) ? "active" : "stopped");
    stream->write_function(stream, "Flags................: ---------\n");
    stream->write_function(stream, "  - speaking.........: %s\n", member_flag_test(member, MF_SPEAKING) ? "yes" : "no");
    stream->write_function(stream, "  - muted............: %s\n", member_flag_test(member, MF_MUTED) ? "on" : "off");
    stream->write_function(stream, "  - deaf.............: %s\n", member_flag_test(member, MF_DEAF) ? "on" : "off");
    stream->write_function(stream, "  - vad..............: %s\n", member_flag_test(member, MF_VAD) ? "on" : "off");
    stream->write_function(stream, "  - agc..............: %s\n", member_flag_test(member, MF_AGC) ? "on" : "off");
    stream->write_function(stream, "  - cng..............: %s\n", member_flag_test(member, MF_CNG) ? "on" : "off");
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------
switch_status_t audio_tranfser_buffer_alloc(audio_tranfser_buffer_t **out, switch_byte_t *data, uint32_t data_len) {
    audio_tranfser_buffer_t *buf = NULL;

    switch_zmalloc(buf, sizeof(audio_tranfser_buffer_t));

    if(data_len) {
        switch_malloc(buf->data, data_len);
        buf->data_len = data_len;
        memcpy(buf->data, data, data_len);
    }

    *out = buf;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t audio_tranfser_buffer_clone(audio_tranfser_buffer_t **dst, audio_tranfser_buffer_t *src) {
    audio_tranfser_buffer_t *buf;

    switch_assert(src);

    switch_zmalloc(buf, sizeof(audio_tranfser_buffer_t));

    buf->id = src->id;
    buf->flags = src->flags;
    buf->conference_id = src->conference_id;
    buf->samplerate = src->samplerate;
    buf->channels = src->channels;
    buf->data_len = src->data_len;

    if(src->data_len) {
        switch_malloc(buf->data, src->data_len);
        memcpy(buf->data, src->data, src->data_len);
    }

    *dst = buf;
    return SWITCH_STATUS_SUCCESS;
}

void audio_tranfser_buffer_free(audio_tranfser_buffer_t *buf) {
    if(buf) {
        switch_safe_free(buf->data);
        switch_safe_free(buf);
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------
inline int dm_packet_flag_test(dm_packet_hdr_t *packet, int flag) {
    switch_assert(packet);
    return BIT_CHECK(packet->packet_flags, flag);
}

inline void dm_packet_flag_set(dm_packet_hdr_t *packet, int flag, int val) {
    switch_assert(packet);
    if(val) {
        BIT_SET(packet->packet_flags, flag);
    } else {
        BIT_CLEAR(packet->packet_flags, flag);
    }
}

uint32_t dm_server_clean_nodes_status_cache(switch_inthash_t *nodes_map, uint8_t flush_all) {
    switch_hash_index_t *hidx = NULL;
    node_stat_t *node_stat = NULL;
    uint32_t del_count = 0;
    const void *hvar = NULL;
    void *hval = NULL;

    switch_assert(nodes_map);

    if(flush_all) {
        for (hidx = switch_core_hash_first_iter(nodes_map, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
            switch_core_hash_this(hidx, &hvar, NULL, &hval);
            node_stat = (node_stat_t *) hval;
            if(node_stat) {
                switch_core_inthash_delete(nodes_map, node_stat->node);
                switch_safe_free(node_stat);
                del_count++;
            }
        }
    } else {
        time_t ts = switch_epoch_time_now(NULL);
        for (hidx = switch_core_hash_first_iter(nodes_map, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
            switch_core_hash_this(hidx, &hvar, NULL, &hval);
            node_stat = (node_stat_t *) hval;
            if(node_stat && node_stat->expiry < ts) {
                switch_core_inthash_delete(nodes_map, node_stat->node);
                switch_safe_free(node_stat);
                del_count++;
            }
        }
    }
    return del_count;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------
void flush_audio_queue(switch_queue_t *queue) {
    void *data = NULL;

    if(!queue || !switch_queue_size(queue)) {
        return;
    }
    while(switch_queue_trypop(queue, &data) == SWITCH_STATUS_SUCCESS) {
        if(data) {
            audio_tranfser_buffer_free((audio_tranfser_buffer_t *)data);
        }
    }
}

void flush_commands_queue(switch_queue_t *queue) {
    void *data = NULL;

    if(!queue || !switch_queue_size(queue)) {
        return;
    }
    while(switch_queue_trypop(queue, &data) == SWITCH_STATUS_SUCCESS) {
        if(data) {
            //
        }
    }
}
