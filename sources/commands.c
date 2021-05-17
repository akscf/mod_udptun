/**
 * Copyright (C) AlexandrinKS
 * https://akscf.me/
 **/
#include "mod_xconf.h"
extern globals_t globals;

//---------------------------------------------------------------------------------------------------------------------------------------------------
static switch_status_t member_cmd_hangup(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;

    member_flag_set(member, MF_KICK, true);

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t member_cmd_deaf(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;

    member_flag_set(member, MF_DEAF, !member_flag_test(member, MF_DEAF));

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t member_cmd_mute(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;

    member_flag_set(member, MF_MUTED, !member_flag_test(member, MF_MUTED));

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t member_cmd_deaf_mute(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;

    member_flag_set(member, MF_DEAF, !member_flag_test(member, MF_DEAF));
    member_flag_set(member, MF_MUTED, !member_flag_test(member, MF_MUTED));

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t member_cmd_vad_level_adj(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;
    int ival = 0;

    if(zstr(action->args)) {
       return SWITCH_STATUS_FALSE;
    }

    ival = atoi(action->args);
    if(ival == 0) {
        member->vad_lvl = conference->vad_lvl;
    } else {
        int32_t tmp = (member->vad_lvl + ival);
        if (tmp >= 0 && tmp < 1800) {
            member->vad_lvl = tmp;
        }
    }
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t member_cmd_agc_level_adj(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;
    int ival = 0;

    if(zstr(action->args)) {
       return SWITCH_STATUS_FALSE;
    }

    ival = atoi(action->args);
    if(ival == 0) {
        member->agc_lvl = conference->agc_lvl;
    } else {
        int32_t tmp = (member->agc_lvl + ival);
        if (tmp >= 0 && tmp < 1800) {
            member->agc_lvl = tmp;
        }
    }

    switch_mutex_lock(member->mutex_agc);
    if(member->agc) {
        switch_agc_set(member->agc, member->agc_lvl, member->agc_low_lvl, member->agc_margin, member->agc_change_factor, member->agc_period_len);
    }
    switch_mutex_unlock(member->mutex_agc);

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t member_cmd_vol_talk_adj(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;
    int ival = 0;

    if(zstr(action->args)) {
       return SWITCH_STATUS_FALSE;
    }

    ival = atoi(action->args);
    if(ival == 0) {
        member->volume_out_lvl = 0;
    } else {
        int32_t tmp = (member->volume_out_lvl + ival);
        if(tmp > -5 && tmp < 5) {
            member->volume_out_lvl = tmp;
        }
    }

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t member_cmd_vol_listen_adj(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;
    int ival = 0;

    if(zstr(action->args)) {
       return SWITCH_STATUS_FALSE;
    }

    ival = atoi(action->args);
    if(ival == 0) {
        member->volume_in_lvl = 0;
    } else {
        int32_t tmp = (member->volume_in_lvl + ival);
        if(tmp > -5 && tmp < 5) {
            member->volume_in_lvl = tmp;
        }
    }

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t member_cmd_playback(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;

    if(!zstr(action->args)) {
        if(strcasecmp(action->args, "stop") == 0) {
            return member_playback_stop(member);
        } else {
            return member_playback(member, action->args, true, NULL, 0);
        }
    }

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t member_cmd_swith_to_admin(void *conference_ref, void *member_ref, void *action_ref) {
    switch_status_t status = SWITCH_STATUS_FALSE;
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;
    char pin_code_buffer[PIN_CODE_BUFFER_SIZE] = { 0 };
    char term = '\0';
    uint32_t pin_code_len = 0;

    if(member_flag_test(member, MF_ADMIN)) {
        return SWITCH_STATUS_SUCCESS;
    }

    if(!zstr(conference->admin_pin_code)) {
        pin_code_len = strlen(conference->admin_pin_code);
        memset(pin_code_buffer, 0, sizeof(pin_code_buffer));

        member_playback(member, conference->sound_enter_pin_code, false, pin_code_buffer, sizeof(pin_code_buffer));

        if(strlen(pin_code_buffer) < pin_code_len) {
            char *p = (pin_code_buffer + strlen(pin_code_buffer));

            status = switch_ivr_collect_digits_count(member->session, p, sizeof(pin_code_buffer) - strlen(pin_code_buffer), pin_code_len - strlen(pin_code_buffer), "#", &term, 10000, 0, 0);
            if(status == SWITCH_STATUS_TIMEOUT) {
                status = SWITCH_STATUS_SUCCESS;
            }
        } else {
            status = SWITCH_STATUS_SUCCESS;
        }
        if(status == SWITCH_STATUS_SUCCESS) {
            if(!zstr(pin_code_buffer)) {
                if(strcmp(pin_code_buffer, conference->admin_pin_code) == 0) {
                    member_flag_set(member, MF_ADMIN, true);
                }
            }
            if(!member_flag_test(member, MF_ADMIN)) {
                member_playback(member, conference->sound_bad_pin_code, false, NULL, 0);
            }
        }
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s: admin pin code is empty\n", conference->name);
    }

    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t member_cmd_call_api(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;
    switch_stream_handle_t stream = { 0 };
    switch_status_t status;
    char *ptr = NULL, *cmd = NULL, *args = NULL;

    if(zstr(action->args)) {
        return SWITCH_STATUS_FALSE;
    }

    cmd = action->args;
    ptr = action->args;
    while (*ptr++) {
        if(*ptr == ' ') { *ptr = '\0'; args = ++ptr; break; }
    }

    SWITCH_STANDARD_STREAM(stream);

    status = switch_api_execute(cmd, args, member->session, &stream);
    if (status == SWITCH_STATUS_SUCCESS) {
        stream.write_function(&stream, "+OK\n");
    } else {
        stream.write_function(&stream, "-ERR %s\n", (stream.data ? (char *)stream.data : "unknown"));
    }

    switch_safe_free(stream.data);

    return status;
}

static switch_status_t member_cmd_exec_app(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;
    char *ptr = NULL, *cmd = NULL, *args = NULL;

    if(zstr(action->args)) {
        return SWITCH_STATUS_FALSE;
    }

    cmd = action->args;
    ptr = action->args;
    while (*ptr++) {
        if(*ptr == ' ') { *ptr = '\0'; args = ++ptr; break; }
    }

    return switch_core_session_execute_application(member->session, cmd, args);
}

/* action parser */
switch_status_t conf_action_parse(char *action_str, controls_profile_t *profile, controls_profile_action_t *action) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    switch_assert(action_str);
    switch_assert(profile);
    switch_assert(action);

    if(strcasecmp(action_str, "hangup") == 0) {
        action->args = NULL;
        action->fnc = member_cmd_hangup;
    } else if(strcasecmp(action_str, "deaf") == 0) {
        action->args = NULL;
        action->fnc = member_cmd_deaf;
    } else if(strcasecmp(action_str, "mute") == 0) {
        action->args = NULL;
        action->fnc = member_cmd_mute;
    } else if(strcasecmp(action_str, "deaf-mute") == 0) {
        action->args = NULL;
        action->fnc = member_cmd_deaf_mute;
    } else if(strcasecmp(action_str, "admin") == 0) {
        action->args = NULL;
        action->fnc = member_cmd_swith_to_admin;
    } else if(strncasecmp(action_str, "vad-level:", 10) == 0) {
        action->args = switch_core_strdup(profile->pool, action_str + 10);
        action->fnc = member_cmd_vad_level_adj;
    } else if(strncasecmp(action_str, "agc-level:", 10) == 0) {
        action->args = switch_core_strdup(profile->pool, action_str + 10);
        action->fnc = member_cmd_agc_level_adj;
    } else if(strncasecmp(action_str, "vol-talk:", 9) == 0) {
        action->args = switch_core_strdup(profile->pool, action_str + 9);
        action->fnc = member_cmd_vol_talk_adj;
    } else if(strncasecmp(action_str, "vol-listen:", 11) == 0) {
        action->args = switch_core_strdup(profile->pool, action_str + 11);
        action->fnc = member_cmd_vol_listen_adj;
    } else if(strncasecmp(action_str, "playback:", 9) == 0) {
        action->args = switch_core_strdup(profile->pool, action_str + 9);
        action->fnc = member_cmd_playback;
    } else if(strncasecmp(action_str, "api:", 4) == 0) {
        action->args = switch_core_strdup(profile->pool, action_str + 4);
        action->fnc = member_cmd_call_api;
    } else if(strncasecmp(action_str, "exec:", 5) == 0) {
        action->args = switch_core_strdup(profile->pool, action_str + 5);
        action->fnc = member_cmd_exec_app;
    } else {
        status = SWITCH_STATUS_FALSE;
    }

    return status;
}
