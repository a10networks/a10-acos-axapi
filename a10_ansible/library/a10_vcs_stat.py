#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_vcs_stat
description:
    - Show aVCS statistics information
short_description: Configures A10 vcs.stat
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - present
          - absent
          - noop
        required: True
    a10_host:
        description:
        - Host for AXAPI authentication
        required: True
    a10_username:
        description:
        - Username for AXAPI authentication
        required: True
    a10_password:
        description:
        - Password for AXAPI authentication
        required: True
    a10_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_protocol:
        description:
        - Protocol for AXAPI authentication
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'elect_recv_err'= Receive error counter of aVCS election; 'elect_send_err'= Send error counter of aVCS election; 'elect_recv_byte'= Receive bytes counter of aVCS election; 'elect_send_byte'= Send bytes counter of aVCS election; 'elect_pdu_master_recv'= Received vMaster-PDU counter of aVCS election; 'elect_pdu_master_cand_recv'= Received MC-PDU counter of aVCS election; 'elect_pdu_slave_recv'= Received vBlade-PDU counter of aVCS election; 'elect_pdu_master_take_over_recv'= Received MTO-PDU counter of aVCS election; 'elect_pdu_unknown_recv'= Received Unknown-PDU counter of aVCS election; 'elect_pdu_master_sent'= Sent vMaster-PDU counter of aVCS election; 'elect_pdu_master_cand_sent'= Sent MC-PDU counter of aVCS election; 'elect_pdu_slave_sent'= Sent vBlade-PDU counter of aVCS election; 'elect_pdu_master_take_over_sent'= Sent MTO-PDU counter of aVCS election; 'elect_pdu_unknown_sent'= Sent Unknown-PDU counter of aVCS election; 'elect_pdu_inval'= Invalid PDU counter of aVCS election; 'elect_pdu_hw_mismatch'= PDU HW mismatch counter of aVCS election; 'elect_pdu_cluster_mismatch'= PDU Chassis-ID mismatch counter of aVCS election; 'elect_pdu_dev_id_collision'= PDU Device-ID collision counter of aVCS election; 'elect_mc_discard_master'= MC discarded vMaster-PDU counter of aVCS election; 'elect_mc_replace_master'= MC replaced vMaster-PDU counter of aVCS election; 'elect_mc_dup_masterr'= MC duplicate vMaster-PDU counter of aVCS election; 'elect_mc_reset_timer_by_mc'= MC timers reset by MC-PDU counter of aVCS election; 'elect_mc_reset_timer_by_mto'= MC timers reset by MTO-PDU counter of aVCS election; 'elect_slave_dup_master'= vBlade duplicate vMaster-PDU counter of aVCS election; 'elect_slave_discard_challenger'= vBlade discard challenger counter of aVCS election; 'elect_slave_replace_challenger'= vBlade replace challenger counter of aVCS election; 'elect_slave_dup_challenger'= vBlade duplicate challenger counter of aVCS election; 'elect_slave_discard_neighbour'= vBlade discard neighbour counter of aVCS election; 'elect_slave_too_many_neighbour'= vBlade too many neighbours counter of aVCS election; 'elect_slave_dup_neighbour'= send vBlade duplicate neighbours of aVCS election; 'elect_master_discard_challenger'= vMaster discard challenger counter of aVCS election; 'elect_master_new_challenger'= vMaster new challenger counter of aVCS election; 'elect_master_replace_challenger'= vMaster replace challenger counter of aVCS election; 'elect_master_dup_challenger'= vMaster duplicate challenger counter of aVCS election; 'elect_master_discard_neighbour'= vMaster discard neighbour counter of aVCS election; 'elect_master_too_many_neighbour'= vMaster too many neighbours counter of aVCS election; 'elect_master_dup_neighbour'= vMaster duplicate neighbours counter of aVCS election; 'elect_enter_master_cand_stat'= Enter MC counter of aVCS election; 'elect_enter_slave'= Enter vBlade counter of aVCS election; 'elect_enter_master'= Enter vMaster counter of aVCS election; 'elect_enter_master_take_over'= Enter MTO counter of aVCS election; 'elect_leave_master_cand'= Leave MC counter of aVCS election; 'elect_leave_slave'= Leave vBlade counter of aVCS election; 'elect_leave_master'= Leave vMaster counter of aVCS election; 'elect_leave_master_take_over'= Leave MTO counter of aVCS election; 'master_slave_start_err'= vMaster Start vBlade Errors counter of aVCS election; 'master_slave_start'= vMaster vBlades Started counter of aVCS election; 'master_slave_stop'= vMaster vBlades stopped counter of aVCS election; 'master_cfg_upd'= Received vMaster Configuration Updates counter of aVCS election; 'master_cfg_upd_l_fail'= vMaster Local Configuration Update Errors counter of aVCS election; 'master_cfg_upd_r_fail'= vMaster Remote Configuration Update Errors counter of aVCS election; 'master_cfg_upd_notif_err'= vMaster Configuration Update Notif Errors counter of aVCS election; 'master_cfg_upd_result_err'= vMaster Configuration Update Result Errors counter of aVCS election; 'slave_recv_err'= vBlade Receive Errors counter of aVCS election; 'slave_send_err'= vBlade Send Errors counter of aVCS election; 'slave_recv_bytes'= vBlade Received Bytes counter of aVCS election; 'slave_sent_bytes'= vBlade Sent Bytes counter of aVCS election; 'slave_n_recv'= vBlade Received Messages counter of aVCS election; 'slave_n_sent'= vBlade Sent Messages counter of aVCS election; 'slave_msg_inval'= vBlade Invalid Messages counter of aVCS election; 'slave_keepalive'= vBlade Received Keepalives counter of aVCS election; 'slave_cfg_upd'= vBlade Received Configuration Updates counter of aVCS election; 'slave_cfg_upd_fail'= vBlade Configuration Update Failures counter of aVCS election; 'daemon_n_elec_start'= times of aVCS election start; 'daemon_n_elec_stop'= times of aVCS election stop; 'daemon_recv_err'= counter of aVCS daemon receive error; 'daemon_send_err'= counter of aVCS daemon sent error; 'daemon_recv_bytes'= bytes of aVCS daemon receive; 'daemon_sent_bytes'= bytes of aVCS daemon sent; 'daemon_n_recv'= counter of aVCS daemon receive; 'daemon_n_sent'= counter of aVCS daemon sent; 'daemon_msg_inval'= counter of aVCS daemon invalid message; 'daemon_msg_handle_failure'= counter of aVCS daemon message handle failure; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            elect_master_discard_challenger:
                description:
                - "vMaster discard challenger counter of aVCS election"
            elect_pdu_master_sent:
                description:
                - "Sent vMaster-PDU counter of aVCS election"
            elect_pdu_cluster_mismatch:
                description:
                - "PDU Chassis-ID mismatch counter of aVCS election"
            daemon_sent_bytes:
                description:
                - "bytes of aVCS daemon sent"
            elect_slave_too_many_neighbour:
                description:
                - "vBlade too many neighbours counter of aVCS election"
            elect_mc_reset_timer_by_mc:
                description:
                - "MC timers reset by MC-PDU counter of aVCS election"
            elect_pdu_slave_recv:
                description:
                - "Received vBlade-PDU counter of aVCS election"
            daemon_n_elec_stop:
                description:
                - "times of aVCS election stop"
            elect_pdu_unknown_sent:
                description:
                - "Sent Unknown-PDU counter of aVCS election"
            elect_recv_byte:
                description:
                - "Receive bytes counter of aVCS election"
            elect_mc_dup_masterr:
                description:
                - "MC duplicate vMaster-PDU counter of aVCS election"
            elect_enter_master_take_over:
                description:
                - "Enter MTO counter of aVCS election"
            elect_pdu_slave_sent:
                description:
                - "Sent vBlade-PDU counter of aVCS election"
            master_slave_start_err:
                description:
                - "vMaster Start vBlade Errors counter of aVCS election"
            elect_master_replace_challenger:
                description:
                - "vMaster replace challenger counter of aVCS election"
            elect_slave_discard_challenger:
                description:
                - "vBlade discard challenger counter of aVCS election"
            elect_pdu_unknown_recv:
                description:
                - "Received Unknown-PDU counter of aVCS election"
            elect_mc_discard_master:
                description:
                - "MC discarded vMaster-PDU counter of aVCS election"
            daemon_recv_err:
                description:
                - "counter of aVCS daemon receive error"
            elect_pdu_master_recv:
                description:
                - "Received vMaster-PDU counter of aVCS election"
            slave_cfg_upd:
                description:
                - "vBlade Received Configuration Updates counter of aVCS election"
            master_cfg_upd_r_fail:
                description:
                - "vMaster Remote Configuration Update Errors counter of aVCS election"
            slave_msg_inval:
                description:
                - "vBlade Invalid Messages counter of aVCS election"
            elect_pdu_dev_id_collision:
                description:
                - "PDU Device-ID collision counter of aVCS election"
            slave_n_recv:
                description:
                - "vBlade Received Messages counter of aVCS election"
            elect_mc_reset_timer_by_mto:
                description:
                - "MC timers reset by MTO-PDU counter of aVCS election"
            master_slave_start:
                description:
                - "vMaster vBlades Started counter of aVCS election"
            elect_slave_discard_neighbour:
                description:
                - "vBlade discard neighbour counter of aVCS election"
            elect_slave_dup_neighbour:
                description:
                - "send vBlade duplicate neighbours of aVCS election"
            elect_pdu_master_cand_recv:
                description:
                - "Received MC-PDU counter of aVCS election"
            elect_master_discard_neighbour:
                description:
                - "vMaster discard neighbour counter of aVCS election"
            elect_slave_dup_master:
                description:
                - "vBlade duplicate vMaster-PDU counter of aVCS election"
            elect_send_err:
                description:
                - "Send error counter of aVCS election"
            elect_pdu_master_cand_sent:
                description:
                - "Sent MC-PDU counter of aVCS election"
            master_cfg_upd:
                description:
                - "Received vMaster Configuration Updates counter of aVCS election"
            slave_sent_bytes:
                description:
                - "vBlade Sent Bytes counter of aVCS election"
            elect_send_byte:
                description:
                - "Send bytes counter of aVCS election"
            elect_pdu_hw_mismatch:
                description:
                - "PDU HW mismatch counter of aVCS election"
            master_slave_stop:
                description:
                - "vMaster vBlades stopped counter of aVCS election"
            daemon_msg_inval:
                description:
                - "counter of aVCS daemon invalid message"
            elect_master_too_many_neighbour:
                description:
                - "vMaster too many neighbours counter of aVCS election"
            slave_keepalive:
                description:
                - "vBlade Received Keepalives counter of aVCS election"
            elect_leave_master:
                description:
                - "Leave vMaster counter of aVCS election"
            slave_recv_err:
                description:
                - "vBlade Receive Errors counter of aVCS election"
            elect_enter_master:
                description:
                - "Enter vMaster counter of aVCS election"
            elect_enter_master_cand_stat:
                description:
                - "Enter MC counter of aVCS election"
            elect_pdu_master_take_over_recv:
                description:
                - "Received MTO-PDU counter of aVCS election"
            elect_master_dup_challenger:
                description:
                - "vMaster duplicate challenger counter of aVCS election"
            elect_recv_err:
                description:
                - "Receive error counter of aVCS election"
            daemon_send_err:
                description:
                - "counter of aVCS daemon sent error"
            daemon_n_elec_start:
                description:
                - "times of aVCS election start"
            master_cfg_upd_l_fail:
                description:
                - "vMaster Local Configuration Update Errors counter of aVCS election"
            slave_n_sent:
                description:
                - "vBlade Sent Messages counter of aVCS election"
            elect_slave_replace_challenger:
                description:
                - "vBlade replace challenger counter of aVCS election"
            elect_master_dup_neighbour:
                description:
                - "vMaster duplicate neighbours counter of aVCS election"
            elect_enter_slave:
                description:
                - "Enter vBlade counter of aVCS election"
            slave_recv_bytes:
                description:
                - "vBlade Received Bytes counter of aVCS election"
            elect_slave_dup_challenger:
                description:
                - "vBlade duplicate challenger counter of aVCS election"
            daemon_msg_handle_failure:
                description:
                - "counter of aVCS daemon message handle failure"
            daemon_n_sent:
                description:
                - "counter of aVCS daemon sent"
            elect_mc_replace_master:
                description:
                - "MC replaced vMaster-PDU counter of aVCS election"
            daemon_n_recv:
                description:
                - "counter of aVCS daemon receive"
            master_cfg_upd_notif_err:
                description:
                - "vMaster Configuration Update Notif Errors counter of aVCS election"
            elect_pdu_inval:
                description:
                - "Invalid PDU counter of aVCS election"
            elect_leave_master_cand:
                description:
                - "Leave MC counter of aVCS election"
            elect_master_new_challenger:
                description:
                - "vMaster new challenger counter of aVCS election"
            daemon_recv_bytes:
                description:
                - "bytes of aVCS daemon receive"
            master_cfg_upd_result_err:
                description:
                - "vMaster Configuration Update Result Errors counter of aVCS election"
            elect_leave_slave:
                description:
                - "Leave vBlade counter of aVCS election"
            slave_send_err:
                description:
                - "vBlade Send Errors counter of aVCS election"
            elect_pdu_master_take_over_sent:
                description:
                - "Sent MTO-PDU counter of aVCS election"
            slave_cfg_upd_fail:
                description:
                - "vBlade Configuration Update Failures counter of aVCS election"
            elect_leave_master_take_over:
                description:
                - "Leave MTO counter of aVCS election"
    uuid:
        description:
        - "uuid of the object"
        required: False


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["sampling_enable","stats","uuid",]

# our imports go at the top so we fail fast.
try:
    from a10_ansible import errors as a10_ex
    from a10_ansible.axapi_http import client_factory, session_factory
    from a10_ansible.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['present', 'absent', 'noop']),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','elect_recv_err','elect_send_err','elect_recv_byte','elect_send_byte','elect_pdu_master_recv','elect_pdu_master_cand_recv','elect_pdu_slave_recv','elect_pdu_master_take_over_recv','elect_pdu_unknown_recv','elect_pdu_master_sent','elect_pdu_master_cand_sent','elect_pdu_slave_sent','elect_pdu_master_take_over_sent','elect_pdu_unknown_sent','elect_pdu_inval','elect_pdu_hw_mismatch','elect_pdu_cluster_mismatch','elect_pdu_dev_id_collision','elect_mc_discard_master','elect_mc_replace_master','elect_mc_dup_masterr','elect_mc_reset_timer_by_mc','elect_mc_reset_timer_by_mto','elect_slave_dup_master','elect_slave_discard_challenger','elect_slave_replace_challenger','elect_slave_dup_challenger','elect_slave_discard_neighbour','elect_slave_too_many_neighbour','elect_slave_dup_neighbour','elect_master_discard_challenger','elect_master_new_challenger','elect_master_replace_challenger','elect_master_dup_challenger','elect_master_discard_neighbour','elect_master_too_many_neighbour','elect_master_dup_neighbour','elect_enter_master_cand_stat','elect_enter_slave','elect_enter_master','elect_enter_master_take_over','elect_leave_master_cand','elect_leave_slave','elect_leave_master','elect_leave_master_take_over','master_slave_start_err','master_slave_start','master_slave_stop','master_cfg_upd','master_cfg_upd_l_fail','master_cfg_upd_r_fail','master_cfg_upd_notif_err','master_cfg_upd_result_err','slave_recv_err','slave_send_err','slave_recv_bytes','slave_sent_bytes','slave_n_recv','slave_n_sent','slave_msg_inval','slave_keepalive','slave_cfg_upd','slave_cfg_upd_fail','daemon_n_elec_start','daemon_n_elec_stop','daemon_recv_err','daemon_send_err','daemon_recv_bytes','daemon_sent_bytes','daemon_n_recv','daemon_n_sent','daemon_msg_inval','daemon_msg_handle_failure'])),
        stats=dict(type='dict',elect_master_discard_challenger=dict(type='str',),elect_pdu_master_sent=dict(type='str',),elect_pdu_cluster_mismatch=dict(type='str',),daemon_sent_bytes=dict(type='str',),elect_slave_too_many_neighbour=dict(type='str',),elect_mc_reset_timer_by_mc=dict(type='str',),elect_pdu_slave_recv=dict(type='str',),daemon_n_elec_stop=dict(type='str',),elect_pdu_unknown_sent=dict(type='str',),elect_recv_byte=dict(type='str',),elect_mc_dup_masterr=dict(type='str',),elect_enter_master_take_over=dict(type='str',),elect_pdu_slave_sent=dict(type='str',),master_slave_start_err=dict(type='str',),elect_master_replace_challenger=dict(type='str',),elect_slave_discard_challenger=dict(type='str',),elect_pdu_unknown_recv=dict(type='str',),elect_mc_discard_master=dict(type='str',),daemon_recv_err=dict(type='str',),elect_pdu_master_recv=dict(type='str',),slave_cfg_upd=dict(type='str',),master_cfg_upd_r_fail=dict(type='str',),slave_msg_inval=dict(type='str',),elect_pdu_dev_id_collision=dict(type='str',),slave_n_recv=dict(type='str',),elect_mc_reset_timer_by_mto=dict(type='str',),master_slave_start=dict(type='str',),elect_slave_discard_neighbour=dict(type='str',),elect_slave_dup_neighbour=dict(type='str',),elect_pdu_master_cand_recv=dict(type='str',),elect_master_discard_neighbour=dict(type='str',),elect_slave_dup_master=dict(type='str',),elect_send_err=dict(type='str',),elect_pdu_master_cand_sent=dict(type='str',),master_cfg_upd=dict(type='str',),slave_sent_bytes=dict(type='str',),elect_send_byte=dict(type='str',),elect_pdu_hw_mismatch=dict(type='str',),master_slave_stop=dict(type='str',),daemon_msg_inval=dict(type='str',),elect_master_too_many_neighbour=dict(type='str',),slave_keepalive=dict(type='str',),elect_leave_master=dict(type='str',),slave_recv_err=dict(type='str',),elect_enter_master=dict(type='str',),elect_enter_master_cand_stat=dict(type='str',),elect_pdu_master_take_over_recv=dict(type='str',),elect_master_dup_challenger=dict(type='str',),elect_recv_err=dict(type='str',),daemon_send_err=dict(type='str',),daemon_n_elec_start=dict(type='str',),master_cfg_upd_l_fail=dict(type='str',),slave_n_sent=dict(type='str',),elect_slave_replace_challenger=dict(type='str',),elect_master_dup_neighbour=dict(type='str',),elect_enter_slave=dict(type='str',),slave_recv_bytes=dict(type='str',),elect_slave_dup_challenger=dict(type='str',),daemon_msg_handle_failure=dict(type='str',),daemon_n_sent=dict(type='str',),elect_mc_replace_master=dict(type='str',),daemon_n_recv=dict(type='str',),master_cfg_upd_notif_err=dict(type='str',),elect_pdu_inval=dict(type='str',),elect_leave_master_cand=dict(type='str',),elect_master_new_challenger=dict(type='str',),daemon_recv_bytes=dict(type='str',),master_cfg_upd_result_err=dict(type='str',),elect_leave_slave=dict(type='str',),slave_send_err=dict(type='str',),elect_pdu_master_take_over_sent=dict(type='str',),slave_cfg_upd_fail=dict(type='str',),elect_leave_master_take_over=dict(type='str',)),
        uuid=dict(type='str',)
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vcs/stat"

    f_dict = {}

    return url_base.format(**f_dict)

def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k,v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module),
                                 params=query_params)
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")

def _build_dict_from_param(param):
    rv = {}

    for k,v in param.items():
        hk = _to_axapi(k)
        if isinstance(v, dict):
            v_dict = _build_dict_from_param(v)
            rv[hk] = v_dict
        elif isinstance(v, list):
            nv = [_build_dict_from_param(x) for x in v]
            rv[hk] = nv
        else:
            rv[hk] = v

    return rv

def build_envelope(title, data):
    return {
        title: data
    }

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vcs/stat"

    f_dict = {}

    return url_base.format(**f_dict)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params and params.get(x) is not None])
    
    errors = []
    marg = []
    
    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc,msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc,msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc,msg = REQUIRED_VALID
    
    if not rc:
        errors.append(msg.format(", ".join(marg)))
    
    return rc,errors

def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v is not None:
            rx = _to_axapi(x)

            if isinstance(v, dict):
                nv = _build_dict_from_param(v)
                rv[rx] = nv
            elif isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["stat"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["stat"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["stat"][k] = v
            result.update(**existing_config)
    else:
        result.update(**payload)
    return result

def create(module, result, payload):
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def update(module, result, existing_config, payload):
    try:
        post_result = module.client.post(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result, existing_config):
    payload = build_json("stat", module)
    changed_config = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return changed_config
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and not changed_config.get('changed'):
        return update(module, result, existing_config, payload)
    else:
        result["changed"] = True
        return result

def delete(module, result):
    try:
        module.client.delete(existing_url(module))
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def absent(module, result, existing_config):
    if module.check_mode:
        if existing_config:
            result["changed"] = True
            return result
        else:
            result["changed"] = False
            return result
    else:
        return delete(module, result)

def replace(module, result, existing_config, payload):
    try:
        post_result = module.client.put(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def run_command(module):
    run_errors = []

    result = dict(
        changed=False,
        original_message="",
        message="",
        result={}
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    
    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)
    
    if state == 'present':
        result = present(module, result, existing_config)

    elif state == 'absent':
        result = absent(module, result, existing_config)
    
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()