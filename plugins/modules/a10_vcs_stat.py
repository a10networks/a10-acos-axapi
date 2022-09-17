#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_vcs_stat
description:
    - Show aVCS statistics information
author: A10 Networks 2021
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        type: str
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        type: str
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        type: str
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        type: str
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        type: int
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        type: int
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        type: str
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'elect_recv_err'= Receive error counter of aVCS election;
          'elect_send_err'= Send error counter of aVCS election; 'elect_recv_byte'=
          Receive bytes counter of aVCS election; 'elect_send_byte'= Send bytes counter
          of aVCS election; 'elect_pdu_master_recv'= Received vMaster-PDU counter of aVCS
          election; 'elect_pdu_master_cand_recv'= Received MC-PDU counter of aVCS
          election; 'elect_pdu_slave_recv'= Received vBlade-PDU counter of aVCS election;
          'elect_pdu_master_take_over_recv'= Received MTO-PDU counter of aVCS election;
          'elect_pdu_unknown_recv'= Received Unknown-PDU counter of aVCS election;
          'elect_pdu_master_sent'= Sent vMaster-PDU counter of aVCS election;
          'elect_pdu_master_cand_sent'= Sent MC-PDU counter of aVCS election;
          'elect_pdu_slave_sent'= Sent vBlade-PDU counter of aVCS election;
          'elect_pdu_master_take_over_sent'= Sent MTO-PDU counter of aVCS election;
          'elect_pdu_unknown_sent'= Sent Unknown-PDU counter of aVCS election;
          'elect_pdu_inval'= Invalid PDU counter of aVCS election;
          'elect_pdu_hw_mismatch'= PDU HW mismatch counter of aVCS election;
          'elect_pdu_cluster_mismatch'= PDU Chassis-ID mismatch counter of aVCS election;
          'elect_pdu_dev_id_collision'= PDU Device-ID collision counter of aVCS election;
          'elect_mc_discard_master'= MC discarded vMaster-PDU counter of aVCS election;
          'elect_mc_replace_master'= MC replaced vMaster-PDU counter of aVCS election;
          'elect_mc_dup_masterr'= MC duplicate vMaster-PDU counter of aVCS election;
          'elect_mc_reset_timer_by_mc'= MC timers reset by MC-PDU counter of aVCS
          election; 'elect_mc_reset_timer_by_mto'= MC timers reset by MTO-PDU counter of
          aVCS election; 'elect_slave_dup_master'= vBlade duplicate vMaster-PDU counter
          of aVCS election; 'elect_slave_discard_challenger'= vBlade discard challenger
          counter of aVCS election; 'elect_slave_replace_challenger'= vBlade replace
          challenger counter of aVCS election; 'elect_slave_dup_challenger'= vBlade
          duplicate challenger counter of aVCS election; 'elect_slave_discard_neighbour'=
          vBlade discard neighbour counter of aVCS election;
          'elect_slave_too_many_neighbour'= vBlade too many neighbours counter of aVCS
          election; 'elect_slave_dup_neighbour'= send vBlade duplicate neighbours of aVCS
          election; 'elect_master_discard_challenger'= vMaster discard challenger counter
          of aVCS election; 'elect_master_new_challenger'= vMaster new challenger counter
          of aVCS election; 'elect_master_replace_challenger'= vMaster replace challenger
          counter of aVCS election; 'elect_master_dup_challenger'= vMaster duplicate
          challenger counter of aVCS election; 'elect_master_discard_neighbour'= vMaster
          discard neighbour counter of aVCS election; 'elect_master_too_many_neighbour'=
          vMaster too many neighbours counter of aVCS election;
          'elect_master_dup_neighbour'= vMaster duplicate neighbours counter of aVCS
          election; 'elect_enter_master_cand_stat'= Enter MC counter of aVCS election;
          'elect_enter_slave'= Enter vBlade counter of aVCS election;
          'elect_enter_master'= Enter vMaster counter of aVCS election;
          'elect_enter_master_take_over'= Enter MTO counter of aVCS election;
          'elect_leave_master_cand'= Leave MC counter of aVCS election;
          'elect_leave_slave'= Leave vBlade counter of aVCS election;
          'elect_leave_master'= Leave vMaster counter of aVCS election;
          'elect_leave_master_take_over'= Leave MTO counter of aVCS election;
          'master_slave_start_err'= vMaster Start vBlade Errors counter of aVCS election;
          'master_slave_start'= vMaster vBlades Started counter of aVCS election;
          'master_slave_stop'= vMaster vBlades stopped counter of aVCS election;
          'master_cfg_upd'= Received vMaster Configuration Updates counter of aVCS
          election; 'master_cfg_upd_l_fail'= vMaster Local Configuration Update Errors
          counter of aVCS election; 'master_cfg_upd_r_fail'= vMaster Remote Configuration
          Update Errors counter of aVCS election; 'master_cfg_upd_notif_err'= vMaster
          Configuration Update Notif Errors counter of aVCS election;
          'master_cfg_upd_result_err'= vMaster Configuration Update Result Errors counter
          of aVCS election; 'slave_recv_err'= vBlade Receive Errors counter of aVCS
          election; 'slave_send_err'= vBlade Send Errors counter of aVCS election;
          'slave_recv_bytes'= vBlade Received Bytes counter of aVCS election;
          'slave_sent_bytes'= vBlade Sent Bytes counter of aVCS election; 'slave_n_recv'=
          vBlade Received Messages counter of aVCS election; 'slave_n_sent'= vBlade Sent
          Messages counter of aVCS election; 'slave_msg_inval'= vBlade Invalid Messages
          counter of aVCS election; 'slave_keepalive'= vBlade Received Keepalives counter
          of aVCS election; 'slave_cfg_upd'= vBlade Received Configuration Updates
          counter of aVCS election; 'slave_cfg_upd_fail'= vBlade Configuration Update
          Failures counter of aVCS election; 'daemon_n_elec_start'= times of aVCS
          election start; 'daemon_n_elec_stop'= times of aVCS election stop;
          'daemon_recv_err'= counter of aVCS daemon receive error; 'daemon_send_err'=
          counter of aVCS daemon sent error; 'daemon_recv_bytes'= bytes of aVCS daemon
          receive; 'daemon_sent_bytes'= bytes of aVCS daemon sent; 'daemon_n_recv'=
          counter of aVCS daemon receive; 'daemon_n_sent'= counter of aVCS daemon sent;
          'daemon_msg_inval'= counter of aVCS daemon invalid message;
          'daemon_msg_handle_failure'= counter of aVCS daemon message handle failure;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            elect_recv_err:
                description:
                - "Receive error counter of aVCS election"
                type: str
            elect_send_err:
                description:
                - "Send error counter of aVCS election"
                type: str
            elect_recv_byte:
                description:
                - "Receive bytes counter of aVCS election"
                type: str
            elect_send_byte:
                description:
                - "Send bytes counter of aVCS election"
                type: str
            elect_pdu_master_recv:
                description:
                - "Received vMaster-PDU counter of aVCS election"
                type: str
            elect_pdu_master_cand_recv:
                description:
                - "Received MC-PDU counter of aVCS election"
                type: str
            elect_pdu_slave_recv:
                description:
                - "Received vBlade-PDU counter of aVCS election"
                type: str
            elect_pdu_master_take_over_recv:
                description:
                - "Received MTO-PDU counter of aVCS election"
                type: str
            elect_pdu_unknown_recv:
                description:
                - "Received Unknown-PDU counter of aVCS election"
                type: str
            elect_pdu_master_sent:
                description:
                - "Sent vMaster-PDU counter of aVCS election"
                type: str
            elect_pdu_master_cand_sent:
                description:
                - "Sent MC-PDU counter of aVCS election"
                type: str
            elect_pdu_slave_sent:
                description:
                - "Sent vBlade-PDU counter of aVCS election"
                type: str
            elect_pdu_master_take_over_sent:
                description:
                - "Sent MTO-PDU counter of aVCS election"
                type: str
            elect_pdu_unknown_sent:
                description:
                - "Sent Unknown-PDU counter of aVCS election"
                type: str
            elect_pdu_inval:
                description:
                - "Invalid PDU counter of aVCS election"
                type: str
            elect_pdu_hw_mismatch:
                description:
                - "PDU HW mismatch counter of aVCS election"
                type: str
            elect_pdu_cluster_mismatch:
                description:
                - "PDU Chassis-ID mismatch counter of aVCS election"
                type: str
            elect_pdu_dev_id_collision:
                description:
                - "PDU Device-ID collision counter of aVCS election"
                type: str
            elect_mc_discard_master:
                description:
                - "MC discarded vMaster-PDU counter of aVCS election"
                type: str
            elect_mc_replace_master:
                description:
                - "MC replaced vMaster-PDU counter of aVCS election"
                type: str
            elect_mc_dup_masterr:
                description:
                - "MC duplicate vMaster-PDU counter of aVCS election"
                type: str
            elect_mc_reset_timer_by_mc:
                description:
                - "MC timers reset by MC-PDU counter of aVCS election"
                type: str
            elect_mc_reset_timer_by_mto:
                description:
                - "MC timers reset by MTO-PDU counter of aVCS election"
                type: str
            elect_slave_dup_master:
                description:
                - "vBlade duplicate vMaster-PDU counter of aVCS election"
                type: str
            elect_slave_discard_challenger:
                description:
                - "vBlade discard challenger counter of aVCS election"
                type: str
            elect_slave_replace_challenger:
                description:
                - "vBlade replace challenger counter of aVCS election"
                type: str
            elect_slave_dup_challenger:
                description:
                - "vBlade duplicate challenger counter of aVCS election"
                type: str
            elect_slave_discard_neighbour:
                description:
                - "vBlade discard neighbour counter of aVCS election"
                type: str
            elect_slave_too_many_neighbour:
                description:
                - "vBlade too many neighbours counter of aVCS election"
                type: str
            elect_slave_dup_neighbour:
                description:
                - "send vBlade duplicate neighbours of aVCS election"
                type: str
            elect_master_discard_challenger:
                description:
                - "vMaster discard challenger counter of aVCS election"
                type: str
            elect_master_new_challenger:
                description:
                - "vMaster new challenger counter of aVCS election"
                type: str
            elect_master_replace_challenger:
                description:
                - "vMaster replace challenger counter of aVCS election"
                type: str
            elect_master_dup_challenger:
                description:
                - "vMaster duplicate challenger counter of aVCS election"
                type: str
            elect_master_discard_neighbour:
                description:
                - "vMaster discard neighbour counter of aVCS election"
                type: str
            elect_master_too_many_neighbour:
                description:
                - "vMaster too many neighbours counter of aVCS election"
                type: str
            elect_master_dup_neighbour:
                description:
                - "vMaster duplicate neighbours counter of aVCS election"
                type: str
            elect_enter_master_cand_stat:
                description:
                - "Enter MC counter of aVCS election"
                type: str
            elect_enter_slave:
                description:
                - "Enter vBlade counter of aVCS election"
                type: str
            elect_enter_master:
                description:
                - "Enter vMaster counter of aVCS election"
                type: str
            elect_enter_master_take_over:
                description:
                - "Enter MTO counter of aVCS election"
                type: str
            elect_leave_master_cand:
                description:
                - "Leave MC counter of aVCS election"
                type: str
            elect_leave_slave:
                description:
                - "Leave vBlade counter of aVCS election"
                type: str
            elect_leave_master:
                description:
                - "Leave vMaster counter of aVCS election"
                type: str
            elect_leave_master_take_over:
                description:
                - "Leave MTO counter of aVCS election"
                type: str
            master_slave_start_err:
                description:
                - "vMaster Start vBlade Errors counter of aVCS election"
                type: str
            master_slave_start:
                description:
                - "vMaster vBlades Started counter of aVCS election"
                type: str
            master_slave_stop:
                description:
                - "vMaster vBlades stopped counter of aVCS election"
                type: str
            master_cfg_upd:
                description:
                - "Received vMaster Configuration Updates counter of aVCS election"
                type: str
            master_cfg_upd_l_fail:
                description:
                - "vMaster Local Configuration Update Errors counter of aVCS election"
                type: str
            master_cfg_upd_r_fail:
                description:
                - "vMaster Remote Configuration Update Errors counter of aVCS election"
                type: str
            master_cfg_upd_notif_err:
                description:
                - "vMaster Configuration Update Notif Errors counter of aVCS election"
                type: str
            master_cfg_upd_result_err:
                description:
                - "vMaster Configuration Update Result Errors counter of aVCS election"
                type: str
            slave_recv_err:
                description:
                - "vBlade Receive Errors counter of aVCS election"
                type: str
            slave_send_err:
                description:
                - "vBlade Send Errors counter of aVCS election"
                type: str
            slave_recv_bytes:
                description:
                - "vBlade Received Bytes counter of aVCS election"
                type: str
            slave_sent_bytes:
                description:
                - "vBlade Sent Bytes counter of aVCS election"
                type: str
            slave_n_recv:
                description:
                - "vBlade Received Messages counter of aVCS election"
                type: str
            slave_n_sent:
                description:
                - "vBlade Sent Messages counter of aVCS election"
                type: str
            slave_msg_inval:
                description:
                - "vBlade Invalid Messages counter of aVCS election"
                type: str
            slave_keepalive:
                description:
                - "vBlade Received Keepalives counter of aVCS election"
                type: str
            slave_cfg_upd:
                description:
                - "vBlade Received Configuration Updates counter of aVCS election"
                type: str
            slave_cfg_upd_fail:
                description:
                - "vBlade Configuration Update Failures counter of aVCS election"
                type: str
            daemon_n_elec_start:
                description:
                - "times of aVCS election start"
                type: str
            daemon_n_elec_stop:
                description:
                - "times of aVCS election stop"
                type: str
            daemon_recv_err:
                description:
                - "counter of aVCS daemon receive error"
                type: str
            daemon_send_err:
                description:
                - "counter of aVCS daemon sent error"
                type: str
            daemon_recv_bytes:
                description:
                - "bytes of aVCS daemon receive"
                type: str
            daemon_sent_bytes:
                description:
                - "bytes of aVCS daemon sent"
                type: str
            daemon_n_recv:
                description:
                - "counter of aVCS daemon receive"
                type: str
            daemon_n_sent:
                description:
                - "counter of aVCS daemon sent"
                type: str
            daemon_msg_inval:
                description:
                - "counter of aVCS daemon invalid message"
                type: str
            daemon_msg_handle_failure:
                description:
                - "counter of aVCS daemon message handle failure"
                type: str

'''

RETURN = r'''
modified_values:
    description:
    - Values modified (or potential changes if using check_mode) as a result of task operation
    returned: changed
    type: dict
axapi_calls:
    description: Sequential list of AXAPI calls made by the task
    returned: always
    type: list
    elements: dict
    contains:
        endpoint:
            description: The AXAPI endpoint being accessed.
            type: str
            sample:
                - /axapi/v3/slb/virtual_server
                - /axapi/v3/file/ssl-cert
        http_method:
            description:
            - HTTP method being used by the primary task to interact with the AXAPI endpoint.
            type: str
            sample:
                - POST
                - GET
        request_body:
            description: Params used to query the AXAPI
            type: complex
        response_body:
            description: Response from the AXAPI
            type: complex
'''

EXAMPLES = """
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["sampling_enable", "stats", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({'uuid': {'type': 'str', },
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'elect_recv_err', 'elect_send_err', 'elect_recv_byte', 'elect_send_byte', 'elect_pdu_master_recv', 'elect_pdu_master_cand_recv', 'elect_pdu_slave_recv', 'elect_pdu_master_take_over_recv', 'elect_pdu_unknown_recv', 'elect_pdu_master_sent', 'elect_pdu_master_cand_sent', 'elect_pdu_slave_sent', 'elect_pdu_master_take_over_sent', 'elect_pdu_unknown_sent', 'elect_pdu_inval', 'elect_pdu_hw_mismatch', 'elect_pdu_cluster_mismatch', 'elect_pdu_dev_id_collision', 'elect_mc_discard_master', 'elect_mc_replace_master', 'elect_mc_dup_masterr', 'elect_mc_reset_timer_by_mc', 'elect_mc_reset_timer_by_mto', 'elect_slave_dup_master', 'elect_slave_discard_challenger', 'elect_slave_replace_challenger', 'elect_slave_dup_challenger', 'elect_slave_discard_neighbour', 'elect_slave_too_many_neighbour', 'elect_slave_dup_neighbour', 'elect_master_discard_challenger', 'elect_master_new_challenger', 'elect_master_replace_challenger', 'elect_master_dup_challenger', 'elect_master_discard_neighbour', 'elect_master_too_many_neighbour', 'elect_master_dup_neighbour', 'elect_enter_master_cand_stat', 'elect_enter_slave', 'elect_enter_master', 'elect_enter_master_take_over', 'elect_leave_master_cand', 'elect_leave_slave', 'elect_leave_master', 'elect_leave_master_take_over', 'master_slave_start_err', 'master_slave_start', 'master_slave_stop', 'master_cfg_upd', 'master_cfg_upd_l_fail', 'master_cfg_upd_r_fail', 'master_cfg_upd_notif_err', 'master_cfg_upd_result_err', 'slave_recv_err', 'slave_send_err', 'slave_recv_bytes', 'slave_sent_bytes', 'slave_n_recv', 'slave_n_sent', 'slave_msg_inval', 'slave_keepalive', 'slave_cfg_upd', 'slave_cfg_upd_fail', 'daemon_n_elec_start', 'daemon_n_elec_stop', 'daemon_recv_err', 'daemon_send_err', 'daemon_recv_bytes', 'daemon_sent_bytes', 'daemon_n_recv', 'daemon_n_sent', 'daemon_msg_inval', 'daemon_msg_handle_failure']}},
        'stats': {'type': 'dict', 'elect_recv_err': {'type': 'str', }, 'elect_send_err': {'type': 'str', }, 'elect_recv_byte': {'type': 'str', }, 'elect_send_byte': {'type': 'str', }, 'elect_pdu_master_recv': {'type': 'str', }, 'elect_pdu_master_cand_recv': {'type': 'str', }, 'elect_pdu_slave_recv': {'type': 'str', }, 'elect_pdu_master_take_over_recv': {'type': 'str', }, 'elect_pdu_unknown_recv': {'type': 'str', }, 'elect_pdu_master_sent': {'type': 'str', }, 'elect_pdu_master_cand_sent': {'type': 'str', }, 'elect_pdu_slave_sent': {'type': 'str', }, 'elect_pdu_master_take_over_sent': {'type': 'str', }, 'elect_pdu_unknown_sent': {'type': 'str', }, 'elect_pdu_inval': {'type': 'str', }, 'elect_pdu_hw_mismatch': {'type': 'str', }, 'elect_pdu_cluster_mismatch': {'type': 'str', }, 'elect_pdu_dev_id_collision': {'type': 'str', }, 'elect_mc_discard_master': {'type': 'str', }, 'elect_mc_replace_master': {'type': 'str', }, 'elect_mc_dup_masterr': {'type': 'str', }, 'elect_mc_reset_timer_by_mc': {'type': 'str', }, 'elect_mc_reset_timer_by_mto': {'type': 'str', }, 'elect_slave_dup_master': {'type': 'str', }, 'elect_slave_discard_challenger': {'type': 'str', }, 'elect_slave_replace_challenger': {'type': 'str', }, 'elect_slave_dup_challenger': {'type': 'str', }, 'elect_slave_discard_neighbour': {'type': 'str', }, 'elect_slave_too_many_neighbour': {'type': 'str', }, 'elect_slave_dup_neighbour': {'type': 'str', }, 'elect_master_discard_challenger': {'type': 'str', }, 'elect_master_new_challenger': {'type': 'str', }, 'elect_master_replace_challenger': {'type': 'str', }, 'elect_master_dup_challenger': {'type': 'str', }, 'elect_master_discard_neighbour': {'type': 'str', }, 'elect_master_too_many_neighbour': {'type': 'str', }, 'elect_master_dup_neighbour': {'type': 'str', }, 'elect_enter_master_cand_stat': {'type': 'str', }, 'elect_enter_slave': {'type': 'str', }, 'elect_enter_master': {'type': 'str', }, 'elect_enter_master_take_over': {'type': 'str', }, 'elect_leave_master_cand': {'type': 'str', }, 'elect_leave_slave': {'type': 'str', }, 'elect_leave_master': {'type': 'str', }, 'elect_leave_master_take_over': {'type': 'str', }, 'master_slave_start_err': {'type': 'str', }, 'master_slave_start': {'type': 'str', }, 'master_slave_stop': {'type': 'str', }, 'master_cfg_upd': {'type': 'str', }, 'master_cfg_upd_l_fail': {'type': 'str', }, 'master_cfg_upd_r_fail': {'type': 'str', }, 'master_cfg_upd_notif_err': {'type': 'str', }, 'master_cfg_upd_result_err': {'type': 'str', }, 'slave_recv_err': {'type': 'str', }, 'slave_send_err': {'type': 'str', }, 'slave_recv_bytes': {'type': 'str', }, 'slave_sent_bytes': {'type': 'str', }, 'slave_n_recv': {'type': 'str', }, 'slave_n_sent': {'type': 'str', }, 'slave_msg_inval': {'type': 'str', }, 'slave_keepalive': {'type': 'str', }, 'slave_cfg_upd': {'type': 'str', }, 'slave_cfg_upd_fail': {'type': 'str', }, 'daemon_n_elec_start': {'type': 'str', }, 'daemon_n_elec_stop': {'type': 'str', }, 'daemon_recv_err': {'type': 'str', }, 'daemon_send_err': {'type': 'str', }, 'daemon_recv_bytes': {'type': 'str', }, 'daemon_sent_bytes': {'type': 'str', }, 'daemon_n_recv': {'type': 'str', }, 'daemon_n_sent': {'type': 'str', }, 'daemon_msg_inval': {'type': 'str', }, 'daemon_msg_handle_failure': {'type': 'str', }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vcs/stat"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vcs/stat"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["stat"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["stat"].get(k) != v:
            change_results["changed"] = True
            config_changes["stat"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(
        **call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(
            **call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("stat", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def delete(module, result):
    try:
        call_result = api_client.delete(module.client, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

    return delete(module, result)


def run_command(module):
    result = dict(
        changed=False,
        messages="",
        modified_values={},
        axapi_calls=[],
        ansible_facts={},
        acos_info={}
    )

    state = module.params["state"]
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    if ansible_port == 80:
        protocol = "http"
    elif ansible_port == 443:
        protocol = "https"

    module.client = client_factory(ansible_host, ansible_port,
                                   protocol, ansible_username,
                                   ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params, requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)


    try:
        if a10_partition:
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
             result["axapi_calls"].append(
                api_client.switch_device_context(module.client, a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
        result["axapi_calls"].append(existing_config)
        if existing_config['response_body'] != 'NotFound':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["stat"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["stat-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["stat"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

if __name__ == '__main__':
    main()
