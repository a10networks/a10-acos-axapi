#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_l4_tcp
description:
    - l4 tcp counters
author: A10 Networks
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
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            tcp_sess_create:
                description:
                - "TCP Sessions Created"
                type: str
            intcp:
                description:
                - "TCP Total Packets Received"
                type: str
            tcp_syn_rcvd:
                description:
                - "TCP SYN Received"
                type: str
            tcp_invalid_syn_rcvd:
                description:
                - "TCP Invalid SYN Received"
                type: str
            tcp_syn_ack_rcvd:
                description:
                - "TCP SYN ACK Received"
                type: str
            tcp_ack_rcvd:
                description:
                - "TCP ACK Received"
                type: str
            tcp_fin_rcvd:
                description:
                - "TCP FIN Received"
                type: str
            tcp_rst_rcvd:
                description:
                - "TCP RST Received"
                type: str
            tcp_outrst:
                description:
                - "TCP Outbound RST"
                type: str
            tcp_reset_client:
                description:
                - "TCP Reset Client"
                type: str
            tcp_reset_server:
                description:
                - "TCP Reset Server"
                type: str
            tcp_syn_rate:
                description:
                - "TCP SYN Rate Per Sec"
                type: str
            tcp_total_drop:
                description:
                - "TCP Total Packets Dropped"
                type: str
            tcp_dst_drop:
                description:
                - "TCP Dst Packets Dropped"
                type: str
            tcp_src_drop:
                description:
                - "TCP Src Packets Dropped"
                type: str
            tcp_drop_black_user_cfg_src:
                description:
                - "TCP Src Blacklist User Packets Dropped"
                type: str
            tcp_src_dst_drop:
                description:
                - "TCP SrcDst Packets Dropped"
                type: str
            tcp_drop_black_user_cfg_src_dst:
                description:
                - "TCP SrcDst Blacklist User Packets Dropped"
                type: str
            tcp_port_zero_drop:
                description:
                - "TCP Port 0 Packets Dropped"
                type: str
            tcp_syncookie_sent:
                description:
                - "TCP SYN Cookie Sent"
                type: str
            tcp_syncookie_sent_fail:
                description:
                - "TCP SYN Cookie Send Failed"
                type: str
            tcp_syncookie_check_fail:
                description:
                - "TCP SYN Cookie Check Failed"
                type: str
            tcp_syncookie_hw_missing:
                description:
                - "TCP SYN Cookie HW Missed"
                type: str
            tcp_syncookie_fail_bl:
                description:
                - "TCP SYN Cookie Blacklist Failed"
                type: str
            tcp_syncookie_pass:
                description:
                - "TCP SYN Cookie Passed"
                type: str
            syn_auth_pass:
                description:
                - "TCP SYN Auth Passed"
                type: str
            syn_auth_skip:
                description:
                - "TCP SYN Auth Skipped"
                type: str
            tcp_action_on_ack_start:
                description:
                - "TCP ACK Retry Init"
                type: str
            tcp_action_on_ack_matched:
                description:
                - "TCP ACK Retry Matched"
                type: str
            tcp_action_on_ack_passed:
                description:
                - "TCP ACK Retry Passed"
                type: str
            tcp_action_on_ack_failed:
                description:
                - "TCP ACK Retry Dropped"
                type: str
            tcp_action_on_ack_timeout:
                description:
                - "TCP ACK Retry Timeout"
                type: str
            tcp_action_on_ack_reset:
                description:
                - "TCP ACK Retry Timeout Reset"
                type: str
            tcp_ack_no_syn:
                description:
                - "TCP ACK No SYN"
                type: str
            tcp_out_of_seq:
                description:
                - "TCP Out-Of-Seq Total"
                type: str
            tcp_zero_window:
                description:
                - "TCP Zero-Window Total"
                type: str
            tcp_retransmit:
                description:
                - "TCP Retransmit Total"
                type: str
            tcp_rexmit_syn_limit_drop:
                description:
                - "TCP Retransmit SYN Exceed Dropped"
                type: str
            tcp_zero_window_bl:
                description:
                - "TCP Zero-Window Blacklisted"
                type: str
            tcp_out_of_seq_bl:
                description:
                - "TCP Out-Of-Seq Blacklisted"
                type: str
            tcp_retransmit_bl:
                description:
                - "TCP Retransmit Blacklisted"
                type: str
            tcp_rexmit_syn_limit_bl:
                description:
                - "TCP Retransmit SYN Exceed Blacklisted"
                type: str
            tcp_per_conn_prate_exceed:
                description:
                - "TCP Conn Pkt Rate Dropped"
                type: str
            tcp_action_on_ack_gap_drop:
                description:
                - "TCP ACK Retry Retry-Gap Dropped"
                type: str
            tcp_action_on_ack_gap_pass:
                description:
                - "TCP ACK Retry Retry-Gap Passed"
                type: str
            tcp_action_on_syn_start:
                description:
                - "TCP SYN Retry Init"
                type: str
            tcp_action_on_syn_passed:
                description:
                - "TCP SYN Retry Passed"
                type: str
            tcp_action_on_syn_failed:
                description:
                - "TCP SYN Retry Dropped"
                type: str
            tcp_action_on_syn_timeout:
                description:
                - "TCP SYN Retry Timeout"
                type: str
            tcp_action_on_syn_reset:
                description:
                - "TCP SYN Retry Timeout Reset"
                type: str
            tcp_action_on_syn_gap_drop:
                description:
                - "TCP SYN Retry Retry-Gap Dropped"
                type: str
            tcp_action_on_syn_gap_pass:
                description:
                - "TCP SYN Retry Retry-Gap Passed"
                type: str
            tcp_unauth_rst_drop:
                description:
                - "TCP Unauth RST Dropped"
                type: str
            dst_tcp_filter_match:
                description:
                - "Dst Filter Match"
                type: str
            dst_tcp_filter_not_match:
                description:
                - "Dst Filter No Match"
                type: str
            dst_tcp_filter_action_blacklist:
                description:
                - "Dst Filter Action Blacklist"
                type: str
            dst_tcp_filter_action_drop:
                description:
                - "Dst Filter Action Drop"
                type: str
            dst_tcp_filter_action_default_pass:
                description:
                - "Dst Filter Action Default Pass"
                type: str
            tcp_concurrent:
                description:
                - "TCP Concurrent Port Access"
                type: str
            dst_tcp_filter_action_whitelist:
                description:
                - "Dst Filter Action WL"
                type: str
            src_tcp_filter_match:
                description:
                - "Src Filter Match"
                type: str
            src_tcp_filter_not_match:
                description:
                - "Src Filter No Match"
                type: str
            src_tcp_filter_action_blacklist:
                description:
                - "Src Filter Action Blacklist"
                type: str
            src_tcp_filter_action_drop:
                description:
                - "Src Filter Action Drop"
                type: str
            src_tcp_filter_action_default_pass:
                description:
                - "Src Filter Action Default Pass"
                type: str
            src_tcp_filter_action_whitelist:
                description:
                - "Src Filter Action WL"
                type: str
            src_dst_tcp_filter_match:
                description:
                - "SrcDst Filter Match"
                type: str
            src_dst_tcp_filter_not_match:
                description:
                - "SrcDst Filter No Match"
                type: str
            src_dst_tcp_filter_action_blacklist:
                description:
                - "SrcDst Filter Action Blacklist"
                type: str
            src_dst_tcp_filter_action_drop:
                description:
                - "SrcDst Filter Action Drop"
                type: str
            src_dst_tcp_filter_action_default_pass:
                description:
                - "SrcDst Filter Action Default Pass"
                type: str
            src_dst_tcp_filter_action_whitelist:
                description:
                - "SrcDst Filter Action WL"
                type: str
            syn_auth_pass_wl:
                description:
                - "TCP SYN Auth Pass WL"
                type: str
            tcp_out_of_seq_drop:
                description:
                - "TCP Out-Of-Seq Dropped"
                type: str
            tcp_zero_window_drop:
                description:
                - "TCP Zero-Window Dropped"
                type: str
            tcp_retransmit_drop:
                description:
                - "TCP Retransmit Dropped"
                type: str
            tcp_per_conn_prate_exceed_bl:
                description:
                - "TCP Conn Pkt Rate Blacklisted"
                type: str
            tcp_any_exceed:
                description:
                - "TCP Exceeded"
                type: str
            tcp_drop_bl:
                description:
                - "TCP Blacklist Packets Dropped"
                type: str
            tcp_frag_rcvd:
                description:
                - "TCP Frag Received"
                type: str
            tcp_frag_drop:
                description:
                - "TCP Frag Dropped"
                type: str
            tcp_auth_drop:
                description:
                - "TCP Auth Dropped"
                type: str
            tcp_auth_resp:
                description:
                - "TCP Auth Responded"
                type: str
            tcp_total_bytes_rcv:
                description:
                - "TCP Total Bytes Received"
                type: str
            tcp_total_bytes_drop:
                description:
                - "TCP Total Bytes Dropped"
                type: str
            tcp_action_on_ack_bl:
                description:
                - "TCP ACK Retry Timeout Blacklisted"
                type: str
            tcp_action_on_syn_bl:
                description:
                - "TCP SYN Retry Timeout Blacklisted"
                type: str
            tcp_per_conn_ofo_rate_exceed_drop:
                description:
                - "TCP Conn Out-Of-Seq Rate Dropped"
                type: str
            tcp_per_conn_ofo_rate_exceed_bl:
                description:
                - "TCP Conn Out-Of-Seq Rate Blacklisted"
                type: str
            tcp_per_conn_rexmit_rate_exceed_drop:
                description:
                - "TCP Conn Retransmit Rate Dropped"
                type: str
            tcp_per_conn_rexmit_rate_exceed_bl:
                description:
                - "TCP Conn Retransmit Rate Blacklisted"
                type: str
            tcp_per_conn_zwindow_rate_exceed_drop:
                description:
                - "TCP Conn Zero-Window Rate Dropped"
                type: str
            tcp_per_conn_zwindow_rate_exceed_bl:
                description:
                - "TCP Conn Zero-Window Rate Blacklisted"
                type: str
            tcp_syn_tfo_rcvd:
                description:
                - "TCP SYN TFO Received"
                type: str
            tcp_progression_violation_exceed:
                description:
                - "Progression= Violation Exceeded"
                type: str
            tcp_progression_violation_exceed_bl:
                description:
                - "Progression= Violation Exceeded Blacklisted"
                type: str
            tcp_progression_violation_exceed_drop:
                description:
                - "Progression= Violation Exceeded Dropped"
                type: str
            tcp_progression_violation_exceed_reset:
                description:
                - "Progression= Violation Exceeded Reset"
                type: str
            tcp_auth_rst:
                description:
                - "TCP Auth Reset"
                type: str
            hybrid_syn_auth_unknown_pass:
                description:
                - "SYN Auth Hybrid Unknown Auth Pass"
                type: str
            hybrid_syn_auth_unknown_fail:
                description:
                - "SYN Auth Hybrid Unknown Auth Fail"
                type: str
            hybrid_syn_auth_valid_sa_sent:
                description:
                - "SYN Auth Hybrid Valid SYNACK Sent"
                type: str
            hybrid_syn_auth_invalid_sa_sent:
                description:
                - "SYN Auth Hybrid Invalid SYNACK Sent"
                type: str
            hybrid_syn_auth_filter_full:
                description:
                - "SYN Auth Hybrid Filter Full"
                type: str
            hybrid_syn_auth_lookup_fail:
                description:
                - "SYN Auth Hybrid Lookup Fail"
                type: str
            hybrid_syn_auth_invalid_pass:
                description:
                - "SYN Auth Hybrid Invalid SYNACK Auth Pass"
                type: str
            hybrid_syn_auth_valid_pass:
                description:
                - "SYN Auth Hybrid Valid SYNACK Auth Pass"
                type: str
            hybrid_syn_auth_invalid_fail:
                description:
                - "SYN Auth Hybrid Invalid SYNACK Auth Fail"
                type: str
            hybrid_syn_auth_valid_fail:
                description:
                - "SYN Auth Hybrid Valid SYNACK Auth Fail"
                type: str
            tcp_invalid_synack_rcvd:
                description:
                - "TCP Invalid SYNACK Received"
                type: str
            hybrid_syn_auth_method_change:
                description:
                - "SYN Auth Hybrid Method Change"
                type: str
            tcp_small_window:
                description:
                - "TCP Small-Window Total"
                type: str
            tcp_small_window_bl:
                description:
                - "TCP Small-Window Blacklisted"
                type: str
            tcp_small_window_drop:
                description:
                - "TCP Small-Window Dropped"
                type: str
            hybrid_syn_auth_entry_aged_out:
                description:
                - "SYN Auth Hybrid Entry Aged Out"
                type: str
            hybrid_syn_auth_auth_no_match:
                description:
                - "SYN Auth Hybrid Auth no match"
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
AVAILABLE_PROPERTIES = ["stats", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False,
                           ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False,
                                   ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
        )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'uuid': {
            'type': 'str',
            },
        'stats': {
            'type': 'dict',
            'tcp_sess_create': {
                'type': 'str',
                },
            'intcp': {
                'type': 'str',
                },
            'tcp_syn_rcvd': {
                'type': 'str',
                },
            'tcp_invalid_syn_rcvd': {
                'type': 'str',
                },
            'tcp_syn_ack_rcvd': {
                'type': 'str',
                },
            'tcp_ack_rcvd': {
                'type': 'str',
                },
            'tcp_fin_rcvd': {
                'type': 'str',
                },
            'tcp_rst_rcvd': {
                'type': 'str',
                },
            'tcp_outrst': {
                'type': 'str',
                },
            'tcp_reset_client': {
                'type': 'str',
                },
            'tcp_reset_server': {
                'type': 'str',
                },
            'tcp_syn_rate': {
                'type': 'str',
                },
            'tcp_total_drop': {
                'type': 'str',
                },
            'tcp_dst_drop': {
                'type': 'str',
                },
            'tcp_src_drop': {
                'type': 'str',
                },
            'tcp_drop_black_user_cfg_src': {
                'type': 'str',
                },
            'tcp_src_dst_drop': {
                'type': 'str',
                },
            'tcp_drop_black_user_cfg_src_dst': {
                'type': 'str',
                },
            'tcp_port_zero_drop': {
                'type': 'str',
                },
            'tcp_syncookie_sent': {
                'type': 'str',
                },
            'tcp_syncookie_sent_fail': {
                'type': 'str',
                },
            'tcp_syncookie_check_fail': {
                'type': 'str',
                },
            'tcp_syncookie_hw_missing': {
                'type': 'str',
                },
            'tcp_syncookie_fail_bl': {
                'type': 'str',
                },
            'tcp_syncookie_pass': {
                'type': 'str',
                },
            'syn_auth_pass': {
                'type': 'str',
                },
            'syn_auth_skip': {
                'type': 'str',
                },
            'tcp_action_on_ack_start': {
                'type': 'str',
                },
            'tcp_action_on_ack_matched': {
                'type': 'str',
                },
            'tcp_action_on_ack_passed': {
                'type': 'str',
                },
            'tcp_action_on_ack_failed': {
                'type': 'str',
                },
            'tcp_action_on_ack_timeout': {
                'type': 'str',
                },
            'tcp_action_on_ack_reset': {
                'type': 'str',
                },
            'tcp_ack_no_syn': {
                'type': 'str',
                },
            'tcp_out_of_seq': {
                'type': 'str',
                },
            'tcp_zero_window': {
                'type': 'str',
                },
            'tcp_retransmit': {
                'type': 'str',
                },
            'tcp_rexmit_syn_limit_drop': {
                'type': 'str',
                },
            'tcp_zero_window_bl': {
                'type': 'str',
                },
            'tcp_out_of_seq_bl': {
                'type': 'str',
                },
            'tcp_retransmit_bl': {
                'type': 'str',
                },
            'tcp_rexmit_syn_limit_bl': {
                'type': 'str',
                },
            'tcp_per_conn_prate_exceed': {
                'type': 'str',
                },
            'tcp_action_on_ack_gap_drop': {
                'type': 'str',
                },
            'tcp_action_on_ack_gap_pass': {
                'type': 'str',
                },
            'tcp_action_on_syn_start': {
                'type': 'str',
                },
            'tcp_action_on_syn_passed': {
                'type': 'str',
                },
            'tcp_action_on_syn_failed': {
                'type': 'str',
                },
            'tcp_action_on_syn_timeout': {
                'type': 'str',
                },
            'tcp_action_on_syn_reset': {
                'type': 'str',
                },
            'tcp_action_on_syn_gap_drop': {
                'type': 'str',
                },
            'tcp_action_on_syn_gap_pass': {
                'type': 'str',
                },
            'tcp_unauth_rst_drop': {
                'type': 'str',
                },
            'dst_tcp_filter_match': {
                'type': 'str',
                },
            'dst_tcp_filter_not_match': {
                'type': 'str',
                },
            'dst_tcp_filter_action_blacklist': {
                'type': 'str',
                },
            'dst_tcp_filter_action_drop': {
                'type': 'str',
                },
            'dst_tcp_filter_action_default_pass': {
                'type': 'str',
                },
            'tcp_concurrent': {
                'type': 'str',
                },
            'dst_tcp_filter_action_whitelist': {
                'type': 'str',
                },
            'src_tcp_filter_match': {
                'type': 'str',
                },
            'src_tcp_filter_not_match': {
                'type': 'str',
                },
            'src_tcp_filter_action_blacklist': {
                'type': 'str',
                },
            'src_tcp_filter_action_drop': {
                'type': 'str',
                },
            'src_tcp_filter_action_default_pass': {
                'type': 'str',
                },
            'src_tcp_filter_action_whitelist': {
                'type': 'str',
                },
            'src_dst_tcp_filter_match': {
                'type': 'str',
                },
            'src_dst_tcp_filter_not_match': {
                'type': 'str',
                },
            'src_dst_tcp_filter_action_blacklist': {
                'type': 'str',
                },
            'src_dst_tcp_filter_action_drop': {
                'type': 'str',
                },
            'src_dst_tcp_filter_action_default_pass': {
                'type': 'str',
                },
            'src_dst_tcp_filter_action_whitelist': {
                'type': 'str',
                },
            'syn_auth_pass_wl': {
                'type': 'str',
                },
            'tcp_out_of_seq_drop': {
                'type': 'str',
                },
            'tcp_zero_window_drop': {
                'type': 'str',
                },
            'tcp_retransmit_drop': {
                'type': 'str',
                },
            'tcp_per_conn_prate_exceed_bl': {
                'type': 'str',
                },
            'tcp_any_exceed': {
                'type': 'str',
                },
            'tcp_drop_bl': {
                'type': 'str',
                },
            'tcp_frag_rcvd': {
                'type': 'str',
                },
            'tcp_frag_drop': {
                'type': 'str',
                },
            'tcp_auth_drop': {
                'type': 'str',
                },
            'tcp_auth_resp': {
                'type': 'str',
                },
            'tcp_total_bytes_rcv': {
                'type': 'str',
                },
            'tcp_total_bytes_drop': {
                'type': 'str',
                },
            'tcp_action_on_ack_bl': {
                'type': 'str',
                },
            'tcp_action_on_syn_bl': {
                'type': 'str',
                },
            'tcp_per_conn_ofo_rate_exceed_drop': {
                'type': 'str',
                },
            'tcp_per_conn_ofo_rate_exceed_bl': {
                'type': 'str',
                },
            'tcp_per_conn_rexmit_rate_exceed_drop': {
                'type': 'str',
                },
            'tcp_per_conn_rexmit_rate_exceed_bl': {
                'type': 'str',
                },
            'tcp_per_conn_zwindow_rate_exceed_drop': {
                'type': 'str',
                },
            'tcp_per_conn_zwindow_rate_exceed_bl': {
                'type': 'str',
                },
            'tcp_syn_tfo_rcvd': {
                'type': 'str',
                },
            'tcp_progression_violation_exceed': {
                'type': 'str',
                },
            'tcp_progression_violation_exceed_bl': {
                'type': 'str',
                },
            'tcp_progression_violation_exceed_drop': {
                'type': 'str',
                },
            'tcp_progression_violation_exceed_reset': {
                'type': 'str',
                },
            'tcp_auth_rst': {
                'type': 'str',
                },
            'hybrid_syn_auth_unknown_pass': {
                'type': 'str',
                },
            'hybrid_syn_auth_unknown_fail': {
                'type': 'str',
                },
            'hybrid_syn_auth_valid_sa_sent': {
                'type': 'str',
                },
            'hybrid_syn_auth_invalid_sa_sent': {
                'type': 'str',
                },
            'hybrid_syn_auth_filter_full': {
                'type': 'str',
                },
            'hybrid_syn_auth_lookup_fail': {
                'type': 'str',
                },
            'hybrid_syn_auth_invalid_pass': {
                'type': 'str',
                },
            'hybrid_syn_auth_valid_pass': {
                'type': 'str',
                },
            'hybrid_syn_auth_invalid_fail': {
                'type': 'str',
                },
            'hybrid_syn_auth_valid_fail': {
                'type': 'str',
                },
            'tcp_invalid_synack_rcvd': {
                'type': 'str',
                },
            'hybrid_syn_auth_method_change': {
                'type': 'str',
                },
            'tcp_small_window': {
                'type': 'str',
                },
            'tcp_small_window_bl': {
                'type': 'str',
                },
            'tcp_small_window_drop': {
                'type': 'str',
                },
            'hybrid_syn_auth_entry_aged_out': {
                'type': 'str',
                },
            'hybrid_syn_auth_auth_no_match': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/l4-tcp"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/l4-tcp"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config):
    if existing_config:
        result["changed"] = True
    return result


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(**call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("l4-tcp", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(changed=False, messages="", modified_values={}, axapi_calls=[], ansible_facts={}, acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

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
            result["axapi_calls"].append(api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(api_client.switch_device_context(module.client, a10_device_context_id))

        if state == 'present' or state == 'absent':
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
            if module.params.get("get_type") == "single" or module.params.get("get_type") is None:
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["l4-tcp"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["l4-tcp-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["l4-tcp"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


"""
    Custom class which override the _check_required_arguments function to check check required arguments based on state and get_type.
"""


class AcosAnsibleModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        super(AcosAnsibleModule, self).__init__(*args, **kwargs)

    def _check_required_arguments(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        # skip validation if state is 'noop' and get_type is 'list'
        if not (param.get("state") == "noop" and param.get("get_type") == "list"):
            missing = []
            if spec is None:
                return missing
            # Check for missing required parameters in the provided argument spec
            for (k, v) in spec.items():
                required = v.get('required', False)
                if required and k not in param:
                    missing.append(k)
            if missing:
                self.fail_json(msg="Missing required parameters: {}".format(", ".join(missing)))


def main():
    module = AcosAnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
