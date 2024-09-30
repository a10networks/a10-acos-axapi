#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_dst_entry_port_range_stats_tcp_port
description:
    - Statistics for the object port-range
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
    protocol:
        description:
        - Key to identify parent object
        type: str
        required: True
    port_range_end:
        description:
        - Key to identify parent object
        type: str
        required: True
    port_range_port_range_start:
        description:
        - Key to identify parent object
        type: str
        required: True
    entry_dst_entry_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    port_range_start:
        description:
        - "Port-Range Start Port Number"
        type: int
        required: True
    port_range_end:
        description:
        - "Port-Range End Port Number"
        type: int
        required: True
    protocol:
        description:
        - "'dns-tcp'= DNS-TCP Port; 'dns-udp'= DNS-UDP Port; 'http'= HTTP Port; 'tcp'= TCP
          Port; 'udp'= UDP Port; 'ssl-l4'= SSL-L4 Port; 'sip-udp'= SIP-UDP Port; 'sip-
          tcp'= SIP-TCP Port;"
        type: str
        required: True
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            tcp_port:
                description:
                - "Field tcp_port"
                type: dict

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
AVAILABLE_PROPERTIES = ["port_range_end", "port_range_start", "protocol", "stats", ]


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
        'port_range_start': {
            'type': 'int',
            'required': True,
            },
        'port_range_end': {
            'type': 'int',
            'required': True,
            },
        'protocol': {
            'type': 'str',
            'required': True,
            'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4', 'sip-udp', 'sip-tcp']
            },
        'stats': {
            'type': 'dict',
            'tcp_port': {
                'type': 'dict',
                'filter1_match': {
                    'type': 'str',
                    },
                'filter2_match': {
                    'type': 'str',
                    },
                'filter3_match': {
                    'type': 'str',
                    },
                'filter4_match': {
                    'type': 'str',
                    },
                'filter5_match': {
                    'type': 'str',
                    },
                'filter_none_match': {
                    'type': 'str',
                    },
                'port_rcvd': {
                    'type': 'str',
                    },
                'port_drop': {
                    'type': 'str',
                    },
                'port_pkt_sent': {
                    'type': 'str',
                    },
                'port_pkt_rate_exceed': {
                    'type': 'str',
                    },
                'port_kbit_rate_exceed': {
                    'type': 'str',
                    },
                'port_conn_rate_exceed': {
                    'type': 'str',
                    },
                'port_conn_limm_exceed': {
                    'type': 'str',
                    },
                'filter_auth_fail': {
                    'type': 'str',
                    },
                'syn_auth_fail': {
                    'type': 'str',
                    },
                'ack_auth_fail': {
                    'type': 'str',
                    },
                'syn_cookie_fail': {
                    'type': 'str',
                    },
                'port_bytes': {
                    'type': 'str',
                    },
                'outbound_port_bytes': {
                    'type': 'str',
                    },
                'outbound_port_rcvd': {
                    'type': 'str',
                    },
                'outbound_port_pkt_sent': {
                    'type': 'str',
                    },
                'port_bytes_sent': {
                    'type': 'str',
                    },
                'port_bytes_drop': {
                    'type': 'str',
                    },
                'port_src_bl': {
                    'type': 'str',
                    },
                'sess_create': {
                    'type': 'str',
                    },
                'filter_action_blacklist': {
                    'type': 'str',
                    },
                'filter_action_drop': {
                    'type': 'str',
                    },
                'filter_action_default_pass': {
                    'type': 'str',
                    },
                'filter_action_whitelist': {
                    'type': 'str',
                    },
                'exceed_drop_prate_src': {
                    'type': 'str',
                    },
                'exceed_drop_crate_src': {
                    'type': 'str',
                    },
                'exceed_drop_climit_src': {
                    'type': 'str',
                    },
                'exceed_drop_brate_src': {
                    'type': 'str',
                    },
                'outbound_port_bytes_sent': {
                    'type': 'str',
                    },
                'outbound_port_drop': {
                    'type': 'str',
                    },
                'outbound_port_bytes_drop': {
                    'type': 'str',
                    },
                'syn_auth_pass': {
                    'type': 'str',
                    },
                'exceed_drop_brate_src_pkt': {
                    'type': 'str',
                    },
                'port_kbit_rate_exceed_pkt': {
                    'type': 'str',
                    },
                'syn_cookie_sent': {
                    'type': 'str',
                    },
                'ack_retry_init': {
                    'type': 'str',
                    },
                'ack_retry_gap_drop': {
                    'type': 'str',
                    },
                'conn_prate_excd': {
                    'type': 'str',
                    },
                'out_of_seq_excd': {
                    'type': 'str',
                    },
                'retransmit_excd': {
                    'type': 'str',
                    },
                'zero_window_excd': {
                    'type': 'str',
                    },
                'syn_retry_init': {
                    'type': 'str',
                    },
                'syn_retry_gap_drop': {
                    'type': 'str',
                    },
                'ack_retry_pass': {
                    'type': 'str',
                    },
                'syn_retry_pass': {
                    'type': 'str',
                    },
                'tcp_auth_drop': {
                    'type': 'str',
                    },
                'tcp_auth_resp': {
                    'type': 'str',
                    },
                'bl': {
                    'type': 'str',
                    },
                'src_drop': {
                    'type': 'str',
                    },
                'frag_rcvd': {
                    'type': 'str',
                    },
                'frag_drop': {
                    'type': 'str',
                    },
                'sess_create_inbound': {
                    'type': 'str',
                    },
                'sess_create_outbound': {
                    'type': 'str',
                    },
                'conn_create_from_syn': {
                    'type': 'str',
                    },
                'conn_create_from_ack': {
                    'type': 'str',
                    },
                'conn_close': {
                    'type': 'str',
                    },
                'conn_close_w_rst': {
                    'type': 'str',
                    },
                'conn_close_w_fin': {
                    'type': 'str',
                    },
                'conn_close_w_idle': {
                    'type': 'str',
                    },
                'conn_close_half_open': {
                    'type': 'str',
                    },
                'sess_aged': {
                    'type': 'str',
                    },
                'syn_drop': {
                    'type': 'str',
                    },
                'unauth_drop': {
                    'type': 'str',
                    },
                'rst_cookie_fail': {
                    'type': 'str',
                    },
                'syn_retry_failed': {
                    'type': 'str',
                    },
                'filter_total_not_match': {
                    'type': 'str',
                    },
                'src_syn_auth_fail': {
                    'type': 'str',
                    },
                'src_syn_cookie_sent': {
                    'type': 'str',
                    },
                'src_syn_cookie_fail': {
                    'type': 'str',
                    },
                'src_unauth_drop': {
                    'type': 'str',
                    },
                'src_rst_cookie_fail': {
                    'type': 'str',
                    },
                'src_syn_retry_init': {
                    'type': 'str',
                    },
                'src_syn_retry_gap_drop': {
                    'type': 'str',
                    },
                'src_syn_retry_failed': {
                    'type': 'str',
                    },
                'src_ack_retry_init': {
                    'type': 'str',
                    },
                'src_ack_retry_gap_drop': {
                    'type': 'str',
                    },
                'src_ack_auth_fail': {
                    'type': 'str',
                    },
                'src_out_of_seq_excd': {
                    'type': 'str',
                    },
                'src_retransmit_excd': {
                    'type': 'str',
                    },
                'src_zero_window_excd': {
                    'type': 'str',
                    },
                'src_conn_pkt_rate_excd': {
                    'type': 'str',
                    },
                'src_filter_action_blacklist': {
                    'type': 'str',
                    },
                'src_filter_action_drop': {
                    'type': 'str',
                    },
                'src_filter_action_default_pass': {
                    'type': 'str',
                    },
                'src_filter_action_whitelist': {
                    'type': 'str',
                    },
                'tcp_rexmit_syn_limit_drop': {
                    'type': 'str',
                    },
                'tcp_rexmit_syn_limit_bl': {
                    'type': 'str',
                    },
                'conn_ofo_rate_excd': {
                    'type': 'str',
                    },
                'conn_rexmit_rate_excd': {
                    'type': 'str',
                    },
                'conn_zwindow_rate_excd': {
                    'type': 'str',
                    },
                'src_conn_ofo_rate_excd': {
                    'type': 'str',
                    },
                'src_conn_rexmit_rate_excd': {
                    'type': 'str',
                    },
                'src_conn_zwindow_rate_excd': {
                    'type': 'str',
                    },
                'ack_retry_rto_pass': {
                    'type': 'str',
                    },
                'ack_retry_rto_fail': {
                    'type': 'str',
                    },
                'ack_retry_rto_progress': {
                    'type': 'str',
                    },
                'syn_retry_rto_pass': {
                    'type': 'str',
                    },
                'syn_retry_rto_fail': {
                    'type': 'str',
                    },
                'syn_retry_rto_progress': {
                    'type': 'str',
                    },
                'src_syn_retry_rto_pass': {
                    'type': 'str',
                    },
                'src_syn_retry_rto_fail': {
                    'type': 'str',
                    },
                'src_syn_retry_rto_progress': {
                    'type': 'str',
                    },
                'src_ack_retry_rto_pass': {
                    'type': 'str',
                    },
                'src_ack_retry_rto_fail': {
                    'type': 'str',
                    },
                'src_ack_retry_rto_progress': {
                    'type': 'str',
                    },
                'wellknown_sport_drop': {
                    'type': 'str',
                    },
                'src_well_known_port': {
                    'type': 'str',
                    },
                'src_auth_drop': {
                    'type': 'str',
                    },
                'src_frag_drop': {
                    'type': 'str',
                    },
                'frag_timeout': {
                    'type': 'str',
                    },
                'create_conn_non_syn_dropped': {
                    'type': 'str',
                    },
                'src_create_conn_non_syn_dropped': {
                    'type': 'str',
                    },
                'port_syn_rate_exceed': {
                    'type': 'str',
                    },
                'src_syn_rate_exceed': {
                    'type': 'str',
                    },
                'pattern_recognition_proceeded': {
                    'type': 'str',
                    },
                'pattern_not_found': {
                    'type': 'str',
                    },
                'pattern_recognition_generic_error': {
                    'type': 'str',
                    },
                'pattern_filter1_match': {
                    'type': 'str',
                    },
                'pattern_filter2_match': {
                    'type': 'str',
                    },
                'pattern_filter3_match': {
                    'type': 'str',
                    },
                'pattern_filter4_match': {
                    'type': 'str',
                    },
                'pattern_filter5_match': {
                    'type': 'str',
                    },
                'pattern_filter_drop': {
                    'type': 'str',
                    },
                'src_filter1_match': {
                    'type': 'str',
                    },
                'src_filter2_match': {
                    'type': 'str',
                    },
                'src_filter3_match': {
                    'type': 'str',
                    },
                'src_filter4_match': {
                    'type': 'str',
                    },
                'src_filter5_match': {
                    'type': 'str',
                    },
                'src_filter_none_match': {
                    'type': 'str',
                    },
                'src_filter_total_not_match': {
                    'type': 'str',
                    },
                'src_filter_auth_fail': {
                    'type': 'str',
                    },
                'syn_tfo_rcv': {
                    'type': 'str',
                    },
                'ack_retry_timeout': {
                    'type': 'str',
                    },
                'ack_retry_reset': {
                    'type': 'str',
                    },
                'ack_retry_blacklist': {
                    'type': 'str',
                    },
                'src_ack_retry_timeout': {
                    'type': 'str',
                    },
                'src_ack_retry_reset': {
                    'type': 'str',
                    },
                'src_ack_retry_blacklist': {
                    'type': 'str',
                    },
                'syn_retry_timeout': {
                    'type': 'str',
                    },
                'syn_retry_reset': {
                    'type': 'str',
                    },
                'syn_retry_blacklist': {
                    'type': 'str',
                    },
                'src_syn_retry_timeout': {
                    'type': 'str',
                    },
                'src_syn_retry_reset': {
                    'type': 'str',
                    },
                'src_syn_retry_blacklist': {
                    'type': 'str',
                    },
                'sflow_internal_samples_packed': {
                    'type': 'str',
                    },
                'sflow_external_samples_packed': {
                    'type': 'str',
                    },
                'sflow_internal_packets_sent': {
                    'type': 'str',
                    },
                'sflow_external_packets_sent': {
                    'type': 'str',
                    },
                'pattern_recognition_sampling_started': {
                    'type': 'str',
                    },
                'pattern_recognition_pattern_changed': {
                    'type': 'str',
                    },
                'exceed_action_tunnel': {
                    'type': 'str',
                    },
                'dst_hw_drop': {
                    'type': 'str',
                    },
                'synack_reset_sent': {
                    'type': 'str',
                    },
                'synack_multiple_attempts_per_ip_detected': {
                    'type': 'str',
                    },
                'prog_first_req_time_exceed': {
                    'type': 'str',
                    },
                'prog_req_resp_time_exceed': {
                    'type': 'str',
                    },
                'prog_request_len_exceed': {
                    'type': 'str',
                    },
                'prog_response_len_exceed': {
                    'type': 'str',
                    },
                'prog_resp_pkt_rate_exceed': {
                    'type': 'str',
                    },
                'prog_resp_req_time_exceed': {
                    'type': 'str',
                    },
                'prog_conn_sent_exceed': {
                    'type': 'str',
                    },
                'prog_conn_rcvd_exceed': {
                    'type': 'str',
                    },
                'prog_conn_time_exceed': {
                    'type': 'str',
                    },
                'prog_conn_rcvd_sent_ratio_exceed': {
                    'type': 'str',
                    },
                'prog_win_sent_exceed': {
                    'type': 'str',
                    },
                'prog_win_rcvd_exceed': {
                    'type': 'str',
                    },
                'prog_win_rcvd_sent_ratio_exceed': {
                    'type': 'str',
                    },
                'snat_fail': {
                    'type': 'str',
                    },
                'prog_exceed_drop': {
                    'type': 'str',
                    },
                'prog_exceed_bl': {
                    'type': 'str',
                    },
                'prog_conn_exceed_drop': {
                    'type': 'str',
                    },
                'prog_conn_exceed_bl': {
                    'type': 'str',
                    },
                'prog_win_exceed_drop': {
                    'type': 'str',
                    },
                'prog_win_exceed_bl': {
                    'type': 'str',
                    },
                'exceed_action_drop': {
                    'type': 'str',
                    },
                'syn_auth_rst_ack_drop': {
                    'type': 'str',
                    },
                'prog_exceed_reset': {
                    'type': 'str',
                    },
                'prog_conn_exceed_reset': {
                    'type': 'str',
                    },
                'prog_win_exceed_reset': {
                    'type': 'str',
                    },
                'conn_create_from_synack': {
                    'type': 'str',
                    },
                'port_synack_rate_exceed': {
                    'type': 'str',
                    },
                'tcp_auth_rst': {
                    'type': 'str',
                    },
                'src_tcp_auth_rst': {
                    'type': 'str',
                    },
                'hybrid_auth_unknown_pass': {
                    'type': 'str',
                    },
                'hybrid_auth_unknown_fail': {
                    'type': 'str',
                    },
                'hybrid_auth_valid_sa_sent': {
                    'type': 'str',
                    },
                'hybrid_auth_invalid_sa_sent': {
                    'type': 'str',
                    },
                'hybrid_auth_filter_full': {
                    'type': 'str',
                    },
                'hybrid_auth_lookup_fail': {
                    'type': 'str',
                    },
                'hybrid_auth_invalid_pass': {
                    'type': 'str',
                    },
                'hybrid_auth_valid_pass': {
                    'type': 'str',
                    },
                'hybrid_auth_invalid_fail': {
                    'type': 'str',
                    },
                'hybrid_auth_valid_fail': {
                    'type': 'str',
                    },
                'prog_query_exceed': {
                    'type': 'str',
                    },
                'prog_think_exceed': {
                    'type': 'str',
                    },
                'prog_conn_samples': {
                    'type': 'str',
                    },
                'prog_req_samples': {
                    'type': 'str',
                    },
                'prog_win_samples': {
                    'type': 'str',
                    },
                'prog_conn_samples_processed': {
                    'type': 'str',
                    },
                'prog_req_samples_processed': {
                    'type': 'str',
                    },
                'prog_win_samples_processed': {
                    'type': 'str',
                    },
                'hybrid_auth_method_change': {
                    'type': 'str',
                    },
                'small_window_excd': {
                    'type': 'str',
                    },
                'src_small_window_excd': {
                    'type': 'str',
                    },
                'small_window_rcv': {
                    'type': 'str',
                    },
                'hybrid_auth_entry_aged_out': {
                    'type': 'str',
                    },
                'tcp_syn_rcvd': {
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
                'hybrid_auth_auth_no_match': {
                    'type': 'str',
                    },
                'tcp_auth_drop_syn': {
                    'type': 'str',
                    },
                'src_auth_drop_syn': {
                    'type': 'str',
                    },
                'tcp_auth_drop_ack': {
                    'type': 'str',
                    },
                'src_auth_drop_ack': {
                    'type': 'str',
                    },
                'tcp_auth_drop_rst': {
                    'type': 'str',
                    },
                'src_auth_drop_rst': {
                    'type': 'str',
                    },
                'tcp_auth_drop_ack_pass_auth': {
                    'type': 'str',
                    },
                'src_auth_drop_ack_pass_auth': {
                    'type': 'str',
                    },
                'tcp_auth_drop_ack_fail_auth': {
                    'type': 'str',
                    },
                'src_auth_drop_ack_fail_auth': {
                    'type': 'str',
                    },
                'tcp_auth_drop_rst_pass_auth': {
                    'type': 'str',
                    },
                'src_auth_drop_rst_pass_auth': {
                    'type': 'str',
                    },
                'tcp_auth_drop_rst_fail_auth': {
                    'type': 'str',
                    },
                'src_auth_drop_rst_fail_auth': {
                    'type': 'str',
                    },
                'hybrid_auth_auth_no_match_rst_rcv': {
                    'type': 'str',
                    },
                'hybrid_auth_auth_no_match_ack_rcv': {
                    'type': 'str',
                    },
                'tcp_auth_drop_ack_xmit': {
                    'type': 'str',
                    },
                'src_auth_drop_ack_xmit': {
                    'type': 'str',
                    },
                'tcp_auth_drop_rst_xmit': {
                    'type': 'str',
                    },
                'src_auth_drop_rst_xmit': {
                    'type': 'str',
                    }
                }
            }
        })
    # Parent keys
    rv.update(dict(protocol=dict(type='str', required=True), port_range_end=dict(type='str', required=True), port_range_port_range_start=dict(type='str', required=True), entry_dst_entry_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/dst/entry/{entry_dst_entry_name}/port-range/{port_range_port_range_start}+{port_range_end}+{protocol}/stats?tcp-port=true"

    f_dict = {}
    if '/' in module.params["protocol"]:
        f_dict["protocol"] = module.params["protocol"].replace("/", "%2F")
    else:
        f_dict["protocol"] = module.params["protocol"]
    if '/' in module.params["port_range_end"]:
        f_dict["port_range_end"] = module.params["port_range_end"].replace("/", "%2F")
    else:
        f_dict["port_range_end"] = module.params["port_range_end"]
    if '/' in module.params["port_range_port_range_start"]:
        f_dict["port_range_port_range_start"] = module.params["port_range_port_range_start"].replace("/", "%2F")
    else:
        f_dict["port_range_port_range_start"] = module.params["port_range_port_range_start"]
    if '/' in module.params["entry_dst_entry_name"]:
        f_dict["entry_dst_entry_name"] = module.params["entry_dst_entry_name"].replace("/", "%2F")
    else:
        f_dict["entry_dst_entry_name"] = module.params["entry_dst_entry_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/dst/entry/{entry_dst_entry_name}/port-range/{port_range_port_range_start}+{port_range_end}+{protocol}/stats?tcp-port=true"

    f_dict = {}
    f_dict["protocol"] = module.params["protocol"]
    f_dict["port_range_end"] = module.params["port_range_end"]
    f_dict["port_range_port_range_start"] = module.params["port_range_port_range_start"]
    f_dict["entry_dst_entry_name"] = module.params["entry_dst_entry_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["port-range"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["port-range"].get(k) != v:
            change_results["changed"] = True
            config_changes["port-range"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


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
    payload = utils.build_json("port-range", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["port-range"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["port-range-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["port-range"]["stats"] if info != "NotFound" else info
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
