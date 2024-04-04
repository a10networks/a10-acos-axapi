#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_dst_dynamic_entry
description:
    - Dst dynamic entry info
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
    all_entries:
        description:
        - "Field all_entries"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            ddos_entry_list:
                description:
                - "Field ddos_entry_list"
                type: list
            ip_conn_total:
                description:
                - "Field ip_conn_total"
                type: int
            ipv6_conn_total:
                description:
                - "Field ipv6_conn_total"
                type: int
            entry_displayed_count:
                description:
                - "Field entry_displayed_count"
                type: int
            service_displayed_count:
                description:
                - "Field service_displayed_count"
                type: int
            ipv6:
                description:
                - "Field ipv6"
                type: str
            subnet_ip_addr:
                description:
                - "Field subnet_ip_addr"
                type: str
            subnet_ipv6_addr:
                description:
                - "Field subnet_ipv6_addr"
                type: str
            overflow_policy:
                description:
                - "Field overflow_policy"
                type: str
            ip_proto_num:
                description:
                - "Field ip_proto_num"
                type: int
            l4_type_str:
                description:
                - "Field l4_type_str"
                type: str
            port_num:
                description:
                - "Field port_num"
                type: int
            port_range_start:
                description:
                - "Field port_range_start"
                type: int
            port_range_end:
                description:
                - "Field port_range_end"
                type: int
            src_port_num:
                description:
                - "Field src_port_num"
                type: int
            src_port_range_start:
                description:
                - "Field src_port_range_start"
                type: int
            src_port_range_end:
                description:
                - "Field src_port_range_end"
                type: int
            protocol:
                description:
                - "Field protocol"
                type: str
            sport_protocol:
                description:
                - "Field sport_protocol"
                type: str
            app_stat:
                description:
                - "Field app_stat"
                type: bool
            all_entries:
                description:
                - "Field all_entries"
                type: bool
            all_ip_protos:
                description:
                - "Field all_ip_protos"
                type: bool
            all_l4_types:
                description:
                - "Field all_l4_types"
                type: bool
            all_ports:
                description:
                - "Field all_ports"
                type: bool
            all_src_ports:
                description:
                - "Field all_src_ports"
                type: bool
            black_holed:
                description:
                - "Field black_holed"
                type: bool
            exceeded:
                description:
                - "Field exceeded"
                type: bool
            max_count:
                description:
                - "Field max_count"
                type: int
            resource_usage:
                description:
                - "Field resource_usage"
                type: bool
            hw_blacklisted:
                description:
                - "Field hw_blacklisted"
                type: bool

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
AVAILABLE_PROPERTIES = ["all_entries", "oper", "uuid", ]


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
        'all_entries': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'dst_tcp_any_exceed', 'dst_tcp_pkt_rate_exceed', 'dst_tcp_conn_rate_exceed', 'dst_udp_any_exceed', 'dst_udp_pkt_rate_exceed', 'dst_udp_conn_limit_exceed', 'dst_udp_conn_rate_exceed', 'dst_icmp_pkt_rate_exceed', 'dst_other_pkt_rate_exceed', 'dst_other_frag_pkt_rate_exceed', 'dst_port_pkt_rate_exceed',
                        'dst_port_conn_limit_exceed', 'dst_port_conn_rate_exceed', 'dst_pkt_sent', 'dst_udp_pkt_sent', 'dst_tcp_pkt_sent', 'dst_icmp_pkt_sent', 'dst_other_pkt_sent', 'dst_tcp_conn_limit_exceed', 'dst_tcp_pkt_rcvd', 'dst_udp_pkt_rcvd', 'dst_icmp_pkt_rcvd', 'dst_other_pkt_rcvd', 'dst_udp_filter_match', 'dst_udp_filter_not_match',
                        'dst_udp_filter_action_blacklist', 'dst_udp_filter_action_drop', 'dst_tcp_syn', 'dst_tcp_syn_drop', 'dst_tcp_src_rate_drop', 'dst_udp_src_rate_drop', 'dst_icmp_src_rate_drop', 'dst_other_frag_src_rate_drop', 'dst_other_src_rate_drop', 'dst_tcp_drop', 'dst_udp_drop', 'dst_icmp_drop', 'dst_frag_drop', 'dst_other_drop',
                        'dst_tcp_auth', 'dst_udp_filter_action_default_pass', 'dst_tcp_filter_match', 'dst_tcp_filter_not_match', 'dst_tcp_filter_action_blacklist', 'dst_tcp_filter_action_drop', 'dst_tcp_filter_action_default_pass', 'dst_udp_filter_action_whitelist', 'dst_over_limit_on', 'dst_over_limit_off', 'dst_port_over_limit_on',
                        'dst_port_over_limit_off', 'dst_over_limit_action', 'dst_port_over_limit_action', 'scanning_detected_drop', 'scanning_detected_blacklist', 'dst_udp_kibit_rate_drop', 'dst_tcp_kibit_rate_drop', 'dst_icmp_kibit_rate_drop', 'dst_other_kibit_rate_drop', 'dst_port_undef_drop', 'dst_port_bl', 'dst_src_port_bl',
                        'dst_port_kbit_rate_exceed', 'dst_tcp_src_drop', 'dst_udp_src_drop', 'dst_icmp_src_drop', 'dst_other_src_drop', 'tcp_syn_rcvd', 'tcp_syn_ack_rcvd', 'tcp_ack_rcvd', 'tcp_fin_rcvd', 'tcp_rst_rcvd', 'ingress_bytes', 'egress_bytes', 'ingress_packets', 'egress_packets', 'tcp_fwd_recv', 'udp_fwd_recv', 'icmp_fwd_recv',
                        'tcp_syn_cookie_fail', 'dst_tcp_session_created', 'dst_udp_session_created', 'dst_tcp_filter_action_whitelist', 'dst_other_filter_match', 'dst_other_filter_not_match', 'dst_other_filter_action_blacklist', 'dst_other_filter_action_drop', 'dst_other_filter_action_whitelist', 'dst_other_filter_action_default_pass',
                        'dst_blackhole_inject', 'dst_blackhole_withdraw', 'dst_tcp_out_of_seq_excd', 'dst_tcp_retransmit_excd', 'dst_tcp_zero_window_excd', 'dst_tcp_conn_prate_excd', 'dst_tcp_action_on_ack_init', 'dst_tcp_action_on_ack_gap_drop', 'dst_tcp_action_on_ack_fail', 'dst_tcp_action_on_ack_pass', 'dst_tcp_action_on_syn_init',
                        'dst_tcp_action_on_syn_gap_drop', 'dst_tcp_action_on_syn_fail', 'dst_tcp_action_on_syn_pass', 'udp_payload_too_small', 'udp_payload_too_big', 'dst_udp_conn_prate_excd', 'dst_udp_ntp_monlist_req', 'dst_udp_ntp_monlist_resp', 'dst_udp_wellknown_sport_drop', 'dst_udp_retry_init', 'dst_udp_retry_pass', 'dst_tcp_bytes_drop',
                        'dst_udp_bytes_drop', 'dst_icmp_bytes_drop', 'dst_other_bytes_drop', 'dst_out_no_route', 'outbound_bytes_sent', 'outbound_pkt_drop', 'outbound_bytes_drop', 'outbound_pkt_sent', 'inbound_bytes_sent', 'inbound_bytes_drop', 'dst_src_port_pkt_rate_exceed', 'dst_src_port_kbit_rate_exceed', 'dst_src_port_conn_limit_exceed',
                        'dst_src_port_conn_rate_exceed', 'dst_ip_proto_pkt_rate_exceed', 'dst_ip_proto_kbit_rate_exceed', 'dst_tcp_port_any_exceed', 'dst_udp_port_any_exceed', 'dst_tcp_auth_pass', 'dst_tcp_rst_cookie_fail', 'dst_tcp_unauth_drop', 'src_tcp_syn_auth_fail', 'src_tcp_syn_cookie_sent', 'src_tcp_syn_cookie_fail',
                        'src_tcp_rst_cookie_fail', 'src_tcp_unauth_drop', 'src_tcp_action_on_syn_init'
                        ]
                    },
                'counters2': {
                    'type':
                    'str',
                    'choices': [
                        'src_tcp_action_on_syn_gap_drop', 'src_tcp_action_on_syn_fail', 'src_tcp_action_on_ack_init', 'src_tcp_action_on_ack_gap_drop', 'src_tcp_action_on_ack_fail', 'src_tcp_out_of_seq_excd', 'src_tcp_retransmit_excd', 'src_tcp_zero_window_excd', 'src_tcp_conn_prate_excd', 'src_udp_min_payload', 'src_udp_max_payload',
                        'src_udp_conn_prate_excd', 'src_udp_ntp_monlist_req', 'src_udp_ntp_monlist_resp', 'src_udp_wellknown_sport_drop', 'src_udp_retry_init', 'dst_udp_retry_gap_drop', 'dst_udp_retry_fail', 'dst_tcp_session_aged', 'dst_udp_session_aged', 'dst_tcp_conn_close', 'dst_tcp_conn_close_half_open', 'dst_l4_tcp_auth',
                        'tcp_l4_syn_cookie_fail', 'tcp_l4_rst_cookie_fail', 'tcp_l4_unauth_drop', 'dst_drop_frag_pkt', 'src_tcp_filter_action_blacklist', 'src_tcp_filter_action_whitelist', 'src_tcp_filter_action_drop', 'src_tcp_filter_action_default_pass', 'src_udp_filter_action_blacklist', 'src_udp_filter_action_whitelist',
                        'src_udp_filter_action_drop', 'src_udp_filter_action_default_pass', 'src_other_filter_action_blacklist', 'src_other_filter_action_whitelist', 'src_other_filter_action_drop', 'src_other_filter_action_default_pass', 'tcp_invalid_syn', 'dst_tcp_conn_close_w_rst', 'dst_tcp_conn_close_w_fin', 'dst_tcp_conn_close_w_idle',
                        'dst_tcp_conn_create_from_syn', 'dst_tcp_conn_create_from_ack', 'src_frag_drop', 'dst_l4_tcp_blacklist_drop', 'dst_l4_udp_blacklist_drop', 'dst_l4_icmp_blacklist_drop', 'dst_l4_other_blacklist_drop', 'src_l4_tcp_blacklist_drop', 'src_l4_udp_blacklist_drop', 'src_l4_icmp_blacklist_drop', 'src_l4_other_blacklist_drop',
                        'drop_frag_timeout_drop', 'dst_port_kbit_rate_exceed_pkt', 'dst_tcp_bytes_rcv', 'dst_udp_bytes_rcv', 'dst_icmp_bytes_rcv', 'dst_other_bytes_rcv', 'dst_tcp_bytes_sent', 'dst_udp_bytes_sent', 'dst_icmp_bytes_sent', 'dst_other_bytes_sent', 'dst_udp_auth_drop', 'dst_tcp_auth_drop', 'dst_tcp_auth_resp', 'inbound_pkt_drop',
                        'dst_entry_pkt_rate_exceed', 'dst_entry_kbit_rate_exceed', 'dst_entry_conn_limit_exceed', 'dst_entry_conn_rate_exceed', 'dst_entry_frag_pkt_rate_exceed', 'dst_icmp_any_exceed', 'dst_other_any_exceed', 'src_dst_pair_entry_total', 'src_dst_pair_entry_udp', 'src_dst_pair_entry_tcp', 'src_dst_pair_entry_icmp',
                        'src_dst_pair_entry_other', 'dst_clist_overflow_policy_at_learning', 'tcp_rexmit_syn_limit_drop', 'tcp_rexmit_syn_limit_bl', 'dst_tcp_wellknown_sport_drop', 'src_tcp_wellknown_sport_drop', 'dst_frag_rcvd', 'no_policy_class_list_match', 'src_udp_retry_gap_drop', 'dst_entry_kbit_rate_exceed_count', 'dst_port_undef_hit',
                        'dst_tcp_action_on_ack_timeout', 'dst_tcp_action_on_ack_reset', 'dst_tcp_action_on_ack_blacklist', 'src_tcp_action_on_ack_timeout', 'src_tcp_action_on_ack_reset', 'src_tcp_action_on_ack_blacklist', 'dst_tcp_action_on_syn_timeout', 'dst_tcp_action_on_syn_reset', 'dst_tcp_action_on_syn_blacklist',
                        'src_tcp_action_on_syn_timeout', 'src_tcp_action_on_syn_reset', 'src_tcp_action_on_syn_blacklist', 'dst_udp_frag_pkt_rate_exceed', 'dst_udp_frag_src_rate_drop', 'dst_tcp_frag_pkt_rate_exceed', 'dst_tcp_frag_src_rate_drop', 'dst_icmp_frag_pkt_rate_exceed', 'dst_icmp_frag_src_rate_drop', 'sflow_internal_samples_packed',
                        'sflow_external_samples_packed', 'sflow_internal_packets_sent', 'sflow_external_packets_sent', 'dns_outbound_total_query', 'dns_outbound_query_malformed', 'dns_outbound_query_resp_chk_failed', 'dns_outbound_query_resp_chk_blacklisted', 'dns_outbound_query_resp_chk_refused_sent', 'dns_outbound_query_resp_chk_reset_sent',
                        'dns_outbound_query_resp_chk_no_resp_sent', 'dns_outbound_query_resp_size_exceed', 'dns_outbound_query_sess_timed_out', 'dst_exceed_action_tunnel', 'src_udp_auth_timeout', 'src_udp_retry_pass'
                        ]
                    },
                'counters3': {
                    'type':
                    'str',
                    'choices': [
                        'dst_hw_drop_rule_insert', 'dst_hw_drop_rule_remove', 'src_hw_drop_rule_insert', 'src_hw_drop_rule_remove', 'prog_first_req_time_exceed', 'prog_req_resp_time_exceed', 'prog_request_len_exceed', 'prog_response_len_exceed', 'prog_resp_req_ratio_exceed', 'prog_resp_req_time_exceed', 'entry_sync_message_received',
                        'entry_sync_message_sent', 'prog_conn_sent_exceed', 'prog_conn_rcvd_exceed', 'prog_conn_time_exceed', 'prog_conn_rcvd_sent_ratio_exceed', 'prog_win_sent_exceed', 'prog_win_rcvd_exceed', 'prog_win_rcvd_sent_ratio_exceed', 'prog_exceed_drop', 'prog_exceed_bl', 'prog_conn_exceed_drop', 'prog_conn_exceed_bl',
                        'prog_win_exceed_drop', 'prog_win_exceed_bl', 'dst_exceed_action_drop', 'src_hw_drop', 'dst_tcp_auth_rst', 'dst_src_learn_overflow', 'tcp_fwd_sent', 'udp_fwd_sent'
                        ]
                    }
                }
            },
        'oper': {
            'type': 'dict',
            'ddos_entry_list': {
                'type': 'list',
                'dst_address_str': {
                    'type': 'str',
                    },
                'src_address_str': {
                    'type': 'str',
                    },
                'port_str': {
                    'type': 'str',
                    },
                'state_str': {
                    'type': 'str',
                    },
                'level_str': {
                    'type': 'str',
                    },
                'current_connections': {
                    'type': 'str',
                    },
                'connection_limit': {
                    'type': 'str',
                    },
                'current_connection_rate': {
                    'type': 'str',
                    },
                'connection_rate_limit': {
                    'type': 'str',
                    },
                'current_packet_rate': {
                    'type': 'str',
                    },
                'packet_rate_limit': {
                    'type': 'str',
                    },
                'current_kBit_rate': {
                    'type': 'str',
                    },
                'kBit_rate_limit': {
                    'type': 'str',
                    },
                'current_frag_packet_rate': {
                    'type': 'str',
                    },
                'frag_packet_rate_limit': {
                    'type': 'str',
                    },
                'current_app_stat1': {
                    'type': 'str',
                    },
                'app_stat1_limit': {
                    'type': 'str',
                    },
                'current_app_stat2': {
                    'type': 'str',
                    },
                'app_stat2_limit': {
                    'type': 'str',
                    },
                'current_app_stat3': {
                    'type': 'str',
                    },
                'app_stat3_limit': {
                    'type': 'str',
                    },
                'current_app_stat4': {
                    'type': 'str',
                    },
                'app_stat4_limit': {
                    'type': 'str',
                    },
                'current_app_stat5': {
                    'type': 'str',
                    },
                'app_stat5_limit': {
                    'type': 'str',
                    },
                'current_app_stat6': {
                    'type': 'str',
                    },
                'app_stat6_limit': {
                    'type': 'str',
                    },
                'current_app_stat7': {
                    'type': 'str',
                    },
                'app_stat7_limit': {
                    'type': 'str',
                    },
                'current_app_stat8': {
                    'type': 'str',
                    },
                'app_stat8_limit': {
                    'type': 'str',
                    },
                'age_str': {
                    'type': 'str',
                    },
                'lockup_time_str': {
                    'type': 'str',
                    },
                'dynamic_entry_count': {
                    'type': 'str',
                    },
                'dynamic_entry_limit': {
                    'type': 'str',
                    },
                'sflow_source_id': {
                    'type': 'str',
                    },
                'debug_str': {
                    'type': 'str',
                    }
                },
            'ip_conn_total': {
                'type': 'int',
                },
            'ipv6_conn_total': {
                'type': 'int',
                },
            'entry_displayed_count': {
                'type': 'int',
                },
            'service_displayed_count': {
                'type': 'int',
                },
            'ipv6': {
                'type': 'str',
                },
            'subnet_ip_addr': {
                'type': 'str',
                },
            'subnet_ipv6_addr': {
                'type': 'str',
                },
            'overflow_policy': {
                'type': 'str',
                },
            'ip_proto_num': {
                'type': 'int',
                },
            'l4_type_str': {
                'type': 'str',
                },
            'port_num': {
                'type': 'int',
                },
            'port_range_start': {
                'type': 'int',
                },
            'port_range_end': {
                'type': 'int',
                },
            'src_port_num': {
                'type': 'int',
                },
            'src_port_range_start': {
                'type': 'int',
                },
            'src_port_range_end': {
                'type': 'int',
                },
            'protocol': {
                'type': 'str',
                },
            'sport_protocol': {
                'type': 'str',
                },
            'app_stat': {
                'type': 'bool',
                },
            'all_entries': {
                'type': 'bool',
                },
            'all_ip_protos': {
                'type': 'bool',
                },
            'all_l4_types': {
                'type': 'bool',
                },
            'all_ports': {
                'type': 'bool',
                },
            'all_src_ports': {
                'type': 'bool',
                },
            'black_holed': {
                'type': 'bool',
                },
            'exceeded': {
                'type': 'bool',
                },
            'max_count': {
                'type': 'int',
                },
            'resource_usage': {
                'type': 'bool',
                },
            'hw_blacklisted': {
                'type': 'bool',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/dst/dynamic-entry"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/dst/dynamic-entry"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["dynamic-entry"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["dynamic-entry"].get(k) != v:
            change_results["changed"] = True
            config_changes["dynamic-entry"][k] = v

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
    payload = utils.build_json("dynamic-entry", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["dynamic-entry"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["dynamic-entry-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["dynamic-entry"]["oper"] if info != "NotFound" else info
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
