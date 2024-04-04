#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_long
description:
    - long Statistics
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
            tcp_syncookie_sent:
                description:
                - "TCP SYN Cookie Sent"
                type: str
            tcp_syncookie_pass:
                description:
                - "TCP SYN Cookie Passed"
                type: str
            tcp_syncookie_sent_fail:
                description:
                - "TCP SYN Cookie Send Failed"
                type: str
            tcp_syncookie_check_fail:
                description:
                - "TCP SYN Cookie Check Failed"
                type: str
            tcp_syncookie_fail_bl:
                description:
                - "TCP SYN Cookie Blacklist Failed"
                type: str
            tcp_outrst:
                description:
                - "TCP Outbound RST"
                type: str
            tcp_syn_received:
                description:
                - "TCP SYN Received"
                type: str
            tcp_syn_rate:
                description:
                - "TCP SYN Rate Per Sec"
                type: str
            udp_exceed_drop_conn_prate:
                description:
                - "UDP Conn Pkt Rate Exceeded"
                type: str
            dns_malform_drop:
                description:
                - "DNS Malform Drop"
                type: str
            dns_qry_any_drop:
                description:
                - "DNS Query Any Drop"
                type: str
            tcp_reset_client:
                description:
                - "TCP Reset Client"
                type: str
            tcp_reset_server:
                description:
                - "TCP Reset Server"
                type: str
            dst_entry_learn:
                description:
                - "Dst Entry Learned"
                type: str
            dst_entry_hit:
                description:
                - "Dst Entry Hit"
                type: str
            src_entry_learn:
                description:
                - "Src Entry Learned"
                type: str
            src_entry_hit:
                description:
                - "Src Entry Hit"
                type: str
            sync_src_wl_sent:
                description:
                - "Sync Src Sent"
                type: str
            sync_src_dst_wl_sent:
                description:
                - "Sync SrcDst Sent"
                type: str
            sync_dst_wl_sent:
                description:
                - "Sync Dst Sent"
                type: str
            sync_src_wl_rcv:
                description:
                - "Sync Src Received"
                type: str
            sync_src_dst_wl_rcv:
                description:
                - "Sync SrcDst Received"
                type: str
            sync_dst_wl_rcv:
                description:
                - "Sync Dst Received"
                type: str
            dst_port_pkt_rate_exceed:
                description:
                - "Dst Port Pkt Rate Exceeded"
                type: str
            dst_port_conn_limit_exceed:
                description:
                - "Dst Port Conn Limit Exceeded"
                type: str
            dst_port_conn_rate_exceed:
                description:
                - "Dst Port Conn Rate Exceeded"
                type: str
            dst_sport_pkt_rate_exceed:
                description:
                - "Dst SrcPort Pkt Rate Exceeded"
                type: str
            dst_sport_conn_limit_exceed:
                description:
                - "Dst SrcPort Conn Limit Exceeded"
                type: str
            dst_sport_conn_rate_exceed:
                description:
                - "Dst SrcPort Conn Rate Exceeded"
                type: str
            dst_ipproto_pkt_rate_exceed:
                description:
                - "Dst IP-Proto Pkt Rate Exceeded"
                type: str
            tcp_ack_no_syn:
                description:
                - "TCP ACK No SYN"
                type: str
            tcp_out_of_order:
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
            src_entry_aged:
                description:
                - "Src Entry Aged"
                type: str
            dst_entry_aged:
                description:
                - "Dst Entry Aged"
                type: str
            tcp_zero_wind_bl:
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
            syn_auth_skip:
                description:
                - "TCP SYN Auth Skipped"
                type: str
            udp_retry_pass:
                description:
                - "UDP Retry Passed"
                type: str
            dns_auth_udp_pass:
                description:
                - "DNS Auth UDP Passed"
                type: str
            udp_dst_wellknown_port_drop:
                description:
                - "UDP Wellknown Port Drop"
                type: str
            udp_ntp_monlist_req_drop:
                description:
                - "NTP Monlist Request Dropped"
                type: str
            udp_ntp_monlist_resp_drop:
                description:
                - "NTP Monlist Response Dropped"
                type: str
            udp_payload_too_big_drop:
                description:
                - "UDP Payload Too Large Dropped"
                type: str
            udp_payload_too_small_drop:
                description:
                - "UDP Payload Too Small Dropped"
                type: str
            tcp_rexmit_syn_limit_drop:
                description:
                - "TCP Retransmit SYN Exceed Dropped"
                type: str
            tcp_rexmit_syn_limit_bl:
                description:
                - "TCP Retransmit SYN Exceed Blacklisted"
                type: str
            tcp_exceed_drop_conn_prate:
                description:
                - "TCP Conn Pkt Rate Dropped"
                type: str
            ip_tunnel_rcvd:
                description:
                - "IPv4 Tunnel Received"
                type: str
            ipv6_tunnel_rcvd:
                description:
                - "IPv6 Tunnel Received"
                type: str
            gre_tunnel_rcvd:
                description:
                - "GRE Tunnel Received"
                type: str
            gre_v6_tunnel_rcvd:
                description:
                - "GRE V6 Tunnel Received"
                type: str
            dns_tcp_auth_pass:
                description:
                - "DNS Auth Force-TCP Passed"
                type: str
            jumbo_frag_drop:
                description:
                - "Jumbo Frag Drop"
                type: str
            entry_create_fail_drop:
                description:
                - "Entry Create Fail Drop"
                type: str
            dst_port_kbit_rate_exceed:
                description:
                - "Dst Port KiBit Rate Exceeded (KiBit)"
                type: str
            dst_sport_kbit_rate_exceed:
                description:
                - "Dst SrcPort KiBit Rate Exceeded (KiBit)"
                type: str
            ip_tunnel_encap:
                description:
                - "IPv4 Tunnel Encap"
                type: str
            ip_tunnel_encap_fail:
                description:
                - "IPv4 Tunnel Encap Failed"
                type: str
            ip_tunnel_decap:
                description:
                - "IPv4 Tunnel Decap"
                type: str
            ip_tunnel_decap_fail:
                description:
                - "IPv4 Tunnel Decap Failed"
                type: str
            ip_tunnel_rate_limit_inner:
                description:
                - "IPv4 Tunnel Rate Limit Inner Pkts"
                type: str
            ipv6_tunnel_encap:
                description:
                - "IPv6 Tunnel Encap"
                type: str
            ipv6_tunnel_encap_fail:
                description:
                - "IPv6 Tunnel Encap Failed"
                type: str
            ipv6_tunnel_decap:
                description:
                - "IPv6 Tunnel Decap"
                type: str
            ipv6_tunnel_decap_fail:
                description:
                - "IPv6 Tunnel Decap Failed"
                type: str
            ipv6_tunnel_rate_limit_inner:
                description:
                - "IPv6 Tunnel Rate Limit Inner Pkts"
                type: str
            ip_gre_tunnel_encap:
                description:
                - "GRE Tunnel Encap"
                type: str
            ip_gre_tunnel_encap_fail:
                description:
                - "GRE Tunnel Encap Failed"
                type: str
            ip_gre_tunnel_decap:
                description:
                - "GRE Tunnel Decap"
                type: str
            ip_gre_tunnel_decap_fail:
                description:
                - "GRE Tunnel Decap Failed"
                type: str
            ip_gre_tunnel_rate_limit_inner:
                description:
                - "GRE Tunnel Rate Limit Inner Pkts"
                type: str
            ip_gre_tunnel_encap_key:
                description:
                - "GRE Tunnel Encap W/ Key"
                type: str
            ip_gre_tunnel_decap_key:
                description:
                - "GRE Tunnel Decap W/ Key"
                type: str
            ip_gre_tunnel_decap_key_drop:
                description:
                - "GRE Tunnel Decap Key Mismatch Dropped"
                type: str
            ipv6_gre_tunnel_encap:
                description:
                - "GRE V6 Tunnel Encap"
                type: str
            ipv6_gre_tunnel_encap_fail:
                description:
                - "GRE V6 Tunnel Encap Failed"
                type: str
            ipv6_gre_tunnel_decap:
                description:
                - "GRE V6 Tunnel Decap"
                type: str
            ipv6_gre_tunnel_decap_fail:
                description:
                - "GRE V6 Tunnel Decap Failed"
                type: str
            ipv6_gre_tunnel_rate_limit_inner:
                description:
                - "GRE V6 Tunnel Rate Limit Inner Pkts"
                type: str
            ipv6_gre_tunnel_encap_key:
                description:
                - "GRE V6 Tunnel Encap W/ Key"
                type: str
            ipv6_gre_tunnel_decap_key:
                description:
                - "GRE V6 Tunnel Decap W/ Key"
                type: str
            ipv6_gre_tunnel_decap_key_drop:
                description:
                - "GRE V6 Tunnel Decap Key Mismatch Dropped"
                type: str
            ip_vxlan_tunnel_rcvd:
                description:
                - "IP VxLAN Tunnel Received"
                type: str
            ip_vxlan_tunnel_invalid_vni:
                description:
                - "IP VxLAN Tunnel Invalid VNI"
                type: str
            ip_vxlan_tunnel_decap:
                description:
                - "IP VxLAN Tunnel Decap"
                type: str
            ip_vxlan_tunnel_decap_err:
                description:
                - "IP VxLAN Tunnel Decap Error"
                type: str
            jumbo_frag_drop_by_filter:
                description:
                - "Jumbo Fragment Filter Miss Drop"
                type: str
            jumbo_frag_drop_before_slb:
                description:
                - "Jumbo Fragment Non Data Plane Drop"
                type: str
            jumbo_outgoing_mtu_exceed_drop:
                description:
                - "Jumbo Outgoing MTU Exceed Drop"
                type: str
            jumbo_in_tunnel_drop:
                description:
                - "Jumbo Packet in Tunnel Drop"
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
            'tcp_syncookie_sent': {
                'type': 'str',
                },
            'tcp_syncookie_pass': {
                'type': 'str',
                },
            'tcp_syncookie_sent_fail': {
                'type': 'str',
                },
            'tcp_syncookie_check_fail': {
                'type': 'str',
                },
            'tcp_syncookie_fail_bl': {
                'type': 'str',
                },
            'tcp_outrst': {
                'type': 'str',
                },
            'tcp_syn_received': {
                'type': 'str',
                },
            'tcp_syn_rate': {
                'type': 'str',
                },
            'udp_exceed_drop_conn_prate': {
                'type': 'str',
                },
            'dns_malform_drop': {
                'type': 'str',
                },
            'dns_qry_any_drop': {
                'type': 'str',
                },
            'tcp_reset_client': {
                'type': 'str',
                },
            'tcp_reset_server': {
                'type': 'str',
                },
            'dst_entry_learn': {
                'type': 'str',
                },
            'dst_entry_hit': {
                'type': 'str',
                },
            'src_entry_learn': {
                'type': 'str',
                },
            'src_entry_hit': {
                'type': 'str',
                },
            'sync_src_wl_sent': {
                'type': 'str',
                },
            'sync_src_dst_wl_sent': {
                'type': 'str',
                },
            'sync_dst_wl_sent': {
                'type': 'str',
                },
            'sync_src_wl_rcv': {
                'type': 'str',
                },
            'sync_src_dst_wl_rcv': {
                'type': 'str',
                },
            'sync_dst_wl_rcv': {
                'type': 'str',
                },
            'dst_port_pkt_rate_exceed': {
                'type': 'str',
                },
            'dst_port_conn_limit_exceed': {
                'type': 'str',
                },
            'dst_port_conn_rate_exceed': {
                'type': 'str',
                },
            'dst_sport_pkt_rate_exceed': {
                'type': 'str',
                },
            'dst_sport_conn_limit_exceed': {
                'type': 'str',
                },
            'dst_sport_conn_rate_exceed': {
                'type': 'str',
                },
            'dst_ipproto_pkt_rate_exceed': {
                'type': 'str',
                },
            'tcp_ack_no_syn': {
                'type': 'str',
                },
            'tcp_out_of_order': {
                'type': 'str',
                },
            'tcp_zero_window': {
                'type': 'str',
                },
            'tcp_retransmit': {
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
            'src_entry_aged': {
                'type': 'str',
                },
            'dst_entry_aged': {
                'type': 'str',
                },
            'tcp_zero_wind_bl': {
                'type': 'str',
                },
            'tcp_out_of_seq_bl': {
                'type': 'str',
                },
            'tcp_retransmit_bl': {
                'type': 'str',
                },
            'syn_auth_skip': {
                'type': 'str',
                },
            'udp_retry_pass': {
                'type': 'str',
                },
            'dns_auth_udp_pass': {
                'type': 'str',
                },
            'udp_dst_wellknown_port_drop': {
                'type': 'str',
                },
            'udp_ntp_monlist_req_drop': {
                'type': 'str',
                },
            'udp_ntp_monlist_resp_drop': {
                'type': 'str',
                },
            'udp_payload_too_big_drop': {
                'type': 'str',
                },
            'udp_payload_too_small_drop': {
                'type': 'str',
                },
            'tcp_rexmit_syn_limit_drop': {
                'type': 'str',
                },
            'tcp_rexmit_syn_limit_bl': {
                'type': 'str',
                },
            'tcp_exceed_drop_conn_prate': {
                'type': 'str',
                },
            'ip_tunnel_rcvd': {
                'type': 'str',
                },
            'ipv6_tunnel_rcvd': {
                'type': 'str',
                },
            'gre_tunnel_rcvd': {
                'type': 'str',
                },
            'gre_v6_tunnel_rcvd': {
                'type': 'str',
                },
            'dns_tcp_auth_pass': {
                'type': 'str',
                },
            'jumbo_frag_drop': {
                'type': 'str',
                },
            'entry_create_fail_drop': {
                'type': 'str',
                },
            'dst_port_kbit_rate_exceed': {
                'type': 'str',
                },
            'dst_sport_kbit_rate_exceed': {
                'type': 'str',
                },
            'ip_tunnel_encap': {
                'type': 'str',
                },
            'ip_tunnel_encap_fail': {
                'type': 'str',
                },
            'ip_tunnel_decap': {
                'type': 'str',
                },
            'ip_tunnel_decap_fail': {
                'type': 'str',
                },
            'ip_tunnel_rate_limit_inner': {
                'type': 'str',
                },
            'ipv6_tunnel_encap': {
                'type': 'str',
                },
            'ipv6_tunnel_encap_fail': {
                'type': 'str',
                },
            'ipv6_tunnel_decap': {
                'type': 'str',
                },
            'ipv6_tunnel_decap_fail': {
                'type': 'str',
                },
            'ipv6_tunnel_rate_limit_inner': {
                'type': 'str',
                },
            'ip_gre_tunnel_encap': {
                'type': 'str',
                },
            'ip_gre_tunnel_encap_fail': {
                'type': 'str',
                },
            'ip_gre_tunnel_decap': {
                'type': 'str',
                },
            'ip_gre_tunnel_decap_fail': {
                'type': 'str',
                },
            'ip_gre_tunnel_rate_limit_inner': {
                'type': 'str',
                },
            'ip_gre_tunnel_encap_key': {
                'type': 'str',
                },
            'ip_gre_tunnel_decap_key': {
                'type': 'str',
                },
            'ip_gre_tunnel_decap_key_drop': {
                'type': 'str',
                },
            'ipv6_gre_tunnel_encap': {
                'type': 'str',
                },
            'ipv6_gre_tunnel_encap_fail': {
                'type': 'str',
                },
            'ipv6_gre_tunnel_decap': {
                'type': 'str',
                },
            'ipv6_gre_tunnel_decap_fail': {
                'type': 'str',
                },
            'ipv6_gre_tunnel_rate_limit_inner': {
                'type': 'str',
                },
            'ipv6_gre_tunnel_encap_key': {
                'type': 'str',
                },
            'ipv6_gre_tunnel_decap_key': {
                'type': 'str',
                },
            'ipv6_gre_tunnel_decap_key_drop': {
                'type': 'str',
                },
            'ip_vxlan_tunnel_rcvd': {
                'type': 'str',
                },
            'ip_vxlan_tunnel_invalid_vni': {
                'type': 'str',
                },
            'ip_vxlan_tunnel_decap': {
                'type': 'str',
                },
            'ip_vxlan_tunnel_decap_err': {
                'type': 'str',
                },
            'jumbo_frag_drop_by_filter': {
                'type': 'str',
                },
            'jumbo_frag_drop_before_slb': {
                'type': 'str',
                },
            'jumbo_outgoing_mtu_exceed_drop': {
                'type': 'str',
                },
            'jumbo_in_tunnel_drop': {
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
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/long"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/long"

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
    payload = utils.build_json("long", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["long"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["long-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["long"]["stats"] if info != "NotFound" else info
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
