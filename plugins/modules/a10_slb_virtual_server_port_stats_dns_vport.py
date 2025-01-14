#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_virtual_server_port_stats_dns_vport
description:
    - Statistics for the object port
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
    port_number:
        description:
        - Key to identify parent object
        type: str
        required: True
    virtual_server_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    port_number:
        description:
        - "Port"
        type: int
        required: True
    protocol:
        description:
        - "'tcp'= TCP LB service; 'udp'= UDP Port; 'others'= for no tcp/udp protocol, do
          IP load balancing; 'diameter'= diameter port; 'dns-tcp'= DNS service over TCP;
          'dns-udp'= DNS service over UDP; 'fast-http'= Fast HTTP Port; 'fix'= FIX Port;
          'ftp'= File Transfer Protocol Port; 'ftp-proxy'= ftp proxy port; 'http'= HTTP
          Port; 'https'= HTTPS port; 'imap'= imap proxy port; 'mlb'= Message based load
          balancing; 'mms'= Microsoft Multimedia Service Port; 'mysql'= mssql port;
          'mssql'= mssql; 'pop3'= pop3 proxy port; 'radius'= RADIUS Port; 'rtsp'= Real
          Time Streaming Protocol Port; 'sip'= Session initiation protocol over UDP;
          'sip-tcp'= Session initiation protocol over TCP; 'sips'= Session initiation
          protocol over TLS; 'smpp-tcp'= SMPP service over TCP; 'spdy'= spdy port;
          'spdys'= spdys port; 'smtp'= SMTP Port; 'mqtt'= MQTT Port; 'mqtts'= MQTTS Port;
          'ssl-proxy'= Generic SSL proxy; 'ssli'= SSL insight; 'ssh'= SSH Port; 'tcp-
          proxy'= Generic TCP proxy; 'tftp'= TFTP Port; 'fast-fix'= Fast FIX port; 'http-
          over-quic'= HTTP3-over-quic port;"
        type: str
        required: True
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            dns_vport:
                description:
                - "Field dns_vport"
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
AVAILABLE_PROPERTIES = ["port_number", "protocol", "stats", ]


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
        'port_number': {
            'type': 'int',
            'required': True,
            },
        'protocol': {
            'type':
            'str',
            'required':
            True,
            'choices': [
                'tcp', 'udp', 'others', 'diameter', 'dns-tcp', 'dns-udp', 'fast-http', 'fix', 'ftp', 'ftp-proxy', 'http', 'https', 'imap', 'mlb', 'mms', 'mysql', 'mssql', 'pop3', 'radius', 'rtsp', 'sip', 'sip-tcp', 'sips', 'smpp-tcp', 'spdy', 'spdys', 'smtp', 'mqtt', 'mqtts', 'ssl-proxy', 'ssli', 'ssh', 'tcp-proxy', 'tftp', 'fast-fix',
                'http-over-quic'
                ]
            },
        'stats': {
            'type': 'dict',
            'dns_vport': {
                'type': 'dict',
                'dns_total_request': {
                    'type': 'str',
                    },
                'dns_total_response': {
                    'type': 'str',
                    },
                'dns_total_drop': {
                    'type': 'str',
                    },
                'dns_request_response': {
                    'type': 'str',
                    },
                'dns_request_send': {
                    'type': 'str',
                    },
                'dns_request_drop': {
                    'type': 'str',
                    },
                'dns_response_drop': {
                    'type': 'str',
                    },
                'dns_response_send': {
                    'type': 'str',
                    },
                'dns_request_timeout': {
                    'type': 'str',
                    },
                'dns_request_rexmit': {
                    'type': 'str',
                    },
                'dns_cache_hit': {
                    'type': 'str',
                    },
                'dnsrrl_total_dropped': {
                    'type': 'str',
                    },
                'total_mf_dns_pkt': {
                    'type': 'str',
                    },
                'total_filter_drop': {
                    'type': 'str',
                    },
                'total_max_query_len_drop': {
                    'type': 'str',
                    },
                'rcode_formerr_receive': {
                    'type': 'str',
                    },
                'rcode_serverr_receive': {
                    'type': 'str',
                    },
                'rcode_nxdomain_receive': {
                    'type': 'str',
                    },
                'rcode_notimpl_receive': {
                    'type': 'str',
                    },
                'rcode_refuse_receive': {
                    'type': 'str',
                    },
                'rcode_yxdomain_receive': {
                    'type': 'str',
                    },
                'rcode_yxrrset_receive': {
                    'type': 'str',
                    },
                'rcode_nxrrset_receive': {
                    'type': 'str',
                    },
                'rcode_notauth_receive': {
                    'type': 'str',
                    },
                'rcode_dsotypen_receive': {
                    'type': 'str',
                    },
                'rcode_badver_receive': {
                    'type': 'str',
                    },
                'rcode_badkey_receive': {
                    'type': 'str',
                    },
                'rcode_badtime_receive': {
                    'type': 'str',
                    },
                'rcode_badmode_receive': {
                    'type': 'str',
                    },
                'rcode_badname_receive': {
                    'type': 'str',
                    },
                'rcode_badalg_receive': {
                    'type': 'str',
                    },
                'rcode_badtranc_receive': {
                    'type': 'str',
                    },
                'rcode_badcookie_receive': {
                    'type': 'str',
                    },
                'rcode_other_receive': {
                    'type': 'str',
                    },
                'rcode_noerror_generate': {
                    'type': 'str',
                    },
                'rcode_formerr_response': {
                    'type': 'str',
                    },
                'rcode_serverr_response': {
                    'type': 'str',
                    },
                'rcode_nxdomain_response': {
                    'type': 'str',
                    },
                'rcode_notimpl_response': {
                    'type': 'str',
                    },
                'rcode_refuse_response': {
                    'type': 'str',
                    },
                'rcode_yxdomain_response': {
                    'type': 'str',
                    },
                'rcode_yxrrset_response': {
                    'type': 'str',
                    },
                'rcode_nxrrset_response': {
                    'type': 'str',
                    },
                'rcode_notauth_response': {
                    'type': 'str',
                    },
                'rcode_dsotypen_response': {
                    'type': 'str',
                    },
                'rcode_badver_response': {
                    'type': 'str',
                    },
                'rcode_badkey_response': {
                    'type': 'str',
                    },
                'rcode_badtime_response': {
                    'type': 'str',
                    },
                'rcode_badmode_response': {
                    'type': 'str',
                    },
                'rcode_badname_response': {
                    'type': 'str',
                    },
                'rcode_badalg_response': {
                    'type': 'str',
                    },
                'rcode_badtranc_response': {
                    'type': 'str',
                    },
                'rcode_badcookie_response': {
                    'type': 'str',
                    },
                'rcode_other_response': {
                    'type': 'str',
                    },
                'gslb_drop': {
                    'type': 'str',
                    },
                'gslb_query_drop': {
                    'type': 'str',
                    },
                'gslb_query_bad': {
                    'type': 'str',
                    },
                'gslb_response_drop': {
                    'type': 'str',
                    },
                'gslb_response_bad': {
                    'type': 'str',
                    },
                'gslb_query_fwd': {
                    'type': 'str',
                    },
                'gslb_response_rvs': {
                    'type': 'str',
                    },
                'gslb_response_good': {
                    'type': 'str',
                    },
                'type_A_query': {
                    'type': 'str',
                    },
                'type_AAAA_query': {
                    'type': 'str',
                    },
                'type_CNAME_query': {
                    'type': 'str',
                    },
                'type_MX_query': {
                    'type': 'str',
                    },
                'type_NS_query': {
                    'type': 'str',
                    },
                'type_SRV_query': {
                    'type': 'str',
                    },
                'type_PTR_query': {
                    'type': 'str',
                    },
                'type_SOA_query': {
                    'type': 'str',
                    },
                'type_TXT_query': {
                    'type': 'str',
                    },
                'type_ANY_query': {
                    'type': 'str',
                    },
                'type_other_query': {
                    'type': 'str',
                    },
                'type_NSID_query': {
                    'type': 'str',
                    },
                'type_DAU_query': {
                    'type': 'str',
                    },
                'type_N3U_query': {
                    'type': 'str',
                    },
                'type_EXPIRE_query': {
                    'type': 'str',
                    },
                'type_COOKIE_query': {
                    'type': 'str',
                    },
                'type_KEEPALIVE_query': {
                    'type': 'str',
                    },
                'type_PADDING_query': {
                    'type': 'str',
                    },
                'type_CHAIN_query': {
                    'type': 'str',
                    },
                'total_dns_filter_type_drop': {
                    'type': 'str',
                    },
                'total_dns_filter_class_drop': {
                    'type': 'str',
                    },
                'dns_filter_type_a_drop': {
                    'type': 'str',
                    },
                'dns_filter_type_aaaa_drop': {
                    'type': 'str',
                    },
                'dns_filter_type_cname_drop': {
                    'type': 'str',
                    },
                'dns_filter_type_mx_drop': {
                    'type': 'str',
                    },
                'dns_filter_type_ns_drop': {
                    'type': 'str',
                    },
                'dns_filter_type_srv_drop': {
                    'type': 'str',
                    },
                'dns_filter_type_ptr_drop': {
                    'type': 'str',
                    },
                'dns_filter_type_soa_drop': {
                    'type': 'str',
                    },
                'dns_filter_type_txt_drop': {
                    'type': 'str',
                    },
                'dns_filter_type_any_drop': {
                    'type': 'str',
                    },
                'dns_filter_type_others_drop': {
                    'type': 'str',
                    },
                'dns_filter_class_internet_drop': {
                    'type': 'str',
                    },
                'dns_filter_class_chaos_drop': {
                    'type': 'str',
                    },
                'dns_filter_class_hesiod_drop': {
                    'type': 'str',
                    },
                'dns_filter_class_none_drop': {
                    'type': 'str',
                    },
                'dns_filter_class_any_drop': {
                    'type': 'str',
                    },
                'dns_filter_class_others_drop': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_started': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_succeeded': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_send_failed': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_timeout': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_retransmit_sent': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_retransmit_exceeded': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_buff_alloc_failed': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_ongoing_client_retransmit': {
                    'type': 'str',
                    },
                'slb_dns_client_ssl_succ': {
                    'type': 'str',
                    },
                'slb_dns_server_ssl_succ': {
                    'type': 'str',
                    },
                'slb_dns_udp_conn': {
                    'type': 'str',
                    },
                'slb_dns_udp_conn_succ': {
                    'type': 'str',
                    },
                'slb_dns_padding_to_server_removed': {
                    'type': 'str',
                    },
                'slb_dns_padding_to_client_added': {
                    'type': 'str',
                    },
                'slb_dns_edns_subnet_to_server_removed': {
                    'type': 'str',
                    },
                'slb_dns_udp_retransmit': {
                    'type': 'str',
                    },
                'slb_dns_udp_retransmit_fail': {
                    'type': 'str',
                    },
                'dns_rpz_action_drop': {
                    'type': 'str',
                    },
                'dns_rpz_action_pass_thru': {
                    'type': 'str',
                    },
                'dns_rpz_action_tcp_only': {
                    'type': 'str',
                    },
                'dns_rpz_action_nxdomain': {
                    'type': 'str',
                    },
                'dns_rpz_action_nodata': {
                    'type': 'str',
                    },
                'dns_rpz_action_local_data': {
                    'type': 'str',
                    },
                'dns_rpz_trigger_client_ip': {
                    'type': 'str',
                    },
                'dns_rpz_trigger_resp_ip': {
                    'type': 'str',
                    },
                'dns_rpz_trigger_ns_ip': {
                    'type': 'str',
                    },
                'dns_rpz_trigger_qname': {
                    'type': 'str',
                    },
                'dns_rpz_trigger_ns_name': {
                    'type': 'str',
                    },
                'dnsrrl_total_allowed': {
                    'type': 'str',
                    },
                'dnsrrl_total_slipped': {
                    'type': 'str',
                    },
                'dnsrrl_bad_fqdn': {
                    'type': 'str',
                    },
                'total_mf_dns_pkt_detect': {
                    'type': 'str',
                    },
                'type_RRSIG_query': {
                    'type': 'str',
                    },
                'type_TSIG_query': {
                    'type': 'str',
                    },
                'type_DNSKEY_query': {
                    'type': 'str',
                    },
                'type_AXFR_query': {
                    'type': 'str',
                    },
                'type_IXFR_query': {
                    'type': 'str',
                    },
                'type_CAA_query': {
                    'type': 'str',
                    },
                'type_NAPTR_query': {
                    'type': 'str',
                    },
                'type_DS_query': {
                    'type': 'str',
                    },
                'type_CERT_query': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_not_dplane': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_no_resolver': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_max_trials_exceeded': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_no_hints': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_res_submit_err': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_res_check_err': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_udp_conn_err': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_tcp_conn_err': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_udp_send_failed': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_icmp_err': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_query_not_sent': {
                    'type': 'str',
                    },
                'dns_tcp_pipeline_request_drop': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_resp_truncated': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_full_response': {
                    'type': 'str',
                    },
                'dns_full_response_from_cache': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_missing_glue': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_ns_cache_hit': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_ns_cache_miss': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_lookup_ip_proto_switch_46': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_lookup_ip_proto_switch_64': {
                    'type': 'str',
                    },
                'slb_dns_edns_ecs_received': {
                    'type': 'str',
                    },
                'slb_dns_edns_ecs_inserted': {
                    'type': 'str',
                    },
                'slb_dns_edns_ecs_insertion_fail': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_invalid_hints': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_pending_resolution': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_query_dropped': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_respond_with_servfail': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_total_trials_1': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_total_trials_3': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_total_trials_6': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_total_trials_12': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_total_trials_24': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_total_trials_48': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_total_trials_64': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_total_trials_128': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_total_trials_max': {
                    'type': 'str',
                    },
                'type_HTTPS_query': {
                    'type': 'str',
                    },
                'empty_response': {
                    'type': 'str',
                    },
                'dnsrrl_total_tc': {
                    'type': 'str',
                    },
                'dns_negative_served': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_reach_max_depth': {
                    'type': 'str',
                    },
                'dns_rr_dnssec_req_received': {
                    'type': 'str',
                    },
                'dns_rr_dnssec_resp_served': {
                    'type': 'str',
                    },
                'dns_rr_dnssec_validation_failed': {
                    'type': 'str',
                    },
                'dns_rr_dnssec_val_alg_not_supported': {
                    'type': 'str',
                    },
                'dns_rr_dnssec_val_dgst_not_supported': {
                    'type': 'str',
                    },
                'dns_rr_dnssec_val_rrsig_signer_err': {
                    'type': 'str',
                    },
                'dns_rr_dnssec_val_rrsig_labels_err': {
                    'type': 'str',
                    },
                'dns_rr_dnssec_val_rrsig_non_validity_period': {
                    'type': 'str',
                    },
                'dns_rr_dnssec_val_dnskey_proto_err': {
                    'type': 'str',
                    },
                'dns_rr_dnssec_val_incorrect_sig': {
                    'type': 'str',
                    },
                'dns_rr_dnssec_val_incorrect_key_dgst': {
                    'type': 'str',
                    },
                'dns_rr_dnssec_val_with_trust_anchor_failed': {
                    'type': 'str',
                    },
                'dns_rr_dnssec_val_rrset_size_exceed_limit': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_late_ans': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_udp_conn': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_tcp_conn': {
                    'type': 'str',
                    },
                'dns_category_action_drop': {
                    'type': 'str',
                    },
                'dns_category_action_respond': {
                    'type': 'str',
                    },
                'dns_category_action_permit': {
                    'type': 'str',
                    },
                'dns_category_resp_nxdomain': {
                    'type': 'str',
                    },
                'dns_category_resp_noanswer': {
                    'type': 'str',
                    },
                'dns_category_resp_a': {
                    'type': 'str',
                    },
                'dns_category_resp_aaaa': {
                    'type': 'str',
                    },
                'dns_category_resp_cname': {
                    'type': 'str',
                    },
                'dns_category_bypass': {
                    'type': 'str',
                    },
                'dns_category_async_sent': {
                    'type': 'str',
                    },
                'dns_category_async_received': {
                    'type': 'str',
                    },
                'dns_category_no_local_result': {
                    'type': 'str',
                    },
                'rcode_notzone_receive': {
                    'type': 'str',
                    },
                'rcode_tsig_badsig_receive': {
                    'type': 'str',
                    },
                'rcode_tsig_badkey_receive': {
                    'type': 'str',
                    },
                'rcode_tsig_badtime_receive': {
                    'type': 'str',
                    },
                'rcode_tsig_badtrunc_receive': {
                    'type': 'str',
                    },
                'dns_filter_tld_drop': {
                    'type': 'str',
                    },
                'dnsrrl_qps_drop': {
                    'type': 'str',
                    },
                'dnsrrl_nx_drop': {
                    'type': 'str',
                    },
                'dnsrrl_nx_exceed': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_request_send': {
                    'type': 'str',
                    },
                'dns_recursive_resolution_response_receive': {
                    'type': 'str',
                    }
                }
            }
        })
    # Parent keys
    rv.update(dict(protocol=dict(type='str', required=True), port_number=dict(type='str', required=True), virtual_server_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/virtual-server/{virtual_server_name}/port/{port_number}+{protocol}/stats?dns_vport=true"

    f_dict = {}
    if '/' in module.params["protocol"]:
        f_dict["protocol"] = module.params["protocol"].replace("/", "%2F")
    else:
        f_dict["protocol"] = module.params["protocol"]
    if '/' in module.params["port_number"]:
        f_dict["port_number"] = module.params["port_number"].replace("/", "%2F")
    else:
        f_dict["port_number"] = module.params["port_number"]
    if '/' in module.params["virtual_server_name"]:
        f_dict["virtual_server_name"] = module.params["virtual_server_name"].replace("/", "%2F")
    else:
        f_dict["virtual_server_name"] = module.params["virtual_server_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/virtual-server/{virtual_server_name}/port/{port_number}+{protocol}/stats?dns_vport=true"

    f_dict = {}
    f_dict["protocol"] = module.params["protocol"]
    f_dict["port_number"] = module.params["port_number"]
    f_dict["virtual_server_name"] = module.params["virtual_server_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["port"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["port"].get(k) != v:
            change_results["changed"] = True
            config_changes["port"][k] = v

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
    payload = utils.build_json("port", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["port"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["port-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["port"]["stats"] if info != "NotFound" else info
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
