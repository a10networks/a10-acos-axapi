#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_system_session
description:
    - Session Entries
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
                - "'all'= all; 'total_l4_conn'= Total L4 Count; 'conn_counter'= Conn Count;
          'conn_freed_counter'= Conn Freed; 'total_l4_packet_count'= Total L4 Packet
          Count; 'total_l7_packet_count'= Total L7 Packet Count; 'total_l4_conn_proxy'=
          Total L4 Conn Proxy Count; 'total_l7_conn'= Total L7 Conn; 'total_tcp_conn'=
          Total TCP Conn; 'curr_free_conn'= Curr Free Conn; 'tcp_est_counter'= TCP
          Established; 'tcp_half_open_counter'= TCP Half Open; 'tcp_half_close_counter'=
          TCP Half Closed; 'udp_counter'= UDP Count; 'ip_counter'= IP Count;
          'other_counter'= Non TCP/UDP IP sessions; 'reverse_nat_tcp_counter'= Reverse
          NAT TCP; 'reverse_nat_udp_counter'= Reverse NAT UDP;
          'tcp_syn_half_open_counter'= TCP SYN Half Open; 'conn_smp_alloc_counter'= Conn
          SMP Alloc; 'conn_smp_free_counter'= Conn SMP Free; 'conn_smp_aged_counter'=
          Conn SMP Aged; 'ssl_count_curr'= Curr SSL Count; 'ssl_count_total'= Total SSL
          Count; 'server_ssl_count_curr'= Current SSL Server Count;
          'server_ssl_count_total'= Total SSL Server Count; 'client_ssl_reuse_total'=
          Total SSL Client Reuse; 'server_ssl_reuse_total'= Total SSL Server Reuse;
          'ssl_failed_total'= Total SSL Failures; 'ssl_failed_ca_verification'= SSL Cert
          Auth Verification Errors; 'ssl_server_cert_error'= SSL Server Cert Errors;
          'ssl_client_cert_auth_fail'= SSL Client Cert Auth Failures;
          'total_ip_nat_conn'= Total IP Nat Conn; 'total_l2l3_conn'= Totl L2/L3
          Connections; 'client_ssl_ctx_malloc_failure'= Client SSL Ctx malloc Failures;
          'conn_type_0_available'= Conn Type 0 Available; 'conn_type_1_available'= Conn
          Type 1 Available; 'conn_type_2_available'= Conn Type 2 Available;
          'conn_type_3_available'= Conn Type 3 Available; 'conn_type_4_available'= Conn
          Type 4 Available; 'conn_smp_type_0_available'= Conn SMP Type 0 Available;
          'conn_smp_type_1_available'= Conn SMP Type 1 Available;
          'conn_smp_type_2_available'= Conn SMP Type 2 Available;
          'conn_smp_type_3_available'= Conn SMP Type 3 Available;
          'conn_smp_type_4_available'= Conn SMP Type 4 Available; 'sctp-half-open-
          counter'= SCTP Half Open; 'sctp-est-counter'= SCTP Established;
          'nonssl_bypass'= NON SSL Bypass Count; 'ssl_failsafe_total'= Total SSL Failsafe
          Count; 'ssl_forward_proxy_failed_handshake_total'= Total SSL Forward Proxy
          Failed Handshake Count; 'ssl_forward_proxy_failed_tcp_total'= Total SSL Forward
          Proxy Failed TCP Count; 'ssl_forward_proxy_failed_crypto_total'= Total SSL
          Forward Proxy Failed Crypto Count;
          'ssl_forward_proxy_failed_cert_verify_total'= Total SSL Forward Proxy Failed
          Certificate Verification Count;
          'ssl_forward_proxy_invalid_ocsp_stapling_total'= Total SSL Forward Proxy
          Invalid OCSP Stapling Count; 'ssl_forward_proxy_revoked_ocsp_total'= Total SSL
          Forward Proxy Revoked OCSP Response Count;
          'ssl_forward_proxy_failed_cert_signing_total'= Total SSL Forward Proxy Failed
          Certificate Signing Count; 'ssl_forward_proxy_failed_ssl_version_total'= Total
          SSL Forward Proxy Unsupported version Count;
          'ssl_forward_proxy_sni_bypass_total'= Total SSL Forward Proxy SNI Bypass Count;
          'ssl_forward_proxy_client_auth_bypass_total'= Total SSL Forward Proxy Client
          Auth Bypass Count; 'conn_app_smp_alloc_counter'= Conn APP SMP Alloc;
          'diameter_conn_counter'= Diameter Conn Count; 'diameter_conn_freed_counter'=
          Diameter Conn Freed; 'debug_tcp_counter'= Hidden TCP sessions for CGNv6
          Stateless Technologies; 'debug_udp_counter'= Hidden UDP sessions for CGNv6
          Stateless Technologies; 'total_fw_conn'= Total Firewall Conn;
          'total_local_conn'= Total Local Conn; 'total_curr_conn'= Total Curr Conn;
          'client_ssl_fatal_alert'= client ssl fatal alert; 'client_ssl_fin_rst'= client
          ssl fin rst; 'fp_session_fin_rst'= FP Session FIN/RST;
          'server_ssl_fatal_alert'= server ssl fatal alert; 'server_ssl_fin_rst'= server
          ssl fin rst; 'client_template_int_err'= client template internal error;
          'client_template_unknown_err'= client template unknown error;
          'server_template_int_err'= server template int error;
          'server_template_unknown_err'= server template unknown error;
          'total_debug_conn'= Total Debug Conn; 'ssl_forward_proxy_failed_aflex_total'=
          Total SSL Forward Proxy AFLEX Count;
          'ssl_forward_proxy_cert_subject_bypass_total'= Total SSL Forward Proxy
          Certificate Subject Bypass Count; 'ssl_forward_proxy_cert_issuer_bypass_total'=
          Total SSL Forward Proxy Certificate Issuer Bypass Count;
          'ssl_forward_proxy_cert_san_bypass_total'= Total SSL Forward Proxy Certificate
          SAN Bypass Count; 'ssl_forward_proxy_no_sni_bypass_total'= Total SSL Forward
          Proxy No SNI Bypass Count; 'ssl_forward_proxy_no_sni_reset_total'= Total SSL
          Forward Proxy No SNI reset Count; 'ssl_forward_proxy_username_bypass_total'=
          Total SSL Forward Proxy Username Bypass Count;
          'ssl_forward_proxy_ad_grpup_bypass_total'= Total SSL Forward Proxy AD-Group
          Bypass Count; 'diameter_concurrent_user_sessions_counter'= Diameter Concurrent
          User-Sessions;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            total_l4_conn:
                description:
                - "Total L4 Count"
                type: str
            conn_counter:
                description:
                - "Conn Count"
                type: str
            conn_freed_counter:
                description:
                - "Conn Freed"
                type: str
            total_l4_packet_count:
                description:
                - "Total L4 Packet Count"
                type: str
            total_l7_packet_count:
                description:
                - "Total L7 Packet Count"
                type: str
            total_l4_conn_proxy:
                description:
                - "Total L4 Conn Proxy Count"
                type: str
            total_l7_conn:
                description:
                - "Total L7 Conn"
                type: str
            total_tcp_conn:
                description:
                - "Total TCP Conn"
                type: str
            curr_free_conn:
                description:
                - "Curr Free Conn"
                type: str
            tcp_est_counter:
                description:
                - "TCP Established"
                type: str
            tcp_half_open_counter:
                description:
                - "TCP Half Open"
                type: str
            tcp_half_close_counter:
                description:
                - "TCP Half Closed"
                type: str
            udp_counter:
                description:
                - "UDP Count"
                type: str
            ip_counter:
                description:
                - "IP Count"
                type: str
            other_counter:
                description:
                - "Non TCP/UDP IP sessions"
                type: str
            reverse_nat_tcp_counter:
                description:
                - "Reverse NAT TCP"
                type: str
            reverse_nat_udp_counter:
                description:
                - "Reverse NAT UDP"
                type: str
            tcp_syn_half_open_counter:
                description:
                - "TCP SYN Half Open"
                type: str
            conn_smp_alloc_counter:
                description:
                - "Conn SMP Alloc"
                type: str
            conn_smp_free_counter:
                description:
                - "Conn SMP Free"
                type: str
            conn_smp_aged_counter:
                description:
                - "Conn SMP Aged"
                type: str
            ssl_count_curr:
                description:
                - "Curr SSL Count"
                type: str
            ssl_count_total:
                description:
                - "Total SSL Count"
                type: str
            server_ssl_count_curr:
                description:
                - "Current SSL Server Count"
                type: str
            server_ssl_count_total:
                description:
                - "Total SSL Server Count"
                type: str
            client_ssl_reuse_total:
                description:
                - "Total SSL Client Reuse"
                type: str
            server_ssl_reuse_total:
                description:
                - "Total SSL Server Reuse"
                type: str
            total_ip_nat_conn:
                description:
                - "Total IP Nat Conn"
                type: str
            total_l2l3_conn:
                description:
                - "Totl L2/L3 Connections"
                type: str
            conn_type_0_available:
                description:
                - "Conn Type 0 Available"
                type: str
            conn_type_1_available:
                description:
                - "Conn Type 1 Available"
                type: str
            conn_type_2_available:
                description:
                - "Conn Type 2 Available"
                type: str
            conn_type_3_available:
                description:
                - "Conn Type 3 Available"
                type: str
            conn_type_4_available:
                description:
                - "Conn Type 4 Available"
                type: str
            conn_smp_type_0_available:
                description:
                - "Conn SMP Type 0 Available"
                type: str
            conn_smp_type_1_available:
                description:
                - "Conn SMP Type 1 Available"
                type: str
            conn_smp_type_2_available:
                description:
                - "Conn SMP Type 2 Available"
                type: str
            conn_smp_type_3_available:
                description:
                - "Conn SMP Type 3 Available"
                type: str
            conn_smp_type_4_available:
                description:
                - "Conn SMP Type 4 Available"
                type: str
            sctp_half_open_counter:
                description:
                - "SCTP Half Open"
                type: str
            sctp_est_counter:
                description:
                - "SCTP Established"
                type: str
            conn_app_smp_alloc_counter:
                description:
                - "Conn APP SMP Alloc"
                type: str
            diameter_conn_counter:
                description:
                - "Diameter Conn Count"
                type: str
            diameter_conn_freed_counter:
                description:
                - "Diameter Conn Freed"
                type: str
            total_fw_conn:
                description:
                - "Total Firewall Conn"
                type: str
            total_local_conn:
                description:
                - "Total Local Conn"
                type: str
            total_curr_conn:
                description:
                - "Total Curr Conn"
                type: str
            client_ssl_fatal_alert:
                description:
                - "client ssl fatal alert"
                type: str
            client_ssl_fin_rst:
                description:
                - "client ssl fin rst"
                type: str
            fp_session_fin_rst:
                description:
                - "FP Session FIN/RST"
                type: str
            server_ssl_fatal_alert:
                description:
                - "server ssl fatal alert"
                type: str
            server_ssl_fin_rst:
                description:
                - "server ssl fin rst"
                type: str
            client_template_int_err:
                description:
                - "client template internal error"
                type: str
            client_template_unknown_err:
                description:
                - "client template unknown error"
                type: str
            server_template_int_err:
                description:
                - "server template int error"
                type: str
            server_template_unknown_err:
                description:
                - "server template unknown error"
                type: str
            diameter_concurrent_user_sessions_counter:
                description:
                - "Diameter Concurrent User-Sessions"
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

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "sampling_enable",
    "stats",
    "uuid",
]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str',
                   default="present",
                   choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='str',
            required=False,
        ),
        a10_device_context_id=dict(
            type='int',
            choices=[1, 2, 3, 4, 5, 6, 7, 8],
            required=False,
        ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'total_l4_conn', 'conn_counter',
                    'conn_freed_counter', 'total_l4_packet_count',
                    'total_l7_packet_count', 'total_l4_conn_proxy',
                    'total_l7_conn', 'total_tcp_conn', 'curr_free_conn',
                    'tcp_est_counter', 'tcp_half_open_counter',
                    'tcp_half_close_counter', 'udp_counter', 'ip_counter',
                    'other_counter', 'reverse_nat_tcp_counter',
                    'reverse_nat_udp_counter', 'tcp_syn_half_open_counter',
                    'conn_smp_alloc_counter', 'conn_smp_free_counter',
                    'conn_smp_aged_counter', 'ssl_count_curr',
                    'ssl_count_total', 'server_ssl_count_curr',
                    'server_ssl_count_total', 'client_ssl_reuse_total',
                    'server_ssl_reuse_total', 'ssl_failed_total',
                    'ssl_failed_ca_verification', 'ssl_server_cert_error',
                    'ssl_client_cert_auth_fail', 'total_ip_nat_conn',
                    'total_l2l3_conn', 'client_ssl_ctx_malloc_failure',
                    'conn_type_0_available', 'conn_type_1_available',
                    'conn_type_2_available', 'conn_type_3_available',
                    'conn_type_4_available', 'conn_smp_type_0_available',
                    'conn_smp_type_1_available', 'conn_smp_type_2_available',
                    'conn_smp_type_3_available', 'conn_smp_type_4_available',
                    'sctp-half-open-counter', 'sctp-est-counter',
                    'nonssl_bypass', 'ssl_failsafe_total',
                    'ssl_forward_proxy_failed_handshake_total',
                    'ssl_forward_proxy_failed_tcp_total',
                    'ssl_forward_proxy_failed_crypto_total',
                    'ssl_forward_proxy_failed_cert_verify_total',
                    'ssl_forward_proxy_invalid_ocsp_stapling_total',
                    'ssl_forward_proxy_revoked_ocsp_total',
                    'ssl_forward_proxy_failed_cert_signing_total',
                    'ssl_forward_proxy_failed_ssl_version_total',
                    'ssl_forward_proxy_sni_bypass_total',
                    'ssl_forward_proxy_client_auth_bypass_total',
                    'conn_app_smp_alloc_counter', 'diameter_conn_counter',
                    'diameter_conn_freed_counter', 'debug_tcp_counter',
                    'debug_udp_counter', 'total_fw_conn', 'total_local_conn',
                    'total_curr_conn', 'client_ssl_fatal_alert',
                    'client_ssl_fin_rst', 'fp_session_fin_rst',
                    'server_ssl_fatal_alert', 'server_ssl_fin_rst',
                    'client_template_int_err', 'client_template_unknown_err',
                    'server_template_int_err', 'server_template_unknown_err',
                    'total_debug_conn', 'ssl_forward_proxy_failed_aflex_total',
                    'ssl_forward_proxy_cert_subject_bypass_total',
                    'ssl_forward_proxy_cert_issuer_bypass_total',
                    'ssl_forward_proxy_cert_san_bypass_total',
                    'ssl_forward_proxy_no_sni_bypass_total',
                    'ssl_forward_proxy_no_sni_reset_total',
                    'ssl_forward_proxy_username_bypass_total',
                    'ssl_forward_proxy_ad_grpup_bypass_total',
                    'diameter_concurrent_user_sessions_counter'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'total_l4_conn': {
                'type': 'str',
            },
            'conn_counter': {
                'type': 'str',
            },
            'conn_freed_counter': {
                'type': 'str',
            },
            'total_l4_packet_count': {
                'type': 'str',
            },
            'total_l7_packet_count': {
                'type': 'str',
            },
            'total_l4_conn_proxy': {
                'type': 'str',
            },
            'total_l7_conn': {
                'type': 'str',
            },
            'total_tcp_conn': {
                'type': 'str',
            },
            'curr_free_conn': {
                'type': 'str',
            },
            'tcp_est_counter': {
                'type': 'str',
            },
            'tcp_half_open_counter': {
                'type': 'str',
            },
            'tcp_half_close_counter': {
                'type': 'str',
            },
            'udp_counter': {
                'type': 'str',
            },
            'ip_counter': {
                'type': 'str',
            },
            'other_counter': {
                'type': 'str',
            },
            'reverse_nat_tcp_counter': {
                'type': 'str',
            },
            'reverse_nat_udp_counter': {
                'type': 'str',
            },
            'tcp_syn_half_open_counter': {
                'type': 'str',
            },
            'conn_smp_alloc_counter': {
                'type': 'str',
            },
            'conn_smp_free_counter': {
                'type': 'str',
            },
            'conn_smp_aged_counter': {
                'type': 'str',
            },
            'ssl_count_curr': {
                'type': 'str',
            },
            'ssl_count_total': {
                'type': 'str',
            },
            'server_ssl_count_curr': {
                'type': 'str',
            },
            'server_ssl_count_total': {
                'type': 'str',
            },
            'client_ssl_reuse_total': {
                'type': 'str',
            },
            'server_ssl_reuse_total': {
                'type': 'str',
            },
            'total_ip_nat_conn': {
                'type': 'str',
            },
            'total_l2l3_conn': {
                'type': 'str',
            },
            'conn_type_0_available': {
                'type': 'str',
            },
            'conn_type_1_available': {
                'type': 'str',
            },
            'conn_type_2_available': {
                'type': 'str',
            },
            'conn_type_3_available': {
                'type': 'str',
            },
            'conn_type_4_available': {
                'type': 'str',
            },
            'conn_smp_type_0_available': {
                'type': 'str',
            },
            'conn_smp_type_1_available': {
                'type': 'str',
            },
            'conn_smp_type_2_available': {
                'type': 'str',
            },
            'conn_smp_type_3_available': {
                'type': 'str',
            },
            'conn_smp_type_4_available': {
                'type': 'str',
            },
            'sctp_half_open_counter': {
                'type': 'str',
            },
            'sctp_est_counter': {
                'type': 'str',
            },
            'conn_app_smp_alloc_counter': {
                'type': 'str',
            },
            'diameter_conn_counter': {
                'type': 'str',
            },
            'diameter_conn_freed_counter': {
                'type': 'str',
            },
            'total_fw_conn': {
                'type': 'str',
            },
            'total_local_conn': {
                'type': 'str',
            },
            'total_curr_conn': {
                'type': 'str',
            },
            'client_ssl_fatal_alert': {
                'type': 'str',
            },
            'client_ssl_fin_rst': {
                'type': 'str',
            },
            'fp_session_fin_rst': {
                'type': 'str',
            },
            'server_ssl_fatal_alert': {
                'type': 'str',
            },
            'server_ssl_fin_rst': {
                'type': 'str',
            },
            'client_template_int_err': {
                'type': 'str',
            },
            'client_template_unknown_err': {
                'type': 'str',
            },
            'server_template_int_err': {
                'type': 'str',
            },
            'server_template_unknown_err': {
                'type': 'str',
            },
            'diameter_concurrent_user_sessions_counter': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/session"

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


def _get(module, url, params={}):

    resp = None
    try:
        resp = module.client.get(url, params=params)
    except a10_ex.NotFound:
        resp = "Not Found"

    call_result = {
        "endpoint": url,
        "http_method": "GET",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _post(module, url, params={}, file_content=None, file_name=None):
    resp = module.client.post(url, params=params)
    resp = resp if resp else {}
    call_result = {
        "endpoint": url,
        "http_method": "POST",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _delete(module, url):
    call_result = {
        "endpoint": url,
        "http_method": "DELETE",
        "request_body": {},
        "response_body": module.client.delete(url),
    }
    return call_result


def _switch_device_context(module, device_id):
    call_result = {
        "endpoint": "/axapi/v3/device-context",
        "http_method": "POST",
        "request_body": {
            "device-id": device_id
        },
        "response_body": module.client.change_context(device_id)
    }
    return call_result


def _active_partition(module, a10_partition):
    call_result = {
        "endpoint": "/axapi/v3/active-partition",
        "http_method": "POST",
        "request_body": {
            "curr_part_name": a10_partition
        },
        "response_body": module.client.activate_partition(a10_partition)
    }
    return call_result


def get(module):
    return _get(module, existing_url(module))


def get_list(module):
    return _get(module, list_url(module))


def get_stats(module):
    query_params = {}
    if module.params.get("stats"):
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, stats_url(module), params=query_params)


def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")


def _build_dict_from_param(param):
    rv = {}

    for k, v in param.items():
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
    return {title: data}


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/system/session"

    f_dict = {}

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


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
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["session"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["session"].get(k) != v:
            change_results["changed"] = True
            config_changes["session"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload):
    try:
        call_result = _post(module, new_url(module), payload)
        result["axapi_calls"].append(call_result)
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config, payload):
    try:
        call_result = _post(module, existing_url(module), payload)
        result["axapi_calls"].append(call_result)
        if call_result["response_body"] == existing_config:
            result["changed"] = False
        else:
            result["modified_values"].update(**call_result["response_body"])
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def present(module, result, existing_config):
    payload = build_json("session", module)
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
        call_result = _delete(module, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

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
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[])

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

    valid = True

    run_errors = []
    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        result["axapi_calls"].append(_active_partition(module, a10_partition))

    if a10_device_context_id:
        result["axapi_calls"].append(
            _switch_device_context(module, a10_device_context_id))

    existing_config = get(module)
    result["axapi_calls"].append(existing_config)
    if existing_config['response_body'] != 'Not Found':
        existing_config = existing_config["response_body"]
    else:
        existing_config = None

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["axapi_calls"].append(get(module))
        elif module.params.get("get_type") == "list":
            result["axapi_calls"].append(get_list(module))
        elif module.params.get("get_type") == "stats":
            result["axapi_calls"].append(get_stats(module))
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
