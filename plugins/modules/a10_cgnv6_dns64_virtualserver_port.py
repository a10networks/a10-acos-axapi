#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_dns64_virtualserver_port
description:
    - Virtual Port
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
    dns64_virtualserver_name:
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
        - "'dns-udp'= DNS service over UDP;"
        type: str
        required: True
    action:
        description:
        - "'enable'= Enable; 'disable'= Disable;"
        type: str
        required: False
    pool:
        description:
        - "Specify NAT pool or pool group"
        type: str
        required: False
    auto:
        description:
        - "Configure auto NAT for the vport"
        type: bool
        required: False
    precedence:
        description:
        - "Set auto NAT pool as higher precedence for source NAT"
        type: bool
        required: False
    service_group:
        description:
        - "Bind a Service Group to this Virtual Server (Service Group Name)"
        type: str
        required: False
    template_dns:
        description:
        - "DNS template (DNS template name)"
        type: str
        required: False
    template_policy:
        description:
        - "Policy Template (Policy template name)"
        type: str
        required: False
    acl_id_list:
        description:
        - "Field acl_id_list"
        type: list
        required: False
        suboptions:
            acl_id:
                description:
                - "ACL id VPORT"
                type: int
            acl_id_src_nat_pool:
                description:
                - "Policy based Source NAT (NAT Pool or Pool Group)"
                type: str
            acl_id_seq_num:
                description:
                - "Specify ACL precedence (sequence-number)"
                type: int
    acl_name_list:
        description:
        - "Field acl_name_list"
        type: list
        required: False
        suboptions:
            acl_name:
                description:
                - "Apply an access list name (Named Access List)"
                type: str
            acl_name_src_nat_pool:
                description:
                - "Policy based Source NAT (NAT Pool or Pool Group)"
                type: str
            acl_name_seq_num:
                description:
                - "Specify ACL precedence (sequence-number)"
                type: int
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    user_tag:
        description:
        - "Customized tag"
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
                - "'all'= all; 'curr_conn'= Current connection; 'total_l4_conn'= Total L4
          connections; 'total_l7_conn'= Total L7 connections; 'toatal_tcp_conn'= Total
          TCP connections; 'total_conn'= Total connections; 'total_fwd_bytes'= Total
          forward bytes; 'total_fwd_pkts'= Total forward packets; 'total_rev_bytes'=
          Total reverse bytes; 'total_rev_pkts'= Total reverse packets; 'total_dns_pkts'=
          Total DNS packets; 'total_mf_dns_pkts'= Total MF DNS packets;
          'es_total_failure_actions'= Total failure actions; 'compression_bytes_before'=
          Data into compression engine; 'compression_bytes_after'= Data out of
          compression engine; 'compression_hit'= Number of requests compressed;
          'compression_miss'= Number of requests NOT compressed;
          'compression_miss_no_client'= Compression miss no client;
          'compression_miss_template_exclusion'= Compression miss template exclusion;
          'curr_req'= Current requests; 'total_req'= Total requests; 'total_req_succ'=
          Total successful requests; 'peak_conn'= Peak connections; 'curr_conn_rate'=
          Current connection rate; 'last_rsp_time'= Last response time;
          'fastest_rsp_time'= Fastest response time; 'slowest_rsp_time'= Slowest response
          time;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            state:
                description:
                - "Field state"
                type: str
            loc_list:
                description:
                - "Field loc_list"
                type: str
            geo_location:
                description:
                - "Field geo_location"
                type: str
            level_str:
                description:
                - "Field level_str"
                type: str
            group_id:
                description:
                - "Field group_id"
                type: int
            loc_max_depth:
                description:
                - "Field loc_max_depth"
                type: int
            loc_success:
                description:
                - "Field loc_success"
                type: int
            loc_error:
                description:
                - "Field loc_error"
                type: int
            loc_override:
                description:
                - "Field loc_override"
                type: int
            loc_last:
                description:
                - "Field loc_last"
                type: str
            http_hits_list:
                description:
                - "Field http_hits_list"
                type: list
            http_vport_cpu_list:
                description:
                - "Field http_vport_cpu_list"
                type: list
            cpu_count:
                description:
                - "Field cpu_count"
                type: int
            http_host_hits:
                description:
                - "Field http_host_hits"
                type: bool
            http_url_hits:
                description:
                - "Field http_url_hits"
                type: bool
            http_vport:
                description:
                - "Field http_vport"
                type: bool
            real_curr_conn:
                description:
                - "Field real_curr_conn"
                type: int
            port_number:
                description:
                - "Port"
                type: int
            protocol:
                description:
                - "'dns-udp'= DNS service over UDP;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            curr_conn:
                description:
                - "Current connection"
                type: str
            total_l4_conn:
                description:
                - "Total L4 connections"
                type: str
            total_l7_conn:
                description:
                - "Total L7 connections"
                type: str
            toatal_tcp_conn:
                description:
                - "Total TCP connections"
                type: str
            total_conn:
                description:
                - "Total connections"
                type: str
            total_fwd_bytes:
                description:
                - "Total forward bytes"
                type: str
            total_fwd_pkts:
                description:
                - "Total forward packets"
                type: str
            total_rev_bytes:
                description:
                - "Total reverse bytes"
                type: str
            total_rev_pkts:
                description:
                - "Total reverse packets"
                type: str
            total_dns_pkts:
                description:
                - "Total DNS packets"
                type: str
            total_mf_dns_pkts:
                description:
                - "Total MF DNS packets"
                type: str
            es_total_failure_actions:
                description:
                - "Total failure actions"
                type: str
            compression_bytes_before:
                description:
                - "Data into compression engine"
                type: str
            compression_bytes_after:
                description:
                - "Data out of compression engine"
                type: str
            compression_hit:
                description:
                - "Number of requests compressed"
                type: str
            compression_miss:
                description:
                - "Number of requests NOT compressed"
                type: str
            compression_miss_no_client:
                description:
                - "Compression miss no client"
                type: str
            compression_miss_template_exclusion:
                description:
                - "Compression miss template exclusion"
                type: str
            curr_req:
                description:
                - "Current requests"
                type: str
            total_req:
                description:
                - "Total requests"
                type: str
            total_req_succ:
                description:
                - "Total successful requests"
                type: str
            peak_conn:
                description:
                - "Peak connections"
                type: str
            curr_conn_rate:
                description:
                - "Current connection rate"
                type: str
            last_rsp_time:
                description:
                - "Last response time"
                type: str
            fastest_rsp_time:
                description:
                - "Fastest response time"
                type: str
            slowest_rsp_time:
                description:
                - "Slowest response time"
                type: str
            port_number:
                description:
                - "Port"
                type: int
            protocol:
                description:
                - "'dns-udp'= DNS service over UDP;"
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
AVAILABLE_PROPERTIES = [
    "acl_id_list",
    "acl_name_list",
    "action",
    "auto",
    "oper",
    "pool",
    "port_number",
    "precedence",
    "protocol",
    "sampling_enable",
    "service_group",
    "stats",
    "template_dns",
    "template_policy",
    "user_tag",
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
        'port_number': {
            'type': 'int',
            'required': True,
        },
        'protocol': {
            'type': 'str',
            'required': True,
            'choices': ['dns-udp']
        },
        'action': {
            'type': 'str',
            'choices': ['enable', 'disable']
        },
        'pool': {
            'type': 'str',
        },
        'auto': {
            'type': 'bool',
        },
        'precedence': {
            'type': 'bool',
        },
        'service_group': {
            'type': 'str',
        },
        'template_dns': {
            'type': 'str',
        },
        'template_policy': {
            'type': 'str',
        },
        'acl_id_list': {
            'type': 'list',
            'acl_id': {
                'type': 'int',
            },
            'acl_id_src_nat_pool': {
                'type': 'str',
            },
            'acl_id_seq_num': {
                'type': 'int',
            }
        },
        'acl_name_list': {
            'type': 'list',
            'acl_name': {
                'type': 'str',
            },
            'acl_name_src_nat_pool': {
                'type': 'str',
            },
            'acl_name_seq_num': {
                'type': 'int',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'curr_conn', 'total_l4_conn', 'total_l7_conn',
                    'toatal_tcp_conn', 'total_conn', 'total_fwd_bytes',
                    'total_fwd_pkts', 'total_rev_bytes', 'total_rev_pkts',
                    'total_dns_pkts', 'total_mf_dns_pkts',
                    'es_total_failure_actions', 'compression_bytes_before',
                    'compression_bytes_after', 'compression_hit',
                    'compression_miss', 'compression_miss_no_client',
                    'compression_miss_template_exclusion', 'curr_req',
                    'total_req', 'total_req_succ', 'peak_conn',
                    'curr_conn_rate', 'last_rsp_time', 'fastest_rsp_time',
                    'slowest_rsp_time'
                ]
            }
        },
        'oper': {
            'type': 'dict',
            'state': {
                'type': 'str',
                'choices': ['All Up', 'Functional Up', 'Down', 'Disb', 'Unkn']
            },
            'loc_list': {
                'type': 'str',
            },
            'geo_location': {
                'type': 'str',
            },
            'level_str': {
                'type': 'str',
            },
            'group_id': {
                'type': 'int',
            },
            'loc_max_depth': {
                'type': 'int',
            },
            'loc_success': {
                'type': 'int',
            },
            'loc_error': {
                'type': 'int',
            },
            'loc_override': {
                'type': 'int',
            },
            'loc_last': {
                'type': 'str',
            },
            'http_hits_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                },
                'hits_count': {
                    'type': 'int',
                }
            },
            'http_vport_cpu_list': {
                'type': 'list',
                'status_200': {
                    'type': 'int',
                },
                'status_201': {
                    'type': 'int',
                },
                'status_202': {
                    'type': 'int',
                },
                'status_203': {
                    'type': 'int',
                },
                'status_204': {
                    'type': 'int',
                },
                'status_205': {
                    'type': 'int',
                },
                'status_206': {
                    'type': 'int',
                },
                'status_207': {
                    'type': 'int',
                },
                'status_100': {
                    'type': 'int',
                },
                'status_101': {
                    'type': 'int',
                },
                'status_102': {
                    'type': 'int',
                },
                'status_300': {
                    'type': 'int',
                },
                'status_301': {
                    'type': 'int',
                },
                'status_302': {
                    'type': 'int',
                },
                'status_303': {
                    'type': 'int',
                },
                'status_304': {
                    'type': 'int',
                },
                'status_305': {
                    'type': 'int',
                },
                'status_306': {
                    'type': 'int',
                },
                'status_307': {
                    'type': 'int',
                },
                'status_400': {
                    'type': 'int',
                },
                'status_401': {
                    'type': 'int',
                },
                'status_402': {
                    'type': 'int',
                },
                'status_403': {
                    'type': 'int',
                },
                'status_404': {
                    'type': 'int',
                },
                'status_405': {
                    'type': 'int',
                },
                'status_406': {
                    'type': 'int',
                },
                'status_407': {
                    'type': 'int',
                },
                'status_408': {
                    'type': 'int',
                },
                'status_409': {
                    'type': 'int',
                },
                'status_410': {
                    'type': 'int',
                },
                'status_411': {
                    'type': 'int',
                },
                'status_412': {
                    'type': 'int',
                },
                'status_413': {
                    'type': 'int',
                },
                'status_414': {
                    'type': 'int',
                },
                'status_415': {
                    'type': 'int',
                },
                'status_416': {
                    'type': 'int',
                },
                'status_417': {
                    'type': 'int',
                },
                'status_418': {
                    'type': 'int',
                },
                'status_422': {
                    'type': 'int',
                },
                'status_423': {
                    'type': 'int',
                },
                'status_424': {
                    'type': 'int',
                },
                'status_425': {
                    'type': 'int',
                },
                'status_426': {
                    'type': 'int',
                },
                'status_449': {
                    'type': 'int',
                },
                'status_450': {
                    'type': 'int',
                },
                'status_500': {
                    'type': 'int',
                },
                'status_501': {
                    'type': 'int',
                },
                'status_502': {
                    'type': 'int',
                },
                'status_503': {
                    'type': 'int',
                },
                'status_504': {
                    'type': 'int',
                },
                'status_504_ax': {
                    'type': 'int',
                },
                'status_505': {
                    'type': 'int',
                },
                'status_506': {
                    'type': 'int',
                },
                'status_507': {
                    'type': 'int',
                },
                'status_508': {
                    'type': 'int',
                },
                'status_509': {
                    'type': 'int',
                },
                'status_510': {
                    'type': 'int',
                },
                'status_1xx': {
                    'type': 'int',
                },
                'status_2xx': {
                    'type': 'int',
                },
                'status_3xx': {
                    'type': 'int',
                },
                'status_4xx': {
                    'type': 'int',
                },
                'status_5xx': {
                    'type': 'int',
                },
                'status_6xx': {
                    'type': 'int',
                },
                'status_unknown': {
                    'type': 'int',
                },
                'ws_handshake_request': {
                    'type': 'int',
                },
                'ws_handshake_success': {
                    'type': 'int',
                },
                'ws_client_switch': {
                    'type': 'int',
                },
                'ws_server_switch': {
                    'type': 'int',
                },
                'REQ_10u': {
                    'type': 'int',
                },
                'REQ_20u': {
                    'type': 'int',
                },
                'REQ_50u': {
                    'type': 'int',
                },
                'REQ_100u': {
                    'type': 'int',
                },
                'REQ_200u': {
                    'type': 'int',
                },
                'REQ_500u': {
                    'type': 'int',
                },
                'REQ_1m': {
                    'type': 'int',
                },
                'REQ_2m': {
                    'type': 'int',
                },
                'REQ_5m': {
                    'type': 'int',
                },
                'REQ_10m': {
                    'type': 'int',
                },
                'REQ_20m': {
                    'type': 'int',
                },
                'REQ_50m': {
                    'type': 'int',
                },
                'REQ_100m': {
                    'type': 'int',
                },
                'REQ_200m': {
                    'type': 'int',
                },
                'REQ_500m': {
                    'type': 'int',
                },
                'REQ_1s': {
                    'type': 'int',
                },
                'REQ_2s': {
                    'type': 'int',
                },
                'REQ_5s': {
                    'type': 'int',
                },
                'REQ_OVER_5s': {
                    'type': 'int',
                },
                'curr_http2_conn': {
                    'type': 'int',
                },
                'total_http2_conn': {
                    'type': 'int',
                },
                'peak_http2_conn': {
                    'type': 'int',
                },
                'total_http2_bytes': {
                    'type': 'int',
                },
                'http2_control_bytes': {
                    'type': 'int',
                },
                'http2_header_bytes': {
                    'type': 'int',
                },
                'http2_data_bytes': {
                    'type': 'int',
                },
                'http2_reset_received': {
                    'type': 'int',
                },
                'http2_reset_sent': {
                    'type': 'int',
                },
                'http2_goaway_received': {
                    'type': 'int',
                },
                'http2_goaway_sent': {
                    'type': 'int',
                },
                'stream_closed': {
                    'type': 'int',
                },
                'header_length_long': {
                    'type': 'int',
                }
            },
            'cpu_count': {
                'type': 'int',
            },
            'http_host_hits': {
                'type': 'bool',
            },
            'http_url_hits': {
                'type': 'bool',
            },
            'http_vport': {
                'type': 'bool',
            },
            'real_curr_conn': {
                'type': 'int',
            },
            'port_number': {
                'type': 'int',
                'required': True,
            },
            'protocol': {
                'type': 'str',
                'required': True,
                'choices': ['dns-udp']
            }
        },
        'stats': {
            'type': 'dict',
            'curr_conn': {
                'type': 'str',
            },
            'total_l4_conn': {
                'type': 'str',
            },
            'total_l7_conn': {
                'type': 'str',
            },
            'toatal_tcp_conn': {
                'type': 'str',
            },
            'total_conn': {
                'type': 'str',
            },
            'total_fwd_bytes': {
                'type': 'str',
            },
            'total_fwd_pkts': {
                'type': 'str',
            },
            'total_rev_bytes': {
                'type': 'str',
            },
            'total_rev_pkts': {
                'type': 'str',
            },
            'total_dns_pkts': {
                'type': 'str',
            },
            'total_mf_dns_pkts': {
                'type': 'str',
            },
            'es_total_failure_actions': {
                'type': 'str',
            },
            'compression_bytes_before': {
                'type': 'str',
            },
            'compression_bytes_after': {
                'type': 'str',
            },
            'compression_hit': {
                'type': 'str',
            },
            'compression_miss': {
                'type': 'str',
            },
            'compression_miss_no_client': {
                'type': 'str',
            },
            'compression_miss_template_exclusion': {
                'type': 'str',
            },
            'curr_req': {
                'type': 'str',
            },
            'total_req': {
                'type': 'str',
            },
            'total_req_succ': {
                'type': 'str',
            },
            'peak_conn': {
                'type': 'str',
            },
            'curr_conn_rate': {
                'type': 'str',
            },
            'last_rsp_time': {
                'type': 'str',
            },
            'fastest_rsp_time': {
                'type': 'str',
            },
            'slowest_rsp_time': {
                'type': 'str',
            },
            'port_number': {
                'type': 'int',
                'required': True,
            },
            'protocol': {
                'type': 'str',
                'required': True,
                'choices': ['dns-udp']
            }
        }
    })
    # Parent keys
    rv.update(dict(dns64_virtualserver_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/dns64-virtualserver/{dns64_virtualserver_name}/port/{port-number}+{protocol}"

    f_dict = {}
    f_dict["port-number"] = module.params["port_number"]
    f_dict["protocol"] = module.params["protocol"]
    f_dict["dns64_virtualserver_name"] = module.params[
        "dns64_virtualserver_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/dns64-virtualserver/{dns64_virtualserver_name}/port/{port-number}+{protocol}"

    f_dict = {}
    f_dict["port-number"] = ""
    f_dict["protocol"] = ""
    f_dict["dns64_virtualserver_name"] = module.params[
        "dns64_virtualserver_name"]

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
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[],
                  ansible_facts={},
                  acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params,
                                                  requires_one_of)
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
                api_client.switch_device_context(module.client,
                                                 a10_device_context_id))

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
                get_result = api_client.get(module.client,
                                            existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result[
                    "acos_info"] = info["port"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "port-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client,
                                                      existing_url(module),
                                                      params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["port"][
                    "oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client,
                                                       existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["port"][
                    "stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()
        raise gex
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
