#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_dns64_virtualserver
description:
    - Create a DNS64 Virtual Server
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
    name:
        description:
        - "CGNV6 Virtual Server Name"
        type: str
        required: True
    ipv6_address:
        description:
        - "IPV6 address"
        type: str
        required: False
    ip_address:
        description:
        - "IP Address"
        type: str
        required: False
    netmask:
        description:
        - "IP subnet mask"
        type: str
        required: False
    use_if_ip:
        description:
        - "Use Interface IP"
        type: bool
        required: False
    ethernet:
        description:
        - "Ethernet interface"
        type: str
        required: False
    enable_disable_action:
        description:
        - "'enable'= Enable Virtual Server (default); 'disable'= Disable Virtual Server;"
        type: str
        required: False
    policy:
        description:
        - "Policy template"
        type: bool
        required: False
    template_policy:
        description:
        - "Policy template name"
        type: str
        required: False
    vrid:
        description:
        - "Join a vrrp group (Specify ha VRRP-A vrid)"
        type: int
        required: False
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
    port_list:
        description:
        - "Field port_list"
        type: list
        required: False
        suboptions:
            port_number:
                description:
                - "Port"
                type: int
            protocol:
                description:
                - "'dns-udp'= DNS service over UDP;"
                type: str
            action:
                description:
                - "'enable'= Enable; 'disable'= Disable;"
                type: str
            pool:
                description:
                - "Specify NAT pool or pool group"
                type: str
            auto:
                description:
                - "Configure auto NAT for the vport"
                type: bool
            precedence:
                description:
                - "Set auto NAT pool as higher precedence for source NAT"
                type: bool
            service_group:
                description:
                - "Bind a Service Group to this Virtual Server (Service Group Name)"
                type: str
            template_dns:
                description:
                - "DNS template (DNS template name)"
                type: str
            template_policy:
                description:
                - "Policy Template (Policy template name)"
                type: str
            acl_id_list:
                description:
                - "Field acl_id_list"
                type: list
            acl_name_list:
                description:
                - "Field acl_name_list"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
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
            mac:
                description:
                - "Field mac"
                type: str
            state:
                description:
                - "Field state"
                type: str
            curr_conn_rate:
                description:
                - "Field curr_conn_rate"
                type: int
            conn_rate_unit:
                description:
                - "Field conn_rate_unit"
                type: str
            curr_icmp_rate:
                description:
                - "Field curr_icmp_rate"
                type: int
            icmp_lockup_time_left:
                description:
                - "Field icmp_lockup_time_left"
                type: int
            icmp_rate_over_limit_drop:
                description:
                - "Field icmp_rate_over_limit_drop"
                type: int
            curr_icmpv6_rate:
                description:
                - "Field curr_icmpv6_rate"
                type: int
            icmpv6_lockup_time_left:
                description:
                - "Field icmpv6_lockup_time_left"
                type: int
            icmpv6_rate_over_limit_drop:
                description:
                - "Field icmpv6_rate_over_limit_drop"
                type: int
            migration_status:
                description:
                - "Field migration_status"
                type: str
            peak_conn:
                description:
                - "Field peak_conn"
                type: int
            ip_address:
                description:
                - "Field ip_address"
                type: str
            curr_conn_overflow:
                description:
                - "Field curr_conn_overflow"
                type: int
            ip_only_lb_fwd_bytes:
                description:
                - "Field ip_only_lb_fwd_bytes"
                type: int
            ip_only_lb_rev_bytes:
                description:
                - "Field ip_only_lb_rev_bytes"
                type: int
            ip_only_lb_fwd_pkts:
                description:
                - "Field ip_only_lb_fwd_pkts"
                type: int
            ip_only_lb_rev_pkts:
                description:
                - "Field ip_only_lb_rev_pkts"
                type: int
            name:
                description:
                - "CGNV6 Virtual Server Name"
                type: str
            port_list:
                description:
                - "Field port_list"
                type: list

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

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "enable_disable_action",
    "ethernet",
    "ip_address",
    "ipv6_address",
    "name",
    "netmask",
    "oper",
    "policy",
    "port_list",
    "template_policy",
    "use_if_ip",
    "user_tag",
    "uuid",
    "vrid",
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
        'name': {
            'type': 'str',
            'required': True,
        },
        'ipv6_address': {
            'type': 'str',
        },
        'ip_address': {
            'type': 'str',
        },
        'netmask': {
            'type': 'str',
        },
        'use_if_ip': {
            'type': 'bool',
        },
        'ethernet': {
            'type': 'str',
        },
        'enable_disable_action': {
            'type': 'str',
            'choices': ['enable', 'disable']
        },
        'policy': {
            'type': 'bool',
        },
        'template_policy': {
            'type': 'str',
        },
        'vrid': {
            'type': 'int',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'port_list': {
            'type': 'list',
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
            }
        },
        'oper': {
            'type': 'dict',
            'mac': {
                'type': 'str',
            },
            'state': {
                'type':
                'str',
                'choices': [
                    'All Up', 'Functional Up', 'Partial Up', 'Down', 'Disb',
                    'Unkn'
                ]
            },
            'curr_conn_rate': {
                'type': 'int',
            },
            'conn_rate_unit': {
                'type': 'str',
                'choices': ['100ms', 'second']
            },
            'curr_icmp_rate': {
                'type': 'int',
            },
            'icmp_lockup_time_left': {
                'type': 'int',
            },
            'icmp_rate_over_limit_drop': {
                'type': 'int',
            },
            'curr_icmpv6_rate': {
                'type': 'int',
            },
            'icmpv6_lockup_time_left': {
                'type': 'int',
            },
            'icmpv6_rate_over_limit_drop': {
                'type': 'int',
            },
            'migration_status': {
                'type': 'str',
            },
            'peak_conn': {
                'type': 'int',
            },
            'ip_address': {
                'type': 'str',
            },
            'curr_conn_overflow': {
                'type': 'int',
            },
            'ip_only_lb_fwd_bytes': {
                'type': 'int',
            },
            'ip_only_lb_rev_bytes': {
                'type': 'int',
            },
            'ip_only_lb_fwd_pkts': {
                'type': 'int',
            },
            'ip_only_lb_rev_pkts': {
                'type': 'int',
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'port_list': {
                'type': 'list',
                'port_number': {
                    'type': 'int',
                    'required': True,
                },
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['dns-udp']
                },
                'oper': {
                    'type': 'dict',
                    'state': {
                        'type':
                        'str',
                        'choices':
                        ['All Up', 'Functional Up', 'Down', 'Disb', 'Unkn']
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
                    }
                }
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/dns64-virtualserver/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"


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


def get_oper(module):
    query_params = {}
    if module.params.get("oper"):
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, oper_url(module), params=query_params)


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
    url_base = "/axapi/v3/cgnv6/dns64-virtualserver/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
    for k, v in payload["dns64-virtualserver"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["dns64-virtualserver"].get(k) != v:
            change_results["changed"] = True
            config_changes["dns64-virtualserver"][k] = v

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
    finally:
        module.client.session.close()
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
    finally:
        module.client.session.close()
    return result


def present(module, result, existing_config):
    payload = build_json("dns64-virtualserver", module)
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
    finally:
        module.client.session.close()
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
    finally:
        module.client.session.close()
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
        elif module.params.get("get_type") == "oper":
            result["axapi_calls"].append(get_oper(module))

    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
