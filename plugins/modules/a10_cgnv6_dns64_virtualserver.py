#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_dns64_virtualserver
description:
    - Create a DNS64 Virtual Server
short_description: Configures A10 cgnv6.dns64-virtualserver
author: A10 Networks 2018
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
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
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            peak_conn:
                description:
                - "Field peak_conn"
            conn_rate_unit:
                description:
                - "Field conn_rate_unit"
            port_list:
                description:
                - "Field port_list"
            curr_conn_overflow:
                description:
                - "Field curr_conn_overflow"
            icmp_rate_over_limit_drop:
                description:
                - "Field icmp_rate_over_limit_drop"
            name:
                description:
                - "CGNV6 Virtual Server Name"
            icmpv6_rate_over_limit_drop:
                description:
                - "Field icmpv6_rate_over_limit_drop"
            curr_conn_rate:
                description:
                - "Field curr_conn_rate"
            mac:
                description:
                - "Field mac"
            curr_icmp_rate:
                description:
                - "Field curr_icmp_rate"
            icmpv6_lockup_time_left:
                description:
                - "Field icmpv6_lockup_time_left"
            state:
                description:
                - "Field state"
            curr_icmpv6_rate:
                description:
                - "Field curr_icmpv6_rate"
            ip_address:
                description:
                - "Field ip_address"
            icmp_lockup_time_left:
                description:
                - "Field icmp_lockup_time_left"
            migration_status:
                description:
                - "Field migration_status"
    use_if_ip:
        description:
        - "Use Interface IP"
        required: False
    port_list:
        description:
        - "Field port_list"
        required: False
        suboptions:
            protocol:
                description:
                - "'dns-udp'= DNS service over UDP;"
            uuid:
                description:
                - "uuid of the object"
            precedence:
                description:
                - "Set auto NAT pool as higher precedence for source NAT"
            auto:
                description:
                - "Configure auto NAT for the vport"
            template_policy:
                description:
                - "Policy Template (Policy template name)"
            service_group:
                description:
                - "Bind a Service Group to this Virtual Server (Service Group Name)"
            port_number:
                description:
                - "Port"
            acl_name_list:
                description:
                - "Field acl_name_list"
            sampling_enable:
                description:
                - "Field sampling_enable"
            user_tag:
                description:
                - "Customized tag"
            template_dns:
                description:
                - "DNS template (DNS template name)"
            acl_id_list:
                description:
                - "Field acl_id_list"
            action:
                description:
                - "'enable'= Enable; 'disable'= Disable;"
            pool:
                description:
                - "Specify NAT pool or pool group"
    name:
        description:
        - "CGNV6 Virtual Server Name"
        required: True
    template_policy:
        description:
        - "Policy template name"
        required: False
    vrid:
        description:
        - "Join a vrrp group (Specify ha VRRP-A vrid)"
        required: False
    enable_disable_action:
        description:
        - "'enable'= Enable Virtual Server (default); 'disable'= Disable Virtual Server;"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    ipv6_address:
        description:
        - "IPV6 address"
        required: False
    netmask:
        description:
        - "IP subnet mask"
        required: False
    ip_address:
        description:
        - "IP Address"
        required: False
    policy:
        description:
        - "Policy template"
        required: False
    ethernet:
        description:
        - "Ethernet interface"
        required: False
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

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


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
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
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
        'oper': {
            'type': 'dict',
            'peak_conn': {
                'type': 'int',
            },
            'conn_rate_unit': {
                'type': 'str',
                'choices': ['100ms', 'second']
            },
            'port_list': {
                'type': 'list',
                'oper': {
                    'type': 'dict',
                    'http_host_hits': {
                        'type': 'bool',
                    },
                    'cpu_count': {
                        'type': 'int',
                    },
                    'loc_list': {
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
                    'http_vport': {
                        'type': 'bool',
                    },
                    'state': {
                        'type':
                        'str',
                        'choices':
                        ['All Up', 'Functional Up', 'Down', 'Disb', 'Unkn']
                    },
                    'loc_max_depth': {
                        'type': 'int',
                    },
                    'level_str': {
                        'type': 'str',
                    },
                    'loc_last': {
                        'type': 'str',
                    },
                    'http_url_hits': {
                        'type': 'bool',
                    },
                    'geo_location': {
                        'type': 'str',
                    },
                    'http_vport_cpu_list': {
                        'type': 'list',
                        'REQ_50u': {
                            'type': 'int',
                        },
                        'http2_control_bytes': {
                            'type': 'int',
                        },
                        'ws_server_switch': {
                            'type': 'int',
                        },
                        'REQ_50m': {
                            'type': 'int',
                        },
                        'status_450': {
                            'type': 'int',
                        },
                        'http2_reset_received': {
                            'type': 'int',
                        },
                        'status_510': {
                            'type': 'int',
                        },
                        'ws_handshake_request': {
                            'type': 'int',
                        },
                        'http2_header_bytes': {
                            'type': 'int',
                        },
                        'status_207': {
                            'type': 'int',
                        },
                        'status_206': {
                            'type': 'int',
                        },
                        'status_205': {
                            'type': 'int',
                        },
                        'status_204': {
                            'type': 'int',
                        },
                        'status_203': {
                            'type': 'int',
                        },
                        'status_202': {
                            'type': 'int',
                        },
                        'status_201': {
                            'type': 'int',
                        },
                        'status_200': {
                            'type': 'int',
                        },
                        'ws_client_switch': {
                            'type': 'int',
                        },
                        'status_2xx': {
                            'type': 'int',
                        },
                        'http2_goaway_received': {
                            'type': 'int',
                        },
                        'REQ_500u': {
                            'type': 'int',
                        },
                        'status_4xx': {
                            'type': 'int',
                        },
                        'status_3xx': {
                            'type': 'int',
                        },
                        'REQ_200u': {
                            'type': 'int',
                        },
                        'stream_closed': {
                            'type': 'int',
                        },
                        'REQ_100m': {
                            'type': 'int',
                        },
                        'REQ_5m': {
                            'type': 'int',
                        },
                        'REQ_100u': {
                            'type': 'int',
                        },
                        'REQ_5s': {
                            'type': 'int',
                        },
                        'REQ_20m': {
                            'type': 'int',
                        },
                        'header_length_long': {
                            'type': 'int',
                        },
                        'REQ_20u': {
                            'type': 'int',
                        },
                        'REQ_2s': {
                            'type': 'int',
                        },
                        'total_http2_bytes': {
                            'type': 'int',
                        },
                        'status_411': {
                            'type': 'int',
                        },
                        'status_306': {
                            'type': 'int',
                        },
                        'status_307': {
                            'type': 'int',
                        },
                        'status_304': {
                            'type': 'int',
                        },
                        'status_305': {
                            'type': 'int',
                        },
                        'status_302': {
                            'type': 'int',
                        },
                        'status_303': {
                            'type': 'int',
                        },
                        'REQ_2m': {
                            'type': 'int',
                        },
                        'status_301': {
                            'type': 'int',
                        },
                        'REQ_10u': {
                            'type': 'int',
                        },
                        'total_http2_conn': {
                            'type': 'int',
                        },
                        'REQ_10m': {
                            'type': 'int',
                        },
                        'REQ_200m': {
                            'type': 'int',
                        },
                        'peak_http2_conn': {
                            'type': 'int',
                        },
                        'status_412': {
                            'type': 'int',
                        },
                        'status_413': {
                            'type': 'int',
                        },
                        'status_410': {
                            'type': 'int',
                        },
                        'http2_reset_sent': {
                            'type': 'int',
                        },
                        'status_416': {
                            'type': 'int',
                        },
                        'status_417': {
                            'type': 'int',
                        },
                        'status_414': {
                            'type': 'int',
                        },
                        'status_415': {
                            'type': 'int',
                        },
                        'status_418': {
                            'type': 'int',
                        },
                        'status_unknown': {
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
                        'status_424': {
                            'type': 'int',
                        },
                        'curr_http2_conn': {
                            'type': 'int',
                        },
                        'ws_handshake_success': {
                            'type': 'int',
                        },
                        'status_504_ax': {
                            'type': 'int',
                        },
                        'status_6xx': {
                            'type': 'int',
                        },
                        'status_5xx': {
                            'type': 'int',
                        },
                        'status_401': {
                            'type': 'int',
                        },
                        'status_400': {
                            'type': 'int',
                        },
                        'status_403': {
                            'type': 'int',
                        },
                        'status_402': {
                            'type': 'int',
                        },
                        'status_405': {
                            'type': 'int',
                        },
                        'status_404': {
                            'type': 'int',
                        },
                        'status_407': {
                            'type': 'int',
                        },
                        'status_406': {
                            'type': 'int',
                        },
                        'status_409': {
                            'type': 'int',
                        },
                        'status_408': {
                            'type': 'int',
                        },
                        'http2_goaway_sent': {
                            'type': 'int',
                        },
                        'REQ_1m': {
                            'type': 'int',
                        },
                        'REQ_1s': {
                            'type': 'int',
                        },
                        'status_1xx': {
                            'type': 'int',
                        },
                        'http2_data_bytes': {
                            'type': 'int',
                        },
                        'status_423': {
                            'type': 'int',
                        },
                        'status_422': {
                            'type': 'int',
                        },
                        'status_426': {
                            'type': 'int',
                        },
                        'status_425': {
                            'type': 'int',
                        },
                        'REQ_500m': {
                            'type': 'int',
                        },
                        'status_508': {
                            'type': 'int',
                        },
                        'status_509': {
                            'type': 'int',
                        },
                        'REQ_OVER_5s': {
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
                        'status_505': {
                            'type': 'int',
                        },
                        'status_506': {
                            'type': 'int',
                        },
                        'status_507': {
                            'type': 'int',
                        },
                        'status_449': {
                            'type': 'int',
                        }
                    },
                    'real_curr_conn': {
                        'type': 'int',
                    },
                    'loc_success': {
                        'type': 'int',
                    },
                    'loc_error': {
                        'type': 'int',
                    },
                    'group_id': {
                        'type': 'int',
                    },
                    'loc_override': {
                        'type': 'int',
                    }
                },
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['dns-udp']
                },
                'port_number': {
                    'type': 'int',
                    'required': True,
                }
            },
            'curr_conn_overflow': {
                'type': 'int',
            },
            'icmp_rate_over_limit_drop': {
                'type': 'int',
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'icmpv6_rate_over_limit_drop': {
                'type': 'int',
            },
            'curr_conn_rate': {
                'type': 'int',
            },
            'mac': {
                'type': 'str',
            },
            'curr_icmp_rate': {
                'type': 'int',
            },
            'icmpv6_lockup_time_left': {
                'type': 'int',
            },
            'state': {
                'type':
                'str',
                'choices': [
                    'All Up', 'Functional Up', 'Partial Up', 'Down', 'Disb',
                    'Unkn'
                ]
            },
            'curr_icmpv6_rate': {
                'type': 'int',
            },
            'ip_address': {
                'type': 'str',
            },
            'icmp_lockup_time_left': {
                'type': 'int',
            },
            'migration_status': {
                'type': 'str',
            }
        },
        'use_if_ip': {
            'type': 'bool',
        },
        'port_list': {
            'type': 'list',
            'protocol': {
                'type': 'str',
                'required': True,
                'choices': ['dns-udp']
            },
            'uuid': {
                'type': 'str',
            },
            'precedence': {
                'type': 'bool',
            },
            'auto': {
                'type': 'bool',
            },
            'template_policy': {
                'type': 'str',
            },
            'service_group': {
                'type': 'str',
            },
            'port_number': {
                'type': 'int',
                'required': True,
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
            'user_tag': {
                'type': 'str',
            },
            'template_dns': {
                'type': 'str',
            },
            'acl_id_list': {
                'type': 'list',
                'acl_id_seq_num': {
                    'type': 'int',
                },
                'acl_id': {
                    'type': 'int',
                },
                'acl_id_src_nat_pool': {
                    'type': 'str',
                }
            },
            'action': {
                'type': 'str',
                'choices': ['enable', 'disable']
            },
            'pool': {
                'type': 'str',
            }
        },
        'name': {
            'type': 'str',
            'required': True,
        },
        'template_policy': {
            'type': 'str',
        },
        'vrid': {
            'type': 'int',
        },
        'enable_disable_action': {
            'type': 'str',
            'choices': ['enable', 'disable']
        },
        'user_tag': {
            'type': 'str',
        },
        'ipv6_address': {
            'type': 'str',
        },
        'netmask': {
            'type': 'str',
        },
        'ip_address': {
            'type': 'str',
        },
        'policy': {
            'type': 'bool',
        },
        'ethernet': {
            'type': 'str',
        },
        'uuid': {
            'type': 'str',
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


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
    return module.client.get(oper_url(module))


def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None


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
    if existing_config:
        for k, v in payload["dns64-virtualserver"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["dns64-virtualserver"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["dns64-virtualserver"][k] = v
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
    payload = build_json("dns64-virtualserver", module)
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

    result = dict(changed=False, original_message="", message="", result={})

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
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
