#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_router_isis
description:
    - Intermediate System - Intermediate System (IS-IS)
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
    tag:
        description:
        - "ISO routing area tag"
        type: str
        required: True
    adjacency_check:
        description:
        - "Check ISIS neighbor protocol support"
        type: bool
        required: False
    area_password_cfg:
        description:
        - "Field area_password_cfg"
        type: dict
        required: False
        suboptions:
            password:
                description:
                - "Configure the authentication password for an area (Area password)"
                type: str
            authenticate:
                description:
                - "Field authenticate"
                type: dict
    authentication:
        description:
        - "Field authentication"
        type: dict
        required: False
        suboptions:
            send_only_list:
                description:
                - "Field send_only_list"
                type: list
            mode_list:
                description:
                - "Field mode_list"
                type: list
            key_chain_list:
                description:
                - "Field key_chain_list"
                type: list
    bfd:
        description:
        - "'all-interfaces'= Enable BFD on all interfaces;"
        type: str
        required: False
    default_information:
        description:
        - "'originate'= Distribute a default route;"
        type: str
        required: False
    distance_list:
        description:
        - "Field distance_list"
        type: list
        required: False
        suboptions:
            distance:
                description:
                - "ISIS Administrative Distance (Distance value)"
                type: int
            System_ID:
                description:
                - "System-ID in XXXX.XXXX.XXXX"
                type: str
            acl:
                description:
                - "Access list name"
                type: str
    domain_password_cfg:
        description:
        - "Field domain_password_cfg"
        type: dict
        required: False
        suboptions:
            password:
                description:
                - "Set the authentication password for a routing domain (Routing domain password)"
                type: str
            authenticate:
                description:
                - "Field authenticate"
                type: dict
    ha_standby_extra_cost:
        description:
        - "Field ha_standby_extra_cost"
        type: list
        required: False
        suboptions:
            extra_cost:
                description:
                - "The extra cost value"
                type: int
            group:
                description:
                - "Group (Group ID)"
                type: int
    ignore_lsp_errors:
        description:
        - "Ignore LSPs with bad checksums"
        type: bool
        required: False
    is_type:
        description:
        - "'level-1'= Act as a station router only; 'level-1-2'= Act as both a station
          router and an area router; 'level-2-only'= Act as an area router only;"
        type: str
        required: False
    log_adjacency_changes_cfg:
        description:
        - "Field log_adjacency_changes_cfg"
        type: dict
        required: False
        suboptions:
            state:
                description:
                - "'detail'= Log changes in adjacency state; 'disable'= Disable logging;"
                type: str
    lsp_gen_interval_list:
        description:
        - "Field lsp_gen_interval_list"
        type: list
        required: False
        suboptions:
            interval:
                description:
                - "Minimum interval in seconds"
                type: int
            level:
                description:
                - "'level-1'= Set interval for level 1 only; 'level-2'= Set interval for level 2
          only;"
                type: str
    lsp_refresh_interval:
        description:
        - "Set LSP refresh interval (LSP refresh time in seconds)"
        type: int
        required: False
    max_lsp_lifetime:
        description:
        - "Set maximum LSP lifetime (Maximum LSP lifetime in seconds)"
        type: int
        required: False
    metric_style_list:
        description:
        - "Field metric_style_list"
        type: list
        required: False
        suboptions:
            ntype:
                description:
                - "'narrow'= Use old style of TLVs with narrow metric; 'wide'= Use new style of
          TLVs to carry wider metric; 'transition'= Send and accept both styles of TLVs
          during transition; 'narrow-transition'= Send old style of TLVs with narrow
          metric with accepting both styles of TLVs; 'wide-transition'= Send new style of
          TLVs to carry wider metric with accepting both styles of TLVs;"
                type: str
            level:
                description:
                - "'level-1'= Level-1 only; 'level-1-2'= Level-1-2; 'level-2'= Level-2 only;"
                type: str
    passive_interface_list:
        description:
        - "Field passive_interface_list"
        type: list
        required: False
        suboptions:
            ethernet:
                description:
                - "Ethernet interface (Port number)"
                type: str
            loopback:
                description:
                - "Loopback interface (Port number)"
                type: str
            trunk:
                description:
                - "Trunk interface (Trunk interface number)"
                type: str
            lif:
                description:
                - "Logical interface (Lif interface number)"
                type: str
            ve:
                description:
                - "Virtual ethernet interface (Virtual ethernet interface number)"
                type: str
            tunnel:
                description:
                - "Tunnel interface (Tunnel interface number)"
                type: str
    protocol_list:
        description:
        - "Field protocol_list"
        type: list
        required: False
        suboptions:
            protocol_topology:
                description:
                - "Protocol Topology"
                type: bool
    set_overload_bit_cfg:
        description:
        - "Field set_overload_bit_cfg"
        type: dict
        required: False
        suboptions:
            set_overload_bit:
                description:
                - "Signal other touers not to use us in SPF"
                type: bool
            on_startup:
                description:
                - "Field on_startup"
                type: dict
            suppress_cfg:
                description:
                - "Field suppress_cfg"
                type: dict
    spf_interval_exp_list:
        description:
        - "Field spf_interval_exp_list"
        type: list
        required: False
        suboptions:
            min:
                description:
                - "Minimum Delay between receiving a change to SPF calculation in milliseconds"
                type: int
            max:
                description:
                - "Maximum Delay between receiving a change to SPF calculation in milliseconds"
                type: int
            level:
                description:
                - "'level-1'= Set interval for level 1 only; 'level-2'= Set interval for level 2
          only;"
                type: str
    summary_address_list:
        description:
        - "Field summary_address_list"
        type: list
        required: False
        suboptions:
            prefix:
                description:
                - "IP network prefix"
                type: str
            level:
                description:
                - "'level-1'= Summarize into level-1 area; 'level-1-2'= Summarize into both area
          and sub-domain; 'level-2'= Summarize into level-2 sub-domain;"
                type: str
    net_list:
        description:
        - "Field net_list"
        type: list
        required: False
        suboptions:
            net:
                description:
                - "A Network Entity Title for this process (XX.XXXX. ... .XXXX.XX  Network entity
          title (NET))"
                type: str
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
    redistribute:
        description:
        - "Field redistribute"
        type: dict
        required: False
        suboptions:
            redist_list:
                description:
                - "Field redist_list"
                type: list
            vip_list:
                description:
                - "Field vip_list"
                type: list
            isis:
                description:
                - "Field isis"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
    address_family:
        description:
        - "Field address_family"
        type: dict
        required: False
        suboptions:
            ipv6:
                description:
                - "Field ipv6"
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
    "address_family",
    "adjacency_check",
    "area_password_cfg",
    "authentication",
    "bfd",
    "default_information",
    "distance_list",
    "domain_password_cfg",
    "ha_standby_extra_cost",
    "ignore_lsp_errors",
    "is_type",
    "log_adjacency_changes_cfg",
    "lsp_gen_interval_list",
    "lsp_refresh_interval",
    "max_lsp_lifetime",
    "metric_style_list",
    "net_list",
    "passive_interface_list",
    "protocol_list",
    "redistribute",
    "set_overload_bit_cfg",
    "spf_interval_exp_list",
    "summary_address_list",
    "tag",
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
        'tag': {
            'type': 'str',
            'required': True,
        },
        'adjacency_check': {
            'type': 'bool',
        },
        'area_password_cfg': {
            'type': 'dict',
            'password': {
                'type': 'str',
            },
            'authenticate': {
                'type': 'dict',
                'snp': {
                    'type': 'str',
                    'choices': ['send-only', 'validate']
                }
            }
        },
        'authentication': {
            'type': 'dict',
            'send_only_list': {
                'type': 'list',
                'send_only': {
                    'type': 'bool',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'mode_list': {
                'type': 'list',
                'mode': {
                    'type': 'str',
                    'choices': ['md5']
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'key_chain_list': {
                'type': 'list',
                'key_chain': {
                    'type': 'str',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            }
        },
        'bfd': {
            'type': 'str',
            'choices': ['all-interfaces']
        },
        'default_information': {
            'type': 'str',
            'choices': ['originate']
        },
        'distance_list': {
            'type': 'list',
            'distance': {
                'type': 'int',
            },
            'System_ID': {
                'type': 'str',
            },
            'acl': {
                'type': 'str',
            }
        },
        'domain_password_cfg': {
            'type': 'dict',
            'password': {
                'type': 'str',
            },
            'authenticate': {
                'type': 'dict',
                'snp': {
                    'type': 'str',
                    'choices': ['send-only', 'validate']
                }
            }
        },
        'ha_standby_extra_cost': {
            'type': 'list',
            'extra_cost': {
                'type': 'int',
            },
            'group': {
                'type': 'int',
            }
        },
        'ignore_lsp_errors': {
            'type': 'bool',
        },
        'is_type': {
            'type': 'str',
            'choices': ['level-1', 'level-1-2', 'level-2-only']
        },
        'log_adjacency_changes_cfg': {
            'type': 'dict',
            'state': {
                'type': 'str',
                'choices': ['detail', 'disable']
            }
        },
        'lsp_gen_interval_list': {
            'type': 'list',
            'interval': {
                'type': 'int',
            },
            'level': {
                'type': 'str',
                'choices': ['level-1', 'level-2']
            }
        },
        'lsp_refresh_interval': {
            'type': 'int',
        },
        'max_lsp_lifetime': {
            'type': 'int',
        },
        'metric_style_list': {
            'type': 'list',
            'ntype': {
                'type':
                'str',
                'choices': [
                    'narrow', 'wide', 'transition', 'narrow-transition',
                    'wide-transition'
                ]
            },
            'level': {
                'type': 'str',
                'choices': ['level-1', 'level-1-2', 'level-2']
            }
        },
        'passive_interface_list': {
            'type': 'list',
            'ethernet': {
                'type': 'str',
            },
            'loopback': {
                'type': 'str',
            },
            'trunk': {
                'type': 'str',
            },
            'lif': {
                'type': 'str',
            },
            've': {
                'type': 'str',
            },
            'tunnel': {
                'type': 'str',
            }
        },
        'protocol_list': {
            'type': 'list',
            'protocol_topology': {
                'type': 'bool',
            }
        },
        'set_overload_bit_cfg': {
            'type': 'dict',
            'set_overload_bit': {
                'type': 'bool',
            },
            'on_startup': {
                'type': 'dict',
                'delay': {
                    'type': 'int',
                },
                'wait_for_bgp': {
                    'type': 'bool',
                }
            },
            'suppress_cfg': {
                'type': 'dict',
                'external': {
                    'type': 'bool',
                },
                'interlevel': {
                    'type': 'bool',
                }
            }
        },
        'spf_interval_exp_list': {
            'type': 'list',
            'min': {
                'type': 'int',
            },
            'max': {
                'type': 'int',
            },
            'level': {
                'type': 'str',
                'choices': ['level-1', 'level-2']
            }
        },
        'summary_address_list': {
            'type': 'list',
            'prefix': {
                'type': 'str',
            },
            'level': {
                'type': 'str',
                'choices': ['level-1', 'level-1-2', 'level-2']
            }
        },
        'net_list': {
            'type': 'list',
            'net': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'redistribute': {
            'type': 'dict',
            'redist_list': {
                'type': 'list',
                'ntype': {
                    'type':
                    'str',
                    'choices': [
                        'bgp', 'connected', 'floating-ip', 'ip-nat-list',
                        'ip-nat', 'lw4o6', 'nat-map', 'static-nat', 'ospf',
                        'rip', 'static'
                    ]
                },
                'metric': {
                    'type': 'int',
                },
                'metric_type': {
                    'type': 'str',
                    'choices': ['external', 'internal']
                },
                'route_map': {
                    'type': 'str',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-1-2', 'level-2']
                }
            },
            'vip_list': {
                'type': 'list',
                'vip_type': {
                    'type': 'str',
                    'choices': ['only-flagged', 'only-not-flagged']
                },
                'vip_metric': {
                    'type': 'int',
                },
                'vip_route_map': {
                    'type': 'str',
                },
                'vip_metric_type': {
                    'type': 'str',
                    'choices': ['external', 'internal']
                },
                'vip_level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-1-2', 'level-2']
                }
            },
            'isis': {
                'type': 'dict',
                'level_1_from': {
                    'type': 'dict',
                    'into_1': {
                        'type': 'dict',
                        'level_2': {
                            'type': 'bool',
                        },
                        'distribute_list': {
                            'type': 'str',
                        }
                    }
                },
                'level_2_from': {
                    'type': 'dict',
                    'into_2': {
                        'type': 'dict',
                        'level_1': {
                            'type': 'bool',
                        },
                        'distribute_list': {
                            'type': 'str',
                        }
                    }
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'address_family': {
            'type': 'dict',
            'ipv6': {
                'type': 'dict',
                'default_information': {
                    'type': 'str',
                    'choices': ['originate']
                },
                'adjacency_check': {
                    'type': 'bool',
                },
                'distance': {
                    'type': 'int',
                },
                'multi_topology_cfg': {
                    'type': 'dict',
                    'multi_topology': {
                        'type': 'bool',
                    },
                    'level': {
                        'type': 'str',
                        'choices': ['level-1', 'level-1-2', 'level-2']
                    },
                    'transition': {
                        'type': 'bool',
                    },
                    'level_transition': {
                        'type': 'bool',
                    }
                },
                'summary_prefix_list': {
                    'type': 'list',
                    'prefix': {
                        'type': 'str',
                    },
                    'level': {
                        'type': 'str',
                        'choices': ['level-1', 'level-1-2', 'level-2']
                    }
                },
                'uuid': {
                    'type': 'str',
                },
                'redistribute': {
                    'type': 'dict',
                    'redist_list': {
                        'type': 'list',
                        'ntype': {
                            'type':
                            'str',
                            'choices': [
                                'bgp', 'connected', 'floating-ip',
                                'ip-nat-list', 'ip-nat', 'lw4o6', 'nat-map',
                                'static-nat', 'nat64', 'ospf', 'rip', 'static'
                            ]
                        },
                        'metric': {
                            'type': 'int',
                        },
                        'metric_type': {
                            'type': 'str',
                            'choices': ['external', 'internal']
                        },
                        'route_map': {
                            'type': 'str',
                        },
                        'level': {
                            'type': 'str',
                            'choices': ['level-1', 'level-1-2', 'level-2']
                        }
                    },
                    'vip_list': {
                        'type': 'list',
                        'vip_type': {
                            'type': 'str',
                            'choices': ['only-flagged', 'only-not-flagged']
                        },
                        'vip_metric': {
                            'type': 'int',
                        },
                        'vip_route_map': {
                            'type': 'str',
                        },
                        'vip_metric_type': {
                            'type': 'str',
                            'choices': ['external', 'internal']
                        },
                        'vip_level': {
                            'type': 'str',
                            'choices': ['level-1', 'level-1-2', 'level-2']
                        }
                    },
                    'isis': {
                        'type': 'dict',
                        'level_1_from': {
                            'type': 'dict',
                            'into_1': {
                                'type': 'dict',
                                'level_2': {
                                    'type': 'bool',
                                },
                                'distribute_list': {
                                    'type': 'str',
                                }
                            }
                        },
                        'level_2_from': {
                            'type': 'dict',
                            'into_2': {
                                'type': 'dict',
                                'level_1': {
                                    'type': 'bool',
                                },
                                'distribute_list': {
                                    'type': 'str',
                                }
                            }
                        }
                    },
                    'uuid': {
                        'type': 'str',
                    }
                }
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/isis/{tag}"

    f_dict = {}
    f_dict["tag"] = module.params["tag"]

    return url_base.format(**f_dict)


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
    url_base = "/axapi/v3/router/isis/{tag}"

    f_dict = {}
    f_dict["tag"] = ""

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
    for k, v in payload["isis"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["isis"].get(k) != v:
            change_results["changed"] = True
            config_changes["isis"][k] = v

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
    payload = build_json("isis", module)
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
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
