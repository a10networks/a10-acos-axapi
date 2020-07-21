#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_interface_loopback
description:
    - Loopback interface
short_description: Configures A10 interface.loopback
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
            ipv6_list:
                description:
                - "Field ipv6_list"
            line_protocol:
                description:
                - "Field line_protocol"
            ipv4_netmask:
                description:
                - "IP subnet mask"
            ipv6_link_local:
                description:
                - "Field ipv6_link_local"
            ifnum:
                description:
                - "Loopback interface number"
            state:
                description:
                - "Field state"
            ipv6_link_local_prefix:
                description:
                - "Field ipv6_link_local_prefix"
            ipv4_addr_count:
                description:
                - "Field ipv4_addr_count"
            ipv6_link_local_type:
                description:
                - "Field ipv6_link_local_type"
            ipv6_link_local_scope:
                description:
                - "Field ipv6_link_local_scope"
            ipv6_addr_count:
                description:
                - "Field ipv6_addr_count"
            ipv4_address:
                description:
                - "IP address"
            ipv4_list:
                description:
                - "Field ipv4_list"
    isis:
        description:
        - "Field isis"
        required: False
        suboptions:
            priority_list:
                description:
                - "Field priority_list"
            padding:
                description:
                - "Add padding to IS-IS hello packets"
            hello_interval_minimal_list:
                description:
                - "Field hello_interval_minimal_list"
            mesh_group:
                description:
                - "Field mesh_group"
            uuid:
                description:
                - "uuid of the object"
            authentication:
                description:
                - "Field authentication"
            csnp_interval_list:
                description:
                - "Field csnp_interval_list"
            retransmit_interval:
                description:
                - "Set per-LSP retransmission interval (Interval between retransmissions of the
          same LSP (seconds))"
            password_list:
                description:
                - "Field password_list"
            bfd_cfg:
                description:
                - "Field bfd_cfg"
            wide_metric_list:
                description:
                - "Field wide_metric_list"
            hello_interval_list:
                description:
                - "Field hello_interval_list"
            circuit_type:
                description:
                - "'level-1'= Level-1 only adjacencies are formed; 'level-1-2'= Level-1-2
          adjacencies are formed; 'level-2-only'= Level-2 only adjacencies are formed;"
            hello_multiplier_list:
                description:
                - "Field hello_multiplier_list"
            metric_list:
                description:
                - "Field metric_list"
            lsp_interval:
                description:
                - "Set LSP transmission interval (LSP transmission interval (milliseconds))"
    uuid:
        description:
        - "uuid of the object"
        required: False
    snmp_server:
        description:
        - "Field snmp_server"
        required: False
        suboptions:
            trap_source:
                description:
                - "The trap source"
    ip:
        description:
        - "Field ip"
        required: False
        suboptions:
            address_list:
                description:
                - "Field address_list"
            ospf:
                description:
                - "Field ospf"
            uuid:
                description:
                - "uuid of the object"
            rip:
                description:
                - "Field rip"
            router:
                description:
                - "Field router"
    user_tag:
        description:
        - "Customized tag"
        required: False
    ifnum:
        description:
        - "Loopback interface number"
        required: True
    ipv6:
        description:
        - "Field ipv6"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            address_list:
                description:
                - "Field address_list"
            rip:
                description:
                - "Field rip"
            ipv6_enable:
                description:
                - "Enable IPv6 processing"
            router:
                description:
                - "Field router"
            ospf:
                description:
                - "Field ospf"
    name:
        description:
        - "Name for the interface"
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
    "ifnum",
    "ip",
    "ipv6",
    "isis",
    "name",
    "oper",
    "snmp_server",
    "user_tag",
    "uuid",
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
            'ipv6_list': {
                'type': 'list',
                'is_anycast': {
                    'type': 'int',
                },
                'prefix': {
                    'type': 'str',
                },
                'addr': {
                    'type': 'str',
                }
            },
            'line_protocol': {
                'type': 'str',
            },
            'ipv4_netmask': {
                'type': 'str',
            },
            'ipv6_link_local': {
                'type': 'str',
            },
            'ifnum': {
                'type': 'str',
                'required': True,
            },
            'state': {
                'type': 'str',
            },
            'ipv6_link_local_prefix': {
                'type': 'str',
            },
            'ipv4_addr_count': {
                'type': 'int',
            },
            'ipv6_link_local_type': {
                'type': 'str',
            },
            'ipv6_link_local_scope': {
                'type': 'str',
            },
            'ipv6_addr_count': {
                'type': 'int',
            },
            'ipv4_address': {
                'type': 'str',
            },
            'ipv4_list': {
                'type': 'list',
                'mask': {
                    'type': 'str',
                },
                'addr': {
                    'type': 'str',
                }
            }
        },
        'isis': {
            'type': 'dict',
            'priority_list': {
                'type': 'list',
                'priority': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'padding': {
                'type': 'bool',
            },
            'hello_interval_minimal_list': {
                'type': 'list',
                'hello_interval_minimal': {
                    'type': 'bool',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'mesh_group': {
                'type': 'dict',
                'value': {
                    'type': 'int',
                },
                'blocked': {
                    'type': 'bool',
                }
            },
            'uuid': {
                'type': 'str',
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
            'csnp_interval_list': {
                'type': 'list',
                'csnp_interval': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'retransmit_interval': {
                'type': 'int',
            },
            'password_list': {
                'type': 'list',
                'password': {
                    'type': 'str',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'bfd_cfg': {
                'type': 'dict',
                'disable': {
                    'type': 'bool',
                },
                'bfd': {
                    'type': 'bool',
                }
            },
            'wide_metric_list': {
                'type': 'list',
                'wide_metric': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'hello_interval_list': {
                'type': 'list',
                'hello_interval': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'circuit_type': {
                'type': 'str',
                'choices': ['level-1', 'level-1-2', 'level-2-only']
            },
            'hello_multiplier_list': {
                'type': 'list',
                'hello_multiplier': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'metric_list': {
                'type': 'list',
                'metric': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'lsp_interval': {
                'type': 'int',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'snmp_server': {
            'type': 'dict',
            'trap_source': {
                'type': 'bool',
            }
        },
        'ip': {
            'type': 'dict',
            'address_list': {
                'type': 'list',
                'ipv4_address': {
                    'type': 'str',
                },
                'ipv4_netmask': {
                    'type': 'str',
                }
            },
            'ospf': {
                'type': 'dict',
                'ospf_ip_list': {
                    'type': 'list',
                    'dead_interval': {
                        'type': 'int',
                    },
                    'authentication_key': {
                        'type': 'str',
                    },
                    'uuid': {
                        'type': 'str',
                    },
                    'mtu_ignore': {
                        'type': 'bool',
                    },
                    'transmit_delay': {
                        'type': 'int',
                    },
                    'value': {
                        'type': 'str',
                        'choices': ['message-digest', 'null']
                    },
                    'priority': {
                        'type': 'int',
                    },
                    'authentication': {
                        'type': 'bool',
                    },
                    'cost': {
                        'type': 'int',
                    },
                    'database_filter': {
                        'type': 'str',
                        'choices': ['all']
                    },
                    'hello_interval': {
                        'type': 'int',
                    },
                    'ip_addr': {
                        'type': 'str',
                        'required': True,
                    },
                    'retransmit_interval': {
                        'type': 'int',
                    },
                    'message_digest_cfg': {
                        'type': 'list',
                        'md5_value': {
                            'type': 'str',
                        },
                        'message_digest_key': {
                            'type': 'int',
                        },
                        'encrypted': {
                            'type': 'str',
                        }
                    },
                    'out': {
                        'type': 'bool',
                    }
                },
                'ospf_global': {
                    'type': 'dict',
                    'dead_interval': {
                        'type': 'int',
                    },
                    'authentication_key': {
                        'type': 'str',
                    },
                    'uuid': {
                        'type': 'str',
                    },
                    'mtu_ignore': {
                        'type': 'bool',
                    },
                    'transmit_delay': {
                        'type': 'int',
                    },
                    'authentication_cfg': {
                        'type': 'dict',
                        'authentication': {
                            'type': 'bool',
                        },
                        'value': {
                            'type': 'str',
                            'choices': ['message-digest', 'null']
                        }
                    },
                    'retransmit_interval': {
                        'type': 'int',
                    },
                    'bfd_cfg': {
                        'type': 'dict',
                        'disable': {
                            'type': 'bool',
                        },
                        'bfd': {
                            'type': 'bool',
                        }
                    },
                    'disable': {
                        'type': 'str',
                        'choices': ['all']
                    },
                    'hello_interval': {
                        'type': 'int',
                    },
                    'database_filter_cfg': {
                        'type': 'dict',
                        'database_filter': {
                            'type': 'str',
                            'choices': ['all']
                        },
                        'out': {
                            'type': 'bool',
                        }
                    },
                    'priority': {
                        'type': 'int',
                    },
                    'mtu': {
                        'type': 'int',
                    },
                    'message_digest_cfg': {
                        'type': 'list',
                        'message_digest_key': {
                            'type': 'int',
                        },
                        'md5': {
                            'type': 'dict',
                            'md5_value': {
                                'type': 'str',
                            },
                            'encrypted': {
                                'type': 'str',
                            }
                        }
                    },
                    'cost': {
                        'type': 'int',
                    }
                }
            },
            'uuid': {
                'type': 'str',
            },
            'rip': {
                'type': 'dict',
                'receive_cfg': {
                    'type': 'dict',
                    'receive': {
                        'type': 'bool',
                    },
                    'version': {
                        'type': 'str',
                        'choices': ['1', '2', '1-2']
                    }
                },
                'uuid': {
                    'type': 'str',
                },
                'receive_packet': {
                    'type': 'bool',
                },
                'split_horizon_cfg': {
                    'type': 'dict',
                    'state': {
                        'type': 'str',
                        'choices': ['poisoned', 'disable', 'enable']
                    }
                },
                'authentication': {
                    'type': 'dict',
                    'key_chain': {
                        'type': 'dict',
                        'key_chain': {
                            'type': 'str',
                        }
                    },
                    'mode': {
                        'type': 'dict',
                        'mode': {
                            'type': 'str',
                            'choices': ['md5', 'text']
                        }
                    },
                    'str': {
                        'type': 'dict',
                        'string': {
                            'type': 'str',
                        }
                    }
                },
                'send_cfg': {
                    'type': 'dict',
                    'version': {
                        'type': 'str',
                        'choices': ['1', '2', '1-compatible', '1-2']
                    },
                    'send': {
                        'type': 'bool',
                    }
                },
                'send_packet': {
                    'type': 'bool',
                }
            },
            'router': {
                'type': 'dict',
                'isis': {
                    'type': 'dict',
                    'tag': {
                        'type': 'str',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                }
            }
        },
        'user_tag': {
            'type': 'str',
        },
        'ifnum': {
            'type': 'str',
            'required': True,
        },
        'ipv6': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            },
            'address_list': {
                'type': 'list',
                'link_local': {
                    'type': 'bool',
                },
                'ipv6_addr': {
                    'type': 'str',
                },
                'anycast': {
                    'type': 'bool',
                }
            },
            'rip': {
                'type': 'dict',
                'split_horizon_cfg': {
                    'type': 'dict',
                    'state': {
                        'type': 'str',
                        'choices': ['poisoned', 'disable', 'enable']
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'ipv6_enable': {
                'type': 'bool',
            },
            'router': {
                'type': 'dict',
                'ripng': {
                    'type': 'dict',
                    'uuid': {
                        'type': 'str',
                    },
                    'rip': {
                        'type': 'bool',
                    }
                },
                'ospf': {
                    'type': 'dict',
                    'area_list': {
                        'type': 'list',
                        'area_id_addr': {
                            'type': 'str',
                        },
                        'tag': {
                            'type': 'str',
                        },
                        'instance_id': {
                            'type': 'int',
                        },
                        'area_id_num': {
                            'type': 'int',
                        }
                    },
                    'uuid': {
                        'type': 'str',
                    }
                },
                'isis': {
                    'type': 'dict',
                    'tag': {
                        'type': 'str',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                }
            },
            'ospf': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                },
                'bfd': {
                    'type': 'bool',
                },
                'cost_cfg': {
                    'type': 'list',
                    'cost': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'hello_interval_cfg': {
                    'type': 'list',
                    'hello_interval': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'priority_cfg': {
                    'type': 'list',
                    'priority': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'mtu_ignore_cfg': {
                    'type': 'list',
                    'mtu_ignore': {
                        'type': 'bool',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'retransmit_interval_cfg': {
                    'type': 'list',
                    'retransmit_interval': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'disable': {
                    'type': 'bool',
                },
                'transmit_delay_cfg': {
                    'type': 'list',
                    'transmit_delay': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'dead_interval_cfg': {
                    'type': 'list',
                    'dead_interval': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                }
            }
        },
        'name': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/loopback/{ifnum}"

    f_dict = {}
    f_dict["ifnum"] = module.params["ifnum"]

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
    url_base = "/axapi/v3/interface/loopback/{ifnum}"

    f_dict = {}
    f_dict["ifnum"] = ""

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
        for k, v in payload["loopback"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["loopback"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["loopback"][k] = v
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
    payload = build_json("loopback", module)
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
