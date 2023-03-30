#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_interface_loopback
description:
    - Loopback interface
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
    ifnum:
        description:
        - "Loopback interface number"
        type: str
        required: True
    name:
        description:
        - "Name for the interface"
        type: str
        required: False
    snmp_server:
        description:
        - "Field snmp_server"
        type: dict
        required: False
        suboptions:
            trap_source:
                description:
                - "The trap source"
                type: bool
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
    ip:
        description:
        - "Field ip"
        type: dict
        required: False
        suboptions:
            address_list:
                description:
                - "Field address_list"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
            router:
                description:
                - "Field router"
                type: dict
            rip:
                description:
                - "Field rip"
                type: dict
            ospf:
                description:
                - "Field ospf"
                type: dict
    ipv6:
        description:
        - "Field ipv6"
        type: dict
        required: False
        suboptions:
            address_list:
                description:
                - "Field address_list"
                type: list
            ipv6_enable:
                description:
                - "Enable IPv6 processing"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            router:
                description:
                - "Field router"
                type: dict
            rip:
                description:
                - "Field rip"
                type: dict
            ospf:
                description:
                - "Field ospf"
                type: dict
    isis:
        description:
        - "Field isis"
        type: dict
        required: False
        suboptions:
            authentication:
                description:
                - "Field authentication"
                type: dict
            bfd_cfg:
                description:
                - "Field bfd_cfg"
                type: dict
            circuit_type:
                description:
                - "'level-1'= Level-1 only adjacencies are formed; 'level-1-2'= Level-1-2
          adjacencies are formed; 'level-2-only'= Level-2 only adjacencies are formed;"
                type: str
            csnp_interval_list:
                description:
                - "Field csnp_interval_list"
                type: list
            padding:
                description:
                - "Add padding to IS-IS hello packets"
                type: bool
            hello_interval_list:
                description:
                - "Field hello_interval_list"
                type: list
            hello_interval_minimal_list:
                description:
                - "Field hello_interval_minimal_list"
                type: list
            hello_multiplier_list:
                description:
                - "Field hello_multiplier_list"
                type: list
            lsp_interval:
                description:
                - "Set LSP transmission interval (LSP transmission interval (milliseconds))"
                type: int
            mesh_group:
                description:
                - "Field mesh_group"
                type: dict
            metric_list:
                description:
                - "Field metric_list"
                type: list
            password_list:
                description:
                - "Field password_list"
                type: list
            priority_list:
                description:
                - "Field priority_list"
                type: list
            retransmit_interval:
                description:
                - "Set per-LSP retransmission interval (Interval between retransmissions of the
          same LSP (seconds))"
                type: int
            wide_metric_list:
                description:
                - "Field wide_metric_list"
                type: list
            uuid:
                description:
                - "uuid of the object"
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
            line_protocol:
                description:
                - "Field line_protocol"
                type: str
            ipv4_address:
                description:
                - "IP address"
                type: str
            ipv4_netmask:
                description:
                - "IP subnet mask"
                type: str
            ipv6_link_local:
                description:
                - "Field ipv6_link_local"
                type: str
            ipv6_link_local_prefix:
                description:
                - "Field ipv6_link_local_prefix"
                type: str
            ipv6_link_local_type:
                description:
                - "Field ipv6_link_local_type"
                type: str
            ipv6_link_local_scope:
                description:
                - "Field ipv6_link_local_scope"
                type: str
            ipv4_addr_count:
                description:
                - "Field ipv4_addr_count"
                type: int
            ipv4_list:
                description:
                - "Field ipv4_list"
                type: list
            ipv6_addr_count:
                description:
                - "Field ipv6_addr_count"
                type: int
            ipv6_list:
                description:
                - "Field ipv6_list"
                type: list
            ifnum:
                description:
                - "Loopback interface number"
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
AVAILABLE_PROPERTIES = ["ifnum", "ip", "ipv6", "isis", "name", "oper", "snmp_server", "user_tag", "uuid", ]


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
        'ifnum': {
            'type': 'str',
            'required': True,
            },
        'name': {
            'type': 'str',
            },
        'snmp_server': {
            'type': 'dict',
            'trap_source': {
                'type': 'bool',
                }
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
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
            'uuid': {
                'type': 'str',
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
                },
            'rip': {
                'type': 'dict',
                'authentication': {
                    'type': 'dict',
                    'str': {
                        'type': 'dict',
                        'string': {
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
                    'key_chain': {
                        'type': 'dict',
                        'key_chain': {
                            'type': 'str',
                            }
                        }
                    },
                'send_packet': {
                    'type': 'bool',
                    },
                'receive_packet': {
                    'type': 'bool',
                    },
                'send_cfg': {
                    'type': 'dict',
                    'send': {
                        'type': 'bool',
                        },
                    'version': {
                        'type': 'str',
                        'choices': ['1', '2', '1-compatible', '1-2']
                        }
                    },
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
            'ospf': {
                'type': 'dict',
                'ospf_global': {
                    'type': 'dict',
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
                    'authentication_key': {
                        'type': 'str',
                        },
                    'bfd_cfg': {
                        'type': 'dict',
                        'bfd': {
                            'type': 'bool',
                            },
                        'disable': {
                            'type': 'bool',
                            }
                        },
                    'cost': {
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
                    'dead_interval': {
                        'type': 'int',
                        },
                    'disable': {
                        'type': 'str',
                        'choices': ['all']
                        },
                    'hello_interval': {
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
                    'mtu': {
                        'type': 'int',
                        },
                    'mtu_ignore': {
                        'type': 'bool',
                        },
                    'priority': {
                        'type': 'int',
                        },
                    'retransmit_interval': {
                        'type': 'int',
                        },
                    'transmit_delay': {
                        'type': 'int',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'ospf_ip_list': {
                    'type': 'list',
                    'ip_addr': {
                        'type': 'str',
                        'required': True,
                        },
                    'authentication': {
                        'type': 'bool',
                        },
                    'value': {
                        'type': 'str',
                        'choices': ['message-digest', 'null']
                        },
                    'authentication_key': {
                        'type': 'str',
                        },
                    'cost': {
                        'type': 'int',
                        },
                    'database_filter': {
                        'type': 'str',
                        'choices': ['all']
                        },
                    'out': {
                        'type': 'bool',
                        },
                    'dead_interval': {
                        'type': 'int',
                        },
                    'hello_interval': {
                        'type': 'int',
                        },
                    'message_digest_cfg': {
                        'type': 'list',
                        'message_digest_key': {
                            'type': 'int',
                            },
                        'md5_value': {
                            'type': 'str',
                            },
                        'encrypted': {
                            'type': 'str',
                            }
                        },
                    'mtu_ignore': {
                        'type': 'bool',
                        },
                    'priority': {
                        'type': 'int',
                        },
                    'retransmit_interval': {
                        'type': 'int',
                        },
                    'transmit_delay': {
                        'type': 'int',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                }
            },
        'ipv6': {
            'type': 'dict',
            'address_list': {
                'type': 'list',
                'ipv6_addr': {
                    'type': 'str',
                    },
                'anycast': {
                    'type': 'bool',
                    },
                'link_local': {
                    'type': 'bool',
                    }
                },
            'ipv6_enable': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                },
            'router': {
                'type': 'dict',
                'ripng': {
                    'type': 'dict',
                    'rip': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'ospf': {
                    'type': 'dict',
                    'area_list': {
                        'type': 'list',
                        'area_id_num': {
                            'type': 'int',
                            },
                        'area_id_addr': {
                            'type': 'str',
                            },
                        'tag': {
                            'type': 'str',
                            },
                        'instance_id': {
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
            'ospf': {
                'type': 'dict',
                'bfd': {
                    'type': 'bool',
                    },
                'disable': {
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
                'dead_interval_cfg': {
                    'type': 'list',
                    'dead_interval': {
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
                'mtu_ignore_cfg': {
                    'type': 'list',
                    'mtu_ignore': {
                        'type': 'bool',
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
                'retransmit_interval_cfg': {
                    'type': 'list',
                    'retransmit_interval': {
                        'type': 'int',
                        },
                    'instance_id': {
                        'type': 'int',
                        }
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
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'isis': {
            'type': 'dict',
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
            'bfd_cfg': {
                'type': 'dict',
                'bfd': {
                    'type': 'bool',
                    },
                'disable': {
                    'type': 'bool',
                    }
                },
            'circuit_type': {
                'type': 'str',
                'choices': ['level-1', 'level-1-2', 'level-2-only']
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
            'padding': {
                'type': 'bool',
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
            'lsp_interval': {
                'type': 'int',
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
            'retransmit_interval': {
                'type': 'int',
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
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'state': {
                'type': 'str',
                },
            'line_protocol': {
                'type': 'str',
                },
            'ipv4_address': {
                'type': 'str',
                },
            'ipv4_netmask': {
                'type': 'str',
                },
            'ipv6_link_local': {
                'type': 'str',
                },
            'ipv6_link_local_prefix': {
                'type': 'str',
                },
            'ipv6_link_local_type': {
                'type': 'str',
                },
            'ipv6_link_local_scope': {
                'type': 'str',
                },
            'ipv4_addr_count': {
                'type': 'int',
                },
            'ipv4_list': {
                'type': 'list',
                'addr': {
                    'type': 'str',
                    },
                'mask': {
                    'type': 'str',
                    }
                },
            'ipv6_addr_count': {
                'type': 'int',
                },
            'ipv6_list': {
                'type': 'list',
                'addr': {
                    'type': 'str',
                    },
                'prefix': {
                    'type': 'str',
                    },
                'is_anycast': {
                    'type': 'int',
                    }
                },
            'ifnum': {
                'type': 'str',
                'required': True,
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/loopback/{ifnum}"

    f_dict = {}
    if '/' in str(module.params["ifnum"]):
        f_dict["ifnum"] = module.params["ifnum"].replace("/", "%2F")
    else:
        f_dict["ifnum"] = module.params["ifnum"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/interface/loopback"

    f_dict = {}
    f_dict["ifnum"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["loopback"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["loopback"].get(k) != v:
            change_results["changed"] = True
            config_changes["loopback"][k] = v

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
    payload = utils.build_json("loopback", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["loopback"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["loopback-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["loopback"]["oper"] if info != "NotFound" else info
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
