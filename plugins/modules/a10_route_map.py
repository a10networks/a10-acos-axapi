#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_route_map
description:
    - Configure route-map
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
    tag:
        description:
        - "Route map tag"
        type: str
        required: True
    action:
        description:
        - "'permit'= Route map permits set operations; 'deny'= Route map denies set
          operations;"
        type: str
        required: True
    sequence:
        description:
        - "Sequence to insert to/delete from existing route-map entry"
        type: int
        required: True
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
    match:
        description:
        - "Field match"
        type: dict
        required: False
        suboptions:
            as_path:
                description:
                - "Field as_path"
                type: dict
            community:
                description:
                - "Field community"
                type: dict
            extcommunity:
                description:
                - "Field extcommunity"
                type: dict
            group:
                description:
                - "Field group"
                type: dict
            scaleout:
                description:
                - "Field scaleout"
                type: dict
            interface:
                description:
                - "Field interface"
                type: dict
            local_preference:
                description:
                - "Field local_preference"
                type: dict
            origin:
                description:
                - "Field origin"
                type: dict
            ip:
                description:
                - "Field ip"
                type: dict
            ipv6:
                description:
                - "Field ipv6"
                type: dict
            metric:
                description:
                - "Field metric"
                type: dict
            route_type:
                description:
                - "Field route_type"
                type: dict
            tag:
                description:
                - "Field tag"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
    set:
        description:
        - "Field set"
        type: dict
        required: False
        suboptions:
            ip:
                description:
                - "Field ip"
                type: dict
            ddos:
                description:
                - "Field ddos"
                type: dict
            ipv6:
                description:
                - "Field ipv6"
                type: dict
            level:
                description:
                - "Field level"
                type: dict
            metric:
                description:
                - "Field metric"
                type: dict
            metric_type:
                description:
                - "Field metric_type"
                type: dict
            tag:
                description:
                - "Field tag"
                type: dict
            aggregator:
                description:
                - "Field aggregator"
                type: dict
            as_path:
                description:
                - "Field as_path"
                type: dict
            atomic_aggregate:
                description:
                - "BGP atomic aggregate attribute"
                type: bool
            comm_list:
                description:
                - "Field comm_list"
                type: dict
            community:
                description:
                - "BGP community attribute"
                type: str
            dampening_cfg:
                description:
                - "Field dampening_cfg"
                type: dict
            extcommunity:
                description:
                - "Field extcommunity"
                type: dict
            local_preference:
                description:
                - "Field local_preference"
                type: dict
            originator_id:
                description:
                - "Field originator_id"
                type: dict
            weight:
                description:
                - "Field weight"
                type: dict
            origin:
                description:
                - "Field origin"
                type: dict
            uuid:
                description:
                - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["action", "match", "sequence", "set", "tag", "user_tag", "uuid", ]


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
        'tag': {
            'type': 'str',
            'required': True,
            },
        'action': {
            'type': 'str',
            'required': True,
            'choices': ['permit', 'deny']
            },
        'sequence': {
            'type': 'int',
            'required': True,
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'match': {
            'type': 'dict',
            'as_path': {
                'type': 'dict',
                'name': {
                    'type': 'str',
                    }
                },
            'community': {
                'type': 'dict',
                'name_cfg': {
                    'type': 'dict',
                    'name': {
                        'type': 'str',
                        },
                    'exact_match': {
                        'type': 'bool',
                        }
                    }
                },
            'extcommunity': {
                'type': 'dict',
                'extcommunity_l_name': {
                    'type': 'dict',
                    'name': {
                        'type': 'str',
                        },
                    'exact_match': {
                        'type': 'bool',
                        }
                    }
                },
            'group': {
                'type': 'dict',
                'group_id': {
                    'type': 'int',
                    },
                'ha_state': {
                    'type': 'str',
                    'choices': ['active', 'standby']
                    }
                },
            'scaleout': {
                'type': 'dict',
                'cluster_id': {
                    'type': 'int',
                    },
                'operational_state': {
                    'type': 'str',
                    'choices': ['up', 'down']
                    }
                },
            'interface': {
                'type': 'dict',
                'ethernet': {
                    'type': 'str',
                    },
                'loopback': {
                    'type': 'int',
                    },
                'trunk': {
                    'type': 'int',
                    },
                've': {
                    'type': 'int',
                    },
                'tunnel': {
                    'type': 'str',
                    }
                },
            'local_preference': {
                'type': 'dict',
                'val': {
                    'type': 'int',
                    }
                },
            'origin': {
                'type': 'dict',
                'egp': {
                    'type': 'bool',
                    },
                'igp': {
                    'type': 'bool',
                    },
                'incomplete': {
                    'type': 'bool',
                    }
                },
            'ip': {
                'type': 'dict',
                'address': {
                    'type': 'dict',
                    'acl1': {
                        'type': 'int',
                        },
                    'acl2': {
                        'type': 'int',
                        },
                    'name': {
                        'type': 'str',
                        },
                    'prefix_list': {
                        'type': 'dict',
                        'name': {
                            'type': 'str',
                            }
                        }
                    },
                'next_hop': {
                    'type': 'dict',
                    'acl1': {
                        'type': 'int',
                        },
                    'acl2': {
                        'type': 'int',
                        },
                    'name': {
                        'type': 'str',
                        },
                    'prefix_list_1': {
                        'type': 'dict',
                        'name': {
                            'type': 'str',
                            }
                        }
                    },
                'peer': {
                    'type': 'dict',
                    'acl1': {
                        'type': 'int',
                        },
                    'acl2': {
                        'type': 'int',
                        },
                    'name': {
                        'type': 'str',
                        }
                    },
                'rib': {
                    'type': 'dict',
                    'exact': {
                        'type': 'str',
                        },
                    'reachable': {
                        'type': 'str',
                        },
                    'unreachable': {
                        'type': 'str',
                        }
                    }
                },
            'ipv6': {
                'type': 'dict',
                'address_1': {
                    'type': 'dict',
                    'name': {
                        'type': 'str',
                        },
                    'prefix_list_2': {
                        'type': 'dict',
                        'name': {
                            'type': 'str',
                            }
                        }
                    },
                'next_hop_1': {
                    'type': 'dict',
                    'next_hop_acl_name': {
                        'type': 'str',
                        },
                    'v6_addr': {
                        'type': 'str',
                        },
                    'prefix_list_name': {
                        'type': 'str',
                        }
                    },
                'peer_1': {
                    'type': 'dict',
                    'acl1': {
                        'type': 'int',
                        },
                    'acl2': {
                        'type': 'int',
                        },
                    'name': {
                        'type': 'str',
                        }
                    },
                'rib': {
                    'type': 'dict',
                    'exact': {
                        'type': 'str',
                        },
                    'reachable': {
                        'type': 'str',
                        },
                    'unreachable': {
                        'type': 'str',
                        }
                    }
                },
            'metric': {
                'type': 'dict',
                'value': {
                    'type': 'int',
                    }
                },
            'route_type': {
                'type': 'dict',
                'external': {
                    'type': 'dict',
                    'value': {
                        'type': 'str',
                        'choices': ['type-1', 'type-2']
                        }
                    }
                },
            'tag': {
                'type': 'dict',
                'value': {
                    'type': 'int',
                    }
                },
            'uuid': {
                'type': 'str',
                }
            },
        'set': {
            'type': 'dict',
            'ip': {
                'type': 'dict',
                'next_hop': {
                    'type': 'dict',
                    'address': {
                        'type': 'str',
                        }
                    }
                },
            'ddos': {
                'type': 'dict',
                'class_list_name': {
                    'type': 'str',
                    },
                'class_list_cid': {
                    'type': 'int',
                    },
                'zone': {
                    'type': 'str',
                    }
                },
            'ipv6': {
                'type': 'dict',
                'next_hop_1': {
                    'type': 'dict',
                    'address': {
                        'type': 'str',
                        },
                    'local': {
                        'type': 'dict',
                        'address': {
                            'type': 'str',
                            }
                        }
                    }
                },
            'level': {
                'type': 'dict',
                'value': {
                    'type': 'str',
                    'choices': ['level-1', 'level-1-2', 'level-2']
                    }
                },
            'metric': {
                'type': 'dict',
                'value': {
                    'type': 'str',
                    }
                },
            'metric_type': {
                'type': 'dict',
                'value': {
                    'type': 'str',
                    'choices': ['external', 'internal', 'type-1', 'type-2']
                    }
                },
            'tag': {
                'type': 'dict',
                'value': {
                    'type': 'int',
                    }
                },
            'aggregator': {
                'type': 'dict',
                'aggregator_as': {
                    'type': 'dict',
                    'asn': {
                        'type': 'int',
                        },
                    'ip': {
                        'type': 'str',
                        }
                    }
                },
            'as_path': {
                'type': 'dict',
                'prepend': {
                    'type': 'str',
                    },
                'num': {
                    'type': 'str',
                    },
                'num2': {
                    'type': 'str',
                    }
                },
            'atomic_aggregate': {
                'type': 'bool',
                },
            'comm_list': {
                'type': 'dict',
                'v_std': {
                    'type': 'int',
                    },
                'delete': {
                    'type': 'bool',
                    },
                'v_exp': {
                    'type': 'int',
                    },
                'v_exp_delete': {
                    'type': 'bool',
                    },
                'name': {
                    'type': 'str',
                    },
                'name_delete': {
                    'type': 'bool',
                    }
                },
            'community': {
                'type': 'str',
                },
            'dampening_cfg': {
                'type': 'dict',
                'dampening': {
                    'type': 'bool',
                    },
                'dampening_half_time': {
                    'type': 'int',
                    },
                'dampening_reuse': {
                    'type': 'int',
                    },
                'dampening_supress': {
                    'type': 'int',
                    },
                'dampening_max_supress': {
                    'type': 'int',
                    },
                'dampening_penalty': {
                    'type': 'int',
                    }
                },
            'extcommunity': {
                'type': 'dict',
                'rt': {
                    'type': 'dict',
                    'value': {
                        'type': 'str',
                        }
                    },
                'soo': {
                    'type': 'dict',
                    'value': {
                        'type': 'str',
                        }
                    }
                },
            'local_preference': {
                'type': 'dict',
                'val': {
                    'type': 'int',
                    }
                },
            'originator_id': {
                'type': 'dict',
                'originator_ip': {
                    'type': 'str',
                    }
                },
            'weight': {
                'type': 'dict',
                'weight_val': {
                    'type': 'int',
                    }
                },
            'origin': {
                'type': 'dict',
                'egp': {
                    'type': 'bool',
                    },
                'igp': {
                    'type': 'bool',
                    },
                'incomplete': {
                    'type': 'bool',
                    }
                },
            'uuid': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/route-map/{tag}+{action}+{sequence}"

    f_dict = {}
    if '/' in str(module.params["tag"]):
        f_dict["tag"] = module.params["tag"].replace("/", "%2F")
    else:
        f_dict["tag"] = module.params["tag"]
    if '/' in str(module.params["action"]):
        f_dict["action"] = module.params["action"].replace("/", "%2F")
    else:
        f_dict["action"] = module.params["action"]
    if '/' in str(module.params["sequence"]):
        f_dict["sequence"] = module.params["sequence"].replace("/", "%2F")
    else:
        f_dict["sequence"] = module.params["sequence"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/route-map/+"

    f_dict = {}
    f_dict["tag"] = ""
    f_dict["action"] = ""
    f_dict["sequence"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["route-map"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["route-map"].get(k) != v:
            change_results["changed"] = True
            config_changes["route-map"][k] = v

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
    payload = utils.build_json("route-map", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["route-map"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["route-map-list"] if info != "NotFound" else info
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
