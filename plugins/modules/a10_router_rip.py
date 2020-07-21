#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_router_rip
description:
    - Routing Information Protocol (RIP)
short_description: Configures A10 router.rip
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
    default_metric:
        description:
        - "Set a metric of redistribute routes (Default metric)"
        required: False
    route_cfg:
        description:
        - "Field route_cfg"
        required: False
        suboptions:
            route:
                description:
                - "Static route advertisement (debugging purpose) (IP prefix network/length)"
    cisco_metric_behavior:
        description:
        - "'enable'= Enables updating metric consistent with Cisco; 'disable'= Disables
          updating metric consistent with Cisco;  (Enable/Disable updating metric
          consistent with Cisco)"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    rip_maximum_prefix_cfg:
        description:
        - "Field rip_maximum_prefix_cfg"
        required: False
        suboptions:
            maximum_prefix:
                description:
                - "Set the maximum number of RIP routes"
            maximum_prefix_thres:
                description:
                - "Percentage of maximum routes to generate a warning (Default 75%)"
    offset_list:
        description:
        - "Field offset_list"
        required: False
        suboptions:
            acl_cfg:
                description:
                - "Field acl_cfg"
            uuid:
                description:
                - "uuid of the object"
    passive_interface_list:
        description:
        - "Field passive_interface_list"
        required: False
        suboptions:
            tunnel:
                description:
                - "Tunnel interface (Tunnel interface number)"
            ethernet:
                description:
                - "Ethernet interface (Port number)"
            trunk:
                description:
                - "Trunk interface (Trunk interface number)"
            ve:
                description:
                - "Virtual ethernet interface (Virtual ethernet interface number)"
            loopback:
                description:
                - "Loopback interface (Port number)"
    redistribute:
        description:
        - "Field redistribute"
        required: False
        suboptions:
            vip_list:
                description:
                - "Field vip_list"
            redist_list:
                description:
                - "Field redist_list"
            uuid:
                description:
                - "uuid of the object"
    neighbor:
        description:
        - "Field neighbor"
        required: False
        suboptions:
            value:
                description:
                - "Neighbor address"
    network_interface_list_cfg:
        description:
        - "Field network_interface_list_cfg"
        required: False
        suboptions:
            tunnel:
                description:
                - "Tunnel interface (Tunnel interface number)"
            ethernet:
                description:
                - "Ethernet interface (Port number)"
            trunk:
                description:
                - "Trunk interface (Trunk interface number)"
            ve:
                description:
                - "Virtual ethernet interface (Virtual ethernet interface number)"
            loopback:
                description:
                - "Loopback interface (Port number)"
    recv_buffer_size:
        description:
        - "Set the RIP UDP receive buffer size (the RIP UDP receive buffer size value)"
        required: False
    timers:
        description:
        - "Field timers"
        required: False
        suboptions:
            timers_cfg:
                description:
                - "Field timers_cfg"
    version:
        description:
        - "Set routing protocol version (RIP version)"
        required: False
    default_information:
        description:
        - "'originate'= originate;  (Distribute default route)"
        required: False
    distribute_list:
        description:
        - "Field distribute_list"
        required: False
        suboptions:
            acl_cfg:
                description:
                - "Field acl_cfg"
            prefix:
                description:
                - "Field prefix"
            uuid:
                description:
                - "uuid of the object"
    distance_list_cfg:
        description:
        - "Field distance_list_cfg"
        required: False
        suboptions:
            distance:
                description:
                - "Administrative distance (Distance value)"
            distance_ipv4_mask:
                description:
                - "IP source prefix"
            distance_acl:
                description:
                - "Access list name"
    network_addresses:
        description:
        - "Field network_addresses"
        required: False
        suboptions:
            network_ipv4_mask:
                description:
                - "IP prefix network/length, e.g., 35.0.0.0/8"


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
    "cisco_metric_behavior",
    "default_information",
    "default_metric",
    "distance_list_cfg",
    "distribute_list",
    "neighbor",
    "network_addresses",
    "network_interface_list_cfg",
    "offset_list",
    "passive_interface_list",
    "recv_buffer_size",
    "redistribute",
    "rip_maximum_prefix_cfg",
    "route_cfg",
    "timers",
    "uuid",
    "version",
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
        'default_metric': {
            'type': 'int',
        },
        'route_cfg': {
            'type': 'list',
            'route': {
                'type': 'str',
            }
        },
        'cisco_metric_behavior': {
            'type': 'str',
            'choices': ['enable', 'disable']
        },
        'uuid': {
            'type': 'str',
        },
        'rip_maximum_prefix_cfg': {
            'type': 'dict',
            'maximum_prefix': {
                'type': 'int',
            },
            'maximum_prefix_thres': {
                'type': 'int',
            }
        },
        'offset_list': {
            'type': 'dict',
            'acl_cfg': {
                'type': 'list',
                've': {
                    'type': 'str',
                },
                'loopback': {
                    'type': 'str',
                },
                'tunnel': {
                    'type': 'str',
                },
                'metric': {
                    'type': 'int',
                },
                'offset_list_direction': {
                    'type': 'str',
                    'choices': ['in', 'out']
                },
                'acl': {
                    'type': 'str',
                },
                'trunk': {
                    'type': 'str',
                },
                'ethernet': {
                    'type': 'str',
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'passive_interface_list': {
            'type': 'list',
            'tunnel': {
                'type': 'str',
            },
            'ethernet': {
                'type': 'str',
            },
            'trunk': {
                'type': 'str',
            },
            've': {
                'type': 'str',
            },
            'loopback': {
                'type': 'str',
            }
        },
        'redistribute': {
            'type': 'dict',
            'vip_list': {
                'type': 'list',
                'vip_metric': {
                    'type': 'int',
                },
                'vip_route_map': {
                    'type': 'str',
                },
                'vip_type': {
                    'type': 'str',
                    'choices': ['only-flagged', 'only-not-flagged']
                }
            },
            'redist_list': {
                'type': 'list',
                'metric': {
                    'type': 'int',
                },
                'route_map': {
                    'type': 'str',
                },
                'ntype': {
                    'type':
                    'str',
                    'choices': [
                        'bgp', 'connected', 'floating-ip', 'ip-nat-list',
                        'ip-nat', 'isis', 'lw4o6', 'nat-map', 'ospf', 'static'
                    ]
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'neighbor': {
            'type': 'list',
            'value': {
                'type': 'str',
            }
        },
        'network_interface_list_cfg': {
            'type': 'list',
            'tunnel': {
                'type': 'str',
            },
            'ethernet': {
                'type': 'str',
            },
            'trunk': {
                'type': 'str',
            },
            've': {
                'type': 'str',
            },
            'loopback': {
                'type': 'str',
            }
        },
        'recv_buffer_size': {
            'type': 'int',
        },
        'timers': {
            'type': 'dict',
            'timers_cfg': {
                'type': 'dict',
                'val_3': {
                    'type': 'int',
                },
                'val_2': {
                    'type': 'int',
                },
                'basic': {
                    'type': 'int',
                }
            }
        },
        'version': {
            'type': 'int',
        },
        'default_information': {
            'type': 'str',
            'choices': ['originate']
        },
        'distribute_list': {
            'type': 'dict',
            'acl_cfg': {
                'type': 'list',
                'acl_direction': {
                    'type': 'str',
                    'choices': ['in', 'out']
                },
                've': {
                    'type': 'str',
                },
                'loopback': {
                    'type': 'str',
                },
                'tunnel': {
                    'type': 'str',
                },
                'acl': {
                    'type': 'str',
                },
                'trunk': {
                    'type': 'str',
                },
                'ethernet': {
                    'type': 'str',
                }
            },
            'prefix': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                },
                'prefix_cfg': {
                    'type': 'list',
                    've': {
                        'type': 'str',
                    },
                    'loopback': {
                        'type': 'str',
                    },
                    'tunnel': {
                        'type': 'str',
                    },
                    'prefix_list': {
                        'type': 'str',
                    },
                    'trunk': {
                        'type': 'str',
                    },
                    'prefix_list_direction': {
                        'type': 'str',
                        'choices': ['in', 'out']
                    },
                    'ethernet': {
                        'type': 'str',
                    }
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'distance_list_cfg': {
            'type': 'list',
            'distance': {
                'type': 'int',
            },
            'distance_ipv4_mask': {
                'type': 'str',
            },
            'distance_acl': {
                'type': 'str',
            }
        },
        'network_addresses': {
            'type': 'list',
            'network_ipv4_mask': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/rip"

    f_dict = {}

    return url_base.format(**f_dict)


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


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
    url_base = "/axapi/v3/router/rip"

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
    if existing_config:
        for k, v in payload["rip"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["rip"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["rip"][k] = v
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
    payload = build_json("rip", module)
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
