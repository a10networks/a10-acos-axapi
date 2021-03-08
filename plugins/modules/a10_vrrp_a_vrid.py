#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_vrrp_a_vrid
description:
    - Specify VRRP-A vrid
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
    vrid_val:
        description:
        - "Specify ha VRRP-A vrid"
        type: int
        required: True
    floating_ip:
        description:
        - "Field floating_ip"
        type: dict
        required: False
        suboptions:
            ip_address_cfg:
                description:
                - "Field ip_address_cfg"
                type: list
            ip_address_part_cfg:
                description:
                - "Field ip_address_part_cfg"
                type: list
            ipv6_address_cfg:
                description:
                - "Field ipv6_address_cfg"
                type: list
            ipv6_address_part_cfg:
                description:
                - "Field ipv6_address_part_cfg"
                type: list
    preempt_mode:
        description:
        - "Field preempt_mode"
        type: dict
        required: False
        suboptions:
            threshold:
                description:
                - "preemption threshold (preemption threshhold (0-255), default 0)"
                type: int
            disable:
                description:
                - "disable preemption"
                type: bool
    follow:
        description:
        - "Field follow"
        type: dict
        required: False
        suboptions:
            vrid_lead:
                description:
                - "Define a VRRP-A VRID leader"
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'associated_vip_count'= Number of vips associated to vrid;
          'associated_vport_count'= Number of vports associated to vrid;
          'associated_natpool_count'= Number of nat pools associated to vrid;"
                type: str
    blade_parameters:
        description:
        - "Field blade_parameters"
        type: dict
        required: False
        suboptions:
            priority:
                description:
                - "VRRP-A priorty (Priority, default is 150)"
                type: int
            fail_over_policy_template:
                description:
                - "Apply a fail over policy template (VRRP-A fail over policy template name)"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            tracking_options:
                description:
                - "Field tracking_options"
                type: dict
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            unit:
                description:
                - "Field unit"
                type: int
            state:
                description:
                - "Field state"
                type: str
            weight:
                description:
                - "Field weight"
                type: int
            priority:
                description:
                - "Field priority"
                type: int
            force_standby:
                description:
                - "Field force_standby"
                type: int
            became_active:
                description:
                - "Field became_active"
                type: str
            peer_list:
                description:
                - "Field peer_list"
                type: list
            vrid_val:
                description:
                - "Specify ha VRRP-A vrid"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            associated_vip_count:
                description:
                - "Number of vips associated to vrid"
                type: str
            associated_vport_count:
                description:
                - "Number of vports associated to vrid"
                type: str
            associated_natpool_count:
                description:
                - "Number of nat pools associated to vrid"
                type: str
            vrid_val:
                description:
                - "Specify ha VRRP-A vrid"
                type: int

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
    "blade_parameters",
    "floating_ip",
    "follow",
    "oper",
    "preempt_mode",
    "sampling_enable",
    "stats",
    "user_tag",
    "uuid",
    "vrid_val",
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
        'vrid_val': {
            'type': 'int',
            'required': True,
        },
        'floating_ip': {
            'type': 'dict',
            'ip_address_cfg': {
                'type': 'list',
                'ip_address': {
                    'type': 'str',
                }
            },
            'ip_address_part_cfg': {
                'type': 'list',
                'ip_address_partition': {
                    'type': 'str',
                }
            },
            'ipv6_address_cfg': {
                'type': 'list',
                'ipv6_address': {
                    'type': 'str',
                },
                'ethernet': {
                    'type': 'str',
                },
                'trunk': {
                    'type': 'int',
                },
                've': {
                    'type': 'int',
                }
            },
            'ipv6_address_part_cfg': {
                'type': 'list',
                'ipv6_address_partition': {
                    'type': 'str',
                },
                'ethernet': {
                    'type': 'str',
                },
                'trunk': {
                    'type': 'int',
                },
                've': {
                    'type': 'int',
                }
            }
        },
        'preempt_mode': {
            'type': 'dict',
            'threshold': {
                'type': 'int',
            },
            'disable': {
                'type': 'bool',
            }
        },
        'follow': {
            'type': 'dict',
            'vrid_lead': {
                'type': 'str',
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
                    'all', 'associated_vip_count', 'associated_vport_count',
                    'associated_natpool_count'
                ]
            }
        },
        'blade_parameters': {
            'type': 'dict',
            'priority': {
                'type': 'int',
            },
            'fail_over_policy_template': {
                'type': 'str',
            },
            'uuid': {
                'type': 'str',
            },
            'tracking_options': {
                'type': 'dict',
                'interface': {
                    'type': 'list',
                    'ethernet': {
                        'type': 'str',
                    },
                    'priority_cost': {
                        'type': 'int',
                    }
                },
                'route': {
                    'type': 'dict',
                    'ip_destination_cfg': {
                        'type': 'list',
                        'ip_destination': {
                            'type': 'str',
                        },
                        'mask': {
                            'type': 'str',
                        },
                        'priority_cost': {
                            'type': 'int',
                        },
                        'gateway': {
                            'type': 'str',
                        },
                        'distance': {
                            'type': 'int',
                        },
                        'protocol': {
                            'type': 'str',
                            'choices': ['any', 'static', 'dynamic']
                        }
                    },
                    'ipv6_destination_cfg': {
                        'type': 'list',
                        'ipv6_destination': {
                            'type': 'str',
                        },
                        'priority_cost': {
                            'type': 'int',
                        },
                        'gatewayv6': {
                            'type': 'str',
                        },
                        'distance': {
                            'type': 'int',
                        },
                        'protocol': {
                            'type': 'str',
                            'choices': ['any', 'static', 'dynamic']
                        }
                    }
                },
                'trunk_cfg': {
                    'type': 'list',
                    'trunk': {
                        'type': 'int',
                    },
                    'priority_cost': {
                        'type': 'int',
                    },
                    'per_port_pri': {
                        'type': 'int',
                    }
                },
                'bgp': {
                    'type': 'dict',
                    'bgp_ipv4_address_cfg': {
                        'type': 'list',
                        'bgp_ipv4_address': {
                            'type': 'str',
                        },
                        'priority_cost': {
                            'type': 'int',
                        }
                    },
                    'bgp_ipv6_address_cfg': {
                        'type': 'list',
                        'bgp_ipv6_address': {
                            'type': 'str',
                        },
                        'priority_cost': {
                            'type': 'int',
                        }
                    }
                },
                'vlan_cfg': {
                    'type': 'list',
                    'vlan': {
                        'type': 'int',
                    },
                    'timeout': {
                        'type': 'int',
                    },
                    'priority_cost': {
                        'type': 'int',
                    }
                },
                'uuid': {
                    'type': 'str',
                },
                'gateway': {
                    'type': 'dict',
                    'ipv4_gateway_list': {
                        'type': 'list',
                        'ip_address': {
                            'type': 'str',
                            'required': True,
                        },
                        'priority_cost': {
                            'type': 'int',
                        },
                        'uuid': {
                            'type': 'str',
                        }
                    },
                    'ipv6_gateway_list': {
                        'type': 'list',
                        'ipv6_address': {
                            'type': 'str',
                            'required': True,
                        },
                        'priority_cost': {
                            'type': 'int',
                        },
                        'uuid': {
                            'type': 'str',
                        }
                    }
                }
            }
        },
        'oper': {
            'type': 'dict',
            'unit': {
                'type': 'int',
            },
            'state': {
                'type': 'str',
                'choices': ['Active', 'Standby']
            },
            'weight': {
                'type': 'int',
            },
            'priority': {
                'type': 'int',
            },
            'force_standby': {
                'type': 'int',
            },
            'became_active': {
                'type': 'str',
            },
            'peer_list': {
                'type': 'list',
                'peer_unit': {
                    'type': 'int',
                },
                'peer_state': {
                    'type': 'str',
                    'choices': ['Active', 'Standby']
                },
                'peer_weight': {
                    'type': 'int',
                },
                'peer_priority': {
                    'type': 'int',
                }
            },
            'vrid_val': {
                'type': 'int',
                'required': True,
            }
        },
        'stats': {
            'type': 'dict',
            'associated_vip_count': {
                'type': 'str',
            },
            'associated_vport_count': {
                'type': 'str',
            },
            'associated_natpool_count': {
                'type': 'str',
            },
            'vrid_val': {
                'type': 'int',
                'required': True,
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vrrp-a/vrid/{vrid-val}"

    f_dict = {}
    f_dict["vrid-val"] = module.params["vrid_val"]

    return url_base.format(**f_dict)


def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"


def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"


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


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
    return module.client.get(stats_url(module))


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
    url_base = "/axapi/v3/vrrp-a/vrid/{vrid-val}"

    f_dict = {}
    f_dict["vrid-val"] = ""

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
        for k, v in payload["vrid"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["vrid"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["vrid"][k] = v
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
    payload = build_json("vrid", module)
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
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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
