#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_route_map_match
description:
    - Match values from routing table
short_description: Configures A10 route.map.match
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
    sequence:
        description:
        - Key to identify parent object    action:
        description:
        - Key to identify parent object    route_map_tag:
        description:
        - Key to identify parent object    extcommunity:
        description:
        - "Field extcommunity"
        required: False
        suboptions:
            extcommunity_l_name:
                description:
                - "Field extcommunity_l_name"
    origin:
        description:
        - "Field origin"
        required: False
        suboptions:
            egp:
                description:
                - "remote EGP"
            incomplete:
                description:
                - "unknown heritage"
            igp:
                description:
                - "local IGP"
    group:
        description:
        - "Field group"
        required: False
        suboptions:
            group_id:
                description:
                - "HA or VRRP-A group id"
            ha_state:
                description:
                - "'active'= HA or VRRP-A in Active State; 'standby'= HA or VRRP-A in Standby
          State;"
    uuid:
        description:
        - "uuid of the object"
        required: False
    ip:
        description:
        - "Field ip"
        required: False
        suboptions:
            peer:
                description:
                - "Field peer"
            next_hop:
                description:
                - "Field next_hop"
            address:
                description:
                - "Field address"
    metric:
        description:
        - "Field metric"
        required: False
        suboptions:
            value:
                description:
                - "Metric value"
    as_path:
        description:
        - "Field as_path"
        required: False
        suboptions:
            name:
                description:
                - "AS path access-list name"
    community:
        description:
        - "Field community"
        required: False
        suboptions:
            name_cfg:
                description:
                - "Field name_cfg"
    local_preference:
        description:
        - "Field local_preference"
        required: False
        suboptions:
            val:
                description:
                - "Preference value"
    route_type:
        description:
        - "Field route_type"
        required: False
        suboptions:
            external:
                description:
                - "Field external"
    tag:
        description:
        - "Field tag"
        required: False
        suboptions:
            value:
                description:
                - "Tag value"
    ipv6:
        description:
        - "Field ipv6"
        required: False
        suboptions:
            next_hop_1:
                description:
                - "Field next_hop_1"
            peer_1:
                description:
                - "Field peer_1"
            address_1:
                description:
                - "Field address_1"
    interface:
        description:
        - "Field interface"
        required: False
        suboptions:
            tunnel:
                description:
                - "Tunnel interface (Tunnel interface number)"
            ethernet:
                description:
                - "Ethernet interface (Port number)"
            loopback:
                description:
                - "Loopback interface (Port number)"
            ve:
                description:
                - "Virtual ethernet interface (Virtual ethernet interface number)"
            trunk:
                description:
                - "Trunk Interface (Trunk interface number)"
    scaleout:
        description:
        - "Field scaleout"
        required: False
        suboptions:
            cluster_id:
                description:
                - "Scaleout Cluster-id"
            operational_state:
                description:
                - "'up'= Scaleout is up and running; 'down'= Scaleout is down or disabled;"

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
    "as_path",
    "community",
    "extcommunity",
    "group",
    "interface",
    "ip",
    "ipv6",
    "local_preference",
    "metric",
    "origin",
    "route_type",
    "scaleout",
    "tag",
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
        'extcommunity': {
            'type': 'dict',
            'extcommunity_l_name': {
                'type': 'dict',
                'exact_match': {
                    'type': 'bool',
                },
                'name': {
                    'type': 'str',
                }
            }
        },
        'origin': {
            'type': 'dict',
            'egp': {
                'type': 'bool',
            },
            'incomplete': {
                'type': 'bool',
            },
            'igp': {
                'type': 'bool',
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
        'uuid': {
            'type': 'str',
        },
        'ip': {
            'type': 'dict',
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
            'address': {
                'type': 'dict',
                'acl1': {
                    'type': 'int',
                },
                'acl2': {
                    'type': 'int',
                },
                'prefix_list': {
                    'type': 'dict',
                    'name': {
                        'type': 'str',
                    }
                },
                'name': {
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
                'exact_match': {
                    'type': 'bool',
                },
                'name': {
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
        'ipv6': {
            'type': 'dict',
            'next_hop_1': {
                'type': 'dict',
                'prefix_list_name': {
                    'type': 'str',
                },
                'v6_addr': {
                    'type': 'str',
                },
                'next_hop_acl_name': {
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
            }
        },
        'interface': {
            'type': 'dict',
            'tunnel': {
                'type': 'str',
            },
            'ethernet': {
                'type': 'str',
            },
            'loopback': {
                'type': 'int',
            },
            've': {
                'type': 'int',
            },
            'trunk': {
                'type': 'int',
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
        }
    })
    # Parent keys
    rv.update(
        dict(
            sequence=dict(type='str', required=True),
            action=dict(type='str', required=True),
            route_map_tag=dict(type='str', required=True),
        ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/route-map/{route_map_tag}+{action}+{sequence}/match"

    f_dict = {}
    f_dict["sequence"] = module.params["sequence"]
    f_dict["action"] = module.params["action"]
    f_dict["route_map_tag"] = module.params["route_map_tag"]

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
    url_base = "/axapi/v3/route-map/{route_map_tag}+{action}+{sequence}/match"

    f_dict = {}
    f_dict["sequence"] = module.params["sequence"]
    f_dict["action"] = module.params["action"]
    f_dict["route_map_tag"] = module.params["route_map_tag"]

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
        for k, v in payload["match"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["match"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["match"][k] = v
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
    payload = build_json("match", module)
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
