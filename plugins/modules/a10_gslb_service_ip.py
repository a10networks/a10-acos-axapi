#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_gslb_service_ip
description:
    - Service IP
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
    node_name:
        description:
        - "Service-IP Name"
        type: str
        required: True
    ipv6_address:
        description:
        - "IPV6 address"
        type: str
        required: False
    ip_address:
        description:
        - "IP address"
        type: str
        required: False
    action:
        description:
        - "'enable'= Enable this GSLB server; 'disable'= Disable this GSLB server;"
        type: str
        required: False
    external_ip:
        description:
        - "External IP address for NAT"
        type: str
        required: False
    ipv6:
        description:
        - "IPv6 address Mapping (Applicable only when service-ip has an IPv4 Address)"
        type: str
        required: False
    health_check:
        description:
        - "Health Check Monitor (Monitor Name)"
        type: str
        required: False
    health_check_protocol_disable:
        description:
        - "Disable GSLB Protocol Health Monitor"
        type: bool
        required: False
    health_check_disable:
        description:
        - "Disable Health Check Monitor"
        type: bool
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'hits'= Number of times the service IP has been selected; 'recent'=
          Recent hits;"
                type: str
    port_list:
        description:
        - "Field port_list"
        type: list
        required: False
        suboptions:
            port_num:
                description:
                - "Port Number"
                type: int
            port_proto:
                description:
                - "'tcp'= TCP Port; 'udp'= UDP Port;"
                type: str
            action:
                description:
                - "'enable'= Enable this GSLB server port; 'disable'= Disable this GSLB server
          port;"
                type: str
            health_check:
                description:
                - "Health Check Monitor (Monitor Name)"
                type: str
            health_check_follow_port:
                description:
                - "Specify which port to follow for health status (Port Number)"
                type: int
            follow_port_protocol:
                description:
                - "'tcp'= TCP Port; 'udp'= UDP Port;"
                type: str
            health_check_protocol_disable:
                description:
                - "Disable GSLB Protocol Health Monitor"
                type: bool
            health_check_disable:
                description:
                - "Disable Health Check Monitor"
                type: bool
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
            service_ip:
                description:
                - "Field service_ip"
                type: str
            ip:
                description:
                - "Field ip"
                type: str
            state:
                description:
                - "Field state"
                type: str
            port_count:
                description:
                - "Field port_count"
                type: int
            virtual_server:
                description:
                - "Field virtual_server"
                type: int
            disabled:
                description:
                - "Field disabled"
                type: int
            gslb_protocol:
                description:
                - "Field gslb_protocol"
                type: int
            local_protocol:
                description:
                - "Field local_protocol"
                type: int
            manually_health_check:
                description:
                - "Field manually_health_check"
                type: int
            use_gslb_state:
                description:
                - "Field use_gslb_state"
                type: int
            dynamic:
                description:
                - "Field dynamic"
                type: int
            node_name:
                description:
                - "Service-IP Name"
                type: str
            port_list:
                description:
                - "Field port_list"
                type: list
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            hits:
                description:
                - "Number of times the service IP has been selected"
                type: str
            recent:
                description:
                - "Recent hits"
                type: str
            node_name:
                description:
                - "Service-IP Name"
                type: str
            port_list:
                description:
                - "Field port_list"
                type: list

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
    "action",
    "external_ip",
    "health_check",
    "health_check_disable",
    "health_check_protocol_disable",
    "ip_address",
    "ipv6",
    "ipv6_address",
    "node_name",
    "oper",
    "port_list",
    "sampling_enable",
    "stats",
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
        'node_name': {
            'type': 'str',
            'required': True,
        },
        'ipv6_address': {
            'type': 'str',
        },
        'ip_address': {
            'type': 'str',
        },
        'action': {
            'type': 'str',
            'choices': ['enable', 'disable']
        },
        'external_ip': {
            'type': 'str',
        },
        'ipv6': {
            'type': 'str',
        },
        'health_check': {
            'type': 'str',
        },
        'health_check_protocol_disable': {
            'type': 'bool',
        },
        'health_check_disable': {
            'type': 'bool',
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
                'type': 'str',
                'choices': ['all', 'hits', 'recent']
            }
        },
        'port_list': {
            'type': 'list',
            'port_num': {
                'type': 'int',
                'required': True,
            },
            'port_proto': {
                'type': 'str',
                'required': True,
                'choices': ['tcp', 'udp']
            },
            'action': {
                'type': 'str',
                'choices': ['enable', 'disable']
            },
            'health_check': {
                'type': 'str',
            },
            'health_check_follow_port': {
                'type': 'int',
            },
            'follow_port_protocol': {
                'type': 'str',
                'choices': ['tcp', 'udp']
            },
            'health_check_protocol_disable': {
                'type': 'bool',
            },
            'health_check_disable': {
                'type': 'bool',
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
                    'type': 'str',
                    'choices': ['all', 'active', 'current']
                }
            }
        },
        'oper': {
            'type': 'dict',
            'service_ip': {
                'type': 'str',
            },
            'ip': {
                'type': 'str',
            },
            'state': {
                'type': 'str',
            },
            'port_count': {
                'type': 'int',
            },
            'virtual_server': {
                'type': 'int',
            },
            'disabled': {
                'type': 'int',
            },
            'gslb_protocol': {
                'type': 'int',
            },
            'local_protocol': {
                'type': 'int',
            },
            'manually_health_check': {
                'type': 'int',
            },
            'use_gslb_state': {
                'type': 'int',
            },
            'dynamic': {
                'type': 'int',
            },
            'node_name': {
                'type': 'str',
                'required': True,
            },
            'port_list': {
                'type': 'list',
                'port_num': {
                    'type': 'int',
                    'required': True,
                },
                'port_proto': {
                    'type': 'str',
                    'required': True,
                    'choices': ['tcp', 'udp']
                },
                'oper': {
                    'type': 'dict',
                    'service_port': {
                        'type': 'int',
                    },
                    'state': {
                        'type': 'str',
                    },
                    'disabled': {
                        'type': 'int',
                    },
                    'gslb_protocol': {
                        'type': 'int',
                    },
                    'local_protocol': {
                        'type': 'int',
                    },
                    'tcp': {
                        'type': 'int',
                    },
                    'manually_health_check': {
                        'type': 'int',
                    },
                    'use_gslb_state': {
                        'type': 'int',
                    },
                    'dynamic': {
                        'type': 'int',
                    }
                }
            }
        },
        'stats': {
            'type': 'dict',
            'hits': {
                'type': 'str',
            },
            'recent': {
                'type': 'str',
            },
            'node_name': {
                'type': 'str',
                'required': True,
            },
            'port_list': {
                'type': 'list',
                'port_num': {
                    'type': 'int',
                    'required': True,
                },
                'port_proto': {
                    'type': 'str',
                    'required': True,
                    'choices': ['tcp', 'udp']
                },
                'stats': {
                    'type': 'dict',
                    'active': {
                        'type': 'str',
                    },
                    'current': {
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
    url_base = "/axapi/v3/gslb/service-ip/{node-name}"

    f_dict = {}
    f_dict["node-name"] = module.params["node_name"]

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
    url_base = "/axapi/v3/gslb/service-ip/{node-name}"

    f_dict = {}
    f_dict["node-name"] = ""

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
        for k, v in payload["service-ip"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["service-ip"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["service-ip"][k] = v
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
    payload = build_json("service-ip", module)
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
