#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_gslb_service_ip_port
description:
    - Server Port
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
    service_ip_node_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    port_num:
        description:
        - "Port Number"
        type: int
        required: True
    port_proto:
        description:
        - "'tcp'= TCP Port; 'udp'= UDP Port;"
        type: str
        required: True
    action:
        description:
        - "'enable'= Enable this GSLB server port; 'disable'= Disable this GSLB server
          port;"
        type: str
        required: False
    health_check:
        description:
        - "Health Check Monitor (Monitor Name)"
        type: str
        required: False
    health_check_follow_port:
        description:
        - "Specify which port to follow for health status (Port Number)"
        type: int
        required: False
    follow_port_protocol:
        description:
        - "'tcp'= TCP Port; 'udp'= UDP Port;"
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
                - "'all'= all; 'active'= Active Servers; 'current'= Current Connections;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            service_port:
                description:
                - "Field service_port"
                type: int
            state:
                description:
                - "Field state"
                type: str
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
            tcp:
                description:
                - "Field tcp"
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
            port_num:
                description:
                - "Port Number"
                type: int
            port_proto:
                description:
                - "'tcp'= TCP Port; 'udp'= UDP Port;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            active:
                description:
                - "Active Servers"
                type: str
            current:
                description:
                - "Current Connections"
                type: str
            port_num:
                description:
                - "Port Number"
                type: int
            port_proto:
                description:
                - "'tcp'= TCP Port; 'udp'= UDP Port;"
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
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "action",
    "follow_port_protocol",
    "health_check",
    "health_check_disable",
    "health_check_follow_port",
    "health_check_protocol_disable",
    "oper",
    "port_num",
    "port_proto",
    "sampling_enable",
    "stats",
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
            },
            'port_num': {
                'type': 'int',
                'required': True,
            },
            'port_proto': {
                'type': 'str',
                'required': True,
                'choices': ['tcp', 'udp']
            }
        },
        'stats': {
            'type': 'dict',
            'active': {
                'type': 'str',
            },
            'current': {
                'type': 'str',
            },
            'port_num': {
                'type': 'int',
                'required': True,
            },
            'port_proto': {
                'type': 'str',
                'required': True,
                'choices': ['tcp', 'udp']
            }
        }
    })
    # Parent keys
    rv.update(dict(service_ip_node_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/service-ip/{service_ip_node_name}/port/{port-num}+{port-proto}"

    f_dict = {}
    f_dict["port-num"] = module.params["port_num"]
    f_dict["port-proto"] = module.params["port_proto"]
    f_dict["service_ip_node_name"] = module.params["service_ip_node_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/service-ip/{service_ip_node_name}/port/{port-num}+{port-proto}"

    f_dict = {}
    f_dict["port-num"] = ""
    f_dict["port-proto"] = ""
    f_dict["service_ip_node_name"] = module.params["service_ip_node_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["port"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["port"].get(k) != v:
            change_results["changed"] = True
            config_changes["port"][k] = v

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
    payload = utils.build_json("port", module.params, AVAILABLE_PROPERTIES)
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

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params,
                                                  requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(
                api_client.switch_device_context(module.client,
                                                 a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
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
                result["axapi_calls"].append(
                    api_client.get(module.client, existing_url(module)))
            elif module.params.get("get_type") == "list":
                result["axapi_calls"].append(
                    api_client.get_list(module.client, existing_url(module)))
            elif module.params.get("get_type") == "oper":
                result["axapi_calls"].append(
                    api_client.get_oper(module.client, existing_url(module)))
            elif module.params.get("get_type") == "stats":
                result["axapi_calls"].append(
                    api_client.get_stats(module.client, existing_url(module)))
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.session.session_id:
            module.client.session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
