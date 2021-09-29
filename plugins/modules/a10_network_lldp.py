#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_network_lldp
description:
    - Configure LLDP
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
    system_name:
        description:
        - "Configure lldp system name"
        type: str
        required: False
    system_description:
        description:
        - "Configure lldp system description"
        type: str
        required: False
    enable_cfg:
        description:
        - "Field enable_cfg"
        type: dict
        required: False
        suboptions:
            enable:
                description:
                - "Enable lldp"
                type: bool
            rx:
                description:
                - "Enable lldp rx"
                type: bool
            tx:
                description:
                - "Enable lldp tx"
                type: bool
    notification_cfg:
        description:
        - "Field notification_cfg"
        type: dict
        required: False
        suboptions:
            notification:
                description:
                - "Enable lldp notification"
                type: bool
            interval:
                description:
                - "Configure lldp notification interval, default is 30 (The lldp notification
          interval value, default is 30)"
                type: int
    tx_set:
        description:
        - "Field tx_set"
        type: dict
        required: False
        suboptions:
            fast_count:
                description:
                - "Configure lldp tx fast count value (The lldp tx fast count value, default is 4)"
                type: int
            fast_interval:
                description:
                - "Configure lldp tx fast interval value (The lldp tx fast interval value, default
          is 1)"
                type: int
            hold:
                description:
                - "Configure lldp tx hold multiplier (The lldp tx hold value, default is 4)"
                type: int
            tx_interval:
                description:
                - "Configure lldp tx interval (The lldp tx interval value, default is 30)"
                type: int
            reinit_delay:
                description:
                - "Configure lldp tx reinit delay (The lldp tx reinit_delay value, default is 2)"
                type: int
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    management_address:
        description:
        - "Field management_address"
        type: dict
        required: False
        suboptions:
            dns_list:
                description:
                - "Field dns_list"
                type: list
            ipv4_addr_list:
                description:
                - "Field ipv4_addr_list"
                type: list
            ipv6_addr_list:
                description:
                - "Field ipv6_addr_list"
                type: list

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
AVAILABLE_PROPERTIES = [
    "enable_cfg",
    "management_address",
    "notification_cfg",
    "system_description",
    "system_name",
    "tx_set",
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
        'system_name': {
            'type': 'str',
        },
        'system_description': {
            'type': 'str',
        },
        'enable_cfg': {
            'type': 'dict',
            'enable': {
                'type': 'bool',
            },
            'rx': {
                'type': 'bool',
            },
            'tx': {
                'type': 'bool',
            }
        },
        'notification_cfg': {
            'type': 'dict',
            'notification': {
                'type': 'bool',
            },
            'interval': {
                'type': 'int',
            }
        },
        'tx_set': {
            'type': 'dict',
            'fast_count': {
                'type': 'int',
            },
            'fast_interval': {
                'type': 'int',
            },
            'hold': {
                'type': 'int',
            },
            'tx_interval': {
                'type': 'int',
            },
            'reinit_delay': {
                'type': 'int',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'management_address': {
            'type': 'dict',
            'dns_list': {
                'type': 'list',
                'dns': {
                    'type': 'str',
                    'required': True,
                },
                'interface': {
                    'type': 'dict',
                    'ethernet': {
                        'type': 'str',
                    },
                    've': {
                        'type': 'int',
                    },
                    'management': {
                        'type': 'bool',
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'ipv4_addr_list': {
                'type': 'list',
                'ipv4': {
                    'type': 'str',
                    'required': True,
                },
                'interface_ipv4': {
                    'type': 'dict',
                    'ipv4_eth': {
                        'type': 'str',
                    },
                    'ipv4_ve': {
                        'type': 'int',
                    },
                    'ipv4_mgmt': {
                        'type': 'bool',
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'ipv6_addr_list': {
                'type': 'list',
                'ipv6': {
                    'type': 'str',
                    'required': True,
                },
                'interface_ipv6': {
                    'type': 'dict',
                    'ipv6_eth': {
                        'type': 'str',
                    },
                    'ipv6_ve': {
                        'type': 'int',
                    },
                    'ipv6_mgmt': {
                        'type': 'bool',
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/network/lldp"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/network/lldp"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["lldp"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["lldp"].get(k) != v:
            change_results["changed"] = True
            config_changes["lldp"][k] = v

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
    payload = utils.build_json("lldp", module.params, AVAILABLE_PROPERTIES)
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
    except a10_ex.ACOSException as ex:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()
        raise gex
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
