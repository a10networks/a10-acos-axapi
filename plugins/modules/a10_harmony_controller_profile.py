#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_harmony_controller_profile
description:
    - Harmony controller profile
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
    host:
        description:
        - "Set harmony controller host adddress"
        type: str
        required: False
    use_mgmt_port:
        description:
        - "Use management port for connections"
        type: bool
        required: False
    port:
        description:
        - "Set port for remote Harmony Controller, default is 8443"
        type: int
        required: False
    provider:
        description:
        - "provider for the harmony-controller"
        type: str
        required: False
    user_name:
        description:
        - "user-name for the tenant"
        type: str
        required: False
    cluster_name:
        description:
        - "cluster name for the device"
        type: str
        required: False
    cluster_id:
        description:
        - "cluster id for the device"
        type: str
        required: False
    secret_value:
        description:
        - "Specify the password for the user"
        type: str
        required: False
    password_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED secret string)"
        type: str
        required: False
    region:
        description:
        - "region of the thunder-device"
        type: str
        required: False
    auto_restart_action:
        description:
        - "'enable'= enable auto analytics bus restart, default behavior is enable;
          'disable'= disable auto analytics bus restart;"
        type: str
        required: False
    interval:
        description:
        - "auto analytics bus restart time interval in mins, default is 3 mins"
        type: int
        required: False
    availability_zone:
        description:
        - "availablity zone of the thunder-device"
        type: str
        required: False
    action:
        description:
        - "'register'= Register the device to the controller; 'deregister'= Deregister the
          device from controller;"
        type: str
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    re_sync:
        description:
        - "Field re_sync"
        type: dict
        required: False
        suboptions:
            schema_registry:
                description:
                - "re-sync the schema registry"
                type: bool
            analytics_bus:
                description:
                - "re-sync analtyics bus connections"
                type: bool
    thunder_mgmt_ip:
        description:
        - "Field thunder_mgmt_ip"
        type: dict
        required: False
        suboptions:
            ip_address:
                description:
                - "IP address (IPv4 address)"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    tunnel:
        description:
        - "Field tunnel"
        type: dict
        required: False
        suboptions:
            action:
                description:
                - "'enable'= Tunnel Enable; 'disable'= Tunnel Disable;"
                type: str
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
            overall_status:
                description:
                - "Field overall_status"
                type: str
            heartbeat_status:
                description:
                - "Field heartbeat_status"
                type: str
            heartbeat_error_message:
                description:
                - "Field heartbeat_error_message"
                type: str
            service_registry:
                description:
                - "Field service_registry"
                type: str
            service_registry_error_message:
                description:
                - "Field service_registry_error_message"
                type: str
            registration_status:
                description:
                - "Field registration_status"
                type: str
            registration_status_code:
                description:
                - "Field registration_status_code"
                type: int
            registration_error_message:
                description:
                - "Field registration_error_message"
                type: str
            deregistration_status:
                description:
                - "Field deregistration_status"
                type: str
            deregistration_status_code:
                description:
                - "Field deregistration_status_code"
                type: int
            deregistration_error_message:
                description:
                - "Field deregistration_error_message"
                type: str
            schema_registry_status:
                description:
                - "Field schema_registry_status"
                type: str
            broker_info:
                description:
                - "Field broker_info"
                type: str
            kafka_broker_state:
                description:
                - "Field kafka_broker_state"
                type: str
            Number_of_tenant_mapped_partitions:
                description:
                - "Field Number_of_tenant_mapped_partitions"
                type: int
            Number_of_tenant_unmapped_partitions:
                description:
                - "Field Number_of_tenant_unmapped_partitions"
                type: int
            tunnel_status:
                description:
                - "Field tunnel_status"
                type: str
            tunnel_error_message:
                description:
                - "Field tunnel_error_message"
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

# standard ansible module imports
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
AVAILABLE_PROPERTIES = ["action", "auto_restart_action", "availability_zone", "cluster_id", "cluster_name", "host", "interval", "oper", "password_encrypted", "port", "provider", "re_sync", "region", "secret_value", "thunder_mgmt_ip", "tunnel", "use_mgmt_port", "user_name", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({'host': {'type': 'str', },
        'use_mgmt_port': {'type': 'bool', },
        'port': {'type': 'int', },
        'provider': {'type': 'str', },
        'user_name': {'type': 'str', },
        'cluster_name': {'type': 'str', },
        'cluster_id': {'type': 'str', },
        'secret_value': {'type': 'str', },
        'password_encrypted': {'type': 'str', },
        'region': {'type': 'str', },
        'auto_restart_action': {'type': 'str', 'choices': ['enable', 'disable']},
        'interval': {'type': 'int', },
        'availability_zone': {'type': 'str', },
        'action': {'type': 'str', 'choices': ['register', 'deregister']},
        'uuid': {'type': 'str', },
        're_sync': {'type': 'dict', 'schema_registry': {'type': 'bool', }, 'analytics_bus': {'type': 'bool', }},
        'thunder_mgmt_ip': {'type': 'dict', 'ip_address': {'type': 'str', }, 'uuid': {'type': 'str', }},
        'tunnel': {'type': 'dict', 'action': {'type': 'str', 'choices': ['enable', 'disable']}, 'uuid': {'type': 'str', }},
        'oper': {'type': 'dict', 'overall_status': {'type': 'str', }, 'heartbeat_status': {'type': 'str', }, 'heartbeat_error_message': {'type': 'str', }, 'service_registry': {'type': 'str', }, 'service_registry_error_message': {'type': 'str', }, 'registration_status': {'type': 'str', }, 'registration_status_code': {'type': 'int', }, 'registration_error_message': {'type': 'str', }, 'deregistration_status': {'type': 'str', }, 'deregistration_status_code': {'type': 'int', }, 'deregistration_error_message': {'type': 'str', }, 'schema_registry_status': {'type': 'str', }, 'broker_info': {'type': 'str', }, 'kafka_broker_state': {'type': 'str', 'choices': ['Up', 'Down']}, 'Number_of_tenant_mapped_partitions': {'type': 'int', }, 'Number_of_tenant_unmapped_partitions': {'type': 'int', }, 'tunnel_status': {'type': 'str', }, 'tunnel_error_message': {'type': 'str', }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/harmony-controller/profile"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/harmony-controller/profile"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["profile"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["profile"].get(k) != v:
            change_results["changed"] = True
            config_changes["profile"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(
        **call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(
            **call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("profile", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(
        changed=False,
        messages="",
        modified_values={},
        axapi_calls=[]
    )

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

    module.client = client_factory(ansible_host, ansible_port,
                                   protocol, ansible_username,
                                   ansible_password)

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
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
             result["axapi_calls"].append(
                api_client.switch_device_context(module.client, a10_device_context_id))

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
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.session.session_id:
            module.client.session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
