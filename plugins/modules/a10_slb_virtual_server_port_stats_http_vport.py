#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_virtual_server_port_stats_http_vport
description:
    - Statistics for the object port
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
    protocol:
        description:
        - Key to identify parent object
        type: str
        required: True
    port_number:
        description:
        - Key to identify parent object
        type: str
        required: True
    virtual_server_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            http_vport:
                description:
                - "Field http_vport"
                type: dict

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
    "stats",
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
        'stats': {
            'type': 'dict',
            'http_vport': {
                'type': 'dict',
                'status_200': {
                    'type': 'str',
                },
                'status_201': {
                    'type': 'str',
                },
                'status_202': {
                    'type': 'str',
                },
                'status_203': {
                    'type': 'str',
                },
                'status_204': {
                    'type': 'str',
                },
                'status_205': {
                    'type': 'str',
                },
                'status_206': {
                    'type': 'str',
                },
                'status_207': {
                    'type': 'str',
                },
                'status_100': {
                    'type': 'str',
                },
                'status_101': {
                    'type': 'str',
                },
                'status_102': {
                    'type': 'str',
                },
                'status_103': {
                    'type': 'str',
                },
                'status_300': {
                    'type': 'str',
                },
                'status_301': {
                    'type': 'str',
                },
                'status_302': {
                    'type': 'str',
                },
                'status_303': {
                    'type': 'str',
                },
                'status_304': {
                    'type': 'str',
                },
                'status_305': {
                    'type': 'str',
                },
                'status_306': {
                    'type': 'str',
                },
                'status_307': {
                    'type': 'str',
                },
                'status_400': {
                    'type': 'str',
                },
                'status_401': {
                    'type': 'str',
                },
                'status_402': {
                    'type': 'str',
                },
                'status_403': {
                    'type': 'str',
                },
                'status_404': {
                    'type': 'str',
                },
                'status_405': {
                    'type': 'str',
                },
                'status_406': {
                    'type': 'str',
                },
                'status_407': {
                    'type': 'str',
                },
                'status_408': {
                    'type': 'str',
                },
                'status_409': {
                    'type': 'str',
                },
                'status_410': {
                    'type': 'str',
                },
                'status_411': {
                    'type': 'str',
                },
                'status_412': {
                    'type': 'str',
                },
                'status_413': {
                    'type': 'str',
                },
                'status_414': {
                    'type': 'str',
                },
                'status_415': {
                    'type': 'str',
                },
                'status_416': {
                    'type': 'str',
                },
                'status_417': {
                    'type': 'str',
                },
                'status_418': {
                    'type': 'str',
                },
                'status_422': {
                    'type': 'str',
                },
                'status_423': {
                    'type': 'str',
                },
                'status_424': {
                    'type': 'str',
                },
                'status_425': {
                    'type': 'str',
                },
                'status_426': {
                    'type': 'str',
                },
                'status_449': {
                    'type': 'str',
                },
                'status_450': {
                    'type': 'str',
                },
                'status_500': {
                    'type': 'str',
                },
                'status_501': {
                    'type': 'str',
                },
                'status_502': {
                    'type': 'str',
                },
                'status_503': {
                    'type': 'str',
                },
                'status_504': {
                    'type': 'str',
                },
                'status_504_ax': {
                    'type': 'str',
                },
                'status_505': {
                    'type': 'str',
                },
                'status_506': {
                    'type': 'str',
                },
                'status_507': {
                    'type': 'str',
                },
                'status_508': {
                    'type': 'str',
                },
                'status_509': {
                    'type': 'str',
                },
                'status_510': {
                    'type': 'str',
                },
                'status_1xx': {
                    'type': 'str',
                },
                'status_2xx': {
                    'type': 'str',
                },
                'status_3xx': {
                    'type': 'str',
                },
                'status_4xx': {
                    'type': 'str',
                },
                'status_5xx': {
                    'type': 'str',
                },
                'status_6xx': {
                    'type': 'str',
                },
                'status_unknown': {
                    'type': 'str',
                },
                'ws_handshake_request': {
                    'type': 'str',
                },
                'ws_handshake_success': {
                    'type': 'str',
                },
                'ws_client_switch': {
                    'type': 'str',
                },
                'ws_server_switch': {
                    'type': 'str',
                },
                'REQ_10u': {
                    'type': 'str',
                },
                'REQ_20u': {
                    'type': 'str',
                },
                'REQ_50u': {
                    'type': 'str',
                },
                'REQ_100u': {
                    'type': 'str',
                },
                'REQ_200u': {
                    'type': 'str',
                },
                'REQ_500u': {
                    'type': 'str',
                },
                'REQ_1m': {
                    'type': 'str',
                },
                'REQ_2m': {
                    'type': 'str',
                },
                'REQ_5m': {
                    'type': 'str',
                },
                'REQ_10m': {
                    'type': 'str',
                },
                'REQ_20m': {
                    'type': 'str',
                },
                'REQ_50m': {
                    'type': 'str',
                },
                'REQ_100m': {
                    'type': 'str',
                },
                'REQ_200m': {
                    'type': 'str',
                },
                'REQ_500m': {
                    'type': 'str',
                },
                'REQ_1s': {
                    'type': 'str',
                },
                'REQ_2s': {
                    'type': 'str',
                },
                'REQ_5s': {
                    'type': 'str',
                },
                'REQ_OVER_5s': {
                    'type': 'str',
                },
                'total_requests': {
                    'type': 'str',
                },
                'curr_http2_conn': {
                    'type': 'str',
                },
                'total_http2_conn': {
                    'type': 'str',
                },
                'peak_http2_conn': {
                    'type': 'str',
                },
                'total_http2_bytes': {
                    'type': 'str',
                },
                'http2_control_bytes': {
                    'type': 'str',
                },
                'http2_header_bytes': {
                    'type': 'str',
                },
                'http2_data_bytes': {
                    'type': 'str',
                },
                'http2_reset_received': {
                    'type': 'str',
                },
                'http2_reset_sent': {
                    'type': 'str',
                },
                'http2_goaway_received': {
                    'type': 'str',
                },
                'http2_goaway_sent': {
                    'type': 'str',
                },
                'stream_closed': {
                    'type': 'str',
                },
                'jsi_requests': {
                    'type': 'str',
                },
                'jsi_responses': {
                    'type': 'str',
                },
                'jsi_pri_requests': {
                    'type': 'str',
                },
                'jsi_api_requests': {
                    'type': 'str',
                },
                'jsi_api_responses': {
                    'type': 'str',
                },
                'jsi_api_no_auth_hdr': {
                    'type': 'str',
                },
                'jsi_api_no_token': {
                    'type': 'str',
                },
                'jsi_skip_no_fi': {
                    'type': 'str',
                },
                'jsi_skip_no_ua': {
                    'type': 'str',
                },
                'jsi_skip_not_browser': {
                    'type': 'str',
                },
                'jsi_hash_add_fails': {
                    'type': 'str',
                },
                'jsi_hash_lookup_fails': {
                    'type': 'str',
                },
                'header_length_long': {
                    'type': 'str',
                }
            }
        }
    })
    # Parent keys
    rv.update(
        dict(
            protocol=dict(type='str', required=True),
            port_number=dict(type='str', required=True),
            virtual_server_name=dict(type='str', required=True),
        ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/virtual-server/{virtual_server_name}/port/{port_number}+{protocol}/stats?http_vport=true"

    f_dict = {}
    f_dict["protocol"] = module.params["protocol"]
    f_dict["port_number"] = module.params["port_number"]
    f_dict["virtual_server_name"] = module.params["virtual_server_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/virtual-server/{virtual_server_name}/port/{port_number}+{protocol}/stats?http_vport=true"

    f_dict = {}
    f_dict["protocol"] = module.params["protocol"]
    f_dict["port_number"] = module.params["port_number"]
    f_dict["virtual_server_name"] = module.params["virtual_server_name"]

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
