#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_fixed_nat_hw_accelerate
description:
    - Fixed-NAT HW accelerate counters
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
    uuid:
        description:
        - "uuid of the object"
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
                - "'all'= all; 'entry-create'= HW Entries Created; 'entry-create-failure'= HW
          Entry Creation Failed; 'entry-create-fail-server-down'= HW Entry Creation
          Failed - server down; 'entry-create-fail-max-entry'= HW Entry Creation Failed -
          max entries exceeded; 'entry-free'= HW Entries Freed; 'entry-free-opp-entry'=
          HW Entries Freed - opposite tuple entry aged-out; 'entry-free-no-hw-prog'= HW
          Entry Freed - no HW prog; 'entry-free-no-conn'= HW Entry Freed - no matched
          conn; 'entry-free-no-sw-entry'= HW Entry Freed - no software entry; 'entry-
          counter'= HW Entries Count; 'entry-age-out'= HW Entries Aged Out; 'entry-age-
          out-idle'= HW Entries Aged Out - idle timeout; 'entry-age-out-tcp-fin'= HW
          Entries Aged Out - TCP FIN; 'entry-age-out-tcp-rst'= HW Entries Aged Out - TCP
          RST; 'entry-age-out-invalid-dst'= HW Entries Aged Out - invalid dst; 'entry-
          force-hw-invalidate'= HW Entries Force HW Invalidate; 'entry-invalidate-server-
          down'= HW Entries Invalidate due to server down; 'tcam-create'= TCAM Flows
          Created; 'tcam-free'= TCAM Flows Freed; 'tcam-counter'= TCAM Flow Count;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            entry_create:
                description:
                - "HW Entries Created"
                type: str
            entry_create_failure:
                description:
                - "HW Entry Creation Failed"
                type: str
            entry_create_fail_server_down:
                description:
                - "HW Entry Creation Failed - server down"
                type: str
            entry_create_fail_max_entry:
                description:
                - "HW Entry Creation Failed - max entries exceeded"
                type: str
            entry_free:
                description:
                - "HW Entries Freed"
                type: str
            entry_free_opp_entry:
                description:
                - "HW Entries Freed - opposite tuple entry aged-out"
                type: str
            entry_free_no_hw_prog:
                description:
                - "HW Entry Freed - no HW prog"
                type: str
            entry_free_no_conn:
                description:
                - "HW Entry Freed - no matched conn"
                type: str
            entry_free_no_sw_entry:
                description:
                - "HW Entry Freed - no software entry"
                type: str
            entry_counter:
                description:
                - "HW Entries Count"
                type: str
            entry_age_out:
                description:
                - "HW Entries Aged Out"
                type: str
            entry_age_out_idle:
                description:
                - "HW Entries Aged Out - idle timeout"
                type: str
            entry_age_out_tcp_fin:
                description:
                - "HW Entries Aged Out - TCP FIN"
                type: str
            entry_age_out_tcp_rst:
                description:
                - "HW Entries Aged Out - TCP RST"
                type: str
            entry_age_out_invalid_dst:
                description:
                - "HW Entries Aged Out - invalid dst"
                type: str
            entry_force_hw_invalidate:
                description:
                - "HW Entries Force HW Invalidate"
                type: str
            entry_invalidate_server_down:
                description:
                - "HW Entries Invalidate due to server down"
                type: str
            tcam_create:
                description:
                - "TCAM Flows Created"
                type: str
            tcam_free:
                description:
                - "TCAM Flows Freed"
                type: str
            tcam_counter:
                description:
                - "TCAM Flow Count"
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
AVAILABLE_PROPERTIES = ["sampling_enable", "stats", "uuid", ]


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
        'uuid': {
            'type': 'str',
            },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'entry-create', 'entry-create-failure', 'entry-create-fail-server-down', 'entry-create-fail-max-entry', 'entry-free', 'entry-free-opp-entry', 'entry-free-no-hw-prog', 'entry-free-no-conn', 'entry-free-no-sw-entry', 'entry-counter', 'entry-age-out', 'entry-age-out-idle', 'entry-age-out-tcp-fin', 'entry-age-out-tcp-rst',
                    'entry-age-out-invalid-dst', 'entry-force-hw-invalidate', 'entry-invalidate-server-down', 'tcam-create', 'tcam-free', 'tcam-counter'
                    ]
                }
            },
        'stats': {
            'type': 'dict',
            'entry_create': {
                'type': 'str',
                },
            'entry_create_failure': {
                'type': 'str',
                },
            'entry_create_fail_server_down': {
                'type': 'str',
                },
            'entry_create_fail_max_entry': {
                'type': 'str',
                },
            'entry_free': {
                'type': 'str',
                },
            'entry_free_opp_entry': {
                'type': 'str',
                },
            'entry_free_no_hw_prog': {
                'type': 'str',
                },
            'entry_free_no_conn': {
                'type': 'str',
                },
            'entry_free_no_sw_entry': {
                'type': 'str',
                },
            'entry_counter': {
                'type': 'str',
                },
            'entry_age_out': {
                'type': 'str',
                },
            'entry_age_out_idle': {
                'type': 'str',
                },
            'entry_age_out_tcp_fin': {
                'type': 'str',
                },
            'entry_age_out_tcp_rst': {
                'type': 'str',
                },
            'entry_age_out_invalid_dst': {
                'type': 'str',
                },
            'entry_force_hw_invalidate': {
                'type': 'str',
                },
            'entry_invalidate_server_down': {
                'type': 'str',
                },
            'tcam_create': {
                'type': 'str',
                },
            'tcam_free': {
                'type': 'str',
                },
            'tcam_counter': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/fixed-nat/hw-accelerate"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/fixed-nat/hw-accelerate"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["hw-accelerate"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["hw-accelerate"].get(k) != v:
            change_results["changed"] = True
            config_changes["hw-accelerate"][k] = v

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
    payload = utils.build_json("hw-accelerate", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["hw-accelerate"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["hw-accelerate-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["hw-accelerate"]["stats"] if info != "NotFound" else info
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
