#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_connection_reuse
description:
    - Configure Connection Reuse
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
                - "'all'= all; 'current_open'= Open persist; 'current_active'= Active persist;
          'nbind'= Total bind; 'nunbind'= Total unbind; 'nestab'= Total established;
          'ntermi'= Total terminated; 'ntermi_err'= Total terminated by err;
          'delay_unbind'= Delayed unbind; 'long_resp'= Long resp; 'miss_resp'= Missed
          resp; 'unbound_data_rcv'= Unbound data rcvd; 'pause_conn'= Pause request;
          'pause_conn_fail'= Pause request fail; 'resume_conn'= Resume request;
          'not_remove_from_rport'= Not remove from list;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            connection_reuse_cpu_list:
                description:
                - "Field connection_reuse_cpu_list"
                type: list
            cpu_count:
                description:
                - "Field cpu_count"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            current_open:
                description:
                - "Open persist"
                type: str
            current_active:
                description:
                - "Active persist"
                type: str
            nbind:
                description:
                - "Total bind"
                type: str
            nunbind:
                description:
                - "Total unbind"
                type: str
            nestab:
                description:
                - "Total established"
                type: str
            ntermi:
                description:
                - "Total terminated"
                type: str
            ntermi_err:
                description:
                - "Total terminated by err"
                type: str
            delay_unbind:
                description:
                - "Delayed unbind"
                type: str
            long_resp:
                description:
                - "Long resp"
                type: str
            miss_resp:
                description:
                - "Missed resp"
                type: str
            unbound_data_rcv:
                description:
                - "Unbound data rcvd"
                type: str
            pause_conn:
                description:
                - "Pause request"
                type: str
            pause_conn_fail:
                description:
                - "Pause request fail"
                type: str
            resume_conn:
                description:
                - "Resume request"
                type: str
            not_remove_from_rport:
                description:
                - "Not remove from list"
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
AVAILABLE_PROPERTIES = ["oper", "sampling_enable", "stats", "uuid", ]


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
                'type': 'str',
                'choices': ['all', 'current_open', 'current_active', 'nbind', 'nunbind', 'nestab', 'ntermi', 'ntermi_err', 'delay_unbind', 'long_resp', 'miss_resp', 'unbound_data_rcv', 'pause_conn', 'pause_conn_fail', 'resume_conn', 'not_remove_from_rport']
                }
            },
        'oper': {
            'type': 'dict',
            'connection_reuse_cpu_list': {
                'type': 'list',
                'current_open': {
                    'type': 'int',
                    },
                'current_active': {
                    'type': 'int',
                    },
                'nbind': {
                    'type': 'int',
                    },
                'nunbind': {
                    'type': 'int',
                    },
                'nestab': {
                    'type': 'int',
                    },
                'ntermi': {
                    'type': 'int',
                    },
                'ntermi_err': {
                    'type': 'int',
                    },
                'delay_unbind': {
                    'type': 'int',
                    },
                'long_resp': {
                    'type': 'int',
                    },
                'miss_resp': {
                    'type': 'int',
                    },
                'unbound_data_rcv': {
                    'type': 'int',
                    },
                'pause_conn': {
                    'type': 'int',
                    },
                'pause_conn_fail': {
                    'type': 'int',
                    },
                'resume_conn': {
                    'type': 'int',
                    },
                'not_remove_from_rport': {
                    'type': 'int',
                    }
                },
            'cpu_count': {
                'type': 'int',
                }
            },
        'stats': {
            'type': 'dict',
            'current_open': {
                'type': 'str',
                },
            'current_active': {
                'type': 'str',
                },
            'nbind': {
                'type': 'str',
                },
            'nunbind': {
                'type': 'str',
                },
            'nestab': {
                'type': 'str',
                },
            'ntermi': {
                'type': 'str',
                },
            'ntermi_err': {
                'type': 'str',
                },
            'delay_unbind': {
                'type': 'str',
                },
            'long_resp': {
                'type': 'str',
                },
            'miss_resp': {
                'type': 'str',
                },
            'unbound_data_rcv': {
                'type': 'str',
                },
            'pause_conn': {
                'type': 'str',
                },
            'pause_conn_fail': {
                'type': 'str',
                },
            'resume_conn': {
                'type': 'str',
                },
            'not_remove_from_rport': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/connection-reuse"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/connection-reuse"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["connection-reuse"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["connection-reuse"].get(k) != v:
            change_results["changed"] = True
            config_changes["connection-reuse"][k] = v

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
    payload = utils.build_json("connection-reuse", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["connection-reuse"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["connection-reuse-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["connection-reuse"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["connection-reuse"]["stats"] if info != "NotFound" else info
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
