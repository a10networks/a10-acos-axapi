#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_vcs_vblades_stat
description:
    - Show aVCS vBlade box statistics information
author: A10 Networks 2021
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
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
    vblade_id:
        description:
        - "vBlade-id"
        type: int
        required: True
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
                - "'all'= all; 'slave_recv_err'= vBlade Receive Errors counter of aVCS election;
          'slave_send_err'= vBlade Send Errors counter of aVCS election;
          'slave_recv_bytes'= vBlade Received Bytes counter of aVCS election;
          'slave_sent_bytes'= vBlade Sent Bytes counter of aVCS election; 'slave_n_recv'=
          vBlade Received Messages counter of aVCS election; 'slave_n_sent'= vBlade Sent
          Messages counter of aVCS election; 'slave_msg_inval'= vBlade Invalid Messages
          counter of aVCS election; 'slave_keepalive'= vBlade Received Keepalives counter
          of aVCS election; 'slave_cfg_upd'= vBlade Received Configuration Updates
          counter of aVCS election; 'slave_cfg_upd_l1_fail'= vBlade Local Configuration
          Update Errors (1) counter of aVCS election; 'slave_cfg_upd_r_fail'= vBlade
          Remote Configuration Update Errors counter of aVCS election;
          'slave_cfg_upd_l2_fail'= vBlade Local Configuration Update Errors (2) counter
          of aVCS election; 'slave_cfg_upd_notif_err'= vBlade Configuration Update Notif
          Errors counter of aVCS election; 'slave_cfg_upd_result_err'= vBlade
          Configuration Update Result Errors counter of aVCS election;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            slave_recv_err:
                description:
                - "vBlade Receive Errors counter of aVCS election"
                type: str
            slave_send_err:
                description:
                - "vBlade Send Errors counter of aVCS election"
                type: str
            slave_recv_bytes:
                description:
                - "vBlade Received Bytes counter of aVCS election"
                type: str
            slave_sent_bytes:
                description:
                - "vBlade Sent Bytes counter of aVCS election"
                type: str
            slave_n_recv:
                description:
                - "vBlade Received Messages counter of aVCS election"
                type: str
            slave_n_sent:
                description:
                - "vBlade Sent Messages counter of aVCS election"
                type: str
            slave_msg_inval:
                description:
                - "vBlade Invalid Messages counter of aVCS election"
                type: str
            slave_keepalive:
                description:
                - "vBlade Received Keepalives counter of aVCS election"
                type: str
            slave_cfg_upd:
                description:
                - "vBlade Received Configuration Updates counter of aVCS election"
                type: str
            slave_cfg_upd_l1_fail:
                description:
                - "vBlade Local Configuration Update Errors (1) counter of aVCS election"
                type: str
            slave_cfg_upd_r_fail:
                description:
                - "vBlade Remote Configuration Update Errors counter of aVCS election"
                type: str
            slave_cfg_upd_l2_fail:
                description:
                - "vBlade Local Configuration Update Errors (2) counter of aVCS election"
                type: str
            slave_cfg_upd_notif_err:
                description:
                - "vBlade Configuration Update Notif Errors counter of aVCS election"
                type: str
            slave_cfg_upd_result_err:
                description:
                - "vBlade Configuration Update Result Errors counter of aVCS election"
                type: str
            vblade_id:
                description:
                - "vBlade-id"
                type: int

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
    "sampling_enable",
    "stats",
    "uuid",
    "vblade_id",
]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present']),
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
        'vblade_id': {
            'type': 'int',
            'required': True,
        },
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'slave_recv_err', 'slave_send_err',
                    'slave_recv_bytes', 'slave_sent_bytes', 'slave_n_recv',
                    'slave_n_sent', 'slave_msg_inval', 'slave_keepalive',
                    'slave_cfg_upd', 'slave_cfg_upd_l1_fail',
                    'slave_cfg_upd_r_fail', 'slave_cfg_upd_l2_fail',
                    'slave_cfg_upd_notif_err', 'slave_cfg_upd_result_err'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'slave_recv_err': {
                'type': 'str',
            },
            'slave_send_err': {
                'type': 'str',
            },
            'slave_recv_bytes': {
                'type': 'str',
            },
            'slave_sent_bytes': {
                'type': 'str',
            },
            'slave_n_recv': {
                'type': 'str',
            },
            'slave_n_sent': {
                'type': 'str',
            },
            'slave_msg_inval': {
                'type': 'str',
            },
            'slave_keepalive': {
                'type': 'str',
            },
            'slave_cfg_upd': {
                'type': 'str',
            },
            'slave_cfg_upd_l1_fail': {
                'type': 'str',
            },
            'slave_cfg_upd_r_fail': {
                'type': 'str',
            },
            'slave_cfg_upd_l2_fail': {
                'type': 'str',
            },
            'slave_cfg_upd_notif_err': {
                'type': 'str',
            },
            'slave_cfg_upd_result_err': {
                'type': 'str',
            },
            'vblade_id': {
                'type': 'int',
                'required': True,
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vcs-vblades/stat/{vblade-id}"

    f_dict = {}
    f_dict["vblade-id"] = module.params["vblade_id"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vcs-vblades/stat/{vblade-id}"

    f_dict = {}
    f_dict["vblade-id"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["stat"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["stat"].get(k) != v:
            change_results["changed"] = True
            config_changes["stat"][k] = v

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
    payload = utils.build_json("stat", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def run_command(module):
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[],
                  ansible_facts={},
                  acos_info={})

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
        if existing_config['response_body'] != 'NotFound':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client,
                                            existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result[
                    "acos_info"] = info["stat"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "stat-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client,
                                                       existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["stat"][
                    "stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
