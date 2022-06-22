#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_template_gtp_message_filtering_policy
description:
    - Configure GTP Message Filtering Policy
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
    name:
        description:
        - "Specify name of the GTP Message Filtering Policy"
        type: str
        required: True
    interface_type:
        description:
        - "'roaming'= Roaming Interface(S8/Gp); 'non-roaming'= Non-Roaming
          Interface(S5/Gn);"
        type: str
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
    version_v2:
        description:
        - "Field version_v2"
        type: dict
        required: False
        suboptions:
            enable_disable_action:
                description:
                - "'enable'= Enable Message Filtering on version; 'disable'= Disable Message
          Filtering on version;"
                type: str
            message_type:
                description:
                - "Specify the Message Type"
                type: bool
            change_notification:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            create_session:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            delete_session:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            modify_bearer:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            remote_ue_report:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            modify_command:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            delete_command:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            bearer_resource:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            create_bearer:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            update_bearer:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            delete_bearer:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            delete_pdn:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            update_pdn:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            suspend:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            resume:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            pgw_downlink_trigger:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            trace_session:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            reserved_messages:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    version_v1:
        description:
        - "Field version_v1"
        type: dict
        required: False
        suboptions:
            enable_disable_action:
                description:
                - "'enable'= Enable Message Filtering on version; 'disable'= Disable Message
          Filtering on version;"
                type: str
            message_type:
                description:
                - "Specify the Message Type"
                type: bool
            create_pdp:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            update_pdp:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            delete_pdp:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            initiate_pdp:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            pdu_notification:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            ms_info_change:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            gtp_pdu:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            mbms_session:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            mbms_notification:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            mbms_registration:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            mbms_deregistration:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            create_mbms:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            delete_mbms:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            update_mbms:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            reserved_messages:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    version_v0:
        description:
        - "Field version_v0"
        type: dict
        required: False
        suboptions:
            enable_disable_action:
                description:
                - "'enable'= Enable Message Filtering on version; 'disable'= Disable Message
          Filtering on version;"
                type: str
            message_type:
                description:
                - "Specify the Message Type"
                type: bool
            create_pdp:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            update_pdp:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            delete_pdp:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            pdu_notification:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            gtp_pdu:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            create_aa_pdp:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            delete_aa_pdp:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            reserved_messages:
                description:
                - "'enable'= Enable the Message Type; 'disable'= Disable the Message Type;"
                type: str
            uuid:
                description:
                - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["interface_type", "name", "user_tag", "uuid", "version_v0", "version_v1", "version_v2", ]


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
    rv.update({'name': {'type': 'str', 'required': True, },
        'interface_type': {'type': 'str', 'choices': ['roaming', 'non-roaming']},
        'uuid': {'type': 'str', },
        'user_tag': {'type': 'str', },
        'version_v2': {'type': 'dict', 'enable_disable_action': {'type': 'str', 'choices': ['enable', 'disable']}, 'message_type': {'type': 'bool', }, 'change_notification': {'type': 'str', 'choices': ['enable', 'disable']}, 'create_session': {'type': 'str', 'choices': ['enable', 'disable']}, 'delete_session': {'type': 'str', 'choices': ['enable', 'disable']}, 'modify_bearer': {'type': 'str', 'choices': ['enable', 'disable']}, 'remote_ue_report': {'type': 'str', 'choices': ['enable', 'disable']}, 'modify_command': {'type': 'str', 'choices': ['enable', 'disable']}, 'delete_command': {'type': 'str', 'choices': ['enable', 'disable']}, 'bearer_resource': {'type': 'str', 'choices': ['enable', 'disable']}, 'create_bearer': {'type': 'str', 'choices': ['enable', 'disable']}, 'update_bearer': {'type': 'str', 'choices': ['enable', 'disable']}, 'delete_bearer': {'type': 'str', 'choices': ['enable', 'disable']}, 'delete_pdn': {'type': 'str', 'choices': ['enable', 'disable']}, 'update_pdn': {'type': 'str', 'choices': ['enable', 'disable']}, 'suspend': {'type': 'str', 'choices': ['enable', 'disable']}, 'resume': {'type': 'str', 'choices': ['enable', 'disable']}, 'pgw_downlink_trigger': {'type': 'str', 'choices': ['enable', 'disable']}, 'trace_session': {'type': 'str', 'choices': ['enable', 'disable']}, 'reserved_messages': {'type': 'str', 'choices': ['enable', 'disable']}, 'uuid': {'type': 'str', }},
        'version_v1': {'type': 'dict', 'enable_disable_action': {'type': 'str', 'choices': ['enable', 'disable']}, 'message_type': {'type': 'bool', }, 'create_pdp': {'type': 'str', 'choices': ['enable', 'disable']}, 'update_pdp': {'type': 'str', 'choices': ['enable', 'disable']}, 'delete_pdp': {'type': 'str', 'choices': ['enable', 'disable']}, 'initiate_pdp': {'type': 'str', 'choices': ['enable', 'disable']}, 'pdu_notification': {'type': 'str', 'choices': ['enable', 'disable']}, 'ms_info_change': {'type': 'str', 'choices': ['enable', 'disable']}, 'gtp_pdu': {'type': 'str', 'choices': ['enable', 'disable']}, 'mbms_session': {'type': 'str', 'choices': ['enable', 'disable']}, 'mbms_notification': {'type': 'str', 'choices': ['enable', 'disable']}, 'mbms_registration': {'type': 'str', 'choices': ['enable', 'disable']}, 'mbms_deregistration': {'type': 'str', 'choices': ['enable', 'disable']}, 'create_mbms': {'type': 'str', 'choices': ['enable', 'disable']}, 'delete_mbms': {'type': 'str', 'choices': ['enable', 'disable']}, 'update_mbms': {'type': 'str', 'choices': ['enable', 'disable']}, 'reserved_messages': {'type': 'str', 'choices': ['enable', 'disable']}, 'uuid': {'type': 'str', }},
        'version_v0': {'type': 'dict', 'enable_disable_action': {'type': 'str', 'choices': ['enable', 'disable']}, 'message_type': {'type': 'bool', }, 'create_pdp': {'type': 'str', 'choices': ['enable', 'disable']}, 'update_pdp': {'type': 'str', 'choices': ['enable', 'disable']}, 'delete_pdp': {'type': 'str', 'choices': ['enable', 'disable']}, 'pdu_notification': {'type': 'str', 'choices': ['enable', 'disable']}, 'gtp_pdu': {'type': 'str', 'choices': ['enable', 'disable']}, 'create_aa_pdp': {'type': 'str', 'choices': ['enable', 'disable']}, 'delete_aa_pdp': {'type': 'str', 'choices': ['enable', 'disable']}, 'reserved_messages': {'type': 'str', 'choices': ['enable', 'disable']}, 'uuid': {'type': 'str', }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/template/gtp/message-filtering-policy/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/template/gtp/message-filtering-policy/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["message-filtering-policy"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["message-filtering-policy"].get(k) != v:
            change_results["changed"] = True
            config_changes["message-filtering-policy"][k] = v

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
    payload = utils.build_json("message-filtering-policy", module.params, AVAILABLE_PROPERTIES)
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
        axapi_calls=[],
        ansible_facts={},
        acos_info={}
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
                result["acos_info"] = info["message-filtering-policy"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["message-filtering-policy-list"] if info != "NotFound" else info
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
