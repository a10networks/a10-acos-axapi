#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_stateful_firewall_alg_sip
description:
    - Configure SIP ALG for NAT stateful firewall (default= enabled)
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
    sip_value:
        description:
        - "'disable'= Disable ALG;"
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
                - "'all'= all; 'stat-request'= Request Received; 'stat-response'= Response
          Received; 'method-register'= Method REGISTER; 'method-invite'= Method INVITE;
          'method-ack'= Method ACK; 'method-cancel'= Method CANCEL; 'method-bye'= Method
          BYE; 'method-port-config'= Method OPTIONS; 'method-prack'= Method PRACK;
          'method-subscribe'= Method SUBSCRIBE; 'method-notify'= Method NOTIFY; 'method-
          publish'= Method PUBLISH; 'method-info'= Method INFO; 'method-refer'= Method
          REFER; 'method-message'= Method MESSAGE; 'method-update'= Method UPDATE;
          'method-unknown'= Method Unknown; 'parse-error'= Message Parse Error; 'keep-
          alive'= Keep Alive; 'contact-error'= Contact Process Error; 'sdp-error'= SDP
          Process Error; 'rtp-port-no-op'= RTP Port No Op; 'rtp-rtcp-port-success'= RTP
          RTCP Port Success; 'rtp-port-failure'= RTP Port Failure; 'rtcp-port-failure'=
          RTCP Port Failure; 'contact-port-no-op'= Contact Port No Op; 'contact-port-
          success'= Contact Port Success; 'contact-port-failure'= Contact Port Failure;
          'contact-new'= Contact Alloc; 'contact-alloc-failure'= Contact Alloc Failure;
          'contact-eim'= Contact EIM; 'contact-eim-set'= Contact EIM Set; 'rtp-new'= RTP
          Alloc; 'rtp-alloc-failure'= RTP Alloc Failure; 'rtp-eim'= RTP EIM;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            stat_request:
                description:
                - "Request Received"
                type: str
            stat_response:
                description:
                - "Response Received"
                type: str
            method_register:
                description:
                - "Method REGISTER"
                type: str
            method_invite:
                description:
                - "Method INVITE"
                type: str
            method_ack:
                description:
                - "Method ACK"
                type: str
            method_cancel:
                description:
                - "Method CANCEL"
                type: str
            method_bye:
                description:
                - "Method BYE"
                type: str
            method_port_config:
                description:
                - "Method OPTIONS"
                type: str
            method_prack:
                description:
                - "Method PRACK"
                type: str
            method_subscribe:
                description:
                - "Method SUBSCRIBE"
                type: str
            method_notify:
                description:
                - "Method NOTIFY"
                type: str
            method_publish:
                description:
                - "Method PUBLISH"
                type: str
            method_info:
                description:
                - "Method INFO"
                type: str
            method_refer:
                description:
                - "Method REFER"
                type: str
            method_message:
                description:
                - "Method MESSAGE"
                type: str
            method_update:
                description:
                - "Method UPDATE"
                type: str
            method_unknown:
                description:
                - "Method Unknown"
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
AVAILABLE_PROPERTIES = [
    "sampling_enable",
    "sip_value",
    "stats",
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
        'sip_value': {
            'type': 'str',
            'choices': ['disable']
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
                    'all', 'stat-request', 'stat-response', 'method-register',
                    'method-invite', 'method-ack', 'method-cancel',
                    'method-bye', 'method-port-config', 'method-prack',
                    'method-subscribe', 'method-notify', 'method-publish',
                    'method-info', 'method-refer', 'method-message',
                    'method-update', 'method-unknown', 'parse-error',
                    'keep-alive', 'contact-error', 'sdp-error',
                    'rtp-port-no-op', 'rtp-rtcp-port-success',
                    'rtp-port-failure', 'rtcp-port-failure',
                    'contact-port-no-op', 'contact-port-success',
                    'contact-port-failure', 'contact-new',
                    'contact-alloc-failure', 'contact-eim', 'contact-eim-set',
                    'rtp-new', 'rtp-alloc-failure', 'rtp-eim'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'stat_request': {
                'type': 'str',
            },
            'stat_response': {
                'type': 'str',
            },
            'method_register': {
                'type': 'str',
            },
            'method_invite': {
                'type': 'str',
            },
            'method_ack': {
                'type': 'str',
            },
            'method_cancel': {
                'type': 'str',
            },
            'method_bye': {
                'type': 'str',
            },
            'method_port_config': {
                'type': 'str',
            },
            'method_prack': {
                'type': 'str',
            },
            'method_subscribe': {
                'type': 'str',
            },
            'method_notify': {
                'type': 'str',
            },
            'method_publish': {
                'type': 'str',
            },
            'method_info': {
                'type': 'str',
            },
            'method_refer': {
                'type': 'str',
            },
            'method_message': {
                'type': 'str',
            },
            'method_update': {
                'type': 'str',
            },
            'method_unknown': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/stateful-firewall/alg/sip"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/stateful-firewall/alg/sip"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["sip"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["sip"].get(k) != v:
            change_results["changed"] = True
            config_changes["sip"][k] = v

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
    payload = utils.build_json("sip", module.params, AVAILABLE_PROPERTIES)
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

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client,
                                            existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result[
                    "acos_info"] = info["sip"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "sip-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client,
                                                       existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["sip"][
                    "stats"] if info != "NotFound" else info
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
