#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_cgnv6_lsn_alg_sip
description:
    - Change LSN SIP ALG Settings
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
        - "'enable'= Enable SIP ALG for LSN;"
        type: str
        required: False
    rtp_stun_timeout:
        description:
        - "RTP/RTCP STUN timeout in minutes (Default is 5 minutes)"
        type: int
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
                - "'all'= all; 'method-register'= SIP Method REGISTER; 'method-invite'= SIP Method
          INVITE; 'method-ack'= SIP Method ACK; 'method-cancel'= SIP Method CANCEL;
          'method-bye'= SIP Method BYE; 'method-options'= SIP Method OPTIONS; 'method-
          prack'= SIP Method PRACK; 'method-subscribe'= SIP Method SUBSCRIBE; 'method-
          notify'= SIP Method NOTIFY; 'method-publish'= SIP Method PUBLISH; 'method-
          info'= SIP Method INFO; 'method-refer'= SIP Method REFER; 'method-message'= SIP
          Method MESSAGE; 'method-update'= SIP Method UPDATE; 'method-unknown'= SIP
          Method UNKNOWN; 'parse-error'= SIP Message Parse Error; 'req-uri-op-failrue'=
          SIP Operate Request Uri Failure; 'via-hdr-op-failrue'= SIP Operate Via Header
          Failure; 'contact-hdr-op-failrue'= SIP Operate Contact Header Failure; 'from-
          hdr-op-failrue'= SIP Operate From Header Failure; 'to-hdr-op-failrue'= SIP
          Operate To Header Failure; 'route-hdr-op-failrue'= SIP Operate Route Header
          Failure; 'record-route-hdr-op-failrue'= SIP Operate Record-Route Header
          Failure; 'content-length-hdr-op-failrue'= SIP Operate Content-Length Failure;
          'third-party-registration'= SIP Third-Party Registration; 'conn-ext-creation-
          failure'= SIP Create Connection Extension Failure; 'alloc-contact-port-
          failure'= SIP Alloc Contact Port Failure; 'outside-contact-port-mismatch'= SIP
          Outside Contact Port Mismatch NAT Port; 'inside-contact-port-mismatch'= SIP
          Inside Contact Port Mismatch; 'third-party-sdp'= SIP Third-Party SDP; 'sdp-
          process-candidate-failure'= SIP Operate SDP Media Candidate Attribute Failure;
          'sdp-op-failure'= SIP Operate SDP Failure; 'sdp-alloc-port-map-success'= SIP
          Alloc SDP Port Map Success; 'sdp-alloc-port-map-failure'= SIP Alloc SDP Port
          Map Failure; 'modify-failure'= SIP Message Modify Failure; 'rewrite-failure'=
          SIP Message Rewrite Failure; 'tcp-out-of-order-drop'= TCP Out-of-Order Drop;
          'smp-conn-alloc-failure'= SMP Helper Conn Alloc Failure; 'helper-found'= SMP
          Helper Conn Found; 'helper-created'= SMP Helper Conn Created; 'helper-deleted'=
          SMP Helper Conn Already Deleted; 'helper-freed'= SMP Helper Conn Freed;
          'helper-failure'= SMP Helper Failure;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            method_register:
                description:
                - "SIP Method REGISTER"
                type: str
            method_invite:
                description:
                - "SIP Method INVITE"
                type: str
            method_ack:
                description:
                - "SIP Method ACK"
                type: str
            method_cancel:
                description:
                - "SIP Method CANCEL"
                type: str
            method_bye:
                description:
                - "SIP Method BYE"
                type: str
            method_options:
                description:
                - "SIP Method OPTIONS"
                type: str
            method_prack:
                description:
                - "SIP Method PRACK"
                type: str
            method_subscribe:
                description:
                - "SIP Method SUBSCRIBE"
                type: str
            method_notify:
                description:
                - "SIP Method NOTIFY"
                type: str
            method_publish:
                description:
                - "SIP Method PUBLISH"
                type: str
            method_info:
                description:
                - "SIP Method INFO"
                type: str
            method_refer:
                description:
                - "SIP Method REFER"
                type: str
            method_message:
                description:
                - "SIP Method MESSAGE"
                type: str
            method_update:
                description:
                - "SIP Method UPDATE"
                type: str
            method_unknown:
                description:
                - "SIP Method UNKNOWN"
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
AVAILABLE_PROPERTIES = ["rtp_stun_timeout", "sampling_enable", "sip_value", "stats", "uuid", ]


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
    rv.update({'sip_value': {'type': 'str', 'choices': ['enable']},
        'rtp_stun_timeout': {'type': 'int', },
        'uuid': {'type': 'str', },
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'method-register', 'method-invite', 'method-ack', 'method-cancel', 'method-bye', 'method-options', 'method-prack', 'method-subscribe', 'method-notify', 'method-publish', 'method-info', 'method-refer', 'method-message', 'method-update', 'method-unknown', 'parse-error', 'req-uri-op-failrue', 'via-hdr-op-failrue', 'contact-hdr-op-failrue', 'from-hdr-op-failrue', 'to-hdr-op-failrue', 'route-hdr-op-failrue', 'record-route-hdr-op-failrue', 'content-length-hdr-op-failrue', 'third-party-registration', 'conn-ext-creation-failure', 'alloc-contact-port-failure', 'outside-contact-port-mismatch', 'inside-contact-port-mismatch', 'third-party-sdp', 'sdp-process-candidate-failure', 'sdp-op-failure', 'sdp-alloc-port-map-success', 'sdp-alloc-port-map-failure', 'modify-failure', 'rewrite-failure', 'tcp-out-of-order-drop', 'smp-conn-alloc-failure', 'helper-found', 'helper-created', 'helper-deleted', 'helper-freed', 'helper-failure']}},
        'stats': {'type': 'dict', 'method_register': {'type': 'str', }, 'method_invite': {'type': 'str', }, 'method_ack': {'type': 'str', }, 'method_cancel': {'type': 'str', }, 'method_bye': {'type': 'str', }, 'method_options': {'type': 'str', }, 'method_prack': {'type': 'str', }, 'method_subscribe': {'type': 'str', }, 'method_notify': {'type': 'str', }, 'method_publish': {'type': 'str', }, 'method_info': {'type': 'str', }, 'method_refer': {'type': 'str', }, 'method_message': {'type': 'str', }, 'method_update': {'type': 'str', }, 'method_unknown': {'type': 'str', }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/lsn/alg/sip"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/lsn/alg/sip"

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
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
