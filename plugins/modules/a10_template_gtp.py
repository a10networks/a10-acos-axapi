#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_template_gtp
description:
    - Define a GTP template
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
        - "GTP Template Name"
        type: str
        required: True
    log:
        description:
        - "Field log"
        type: dict
        required: False
        suboptions:
            message_filtering:
                description:
                - "Log Packet Drop due to Message Filtering"
                type: bool
            information_filtering:
                description:
                - "Log Packet Drop due to Information Filtering"
                type: bool
            invalid_teid:
                description:
                - "Log Packet Drop due to Invalid Tunnel Endpoint Identifier"
                type: bool
            reserved_ie_present:
                description:
                - "Log Packet Drop due to Presence of Reserved Information Element"
                type: bool
            mandatory_ie_missing:
                description:
                - "Log Packet Drop due to Missing Mandatory Information Element"
                type: bool
    protocol_anomaly_filtering:
        description:
        - "'disable'= Disable Anomaly Filtering;"
        type: str
        required: False
    mandatory_ie_filtering:
        description:
        - "'disable'= Disable  Mandatory Information Element Filtering;"
        type: str
        required: False
    tunnel_timeout:
        description:
        - "Idle Timeout in minutes (default= 60 mins)"
        type: int
        required: False
    maximum_message_length:
        description:
        - "Maximum message length for a GTP message"
        type: int
        required: False
    message_type:
        description:
        - "Field message_type"
        type: list
        required: False
        suboptions:
            message_type_v2:
                description:
                - "'bearer-resource'= Bearer Resource Command/Failure; 'change-notification'=
          Change Notification Request/Response; 'context'= Context Request/Response/Ack;
          'config-transfer'= Configuration Transfer Tunnel; 'create-bearer'= Create
          Bearer Request/Response; 'create-data-forwarding'= Create Indirect Data Tunnel
          Request/Response; 'create-tunnel-forwarding'= Create Forwarding Tunnel
          Request/Response; 'create-session'= Create Session Request/Response; 'cs-
          paging'= CS Paging Indication; 'delete-bearer'= Delete Bearer Request/Response;
          'delete-command'= Delete Bearer Command/Failure; 'delete-data-forwarding'=
          Delete Indirect Data Tunnel Request/Response; 'delete-pdn'= Delete PDN
          Connection Request/Response; 'delete-session'= Delete Session Request/Response;
          'detach'= Detach Notification/Ack; 'downlink-notification'= Downlink Data
          Notification/Ack/Failure; 'echo'= Echo Request/Response; 'fwd-access'= Forward
          Access Context Notification/Ack; 'fwd-relocation'= Forward Relocation
          Request/Response/Complete; 'identification'= Identification Request/Response;
          'mbms-session-start'= MBMS Session Start Request/Response; 'mbms-session-stop'=
          MBMS Session Stop Request/Response; 'mbms-session-update'= MBMS Session Update
          Request/Response; 'modify-bearer'= Modify Bearer Request/Response; 'modify-
          command'= Modify Bearer Command/Failure; 'release-access'= Release Access
          Bearer Request/Response; 'relocation-cancel'= Relocation Cancel
          Request/Response; 'resume'= Resume Notification/Ack; 'stop-paging'= Stop Paging
          Indication; 'suspend'= Suspend Notification/Ack; 'trace-session'= Trace Session
          Activation/Deactivation; 'update-bearer'= Update Bearer Request/Response;
          'update-pdn'= Update PDN Connection Request/Response; 'version-not-supported'=
          Version Not Supported;"
                type: str
            message_type_v1:
                description:
                - "'create-pdp'= Create PDP Context Request/Response; 'data-record'= Data Record
          Request/Response; 'delete-pdp'= Delete PDP Context Request/Response; 'echo'=
          Echo Request/Response; 'error-indication'= Error Indication; 'failure-report'=
          Failure Report Request/Response; 'fwd-relocation'= Forward Relocation
          Request/Response/Complete/Complete Acknowledge; 'fwd-srns-context'= Forward
          Srns Context/Context Acknowlege; 'identification'= Identification
          Request/Response; 'node-alive'= Node Alive Request/Response; 'note-ms-present'=
          Note MS GPRS present Request/Response; 'pdu-notification'= PDU Notification
          Request/Response/Reject Request/Reject Response; 'ran-info'= RAN Info Relay;
          'redirection'= Redirection Request/Response; 'relocation-cancel'= Relocation
          Cancel Request/Response; 'send-route'= Send Route Info Request/Response; 'sgsn-
          context'= Sgsn Context Request/Response/Acknowledge; 'supported-extension'=
          Supported Extension Headers Notification; 'gtp-pdu'= G-PDU; 'update-pdp'=
          Update PDP Context Request/Response; 'version-not-supported'= Version Not
          Supported;"
                type: str
            message_type_v0:
                description:
                - "'create-pdp'= Create PDP Context Request/Response; 'data-record'= Data Record
          Request/Response; 'delete-pdp'= Delete PDP Context Request/Response; 'echo'=
          Echo Request/Response; 'error-indication'= Error Indication; 'failure-report'=
          Failure Report Request/Response; 'identification'= Identification
          Request/Response; 'node-alive'= Node Alive Request/Response; 'note-ms-present'=
          Note MS GPRS present Request/Response; 'pdu-notification'= PDU Notification
          Request/Response/Reject Request/Reject Response; 'redirection'= Redirection
          Request/Response; 'send-route'= Send Route Info Request/Response; 'sgsn-
          context'= Sgsn Context Request/Response/Acknowledge; 'gtp-pdu'= T-PDU; 'update-
          pdp'= Update PDP Context Request/Response; 'create-aa-pdp'= Create AA PDP
          Context Request/Response; 'delete-aa-pdp'= Delete AA PDP Context
          Request/Response; 'version-not-supported'= Version Not Supported;"
                type: str
            drop_value:
                description:
                - "'drop'= Drop the Message Type;"
                type: str
    gtp_filter_list:
        description:
        - "Specify a GTP Filter-List (GTP Filter-List Value)"
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
    "gtp_filter_list",
    "log",
    "mandatory_ie_filtering",
    "maximum_message_length",
    "message_type",
    "name",
    "protocol_anomaly_filtering",
    "tunnel_timeout",
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
        'name': {
            'type': 'str',
            'required': True,
        },
        'log': {
            'type': 'dict',
            'message_filtering': {
                'type': 'bool',
            },
            'information_filtering': {
                'type': 'bool',
            },
            'invalid_teid': {
                'type': 'bool',
            },
            'reserved_ie_present': {
                'type': 'bool',
            },
            'mandatory_ie_missing': {
                'type': 'bool',
            }
        },
        'protocol_anomaly_filtering': {
            'type': 'str',
            'choices': ['disable']
        },
        'mandatory_ie_filtering': {
            'type': 'str',
            'choices': ['disable']
        },
        'tunnel_timeout': {
            'type': 'int',
        },
        'maximum_message_length': {
            'type': 'int',
        },
        'message_type': {
            'type': 'list',
            'message_type_v2': {
                'type':
                'str',
                'choices': [
                    'bearer-resource', 'change-notification', 'context',
                    'config-transfer', 'create-bearer',
                    'create-data-forwarding', 'create-tunnel-forwarding',
                    'create-session', 'cs-paging', 'delete-bearer',
                    'delete-command', 'delete-data-forwarding', 'delete-pdn',
                    'delete-session', 'detach', 'downlink-notification',
                    'echo', 'fwd-access', 'fwd-relocation', 'identification',
                    'mbms-session-start', 'mbms-session-stop',
                    'mbms-session-update', 'modify-bearer', 'modify-command',
                    'release-access', 'relocation-cancel', 'resume',
                    'stop-paging', 'suspend', 'trace-session', 'update-bearer',
                    'update-pdn', 'version-not-supported'
                ]
            },
            'message_type_v1': {
                'type':
                'str',
                'choices': [
                    'create-pdp', 'data-record', 'delete-pdp', 'echo',
                    'error-indication', 'failure-report', 'fwd-relocation',
                    'fwd-srns-context', 'identification', 'node-alive',
                    'note-ms-present', 'pdu-notification', 'ran-info',
                    'redirection', 'relocation-cancel', 'send-route',
                    'sgsn-context', 'supported-extension', 'gtp-pdu',
                    'update-pdp', 'version-not-supported'
                ]
            },
            'message_type_v0': {
                'type':
                'str',
                'choices': [
                    'create-pdp', 'data-record', 'delete-pdp', 'echo',
                    'error-indication', 'failure-report', 'identification',
                    'node-alive', 'note-ms-present', 'pdu-notification',
                    'redirection', 'send-route', 'sgsn-context', 'gtp-pdu',
                    'update-pdp', 'create-aa-pdp', 'delete-aa-pdp',
                    'version-not-supported'
                ]
            },
            'drop_value': {
                'type': 'str',
                'choices': ['drop']
            }
        },
        'gtp_filter_list': {
            'type': 'str',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/template/gtp/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/template/gtp/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["gtp"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["gtp"].get(k) != v:
            change_results["changed"] = True
            config_changes["gtp"][k] = v

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
    payload = utils.build_json("gtp", module.params, AVAILABLE_PROPERTIES)
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
