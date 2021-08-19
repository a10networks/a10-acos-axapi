#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_sip
description:
    - SIP Template
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
        - "SIP Template Name"
        type: str
        required: True
    alg_source_nat:
        description:
        - "Translate source IP to NAT IP in SIP message when source NAT is used"
        type: bool
        required: False
    alg_dest_nat:
        description:
        - "Translate VIP to real server IP in SIP message when destination NAT is used"
        type: bool
        required: False
    call_id_persist_disable:
        description:
        - "Disable call-ID persistence"
        type: bool
        required: False
    client_keep_alive:
        description:
        - "Respond client keep-alive packet directly instead of forwarding to server"
        type: bool
        required: False
    pstn_gw:
        description:
        - "configure pstn gw host name for tel= uri translate to sip= uri (Hostname
          String, default is 'pstn')"
        type: str
        required: False
    client_request_header:
        description:
        - "Field client_request_header"
        type: list
        required: False
        suboptions:
            client_request_header_erase:
                description:
                - "Erase a SIP header (Header Name)"
                type: str
            client_request_erase_all:
                description:
                - "Erase all headers"
                type: bool
            client_request_header_insert:
                description:
                - "Insert a SIP header (Header Content (Format= 'name=value'))"
                type: str
            insert_condition_client_request:
                description:
                - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-
          always'= Always insert the header even when there is a header with the same
          name;"
                type: str
    client_response_header:
        description:
        - "Field client_response_header"
        type: list
        required: False
        suboptions:
            client_response_header_erase:
                description:
                - "Erase a SIP header (Header Name)"
                type: str
            client_response_erase_all:
                description:
                - "Erase all headers"
                type: bool
            client_response_header_insert:
                description:
                - "Insert a SIP header (Header Content (Format= 'name=value'))"
                type: str
            insert_condition_client_response:
                description:
                - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-
          always'= Always insert the header even when there is a header with the same
          name;"
                type: str
    exclude_translation:
        description:
        - "Field exclude_translation"
        type: list
        required: False
        suboptions:
            translation_value:
                description:
                - "'start-line'= SIP request line or status line; 'header'= SIP message headers;
          'body'= SIP message body;"
                type: str
            header_string:
                description:
                - "SIP header name"
                type: str
    failed_client_selection:
        description:
        - "Define action when select client fail"
        type: bool
        required: False
    drop_when_client_fail:
        description:
        - "Drop current SIP message when select client fail"
        type: bool
        required: False
    failed_client_selection_message:
        description:
        - "Send SIP message (includs status code) to server when select client
          fail(Format= 3 digits(1XX~6XX) space reason)"
        type: str
        required: False
    failed_server_selection:
        description:
        - "Define action when select server fail"
        type: bool
        required: False
    drop_when_server_fail:
        description:
        - "Drop current SIP message when select server fail"
        type: bool
        required: False
    failed_server_selection_message:
        description:
        - "Send SIP message (includs status code) to client when select server
          fail(Format= 3 digits(1XX~6XX) space reason)"
        type: str
        required: False
    insert_client_ip:
        description:
        - "Insert Client IP address into SIP header"
        type: bool
        required: False
    keep_server_ip_if_match_acl:
        description:
        - "Use Real Server IP for addresses matching the ACL for a Call-Id"
        type: bool
        required: False
    acl_id:
        description:
        - "ACL id"
        type: int
        required: False
    acl_name_value:
        description:
        - "IPv4 Access List Name"
        type: str
        required: False
    service_group:
        description:
        - "service group name"
        type: str
        required: False
    server_keep_alive:
        description:
        - "Send server keep-alive packet for every persist connection when enable conn-
          reuse"
        type: bool
        required: False
    interval:
        description:
        - "The interval of keep-alive packet for each persist connection (second)"
        type: int
        required: False
    server_request_header:
        description:
        - "Field server_request_header"
        type: list
        required: False
        suboptions:
            server_request_header_erase:
                description:
                - "Erase a SIP header (Header Name)"
                type: str
            server_request_erase_all:
                description:
                - "Erase all headers"
                type: bool
            server_request_header_insert:
                description:
                - "Insert a SIP header (Header Content (Format= 'name=value'))"
                type: str
            insert_condition_server_request:
                description:
                - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-
          always'= Always insert the header even when there is a header with the same
          name;"
                type: str
    server_response_header:
        description:
        - "Field server_response_header"
        type: list
        required: False
        suboptions:
            server_response_header_erase:
                description:
                - "Erase a SIP header (Header Name)"
                type: str
            server_response_erase_all:
                description:
                - "Erase all headers"
                type: bool
            server_response_header_insert:
                description:
                - "Insert a SIP header (Header Content (Format= 'name=value'))"
                type: str
            insert_condition_server_response:
                description:
                - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-
          always'= Always insert the header even when there is a header with the same
          name;"
                type: str
    smp_call_id_rtp_session:
        description:
        - "Create the across cpu call-id rtp session"
        type: bool
        required: False
    server_selection_per_request:
        description:
        - "Force server selection on every SIP request"
        type: bool
        required: False
    timeout:
        description:
        - "Time in minutes"
        type: int
        required: False
    dialog_aware:
        description:
        - "Permit system processes dialog session"
        type: bool
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
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "acl_id",
    "acl_name_value",
    "alg_dest_nat",
    "alg_source_nat",
    "call_id_persist_disable",
    "client_keep_alive",
    "client_request_header",
    "client_response_header",
    "dialog_aware",
    "drop_when_client_fail",
    "drop_when_server_fail",
    "exclude_translation",
    "failed_client_selection",
    "failed_client_selection_message",
    "failed_server_selection",
    "failed_server_selection_message",
    "insert_client_ip",
    "interval",
    "keep_server_ip_if_match_acl",
    "name",
    "pstn_gw",
    "server_keep_alive",
    "server_request_header",
    "server_response_header",
    "server_selection_per_request",
    "service_group",
    "smp_call_id_rtp_session",
    "timeout",
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
        'alg_source_nat': {
            'type': 'bool',
        },
        'alg_dest_nat': {
            'type': 'bool',
        },
        'call_id_persist_disable': {
            'type': 'bool',
        },
        'client_keep_alive': {
            'type': 'bool',
        },
        'pstn_gw': {
            'type': 'str',
        },
        'client_request_header': {
            'type': 'list',
            'client_request_header_erase': {
                'type': 'str',
            },
            'client_request_erase_all': {
                'type': 'bool',
            },
            'client_request_header_insert': {
                'type': 'str',
            },
            'insert_condition_client_request': {
                'type': 'str',
                'choices': ['insert-if-not-exist', 'insert-always']
            }
        },
        'client_response_header': {
            'type': 'list',
            'client_response_header_erase': {
                'type': 'str',
            },
            'client_response_erase_all': {
                'type': 'bool',
            },
            'client_response_header_insert': {
                'type': 'str',
            },
            'insert_condition_client_response': {
                'type': 'str',
                'choices': ['insert-if-not-exist', 'insert-always']
            }
        },
        'exclude_translation': {
            'type': 'list',
            'translation_value': {
                'type': 'str',
                'choices': ['start-line', 'header', 'body']
            },
            'header_string': {
                'type': 'str',
            }
        },
        'failed_client_selection': {
            'type': 'bool',
        },
        'drop_when_client_fail': {
            'type': 'bool',
        },
        'failed_client_selection_message': {
            'type': 'str',
        },
        'failed_server_selection': {
            'type': 'bool',
        },
        'drop_when_server_fail': {
            'type': 'bool',
        },
        'failed_server_selection_message': {
            'type': 'str',
        },
        'insert_client_ip': {
            'type': 'bool',
        },
        'keep_server_ip_if_match_acl': {
            'type': 'bool',
        },
        'acl_id': {
            'type': 'int',
        },
        'acl_name_value': {
            'type': 'str',
        },
        'service_group': {
            'type': 'str',
        },
        'server_keep_alive': {
            'type': 'bool',
        },
        'interval': {
            'type': 'int',
        },
        'server_request_header': {
            'type': 'list',
            'server_request_header_erase': {
                'type': 'str',
            },
            'server_request_erase_all': {
                'type': 'bool',
            },
            'server_request_header_insert': {
                'type': 'str',
            },
            'insert_condition_server_request': {
                'type': 'str',
                'choices': ['insert-if-not-exist', 'insert-always']
            }
        },
        'server_response_header': {
            'type': 'list',
            'server_response_header_erase': {
                'type': 'str',
            },
            'server_response_erase_all': {
                'type': 'bool',
            },
            'server_response_header_insert': {
                'type': 'str',
            },
            'insert_condition_server_response': {
                'type': 'str',
                'choices': ['insert-if-not-exist', 'insert-always']
            }
        },
        'smp_call_id_rtp_session': {
            'type': 'bool',
        },
        'server_selection_per_request': {
            'type': 'bool',
        },
        'timeout': {
            'type': 'int',
        },
        'dialog_aware': {
            'type': 'bool',
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
    url_base = "/axapi/v3/slb/template/sip/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/sip/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
