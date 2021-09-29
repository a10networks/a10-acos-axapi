#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_ssl_cert_revoke
description:
    - Configure ssl-cert-revoke-stats
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
                - "'all'= all; 'ocsp_stapling_response_good'= OCSP stapling response good;
          'ocsp_chain_status_good'= Certificate chain status good;
          'ocsp_chain_status_revoked'= Certificate chain status revoked;
          'ocsp_chain_status_unknown'= Certificate chain status unknown; 'ocsp_request'=
          OCSP requests; 'ocsp_response'= OCSP responses; 'ocsp_connection_error'= OCSP
          connection error; 'ocsp_uri_not_found'= OCSP URI not found; 'ocsp_uri_https'=
          Log OCSP URI https; 'ocsp_uri_unsupported'= OCSP URI unsupported;
          'ocsp_response_status_good'= OCSP response status good;
          'ocsp_response_status_revoked'= OCSP response status revoked;
          'ocsp_response_status_unknown'= OCSP response status unknown;
          'ocsp_cache_status_good'= OCSP cache status good; 'ocsp_cache_status_revoked'=
          OCSP cache status revoked; 'ocsp_cache_miss'= OCSP cache miss;
          'ocsp_cache_expired'= OCSP cache expired; 'ocsp_other_error'= Log OCSP other
          errors; 'ocsp_response_no_nonce'= Log OCSP other errors;
          'ocsp_response_nonce_error'= Log OCSP other errors; 'crl_request'= CRL
          requests; 'crl_response'= CRL responses; 'crl_connection_error'= CRL connection
          errors; 'crl_uri_not_found'= CRL URI not found; 'crl_uri_https'= CRL URI https;
          'crl_uri_unsupported'= CRL URI unsupported; 'crl_response_status_good'= CRL
          response status good; 'crl_response_status_revoked'= CRL response status
          revoked; 'crl_response_status_unknown'= CRL response status unknown;
          'crl_cache_status_good'= CRL cache status good; 'crl_cache_status_revoked'= CRL
          cache status revoked; 'crl_other_error'= CRL other errors;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            ocsp_stapling_response_good:
                description:
                - "OCSP stapling response good"
                type: str
            ocsp_chain_status_good:
                description:
                - "Certificate chain status good"
                type: str
            ocsp_chain_status_revoked:
                description:
                - "Certificate chain status revoked"
                type: str
            ocsp_chain_status_unknown:
                description:
                - "Certificate chain status unknown"
                type: str
            ocsp_request:
                description:
                - "OCSP requests"
                type: str
            ocsp_response:
                description:
                - "OCSP responses"
                type: str
            ocsp_connection_error:
                description:
                - "OCSP connection error"
                type: str
            ocsp_uri_not_found:
                description:
                - "OCSP URI not found"
                type: str
            ocsp_uri_https:
                description:
                - "Log OCSP URI https"
                type: str
            ocsp_uri_unsupported:
                description:
                - "OCSP URI unsupported"
                type: str
            ocsp_response_status_good:
                description:
                - "OCSP response status good"
                type: str
            ocsp_response_status_revoked:
                description:
                - "OCSP response status revoked"
                type: str
            ocsp_response_status_unknown:
                description:
                - "OCSP response status unknown"
                type: str
            ocsp_cache_status_good:
                description:
                - "OCSP cache status good"
                type: str
            ocsp_cache_status_revoked:
                description:
                - "OCSP cache status revoked"
                type: str
            ocsp_cache_miss:
                description:
                - "OCSP cache miss"
                type: str
            ocsp_cache_expired:
                description:
                - "OCSP cache expired"
                type: str
            ocsp_other_error:
                description:
                - "Log OCSP other errors"
                type: str
            ocsp_response_no_nonce:
                description:
                - "Log OCSP other errors"
                type: str
            ocsp_response_nonce_error:
                description:
                - "Log OCSP other errors"
                type: str
            crl_request:
                description:
                - "CRL requests"
                type: str
            crl_response:
                description:
                - "CRL responses"
                type: str
            crl_connection_error:
                description:
                - "CRL connection errors"
                type: str
            crl_uri_not_found:
                description:
                - "CRL URI not found"
                type: str
            crl_uri_https:
                description:
                - "CRL URI https"
                type: str
            crl_uri_unsupported:
                description:
                - "CRL URI unsupported"
                type: str
            crl_response_status_good:
                description:
                - "CRL response status good"
                type: str
            crl_response_status_revoked:
                description:
                - "CRL response status revoked"
                type: str
            crl_response_status_unknown:
                description:
                - "CRL response status unknown"
                type: str
            crl_cache_status_good:
                description:
                - "CRL cache status good"
                type: str
            crl_cache_status_revoked:
                description:
                - "CRL cache status revoked"
                type: str
            crl_other_error:
                description:
                - "CRL other errors"
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
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'ocsp_stapling_response_good',
                    'ocsp_chain_status_good', 'ocsp_chain_status_revoked',
                    'ocsp_chain_status_unknown', 'ocsp_request',
                    'ocsp_response', 'ocsp_connection_error',
                    'ocsp_uri_not_found', 'ocsp_uri_https',
                    'ocsp_uri_unsupported', 'ocsp_response_status_good',
                    'ocsp_response_status_revoked',
                    'ocsp_response_status_unknown', 'ocsp_cache_status_good',
                    'ocsp_cache_status_revoked', 'ocsp_cache_miss',
                    'ocsp_cache_expired', 'ocsp_other_error',
                    'ocsp_response_no_nonce', 'ocsp_response_nonce_error',
                    'crl_request', 'crl_response', 'crl_connection_error',
                    'crl_uri_not_found', 'crl_uri_https',
                    'crl_uri_unsupported', 'crl_response_status_good',
                    'crl_response_status_revoked',
                    'crl_response_status_unknown', 'crl_cache_status_good',
                    'crl_cache_status_revoked', 'crl_other_error'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'ocsp_stapling_response_good': {
                'type': 'str',
            },
            'ocsp_chain_status_good': {
                'type': 'str',
            },
            'ocsp_chain_status_revoked': {
                'type': 'str',
            },
            'ocsp_chain_status_unknown': {
                'type': 'str',
            },
            'ocsp_request': {
                'type': 'str',
            },
            'ocsp_response': {
                'type': 'str',
            },
            'ocsp_connection_error': {
                'type': 'str',
            },
            'ocsp_uri_not_found': {
                'type': 'str',
            },
            'ocsp_uri_https': {
                'type': 'str',
            },
            'ocsp_uri_unsupported': {
                'type': 'str',
            },
            'ocsp_response_status_good': {
                'type': 'str',
            },
            'ocsp_response_status_revoked': {
                'type': 'str',
            },
            'ocsp_response_status_unknown': {
                'type': 'str',
            },
            'ocsp_cache_status_good': {
                'type': 'str',
            },
            'ocsp_cache_status_revoked': {
                'type': 'str',
            },
            'ocsp_cache_miss': {
                'type': 'str',
            },
            'ocsp_cache_expired': {
                'type': 'str',
            },
            'ocsp_other_error': {
                'type': 'str',
            },
            'ocsp_response_no_nonce': {
                'type': 'str',
            },
            'ocsp_response_nonce_error': {
                'type': 'str',
            },
            'crl_request': {
                'type': 'str',
            },
            'crl_response': {
                'type': 'str',
            },
            'crl_connection_error': {
                'type': 'str',
            },
            'crl_uri_not_found': {
                'type': 'str',
            },
            'crl_uri_https': {
                'type': 'str',
            },
            'crl_uri_unsupported': {
                'type': 'str',
            },
            'crl_response_status_good': {
                'type': 'str',
            },
            'crl_response_status_revoked': {
                'type': 'str',
            },
            'crl_response_status_unknown': {
                'type': 'str',
            },
            'crl_cache_status_good': {
                'type': 'str',
            },
            'crl_cache_status_revoked': {
                'type': 'str',
            },
            'crl_other_error': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/ssl-cert-revoke"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/ssl-cert-revoke"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["ssl-cert-revoke"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["ssl-cert-revoke"].get(k) != v:
            change_results["changed"] = True
            config_changes["ssl-cert-revoke"][k] = v

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
    payload = utils.build_json("ssl-cert-revoke", module.params,
                               AVAILABLE_PROPERTIES)
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
                    api_client.get_stats(module.client,
                                         existing_url(module),
                                         params=module.params))
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
