#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_aam_authentication_server_ocsp
description:
    - OCSP Authentication Server
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
                - "'all'= all; 'stapling-certificate-good'= Total OCSP Stapling Good Certificate
          Response; 'stapling-certificate-revoked'= Total OCSP Stapling Revoked
          Certificate Response; 'stapling-certificate-unknown'= Total OCSP Stapling
          Unknown Certificate Response; 'stapling-request-normal'= Total OSCP Stapling
          Normal Request; 'stapling-request-dropped'= Total OCSP Stapling Dropped
          Request; 'stapling-response-success'= Total OCSP Stapling Success Response;
          'stapling-response-failure'= Total OCSP Stapling Failure Response; 'stapling-
          response-error'= Total OCSP Stapling Error Response; 'stapling-response-
          timeout'= Total OCSP Stapling Timeout Response; 'stapling-response-other'=
          Total OCSP Stapling Other Response; 'request-normal'= Total OSCP Normal
          Request; 'request-dropped'= Total OCSP Dropped Request; 'response-success'=
          Total OCSP Success Response; 'response-failure'= Total OCSP Failure Response;
          'response-error'= Total OCSP Error Response; 'response-timeout'= Total OCSP
          Timeout Response; 'response-other'= Total OCSP Other Response; 'job-start-
          error'= Total OCSP Job Start Error; 'polling-control-error'= Total OCSP Polling
          Control Error;"
                type: str
    instance_list:
        description:
        - "Field instance_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Specify OCSP authentication server name"
                type: str
            url:
                description:
                - "Specify the OCSP server's address (Format= http=//host[=port]/) (The OCSP
          server's address(Format= http=//host[=port]/))"
                type: str
            responder_ca:
                description:
                - "Specify the trusted OCSP responder's CA cert filename"
                type: str
            responder_cert:
                description:
                - "Specify the trusted OCSP responder's cert filename"
                type: str
            health_check:
                description:
                - "Check server's health status"
                type: bool
            health_check_string:
                description:
                - "Health monitor name"
                type: str
            health_check_disable:
                description:
                - "Disable configured health check configuration"
                type: bool
            port_health_check:
                description:
                - "Check port's health status"
                type: str
            port_health_check_disable:
                description:
                - "Disable configured port health check configuration"
                type: bool
            http_version:
                description:
                - "Set HTTP version (default 1.0)"
                type: bool
            version_type:
                description:
                - "'1.1'= HTTP version 1.1;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
            packet_capture_template:
                description:
                - "Name of the packet capture template to be bind with this object"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            stats_clear_type:
                description:
                - "Field stats_clear_type"
                type: str
            name:
                description:
                - "Field name"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            stapling_certificate_good:
                description:
                - "Total OCSP Stapling Good Certificate Response"
                type: str
            stapling_certificate_revoked:
                description:
                - "Total OCSP Stapling Revoked Certificate Response"
                type: str
            stapling_certificate_unknown:
                description:
                - "Total OCSP Stapling Unknown Certificate Response"
                type: str
            stapling_request_normal:
                description:
                - "Total OSCP Stapling Normal Request"
                type: str
            stapling_request_dropped:
                description:
                - "Total OCSP Stapling Dropped Request"
                type: str
            stapling_response_success:
                description:
                - "Total OCSP Stapling Success Response"
                type: str
            stapling_response_failure:
                description:
                - "Total OCSP Stapling Failure Response"
                type: str
            stapling_response_error:
                description:
                - "Total OCSP Stapling Error Response"
                type: str
            stapling_response_timeout:
                description:
                - "Total OCSP Stapling Timeout Response"
                type: str
            stapling_response_other:
                description:
                - "Total OCSP Stapling Other Response"
                type: str
            request_normal:
                description:
                - "Total OSCP Normal Request"
                type: str
            request_dropped:
                description:
                - "Total OCSP Dropped Request"
                type: str
            response_success:
                description:
                - "Total OCSP Success Response"
                type: str
            response_failure:
                description:
                - "Total OCSP Failure Response"
                type: str
            response_error:
                description:
                - "Total OCSP Error Response"
                type: str
            response_timeout:
                description:
                - "Total OCSP Timeout Response"
                type: str
            response_other:
                description:
                - "Total OCSP Other Response"
                type: str
            job_start_error:
                description:
                - "Total OCSP Job Start Error"
                type: str
            polling_control_error:
                description:
                - "Total OCSP Polling Control Error"
                type: str
            instance_list:
                description:
                - "Field instance_list"
                type: list

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
AVAILABLE_PROPERTIES = ["instance_list", "oper", "sampling_enable", "stats", "uuid", ]


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
                    'all', 'stapling-certificate-good', 'stapling-certificate-revoked', 'stapling-certificate-unknown', 'stapling-request-normal', 'stapling-request-dropped', 'stapling-response-success', 'stapling-response-failure', 'stapling-response-error', 'stapling-response-timeout', 'stapling-response-other', 'request-normal',
                    'request-dropped', 'response-success', 'response-failure', 'response-error', 'response-timeout', 'response-other', 'job-start-error', 'polling-control-error'
                    ]
                }
            },
        'instance_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'url': {
                'type': 'str',
                },
            'responder_ca': {
                'type': 'str',
                },
            'responder_cert': {
                'type': 'str',
                },
            'health_check': {
                'type': 'bool',
                },
            'health_check_string': {
                'type': 'str',
                },
            'health_check_disable': {
                'type': 'bool',
                },
            'port_health_check': {
                'type': 'str',
                },
            'port_health_check_disable': {
                'type': 'bool',
                },
            'http_version': {
                'type': 'bool',
                },
            'version_type': {
                'type': 'str',
                'choices': ['1.1']
                },
            'uuid': {
                'type': 'str',
                },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type': 'str',
                    'choices': ['all', 'request', 'certificate-good', 'certificate-revoked', 'certificate-unknown', 'timeout', 'fail', 'stapling-request', 'stapling-certificate-good', 'stapling-certificate-revoked', 'stapling-certificate-unknown', 'stapling-timeout', 'stapling-fail']
                    }
                },
            'packet_capture_template': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'stats_clear_type': {
                'type': 'str',
                'choices': ['ocsp', 'ocsp-stapling']
                },
            'name': {
                'type': 'str',
                }
            },
        'stats': {
            'type': 'dict',
            'stapling_certificate_good': {
                'type': 'str',
                },
            'stapling_certificate_revoked': {
                'type': 'str',
                },
            'stapling_certificate_unknown': {
                'type': 'str',
                },
            'stapling_request_normal': {
                'type': 'str',
                },
            'stapling_request_dropped': {
                'type': 'str',
                },
            'stapling_response_success': {
                'type': 'str',
                },
            'stapling_response_failure': {
                'type': 'str',
                },
            'stapling_response_error': {
                'type': 'str',
                },
            'stapling_response_timeout': {
                'type': 'str',
                },
            'stapling_response_other': {
                'type': 'str',
                },
            'request_normal': {
                'type': 'str',
                },
            'request_dropped': {
                'type': 'str',
                },
            'response_success': {
                'type': 'str',
                },
            'response_failure': {
                'type': 'str',
                },
            'response_error': {
                'type': 'str',
                },
            'response_timeout': {
                'type': 'str',
                },
            'response_other': {
                'type': 'str',
                },
            'job_start_error': {
                'type': 'str',
                },
            'polling_control_error': {
                'type': 'str',
                },
            'instance_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'stats': {
                    'type': 'dict',
                    'request': {
                        'type': 'str',
                        },
                    'certificate_good': {
                        'type': 'str',
                        },
                    'certificate_revoked': {
                        'type': 'str',
                        },
                    'certificate_unknown': {
                        'type': 'str',
                        },
                    'timeout': {
                        'type': 'str',
                        },
                    'fail': {
                        'type': 'str',
                        },
                    'stapling_request': {
                        'type': 'str',
                        },
                    'stapling_certificate_good': {
                        'type': 'str',
                        },
                    'stapling_certificate_revoked': {
                        'type': 'str',
                        },
                    'stapling_certificate_unknown': {
                        'type': 'str',
                        },
                    'stapling_timeout': {
                        'type': 'str',
                        },
                    'stapling_fail': {
                        'type': 'str',
                        }
                    }
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/server/ocsp"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authentication/server/ocsp"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["ocsp"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["ocsp"].get(k) != v:
            change_results["changed"] = True
            config_changes["ocsp"][k] = v

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
    payload = utils.build_json("ocsp", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["ocsp"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["ocsp-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["ocsp"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["ocsp"]["stats"] if info != "NotFound" else info
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
