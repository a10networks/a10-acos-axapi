#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_aam_authentication_server_windows
description:
    - 'Windows Server, using Kerberos or NTLM for authentication'
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
                - "'all'= all; 'kerberos-request-send'= Total Kerberos Request; 'kerberos-
          response-get'= Total Kerberos Response; 'kerberos-timeout-error'= Total
          Kerberos Timeout; 'kerberos-other-error'= Total Kerberos Other Error; 'ntlm-
          authentication-success'= Total NTLM Authentication Success; 'ntlm-
          authentication-failure'= Total NTLM Authentication Failure; 'ntlm-proto-
          negotiation-success'= Total NTLM Protocol Negotiation Success; 'ntlm-proto-
          negotiation-failure'= Total NTLM Protocol Negotiation Failure; 'ntlm-session-
          setup-success'= Total NTLM Session Setup Success; 'ntlm-session-setup-failed'=
          Total NTLM Session Setup Failure; 'kerberos-request-normal'= Total Kerberos
          Normal Request; 'kerberos-request-dropped'= Total Kerberos Dropped Request;
          'kerberos-response-success'= Total Kerberos Success Response; 'kerberos-
          response-failure'= Total Kerberos Failure Response; 'kerberos-response-error'=
          Total Kerberos Error Response; 'kerberos-response-timeout'= Total Kerberos
          Timeout Response; 'kerberos-response-other'= Total Kerberos Other Response;
          'kerberos-job-start-error'= Total Kerberos Job Start Error; 'kerberos-polling-
          control-error'= Total Kerberos Polling Control Error; 'ntlm-prepare-req-
          success'= Total NTLM Prepare Request Success; 'ntlm-prepare-req-failed'= Total
          NTLM Prepare Request Failed; 'ntlm-timeout-error'= Total NTLM Timeout; 'ntlm-
          other-error'= Total NTLM Other Error; 'ntlm-request-normal'= Total NTLM Normal
          Request; 'ntlm-request-dropped'= Total NTLM Dropped Request; 'ntlm-response-
          success'= Total NTLM Success Response; 'ntlm-response-failure'= Total NTLM
          Failure Response; 'ntlm-response-error'= Total NTLM Error Response; 'ntlm-
          response-timeout'= Total NTLM Timeout Response; 'ntlm-response-other'= Total
          NTLM Other Response; 'ntlm-job-start-error'= Total NTLM Job Start Error; 'ntlm-
          polling-control-error'= Total NTLM Polling Control Error; 'kerberos-pw-expiry'=
          Total Kerberos password expiry; 'kerberos-pw-change-success'= Total Kerberos
          password change success; 'kerberos-pw-change-failure'= Total Kerberos password
          change failure; 'kerberos-validate-kdc-success'= Total Kerberos KDC Validation
          Success; 'kerberos-validate-kdc-failure'= Total Kerberos KDC Validation
          Failure; 'kerberos-generate-kdc-keytab-success'= Total Kerberos KDC Keytab
          Generation Success; 'kerberos-generate-kdc-keytab-failure'= Total Kerberos KDC
          Keytab Generation Failure; 'kerberos-delete-kdc-keytab-success'= Total Kerberos
          KDC Keytab Deletion Success; 'kerberos-delete-kdc-keytab-failure'= Total
          Kerberos KDC Keytab Deletion Failure; 'kerberos-kdc-keytab-count'= Current
          Kerberos KDC Keytab Count;"
                type: str
    instance_list:
        description:
        - "Field instance_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Specify Windows authentication server name"
                type: str
            host:
                description:
                - "Field host"
                type: dict
            timeout:
                description:
                - "Specify connection timeout to server, default is 10 seconds"
                type: int
            auth_protocol:
                description:
                - "Field auth_protocol"
                type: dict
            realm:
                description:
                - "Specify realm of Windows server"
                type: str
            support_apacheds_kdc:
                description:
                - "Enable weak cipher (DES CRC/MD5/MD4) and merge AS-REQ in single packet"
                type: bool
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
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            kerberos_request_send:
                description:
                - "Total Kerberos Request"
                type: str
            kerberos_response_get:
                description:
                - "Total Kerberos Response"
                type: str
            kerberos_timeout_error:
                description:
                - "Total Kerberos Timeout"
                type: str
            kerberos_other_error:
                description:
                - "Total Kerberos Other Error"
                type: str
            ntlm_authentication_success:
                description:
                - "Total NTLM Authentication Success"
                type: str
            ntlm_authentication_failure:
                description:
                - "Total NTLM Authentication Failure"
                type: str
            ntlm_proto_negotiation_success:
                description:
                - "Total NTLM Protocol Negotiation Success"
                type: str
            ntlm_proto_negotiation_failure:
                description:
                - "Total NTLM Protocol Negotiation Failure"
                type: str
            ntlm_session_setup_success:
                description:
                - "Total NTLM Session Setup Success"
                type: str
            ntlm_session_setup_failed:
                description:
                - "Total NTLM Session Setup Failure"
                type: str
            kerberos_request_normal:
                description:
                - "Total Kerberos Normal Request"
                type: str
            kerberos_request_dropped:
                description:
                - "Total Kerberos Dropped Request"
                type: str
            kerberos_response_success:
                description:
                - "Total Kerberos Success Response"
                type: str
            kerberos_response_failure:
                description:
                - "Total Kerberos Failure Response"
                type: str
            kerberos_response_error:
                description:
                - "Total Kerberos Error Response"
                type: str
            kerberos_response_timeout:
                description:
                - "Total Kerberos Timeout Response"
                type: str
            kerberos_response_other:
                description:
                - "Total Kerberos Other Response"
                type: str
            kerberos_job_start_error:
                description:
                - "Total Kerberos Job Start Error"
                type: str
            kerberos_polling_control_error:
                description:
                - "Total Kerberos Polling Control Error"
                type: str
            ntlm_prepare_req_success:
                description:
                - "Total NTLM Prepare Request Success"
                type: str
            ntlm_prepare_req_failed:
                description:
                - "Total NTLM Prepare Request Failed"
                type: str
            ntlm_timeout_error:
                description:
                - "Total NTLM Timeout"
                type: str
            ntlm_other_error:
                description:
                - "Total NTLM Other Error"
                type: str
            ntlm_request_normal:
                description:
                - "Total NTLM Normal Request"
                type: str
            ntlm_request_dropped:
                description:
                - "Total NTLM Dropped Request"
                type: str
            ntlm_response_success:
                description:
                - "Total NTLM Success Response"
                type: str
            ntlm_response_failure:
                description:
                - "Total NTLM Failure Response"
                type: str
            ntlm_response_error:
                description:
                - "Total NTLM Error Response"
                type: str
            ntlm_response_timeout:
                description:
                - "Total NTLM Timeout Response"
                type: str
            ntlm_response_other:
                description:
                - "Total NTLM Other Response"
                type: str
            ntlm_job_start_error:
                description:
                - "Total NTLM Job Start Error"
                type: str
            ntlm_polling_control_error:
                description:
                - "Total NTLM Polling Control Error"
                type: str
            kerberos_pw_expiry:
                description:
                - "Total Kerberos password expiry"
                type: str
            kerberos_pw_change_success:
                description:
                - "Total Kerberos password change success"
                type: str
            kerberos_pw_change_failure:
                description:
                - "Total Kerberos password change failure"
                type: str
            kerberos_validate_kdc_success:
                description:
                - "Total Kerberos KDC Validation Success"
                type: str
            kerberos_validate_kdc_failure:
                description:
                - "Total Kerberos KDC Validation Failure"
                type: str
            kerberos_generate_kdc_keytab_success:
                description:
                - "Total Kerberos KDC Keytab Generation Success"
                type: str
            kerberos_generate_kdc_keytab_failure:
                description:
                - "Total Kerberos KDC Keytab Generation Failure"
                type: str
            kerberos_delete_kdc_keytab_success:
                description:
                - "Total Kerberos KDC Keytab Deletion Success"
                type: str
            kerberos_delete_kdc_keytab_failure:
                description:
                - "Total Kerberos KDC Keytab Deletion Failure"
                type: str
            kerberos_kdc_keytab_count:
                description:
                - "Current Kerberos KDC Keytab Count"
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
AVAILABLE_PROPERTIES = ["instance_list", "sampling_enable", "stats", "uuid", ]


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
    rv.update({'uuid': {'type': 'str', },
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'kerberos-request-send', 'kerberos-response-get', 'kerberos-timeout-error', 'kerberos-other-error', 'ntlm-authentication-success', 'ntlm-authentication-failure', 'ntlm-proto-negotiation-success', 'ntlm-proto-negotiation-failure', 'ntlm-session-setup-success', 'ntlm-session-setup-failed', 'kerberos-request-normal', 'kerberos-request-dropped', 'kerberos-response-success', 'kerberos-response-failure', 'kerberos-response-error', 'kerberos-response-timeout', 'kerberos-response-other', 'kerberos-job-start-error', 'kerberos-polling-control-error', 'ntlm-prepare-req-success', 'ntlm-prepare-req-failed', 'ntlm-timeout-error', 'ntlm-other-error', 'ntlm-request-normal', 'ntlm-request-dropped', 'ntlm-response-success', 'ntlm-response-failure', 'ntlm-response-error', 'ntlm-response-timeout', 'ntlm-response-other', 'ntlm-job-start-error', 'ntlm-polling-control-error', 'kerberos-pw-expiry', 'kerberos-pw-change-success', 'kerberos-pw-change-failure', 'kerberos-validate-kdc-success', 'kerberos-validate-kdc-failure', 'kerberos-generate-kdc-keytab-success', 'kerberos-generate-kdc-keytab-failure', 'kerberos-delete-kdc-keytab-success', 'kerberos-delete-kdc-keytab-failure', 'kerberos-kdc-keytab-count']}},
        'instance_list': {'type': 'list', 'name': {'type': 'str', 'required': True, }, 'host': {'type': 'dict', 'hostip': {'type': 'str', }, 'hostipv6': {'type': 'str', }}, 'timeout': {'type': 'int', }, 'auth_protocol': {'type': 'dict', 'ntlm_disable': {'type': 'bool', }, 'ntlm_version': {'type': 'int', }, 'ntlm_health_check': {'type': 'str', }, 'ntlm_health_check_disable': {'type': 'bool', }, 'kerberos_disable': {'type': 'bool', }, 'kerberos_port': {'type': 'int', }, 'kport_hm': {'type': 'str', }, 'kport_hm_disable': {'type': 'bool', }, 'kerberos_password_change_port': {'type': 'int', }, 'kdc_validate': {'type': 'bool', }, 'kerberos_kdc_validation': {'type': 'dict', 'kdc_spn': {'type': 'str', }, 'kdc_account': {'type': 'str', }, 'kdc_password': {'type': 'bool', }, 'kdc_pwd': {'type': 'str', }, 'encrypted': {'type': 'str', }}}, 'realm': {'type': 'str', }, 'support_apacheds_kdc': {'type': 'bool', }, 'health_check': {'type': 'bool', }, 'health_check_string': {'type': 'str', }, 'health_check_disable': {'type': 'bool', }, 'uuid': {'type': 'str', }, 'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'krb_send_req_success', 'krb_get_resp_success', 'krb_timeout_error', 'krb_other_error', 'krb_pw_expiry', 'krb_pw_change_success', 'krb_pw_change_failure', 'ntlm_proto_nego_success', 'ntlm_proto_nego_failure', 'ntlm_session_setup_success', 'ntlm_session_setup_failure', 'ntlm_prepare_req_success', 'ntlm_prepare_req_error', 'ntlm_auth_success', 'ntlm_auth_failure', 'ntlm_timeout_error', 'ntlm_other_error', 'krb_validate_kdc_success', 'krb_validate_kdc_failure']}}, 'packet_capture_template': {'type': 'str', }},
        'stats': {'type': 'dict', 'kerberos_request_send': {'type': 'str', }, 'kerberos_response_get': {'type': 'str', }, 'kerberos_timeout_error': {'type': 'str', }, 'kerberos_other_error': {'type': 'str', }, 'ntlm_authentication_success': {'type': 'str', }, 'ntlm_authentication_failure': {'type': 'str', }, 'ntlm_proto_negotiation_success': {'type': 'str', }, 'ntlm_proto_negotiation_failure': {'type': 'str', }, 'ntlm_session_setup_success': {'type': 'str', }, 'ntlm_session_setup_failed': {'type': 'str', }, 'kerberos_request_normal': {'type': 'str', }, 'kerberos_request_dropped': {'type': 'str', }, 'kerberos_response_success': {'type': 'str', }, 'kerberos_response_failure': {'type': 'str', }, 'kerberos_response_error': {'type': 'str', }, 'kerberos_response_timeout': {'type': 'str', }, 'kerberos_response_other': {'type': 'str', }, 'kerberos_job_start_error': {'type': 'str', }, 'kerberos_polling_control_error': {'type': 'str', }, 'ntlm_prepare_req_success': {'type': 'str', }, 'ntlm_prepare_req_failed': {'type': 'str', }, 'ntlm_timeout_error': {'type': 'str', }, 'ntlm_other_error': {'type': 'str', }, 'ntlm_request_normal': {'type': 'str', }, 'ntlm_request_dropped': {'type': 'str', }, 'ntlm_response_success': {'type': 'str', }, 'ntlm_response_failure': {'type': 'str', }, 'ntlm_response_error': {'type': 'str', }, 'ntlm_response_timeout': {'type': 'str', }, 'ntlm_response_other': {'type': 'str', }, 'ntlm_job_start_error': {'type': 'str', }, 'ntlm_polling_control_error': {'type': 'str', }, 'kerberos_pw_expiry': {'type': 'str', }, 'kerberos_pw_change_success': {'type': 'str', }, 'kerberos_pw_change_failure': {'type': 'str', }, 'kerberos_validate_kdc_success': {'type': 'str', }, 'kerberos_validate_kdc_failure': {'type': 'str', }, 'kerberos_generate_kdc_keytab_success': {'type': 'str', }, 'kerberos_generate_kdc_keytab_failure': {'type': 'str', }, 'kerberos_delete_kdc_keytab_success': {'type': 'str', }, 'kerberos_delete_kdc_keytab_failure': {'type': 'str', }, 'kerberos_kdc_keytab_count': {'type': 'str', }, 'instance_list': {'type': 'list', 'name': {'type': 'str', 'required': True, }, 'stats': {'type': 'dict', 'krb_send_req_success': {'type': 'str', }, 'krb_get_resp_success': {'type': 'str', }, 'krb_timeout_error': {'type': 'str', }, 'krb_other_error': {'type': 'str', }, 'krb_pw_expiry': {'type': 'str', }, 'krb_pw_change_success': {'type': 'str', }, 'krb_pw_change_failure': {'type': 'str', }, 'ntlm_proto_nego_success': {'type': 'str', }, 'ntlm_proto_nego_failure': {'type': 'str', }, 'ntlm_session_setup_success': {'type': 'str', }, 'ntlm_session_setup_failure': {'type': 'str', }, 'ntlm_prepare_req_success': {'type': 'str', }, 'ntlm_prepare_req_error': {'type': 'str', }, 'ntlm_auth_success': {'type': 'str', }, 'ntlm_auth_failure': {'type': 'str', }, 'ntlm_timeout_error': {'type': 'str', }, 'ntlm_other_error': {'type': 'str', }, 'krb_validate_kdc_success': {'type': 'str', }, 'krb_validate_kdc_failure': {'type': 'str', }}}}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/server/windows"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authentication/server/windows"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["windows"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["windows"].get(k) != v:
            change_results["changed"] = True
            config_changes["windows"][k] = v

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
    payload = utils.build_json("windows", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["windows"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["windows-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["windows"]["stats"] if info != "NotFound" else info
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
