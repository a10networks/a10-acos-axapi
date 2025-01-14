#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_hm_dplane
description:
    - Configure hm-dplane
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
                - "'all'= all; 'curr_entries'= Current HM Entries; 'total_created'= Total HM
          Entries Created; 'total_inserted'= Total HM entries inserted;
          'curr_ready_to_free'= Current HM entries ready to free; 'total_freed'= Total HM
          entries freed; 'err_entry_create_failed'= Entry Creation Failure;
          'err_entry_create_oom'= Entry creation out of memory;
          'err_entry_insert_failed'= Entry insert failed; 'total_tcp_err'= Total TCP
          errors in health-checks sent; 'err_smart_nat_alloc'= Error creating smart-nat
          instance; 'err_smart_nat_port_alloc'= Error obtaining smart-nat source port;
          'err_l4_sess_alloc'= Error allocating L4 session for HM;
          'err_hm_tcp_conn_sent'= Error in initiating TCP connection for HM;
          'hm_tcp_conn_sent'= Total TCP connections sent for HM; 'entry_deleted'= Entry
          deleted; 'err_entry_create_slb_failed'= Error in creating HM internal SLB
          Resource; 'total_match_resp_code'= Total HTTP received response with match
          response code; 'total_match_default_resp_code'= Total HTTP received response
          with match 200 response code; 'total_maintenance_received'= Total maintenace
          response received; 'total_wrong_status_received'= Total HTTP received response
          with wrong response code; 'err_no_hm_entry'= Error no HM entry found;
          'err_ssl_cert_name_mismatch'= Error SSL cert name mismatch;
          'err_server_syn_timeout'= Error SSL server SYN timeout; 'err_http2_callback'=
          Error HTTP2 callback; 'err_l7_sess_process_tcp_estab_failed'= L7 session
          process TCP established failed; 'err_l7_sess_process_tcp_data_failed'= L7
          session process TCP data failed; 'err_http2_ver_mismatch'= Error HTTP2 version
          mismatch; 'smart_nat_alloc'= Total smart-nat allocation successful;
          'smart_nat_release'= Total smart-nat release successful;
          'smart_nat_alloc_failed'= Total smart-nat allocation failed;
          'smart_nat_release_failed'= Total smart-nat release failed;
          'total_server_quic_conn'= Total start server QUIC connections;
          'total_server_quic_conn_err'= Total start server QUIC connections error;
          'total_start_server_conn_err'= Total start server connections error;
          'err_missing_server_ssl_template'= Missing Server-SSL Template;
          'err_create_ssl_ctx_fail'= Error in creating SSL CTX;
          'err_entry_missing_vport'= Entry missing Virtual-Port;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            curr_entries:
                description:
                - "Current HM Entries"
                type: str
            total_created:
                description:
                - "Total HM Entries Created"
                type: str
            total_inserted:
                description:
                - "Total HM entries inserted"
                type: str
            curr_ready_to_free:
                description:
                - "Current HM entries ready to free"
                type: str
            total_freed:
                description:
                - "Total HM entries freed"
                type: str
            err_entry_create_failed:
                description:
                - "Entry Creation Failure"
                type: str
            err_entry_create_oom:
                description:
                - "Entry creation out of memory"
                type: str
            err_entry_insert_failed:
                description:
                - "Entry insert failed"
                type: str
            total_tcp_err:
                description:
                - "Total TCP errors in health-checks sent"
                type: str
            err_smart_nat_alloc:
                description:
                - "Error creating smart-nat instance"
                type: str
            err_smart_nat_port_alloc:
                description:
                - "Error obtaining smart-nat source port"
                type: str
            err_l4_sess_alloc:
                description:
                - "Error allocating L4 session for HM"
                type: str
            err_hm_tcp_conn_sent:
                description:
                - "Error in initiating TCP connection for HM"
                type: str
            hm_tcp_conn_sent:
                description:
                - "Total TCP connections sent for HM"
                type: str
            entry_deleted:
                description:
                - "Entry deleted"
                type: str
            err_entry_create_slb_failed:
                description:
                - "Error in creating HM internal SLB Resource"
                type: str
            total_match_resp_code:
                description:
                - "Total HTTP received response with match response code"
                type: str
            total_match_default_resp_code:
                description:
                - "Total HTTP received response with match 200 response code"
                type: str
            total_maintenance_received:
                description:
                - "Total maintenace response received"
                type: str
            total_wrong_status_received:
                description:
                - "Total HTTP received response with wrong response code"
                type: str
            err_no_hm_entry:
                description:
                - "Error no HM entry found"
                type: str
            err_ssl_cert_name_mismatch:
                description:
                - "Error SSL cert name mismatch"
                type: str
            err_server_syn_timeout:
                description:
                - "Error SSL server SYN timeout"
                type: str
            err_http2_callback:
                description:
                - "Error HTTP2 callback"
                type: str
            err_l7_sess_process_tcp_estab_failed:
                description:
                - "L7 session process TCP established failed"
                type: str
            err_l7_sess_process_tcp_data_failed:
                description:
                - "L7 session process TCP data failed"
                type: str
            err_http2_ver_mismatch:
                description:
                - "Error HTTP2 version mismatch"
                type: str
            smart_nat_alloc:
                description:
                - "Total smart-nat allocation successful"
                type: str
            smart_nat_release:
                description:
                - "Total smart-nat release successful"
                type: str
            smart_nat_alloc_failed:
                description:
                - "Total smart-nat allocation failed"
                type: str
            smart_nat_release_failed:
                description:
                - "Total smart-nat release failed"
                type: str
            total_server_quic_conn:
                description:
                - "Total start server QUIC connections"
                type: str
            total_server_quic_conn_err:
                description:
                - "Total start server QUIC connections error"
                type: str
            total_start_server_conn_err:
                description:
                - "Total start server connections error"
                type: str
            err_missing_server_ssl_template:
                description:
                - "Missing Server-SSL Template"
                type: str
            err_create_ssl_ctx_fail:
                description:
                - "Error in creating SSL CTX"
                type: str
            err_entry_missing_vport:
                description:
                - "Entry missing Virtual-Port"
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
AVAILABLE_PROPERTIES = ["sampling_enable", "stats", "uuid", ]


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
                    'all', 'curr_entries', 'total_created', 'total_inserted', 'curr_ready_to_free', 'total_freed', 'err_entry_create_failed', 'err_entry_create_oom', 'err_entry_insert_failed', 'total_tcp_err', 'err_smart_nat_alloc', 'err_smart_nat_port_alloc', 'err_l4_sess_alloc', 'err_hm_tcp_conn_sent', 'hm_tcp_conn_sent', 'entry_deleted',
                    'err_entry_create_slb_failed', 'total_match_resp_code', 'total_match_default_resp_code', 'total_maintenance_received', 'total_wrong_status_received', 'err_no_hm_entry', 'err_ssl_cert_name_mismatch', 'err_server_syn_timeout', 'err_http2_callback', 'err_l7_sess_process_tcp_estab_failed', 'err_l7_sess_process_tcp_data_failed',
                    'err_http2_ver_mismatch', 'smart_nat_alloc', 'smart_nat_release', 'smart_nat_alloc_failed', 'smart_nat_release_failed', 'total_server_quic_conn', 'total_server_quic_conn_err', 'total_start_server_conn_err', 'err_missing_server_ssl_template', 'err_create_ssl_ctx_fail', 'err_entry_missing_vport'
                    ]
                }
            },
        'stats': {
            'type': 'dict',
            'curr_entries': {
                'type': 'str',
                },
            'total_created': {
                'type': 'str',
                },
            'total_inserted': {
                'type': 'str',
                },
            'curr_ready_to_free': {
                'type': 'str',
                },
            'total_freed': {
                'type': 'str',
                },
            'err_entry_create_failed': {
                'type': 'str',
                },
            'err_entry_create_oom': {
                'type': 'str',
                },
            'err_entry_insert_failed': {
                'type': 'str',
                },
            'total_tcp_err': {
                'type': 'str',
                },
            'err_smart_nat_alloc': {
                'type': 'str',
                },
            'err_smart_nat_port_alloc': {
                'type': 'str',
                },
            'err_l4_sess_alloc': {
                'type': 'str',
                },
            'err_hm_tcp_conn_sent': {
                'type': 'str',
                },
            'hm_tcp_conn_sent': {
                'type': 'str',
                },
            'entry_deleted': {
                'type': 'str',
                },
            'err_entry_create_slb_failed': {
                'type': 'str',
                },
            'total_match_resp_code': {
                'type': 'str',
                },
            'total_match_default_resp_code': {
                'type': 'str',
                },
            'total_maintenance_received': {
                'type': 'str',
                },
            'total_wrong_status_received': {
                'type': 'str',
                },
            'err_no_hm_entry': {
                'type': 'str',
                },
            'err_ssl_cert_name_mismatch': {
                'type': 'str',
                },
            'err_server_syn_timeout': {
                'type': 'str',
                },
            'err_http2_callback': {
                'type': 'str',
                },
            'err_l7_sess_process_tcp_estab_failed': {
                'type': 'str',
                },
            'err_l7_sess_process_tcp_data_failed': {
                'type': 'str',
                },
            'err_http2_ver_mismatch': {
                'type': 'str',
                },
            'smart_nat_alloc': {
                'type': 'str',
                },
            'smart_nat_release': {
                'type': 'str',
                },
            'smart_nat_alloc_failed': {
                'type': 'str',
                },
            'smart_nat_release_failed': {
                'type': 'str',
                },
            'total_server_quic_conn': {
                'type': 'str',
                },
            'total_server_quic_conn_err': {
                'type': 'str',
                },
            'total_start_server_conn_err': {
                'type': 'str',
                },
            'err_missing_server_ssl_template': {
                'type': 'str',
                },
            'err_create_ssl_ctx_fail': {
                'type': 'str',
                },
            'err_entry_missing_vport': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/hm-dplane"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/hm-dplane"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["hm-dplane"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["hm-dplane"].get(k) != v:
            change_results["changed"] = True
            config_changes["hm-dplane"][k] = v

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
    payload = utils.build_json("hm-dplane", module.params, AVAILABLE_PROPERTIES)
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

        if state == 'present' or state == 'absent':
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
            if module.params.get("get_type") == "single" or module.params.get("get_type") is None:
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["hm-dplane"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["hm-dplane-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["hm-dplane"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


"""
    Custom class which override the _check_required_arguments function to check check required arguments based on state and get_type.
"""


class AcosAnsibleModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        super(AcosAnsibleModule, self).__init__(*args, **kwargs)

    def _check_required_arguments(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        # skip validation if state is 'noop' and get_type is 'list'
        if not (param.get("state") == "noop" and param.get("get_type") == "list"):
            missing = []
            if spec is None:
                return missing
            # Check for missing required parameters in the provided argument spec
            for (k, v) in spec.items():
                required = v.get('required', False)
                if required and k not in param:
                    missing.append(k)
            if missing:
                self.fail_json(msg="Missing required parameters: {}".format(", ".join(missing)))


def main():
    module = AcosAnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
