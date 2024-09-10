#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_l7_sip
description:
    - DDOS SIP Statistics
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
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            policy_drop:
                description:
                - "Policy Drop"
                type: str
            policy_violation:
                description:
                - "Policy Violation"
                type: str
            idle_timeout:
                description:
                - "Idle Timeout"
                type: str
            ofo_timeout:
                description:
                - "Out-of-Order Timeout"
                type: str
            seq_check_ofo:
                description:
                - "Sequence Check Out-Of-Order"
                type: str
            pkts_ofo_total:
                description:
                - "Packet Out-Of-Order Total"
                type: str
            ofo_queue_size_exceed:
                description:
                - "Out-Of-Order Queue Size Exceed"
                type: str
            seq_check_retrans_fin:
                description:
                - "Sequence Check Retransmit Fin"
                type: str
            seq_check_retrans_rst:
                description:
                - "Sequence Check Retransmit Rst"
                type: str
            seq_check_retrans_push:
                description:
                - "Sequence Check Retransmit Push"
                type: str
            seq_check_retrans_other:
                description:
                - "Sequence Check Retransmit Other"
                type: str
            pkts_retrans_total:
                description:
                - "Packets Retransmit Total"
                type: str
            client_rst:
                description:
                - "Client Rst"
                type: str
            error_condition:
                description:
                - "Error Condition"
                type: str
            request_method_ack:
                description:
                - "Request Method ACK"
                type: str
            request_method_bye:
                description:
                - "Request Method BYE"
                type: str
            request_method_cancel:
                description:
                - "Request Method CANCEL"
                type: str
            request_method_invite:
                description:
                - "Request Method INVITE"
                type: str
            request_method_info:
                description:
                - "Request Method INFO"
                type: str
            request_method_message:
                description:
                - "Request Method MESSAGE"
                type: str
            request_method_notify:
                description:
                - "Request Method NOTIFY"
                type: str
            request_method_options:
                description:
                - "Request Method OPTIONS"
                type: str
            request_method_prack:
                description:
                - "Request Method PRACK"
                type: str
            request_method_publish:
                description:
                - "Request Method PUBLISH"
                type: str
            request_method_register:
                description:
                - "Request Method REGISTER"
                type: str
            request_method_refer:
                description:
                - "Request Method REFER"
                type: str
            request_method_subscribe:
                description:
                - "Request Method SUBSCRIBE"
                type: str
            request_method_update:
                description:
                - "Request Method UPDATE"
                type: str
            request_method_unknown:
                description:
                - "Unknown Request Method"
                type: str
            request_unknown_version:
                description:
                - "Unknown Request Version"
                type: str
            keep_alive_msg:
                description:
                - "KeepAlive Message"
                type: str
            rate1_limit_exceed:
                description:
                - "Dst Request Rate 1 Limit Exceed"
                type: str
            rate2_limit_exceed:
                description:
                - "Dst Request Rate 2 Limit Exceed"
                type: str
            src_rate1_limit_exceed:
                description:
                - "Src Request Rate 1 Limit Exceed"
                type: str
            src_rate2_limit_exceed:
                description:
                - "Src Request Rate 2 Limit Exceed"
                type: str
            response_1xx:
                description:
                - "Response Status Code 1xx"
                type: str
            response_2xx:
                description:
                - "Response Status Code 2xx"
                type: str
            response_3xx:
                description:
                - "Response Status Code 3xx"
                type: str
            response_4xx:
                description:
                - "Response Status Code 4xx"
                type: str
            response_5xx:
                description:
                - "Response Status Code 5xx"
                type: str
            response_6xx:
                description:
                - "Response Status Code 6xx"
                type: str
            response_unknown:
                description:
                - "Unknown Response Status Code"
                type: str
            response_unknown_version:
                description:
                - "Unknown Response Version"
                type: str
            read_start_line_error:
                description:
                - "Read Start Line Read Error"
                type: str
            invalid_start_line_error:
                description:
                - "Invalid Start Line"
                type: str
            parse_start_line_error:
                description:
                - "Start Line Parse Error"
                type: str
            line_too_long:
                description:
                - "Line Too Long"
                type: str
            line_mem_allocated:
                description:
                - "Line Memory Allocated"
                type: str
            line_mem_freed:
                description:
                - "Line Memory Freed"
                type: str
            max_uri_len_exceed:
                description:
                - "Max URI Length Exceed"
                type: str
            too_many_header:
                description:
                - "Max Header Count Exceed"
                type: str
            invalid_header:
                description:
                - "Invalid Header"
                type: str
            header_name_too_long:
                description:
                - "Max Header Name Length Exceed"
                type: str
            parse_header_fail_error:
                description:
                - "Header Parse Fail"
                type: str
            max_header_value_len_exceed:
                description:
                - "Max Header Value Length Exceed"
                type: str
            max_call_id_len_exceed:
                description:
                - "Max Call ID Length Exceed"
                type: str
            header_filter_match:
                description:
                - "Header Filter Match"
                type: str
            header_filter_not_match:
                description:
                - "Header Filter Not Match"
                type: str
            header_filter_none_match:
                description:
                - "None Header Filter Match"
                type: str
            header_filter_action_drop:
                description:
                - "Header Filter Action Drop"
                type: str
            header_filter_action_blacklist:
                description:
                - "Header Filter Action Blacklist"
                type: str
            header_filter_action_whitelist:
                description:
                - "Header Filter Action Whitelist"
                type: str
            header_filter_action_default_pass:
                description:
                - "Header Filter Action Default Pass"
                type: str
            max_sdp_len_exceed:
                description:
                - "Max SDP Length Exceed"
                type: str
            body_too_big:
                description:
                - "Body Too Big"
                type: str
            get_content_fail_error:
                description:
                - "Get Content Fail"
                type: str
            concatenate_msg:
                description:
                - "Concatenate Msessage"
                type: str
            mem_alloc_fail_error:
                description:
                - "Memory Allocate Fail"
                type: str
            malform_request:
                description:
                - "Malformed Request"
                type: str
            src_header_filter_match:
                description:
                - "Src Header Filter Match"
                type: str
            src_header_filter_not_match:
                description:
                - "Src Header Filter Not Match"
                type: str
            src_header_filter_action_drop:
                description:
                - "Src Header Filter Action Drop"
                type: str
            src_header_filter_action_blacklist:
                description:
                - "Src Header Filter Action Blacklist"
                type: str
            src_header_filter_action_whitelist:
                description:
                - "Src Header Filter Action Whitelist"
                type: str
            src_header_filter_action_default_pass:
                description:
                - "Src Header Filter Action Default Pass"
                type: str
            src_dst_header_filter_match:
                description:
                - "Src Header Filter Match"
                type: str
            src_dst_header_filter_not_match:
                description:
                - "Src Header Filter Not Match"
                type: str
            src_dst_header_filter_action_drop:
                description:
                - "Src Header Filter Action Drop"
                type: str
            src_dst_header_filter_action_blacklist:
                description:
                - "Src Header Filter Action Blacklist"
                type: str
            src_dst_header_filter_action_whitelist:
                description:
                - "Src Header Filter Action Whitelist"
                type: str
            src_dst_header_filter_action_default_pass:
                description:
                - "Src Header Filter Action Default Pass"
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
AVAILABLE_PROPERTIES = ["stats", "uuid", ]


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
        'stats': {
            'type': 'dict',
            'policy_drop': {
                'type': 'str',
                },
            'policy_violation': {
                'type': 'str',
                },
            'idle_timeout': {
                'type': 'str',
                },
            'ofo_timeout': {
                'type': 'str',
                },
            'seq_check_ofo': {
                'type': 'str',
                },
            'pkts_ofo_total': {
                'type': 'str',
                },
            'ofo_queue_size_exceed': {
                'type': 'str',
                },
            'seq_check_retrans_fin': {
                'type': 'str',
                },
            'seq_check_retrans_rst': {
                'type': 'str',
                },
            'seq_check_retrans_push': {
                'type': 'str',
                },
            'seq_check_retrans_other': {
                'type': 'str',
                },
            'pkts_retrans_total': {
                'type': 'str',
                },
            'client_rst': {
                'type': 'str',
                },
            'error_condition': {
                'type': 'str',
                },
            'request_method_ack': {
                'type': 'str',
                },
            'request_method_bye': {
                'type': 'str',
                },
            'request_method_cancel': {
                'type': 'str',
                },
            'request_method_invite': {
                'type': 'str',
                },
            'request_method_info': {
                'type': 'str',
                },
            'request_method_message': {
                'type': 'str',
                },
            'request_method_notify': {
                'type': 'str',
                },
            'request_method_options': {
                'type': 'str',
                },
            'request_method_prack': {
                'type': 'str',
                },
            'request_method_publish': {
                'type': 'str',
                },
            'request_method_register': {
                'type': 'str',
                },
            'request_method_refer': {
                'type': 'str',
                },
            'request_method_subscribe': {
                'type': 'str',
                },
            'request_method_update': {
                'type': 'str',
                },
            'request_method_unknown': {
                'type': 'str',
                },
            'request_unknown_version': {
                'type': 'str',
                },
            'keep_alive_msg': {
                'type': 'str',
                },
            'rate1_limit_exceed': {
                'type': 'str',
                },
            'rate2_limit_exceed': {
                'type': 'str',
                },
            'src_rate1_limit_exceed': {
                'type': 'str',
                },
            'src_rate2_limit_exceed': {
                'type': 'str',
                },
            'response_1xx': {
                'type': 'str',
                },
            'response_2xx': {
                'type': 'str',
                },
            'response_3xx': {
                'type': 'str',
                },
            'response_4xx': {
                'type': 'str',
                },
            'response_5xx': {
                'type': 'str',
                },
            'response_6xx': {
                'type': 'str',
                },
            'response_unknown': {
                'type': 'str',
                },
            'response_unknown_version': {
                'type': 'str',
                },
            'read_start_line_error': {
                'type': 'str',
                },
            'invalid_start_line_error': {
                'type': 'str',
                },
            'parse_start_line_error': {
                'type': 'str',
                },
            'line_too_long': {
                'type': 'str',
                },
            'line_mem_allocated': {
                'type': 'str',
                },
            'line_mem_freed': {
                'type': 'str',
                },
            'max_uri_len_exceed': {
                'type': 'str',
                },
            'too_many_header': {
                'type': 'str',
                },
            'invalid_header': {
                'type': 'str',
                },
            'header_name_too_long': {
                'type': 'str',
                },
            'parse_header_fail_error': {
                'type': 'str',
                },
            'max_header_value_len_exceed': {
                'type': 'str',
                },
            'max_call_id_len_exceed': {
                'type': 'str',
                },
            'header_filter_match': {
                'type': 'str',
                },
            'header_filter_not_match': {
                'type': 'str',
                },
            'header_filter_none_match': {
                'type': 'str',
                },
            'header_filter_action_drop': {
                'type': 'str',
                },
            'header_filter_action_blacklist': {
                'type': 'str',
                },
            'header_filter_action_whitelist': {
                'type': 'str',
                },
            'header_filter_action_default_pass': {
                'type': 'str',
                },
            'max_sdp_len_exceed': {
                'type': 'str',
                },
            'body_too_big': {
                'type': 'str',
                },
            'get_content_fail_error': {
                'type': 'str',
                },
            'concatenate_msg': {
                'type': 'str',
                },
            'mem_alloc_fail_error': {
                'type': 'str',
                },
            'malform_request': {
                'type': 'str',
                },
            'src_header_filter_match': {
                'type': 'str',
                },
            'src_header_filter_not_match': {
                'type': 'str',
                },
            'src_header_filter_action_drop': {
                'type': 'str',
                },
            'src_header_filter_action_blacklist': {
                'type': 'str',
                },
            'src_header_filter_action_whitelist': {
                'type': 'str',
                },
            'src_header_filter_action_default_pass': {
                'type': 'str',
                },
            'src_dst_header_filter_match': {
                'type': 'str',
                },
            'src_dst_header_filter_not_match': {
                'type': 'str',
                },
            'src_dst_header_filter_action_drop': {
                'type': 'str',
                },
            'src_dst_header_filter_action_blacklist': {
                'type': 'str',
                },
            'src_dst_header_filter_action_whitelist': {
                'type': 'str',
                },
            'src_dst_header_filter_action_default_pass': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/l7-sip"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/l7-sip"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config):
    if existing_config:
        result["changed"] = True
    return result


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
    payload = utils.build_json("l7-sip", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["l7-sip"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["l7-sip-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["l7-sip"]["stats"] if info != "NotFound" else info
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
