#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_virtual_server_port_stats_waf
description:
    - Statistics for the object port
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
    protocol:
        description:
        - Key to identify parent object
        type: str
        required: True
    port_number:
        description:
        - Key to identify parent object
        type: str
        required: True
    virtual_server_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    name:
        description:
        - "WAF Template Name"
        type: str
        required: True
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            waf:
                description:
                - "Field waf"
                type: dict

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
    "name",
    "stats",
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
        'stats': {
            'type': 'dict',
            'waf': {
                'type': 'dict',
                'total_req': {
                    'type': 'str',
                },
                'req_allowed': {
                    'type': 'str',
                },
                'req_denied': {
                    'type': 'str',
                },
                'bot_check_succ': {
                    'type': 'str',
                },
                'bot_check_fail': {
                    'type': 'str',
                },
                'form_consistency_succ': {
                    'type': 'str',
                },
                'form_consistency_fail': {
                    'type': 'str',
                },
                'form_csrf_tag_succ': {
                    'type': 'str',
                },
                'form_csrf_tag_fail': {
                    'type': 'str',
                },
                'url_check_succ': {
                    'type': 'str',
                },
                'url_check_fail': {
                    'type': 'str',
                },
                'url_check_learn': {
                    'type': 'str',
                },
                'buf_ovf_url_len_fail': {
                    'type': 'str',
                },
                'buf_ovf_cookie_len_fail': {
                    'type': 'str',
                },
                'buf_ovf_hdrs_len_fail': {
                    'type': 'str',
                },
                'buf_ovf_post_size_fail': {
                    'type': 'str',
                },
                'max_cookies_fail': {
                    'type': 'str',
                },
                'max_hdrs_fail': {
                    'type': 'str',
                },
                'http_method_check_succ': {
                    'type': 'str',
                },
                'http_method_check_fail': {
                    'type': 'str',
                },
                'http_check_succ': {
                    'type': 'str',
                },
                'http_check_fail': {
                    'type': 'str',
                },
                'referer_check_succ': {
                    'type': 'str',
                },
                'referer_check_fail': {
                    'type': 'str',
                },
                'referer_check_redirect': {
                    'type': 'str',
                },
                'uri_wlist_succ': {
                    'type': 'str',
                },
                'uri_wlist_fail': {
                    'type': 'str',
                },
                'uri_blist_succ': {
                    'type': 'str',
                },
                'uri_blist_fail': {
                    'type': 'str',
                },
                'post_form_check_succ': {
                    'type': 'str',
                },
                'post_form_check_sanitize': {
                    'type': 'str',
                },
                'post_form_check_reject': {
                    'type': 'str',
                },
                'ccn_mask_amex': {
                    'type': 'str',
                },
                'ccn_mask_diners': {
                    'type': 'str',
                },
                'ccn_mask_visa': {
                    'type': 'str',
                },
                'ccn_mask_mastercard': {
                    'type': 'str',
                },
                'ccn_mask_discover': {
                    'type': 'str',
                },
                'ccn_mask_jcb': {
                    'type': 'str',
                },
                'ssn_mask': {
                    'type': 'str',
                },
                'pcre_mask': {
                    'type': 'str',
                },
                'cookie_encrypt_succ': {
                    'type': 'str',
                },
                'cookie_encrypt_fail': {
                    'type': 'str',
                },
                'cookie_encrypt_limit_exceeded': {
                    'type': 'str',
                },
                'cookie_encrypt_skip_rcache': {
                    'type': 'str',
                },
                'cookie_decrypt_succ': {
                    'type': 'str',
                },
                'cookie_decrypt_fail': {
                    'type': 'str',
                },
                'sqlia_chk_url_succ': {
                    'type': 'str',
                },
                'sqlia_chk_url_sanitize': {
                    'type': 'str',
                },
                'sqlia_chk_url_reject': {
                    'type': 'str',
                },
                'sqlia_chk_post_succ': {
                    'type': 'str',
                },
                'sqlia_chk_post_sanitize': {
                    'type': 'str',
                },
                'sqlia_chk_post_reject': {
                    'type': 'str',
                },
                'xss_chk_cookie_succ': {
                    'type': 'str',
                },
                'xss_chk_cookie_sanitize': {
                    'type': 'str',
                },
                'xss_chk_cookie_reject': {
                    'type': 'str',
                },
                'xss_chk_url_succ': {
                    'type': 'str',
                },
                'xss_chk_url_sanitize': {
                    'type': 'str',
                },
                'xss_chk_url_reject': {
                    'type': 'str',
                },
                'xss_chk_post_succ': {
                    'type': 'str',
                },
                'xss_chk_post_sanitize': {
                    'type': 'str',
                },
                'xss_chk_post_reject': {
                    'type': 'str',
                },
                'resp_code_hidden': {
                    'type': 'str',
                },
                'resp_hdrs_filtered': {
                    'type': 'str',
                },
                'learn_updates': {
                    'type': 'str',
                },
                'num_drops': {
                    'type': 'str',
                },
                'num_resets': {
                    'type': 'str',
                },
                'form_non_ssl_reject': {
                    'type': 'str',
                },
                'form_non_post_reject': {
                    'type': 'str',
                },
                'sess_check_none': {
                    'type': 'str',
                },
                'sess_check_succ': {
                    'type': 'str',
                },
                'sess_check_fail': {
                    'type': 'str',
                },
                'soap_check_succ': {
                    'type': 'str',
                },
                'soap_check_failure': {
                    'type': 'str',
                },
                'wsdl_fail': {
                    'type': 'str',
                },
                'wsdl_succ': {
                    'type': 'str',
                },
                'xml_schema_fail': {
                    'type': 'str',
                },
                'xml_schema_succ': {
                    'type': 'str',
                },
                'xml_sqlia_chk_fail': {
                    'type': 'str',
                },
                'xml_sqlia_chk_succ': {
                    'type': 'str',
                },
                'xml_xss_chk_fail': {
                    'type': 'str',
                },
                'xml_xss_chk_succ': {
                    'type': 'str',
                },
                'json_check_failure': {
                    'type': 'str',
                },
                'json_check_succ': {
                    'type': 'str',
                },
                'xml_check_failure': {
                    'type': 'str',
                },
                'xml_check_succ': {
                    'type': 'str',
                },
                'buf_ovf_cookie_value_len_fail': {
                    'type': 'str',
                },
                'buf_ovf_cookies_len_fail': {
                    'type': 'str',
                },
                'buf_ovf_hdr_name_len_fail': {
                    'type': 'str',
                },
                'buf_ovf_hdr_value_len_fail': {
                    'type': 'str',
                },
                'buf_ovf_max_data_parse_fail': {
                    'type': 'str',
                },
                'buf_ovf_line_len_fail': {
                    'type': 'str',
                },
                'buf_ovf_parameter_name_len_fail': {
                    'type': 'str',
                },
                'buf_ovf_parameter_value_len_fail': {
                    'type': 'str',
                },
                'buf_ovf_parameter_total_len_fail': {
                    'type': 'str',
                },
                'buf_ovf_query_len_fail': {
                    'type': 'str',
                },
                'max_entities_fail': {
                    'type': 'str',
                },
                'max_parameters_fail': {
                    'type': 'str',
                },
                'buf_ovf_cookie_name_len_fail': {
                    'type': 'str',
                },
                'xml_limit_attr': {
                    'type': 'str',
                },
                'xml_limit_attr_name_len': {
                    'type': 'str',
                },
                'xml_limit_attr_value_len': {
                    'type': 'str',
                },
                'xml_limit_cdata_len': {
                    'type': 'str',
                },
                'xml_limit_elem': {
                    'type': 'str',
                },
                'xml_limit_elem_child': {
                    'type': 'str',
                },
                'xml_limit_elem_depth': {
                    'type': 'str',
                },
                'xml_limit_elem_name_len': {
                    'type': 'str',
                },
                'xml_limit_entity_exp': {
                    'type': 'str',
                },
                'xml_limit_entity_exp_depth': {
                    'type': 'str',
                },
                'xml_limit_namespace': {
                    'type': 'str',
                },
                'xml_limit_namespace_uri_len': {
                    'type': 'str',
                },
                'json_limit_array_value_count': {
                    'type': 'str',
                },
                'json_limit_depth': {
                    'type': 'str',
                },
                'json_limit_object_member_count': {
                    'type': 'str',
                },
                'json_limit_string': {
                    'type': 'str',
                },
                'form_non_masked_password': {
                    'type': 'str',
                },
                'form_non_ssl_password': {
                    'type': 'str',
                },
                'form_password_autocomplete': {
                    'type': 'str',
                },
                'redirect_wlist_succ': {
                    'type': 'str',
                },
                'redirect_wlist_fail': {
                    'type': 'str',
                },
                'redirect_wlist_learn': {
                    'type': 'str',
                },
                'form_set_no_cache': {
                    'type': 'str',
                },
                'resp_denied': {
                    'type': 'str',
                },
                'sessions_alloc': {
                    'type': 'str',
                },
                'sessions_freed': {
                    'type': 'str',
                },
                'out_of_sessions': {
                    'type': 'str',
                },
                'too_many_sessions': {
                    'type': 'str',
                },
                'called': {
                    'type': 'str',
                },
                'permitted': {
                    'type': 'str',
                },
                'brute_force_success': {
                    'type': 'str',
                },
                'brute_force_fail': {
                    'type': 'str',
                },
                'challenge_cookie_sent': {
                    'type': 'str',
                },
                'challenge_javascript_sent': {
                    'type': 'str',
                },
                'challenge_captcha_sent': {
                    'type': 'str',
                }
            }
        }
    })
    # Parent keys
    rv.update(
        dict(
            protocol=dict(type='str', required=True),
            port_number=dict(type='str', required=True),
            virtual_server_name=dict(type='str', required=True),
        ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/virtual-server/{virtual_server_name}/port/{port_number}+{protocol}/stats?waf=true"

    f_dict = {}
    f_dict["protocol"] = module.params["protocol"]
    f_dict["port_number"] = module.params["port_number"]
    f_dict["virtual_server_name"] = module.params["virtual_server_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/virtual-server/{virtual_server_name}/port/{port_number}+{protocol}/stats?waf=true"

    f_dict = {}
    f_dict["protocol"] = module.params["protocol"]
    f_dict["port_number"] = module.params["port_number"]
    f_dict["virtual_server_name"] = module.params["virtual_server_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["port"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["port"].get(k) != v:
            change_results["changed"] = True
            config_changes["port"][k] = v

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
    payload = utils.build_json("port", module.params, AVAILABLE_PROPERTIES)
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
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
