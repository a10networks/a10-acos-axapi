#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_waf_global
description:
    - WAF global stats
short_description: Configures A10 waf.global
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
        - present
        - absent
        required: True
    a10_host:
        description:
        - Host for AXAPI authentication
        required: True
    a10_username:
        description:
        - Username for AXAPI authentication
        required: True
    a10_password:
        description:
        - Password for AXAPI authentication
        required: True
    a10_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_protocol:
        description:
        - Protocol for AXAPI authentication
        required: True
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'total_req'= Total Requests; 'req_allowed'= Requests Allowed; 'req_denied'= Requests Denied; 'bot_check_succ'= Botnet Check Success; 'bot_check_fail'= Botnet Check Failure; 'form_consistency_succ'= Form Consistency Success; 'form_consistency_fail'= Form Consistency Failure; 'form_csrf_tag_succ'= Form CSRF tag Success; 'form_csrf_tag_fail'= Form CSRF tag Failure; 'url_check_succ'= URL Check Success; 'url_check_fail'= URL Check Failure; 'url_check_learn'= URL Check Learn; 'buf_ovf_url_len_fail'= Buffer Overflow - URL Length Failure; 'buf_ovf_cookie_len_fail'= Buffer Overflow - Cookie Length Failure; 'buf_ovf_hdrs_len_fail'= Buffer Overflow - Headers length Failure; 'buf_ovf_post_size_fail'= Buffer Overflow - Post size Failure; 'max_cookies_fail'= Max Cookies Failure; 'max_hdrs_fail'= Max Headers Failure; 'http_method_check_succ'= Http Method Check Success; 'http_method_check_fail'= Http Method Check Failure; 'http_check_succ'= Http Check Success; 'http_check_fail'= Http Check Failure; 'referer_check_succ'= Referer Check Success; 'referer_check_fail'= Referer Check Failure; 'referer_check_redirect'= Referer Check Redirect; 'uri_wlist_succ'= URI White List Success; 'uri_wlist_fail'= URI White List Failure; 'uri_blist_succ'= URI Black List Success; 'uri_blist_fail'= URI Black List Failure; 'post_form_check_succ'= Post Form Check Success; 'post_form_check_sanitize'= Post Form Check Sanitized; 'post_form_check_reject'= Post Form Check Rejected; 'ccn_mask_amex'= Credit Card Number Mask Amex; 'ccn_mask_diners'= Credit Card Number Mask Diners; 'ccn_mask_visa'= Credit Card Number Mask Visa; 'ccn_mask_mastercard'= Credit Card Number Mask Mastercard; 'ccn_mask_discover'= Credit Card Number Mask Discover; 'ccn_mask_jcb'= Credit Card Number Mask Jcb; 'ssn_mask'= Social Security Number Mask; 'pcre_mask'= PCRE Mask; 'cookie_encrypt_succ'= Cookie Encrypt Success; 'cookie_encrypt_fail'= Cookie Encrypt Failure; 'cookie_encrypt_limit_exceeded'= Cookie Encrypt Limit Exceeded; 'cookie_encrypt_skip_rcache'= Cookie Encrypt Skip RCache; 'cookie_decrypt_succ'= Cookie Decrypt Success; 'cookie_decrypt_fail'= Cookie Decrypt Failure; 'sqlia_chk_url_succ'= SQLIA Check URL Success; 'sqlia_chk_url_sanitize'= SQLIA Check URL Sanitized; 'sqlia_chk_url_reject'= SQLIA Check URL Rejected; 'sqlia_chk_post_succ'= SQLIA Check Post Success; 'sqlia_chk_post_sanitize'= SQLIA Check Post Sanitized; 'sqlia_chk_post_reject'= SQLIA Check Post Rejected; 'xss_chk_cookie_succ'= XSS Check Cookie Success; 'xss_chk_cookie_sanitize'= XSS Check Cookie Sanitized; 'xss_chk_cookie_reject'= XSS Check Cookie Rejected; 'xss_chk_url_succ'= XSS Check URL Success; 'xss_chk_url_sanitize'= XSS Check URL Sanitized; 'xss_chk_url_reject'= XSS Check URL Rejected; 'xss_chk_post_succ'= XSS Check Post Success; 'xss_chk_post_sanitize'= XSS Check Post Sanitized; 'xss_chk_post_reject'= XSS Check Post Rejected; 'resp_code_hidden'= Response Code Hidden; 'resp_hdrs_filtered'= Response Headers Filtered; 'learn_updates'= Learning Updates; 'num_drops'= Number Drops; 'num_resets'= Number Resets; 'form_non_ssl_reject'= Form Non SSL Rejected; 'form_non_post_reject'= Form Non Post Rejected; 'sess_check_none'= Session Check None; 'sess_check_succ'= Session Check Success; 'sess_check_fail'= Session Check Failure; 'soap_check_succ'= Soap Check Success; 'soap_check_failure'= Soap Check Failure; 'wsdl_fail'= WSDL Failure; 'wsdl_succ'= WSDL Success; 'xml_schema_fail'= XML Schema Failure; 'xml_schema_succ'= XML Schema Success; 'xml_sqlia_chk_fail'= XML Sqlia Check Failure; 'xml_sqlia_chk_succ'= XML Sqlia Check Success; 'xml_xss_chk_fail'= XML XSS Check Failure; 'xml_xss_chk_succ'= XML XSS Check Success; 'json_check_failure'= JSON Check Failure; 'json_check_succ'= JSON Check Success; 'xml_check_failure'= XML Check Failure; 'xml_check_succ'= XML Check Success; 'buf_ovf_cookie_value_len_fail'= Buffer Overflow - Cookie Value Length Failure; 'buf_ovf_cookies_len_fail'= Buffer Overflow - Cookies Length Failure; 'buf_ovf_hdr_name_len_fail'= Buffer Overflow - Header Name Length Failure; 'buf_ovf_hdr_value_len_fail'= Buffer Overflow - Header Value Length Failure; 'buf_ovf_max_data_parse_fail'= Buffer Overflow - Max Data Parse Failure; 'buf_ovf_line_len_fail'= Buffer Overflow - Line Length Failure; 'buf_ovf_parameter_name_len_fail'= Buffer Overflow - HTML Parameter Name Length Failure; 'buf_ovf_parameter_value_len_fail'= Buffer Overflow - HTML Parameter Value Length Failure; 'buf_ovf_parameter_total_len_fail'= Buffer Overflow - HTML Parameter Total Length Failure; 'buf_ovf_query_len_fail'= Buffer Overflow - Query Length Failure; 'max_entities_fail'= Max Entities Failure; 'max_parameters_fail'= Max Parameters Failure; 'buf_ovf_cookie_name_len_fail'= Buffer Overflow - Cookie Name Length Failure; 'xml_limit_attr'= XML Limit Attribue; 'xml_limit_attr_name_len'= XML Limit Name Length; 'xml_limit_attr_value_len'= XML Limit Value Length; 'xml_limit_cdata_len'= XML Limit CData Length; 'xml_limit_elem'= XML Limit Element; 'xml_limit_elem_child'= XML Limit Element Child; 'xml_limit_elem_depth'= XML Limit Element Depth; 'xml_limit_elem_name_len'= XML Limit Element Name Length; 'xml_limit_entity_exp'= XML Limit Entity Exp; 'xml_limit_entity_exp_depth'= XML Limit Entity Exp Depth; 'xml_limit_namespace'= XML Limit Namespace; 'xml_limit_namespace_uri_len'= XML Limit Namespace URI Length; 'json_limit_array_value_count'= JSON Limit Array Value Count; 'json_limit_depth'= JSON Limit Depth; 'json_limit_object_member_count'= JSON Limit Object Number Count; 'json_limit_string'= JSON Limit String; 'form_non_masked_password'= Form Non Masked Password; 'form_non_ssl_password'= Form Non SSL Password; 'form_password_autocomplete'= Form Password Autocomplete; 'redirect_wlist_succ'= Redirect Whitelist Success; 'redirect_wlist_fail'= Redirect Whitelist Failure; 'redirect_wlist_learn'= Redirect Whitelist Learn; 'form_set_no_cache'= Form Set No Cache; 'resp_denied'= Responses Denied; 'sessions_alloc'= Sessions allocated; 'sessions_freed'= Sessions freed; 'out_of_sessions'= Out of sessions; 'too_many_sessions'= Too many sessions consumed; 'called'= Threshold check count; 'permitted'= Honor threshold  count; 'brute_force_success'= Brute-force checks passed; 'brute_force_fail'= Brute-force checks failed; 'challenge_cookie_sent'= Cookie challenge sent; 'challenge_javascript_sent'= JavaScript challenge sent; 'challenge_captcha_sent'= Captcha challenge sent; "
    uuid:
        description:
        - "uuid of the object"
        required: False


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["sampling_enable","uuid",]

# our imports go at the top so we fail fast.
try:
    from a10_ansible import errors as a10_ex
    from a10_ansible.axapi_http import client_factory, session_factory
    from a10_ansible.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=["present", "absent", "noop"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','total_req','req_allowed','req_denied','bot_check_succ','bot_check_fail','form_consistency_succ','form_consistency_fail','form_csrf_tag_succ','form_csrf_tag_fail','url_check_succ','url_check_fail','url_check_learn','buf_ovf_url_len_fail','buf_ovf_cookie_len_fail','buf_ovf_hdrs_len_fail','buf_ovf_post_size_fail','max_cookies_fail','max_hdrs_fail','http_method_check_succ','http_method_check_fail','http_check_succ','http_check_fail','referer_check_succ','referer_check_fail','referer_check_redirect','uri_wlist_succ','uri_wlist_fail','uri_blist_succ','uri_blist_fail','post_form_check_succ','post_form_check_sanitize','post_form_check_reject','ccn_mask_amex','ccn_mask_diners','ccn_mask_visa','ccn_mask_mastercard','ccn_mask_discover','ccn_mask_jcb','ssn_mask','pcre_mask','cookie_encrypt_succ','cookie_encrypt_fail','cookie_encrypt_limit_exceeded','cookie_encrypt_skip_rcache','cookie_decrypt_succ','cookie_decrypt_fail','sqlia_chk_url_succ','sqlia_chk_url_sanitize','sqlia_chk_url_reject','sqlia_chk_post_succ','sqlia_chk_post_sanitize','sqlia_chk_post_reject','xss_chk_cookie_succ','xss_chk_cookie_sanitize','xss_chk_cookie_reject','xss_chk_url_succ','xss_chk_url_sanitize','xss_chk_url_reject','xss_chk_post_succ','xss_chk_post_sanitize','xss_chk_post_reject','resp_code_hidden','resp_hdrs_filtered','learn_updates','num_drops','num_resets','form_non_ssl_reject','form_non_post_reject','sess_check_none','sess_check_succ','sess_check_fail','soap_check_succ','soap_check_failure','wsdl_fail','wsdl_succ','xml_schema_fail','xml_schema_succ','xml_sqlia_chk_fail','xml_sqlia_chk_succ','xml_xss_chk_fail','xml_xss_chk_succ','json_check_failure','json_check_succ','xml_check_failure','xml_check_succ','buf_ovf_cookie_value_len_fail','buf_ovf_cookies_len_fail','buf_ovf_hdr_name_len_fail','buf_ovf_hdr_value_len_fail','buf_ovf_max_data_parse_fail','buf_ovf_line_len_fail','buf_ovf_parameter_name_len_fail','buf_ovf_parameter_value_len_fail','buf_ovf_parameter_total_len_fail','buf_ovf_query_len_fail','max_entities_fail','max_parameters_fail','buf_ovf_cookie_name_len_fail','xml_limit_attr','xml_limit_attr_name_len','xml_limit_attr_value_len','xml_limit_cdata_len','xml_limit_elem','xml_limit_elem_child','xml_limit_elem_depth','xml_limit_elem_name_len','xml_limit_entity_exp','xml_limit_entity_exp_depth','xml_limit_namespace','xml_limit_namespace_uri_len','json_limit_array_value_count','json_limit_depth','json_limit_object_member_count','json_limit_string','form_non_masked_password','form_non_ssl_password','form_password_autocomplete','redirect_wlist_succ','redirect_wlist_fail','redirect_wlist_learn','form_set_no_cache','resp_denied','sessions_alloc','sessions_freed','out_of_sessions','too_many_sessions','called','permitted','brute_force_success','brute_force_fail','challenge_cookie_sent','challenge_javascript_sent','challenge_captcha_sent'])),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/waf/global"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/waf/global"

    f_dict = {}

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

def build_envelope(title, data):
    return {
        title: data
    }

def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")

def _build_dict_from_param(param):
    rv = {}

    for k,v in param.items():
        hk = _to_axapi(k)
        if isinstance(v, dict):
            v_dict = _build_dict_from_param(v)
            rv[hk] = v_dict
        elif isinstance(v, list):
            nv = [_build_dict_from_param(x) for x in v]
            rv[hk] = nv
        else:
            rv[hk] = v

    return rv

def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v:
            rx = _to_axapi(x)

            if isinstance(v, dict):
                nv = _build_dict_from_param(v)
                rv[rx] = nv
            elif isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params and params.get(x) is not None])
    
    errors = []
    marg = []
    
    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc,msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc,msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc,msg = REQUIRED_VALID
    
    if not rc:
        errors.append(msg.format(", ".join(marg)))
    
    return rc,errors

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def get_oper(module):
    return module.client.get(oper_url(module))

def get_stats(module):
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["global"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["global"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["global"][k] = v
        result.update(**existing_config)
    else:
        result.update(**payload)
    return result

def create(module, result, payload):
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.Exists:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def delete(module, result):
    try:
        module.client.delete(existing_url(module))
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def update(module, result, existing_config, payload):
    try:
        post_result = module.client.post(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result, existing_config):
    payload = build_json("global", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result, existing_config):
    if module.check_mode:
        if existing_config:
            result["changed"] = True
            return result
        else:
            result["changed"] = False
            return result
    else:
        return delete(module, result)

def replace(module, result, existing_config, payload):
    try:
        post_result = module.client.put(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def run_command(module):
    run_errors = []

    result = dict(
        changed=False,
        original_message="",
        message="",
        result={}
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]
    a10_partition = module.params["a10_partition"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    if a10_partition:
        module.client.activate_partition(a10_partition)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result, existing_config)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()