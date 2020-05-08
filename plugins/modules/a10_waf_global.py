#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
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
          - noop
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
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
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
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            redirect_wlist_fail:
                description:
                - "Redirect Whitelist Failure"
            cookie_encrypt_limit_exceeded:
                description:
                - "Cookie Encrypt Limit Exceeded"
            wsdl_succ:
                description:
                - "WSDL Success"
            sqlia_chk_url_succ:
                description:
                - "SQLIA Check URL Success"
            bot_check_succ:
                description:
                - "Botnet Check Success"
            cookie_encrypt_skip_rcache:
                description:
                - "Cookie Encrypt Skip RCache"
            redirect_wlist_learn:
                description:
                - "Redirect Whitelist Learn"
            xml_limit_elem_child:
                description:
                - "XML Limit Element Child"
            buf_ovf_parameter_value_len_fail:
                description:
                - "Buffer Overflow - HTML Parameter Value Length Failure"
            ccn_mask_visa:
                description:
                - "Credit Card Number Mask Visa"
            xss_chk_cookie_succ:
                description:
                - "XSS Check Cookie Success"
            buf_ovf_cookies_len_fail:
                description:
                - "Buffer Overflow - Cookies Length Failure"
            req_denied:
                description:
                - "Requests Denied"
            json_check_failure:
                description:
                - "JSON Check Failure"
            xss_chk_post_reject:
                description:
                - "XSS Check Post Rejected"
            http_check_succ:
                description:
                - "Http Check Success"
            form_consistency_succ:
                description:
                - "Form Consistency Success"
            xml_limit_cdata_len:
                description:
                - "XML Limit CData Length"
            xml_check_failure:
                description:
                - "XML Check Failure"
            buf_ovf_hdrs_len_fail:
                description:
                - "Buffer Overflow - Headers length Failure"
            referer_check_succ:
                description:
                - "Referer Check Success"
            sqlia_chk_post_succ:
                description:
                - "SQLIA Check Post Success"
            xss_chk_url_sanitize:
                description:
                - "XSS Check URL Sanitized"
            cookie_encrypt_succ:
                description:
                - "Cookie Encrypt Success"
            buf_ovf_parameter_total_len_fail:
                description:
                - "Buffer Overflow - HTML Parameter Total Length Failure"
            soap_check_succ:
                description:
                - "Soap Check Success"
            max_cookies_fail:
                description:
                - "Max Cookies Failure"
            json_limit_array_value_count:
                description:
                - "JSON Limit Array Value Count"
            uri_wlist_succ:
                description:
                - "URI White List Success"
            brute_force_success:
                description:
                - "Brute-force checks passed"
            resp_code_hidden:
                description:
                - "Response Code Hidden"
            xml_sqlia_chk_fail:
                description:
                - "XML Sqlia Check Failure"
            xss_chk_post_succ:
                description:
                - "XSS Check Post Success"
            pcre_mask:
                description:
                - "PCRE Mask"
            form_consistency_fail:
                description:
                - "Form Consistency Failure"
            http_check_fail:
                description:
                - "Http Check Failure"
            url_check_succ:
                description:
                - "URL Check Success"
            sqlia_chk_url_reject:
                description:
                - "SQLIA Check URL Rejected"
            sqlia_chk_url_sanitize:
                description:
                - "SQLIA Check URL Sanitized"
            xss_chk_cookie_reject:
                description:
                - "XSS Check Cookie Rejected"
            json_check_succ:
                description:
                - "JSON Check Success"
            max_entities_fail:
                description:
                - "Max Entities Failure"
            http_method_check_fail:
                description:
                - "Http Method Check Failure"
            form_non_ssl_reject:
                description:
                - "Form Non SSL Rejected"
            xss_chk_post_sanitize:
                description:
                - "XSS Check Post Sanitized"
            form_set_no_cache:
                description:
                - "Form Set No Cache"
            xml_schema_succ:
                description:
                - "XML Schema Success"
            xml_limit_attr:
                description:
                - "XML Limit Attribue"
            xml_check_succ:
                description:
                - "XML Check Success"
            sess_check_none:
                description:
                - "Session Check None"
            xml_limit_namespace:
                description:
                - "XML Limit Namespace"
            wsdl_fail:
                description:
                - "WSDL Failure"
            post_form_check_succ:
                description:
                - "Post Form Check Success"
            buf_ovf_query_len_fail:
                description:
                - "Buffer Overflow - Query Length Failure"
            sqlia_chk_post_reject:
                description:
                - "SQLIA Check Post Rejected"
            form_password_autocomplete:
                description:
                - "Form Password Autocomplete"
            permitted:
                description:
                - "Honor threshold  count"
            xml_xss_chk_fail:
                description:
                - "XML XSS Check Failure"
            buf_ovf_url_len_fail:
                description:
                - "Buffer Overflow - URL Length Failure"
            buf_ovf_cookie_len_fail:
                description:
                - "Buffer Overflow - Cookie Length Failure"
            form_csrf_tag_succ:
                description:
                - "Form CSRF tag Success"
            xss_chk_cookie_sanitize:
                description:
                - "XSS Check Cookie Sanitized"
            sessions_alloc:
                description:
                - "Sessions allocated"
            xml_limit_entity_exp:
                description:
                - "XML Limit Entity Exp"
            ccn_mask_diners:
                description:
                - "Credit Card Number Mask Diners"
            sess_check_succ:
                description:
                - "Session Check Success"
            json_limit_depth:
                description:
                - "JSON Limit Depth"
            buf_ovf_cookie_name_len_fail:
                description:
                - "Buffer Overflow - Cookie Name Length Failure"
            learn_updates:
                description:
                - "Learning Updates"
            redirect_wlist_succ:
                description:
                - "Redirect Whitelist Success"
            challenge_javascript_sent:
                description:
                - "JavaScript challenge sent"
            req_allowed:
                description:
                - "Requests Allowed"
            json_limit_object_member_count:
                description:
                - "JSON Limit Object Number Count"
            bot_check_fail:
                description:
                - "Botnet Check Failure"
            uri_wlist_fail:
                description:
                - "URI White List Failure"
            uri_blist_fail:
                description:
                - "URI Black List Failure"
            referer_check_redirect:
                description:
                - "Referer Check Redirect"
            challenge_cookie_sent:
                description:
                - "Cookie challenge sent"
            sqlia_chk_post_sanitize:
                description:
                - "SQLIA Check Post Sanitized"
            ccn_mask_amex:
                description:
                - "Credit Card Number Mask Amex"
            num_drops:
                description:
                - "Number Drops"
            referer_check_fail:
                description:
                - "Referer Check Failure"
            post_form_check_sanitize:
                description:
                - "Post Form Check Sanitized"
            cookie_decrypt_succ:
                description:
                - "Cookie Decrypt Success"
            xss_chk_url_reject:
                description:
                - "XSS Check URL Rejected"
            max_parameters_fail:
                description:
                - "Max Parameters Failure"
            url_check_fail:
                description:
                - "URL Check Failure"
            xml_schema_fail:
                description:
                - "XML Schema Failure"
            form_non_post_reject:
                description:
                - "Form Non Post Rejected"
            num_resets:
                description:
                - "Number Resets"
            xml_limit_entity_exp_depth:
                description:
                - "XML Limit Entity Exp Depth"
            form_non_masked_password:
                description:
                - "Form Non Masked Password"
            buf_ovf_line_len_fail:
                description:
                - "Buffer Overflow - Line Length Failure"
            ccn_mask_discover:
                description:
                - "Credit Card Number Mask Discover"
            ssn_mask:
                description:
                - "Social Security Number Mask"
            json_limit_string:
                description:
                - "JSON Limit String"
            resp_hdrs_filtered:
                description:
                - "Response Headers Filtered"
            called:
                description:
                - "Threshold check count"
            ccn_mask_mastercard:
                description:
                - "Credit Card Number Mask Mastercard"
            xml_sqlia_chk_succ:
                description:
                - "XML Sqlia Check Success"
            brute_force_fail:
                description:
                - "Brute-force checks failed"
            max_hdrs_fail:
                description:
                - "Max Headers Failure"
            xml_limit_attr_name_len:
                description:
                - "XML Limit Name Length"
            form_non_ssl_password:
                description:
                - "Form Non SSL Password"
            too_many_sessions:
                description:
                - "Too many sessions consumed"
            buf_ovf_hdr_value_len_fail:
                description:
                - "Buffer Overflow - Header Value Length Failure"
            uri_blist_succ:
                description:
                - "URI Black List Success"
            sess_check_fail:
                description:
                - "Session Check Failure"
            buf_ovf_hdr_name_len_fail:
                description:
                - "Buffer Overflow - Header Name Length Failure"
            resp_denied:
                description:
                - "Responses Denied"
            sessions_freed:
                description:
                - "Sessions freed"
            out_of_sessions:
                description:
                - "Out of sessions"
            xml_limit_elem:
                description:
                - "XML Limit Element"
            buf_ovf_parameter_name_len_fail:
                description:
                - "Buffer Overflow - HTML Parameter Name Length Failure"
            xml_limit_attr_value_len:
                description:
                - "XML Limit Value Length"
            xml_limit_elem_depth:
                description:
                - "XML Limit Element Depth"
            ccn_mask_jcb:
                description:
                - "Credit Card Number Mask Jcb"
            cookie_decrypt_fail:
                description:
                - "Cookie Decrypt Failure"
            buf_ovf_cookie_value_len_fail:
                description:
                - "Buffer Overflow - Cookie Value Length Failure"
            buf_ovf_post_size_fail:
                description:
                - "Buffer Overflow - Post size Failure"
            total_req:
                description:
                - "Total Requests"
            xml_limit_elem_name_len:
                description:
                - "XML Limit Element Name Length"
            url_check_learn:
                description:
                - "URL Check Learn"
            http_method_check_succ:
                description:
                - "Http Method Check Success"
            xss_chk_url_succ:
                description:
                - "XSS Check URL Success"
            xml_limit_namespace_uri_len:
                description:
                - "XML Limit Namespace URI Length"
            post_form_check_reject:
                description:
                - "Post Form Check Rejected"
            cookie_encrypt_fail:
                description:
                - "Cookie Encrypt Failure"
            soap_check_failure:
                description:
                - "Soap Check Failure"
            challenge_captcha_sent:
                description:
                - "Captcha challenge sent"
            form_csrf_tag_fail:
                description:
                - "Form CSRF tag Failure"
            xml_xss_chk_succ:
                description:
                - "XML XSS Check Success"
            buf_ovf_max_data_parse_fail:
                description:
                - "Buffer Overflow - Max Data Parse Failure"
    uuid:
        description:
        - "uuid of the object"
        required: False


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["sampling_enable","stats","uuid",]

# our imports go at the top so we fail fast.
try:
    from ansible_collections.a10.acos_axapi.plugins.module_utils import errors as a10_ex
    from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import client_factory, session_factory
    from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'total_req', 'req_allowed', 'req_denied', 'bot_check_succ', 'bot_check_fail', 'form_consistency_succ', 'form_consistency_fail', 'form_csrf_tag_succ', 'form_csrf_tag_fail', 'url_check_succ', 'url_check_fail', 'url_check_learn', 'buf_ovf_url_len_fail', 'buf_ovf_cookie_len_fail', 'buf_ovf_hdrs_len_fail', 'buf_ovf_post_size_fail', 'max_cookies_fail', 'max_hdrs_fail', 'http_method_check_succ', 'http_method_check_fail', 'http_check_succ', 'http_check_fail', 'referer_check_succ', 'referer_check_fail', 'referer_check_redirect', 'uri_wlist_succ', 'uri_wlist_fail', 'uri_blist_succ', 'uri_blist_fail', 'post_form_check_succ', 'post_form_check_sanitize', 'post_form_check_reject', 'ccn_mask_amex', 'ccn_mask_diners', 'ccn_mask_visa', 'ccn_mask_mastercard', 'ccn_mask_discover', 'ccn_mask_jcb', 'ssn_mask', 'pcre_mask', 'cookie_encrypt_succ', 'cookie_encrypt_fail', 'cookie_encrypt_limit_exceeded', 'cookie_encrypt_skip_rcache', 'cookie_decrypt_succ', 'cookie_decrypt_fail', 'sqlia_chk_url_succ', 'sqlia_chk_url_sanitize', 'sqlia_chk_url_reject', 'sqlia_chk_post_succ', 'sqlia_chk_post_sanitize', 'sqlia_chk_post_reject', 'xss_chk_cookie_succ', 'xss_chk_cookie_sanitize', 'xss_chk_cookie_reject', 'xss_chk_url_succ', 'xss_chk_url_sanitize', 'xss_chk_url_reject', 'xss_chk_post_succ', 'xss_chk_post_sanitize', 'xss_chk_post_reject', 'resp_code_hidden', 'resp_hdrs_filtered', 'learn_updates', 'num_drops', 'num_resets', 'form_non_ssl_reject', 'form_non_post_reject', 'sess_check_none', 'sess_check_succ', 'sess_check_fail', 'soap_check_succ', 'soap_check_failure', 'wsdl_fail', 'wsdl_succ', 'xml_schema_fail', 'xml_schema_succ', 'xml_sqlia_chk_fail', 'xml_sqlia_chk_succ', 'xml_xss_chk_fail', 'xml_xss_chk_succ', 'json_check_failure', 'json_check_succ', 'xml_check_failure', 'xml_check_succ', 'buf_ovf_cookie_value_len_fail', 'buf_ovf_cookies_len_fail', 'buf_ovf_hdr_name_len_fail', 'buf_ovf_hdr_value_len_fail', 'buf_ovf_max_data_parse_fail', 'buf_ovf_line_len_fail', 'buf_ovf_parameter_name_len_fail', 'buf_ovf_parameter_value_len_fail', 'buf_ovf_parameter_total_len_fail', 'buf_ovf_query_len_fail', 'max_entities_fail', 'max_parameters_fail', 'buf_ovf_cookie_name_len_fail', 'xml_limit_attr', 'xml_limit_attr_name_len', 'xml_limit_attr_value_len', 'xml_limit_cdata_len', 'xml_limit_elem', 'xml_limit_elem_child', 'xml_limit_elem_depth', 'xml_limit_elem_name_len', 'xml_limit_entity_exp', 'xml_limit_entity_exp_depth', 'xml_limit_namespace', 'xml_limit_namespace_uri_len', 'json_limit_array_value_count', 'json_limit_depth', 'json_limit_object_member_count', 'json_limit_string', 'form_non_masked_password', 'form_non_ssl_password', 'form_password_autocomplete', 'redirect_wlist_succ', 'redirect_wlist_fail', 'redirect_wlist_learn', 'form_set_no_cache', 'resp_denied', 'sessions_alloc', 'sessions_freed', 'out_of_sessions', 'too_many_sessions', 'called', 'permitted', 'brute_force_success', 'brute_force_fail', 'challenge_cookie_sent', 'challenge_javascript_sent', 'challenge_captcha_sent'])),
        stats=dict(type='dict', redirect_wlist_fail=dict(type='str', ), cookie_encrypt_limit_exceeded=dict(type='str', ), wsdl_succ=dict(type='str', ), sqlia_chk_url_succ=dict(type='str', ), bot_check_succ=dict(type='str', ), cookie_encrypt_skip_rcache=dict(type='str', ), redirect_wlist_learn=dict(type='str', ), xml_limit_elem_child=dict(type='str', ), buf_ovf_parameter_value_len_fail=dict(type='str', ), ccn_mask_visa=dict(type='str', ), xss_chk_cookie_succ=dict(type='str', ), buf_ovf_cookies_len_fail=dict(type='str', ), req_denied=dict(type='str', ), json_check_failure=dict(type='str', ), xss_chk_post_reject=dict(type='str', ), http_check_succ=dict(type='str', ), form_consistency_succ=dict(type='str', ), xml_limit_cdata_len=dict(type='str', ), xml_check_failure=dict(type='str', ), buf_ovf_hdrs_len_fail=dict(type='str', ), referer_check_succ=dict(type='str', ), sqlia_chk_post_succ=dict(type='str', ), xss_chk_url_sanitize=dict(type='str', ), cookie_encrypt_succ=dict(type='str', ), buf_ovf_parameter_total_len_fail=dict(type='str', ), soap_check_succ=dict(type='str', ), max_cookies_fail=dict(type='str', ), json_limit_array_value_count=dict(type='str', ), uri_wlist_succ=dict(type='str', ), brute_force_success=dict(type='str', ), resp_code_hidden=dict(type='str', ), xml_sqlia_chk_fail=dict(type='str', ), xss_chk_post_succ=dict(type='str', ), pcre_mask=dict(type='str', ), form_consistency_fail=dict(type='str', ), http_check_fail=dict(type='str', ), url_check_succ=dict(type='str', ), sqlia_chk_url_reject=dict(type='str', ), sqlia_chk_url_sanitize=dict(type='str', ), xss_chk_cookie_reject=dict(type='str', ), json_check_succ=dict(type='str', ), max_entities_fail=dict(type='str', ), http_method_check_fail=dict(type='str', ), form_non_ssl_reject=dict(type='str', ), xss_chk_post_sanitize=dict(type='str', ), form_set_no_cache=dict(type='str', ), xml_schema_succ=dict(type='str', ), xml_limit_attr=dict(type='str', ), xml_check_succ=dict(type='str', ), sess_check_none=dict(type='str', ), xml_limit_namespace=dict(type='str', ), wsdl_fail=dict(type='str', ), post_form_check_succ=dict(type='str', ), buf_ovf_query_len_fail=dict(type='str', ), sqlia_chk_post_reject=dict(type='str', ), form_password_autocomplete=dict(type='str', ), permitted=dict(type='str', ), xml_xss_chk_fail=dict(type='str', ), buf_ovf_url_len_fail=dict(type='str', ), buf_ovf_cookie_len_fail=dict(type='str', ), form_csrf_tag_succ=dict(type='str', ), xss_chk_cookie_sanitize=dict(type='str', ), sessions_alloc=dict(type='str', ), xml_limit_entity_exp=dict(type='str', ), ccn_mask_diners=dict(type='str', ), sess_check_succ=dict(type='str', ), json_limit_depth=dict(type='str', ), buf_ovf_cookie_name_len_fail=dict(type='str', ), learn_updates=dict(type='str', ), redirect_wlist_succ=dict(type='str', ), challenge_javascript_sent=dict(type='str', ), req_allowed=dict(type='str', ), json_limit_object_member_count=dict(type='str', ), bot_check_fail=dict(type='str', ), uri_wlist_fail=dict(type='str', ), uri_blist_fail=dict(type='str', ), referer_check_redirect=dict(type='str', ), challenge_cookie_sent=dict(type='str', ), sqlia_chk_post_sanitize=dict(type='str', ), ccn_mask_amex=dict(type='str', ), num_drops=dict(type='str', ), referer_check_fail=dict(type='str', ), post_form_check_sanitize=dict(type='str', ), cookie_decrypt_succ=dict(type='str', ), xss_chk_url_reject=dict(type='str', ), max_parameters_fail=dict(type='str', ), url_check_fail=dict(type='str', ), xml_schema_fail=dict(type='str', ), form_non_post_reject=dict(type='str', ), num_resets=dict(type='str', ), xml_limit_entity_exp_depth=dict(type='str', ), form_non_masked_password=dict(type='str', ), buf_ovf_line_len_fail=dict(type='str', ), ccn_mask_discover=dict(type='str', ), ssn_mask=dict(type='str', ), json_limit_string=dict(type='str', ), resp_hdrs_filtered=dict(type='str', ), called=dict(type='str', ), ccn_mask_mastercard=dict(type='str', ), xml_sqlia_chk_succ=dict(type='str', ), brute_force_fail=dict(type='str', ), max_hdrs_fail=dict(type='str', ), xml_limit_attr_name_len=dict(type='str', ), form_non_ssl_password=dict(type='str', ), too_many_sessions=dict(type='str', ), buf_ovf_hdr_value_len_fail=dict(type='str', ), uri_blist_succ=dict(type='str', ), sess_check_fail=dict(type='str', ), buf_ovf_hdr_name_len_fail=dict(type='str', ), resp_denied=dict(type='str', ), sessions_freed=dict(type='str', ), out_of_sessions=dict(type='str', ), xml_limit_elem=dict(type='str', ), buf_ovf_parameter_name_len_fail=dict(type='str', ), xml_limit_attr_value_len=dict(type='str', ), xml_limit_elem_depth=dict(type='str', ), ccn_mask_jcb=dict(type='str', ), cookie_decrypt_fail=dict(type='str', ), buf_ovf_cookie_value_len_fail=dict(type='str', ), buf_ovf_post_size_fail=dict(type='str', ), total_req=dict(type='str', ), xml_limit_elem_name_len=dict(type='str', ), url_check_learn=dict(type='str', ), http_method_check_succ=dict(type='str', ), xss_chk_url_succ=dict(type='str', ), xml_limit_namespace_uri_len=dict(type='str', ), post_form_check_reject=dict(type='str', ), cookie_encrypt_fail=dict(type='str', ), soap_check_failure=dict(type='str', ), challenge_captcha_sent=dict(type='str', ), form_csrf_tag_fail=dict(type='str', ), xml_xss_chk_succ=dict(type='str', ), buf_ovf_max_data_parse_fail=dict(type='str', )),
        uuid=dict(type='str', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/waf/global"

    f_dict = {}

    return url_base.format(**f_dict)

def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k,v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module),
                                 params=query_params)
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

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

def build_envelope(title, data):
    return {
        title: data
    }

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/waf/global"

    f_dict = {}

    return url_base.format(**f_dict)

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

def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v is not None:
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

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["global"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
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
    changed_config = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return changed_config
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and not changed_config.get('changed'):
        return update(module, result, existing_config, payload)
    else:
        result["changed"] = True
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
    a10_device_context_id = module.params["a10_device_context_id"]

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

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)
    
    if state == 'present':
        result = present(module, result, existing_config)

    elif state == 'absent':
        result = absent(module, result, existing_config)
    
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
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