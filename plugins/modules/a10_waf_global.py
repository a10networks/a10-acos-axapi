#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_waf_global
description:
    - WAF global stats
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
                - "'all'= all; 'total_req'= Total Requests; 'req_allowed'= Requests Allowed;
          'req_denied'= Requests Denied; 'bot_check_succ'= Botnet Check Success;
          'bot_check_fail'= Botnet Check Failure; 'form_consistency_succ'= Form
          Consistency Success; 'form_consistency_fail'= Form Consistency Failure;
          'form_csrf_tag_succ'= Form CSRF tag Success; 'form_csrf_tag_fail'= Form CSRF
          tag Failure; 'url_check_succ'= URL Check Success; 'url_check_fail'= URL Check
          Failure; 'url_check_learn'= URL Check Learn; 'buf_ovf_url_len_fail'= Buffer
          Overflow - URL Length Failure; 'buf_ovf_cookie_len_fail'= Buffer Overflow -
          Cookie Length Failure; 'buf_ovf_hdrs_len_fail'= Buffer Overflow - Headers
          length Failure; 'buf_ovf_post_size_fail'= Buffer Overflow - Post size Failure;
          'max_cookies_fail'= Max Cookies Failure; 'max_hdrs_fail'= Max Headers Failure;
          'http_method_check_succ'= Http Method Check Success; 'http_method_check_fail'=
          Http Method Check Failure; 'http_check_succ'= Http Check Success;
          'http_check_fail'= Http Check Failure; 'referer_check_succ'= Referer Check
          Success; 'referer_check_fail'= Referer Check Failure; 'referer_check_redirect'=
          Referer Check Redirect; 'uri_wlist_succ'= URI White List Success;
          'uri_wlist_fail'= URI White List Failure; 'uri_blist_succ'= URI Black List
          Success; 'uri_blist_fail'= URI Black List Failure; 'post_form_check_succ'= Post
          Form Check Success; 'post_form_check_sanitize'= Post Form Check Sanitized;
          'post_form_check_reject'= Post Form Check Rejected; 'ccn_mask_amex'= Credit
          Card Number Mask Amex; 'ccn_mask_diners'= Credit Card Number Mask Diners;
          'ccn_mask_visa'= Credit Card Number Mask Visa; 'ccn_mask_mastercard'= Credit
          Card Number Mask Mastercard; 'ccn_mask_discover'= Credit Card Number Mask
          Discover; 'ccn_mask_jcb'= Credit Card Number Mask Jcb; 'ssn_mask'= Social
          Security Number Mask; 'pcre_mask'= PCRE Mask; 'cookie_encrypt_succ'= Cookie
          Encrypt Success; 'cookie_encrypt_fail'= Cookie Encrypt Failure;
          'cookie_encrypt_limit_exceeded'= Cookie Encrypt Limit Exceeded;
          'cookie_encrypt_skip_rcache'= Cookie Encrypt Skip RCache;
          'cookie_decrypt_succ'= Cookie Decrypt Success; 'cookie_decrypt_fail'= Cookie
          Decrypt Failure; 'sqlia_chk_url_succ'= SQLIA Check URL Success;
          'sqlia_chk_url_sanitize'= SQLIA Check URL Sanitized; 'sqlia_chk_url_reject'=
          SQLIA Check URL Rejected; 'sqlia_chk_post_succ'= SQLIA Check Post Success;
          'sqlia_chk_post_sanitize'= SQLIA Check Post Sanitized; 'sqlia_chk_post_reject'=
          SQLIA Check Post Rejected; 'xss_chk_cookie_succ'= XSS Check Cookie Success;
          'xss_chk_cookie_sanitize'= XSS Check Cookie Sanitized; 'xss_chk_cookie_reject'=
          XSS Check Cookie Rejected; 'xss_chk_url_succ'= XSS Check URL Success;
          'xss_chk_url_sanitize'= XSS Check URL Sanitized; 'xss_chk_url_reject'= XSS
          Check URL Rejected; 'xss_chk_post_succ'= XSS Check Post Success;
          'xss_chk_post_sanitize'= XSS Check Post Sanitized; 'xss_chk_post_reject'= XSS
          Check Post Rejected; 'resp_code_hidden'= Response Code Hidden;
          'resp_hdrs_filtered'= Response Headers Filtered; 'learn_updates'= Learning
          Updates; 'num_drops'= Number Drops; 'num_resets'= Number Resets;
          'form_non_ssl_reject'= Form Non SSL Rejected; 'form_non_post_reject'= Form Non
          Post Rejected; 'sess_check_none'= Session Check None; 'sess_check_succ'=
          Session Check Success; 'sess_check_fail'= Session Check Failure;
          'soap_check_succ'= Soap Check Success; 'soap_check_failure'= Soap Check
          Failure; 'wsdl_fail'= WSDL Failure; 'wsdl_succ'= WSDL Success;
          'xml_schema_fail'= XML Schema Failure; 'xml_schema_succ'= XML Schema Success;
          'xml_sqlia_chk_fail'= XML Sqlia Check Failure; 'xml_sqlia_chk_succ'= XML Sqlia
          Check Success; 'xml_xss_chk_fail'= XML XSS Check Failure; 'xml_xss_chk_succ'=
          XML XSS Check Success; 'json_check_failure'= JSON Check Failure;
          'json_check_succ'= JSON Check Success; 'xml_check_failure'= XML Check Failure;
          'xml_check_succ'= XML Check Success; 'buf_ovf_cookie_value_len_fail'= Buffer
          Overflow - Cookie Value Length Failure; 'buf_ovf_cookies_len_fail'= Buffer
          Overflow - Cookies Length Failure; 'buf_ovf_hdr_name_len_fail'= Buffer Overflow
          - Header Name Length Failure; 'buf_ovf_hdr_value_len_fail'= Buffer Overflow -
          Header Value Length Failure; 'buf_ovf_max_data_parse_fail'= Buffer Overflow -
          Max Data Parse Failure; 'buf_ovf_line_len_fail'= Buffer Overflow - Line Length
          Failure; 'buf_ovf_parameter_name_len_fail'= Buffer Overflow - HTML Parameter
          Name Length Failure; 'buf_ovf_parameter_value_len_fail'= Buffer Overflow - HTML
          Parameter Value Length Failure; 'buf_ovf_parameter_total_len_fail'= Buffer
          Overflow - HTML Parameter Total Length Failure; 'buf_ovf_query_len_fail'=
          Buffer Overflow - Query Length Failure; 'max_entities_fail'= Max Entities
          Failure; 'max_parameters_fail'= Max Parameters Failure;
          'buf_ovf_cookie_name_len_fail'= Buffer Overflow - Cookie Name Length Failure;
          'xml_limit_attr'= XML Limit Attribue; 'xml_limit_attr_name_len'= XML Limit Name
          Length; 'xml_limit_attr_value_len'= XML Limit Value Length;
          'xml_limit_cdata_len'= XML Limit CData Length; 'xml_limit_elem'= XML Limit
          Element; 'xml_limit_elem_child'= XML Limit Element Child;
          'xml_limit_elem_depth'= XML Limit Element Depth; 'xml_limit_elem_name_len'= XML
          Limit Element Name Length; 'xml_limit_entity_exp'= XML Limit Entity Exp;
          'xml_limit_entity_exp_depth'= XML Limit Entity Exp Depth;
          'xml_limit_namespace'= XML Limit Namespace; 'xml_limit_namespace_uri_len'= XML
          Limit Namespace URI Length; 'json_limit_array_value_count'= JSON Limit Array
          Value Count; 'json_limit_depth'= JSON Limit Depth;
          'json_limit_object_member_count'= JSON Limit Object Number Count;
          'json_limit_string'= JSON Limit String; 'form_non_masked_password'= Form Non
          Masked Password; 'form_non_ssl_password'= Form Non SSL Password;
          'form_password_autocomplete'= Form Password Autocomplete;
          'redirect_wlist_succ'= Redirect Whitelist Success; 'redirect_wlist_fail'=
          Redirect Whitelist Failure; 'redirect_wlist_learn'= Redirect Whitelist Learn;
          'form_set_no_cache'= Form Set No Cache; 'resp_denied'= Responses Denied;
          'sessions_alloc'= Sessions allocated; 'sessions_freed'= Sessions freed;
          'out_of_sessions'= Out of sessions; 'too_many_sessions'= Too many sessions
          consumed; 'called'= Threshold check count; 'permitted'= Honor threshold  count;
          'brute_force_success'= Brute-force checks passed; 'brute_force_fail'= Brute-
          force checks failed; 'challenge_cookie_sent'= Cookie challenge sent;
          'challenge_javascript_sent'= JavaScript challenge sent;
          'challenge_captcha_sent'= Captcha challenge sent;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            total_req:
                description:
                - "Total Requests"
                type: str
            req_allowed:
                description:
                - "Requests Allowed"
                type: str
            req_denied:
                description:
                - "Requests Denied"
                type: str
            bot_check_succ:
                description:
                - "Botnet Check Success"
                type: str
            bot_check_fail:
                description:
                - "Botnet Check Failure"
                type: str
            form_consistency_succ:
                description:
                - "Form Consistency Success"
                type: str
            form_consistency_fail:
                description:
                - "Form Consistency Failure"
                type: str
            form_csrf_tag_succ:
                description:
                - "Form CSRF tag Success"
                type: str
            form_csrf_tag_fail:
                description:
                - "Form CSRF tag Failure"
                type: str
            url_check_succ:
                description:
                - "URL Check Success"
                type: str
            url_check_fail:
                description:
                - "URL Check Failure"
                type: str
            url_check_learn:
                description:
                - "URL Check Learn"
                type: str
            buf_ovf_url_len_fail:
                description:
                - "Buffer Overflow - URL Length Failure"
                type: str
            buf_ovf_cookie_len_fail:
                description:
                - "Buffer Overflow - Cookie Length Failure"
                type: str
            buf_ovf_hdrs_len_fail:
                description:
                - "Buffer Overflow - Headers length Failure"
                type: str
            buf_ovf_post_size_fail:
                description:
                - "Buffer Overflow - Post size Failure"
                type: str
            max_cookies_fail:
                description:
                - "Max Cookies Failure"
                type: str
            max_hdrs_fail:
                description:
                - "Max Headers Failure"
                type: str
            http_method_check_succ:
                description:
                - "Http Method Check Success"
                type: str
            http_method_check_fail:
                description:
                - "Http Method Check Failure"
                type: str
            http_check_succ:
                description:
                - "Http Check Success"
                type: str
            http_check_fail:
                description:
                - "Http Check Failure"
                type: str
            referer_check_succ:
                description:
                - "Referer Check Success"
                type: str
            referer_check_fail:
                description:
                - "Referer Check Failure"
                type: str
            referer_check_redirect:
                description:
                - "Referer Check Redirect"
                type: str
            uri_wlist_succ:
                description:
                - "URI White List Success"
                type: str
            uri_wlist_fail:
                description:
                - "URI White List Failure"
                type: str
            uri_blist_succ:
                description:
                - "URI Black List Success"
                type: str
            uri_blist_fail:
                description:
                - "URI Black List Failure"
                type: str
            post_form_check_succ:
                description:
                - "Post Form Check Success"
                type: str
            post_form_check_sanitize:
                description:
                - "Post Form Check Sanitized"
                type: str
            post_form_check_reject:
                description:
                - "Post Form Check Rejected"
                type: str
            ccn_mask_amex:
                description:
                - "Credit Card Number Mask Amex"
                type: str
            ccn_mask_diners:
                description:
                - "Credit Card Number Mask Diners"
                type: str
            ccn_mask_visa:
                description:
                - "Credit Card Number Mask Visa"
                type: str
            ccn_mask_mastercard:
                description:
                - "Credit Card Number Mask Mastercard"
                type: str
            ccn_mask_discover:
                description:
                - "Credit Card Number Mask Discover"
                type: str
            ccn_mask_jcb:
                description:
                - "Credit Card Number Mask Jcb"
                type: str
            ssn_mask:
                description:
                - "Social Security Number Mask"
                type: str
            pcre_mask:
                description:
                - "PCRE Mask"
                type: str
            cookie_encrypt_succ:
                description:
                - "Cookie Encrypt Success"
                type: str
            cookie_encrypt_fail:
                description:
                - "Cookie Encrypt Failure"
                type: str
            cookie_encrypt_limit_exceeded:
                description:
                - "Cookie Encrypt Limit Exceeded"
                type: str
            cookie_encrypt_skip_rcache:
                description:
                - "Cookie Encrypt Skip RCache"
                type: str
            cookie_decrypt_succ:
                description:
                - "Cookie Decrypt Success"
                type: str
            cookie_decrypt_fail:
                description:
                - "Cookie Decrypt Failure"
                type: str
            sqlia_chk_url_succ:
                description:
                - "SQLIA Check URL Success"
                type: str
            sqlia_chk_url_sanitize:
                description:
                - "SQLIA Check URL Sanitized"
                type: str
            sqlia_chk_url_reject:
                description:
                - "SQLIA Check URL Rejected"
                type: str
            sqlia_chk_post_succ:
                description:
                - "SQLIA Check Post Success"
                type: str
            sqlia_chk_post_sanitize:
                description:
                - "SQLIA Check Post Sanitized"
                type: str
            sqlia_chk_post_reject:
                description:
                - "SQLIA Check Post Rejected"
                type: str
            xss_chk_cookie_succ:
                description:
                - "XSS Check Cookie Success"
                type: str
            xss_chk_cookie_sanitize:
                description:
                - "XSS Check Cookie Sanitized"
                type: str
            xss_chk_cookie_reject:
                description:
                - "XSS Check Cookie Rejected"
                type: str
            xss_chk_url_succ:
                description:
                - "XSS Check URL Success"
                type: str
            xss_chk_url_sanitize:
                description:
                - "XSS Check URL Sanitized"
                type: str
            xss_chk_url_reject:
                description:
                - "XSS Check URL Rejected"
                type: str
            xss_chk_post_succ:
                description:
                - "XSS Check Post Success"
                type: str
            xss_chk_post_sanitize:
                description:
                - "XSS Check Post Sanitized"
                type: str
            xss_chk_post_reject:
                description:
                - "XSS Check Post Rejected"
                type: str
            resp_code_hidden:
                description:
                - "Response Code Hidden"
                type: str
            resp_hdrs_filtered:
                description:
                - "Response Headers Filtered"
                type: str
            learn_updates:
                description:
                - "Learning Updates"
                type: str
            num_drops:
                description:
                - "Number Drops"
                type: str
            num_resets:
                description:
                - "Number Resets"
                type: str
            form_non_ssl_reject:
                description:
                - "Form Non SSL Rejected"
                type: str
            form_non_post_reject:
                description:
                - "Form Non Post Rejected"
                type: str
            sess_check_none:
                description:
                - "Session Check None"
                type: str
            sess_check_succ:
                description:
                - "Session Check Success"
                type: str
            sess_check_fail:
                description:
                - "Session Check Failure"
                type: str
            soap_check_succ:
                description:
                - "Soap Check Success"
                type: str
            soap_check_failure:
                description:
                - "Soap Check Failure"
                type: str
            wsdl_fail:
                description:
                - "WSDL Failure"
                type: str
            wsdl_succ:
                description:
                - "WSDL Success"
                type: str
            xml_schema_fail:
                description:
                - "XML Schema Failure"
                type: str
            xml_schema_succ:
                description:
                - "XML Schema Success"
                type: str
            xml_sqlia_chk_fail:
                description:
                - "XML Sqlia Check Failure"
                type: str
            xml_sqlia_chk_succ:
                description:
                - "XML Sqlia Check Success"
                type: str
            xml_xss_chk_fail:
                description:
                - "XML XSS Check Failure"
                type: str
            xml_xss_chk_succ:
                description:
                - "XML XSS Check Success"
                type: str
            json_check_failure:
                description:
                - "JSON Check Failure"
                type: str
            json_check_succ:
                description:
                - "JSON Check Success"
                type: str
            xml_check_failure:
                description:
                - "XML Check Failure"
                type: str
            xml_check_succ:
                description:
                - "XML Check Success"
                type: str
            buf_ovf_cookie_value_len_fail:
                description:
                - "Buffer Overflow - Cookie Value Length Failure"
                type: str
            buf_ovf_cookies_len_fail:
                description:
                - "Buffer Overflow - Cookies Length Failure"
                type: str
            buf_ovf_hdr_name_len_fail:
                description:
                - "Buffer Overflow - Header Name Length Failure"
                type: str
            buf_ovf_hdr_value_len_fail:
                description:
                - "Buffer Overflow - Header Value Length Failure"
                type: str
            buf_ovf_max_data_parse_fail:
                description:
                - "Buffer Overflow - Max Data Parse Failure"
                type: str
            buf_ovf_line_len_fail:
                description:
                - "Buffer Overflow - Line Length Failure"
                type: str
            buf_ovf_parameter_name_len_fail:
                description:
                - "Buffer Overflow - HTML Parameter Name Length Failure"
                type: str
            buf_ovf_parameter_value_len_fail:
                description:
                - "Buffer Overflow - HTML Parameter Value Length Failure"
                type: str
            buf_ovf_parameter_total_len_fail:
                description:
                - "Buffer Overflow - HTML Parameter Total Length Failure"
                type: str
            buf_ovf_query_len_fail:
                description:
                - "Buffer Overflow - Query Length Failure"
                type: str
            max_entities_fail:
                description:
                - "Max Entities Failure"
                type: str
            max_parameters_fail:
                description:
                - "Max Parameters Failure"
                type: str
            buf_ovf_cookie_name_len_fail:
                description:
                - "Buffer Overflow - Cookie Name Length Failure"
                type: str
            xml_limit_attr:
                description:
                - "XML Limit Attribue"
                type: str
            xml_limit_attr_name_len:
                description:
                - "XML Limit Name Length"
                type: str
            xml_limit_attr_value_len:
                description:
                - "XML Limit Value Length"
                type: str
            xml_limit_cdata_len:
                description:
                - "XML Limit CData Length"
                type: str
            xml_limit_elem:
                description:
                - "XML Limit Element"
                type: str
            xml_limit_elem_child:
                description:
                - "XML Limit Element Child"
                type: str
            xml_limit_elem_depth:
                description:
                - "XML Limit Element Depth"
                type: str
            xml_limit_elem_name_len:
                description:
                - "XML Limit Element Name Length"
                type: str
            xml_limit_entity_exp:
                description:
                - "XML Limit Entity Exp"
                type: str
            xml_limit_entity_exp_depth:
                description:
                - "XML Limit Entity Exp Depth"
                type: str
            xml_limit_namespace:
                description:
                - "XML Limit Namespace"
                type: str
            xml_limit_namespace_uri_len:
                description:
                - "XML Limit Namespace URI Length"
                type: str
            json_limit_array_value_count:
                description:
                - "JSON Limit Array Value Count"
                type: str
            json_limit_depth:
                description:
                - "JSON Limit Depth"
                type: str
            json_limit_object_member_count:
                description:
                - "JSON Limit Object Number Count"
                type: str
            json_limit_string:
                description:
                - "JSON Limit String"
                type: str
            form_non_masked_password:
                description:
                - "Form Non Masked Password"
                type: str
            form_non_ssl_password:
                description:
                - "Form Non SSL Password"
                type: str
            form_password_autocomplete:
                description:
                - "Form Password Autocomplete"
                type: str
            redirect_wlist_succ:
                description:
                - "Redirect Whitelist Success"
                type: str
            redirect_wlist_fail:
                description:
                - "Redirect Whitelist Failure"
                type: str
            redirect_wlist_learn:
                description:
                - "Redirect Whitelist Learn"
                type: str
            form_set_no_cache:
                description:
                - "Form Set No Cache"
                type: str
            resp_denied:
                description:
                - "Responses Denied"
                type: str
            sessions_alloc:
                description:
                - "Sessions allocated"
                type: str
            sessions_freed:
                description:
                - "Sessions freed"
                type: str
            out_of_sessions:
                description:
                - "Out of sessions"
                type: str
            too_many_sessions:
                description:
                - "Too many sessions consumed"
                type: str
            called:
                description:
                - "Threshold check count"
                type: str
            permitted:
                description:
                - "Honor threshold  count"
                type: str
            brute_force_success:
                description:
                - "Brute-force checks passed"
                type: str
            brute_force_fail:
                description:
                - "Brute-force checks failed"
                type: str
            challenge_cookie_sent:
                description:
                - "Cookie challenge sent"
                type: str
            challenge_javascript_sent:
                description:
                - "JavaScript challenge sent"
                type: str
            challenge_captcha_sent:
                description:
                - "Captcha challenge sent"
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
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_client import \
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
                    'all', 'total_req', 'req_allowed', 'req_denied',
                    'bot_check_succ', 'bot_check_fail',
                    'form_consistency_succ', 'form_consistency_fail',
                    'form_csrf_tag_succ', 'form_csrf_tag_fail',
                    'url_check_succ', 'url_check_fail', 'url_check_learn',
                    'buf_ovf_url_len_fail', 'buf_ovf_cookie_len_fail',
                    'buf_ovf_hdrs_len_fail', 'buf_ovf_post_size_fail',
                    'max_cookies_fail', 'max_hdrs_fail',
                    'http_method_check_succ', 'http_method_check_fail',
                    'http_check_succ', 'http_check_fail', 'referer_check_succ',
                    'referer_check_fail', 'referer_check_redirect',
                    'uri_wlist_succ', 'uri_wlist_fail', 'uri_blist_succ',
                    'uri_blist_fail', 'post_form_check_succ',
                    'post_form_check_sanitize', 'post_form_check_reject',
                    'ccn_mask_amex', 'ccn_mask_diners', 'ccn_mask_visa',
                    'ccn_mask_mastercard', 'ccn_mask_discover', 'ccn_mask_jcb',
                    'ssn_mask', 'pcre_mask', 'cookie_encrypt_succ',
                    'cookie_encrypt_fail', 'cookie_encrypt_limit_exceeded',
                    'cookie_encrypt_skip_rcache', 'cookie_decrypt_succ',
                    'cookie_decrypt_fail', 'sqlia_chk_url_succ',
                    'sqlia_chk_url_sanitize', 'sqlia_chk_url_reject',
                    'sqlia_chk_post_succ', 'sqlia_chk_post_sanitize',
                    'sqlia_chk_post_reject', 'xss_chk_cookie_succ',
                    'xss_chk_cookie_sanitize', 'xss_chk_cookie_reject',
                    'xss_chk_url_succ', 'xss_chk_url_sanitize',
                    'xss_chk_url_reject', 'xss_chk_post_succ',
                    'xss_chk_post_sanitize', 'xss_chk_post_reject',
                    'resp_code_hidden', 'resp_hdrs_filtered', 'learn_updates',
                    'num_drops', 'num_resets', 'form_non_ssl_reject',
                    'form_non_post_reject', 'sess_check_none',
                    'sess_check_succ', 'sess_check_fail', 'soap_check_succ',
                    'soap_check_failure', 'wsdl_fail', 'wsdl_succ',
                    'xml_schema_fail', 'xml_schema_succ', 'xml_sqlia_chk_fail',
                    'xml_sqlia_chk_succ', 'xml_xss_chk_fail',
                    'xml_xss_chk_succ', 'json_check_failure',
                    'json_check_succ', 'xml_check_failure', 'xml_check_succ',
                    'buf_ovf_cookie_value_len_fail',
                    'buf_ovf_cookies_len_fail', 'buf_ovf_hdr_name_len_fail',
                    'buf_ovf_hdr_value_len_fail',
                    'buf_ovf_max_data_parse_fail', 'buf_ovf_line_len_fail',
                    'buf_ovf_parameter_name_len_fail',
                    'buf_ovf_parameter_value_len_fail',
                    'buf_ovf_parameter_total_len_fail',
                    'buf_ovf_query_len_fail', 'max_entities_fail',
                    'max_parameters_fail', 'buf_ovf_cookie_name_len_fail',
                    'xml_limit_attr', 'xml_limit_attr_name_len',
                    'xml_limit_attr_value_len', 'xml_limit_cdata_len',
                    'xml_limit_elem', 'xml_limit_elem_child',
                    'xml_limit_elem_depth', 'xml_limit_elem_name_len',
                    'xml_limit_entity_exp', 'xml_limit_entity_exp_depth',
                    'xml_limit_namespace', 'xml_limit_namespace_uri_len',
                    'json_limit_array_value_count', 'json_limit_depth',
                    'json_limit_object_member_count', 'json_limit_string',
                    'form_non_masked_password', 'form_non_ssl_password',
                    'form_password_autocomplete', 'redirect_wlist_succ',
                    'redirect_wlist_fail', 'redirect_wlist_learn',
                    'form_set_no_cache', 'resp_denied', 'sessions_alloc',
                    'sessions_freed', 'out_of_sessions', 'too_many_sessions',
                    'called', 'permitted', 'brute_force_success',
                    'brute_force_fail', 'challenge_cookie_sent',
                    'challenge_javascript_sent', 'challenge_captcha_sent'
                ]
            }
        },
        'stats': {
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
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/waf/global"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/waf/global"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["global"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["global"].get(k) != v:
            change_results["changed"] = True
            config_changes["global"][k] = v

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
    payload = utils.build_json("global", module.params, AVAILABLE_PROPERTIES)
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
