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
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
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
                'resp_denied': {
                    'type': 'str',
                },
                'brute_force_success': {
                    'type': 'str',
                },
                'brute_force_violation': {
                    'type': 'str',
                },
                'brute_force_challenge_cookie_sent': {
                    'type': 'str',
                },
                'brute_force_challenge_cookie_success': {
                    'type': 'str',
                },
                'brute_force_challenge_cookie_violation': {
                    'type': 'str',
                },
                'brute_force_challenge_javascript_sent': {
                    'type': 'str',
                },
                'brute_force_challenge_javascript_success': {
                    'type': 'str',
                },
                'brute_force_challenge_javascript_violation': {
                    'type': 'str',
                },
                'brute_force_challenge_captcha_sent': {
                    'type': 'str',
                },
                'brute_force_challenge_captcha_success': {
                    'type': 'str',
                },
                'brute_force_challenge_captcha_violation': {
                    'type': 'str',
                },
                'brute_force_lockout_limit_success': {
                    'type': 'str',
                },
                'brute_force_lockout_limit_violation': {
                    'type': 'str',
                },
                'brute_force_challenge_limit_success': {
                    'type': 'str',
                },
                'brute_force_challenge_limit_violation': {
                    'type': 'str',
                },
                'brute_force_response_codes_triggered': {
                    'type': 'str',
                },
                'brute_force_response_headers_triggered': {
                    'type': 'str',
                },
                'brute_force_response_string_triggered': {
                    'type': 'str',
                },
                'cookie_security_encrypt_success': {
                    'type': 'str',
                },
                'cookie_security_encrypt_violation': {
                    'type': 'str',
                },
                'cookie_security_encrypt_limit_exceeded': {
                    'type': 'str',
                },
                'cookie_security_encrypt_skip_rcache': {
                    'type': 'str',
                },
                'cookie_security_decrypt_success': {
                    'type': 'str',
                },
                'cookie_security_decrypt_violation': {
                    'type': 'str',
                },
                'cookie_security_sign_success': {
                    'type': 'str',
                },
                'cookie_security_sign_violation': {
                    'type': 'str',
                },
                'cookie_security_sign_limit_exceeded': {
                    'type': 'str',
                },
                'cookie_security_sign_skip_rcache': {
                    'type': 'str',
                },
                'cookie_security_signature_check_success': {
                    'type': 'str',
                },
                'cookie_security_signature_check_violation': {
                    'type': 'str',
                },
                'cookie_security_add_http_only_success': {
                    'type': 'str',
                },
                'cookie_security_add_http_only_violation': {
                    'type': 'str',
                },
                'cookie_security_add_secure_success': {
                    'type': 'str',
                },
                'cookie_security_add_secure_violation': {
                    'type': 'str',
                },
                'cookie_security_missing_cookie_success': {
                    'type': 'str',
                },
                'cookie_security_missing_cookie_violation': {
                    'type': 'str',
                },
                'cookie_security_unrecognized_cookie_success': {
                    'type': 'str',
                },
                'cookie_security_unrecognized_cookie_violation': {
                    'type': 'str',
                },
                'cookie_security_cookie_policy_success': {
                    'type': 'str',
                },
                'cookie_security_cookie_policy_violation': {
                    'type': 'str',
                },
                'cookie_security_persistent_cookies': {
                    'type': 'str',
                },
                'cookie_security_persistent_cookies_encrypted': {
                    'type': 'str',
                },
                'cookie_security_persistent_cookies_signed': {
                    'type': 'str',
                },
                'cookie_security_session_cookies': {
                    'type': 'str',
                },
                'cookie_security_session_cookies_encrypted': {
                    'type': 'str',
                },
                'cookie_security_session_cookies_signed': {
                    'type': 'str',
                },
                'cookie_security_allowed_session_cookies': {
                    'type': 'str',
                },
                'cookie_security_allowed_persistent_cookies': {
                    'type': 'str',
                },
                'cookie_security_disallowed_session_cookies': {
                    'type': 'str',
                },
                'cookie_security_disallowed_persistent_cookies': {
                    'type': 'str',
                },
                'cookie_security_allowed_session_set_cookies': {
                    'type': 'str',
                },
                'cookie_security_allowed_persistent_set_cookies': {
                    'type': 'str',
                },
                'cookie_security_disallowed_session_set_cookies': {
                    'type': 'str',
                },
                'cookie_security_disallowed_persistent_set_cookies': {
                    'type': 'str',
                },
                'csp_header_violation': {
                    'type': 'str',
                },
                'csp_header_success': {
                    'type': 'str',
                },
                'csp_header_inserted': {
                    'type': 'str',
                },
                'form_csrf_tag_success': {
                    'type': 'str',
                },
                'form_csrf_tag_violation': {
                    'type': 'str',
                },
                'form_consistency_success': {
                    'type': 'str',
                },
                'form_consistency_violation': {
                    'type': 'str',
                },
                'form_tag_inserted': {
                    'type': 'str',
                },
                'form_non_ssl_success': {
                    'type': 'str',
                },
                'form_non_ssl_violation': {
                    'type': 'str',
                },
                'form_request_non_post_success': {
                    'type': 'str',
                },
                'form_request_non_post_violation': {
                    'type': 'str',
                },
                'form_check_success': {
                    'type': 'str',
                },
                'form_check_violation': {
                    'type': 'str',
                },
                'form_check_sanitize': {
                    'type': 'str',
                },
                'form_non_masked_password_success': {
                    'type': 'str',
                },
                'form_non_masked_password_violation': {
                    'type': 'str',
                },
                'form_non_ssl_password_success': {
                    'type': 'str',
                },
                'form_non_ssl_password_violation': {
                    'type': 'str',
                },
                'form_password_autocomplete_success': {
                    'type': 'str',
                },
                'form_password_autocomplete_violation': {
                    'type': 'str',
                },
                'form_set_no_cache_success': {
                    'type': 'str',
                },
                'form_set_no_cache': {
                    'type': 'str',
                },
                'dlp_ccn_success': {
                    'type': 'str',
                },
                'dlp_ccn_amex_violation': {
                    'type': 'str',
                },
                'dlp_ccn_amex_masked': {
                    'type': 'str',
                },
                'dlp_ccn_diners_violation': {
                    'type': 'str',
                },
                'dlp_ccn_diners_masked': {
                    'type': 'str',
                },
                'dlp_ccn_visa_violation': {
                    'type': 'str',
                },
                'dlp_ccn_visa_masked': {
                    'type': 'str',
                },
                'dlp_ccn_mastercard_violation': {
                    'type': 'str',
                },
                'dlp_ccn_mastercard_masked': {
                    'type': 'str',
                },
                'dlp_ccn_discover_violation': {
                    'type': 'str',
                },
                'dlp_ccn_discover_masked': {
                    'type': 'str',
                },
                'dlp_ccn_jcb_violation': {
                    'type': 'str',
                },
                'dlp_ccn_jcb_masked': {
                    'type': 'str',
                },
                'dlp_ssn_success': {
                    'type': 'str',
                },
                'dlp_ssn_violation': {
                    'type': 'str',
                },
                'dlp_pcre_success': {
                    'type': 'str',
                },
                'dlp_pcre_violation': {
                    'type': 'str',
                },
                'dlp_pcre_masked': {
                    'type': 'str',
                },
                'evasion_check_apache_whitespace_success': {
                    'type': 'str',
                },
                'evasion_check_apache_whitespace_violation': {
                    'type': 'str',
                },
                'evasion_check_decode_entities_success': {
                    'type': 'str',
                },
                'evasion_check_decode_entities_violation': {
                    'type': 'str',
                },
                'evasion_check_decode_escaped_chars_success': {
                    'type': 'str',
                },
                'evasion_check_decode_escaped_chars_violation': {
                    'type': 'str',
                },
                'evasion_check_decode_unicode_chars_success': {
                    'type': 'str',
                },
                'evasion_check_decode_unicode_chars_violation': {
                    'type': 'str',
                },
                'evasion_check_dir_traversal_success': {
                    'type': 'str',
                },
                'evasion_check_dir_traversal_violation': {
                    'type': 'str',
                },
                'evasion_check_high_ascii_bytes_success': {
                    'type': 'str',
                },
                'evasion_check_high_ascii_bytes_violation': {
                    'type': 'str',
                },
                'evasion_check_invalid_hex_encoding_success': {
                    'type': 'str',
                },
                'evasion_check_invalid_hex_encoding_violation': {
                    'type': 'str',
                },
                'evasion_check_multiple_encoding_levels_success': {
                    'type': 'str',
                },
                'evasion_check_multiple_encoding_levels_violation': {
                    'type': 'str',
                },
                'evasion_check_multiple_slashes_success': {
                    'type': 'str',
                },
                'evasion_check_multiple_slashes_violation': {
                    'type': 'str',
                },
                'evasion_check_max_levels_success': {
                    'type': 'str',
                },
                'evasion_check_max_levels_violation': {
                    'type': 'str',
                },
                'evasion_check_remove_comments_success': {
                    'type': 'str',
                },
                'evasion_check_remove_comments_violation': {
                    'type': 'str',
                },
                'evasion_check_remove_spaces_success': {
                    'type': 'str',
                },
                'evasion_check_remove_spaces_violation': {
                    'type': 'str',
                },
                'http_limit_max_content_length_success': {
                    'type': 'str',
                },
                'http_limit_max_content_length_violation': {
                    'type': 'str',
                },
                'http_limit_max_cookie_header_length_success': {
                    'type': 'str',
                },
                'http_limit_max_cookie_header_length_violation': {
                    'type': 'str',
                },
                'http_limit_max_cookie_name_length_success': {
                    'type': 'str',
                },
                'http_limit_max_cookie_name_length_violation': {
                    'type': 'str',
                },
                'http_limit_max_cookie_value_length_success': {
                    'type': 'str',
                },
                'http_limit_max_cookie_value_length_violation': {
                    'type': 'str',
                },
                'http_limit_max_cookies_success': {
                    'type': 'str',
                },
                'http_limit_max_cookies_violation': {
                    'type': 'str',
                },
                'http_limit_max_cookies_length_success': {
                    'type': 'str',
                },
                'http_limit_max_cookies_length_violation': {
                    'type': 'str',
                },
                'http_limit_max_data_parse_success': {
                    'type': 'str',
                },
                'http_limit_max_data_parse_violation': {
                    'type': 'str',
                },
                'http_limit_max_entities_success': {
                    'type': 'str',
                },
                'http_limit_max_entities_violation': {
                    'type': 'str',
                },
                'http_limit_max_header_length_success': {
                    'type': 'str',
                },
                'http_limit_max_header_length_violation': {
                    'type': 'str',
                },
                'http_limit_max_header_name_length_success': {
                    'type': 'str',
                },
                'http_limit_max_header_name_length_violation': {
                    'type': 'str',
                },
                'http_limit_max_header_value_length_success': {
                    'type': 'str',
                },
                'http_limit_max_header_value_length_violation': {
                    'type': 'str',
                },
                'http_limit_max_headers_success': {
                    'type': 'str',
                },
                'http_limit_max_headers_violation': {
                    'type': 'str',
                },
                'http_limit_max_headers_length_success': {
                    'type': 'str',
                },
                'http_limit_max_headers_length_violation': {
                    'type': 'str',
                },
                'http_limit_max_param_name_length_success': {
                    'type': 'str',
                },
                'http_limit_max_param_name_length_violation': {
                    'type': 'str',
                },
                'http_limit_max_param_value_length_success': {
                    'type': 'str',
                },
                'http_limit_max_param_value_length_violation': {
                    'type': 'str',
                },
                'http_limit_max_params_success': {
                    'type': 'str',
                },
                'http_limit_max_params_violation': {
                    'type': 'str',
                },
                'http_limit_max_params_length_success': {
                    'type': 'str',
                },
                'http_limit_max_params_length_violation': {
                    'type': 'str',
                },
                'http_limit_max_post_length_success': {
                    'type': 'str',
                },
                'http_limit_max_post_length_violation': {
                    'type': 'str',
                },
                'http_limit_max_query_length_success': {
                    'type': 'str',
                },
                'http_limit_max_query_length_violation': {
                    'type': 'str',
                },
                'http_limit_max_request_length_success': {
                    'type': 'str',
                },
                'http_limit_max_request_length_violation': {
                    'type': 'str',
                },
                'http_limit_max_request_line_length_success': {
                    'type': 'str',
                },
                'http_limit_max_request_line_length_violation': {
                    'type': 'str',
                },
                'max_url_length_success': {
                    'type': 'str',
                },
                'max_url_length_violation': {
                    'type': 'str',
                },
                'http_protocol_allowed_headers_success': {
                    'type': 'str',
                },
                'http_protocol_allowed_headers_violation': {
                    'type': 'str',
                },
                'http_protocol_allowed_versions_success': {
                    'type': 'str',
                },
                'http_protocol_allowed_versions_violation': {
                    'type': 'str',
                },
                'http_protocol_allowed_method_check_success': {
                    'type': 'str',
                },
                'http_protocol_allowed_method_check_violation': {
                    'type': 'str',
                },
                'http_protocol_bad_multipart_request_success': {
                    'type': 'str',
                },
                'http_protocol_bad_multipart_request_violation': {
                    'type': 'str',
                },
                'http_protocol_get_with_content_success': {
                    'type': 'str',
                },
                'http_protocol_get_with_content_violation': {
                    'type': 'str',
                },
                'http_protocol_head_with_content_success': {
                    'type': 'str',
                },
                'http_protocol_head_with_content_violation': {
                    'type': 'str',
                },
                'http_protocol_host_header_with_ip_success': {
                    'type': 'str',
                },
                'http_protocol_host_header_with_ip_violation': {
                    'type': 'str',
                },
                'http_protocol_invalid_url_encoding_success': {
                    'type': 'str',
                },
                'http_protocol_invalid_url_encoding_violation': {
                    'type': 'str',
                },
                'http_protocol_malformed_content_length_success': {
                    'type': 'str',
                },
                'http_protocol_malformed_content_length_violation': {
                    'type': 'str',
                },
                'http_protocol_malformed_header_success': {
                    'type': 'str',
                },
                'http_protocol_malformed_header_violation': {
                    'type': 'str',
                },
                'http_protocol_malformed_parameter_success': {
                    'type': 'str',
                },
                'http_protocol_malformed_parameter_violation': {
                    'type': 'str',
                },
                'http_protocol_malformed_request_success': {
                    'type': 'str',
                },
                'http_protocol_malformed_request_violation': {
                    'type': 'str',
                },
                'http_protocol_malformed_request_line_success': {
                    'type': 'str',
                },
                'http_protocol_malformed_request_line_violation': {
                    'type': 'str',
                },
                'http_protocol_missing_header_value_success': {
                    'type': 'str',
                },
                'http_protocol_missing_header_value_violation': {
                    'type': 'str',
                },
                'http_protocol_missing_host_header_success': {
                    'type': 'str',
                },
                'http_protocol_missing_host_header_violation': {
                    'type': 'str',
                },
                'http_protocol_multiple_content_length_success': {
                    'type': 'str',
                },
                'http_protocol_multiple_content_length_violation': {
                    'type': 'str',
                },
                'http_protocol_post_with_0_content_success': {
                    'type': 'str',
                },
                'http_protocol_post_with_0_content_violation': {
                    'type': 'str',
                },
                'http_protocol_post_without_content_success': {
                    'type': 'str',
                },
                'http_protocol_post_without_content_violation': {
                    'type': 'str',
                },
                'http_protocol_success': {
                    'type': 'str',
                },
                'http_protocol_violation': {
                    'type': 'str',
                },
                'json_check_format_success': {
                    'type': 'str',
                },
                'json_check_format_violation': {
                    'type': 'str',
                },
                'json_check_max_array_value_count_success': {
                    'type': 'str',
                },
                'json_check_max_array_value_count_violation': {
                    'type': 'str',
                },
                'json_check_max_depth_success': {
                    'type': 'str',
                },
                'json_check_max_depth_violation': {
                    'type': 'str',
                },
                'json_check_max_object_member_count_success': {
                    'type': 'str',
                },
                'json_check_max_object_member_count_violation': {
                    'type': 'str',
                },
                'json_check_max_string_success': {
                    'type': 'str',
                },
                'json_check_max_string_violation': {
                    'type': 'str',
                },
                'request_check_bot_success': {
                    'type': 'str',
                },
                'request_check_bot_violation': {
                    'type': 'str',
                },
                'request_check_redirect_wlist_success': {
                    'type': 'str',
                },
                'request_check_redirect_wlist_violation': {
                    'type': 'str',
                },
                'request_check_redirect_wlist_learn': {
                    'type': 'str',
                },
                'request_check_referer_success': {
                    'type': 'str',
                },
                'request_check_referer_violation': {
                    'type': 'str',
                },
                'request_check_referer_redirect': {
                    'type': 'str',
                },
                'request_check_session_check_none': {
                    'type': 'str',
                },
                'request_check_session_check_success': {
                    'type': 'str',
                },
                'request_check_session_check_violation': {
                    'type': 'str',
                },
                'request_check_sqlia_url_success': {
                    'type': 'str',
                },
                'request_check_sqlia_url_violation': {
                    'type': 'str',
                },
                'request_check_sqlia_url_sanitize': {
                    'type': 'str',
                },
                'request_check_sqlia_post_body_success': {
                    'type': 'str',
                },
                'request_check_sqlia_post_body_violation': {
                    'type': 'str',
                },
                'request_check_sqlia_post_body_sanitize': {
                    'type': 'str',
                },
                'request_check_url_list_success': {
                    'type': 'str',
                },
                'request_check_url_list_violation': {
                    'type': 'str',
                },
                'request_check_url_list_learn': {
                    'type': 'str',
                },
                'request_check_url_whitelist_success': {
                    'type': 'str',
                },
                'request_check_url_whitelist_violation': {
                    'type': 'str',
                },
                'request_check_url_blacklist_success': {
                    'type': 'str',
                },
                'request_check_url_blacklist_violation': {
                    'type': 'str',
                },
                'request_check_xss_cookie_success': {
                    'type': 'str',
                },
                'request_check_xss_cookie_violation': {
                    'type': 'str',
                },
                'request_check_xss_cookie_sanitize': {
                    'type': 'str',
                },
                'request_check_xss_url_success': {
                    'type': 'str',
                },
                'request_check_xss_url_violation': {
                    'type': 'str',
                },
                'request_check_xss_url_sanitize': {
                    'type': 'str',
                },
                'request_check_xss_post_body_success': {
                    'type': 'str',
                },
                'request_check_xss_post_body_violation': {
                    'type': 'str',
                },
                'request_check_xss_post_body_sanitize': {
                    'type': 'str',
                },
                'response_cloaking_hide_status_code_success': {
                    'type': 'str',
                },
                'response_cloaking_hide_status_code_violation': {
                    'type': 'str',
                },
                'response_cloaking_filter_headers_success': {
                    'type': 'str',
                },
                'response_cloaking_filter_headers_violation': {
                    'type': 'str',
                },
                'soap_check_success': {
                    'type': 'str',
                },
                'soap_check_violation': {
                    'type': 'str',
                },
                'xml_check_format_success': {
                    'type': 'str',
                },
                'xml_check_format_violation': {
                    'type': 'str',
                },
                'xml_check_max_attr_success': {
                    'type': 'str',
                },
                'xml_check_max_attr_violation': {
                    'type': 'str',
                },
                'xml_check_max_attr_name_len_success': {
                    'type': 'str',
                },
                'xml_check_max_attr_name_len_violation': {
                    'type': 'str',
                },
                'xml_check_max_attr_value_len_success': {
                    'type': 'str',
                },
                'xml_check_max_attr_value_len_violation': {
                    'type': 'str',
                },
                'xml_check_max_cdata_len_success': {
                    'type': 'str',
                },
                'xml_check_max_cdata_len_violation': {
                    'type': 'str',
                },
                'xml_check_max_elem_success': {
                    'type': 'str',
                },
                'xml_check_max_elem_violation': {
                    'type': 'str',
                },
                'xml_check_max_elem_child_success': {
                    'type': 'str',
                },
                'xml_check_max_elem_child_violation': {
                    'type': 'str',
                },
                'xml_check_max_elem_depth_success': {
                    'type': 'str',
                },
                'xml_check_max_elem_depth_violation': {
                    'type': 'str',
                },
                'xml_check_max_elem_name_len_success': {
                    'type': 'str',
                },
                'xml_check_max_elem_name_len_violation': {
                    'type': 'str',
                },
                'xml_check_max_entity_exp_success': {
                    'type': 'str',
                },
                'xml_check_max_entity_exp_violation': {
                    'type': 'str',
                },
                'xml_check_max_entity_exp_depth_success': {
                    'type': 'str',
                },
                'xml_check_max_entity_exp_depth_violation': {
                    'type': 'str',
                },
                'xml_check_max_namespace_success': {
                    'type': 'str',
                },
                'xml_check_max_namespace_violation': {
                    'type': 'str',
                },
                'xml_check_namespace_uri_len_success': {
                    'type': 'str',
                },
                'xml_check_namespace_uri_len_violation': {
                    'type': 'str',
                },
                'xml_check_sqlia_success': {
                    'type': 'str',
                },
                'xml_check_sqlia_violation': {
                    'type': 'str',
                },
                'xml_check_xss_success': {
                    'type': 'str',
                },
                'xml_check_xss_violation': {
                    'type': 'str',
                },
                'xml_content_check_schema_success': {
                    'type': 'str',
                },
                'xml_content_check_schema_violation': {
                    'type': 'str',
                },
                'xml_content_check_wsdl_success': {
                    'type': 'str',
                },
                'xml_content_check_wsdl_violation': {
                    'type': 'str',
                },
                'learning_list_full': {
                    'type': 'str',
                },
                'action_allow': {
                    'type': 'str',
                },
                'action_deny_200': {
                    'type': 'str',
                },
                'action_deny_403': {
                    'type': 'str',
                },
                'action_deny_redirect': {
                    'type': 'str',
                },
                'action_deny_reset': {
                    'type': 'str',
                },
                'action_drop': {
                    'type': 'str',
                },
                'action_deny_custom_response': {
                    'type': 'str',
                },
                'action_learn': {
                    'type': 'str',
                },
                'action_log': {
                    'type': 'str',
                },
                'policy_limit_exceeded': {
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
                'regex_violation': {
                    'type': 'str',
                },
                'request_check_command_injection_cookies_success': {
                    'type': 'str',
                },
                'request_check_command_injection_cookies_violation': {
                    'type': 'str',
                },
                'request_check_command_injection_headers_success': {
                    'type': 'str',
                },
                'request_check_command_injection_headers_violation': {
                    'type': 'str',
                },
                'request_check_command_injection_uri_query_success': {
                    'type': 'str',
                },
                'request_check_command_injection_uri_query_violation': {
                    'type': 'str',
                },
                'request_check_command_injection_form_body_success': {
                    'type': 'str',
                },
                'request_check_command_injection_form_body_violation': {
                    'type': 'str',
                },
                'cookie_security_decrypt_in_grace_period_violation': {
                    'type': 'str',
                },
                'form_response_non_post_success': {
                    'type': 'str',
                },
                'form_response_non_post_violation': {
                    'type': 'str',
                },
                'form_response_non_post_sanitize': {
                    'type': 'str',
                },
                'xml_check_max_entity_decl_success': {
                    'type': 'str',
                },
                'xml_check_max_entity_decl_violation': {
                    'type': 'str',
                },
                'xml_check_max_entity_depth_success': {
                    'type': 'str',
                },
                'xml_check_max_entity_depth_violation': {
                    'type': 'str',
                },
                'response_action_allow': {
                    'type': 'str',
                },
                'response_action_deny_200': {
                    'type': 'str',
                },
                'response_action_deny_403': {
                    'type': 'str',
                },
                'response_action_deny_redirect': {
                    'type': 'str',
                },
                'response_action_deny_reset': {
                    'type': 'str',
                },
                'response_action_drop': {
                    'type': 'str',
                },
                'response_action_deny_custom_response': {
                    'type': 'str',
                },
                'response_action_learn': {
                    'type': 'str',
                },
                'response_action_log': {
                    'type': 'str',
                },
                'http_protocol_post_without_content_type_success': {
                    'type': 'str',
                },
                'http_protocol_post_without_content_type_violation': {
                    'type': 'str',
                },
                'http_protocol_body_without_content_type_success': {
                    'type': 'str',
                },
                'http_protocol_body_without_content_type_violation': {
                    'type': 'str',
                },
                'http_protocol_non_ssl_cookie_prefix_success': {
                    'type': 'str',
                },
                'http_protocol_non_ssl_cookie_prefix_violation': {
                    'type': 'str',
                },
                'cookie_security_add_samesite_success': {
                    'type': 'str',
                },
                'cookie_security_add_samesite_violation': {
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
    if '/' in module.params["protocol"]:
        f_dict["protocol"] = module.params["protocol"].replace("/", "%2F")
    else:
        f_dict["protocol"] = module.params["protocol"]
    if '/' in module.params["port_number"]:
        f_dict["port_number"] = module.params["port_number"].replace(
            "/", "%2F")
    else:
        f_dict["port_number"] = module.params["port_number"]
    if '/' in module.params["virtual_server_name"]:
        f_dict["virtual_server_name"] = module.params[
            "virtual_server_name"].replace("/", "%2F")
    else:
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
                  axapi_calls=[],
                  ansible_facts={},
                  acos_info={})

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
                get_result = api_client.get(module.client,
                                            existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result[
                    "acos_info"] = info["port"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "port-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client,
                                                       existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["port"][
                    "stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
