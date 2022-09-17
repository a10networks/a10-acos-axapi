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
    immediate_action:
        description:
        - "Disable the violation aggregation, take action on first violation"
        type: bool
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
          'req_denied'= Requests Denied; 'resp_denied'= Responses Denied;
          'brute_force_success'= Brute-Force checks passed; 'brute_force_violation'=
          Brute-Force checks violation; 'brute_force_challenge_cookie_sent'= Cookie
          Challenge Sent; 'brute_force_challenge_cookie_success'= Cookie Challenge check
          passed; 'brute_force_challenge_cookie_violation'= Cookie challenge violation;
          'brute_force_challenge_javascript_sent'= JavaScript challenge sent;
          'brute_force_challenge_javascript_success'= JavaScript challenge check passed;
          'brute_force_challenge_javascript_violation'= JavaScript challenge violation;
          'brute_force_challenge_captcha_sent'= Captcha challenge sent;
          'brute_force_challenge_captcha_success'= Captcha challenge check passed;
          'brute_force_challenge_captcha_violation'= Captcha challenge violation;
          'brute_force_lockout_limit_success'= Lockout limit check passed;
          'brute_force_lockout_limit_violation'= Lockout limit violation;
          'brute_force_challenge_limit_success'= Lockout limit check passed;
          'brute_force_challenge_limit_violation'= Lockout limit violation;
          'brute_force_response_codes_triggered'= Response Codes Triggered;
          'brute_force_response_headers_triggered'= Brute Force Response Headers
          Triggered; 'brute_force_response_string_triggered'= Brute Force Response string
          Triggered; 'cookie_security_encrypt_success'= Cookie Security - encrypt
          successful; 'cookie_security_encrypt_violation'= Cookie Security - encrypt
          violation; 'cookie_security_encrypt_limit_exceeded'= Cookie Security - encrypt
          limit exceeded; 'cookie_security_encrypt_skip_rcache'= Cookie Security -
          encrypt skipped - RAM cache; 'cookie_security_decrypt_success'= Cookie Security
          - decrypt successful; 'cookie_security_decrypt_violation'= Cookie Security -
          decrypt violation; 'cookie_security_sign_success'= Cookie Security - signing
          successful; 'cookie_security_sign_violation'= Cookie Security - signing
          violation; 'cookie_security_sign_limit_exceeded'= Cookie Security - signing
          limit exceeded; 'cookie_security_sign_skip_rcache'= Cookie Security - signing
          skipped - RAM cache; 'cookie_security_signature_check_success'= Cookie Security
          - signature check successful; 'cookie_security_signature_check_violation'=
          Cookie Security - signature check failed;
          'cookie_security_add_http_only_success'= Cookie Security - http-only flag added
          successfully; 'cookie_security_add_http_only_violation'= Cookie Security -
          http-only flag violation; 'cookie_security_add_secure_success'= Cookie Security
          - secure flag added successfully; 'cookie_security_add_secure_violation'=
          Cookie Security - secure flag violation;
          'cookie_security_missing_cookie_success'= Cookie Security - request with
          missing cookie; 'cookie_security_missing_cookie_violation'= Cookie Security -
          missing cookie violation; 'cookie_security_unrecognized_cookie_success'= Cookie
          Security - request with unrecognized cookie;
          'cookie_security_unrecognized_cookie_violation'= Cookie Security - unrecognized
          cookie violation; 'cookie_security_cookie_policy_success'= Cookie Security -
          cookie policy passed; 'cookie_security_cookie_policy_violation'= Cookie
          Security - cookie policy violation; 'cookie_security_persistent_cookies'=
          Cookie Security - persistent cookies;
          'cookie_security_persistent_cookies_encrypted'= Cookie Security - encrypted
          persistent cookies; 'cookie_security_persistent_cookies_signed'= Cookie
          Security - signed persistent cookies; 'cookie_security_session_cookies'= Cookie
          Security - session cookies; 'cookie_security_session_cookies_encrypted'= Cookie
          Security - encrypted session cookies; 'cookie_security_session_cookies_signed'=
          Cookie Security - signed session cookies;
          'cookie_security_allowed_session_cookies'= Cookie Security - allowed session
          cookies; 'cookie_security_allowed_persistent_cookies'= Cookie Security -
          allowed persistent cookies; 'cookie_security_disallowed_session_cookies'=
          Cookie Security - disallowed session cookies;
          'cookie_security_disallowed_persistent_cookies'= Cookie Security - disallowed
          persistent cookies; 'cookie_security_allowed_session_set_cookies'= Cookie
          Security - allowed session Set-Cookies;
          'cookie_security_allowed_persistent_set_cookies'= Cookie Security - allowed
          persistent Set-Cookies; 'cookie_security_disallowed_session_set_cookies'=
          Cookie Security - disallowed session Set-Cookies;
          'cookie_security_disallowed_persistent_set_cookies'= Cookie Security -
          disallowed persistent Set-Cookies; 'csp_header_violation'= CSP header_missing;
          'csp_header_success'= CSP header found; 'csp_header_inserted'= CSP header
          Inserted; 'form_csrf_tag_success'= Form CSRF tag passed;
          'form_csrf_tag_violation'= Form CSRF tag violation; 'form_consistency_success'=
          Form Consistency passed; 'form_consistency_violation'= Form Consistency
          violation; 'form_tag_inserted'= Form A10 Tag Inserted; 'form_non_ssl_success'=
          Form Non SSL check passed; 'form_non_ssl_violation'= Form Non SSL violation;
          'form_request_non_post_success'= Form Method being Non Post in Request passed;
          'form_request_non_post_violation'= Form Method being Non Post in Request
          violation; 'form_check_success'= Post Form Check passed;
          'form_check_violation'= Post Form Check violation; 'form_check_sanitize'= Post
          Form Check Sanitized; 'form_non_masked_password_success'= Form Non Masked
          Password check passed; 'form_non_masked_password_violation'= Form Non Masked
          Password violation; 'form_non_ssl_password_success'= Form Non SSL Password
          check passed; 'form_non_ssl_password_violation'= Form Non SSL Password
          violation; 'form_password_autocomplete_success'= Form Password Autocomplete
          check passed; 'form_password_autocomplete_violation'= Form Password
          Autocomplete violation; 'form_set_no_cache_success'= Form Set No Cache check
          passed; 'form_set_no_cache'= Form Set No Cache violation; 'dlp_ccn_success'=
          Credit Card Number check passed; 'dlp_ccn_amex_violation'= Amex Credit Card
          Number Detected; 'dlp_ccn_amex_masked'= Amex Credit Card Number Masked;
          'dlp_ccn_diners_violation'= Diners Club Credit Card Number Detected;
          'dlp_ccn_diners_masked'= Diners Club Credit Card Number Masked;
          'dlp_ccn_visa_violation'= Visa Credit Card Number Detected;
          'dlp_ccn_visa_masked'= Visa Credit Card Number Masked;
          'dlp_ccn_mastercard_violation'= MasterCard Credit Card Number Detected;
          'dlp_ccn_mastercard_masked'= MasterCard Credit Card Number Masked;
          'dlp_ccn_discover_violation'= Discover Credit Card Number Detected;
          'dlp_ccn_discover_masked'= Discover Credit Card Number Masked;
          'dlp_ccn_jcb_violation'= JCB Credit Card Number Detected; 'dlp_ccn_jcb_masked'=
          JCB Credit Card Number Masked; 'dlp_ssn_success'= Social Security Number Mask
          check passed; 'dlp_ssn_violation'= Social Security Number Mask violation;
          'dlp_pcre_success'= PCRE Mask check passed; 'dlp_pcre_violation'= PCRE Mask
          violation; 'dlp_pcre_masked'= PCRE Mask violation;
          'evasion_check_apache_whitespace_success'= Apache Whitespace check passed;
          'evasion_check_apache_whitespace_violation'= Apache Whitespace check violation;
          'evasion_check_decode_entities_success'= Decode Entities check passed;
          'evasion_check_decode_entities_violation'= Decode Entities check violation;
          'evasion_check_decode_escaped_chars_success'= Decode Escaped Chars check
          passed; 'evasion_check_decode_escaped_chars_violation'= Decode Escaped Chars
          check violation; 'evasion_check_decode_unicode_chars_success'= Decode Unicode
          Chars check passed; 'evasion_check_decode_unicode_chars_violation'= Decode
          Unicode Chars check violation; 'evasion_check_dir_traversal_success'= Dir
          traversal check passed; 'evasion_check_dir_traversal_violation'= Dir traversal
          check violation;"
                type: str
            counters2:
                description:
                - "'evasion_check_high_ascii_bytes_success'= High Ascii Bytes check passed;
          'evasion_check_high_ascii_bytes_violation'= High Ascii Bytes check violation;
          'evasion_check_invalid_hex_encoding_success'= Invalid Hex Encoding check
          passed; 'evasion_check_invalid_hex_encoding_violation'= Invalid Hex Encoding
          check violation; 'evasion_check_multiple_encoding_levels_success'= Multiple
          Encoding Levels check passed;
          'evasion_check_multiple_encoding_levels_violation'= Multiple Encoding Levels
          check violation; 'evasion_check_multiple_slashes_success'= Multiple Slashes
          check passed; 'evasion_check_multiple_slashes_violation'= Multiple Slashes
          check violation; 'evasion_check_max_levels_success'= Max Levels check passed;
          'evasion_check_max_levels_violation'= Max Levels check violation;
          'evasion_check_remove_comments_success'= Remove Comments check passed;
          'evasion_check_remove_comments_violation'= Remove Comments check violation;
          'evasion_check_remove_spaces_success'= Remove Spaces check passed;
          'evasion_check_remove_spaces_violation'= Remove Spaces check violation;
          'http_limit_max_content_length_success'= MAX content-length check passed;
          'http_limit_max_content_length_violation'= MAX content-length check violation;
          'http_limit_max_cookie_header_length_success'= MAX cookie header length check
          passed; 'http_limit_max_cookie_header_length_violation'= MAX cookie header
          length violation; 'http_limit_max_cookie_name_length_success'= MAX cookie name
          length check passed; 'http_limit_max_cookie_name_length_violation'= MAX cookie
          name length violation; 'http_limit_max_cookie_value_length_success'= MAX cookie
          value length check passed; 'http_limit_max_cookie_value_length_violation'= MAX
          cookie value length violation; 'http_limit_max_cookies_success'= Max Cookies
          check passed; 'http_limit_max_cookies_violation'= Max Cookies violation;
          'http_limit_max_cookies_length_success'= MAX cookies length check passed;
          'http_limit_max_cookies_length_violation'= MAX cookies length violation;
          'http_limit_max_data_parse_success'= Buffer Overflow - Max Data Parse check
          passed; 'http_limit_max_data_parse_violation'= Buffer Overflow - Max Data Parse
          violation; 'http_limit_max_entities_success'= Max Entities check passed;
          'http_limit_max_entities_violation'= Max Entities violation;
          'http_limit_max_header_length_success'= MAX header length check passed;
          'http_limit_max_header_length_violation'= MAX header length check violation;
          'http_limit_max_header_name_length_success'= MAX header name length check
          passed; 'http_limit_max_header_name_length_violation'= MAX header name length
          check violation; 'http_limit_max_header_value_length_success'= MAX header value
          length check passed; 'http_limit_max_header_value_length_violation'= MAX header
          value length check violation; 'http_limit_max_headers_success'= MAX headers
          count check passed; 'http_limit_max_headers_violation'= Max Headers violation;
          'http_limit_max_headers_length_success'= MAX headers length check passed;
          'http_limit_max_headers_length_violation'= MAX headers length check violation;
          'http_limit_max_param_name_length_success'= Limit check - MAX parameter name
          length check passed; 'http_limit_max_param_name_length_violation'= Limit check
          - MAX parameter name length violation;
          'http_limit_max_param_value_length_success'= Limit check - MAX parameter value
          length check passed; 'http_limit_max_param_value_length_violation'= Limit check
          - MAX parameter value length violation; 'http_limit_max_params_success'= Limit
          check - MAX parameters check passed; 'http_limit_max_params_violation'= Limit
          check - MAX parameters violation; 'http_limit_max_params_length_success'= Limit
          check - MAX parameters total length check passed;
          'http_limit_max_params_length_violation'= Limit check - MAX parameters total
          length violation; 'http_limit_max_post_length_success'= MAX POST length check
          passed; 'http_limit_max_post_length_violation'= MAX POST length violation;
          'http_limit_max_query_length_success'= Limit check - MAX query length check
          passed; 'http_limit_max_query_length_violation'= Limit check - MAX query length
          violation; 'http_limit_max_request_length_success'= Limit check - MAX request
          length check passed; 'http_limit_max_request_length_violation'= Limit check -
          MAX request length violation; 'http_limit_max_request_line_length_success'=
          Limit check - MAX request line length check passed;
          'http_limit_max_request_line_length_violation'= Limit check - MAX request line
          length violation; 'max_url_length_success'= Limit check - MAX URL length check
          passed; 'max_url_length_violation'= Limit check - MAX URL length violation;
          'http_protocol_allowed_headers_success'= HTTP headers check passed;
          'http_protocol_allowed_headers_violation'= HTTP headers check violation;
          'http_protocol_allowed_versions_success'= HTTP versions check passed;
          'http_protocol_allowed_versions_violation'= HTTP versions check violation;
          'http_protocol_allowed_method_check_success'= HTTP Method Check passed;
          'http_protocol_allowed_method_check_violation'= HTTP Method Check violation;
          'http_protocol_bad_multipart_request_success'= Bad multi-part request check
          passed; 'http_protocol_bad_multipart_request_violation'= Bad multi-part request
          check violation; 'http_protocol_get_with_content_success'= GET with content
          check passed; 'http_protocol_get_with_content_violation'= GET with content
          check violation; 'http_protocol_head_with_content_success'= HEAD with content
          check passed; 'http_protocol_head_with_content_violation'= HEAD with content
          check violation; 'http_protocol_host_header_with_ip_success'= Host header with
          IP check passed; 'http_protocol_host_header_with_ip_violation'= Host header
          with IP check violation; 'http_protocol_invalid_url_encoding_success'= Invalid
          url encoding check passed; 'http_protocol_invalid_url_encoding_violation'=
          Invalid url encoding check violation;
          'http_protocol_malformed_content_length_success'= Malformed content-length
          check passed; 'http_protocol_malformed_content_length_violation'= Malformed
          content-length check violation; 'http_protocol_malformed_header_success'=
          Malformed header check passed; 'http_protocol_malformed_header_violation'=
          Malformed header check passed; 'http_protocol_malformed_parameter_success'=
          Malformed parameter check passed;
          'http_protocol_malformed_parameter_violation'= Malformed parameter check
          violation; 'http_protocol_malformed_request_success'= Malformed request check
          passed; 'http_protocol_malformed_request_violation'= Malformed request check
          violation; 'http_protocol_malformed_request_line_success'= Malformed request
          line check passed; 'http_protocol_malformed_request_line_violation'= Malformed
          request line check violation; 'http_protocol_missing_header_value_success'=
          Missing header value check violation;
          'http_protocol_missing_header_value_violation'= Missing header value check
          violation; 'http_protocol_missing_host_header_success'= Missing host header
          check passed; 'http_protocol_missing_host_header_violation'= Missing host
          header check violation; 'http_protocol_multiple_content_length_success'=
          Multiple content-length headers check passed;
          'http_protocol_multiple_content_length_violation'= Multiple content-length
          headers check violation; 'http_protocol_post_with_0_content_success'= POST with
          0 content check passed; 'http_protocol_post_with_0_content_violation'= POST
          with 0 content check violation; 'http_protocol_post_without_content_success'=
          POST without content check passed;
          'http_protocol_post_without_content_violation'= POST without content check
          violation; 'http_protocol_success'= HTTP Check passed;
          'http_protocol_violation'= HTTP Check violation; 'json_check_format_success'=
          JSON Check passed;"
                type: str
            counters3:
                description:
                - "'json_check_format_violation'= JSON Check violation;
          'json_check_max_array_value_count_success'= JSON Limit Array Value Count check
          passed; 'json_check_max_array_value_count_violation'= JSON Limit Array Value
          Count violation; 'json_check_max_depth_success'= JSON Limit Depth check passed;
          'json_check_max_depth_violation'= JSON Limit Depth violation;
          'json_check_max_object_member_count_success'= JSON Limit Object Number Count
          check passed; 'json_check_max_object_member_count_violation'= JSON Limit Object
          Number Count violation; 'json_check_max_string_success'= JSON Limit String
          check passed; 'json_check_max_string_violation'= JSON Limit String violation;
          'request_check_bot_success'= Bot check passed; 'request_check_bot_violation'=
          Bot check violation; 'request_check_redirect_wlist_success'= Redirect Whitelist
          passed; 'request_check_redirect_wlist_violation'= Redirect Whitelist violation;
          'request_check_redirect_wlist_learn'= Redirect Whitelist Learn;
          'request_check_referer_success'= Referer Check passed;
          'request_check_referer_violation'= Referer Check violation;
          'request_check_referer_redirect'= Referer Check Redirect;
          'request_check_session_check_none'= Session Created;
          'request_check_session_check_success'= Session Check passed;
          'request_check_session_check_violation'= Session Check violation;
          'request_check_sqlia_url_success'= SQLIA Check URL passed;
          'request_check_sqlia_url_violation'= SQLIA Check URL violation;
          'request_check_sqlia_url_sanitize'= SQLIA Check URL Sanitized;
          'request_check_sqlia_post_body_success'= SQLIA Check Post passed;
          'request_check_sqlia_post_body_violation'= SQLIA Check Post violation;
          'request_check_sqlia_post_body_sanitize'= SQLIA Check Post Sanitized;
          'request_check_url_list_success'= URL Check passed;
          'request_check_url_list_violation'= URL Check violation;
          'request_check_url_list_learn'= URL Check Learn;
          'request_check_url_whitelist_success'= URI White List passed;
          'request_check_url_whitelist_violation'= URI White List violation;
          'request_check_url_blacklist_success'= URI Black List passed;
          'request_check_url_blacklist_violation'= URI Black List violation;
          'request_check_xss_cookie_success'= XSS Check Cookie passed;
          'request_check_xss_cookie_violation'= XSS Check Cookie violation;
          'request_check_xss_cookie_sanitize'= XSS Check Cookie Sanitized;
          'request_check_xss_url_success'= XSS Check URL passed;
          'request_check_xss_url_violation'= XSS Check URL violation;
          'request_check_xss_url_sanitize'= XSS Check URL Sanitized;
          'request_check_xss_post_body_success'= XSS Check Post passed;
          'request_check_xss_post_body_violation'= XSS Check Post violation;
          'request_check_xss_post_body_sanitize'= XSS Check Post Sanitized;
          'response_cloaking_hide_status_code_success'= Response Hide Code check passed;
          'response_cloaking_hide_status_code_violation'= Response Hide Code violation;
          'response_cloaking_filter_headers_success'= Response Headers Filter check
          passed; 'response_cloaking_filter_headers_violation'= Response Headers Filter
          violation; 'soap_check_success'= Soap Check passed; 'soap_check_violation'=
          Soap Check violation; 'xml_check_format_success'= XML Check passed;
          'xml_check_format_violation'= XML Check violation;
          'xml_check_max_attr_success'= XML Limit Attribute check passed;
          'xml_check_max_attr_violation'= XML Limit Attribute violation;
          'xml_check_max_attr_name_len_success'= XML Limit Name Length check passed;
          'xml_check_max_attr_name_len_violation'= XML Limit Name Length violation;
          'xml_check_max_attr_value_len_success'= XML Limit Value Length check passed;
          'xml_check_max_attr_value_len_violation'= XML Limit Value Length violation;
          'xml_check_max_cdata_len_success'= XML Limit CData Length check passed;
          'xml_check_max_cdata_len_violation'= XML Limit CData Length violation;
          'xml_check_max_elem_success'= XML Limit Element check passed;
          'xml_check_max_elem_violation'= XML Limit Element violation;
          'xml_check_max_elem_child_success'= XML Limit Element Child check passed;
          'xml_check_max_elem_child_violation'= XML Limit Element Child violation;
          'xml_check_max_elem_depth_success'= XML Limit Element Depth check passed;
          'xml_check_max_elem_depth_violation'= XML Limit Element Depth violation;
          'xml_check_max_elem_name_len_success'= XML Limit Element Name Length check
          passed; 'xml_check_max_elem_name_len_violation'= XML Limit Element Name Length
          violation; 'xml_check_max_entity_exp_success'= XML Limit Entity Expansions
          check passed; 'xml_check_max_entity_exp_violation'= XML Limit Entity Expansions
          violation; 'xml_check_max_entity_exp_depth_success'= XML Limit Entities Depth
          check passed; 'xml_check_max_entity_exp_depth_violation'= XML Limit Entities
          Depth violation; 'xml_check_max_namespace_success'= XML Limit Namespace check
          passed; 'xml_check_max_namespace_violation'= XML Limit Namespace violation;
          'xml_check_namespace_uri_len_success'= XML Limit Namespace URI Length check
          passed; 'xml_check_namespace_uri_len_violation'= XML Limit Namespace URI Length
          violation; 'xml_check_sqlia_success'= XML Sqlia Check passed;
          'xml_check_sqlia_violation'= XML Sqlia Check violation;
          'xml_check_xss_success'= XML XSS Check passed; 'xml_check_xss_violation'= XML
          XSS Check violation; 'xml_content_check_schema_success'= XML Schema passed;
          'xml_content_check_schema_violation'= XML Schema violation;
          'xml_content_check_wsdl_success'= WSDL passed;
          'xml_content_check_wsdl_violation'= WSDL violation; 'learning_list_full'=
          Learning list is full; 'action_allow'= Request Action allowed;
          'action_deny_200'= Request Deny with 200; 'action_deny_403'= Request Deny with
          403; 'action_deny_redirect'= Request Deny with Redirect; 'action_deny_reset'=
          Request Deny with Resets; 'action_drop'= Number of Dropped Requests;
          'action_deny_custom_response'= Request Deny with custom response;
          'action_learn'= Request Learning Updates; 'action_log'= Log request violation;
          'policy_limit_exceeded'= Policy limit exceeded; 'sessions_alloc'= Sessions
          allocated; 'sessions_freed'= Sessions freed; 'out_of_sessions'= Out of
          sessions; 'too_many_sessions'= Too many sessions consumed; 'regex_violation'=
          Regular expression failure; 'request_check_command_injection_cookies_success'=
          Command Injection Check cookies passed;
          'request_check_command_injection_cookies_violation'= Command Injection Check
          cookies violation; 'request_check_command_injection_headers_success'= Command
          Injection Check headers passed;
          'request_check_command_injection_headers_violation'= Command Injection Check
          headers violation; 'request_check_command_injection_uri_query_success'= Command
          Injection Check url query arguments passed;
          'request_check_command_injection_uri_query_violation'= Command Injection Check
          url query arguments violation;
          'request_check_command_injection_form_body_success'= Command Injection Check
          form body arguments passed;
          'request_check_command_injection_form_body_violation'= Command Injection Check
          form body arguments violation;
          'cookie_security_decrypt_in_grace_period_violation'= Cookie Decrypt violation
          but in grace period; 'form_response_non_post_success'= Response form method was
          POST; 'form_response_non_post_violation'= Response form method was not POST;
          'form_response_non_post_sanitize'= Changed response form method to POST;
          'xml_check_max_entity_decl_success'= XML Limit Entity Decl check passed;
          'xml_check_max_entity_decl_violation'= XML Limit Entity Decl violation;
          'xml_check_max_entity_depth_success'= XML Limit Entity Depth check passed;
          'xml_check_max_entity_depth_violation'= XML Limit Entity Depth violation;
          'action_response_allow'= Response Action allowed; 'action_response_deny_200'=
          Response Deny with 200;"
                type: str
            counters4:
                description:
                - "'action_response_deny_403'= Response Deny with 403;
          'action_response_deny_redirect'= Response Deny with Redirect;
          'action_response_deny_reset'= Deny with Resets; 'action_response_drop'= Number
          of Dropped Responses; 'action_response_deny_custom_response'= Response Deny
          with custom response; 'action_response_learn'= Response Learning Updates;
          'action_response_log'= Log response violation;
          'http_protocol_post_without_content_type_success'= POST without content type
          check passed; 'http_protocol_post_without_content_type_violation'= POST without
          content type check violation;
          'http_protocol_body_without_content_type_success'= Body without content type
          check passed; 'http_protocol_body_without_content_type_violation'= Body without
          content type check violation; 'http_protocol_non_ssl_cookie_prefix_success'=
          Cookie Name Prefix check passed;
          'http_protocol_non_ssl_cookie_prefix_violation'= Cookie Name Prefix check
          violation; 'cookie_security_add_samesite_success'= Cookie Security - samesite
          attribute added successfully; 'cookie_security_add_samesite_violation'= Cookie
          Security - samesite attribute violation; 'rule_set_request'= Requests hanlded
          by WAF rule set; 'rule_set_response'= Responses hanlded by WAF rule set;
          'phase1_pass'= WAF rule set pass hits in phase 1; 'phase1_allow'= WAF rule set
          allow hits in phase 1; 'phase1_deny'= WAF rule set deny hits in phase 1;
          'phase1_drop'= WAF rule set drop hits in phase 1; 'phase1_redirect'= WAF rule
          set redirect hits in phase 1; 'phase1_other'= WAF rule set other hits in phase
          1; 'phase2_pass'= WAF rule set pass hits in phase 2; 'phase2_allow'= WAF rule
          set allow hits in phase 2; 'phase2_deny'= WAF rule set deny hits in phase 2;
          'phase2_drop'= WAF rule set drop hits in phase 2; 'phase2_redirect'= WAF rule
          set redirect hits in phase 2; 'phase2_other'= WAF rule set other hits in phase
          2; 'phase3_pass'= WAF rule set pass hits in phase 3; 'phase3_allow'= WAF rule
          set allow hits in phase 3; 'phase3_deny'= WAF rule set deny hits in phase 3;
          'phase3_drop'= WAF rule set drop hits in phase 3; 'phase3_redirect'= WAF rule
          set redirect hits in phase 3; 'phase3_other'= WAF rule set other hits in phase
          3; 'phase4_pass'= WAF rule set pass hits in phase 4; 'phase4_allow'= WAF rule
          set allow hits in phase 4; 'phase4_deny'= WAF rule set deny hits in phase 4;
          'phase4_drop'= WAF rule set drop hits in phase 4; 'phase4_redirect'= WAF rule
          set redirect hits in phase 4; 'phase4_other'= WAF rule set other hits in phase
          4;"
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
            resp_denied:
                description:
                - "Responses Denied"
                type: str
            brute_force_success:
                description:
                - "Brute-Force checks passed"
                type: str
            brute_force_violation:
                description:
                - "Brute-Force checks violation"
                type: str
            brute_force_challenge_cookie_sent:
                description:
                - "Cookie Challenge Sent"
                type: str
            brute_force_challenge_cookie_success:
                description:
                - "Cookie Challenge check passed"
                type: str
            brute_force_challenge_cookie_violation:
                description:
                - "Cookie challenge violation"
                type: str
            brute_force_challenge_javascript_sent:
                description:
                - "JavaScript challenge sent"
                type: str
            brute_force_challenge_javascript_success:
                description:
                - "JavaScript challenge check passed"
                type: str
            brute_force_challenge_javascript_violation:
                description:
                - "JavaScript challenge violation"
                type: str
            brute_force_challenge_captcha_sent:
                description:
                - "Captcha challenge sent"
                type: str
            brute_force_challenge_captcha_success:
                description:
                - "Captcha challenge check passed"
                type: str
            brute_force_challenge_captcha_violation:
                description:
                - "Captcha challenge violation"
                type: str
            brute_force_lockout_limit_success:
                description:
                - "Lockout limit check passed"
                type: str
            brute_force_lockout_limit_violation:
                description:
                - "Lockout limit violation"
                type: str
            brute_force_challenge_limit_success:
                description:
                - "Lockout limit check passed"
                type: str
            brute_force_challenge_limit_violation:
                description:
                - "Lockout limit violation"
                type: str
            brute_force_response_codes_triggered:
                description:
                - "Response Codes Triggered"
                type: str
            brute_force_response_headers_triggered:
                description:
                - "Brute Force Response Headers Triggered"
                type: str
            brute_force_response_string_triggered:
                description:
                - "Brute Force Response string Triggered"
                type: str
            cookie_security_encrypt_success:
                description:
                - "Cookie Security - encrypt successful"
                type: str
            cookie_security_encrypt_violation:
                description:
                - "Cookie Security - encrypt violation"
                type: str
            cookie_security_encrypt_limit_exceeded:
                description:
                - "Cookie Security - encrypt limit exceeded"
                type: str
            cookie_security_encrypt_skip_rcache:
                description:
                - "Cookie Security - encrypt skipped - RAM cache"
                type: str
            cookie_security_decrypt_success:
                description:
                - "Cookie Security - decrypt successful"
                type: str
            cookie_security_decrypt_violation:
                description:
                - "Cookie Security - decrypt violation"
                type: str
            cookie_security_sign_success:
                description:
                - "Cookie Security - signing successful"
                type: str
            cookie_security_sign_violation:
                description:
                - "Cookie Security - signing violation"
                type: str
            cookie_security_sign_limit_exceeded:
                description:
                - "Cookie Security - signing limit exceeded"
                type: str
            cookie_security_sign_skip_rcache:
                description:
                - "Cookie Security - signing skipped - RAM cache"
                type: str
            cookie_security_signature_check_success:
                description:
                - "Cookie Security - signature check successful"
                type: str
            cookie_security_signature_check_violation:
                description:
                - "Cookie Security - signature check failed"
                type: str
            cookie_security_add_http_only_success:
                description:
                - "Cookie Security - http-only flag added successfully"
                type: str
            cookie_security_add_http_only_violation:
                description:
                - "Cookie Security - http-only flag violation"
                type: str
            cookie_security_add_secure_success:
                description:
                - "Cookie Security - secure flag added successfully"
                type: str
            cookie_security_add_secure_violation:
                description:
                - "Cookie Security - secure flag violation"
                type: str
            cookie_security_missing_cookie_success:
                description:
                - "Cookie Security - request with missing cookie"
                type: str
            cookie_security_missing_cookie_violation:
                description:
                - "Cookie Security - missing cookie violation"
                type: str
            cookie_security_unrecognized_cookie_success:
                description:
                - "Cookie Security - request with unrecognized cookie"
                type: str
            cookie_security_unrecognized_cookie_violation:
                description:
                - "Cookie Security - unrecognized cookie violation"
                type: str
            cookie_security_cookie_policy_success:
                description:
                - "Cookie Security - cookie policy passed"
                type: str
            cookie_security_cookie_policy_violation:
                description:
                - "Cookie Security - cookie policy violation"
                type: str
            cookie_security_persistent_cookies:
                description:
                - "Cookie Security - persistent cookies"
                type: str
            cookie_security_persistent_cookies_encrypted:
                description:
                - "Cookie Security - encrypted persistent cookies"
                type: str
            cookie_security_persistent_cookies_signed:
                description:
                - "Cookie Security - signed persistent cookies"
                type: str
            cookie_security_session_cookies:
                description:
                - "Cookie Security - session cookies"
                type: str
            cookie_security_session_cookies_encrypted:
                description:
                - "Cookie Security - encrypted session cookies"
                type: str
            cookie_security_session_cookies_signed:
                description:
                - "Cookie Security - signed session cookies"
                type: str
            cookie_security_allowed_session_cookies:
                description:
                - "Cookie Security - allowed session cookies"
                type: str
            cookie_security_allowed_persistent_cookies:
                description:
                - "Cookie Security - allowed persistent cookies"
                type: str
            cookie_security_disallowed_session_cookies:
                description:
                - "Cookie Security - disallowed session cookies"
                type: str
            cookie_security_disallowed_persistent_cookies:
                description:
                - "Cookie Security - disallowed persistent cookies"
                type: str
            cookie_security_allowed_session_set_cookies:
                description:
                - "Cookie Security - allowed session Set-Cookies"
                type: str
            cookie_security_allowed_persistent_set_cookies:
                description:
                - "Cookie Security - allowed persistent Set-Cookies"
                type: str
            cookie_security_disallowed_session_set_cookies:
                description:
                - "Cookie Security - disallowed session Set-Cookies"
                type: str
            cookie_security_disallowed_persistent_set_cookies:
                description:
                - "Cookie Security - disallowed persistent Set-Cookies"
                type: str
            csp_header_violation:
                description:
                - "CSP header_missing"
                type: str
            csp_header_success:
                description:
                - "CSP header found"
                type: str
            csp_header_inserted:
                description:
                - "CSP header Inserted"
                type: str
            form_csrf_tag_success:
                description:
                - "Form CSRF tag passed"
                type: str
            form_csrf_tag_violation:
                description:
                - "Form CSRF tag violation"
                type: str
            form_consistency_success:
                description:
                - "Form Consistency passed"
                type: str
            form_consistency_violation:
                description:
                - "Form Consistency violation"
                type: str
            form_tag_inserted:
                description:
                - "Form A10 Tag Inserted"
                type: str
            form_non_ssl_success:
                description:
                - "Form Non SSL check passed"
                type: str
            form_non_ssl_violation:
                description:
                - "Form Non SSL violation"
                type: str
            form_request_non_post_success:
                description:
                - "Form Method being Non Post in Request passed"
                type: str
            form_request_non_post_violation:
                description:
                - "Form Method being Non Post in Request violation"
                type: str
            form_check_success:
                description:
                - "Post Form Check passed"
                type: str
            form_check_violation:
                description:
                - "Post Form Check violation"
                type: str
            form_check_sanitize:
                description:
                - "Post Form Check Sanitized"
                type: str
            form_non_masked_password_success:
                description:
                - "Form Non Masked Password check passed"
                type: str
            form_non_masked_password_violation:
                description:
                - "Form Non Masked Password violation"
                type: str
            form_non_ssl_password_success:
                description:
                - "Form Non SSL Password check passed"
                type: str
            form_non_ssl_password_violation:
                description:
                - "Form Non SSL Password violation"
                type: str
            form_password_autocomplete_success:
                description:
                - "Form Password Autocomplete check passed"
                type: str
            form_password_autocomplete_violation:
                description:
                - "Form Password Autocomplete violation"
                type: str
            form_set_no_cache_success:
                description:
                - "Form Set No Cache check passed"
                type: str
            form_set_no_cache:
                description:
                - "Form Set No Cache violation"
                type: str
            dlp_ccn_success:
                description:
                - "Credit Card Number check passed"
                type: str
            dlp_ccn_amex_violation:
                description:
                - "Amex Credit Card Number Detected"
                type: str
            dlp_ccn_amex_masked:
                description:
                - "Amex Credit Card Number Masked"
                type: str
            dlp_ccn_diners_violation:
                description:
                - "Diners Club Credit Card Number Detected"
                type: str
            dlp_ccn_diners_masked:
                description:
                - "Diners Club Credit Card Number Masked"
                type: str
            dlp_ccn_visa_violation:
                description:
                - "Visa Credit Card Number Detected"
                type: str
            dlp_ccn_visa_masked:
                description:
                - "Visa Credit Card Number Masked"
                type: str
            dlp_ccn_mastercard_violation:
                description:
                - "MasterCard Credit Card Number Detected"
                type: str
            dlp_ccn_mastercard_masked:
                description:
                - "MasterCard Credit Card Number Masked"
                type: str
            dlp_ccn_discover_violation:
                description:
                - "Discover Credit Card Number Detected"
                type: str
            dlp_ccn_discover_masked:
                description:
                - "Discover Credit Card Number Masked"
                type: str
            dlp_ccn_jcb_violation:
                description:
                - "JCB Credit Card Number Detected"
                type: str
            dlp_ccn_jcb_masked:
                description:
                - "JCB Credit Card Number Masked"
                type: str
            dlp_ssn_success:
                description:
                - "Social Security Number Mask check passed"
                type: str
            dlp_ssn_violation:
                description:
                - "Social Security Number Mask violation"
                type: str
            dlp_pcre_success:
                description:
                - "PCRE Mask check passed"
                type: str
            dlp_pcre_violation:
                description:
                - "PCRE Mask violation"
                type: str
            dlp_pcre_masked:
                description:
                - "PCRE Mask violation"
                type: str
            evasion_check_apache_whitespace_success:
                description:
                - "Apache Whitespace check passed"
                type: str
            evasion_check_apache_whitespace_violation:
                description:
                - "Apache Whitespace check violation"
                type: str
            evasion_check_decode_entities_success:
                description:
                - "Decode Entities check passed"
                type: str
            evasion_check_decode_entities_violation:
                description:
                - "Decode Entities check violation"
                type: str
            evasion_check_decode_escaped_chars_success:
                description:
                - "Decode Escaped Chars check passed"
                type: str
            evasion_check_decode_escaped_chars_violation:
                description:
                - "Decode Escaped Chars check violation"
                type: str
            evasion_check_decode_unicode_chars_success:
                description:
                - "Decode Unicode Chars check passed"
                type: str
            evasion_check_decode_unicode_chars_violation:
                description:
                - "Decode Unicode Chars check violation"
                type: str
            evasion_check_dir_traversal_success:
                description:
                - "Dir traversal check passed"
                type: str
            evasion_check_dir_traversal_violation:
                description:
                - "Dir traversal check violation"
                type: str
            evasion_check_high_ascii_bytes_success:
                description:
                - "High Ascii Bytes check passed"
                type: str
            evasion_check_high_ascii_bytes_violation:
                description:
                - "High Ascii Bytes check violation"
                type: str
            evasion_check_invalid_hex_encoding_success:
                description:
                - "Invalid Hex Encoding check passed"
                type: str
            evasion_check_invalid_hex_encoding_violation:
                description:
                - "Invalid Hex Encoding check violation"
                type: str
            evasion_check_multiple_encoding_levels_success:
                description:
                - "Multiple Encoding Levels check passed"
                type: str
            evasion_check_multiple_encoding_levels_violation:
                description:
                - "Multiple Encoding Levels check violation"
                type: str
            evasion_check_multiple_slashes_success:
                description:
                - "Multiple Slashes check passed"
                type: str
            evasion_check_multiple_slashes_violation:
                description:
                - "Multiple Slashes check violation"
                type: str
            evasion_check_max_levels_success:
                description:
                - "Max Levels check passed"
                type: str
            evasion_check_max_levels_violation:
                description:
                - "Max Levels check violation"
                type: str
            evasion_check_remove_comments_success:
                description:
                - "Remove Comments check passed"
                type: str
            evasion_check_remove_comments_violation:
                description:
                - "Remove Comments check violation"
                type: str
            evasion_check_remove_spaces_success:
                description:
                - "Remove Spaces check passed"
                type: str
            evasion_check_remove_spaces_violation:
                description:
                - "Remove Spaces check violation"
                type: str
            http_limit_max_content_length_success:
                description:
                - "MAX content-length check passed"
                type: str
            http_limit_max_content_length_violation:
                description:
                - "MAX content-length check violation"
                type: str
            http_limit_max_cookie_header_length_success:
                description:
                - "MAX cookie header length check passed"
                type: str
            http_limit_max_cookie_header_length_violation:
                description:
                - "MAX cookie header length violation"
                type: str
            http_limit_max_cookie_name_length_success:
                description:
                - "MAX cookie name length check passed"
                type: str
            http_limit_max_cookie_name_length_violation:
                description:
                - "MAX cookie name length violation"
                type: str
            http_limit_max_cookie_value_length_success:
                description:
                - "MAX cookie value length check passed"
                type: str
            http_limit_max_cookie_value_length_violation:
                description:
                - "MAX cookie value length violation"
                type: str
            http_limit_max_cookies_success:
                description:
                - "Max Cookies check passed"
                type: str
            http_limit_max_cookies_violation:
                description:
                - "Max Cookies violation"
                type: str
            http_limit_max_cookies_length_success:
                description:
                - "MAX cookies length check passed"
                type: str
            http_limit_max_cookies_length_violation:
                description:
                - "MAX cookies length violation"
                type: str
            http_limit_max_data_parse_success:
                description:
                - "Buffer Overflow - Max Data Parse check passed"
                type: str
            http_limit_max_data_parse_violation:
                description:
                - "Buffer Overflow - Max Data Parse violation"
                type: str
            http_limit_max_entities_success:
                description:
                - "Max Entities check passed"
                type: str
            http_limit_max_entities_violation:
                description:
                - "Max Entities violation"
                type: str
            http_limit_max_header_length_success:
                description:
                - "MAX header length check passed"
                type: str
            http_limit_max_header_length_violation:
                description:
                - "MAX header length check violation"
                type: str
            http_limit_max_header_name_length_success:
                description:
                - "MAX header name length check passed"
                type: str
            http_limit_max_header_name_length_violation:
                description:
                - "MAX header name length check violation"
                type: str
            http_limit_max_header_value_length_success:
                description:
                - "MAX header value length check passed"
                type: str
            http_limit_max_header_value_length_violation:
                description:
                - "MAX header value length check violation"
                type: str
            http_limit_max_headers_success:
                description:
                - "MAX headers count check passed"
                type: str
            http_limit_max_headers_violation:
                description:
                - "Max Headers violation"
                type: str
            http_limit_max_headers_length_success:
                description:
                - "MAX headers length check passed"
                type: str
            http_limit_max_headers_length_violation:
                description:
                - "MAX headers length check violation"
                type: str
            http_limit_max_param_name_length_success:
                description:
                - "Limit check - MAX parameter name length check passed"
                type: str
            http_limit_max_param_name_length_violation:
                description:
                - "Limit check - MAX parameter name length violation"
                type: str
            http_limit_max_param_value_length_success:
                description:
                - "Limit check - MAX parameter value length check passed"
                type: str
            http_limit_max_param_value_length_violation:
                description:
                - "Limit check - MAX parameter value length violation"
                type: str
            http_limit_max_params_success:
                description:
                - "Limit check - MAX parameters check passed"
                type: str
            http_limit_max_params_violation:
                description:
                - "Limit check - MAX parameters violation"
                type: str
            http_limit_max_params_length_success:
                description:
                - "Limit check - MAX parameters total length check passed"
                type: str
            http_limit_max_params_length_violation:
                description:
                - "Limit check - MAX parameters total length violation"
                type: str
            http_limit_max_post_length_success:
                description:
                - "MAX POST length check passed"
                type: str
            http_limit_max_post_length_violation:
                description:
                - "MAX POST length violation"
                type: str
            http_limit_max_query_length_success:
                description:
                - "Limit check - MAX query length check passed"
                type: str
            http_limit_max_query_length_violation:
                description:
                - "Limit check - MAX query length violation"
                type: str
            http_limit_max_request_length_success:
                description:
                - "Limit check - MAX request length check passed"
                type: str
            http_limit_max_request_length_violation:
                description:
                - "Limit check - MAX request length violation"
                type: str
            http_limit_max_request_line_length_success:
                description:
                - "Limit check - MAX request line length check passed"
                type: str
            http_limit_max_request_line_length_violation:
                description:
                - "Limit check - MAX request line length violation"
                type: str
            max_url_length_success:
                description:
                - "Limit check - MAX URL length check passed"
                type: str
            max_url_length_violation:
                description:
                - "Limit check - MAX URL length violation"
                type: str
            http_protocol_allowed_headers_success:
                description:
                - "HTTP headers check passed"
                type: str
            http_protocol_allowed_headers_violation:
                description:
                - "HTTP headers check violation"
                type: str
            http_protocol_allowed_versions_success:
                description:
                - "HTTP versions check passed"
                type: str
            http_protocol_allowed_versions_violation:
                description:
                - "HTTP versions check violation"
                type: str
            http_protocol_allowed_method_check_success:
                description:
                - "HTTP Method Check passed"
                type: str
            http_protocol_allowed_method_check_violation:
                description:
                - "HTTP Method Check violation"
                type: str
            http_protocol_bad_multipart_request_success:
                description:
                - "Bad multi-part request check passed"
                type: str
            http_protocol_bad_multipart_request_violation:
                description:
                - "Bad multi-part request check violation"
                type: str
            http_protocol_get_with_content_success:
                description:
                - "GET with content check passed"
                type: str
            http_protocol_get_with_content_violation:
                description:
                - "GET with content check violation"
                type: str
            http_protocol_head_with_content_success:
                description:
                - "HEAD with content check passed"
                type: str
            http_protocol_head_with_content_violation:
                description:
                - "HEAD with content check violation"
                type: str
            http_protocol_host_header_with_ip_success:
                description:
                - "Host header with IP check passed"
                type: str
            http_protocol_host_header_with_ip_violation:
                description:
                - "Host header with IP check violation"
                type: str
            http_protocol_invalid_url_encoding_success:
                description:
                - "Invalid url encoding check passed"
                type: str
            http_protocol_invalid_url_encoding_violation:
                description:
                - "Invalid url encoding check violation"
                type: str
            http_protocol_malformed_content_length_success:
                description:
                - "Malformed content-length check passed"
                type: str
            http_protocol_malformed_content_length_violation:
                description:
                - "Malformed content-length check violation"
                type: str
            http_protocol_malformed_header_success:
                description:
                - "Malformed header check passed"
                type: str
            http_protocol_malformed_header_violation:
                description:
                - "Malformed header check passed"
                type: str
            http_protocol_malformed_parameter_success:
                description:
                - "Malformed parameter check passed"
                type: str
            http_protocol_malformed_parameter_violation:
                description:
                - "Malformed parameter check violation"
                type: str
            http_protocol_malformed_request_success:
                description:
                - "Malformed request check passed"
                type: str
            http_protocol_malformed_request_violation:
                description:
                - "Malformed request check violation"
                type: str
            http_protocol_malformed_request_line_success:
                description:
                - "Malformed request line check passed"
                type: str
            http_protocol_malformed_request_line_violation:
                description:
                - "Malformed request line check violation"
                type: str
            http_protocol_missing_header_value_success:
                description:
                - "Missing header value check violation"
                type: str
            http_protocol_missing_header_value_violation:
                description:
                - "Missing header value check violation"
                type: str
            http_protocol_missing_host_header_success:
                description:
                - "Missing host header check passed"
                type: str
            http_protocol_missing_host_header_violation:
                description:
                - "Missing host header check violation"
                type: str
            http_protocol_multiple_content_length_success:
                description:
                - "Multiple content-length headers check passed"
                type: str
            http_protocol_multiple_content_length_violation:
                description:
                - "Multiple content-length headers check violation"
                type: str
            http_protocol_post_with_0_content_success:
                description:
                - "POST with 0 content check passed"
                type: str
            http_protocol_post_with_0_content_violation:
                description:
                - "POST with 0 content check violation"
                type: str
            http_protocol_post_without_content_success:
                description:
                - "POST without content check passed"
                type: str
            http_protocol_post_without_content_violation:
                description:
                - "POST without content check violation"
                type: str
            http_protocol_success:
                description:
                - "HTTP Check passed"
                type: str
            http_protocol_violation:
                description:
                - "HTTP Check violation"
                type: str
            json_check_format_success:
                description:
                - "JSON Check passed"
                type: str
            json_check_format_violation:
                description:
                - "JSON Check violation"
                type: str
            json_check_max_array_value_count_success:
                description:
                - "JSON Limit Array Value Count check passed"
                type: str
            json_check_max_array_value_count_violation:
                description:
                - "JSON Limit Array Value Count violation"
                type: str
            json_check_max_depth_success:
                description:
                - "JSON Limit Depth check passed"
                type: str
            json_check_max_depth_violation:
                description:
                - "JSON Limit Depth violation"
                type: str
            json_check_max_object_member_count_success:
                description:
                - "JSON Limit Object Number Count check passed"
                type: str
            json_check_max_object_member_count_violation:
                description:
                - "JSON Limit Object Number Count violation"
                type: str
            json_check_max_string_success:
                description:
                - "JSON Limit String check passed"
                type: str
            json_check_max_string_violation:
                description:
                - "JSON Limit String violation"
                type: str
            request_check_bot_success:
                description:
                - "Bot check passed"
                type: str
            request_check_bot_violation:
                description:
                - "Bot check violation"
                type: str
            request_check_redirect_wlist_success:
                description:
                - "Redirect Whitelist passed"
                type: str
            request_check_redirect_wlist_violation:
                description:
                - "Redirect Whitelist violation"
                type: str
            request_check_redirect_wlist_learn:
                description:
                - "Redirect Whitelist Learn"
                type: str
            request_check_referer_success:
                description:
                - "Referer Check passed"
                type: str
            request_check_referer_violation:
                description:
                - "Referer Check violation"
                type: str
            request_check_referer_redirect:
                description:
                - "Referer Check Redirect"
                type: str
            request_check_session_check_none:
                description:
                - "Session Created"
                type: str
            request_check_session_check_success:
                description:
                - "Session Check passed"
                type: str
            request_check_session_check_violation:
                description:
                - "Session Check violation"
                type: str
            request_check_sqlia_url_success:
                description:
                - "SQLIA Check URL passed"
                type: str
            request_check_sqlia_url_violation:
                description:
                - "SQLIA Check URL violation"
                type: str
            request_check_sqlia_url_sanitize:
                description:
                - "SQLIA Check URL Sanitized"
                type: str
            request_check_sqlia_post_body_success:
                description:
                - "SQLIA Check Post passed"
                type: str
            request_check_sqlia_post_body_violation:
                description:
                - "SQLIA Check Post violation"
                type: str
            request_check_sqlia_post_body_sanitize:
                description:
                - "SQLIA Check Post Sanitized"
                type: str
            request_check_url_list_success:
                description:
                - "URL Check passed"
                type: str
            request_check_url_list_violation:
                description:
                - "URL Check violation"
                type: str
            request_check_url_list_learn:
                description:
                - "URL Check Learn"
                type: str
            request_check_url_whitelist_success:
                description:
                - "URI White List passed"
                type: str
            request_check_url_whitelist_violation:
                description:
                - "URI White List violation"
                type: str
            request_check_url_blacklist_success:
                description:
                - "URI Black List passed"
                type: str
            request_check_url_blacklist_violation:
                description:
                - "URI Black List violation"
                type: str
            request_check_xss_cookie_success:
                description:
                - "XSS Check Cookie passed"
                type: str
            request_check_xss_cookie_violation:
                description:
                - "XSS Check Cookie violation"
                type: str
            request_check_xss_cookie_sanitize:
                description:
                - "XSS Check Cookie Sanitized"
                type: str
            request_check_xss_url_success:
                description:
                - "XSS Check URL passed"
                type: str
            request_check_xss_url_violation:
                description:
                - "XSS Check URL violation"
                type: str
            request_check_xss_url_sanitize:
                description:
                - "XSS Check URL Sanitized"
                type: str
            request_check_xss_post_body_success:
                description:
                - "XSS Check Post passed"
                type: str
            request_check_xss_post_body_violation:
                description:
                - "XSS Check Post violation"
                type: str
            request_check_xss_post_body_sanitize:
                description:
                - "XSS Check Post Sanitized"
                type: str
            response_cloaking_hide_status_code_success:
                description:
                - "Response Hide Code check passed"
                type: str
            response_cloaking_hide_status_code_violation:
                description:
                - "Response Hide Code violation"
                type: str
            response_cloaking_filter_headers_success:
                description:
                - "Response Headers Filter check passed"
                type: str
            response_cloaking_filter_headers_violation:
                description:
                - "Response Headers Filter violation"
                type: str
            soap_check_success:
                description:
                - "Soap Check passed"
                type: str
            soap_check_violation:
                description:
                - "Soap Check violation"
                type: str
            xml_check_format_success:
                description:
                - "XML Check passed"
                type: str
            xml_check_format_violation:
                description:
                - "XML Check violation"
                type: str
            xml_check_max_attr_success:
                description:
                - "XML Limit Attribute check passed"
                type: str
            xml_check_max_attr_violation:
                description:
                - "XML Limit Attribute violation"
                type: str
            xml_check_max_attr_name_len_success:
                description:
                - "XML Limit Name Length check passed"
                type: str
            xml_check_max_attr_name_len_violation:
                description:
                - "XML Limit Name Length violation"
                type: str
            xml_check_max_attr_value_len_success:
                description:
                - "XML Limit Value Length check passed"
                type: str
            xml_check_max_attr_value_len_violation:
                description:
                - "XML Limit Value Length violation"
                type: str
            xml_check_max_cdata_len_success:
                description:
                - "XML Limit CData Length check passed"
                type: str
            xml_check_max_cdata_len_violation:
                description:
                - "XML Limit CData Length violation"
                type: str
            xml_check_max_elem_success:
                description:
                - "XML Limit Element check passed"
                type: str
            xml_check_max_elem_violation:
                description:
                - "XML Limit Element violation"
                type: str
            xml_check_max_elem_child_success:
                description:
                - "XML Limit Element Child check passed"
                type: str
            xml_check_max_elem_child_violation:
                description:
                - "XML Limit Element Child violation"
                type: str
            xml_check_max_elem_depth_success:
                description:
                - "XML Limit Element Depth check passed"
                type: str
            xml_check_max_elem_depth_violation:
                description:
                - "XML Limit Element Depth violation"
                type: str
            xml_check_max_elem_name_len_success:
                description:
                - "XML Limit Element Name Length check passed"
                type: str
            xml_check_max_elem_name_len_violation:
                description:
                - "XML Limit Element Name Length violation"
                type: str
            xml_check_max_entity_exp_success:
                description:
                - "XML Limit Entity Expansions check passed"
                type: str
            xml_check_max_entity_exp_violation:
                description:
                - "XML Limit Entity Expansions violation"
                type: str
            xml_check_max_entity_exp_depth_success:
                description:
                - "XML Limit Entities Depth check passed"
                type: str
            xml_check_max_entity_exp_depth_violation:
                description:
                - "XML Limit Entities Depth violation"
                type: str
            xml_check_max_namespace_success:
                description:
                - "XML Limit Namespace check passed"
                type: str
            xml_check_max_namespace_violation:
                description:
                - "XML Limit Namespace violation"
                type: str
            xml_check_namespace_uri_len_success:
                description:
                - "XML Limit Namespace URI Length check passed"
                type: str
            xml_check_namespace_uri_len_violation:
                description:
                - "XML Limit Namespace URI Length violation"
                type: str
            xml_check_sqlia_success:
                description:
                - "XML Sqlia Check passed"
                type: str
            xml_check_sqlia_violation:
                description:
                - "XML Sqlia Check violation"
                type: str
            xml_check_xss_success:
                description:
                - "XML XSS Check passed"
                type: str
            xml_check_xss_violation:
                description:
                - "XML XSS Check violation"
                type: str
            xml_content_check_schema_success:
                description:
                - "XML Schema passed"
                type: str
            xml_content_check_schema_violation:
                description:
                - "XML Schema violation"
                type: str
            xml_content_check_wsdl_success:
                description:
                - "WSDL passed"
                type: str
            xml_content_check_wsdl_violation:
                description:
                - "WSDL violation"
                type: str
            learning_list_full:
                description:
                - "Learning list is full"
                type: str
            action_allow:
                description:
                - "Request Action allowed"
                type: str
            action_deny_200:
                description:
                - "Request Deny with 200"
                type: str
            action_deny_403:
                description:
                - "Request Deny with 403"
                type: str
            action_deny_redirect:
                description:
                - "Request Deny with Redirect"
                type: str
            action_deny_reset:
                description:
                - "Request Deny with Resets"
                type: str
            action_drop:
                description:
                - "Number of Dropped Requests"
                type: str
            action_deny_custom_response:
                description:
                - "Request Deny with custom response"
                type: str
            action_learn:
                description:
                - "Request Learning Updates"
                type: str
            action_log:
                description:
                - "Log request violation"
                type: str
            policy_limit_exceeded:
                description:
                - "Policy limit exceeded"
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
            regex_violation:
                description:
                - "Regular expression failure"
                type: str
            request_check_command_injection_cookies_success:
                description:
                - "Command Injection Check cookies passed"
                type: str
            request_check_command_injection_cookies_violation:
                description:
                - "Command Injection Check cookies violation"
                type: str
            request_check_command_injection_headers_success:
                description:
                - "Command Injection Check headers passed"
                type: str
            request_check_command_injection_headers_violation:
                description:
                - "Command Injection Check headers violation"
                type: str
            request_check_command_injection_uri_query_success:
                description:
                - "Command Injection Check url query arguments passed"
                type: str
            request_check_command_injection_uri_query_violation:
                description:
                - "Command Injection Check url query arguments violation"
                type: str
            request_check_command_injection_form_body_success:
                description:
                - "Command Injection Check form body arguments passed"
                type: str
            request_check_command_injection_form_body_violation:
                description:
                - "Command Injection Check form body arguments violation"
                type: str
            cookie_security_decrypt_in_grace_period_violation:
                description:
                - "Cookie Decrypt violation but in grace period"
                type: str
            form_response_non_post_success:
                description:
                - "Response form method was POST"
                type: str
            form_response_non_post_violation:
                description:
                - "Response form method was not POST"
                type: str
            form_response_non_post_sanitize:
                description:
                - "Changed response form method to POST"
                type: str
            xml_check_max_entity_decl_success:
                description:
                - "XML Limit Entity Decl check passed"
                type: str
            xml_check_max_entity_decl_violation:
                description:
                - "XML Limit Entity Decl violation"
                type: str
            xml_check_max_entity_depth_success:
                description:
                - "XML Limit Entity Depth check passed"
                type: str
            xml_check_max_entity_depth_violation:
                description:
                - "XML Limit Entity Depth violation"
                type: str
            action_response_allow:
                description:
                - "Response Action allowed"
                type: str
            action_response_deny_200:
                description:
                - "Response Deny with 200"
                type: str
            action_response_deny_403:
                description:
                - "Response Deny with 403"
                type: str
            action_response_deny_redirect:
                description:
                - "Response Deny with Redirect"
                type: str
            action_response_deny_reset:
                description:
                - "Deny with Resets"
                type: str
            action_response_drop:
                description:
                - "Number of Dropped Responses"
                type: str
            action_response_deny_custom_response:
                description:
                - "Response Deny with custom response"
                type: str
            action_response_learn:
                description:
                - "Response Learning Updates"
                type: str
            action_response_log:
                description:
                - "Log response violation"
                type: str
            http_protocol_post_without_content_type_success:
                description:
                - "POST without content type check passed"
                type: str
            http_protocol_post_without_content_type_violation:
                description:
                - "POST without content type check violation"
                type: str
            http_protocol_body_without_content_type_success:
                description:
                - "Body without content type check passed"
                type: str
            http_protocol_body_without_content_type_violation:
                description:
                - "Body without content type check violation"
                type: str
            http_protocol_non_ssl_cookie_prefix_success:
                description:
                - "Cookie Name Prefix check passed"
                type: str
            http_protocol_non_ssl_cookie_prefix_violation:
                description:
                - "Cookie Name Prefix check violation"
                type: str
            cookie_security_add_samesite_success:
                description:
                - "Cookie Security - samesite attribute added successfully"
                type: str
            cookie_security_add_samesite_violation:
                description:
                - "Cookie Security - samesite attribute violation"
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
AVAILABLE_PROPERTIES = ["immediate_action", "sampling_enable", "stats", "uuid", ]


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
    rv.update({'immediate_action': {'type': 'bool', },
        'uuid': {'type': 'str', },
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'total_req', 'req_allowed', 'req_denied', 'resp_denied', 'brute_force_success', 'brute_force_violation', 'brute_force_challenge_cookie_sent', 'brute_force_challenge_cookie_success', 'brute_force_challenge_cookie_violation', 'brute_force_challenge_javascript_sent', 'brute_force_challenge_javascript_success', 'brute_force_challenge_javascript_violation', 'brute_force_challenge_captcha_sent', 'brute_force_challenge_captcha_success', 'brute_force_challenge_captcha_violation', 'brute_force_lockout_limit_success', 'brute_force_lockout_limit_violation', 'brute_force_challenge_limit_success', 'brute_force_challenge_limit_violation', 'brute_force_response_codes_triggered', 'brute_force_response_headers_triggered', 'brute_force_response_string_triggered', 'cookie_security_encrypt_success', 'cookie_security_encrypt_violation', 'cookie_security_encrypt_limit_exceeded', 'cookie_security_encrypt_skip_rcache', 'cookie_security_decrypt_success', 'cookie_security_decrypt_violation', 'cookie_security_sign_success', 'cookie_security_sign_violation', 'cookie_security_sign_limit_exceeded', 'cookie_security_sign_skip_rcache', 'cookie_security_signature_check_success', 'cookie_security_signature_check_violation', 'cookie_security_add_http_only_success', 'cookie_security_add_http_only_violation', 'cookie_security_add_secure_success', 'cookie_security_add_secure_violation', 'cookie_security_missing_cookie_success', 'cookie_security_missing_cookie_violation', 'cookie_security_unrecognized_cookie_success', 'cookie_security_unrecognized_cookie_violation', 'cookie_security_cookie_policy_success', 'cookie_security_cookie_policy_violation', 'cookie_security_persistent_cookies', 'cookie_security_persistent_cookies_encrypted', 'cookie_security_persistent_cookies_signed', 'cookie_security_session_cookies', 'cookie_security_session_cookies_encrypted', 'cookie_security_session_cookies_signed', 'cookie_security_allowed_session_cookies', 'cookie_security_allowed_persistent_cookies', 'cookie_security_disallowed_session_cookies', 'cookie_security_disallowed_persistent_cookies', 'cookie_security_allowed_session_set_cookies', 'cookie_security_allowed_persistent_set_cookies', 'cookie_security_disallowed_session_set_cookies', 'cookie_security_disallowed_persistent_set_cookies', 'csp_header_violation', 'csp_header_success', 'csp_header_inserted', 'form_csrf_tag_success', 'form_csrf_tag_violation', 'form_consistency_success', 'form_consistency_violation', 'form_tag_inserted', 'form_non_ssl_success', 'form_non_ssl_violation', 'form_request_non_post_success', 'form_request_non_post_violation', 'form_check_success', 'form_check_violation', 'form_check_sanitize', 'form_non_masked_password_success', 'form_non_masked_password_violation', 'form_non_ssl_password_success', 'form_non_ssl_password_violation', 'form_password_autocomplete_success', 'form_password_autocomplete_violation', 'form_set_no_cache_success', 'form_set_no_cache', 'dlp_ccn_success', 'dlp_ccn_amex_violation', 'dlp_ccn_amex_masked', 'dlp_ccn_diners_violation', 'dlp_ccn_diners_masked', 'dlp_ccn_visa_violation', 'dlp_ccn_visa_masked', 'dlp_ccn_mastercard_violation', 'dlp_ccn_mastercard_masked', 'dlp_ccn_discover_violation', 'dlp_ccn_discover_masked', 'dlp_ccn_jcb_violation', 'dlp_ccn_jcb_masked', 'dlp_ssn_success', 'dlp_ssn_violation', 'dlp_pcre_success', 'dlp_pcre_violation', 'dlp_pcre_masked', 'evasion_check_apache_whitespace_success', 'evasion_check_apache_whitespace_violation', 'evasion_check_decode_entities_success', 'evasion_check_decode_entities_violation', 'evasion_check_decode_escaped_chars_success', 'evasion_check_decode_escaped_chars_violation', 'evasion_check_decode_unicode_chars_success', 'evasion_check_decode_unicode_chars_violation', 'evasion_check_dir_traversal_success', 'evasion_check_dir_traversal_violation']}, 'counters2': {'type': 'str', 'choices': ['evasion_check_high_ascii_bytes_success', 'evasion_check_high_ascii_bytes_violation', 'evasion_check_invalid_hex_encoding_success', 'evasion_check_invalid_hex_encoding_violation', 'evasion_check_multiple_encoding_levels_success', 'evasion_check_multiple_encoding_levels_violation', 'evasion_check_multiple_slashes_success', 'evasion_check_multiple_slashes_violation', 'evasion_check_max_levels_success', 'evasion_check_max_levels_violation', 'evasion_check_remove_comments_success', 'evasion_check_remove_comments_violation', 'evasion_check_remove_spaces_success', 'evasion_check_remove_spaces_violation', 'http_limit_max_content_length_success', 'http_limit_max_content_length_violation', 'http_limit_max_cookie_header_length_success', 'http_limit_max_cookie_header_length_violation', 'http_limit_max_cookie_name_length_success', 'http_limit_max_cookie_name_length_violation', 'http_limit_max_cookie_value_length_success', 'http_limit_max_cookie_value_length_violation', 'http_limit_max_cookies_success', 'http_limit_max_cookies_violation', 'http_limit_max_cookies_length_success', 'http_limit_max_cookies_length_violation', 'http_limit_max_data_parse_success', 'http_limit_max_data_parse_violation', 'http_limit_max_entities_success', 'http_limit_max_entities_violation', 'http_limit_max_header_length_success', 'http_limit_max_header_length_violation', 'http_limit_max_header_name_length_success', 'http_limit_max_header_name_length_violation', 'http_limit_max_header_value_length_success', 'http_limit_max_header_value_length_violation', 'http_limit_max_headers_success', 'http_limit_max_headers_violation', 'http_limit_max_headers_length_success', 'http_limit_max_headers_length_violation', 'http_limit_max_param_name_length_success', 'http_limit_max_param_name_length_violation', 'http_limit_max_param_value_length_success', 'http_limit_max_param_value_length_violation', 'http_limit_max_params_success', 'http_limit_max_params_violation', 'http_limit_max_params_length_success', 'http_limit_max_params_length_violation', 'http_limit_max_post_length_success', 'http_limit_max_post_length_violation', 'http_limit_max_query_length_success', 'http_limit_max_query_length_violation', 'http_limit_max_request_length_success', 'http_limit_max_request_length_violation', 'http_limit_max_request_line_length_success', 'http_limit_max_request_line_length_violation', 'max_url_length_success', 'max_url_length_violation', 'http_protocol_allowed_headers_success', 'http_protocol_allowed_headers_violation', 'http_protocol_allowed_versions_success', 'http_protocol_allowed_versions_violation', 'http_protocol_allowed_method_check_success', 'http_protocol_allowed_method_check_violation', 'http_protocol_bad_multipart_request_success', 'http_protocol_bad_multipart_request_violation', 'http_protocol_get_with_content_success', 'http_protocol_get_with_content_violation', 'http_protocol_head_with_content_success', 'http_protocol_head_with_content_violation', 'http_protocol_host_header_with_ip_success', 'http_protocol_host_header_with_ip_violation', 'http_protocol_invalid_url_encoding_success', 'http_protocol_invalid_url_encoding_violation', 'http_protocol_malformed_content_length_success', 'http_protocol_malformed_content_length_violation', 'http_protocol_malformed_header_success', 'http_protocol_malformed_header_violation', 'http_protocol_malformed_parameter_success', 'http_protocol_malformed_parameter_violation', 'http_protocol_malformed_request_success', 'http_protocol_malformed_request_violation', 'http_protocol_malformed_request_line_success', 'http_protocol_malformed_request_line_violation', 'http_protocol_missing_header_value_success', 'http_protocol_missing_header_value_violation', 'http_protocol_missing_host_header_success', 'http_protocol_missing_host_header_violation', 'http_protocol_multiple_content_length_success', 'http_protocol_multiple_content_length_violation', 'http_protocol_post_with_0_content_success', 'http_protocol_post_with_0_content_violation', 'http_protocol_post_without_content_success', 'http_protocol_post_without_content_violation', 'http_protocol_success', 'http_protocol_violation', 'json_check_format_success']}, 'counters3': {'type': 'str', 'choices': ['json_check_format_violation', 'json_check_max_array_value_count_success', 'json_check_max_array_value_count_violation', 'json_check_max_depth_success', 'json_check_max_depth_violation', 'json_check_max_object_member_count_success', 'json_check_max_object_member_count_violation', 'json_check_max_string_success', 'json_check_max_string_violation', 'request_check_bot_success', 'request_check_bot_violation', 'request_check_redirect_wlist_success', 'request_check_redirect_wlist_violation', 'request_check_redirect_wlist_learn', 'request_check_referer_success', 'request_check_referer_violation', 'request_check_referer_redirect', 'request_check_session_check_none', 'request_check_session_check_success', 'request_check_session_check_violation', 'request_check_sqlia_url_success', 'request_check_sqlia_url_violation', 'request_check_sqlia_url_sanitize', 'request_check_sqlia_post_body_success', 'request_check_sqlia_post_body_violation', 'request_check_sqlia_post_body_sanitize', 'request_check_url_list_success', 'request_check_url_list_violation', 'request_check_url_list_learn', 'request_check_url_whitelist_success', 'request_check_url_whitelist_violation', 'request_check_url_blacklist_success', 'request_check_url_blacklist_violation', 'request_check_xss_cookie_success', 'request_check_xss_cookie_violation', 'request_check_xss_cookie_sanitize', 'request_check_xss_url_success', 'request_check_xss_url_violation', 'request_check_xss_url_sanitize', 'request_check_xss_post_body_success', 'request_check_xss_post_body_violation', 'request_check_xss_post_body_sanitize', 'response_cloaking_hide_status_code_success', 'response_cloaking_hide_status_code_violation', 'response_cloaking_filter_headers_success', 'response_cloaking_filter_headers_violation', 'soap_check_success', 'soap_check_violation', 'xml_check_format_success', 'xml_check_format_violation', 'xml_check_max_attr_success', 'xml_check_max_attr_violation', 'xml_check_max_attr_name_len_success', 'xml_check_max_attr_name_len_violation', 'xml_check_max_attr_value_len_success', 'xml_check_max_attr_value_len_violation', 'xml_check_max_cdata_len_success', 'xml_check_max_cdata_len_violation', 'xml_check_max_elem_success', 'xml_check_max_elem_violation', 'xml_check_max_elem_child_success', 'xml_check_max_elem_child_violation', 'xml_check_max_elem_depth_success', 'xml_check_max_elem_depth_violation', 'xml_check_max_elem_name_len_success', 'xml_check_max_elem_name_len_violation', 'xml_check_max_entity_exp_success', 'xml_check_max_entity_exp_violation', 'xml_check_max_entity_exp_depth_success', 'xml_check_max_entity_exp_depth_violation', 'xml_check_max_namespace_success', 'xml_check_max_namespace_violation', 'xml_check_namespace_uri_len_success', 'xml_check_namespace_uri_len_violation', 'xml_check_sqlia_success', 'xml_check_sqlia_violation', 'xml_check_xss_success', 'xml_check_xss_violation', 'xml_content_check_schema_success', 'xml_content_check_schema_violation', 'xml_content_check_wsdl_success', 'xml_content_check_wsdl_violation', 'learning_list_full', 'action_allow', 'action_deny_200', 'action_deny_403', 'action_deny_redirect', 'action_deny_reset', 'action_drop', 'action_deny_custom_response', 'action_learn', 'action_log', 'policy_limit_exceeded', 'sessions_alloc', 'sessions_freed', 'out_of_sessions', 'too_many_sessions', 'regex_violation', 'request_check_command_injection_cookies_success', 'request_check_command_injection_cookies_violation', 'request_check_command_injection_headers_success', 'request_check_command_injection_headers_violation', 'request_check_command_injection_uri_query_success', 'request_check_command_injection_uri_query_violation', 'request_check_command_injection_form_body_success', 'request_check_command_injection_form_body_violation', 'cookie_security_decrypt_in_grace_period_violation', 'form_response_non_post_success', 'form_response_non_post_violation', 'form_response_non_post_sanitize', 'xml_check_max_entity_decl_success', 'xml_check_max_entity_decl_violation', 'xml_check_max_entity_depth_success', 'xml_check_max_entity_depth_violation', 'action_response_allow', 'action_response_deny_200']}, 'counters4': {'type': 'str', 'choices': ['action_response_deny_403', 'action_response_deny_redirect', 'action_response_deny_reset', 'action_response_drop', 'action_response_deny_custom_response', 'action_response_learn', 'action_response_log', 'http_protocol_post_without_content_type_success', 'http_protocol_post_without_content_type_violation', 'http_protocol_body_without_content_type_success', 'http_protocol_body_without_content_type_violation', 'http_protocol_non_ssl_cookie_prefix_success', 'http_protocol_non_ssl_cookie_prefix_violation', 'cookie_security_add_samesite_success', 'cookie_security_add_samesite_violation', 'rule_set_request', 'rule_set_response', 'phase1_pass', 'phase1_allow', 'phase1_deny', 'phase1_drop', 'phase1_redirect', 'phase1_other', 'phase2_pass', 'phase2_allow', 'phase2_deny', 'phase2_drop', 'phase2_redirect', 'phase2_other', 'phase3_pass', 'phase3_allow', 'phase3_deny', 'phase3_drop', 'phase3_redirect', 'phase3_other', 'phase4_pass', 'phase4_allow', 'phase4_deny', 'phase4_drop', 'phase4_redirect', 'phase4_other']}},
        'stats': {'type': 'dict', 'total_req': {'type': 'str', }, 'req_allowed': {'type': 'str', }, 'req_denied': {'type': 'str', }, 'resp_denied': {'type': 'str', }, 'brute_force_success': {'type': 'str', }, 'brute_force_violation': {'type': 'str', }, 'brute_force_challenge_cookie_sent': {'type': 'str', }, 'brute_force_challenge_cookie_success': {'type': 'str', }, 'brute_force_challenge_cookie_violation': {'type': 'str', }, 'brute_force_challenge_javascript_sent': {'type': 'str', }, 'brute_force_challenge_javascript_success': {'type': 'str', }, 'brute_force_challenge_javascript_violation': {'type': 'str', }, 'brute_force_challenge_captcha_sent': {'type': 'str', }, 'brute_force_challenge_captcha_success': {'type': 'str', }, 'brute_force_challenge_captcha_violation': {'type': 'str', }, 'brute_force_lockout_limit_success': {'type': 'str', }, 'brute_force_lockout_limit_violation': {'type': 'str', }, 'brute_force_challenge_limit_success': {'type': 'str', }, 'brute_force_challenge_limit_violation': {'type': 'str', }, 'brute_force_response_codes_triggered': {'type': 'str', }, 'brute_force_response_headers_triggered': {'type': 'str', }, 'brute_force_response_string_triggered': {'type': 'str', }, 'cookie_security_encrypt_success': {'type': 'str', }, 'cookie_security_encrypt_violation': {'type': 'str', }, 'cookie_security_encrypt_limit_exceeded': {'type': 'str', }, 'cookie_security_encrypt_skip_rcache': {'type': 'str', }, 'cookie_security_decrypt_success': {'type': 'str', }, 'cookie_security_decrypt_violation': {'type': 'str', }, 'cookie_security_sign_success': {'type': 'str', }, 'cookie_security_sign_violation': {'type': 'str', }, 'cookie_security_sign_limit_exceeded': {'type': 'str', }, 'cookie_security_sign_skip_rcache': {'type': 'str', }, 'cookie_security_signature_check_success': {'type': 'str', }, 'cookie_security_signature_check_violation': {'type': 'str', }, 'cookie_security_add_http_only_success': {'type': 'str', }, 'cookie_security_add_http_only_violation': {'type': 'str', }, 'cookie_security_add_secure_success': {'type': 'str', }, 'cookie_security_add_secure_violation': {'type': 'str', }, 'cookie_security_missing_cookie_success': {'type': 'str', }, 'cookie_security_missing_cookie_violation': {'type': 'str', }, 'cookie_security_unrecognized_cookie_success': {'type': 'str', }, 'cookie_security_unrecognized_cookie_violation': {'type': 'str', }, 'cookie_security_cookie_policy_success': {'type': 'str', }, 'cookie_security_cookie_policy_violation': {'type': 'str', }, 'cookie_security_persistent_cookies': {'type': 'str', }, 'cookie_security_persistent_cookies_encrypted': {'type': 'str', }, 'cookie_security_persistent_cookies_signed': {'type': 'str', }, 'cookie_security_session_cookies': {'type': 'str', }, 'cookie_security_session_cookies_encrypted': {'type': 'str', }, 'cookie_security_session_cookies_signed': {'type': 'str', }, 'cookie_security_allowed_session_cookies': {'type': 'str', }, 'cookie_security_allowed_persistent_cookies': {'type': 'str', }, 'cookie_security_disallowed_session_cookies': {'type': 'str', }, 'cookie_security_disallowed_persistent_cookies': {'type': 'str', }, 'cookie_security_allowed_session_set_cookies': {'type': 'str', }, 'cookie_security_allowed_persistent_set_cookies': {'type': 'str', }, 'cookie_security_disallowed_session_set_cookies': {'type': 'str', }, 'cookie_security_disallowed_persistent_set_cookies': {'type': 'str', }, 'csp_header_violation': {'type': 'str', }, 'csp_header_success': {'type': 'str', }, 'csp_header_inserted': {'type': 'str', }, 'form_csrf_tag_success': {'type': 'str', }, 'form_csrf_tag_violation': {'type': 'str', }, 'form_consistency_success': {'type': 'str', }, 'form_consistency_violation': {'type': 'str', }, 'form_tag_inserted': {'type': 'str', }, 'form_non_ssl_success': {'type': 'str', }, 'form_non_ssl_violation': {'type': 'str', }, 'form_request_non_post_success': {'type': 'str', }, 'form_request_non_post_violation': {'type': 'str', }, 'form_check_success': {'type': 'str', }, 'form_check_violation': {'type': 'str', }, 'form_check_sanitize': {'type': 'str', }, 'form_non_masked_password_success': {'type': 'str', }, 'form_non_masked_password_violation': {'type': 'str', }, 'form_non_ssl_password_success': {'type': 'str', }, 'form_non_ssl_password_violation': {'type': 'str', }, 'form_password_autocomplete_success': {'type': 'str', }, 'form_password_autocomplete_violation': {'type': 'str', }, 'form_set_no_cache_success': {'type': 'str', }, 'form_set_no_cache': {'type': 'str', }, 'dlp_ccn_success': {'type': 'str', }, 'dlp_ccn_amex_violation': {'type': 'str', }, 'dlp_ccn_amex_masked': {'type': 'str', }, 'dlp_ccn_diners_violation': {'type': 'str', }, 'dlp_ccn_diners_masked': {'type': 'str', }, 'dlp_ccn_visa_violation': {'type': 'str', }, 'dlp_ccn_visa_masked': {'type': 'str', }, 'dlp_ccn_mastercard_violation': {'type': 'str', }, 'dlp_ccn_mastercard_masked': {'type': 'str', }, 'dlp_ccn_discover_violation': {'type': 'str', }, 'dlp_ccn_discover_masked': {'type': 'str', }, 'dlp_ccn_jcb_violation': {'type': 'str', }, 'dlp_ccn_jcb_masked': {'type': 'str', }, 'dlp_ssn_success': {'type': 'str', }, 'dlp_ssn_violation': {'type': 'str', }, 'dlp_pcre_success': {'type': 'str', }, 'dlp_pcre_violation': {'type': 'str', }, 'dlp_pcre_masked': {'type': 'str', }, 'evasion_check_apache_whitespace_success': {'type': 'str', }, 'evasion_check_apache_whitespace_violation': {'type': 'str', }, 'evasion_check_decode_entities_success': {'type': 'str', }, 'evasion_check_decode_entities_violation': {'type': 'str', }, 'evasion_check_decode_escaped_chars_success': {'type': 'str', }, 'evasion_check_decode_escaped_chars_violation': {'type': 'str', }, 'evasion_check_decode_unicode_chars_success': {'type': 'str', }, 'evasion_check_decode_unicode_chars_violation': {'type': 'str', }, 'evasion_check_dir_traversal_success': {'type': 'str', }, 'evasion_check_dir_traversal_violation': {'type': 'str', }, 'evasion_check_high_ascii_bytes_success': {'type': 'str', }, 'evasion_check_high_ascii_bytes_violation': {'type': 'str', }, 'evasion_check_invalid_hex_encoding_success': {'type': 'str', }, 'evasion_check_invalid_hex_encoding_violation': {'type': 'str', }, 'evasion_check_multiple_encoding_levels_success': {'type': 'str', }, 'evasion_check_multiple_encoding_levels_violation': {'type': 'str', }, 'evasion_check_multiple_slashes_success': {'type': 'str', }, 'evasion_check_multiple_slashes_violation': {'type': 'str', }, 'evasion_check_max_levels_success': {'type': 'str', }, 'evasion_check_max_levels_violation': {'type': 'str', }, 'evasion_check_remove_comments_success': {'type': 'str', }, 'evasion_check_remove_comments_violation': {'type': 'str', }, 'evasion_check_remove_spaces_success': {'type': 'str', }, 'evasion_check_remove_spaces_violation': {'type': 'str', }, 'http_limit_max_content_length_success': {'type': 'str', }, 'http_limit_max_content_length_violation': {'type': 'str', }, 'http_limit_max_cookie_header_length_success': {'type': 'str', }, 'http_limit_max_cookie_header_length_violation': {'type': 'str', }, 'http_limit_max_cookie_name_length_success': {'type': 'str', }, 'http_limit_max_cookie_name_length_violation': {'type': 'str', }, 'http_limit_max_cookie_value_length_success': {'type': 'str', }, 'http_limit_max_cookie_value_length_violation': {'type': 'str', }, 'http_limit_max_cookies_success': {'type': 'str', }, 'http_limit_max_cookies_violation': {'type': 'str', }, 'http_limit_max_cookies_length_success': {'type': 'str', }, 'http_limit_max_cookies_length_violation': {'type': 'str', }, 'http_limit_max_data_parse_success': {'type': 'str', }, 'http_limit_max_data_parse_violation': {'type': 'str', }, 'http_limit_max_entities_success': {'type': 'str', }, 'http_limit_max_entities_violation': {'type': 'str', }, 'http_limit_max_header_length_success': {'type': 'str', }, 'http_limit_max_header_length_violation': {'type': 'str', }, 'http_limit_max_header_name_length_success': {'type': 'str', }, 'http_limit_max_header_name_length_violation': {'type': 'str', }, 'http_limit_max_header_value_length_success': {'type': 'str', }, 'http_limit_max_header_value_length_violation': {'type': 'str', }, 'http_limit_max_headers_success': {'type': 'str', }, 'http_limit_max_headers_violation': {'type': 'str', }, 'http_limit_max_headers_length_success': {'type': 'str', }, 'http_limit_max_headers_length_violation': {'type': 'str', }, 'http_limit_max_param_name_length_success': {'type': 'str', }, 'http_limit_max_param_name_length_violation': {'type': 'str', }, 'http_limit_max_param_value_length_success': {'type': 'str', }, 'http_limit_max_param_value_length_violation': {'type': 'str', }, 'http_limit_max_params_success': {'type': 'str', }, 'http_limit_max_params_violation': {'type': 'str', }, 'http_limit_max_params_length_success': {'type': 'str', }, 'http_limit_max_params_length_violation': {'type': 'str', }, 'http_limit_max_post_length_success': {'type': 'str', }, 'http_limit_max_post_length_violation': {'type': 'str', }, 'http_limit_max_query_length_success': {'type': 'str', }, 'http_limit_max_query_length_violation': {'type': 'str', }, 'http_limit_max_request_length_success': {'type': 'str', }, 'http_limit_max_request_length_violation': {'type': 'str', }, 'http_limit_max_request_line_length_success': {'type': 'str', }, 'http_limit_max_request_line_length_violation': {'type': 'str', }, 'max_url_length_success': {'type': 'str', }, 'max_url_length_violation': {'type': 'str', }, 'http_protocol_allowed_headers_success': {'type': 'str', }, 'http_protocol_allowed_headers_violation': {'type': 'str', }, 'http_protocol_allowed_versions_success': {'type': 'str', }, 'http_protocol_allowed_versions_violation': {'type': 'str', }, 'http_protocol_allowed_method_check_success': {'type': 'str', }, 'http_protocol_allowed_method_check_violation': {'type': 'str', }, 'http_protocol_bad_multipart_request_success': {'type': 'str', }, 'http_protocol_bad_multipart_request_violation': {'type': 'str', }, 'http_protocol_get_with_content_success': {'type': 'str', }, 'http_protocol_get_with_content_violation': {'type': 'str', }, 'http_protocol_head_with_content_success': {'type': 'str', }, 'http_protocol_head_with_content_violation': {'type': 'str', }, 'http_protocol_host_header_with_ip_success': {'type': 'str', }, 'http_protocol_host_header_with_ip_violation': {'type': 'str', }, 'http_protocol_invalid_url_encoding_success': {'type': 'str', }, 'http_protocol_invalid_url_encoding_violation': {'type': 'str', }, 'http_protocol_malformed_content_length_success': {'type': 'str', }, 'http_protocol_malformed_content_length_violation': {'type': 'str', }, 'http_protocol_malformed_header_success': {'type': 'str', }, 'http_protocol_malformed_header_violation': {'type': 'str', }, 'http_protocol_malformed_parameter_success': {'type': 'str', }, 'http_protocol_malformed_parameter_violation': {'type': 'str', }, 'http_protocol_malformed_request_success': {'type': 'str', }, 'http_protocol_malformed_request_violation': {'type': 'str', }, 'http_protocol_malformed_request_line_success': {'type': 'str', }, 'http_protocol_malformed_request_line_violation': {'type': 'str', }, 'http_protocol_missing_header_value_success': {'type': 'str', }, 'http_protocol_missing_header_value_violation': {'type': 'str', }, 'http_protocol_missing_host_header_success': {'type': 'str', }, 'http_protocol_missing_host_header_violation': {'type': 'str', }, 'http_protocol_multiple_content_length_success': {'type': 'str', }, 'http_protocol_multiple_content_length_violation': {'type': 'str', }, 'http_protocol_post_with_0_content_success': {'type': 'str', }, 'http_protocol_post_with_0_content_violation': {'type': 'str', }, 'http_protocol_post_without_content_success': {'type': 'str', }, 'http_protocol_post_without_content_violation': {'type': 'str', }, 'http_protocol_success': {'type': 'str', }, 'http_protocol_violation': {'type': 'str', }, 'json_check_format_success': {'type': 'str', }, 'json_check_format_violation': {'type': 'str', }, 'json_check_max_array_value_count_success': {'type': 'str', }, 'json_check_max_array_value_count_violation': {'type': 'str', }, 'json_check_max_depth_success': {'type': 'str', }, 'json_check_max_depth_violation': {'type': 'str', }, 'json_check_max_object_member_count_success': {'type': 'str', }, 'json_check_max_object_member_count_violation': {'type': 'str', }, 'json_check_max_string_success': {'type': 'str', }, 'json_check_max_string_violation': {'type': 'str', }, 'request_check_bot_success': {'type': 'str', }, 'request_check_bot_violation': {'type': 'str', }, 'request_check_redirect_wlist_success': {'type': 'str', }, 'request_check_redirect_wlist_violation': {'type': 'str', }, 'request_check_redirect_wlist_learn': {'type': 'str', }, 'request_check_referer_success': {'type': 'str', }, 'request_check_referer_violation': {'type': 'str', }, 'request_check_referer_redirect': {'type': 'str', }, 'request_check_session_check_none': {'type': 'str', }, 'request_check_session_check_success': {'type': 'str', }, 'request_check_session_check_violation': {'type': 'str', }, 'request_check_sqlia_url_success': {'type': 'str', }, 'request_check_sqlia_url_violation': {'type': 'str', }, 'request_check_sqlia_url_sanitize': {'type': 'str', }, 'request_check_sqlia_post_body_success': {'type': 'str', }, 'request_check_sqlia_post_body_violation': {'type': 'str', }, 'request_check_sqlia_post_body_sanitize': {'type': 'str', }, 'request_check_url_list_success': {'type': 'str', }, 'request_check_url_list_violation': {'type': 'str', }, 'request_check_url_list_learn': {'type': 'str', }, 'request_check_url_whitelist_success': {'type': 'str', }, 'request_check_url_whitelist_violation': {'type': 'str', }, 'request_check_url_blacklist_success': {'type': 'str', }, 'request_check_url_blacklist_violation': {'type': 'str', }, 'request_check_xss_cookie_success': {'type': 'str', }, 'request_check_xss_cookie_violation': {'type': 'str', }, 'request_check_xss_cookie_sanitize': {'type': 'str', }, 'request_check_xss_url_success': {'type': 'str', }, 'request_check_xss_url_violation': {'type': 'str', }, 'request_check_xss_url_sanitize': {'type': 'str', }, 'request_check_xss_post_body_success': {'type': 'str', }, 'request_check_xss_post_body_violation': {'type': 'str', }, 'request_check_xss_post_body_sanitize': {'type': 'str', }, 'response_cloaking_hide_status_code_success': {'type': 'str', }, 'response_cloaking_hide_status_code_violation': {'type': 'str', }, 'response_cloaking_filter_headers_success': {'type': 'str', }, 'response_cloaking_filter_headers_violation': {'type': 'str', }, 'soap_check_success': {'type': 'str', }, 'soap_check_violation': {'type': 'str', }, 'xml_check_format_success': {'type': 'str', }, 'xml_check_format_violation': {'type': 'str', }, 'xml_check_max_attr_success': {'type': 'str', }, 'xml_check_max_attr_violation': {'type': 'str', }, 'xml_check_max_attr_name_len_success': {'type': 'str', }, 'xml_check_max_attr_name_len_violation': {'type': 'str', }, 'xml_check_max_attr_value_len_success': {'type': 'str', }, 'xml_check_max_attr_value_len_violation': {'type': 'str', }, 'xml_check_max_cdata_len_success': {'type': 'str', }, 'xml_check_max_cdata_len_violation': {'type': 'str', }, 'xml_check_max_elem_success': {'type': 'str', }, 'xml_check_max_elem_violation': {'type': 'str', }, 'xml_check_max_elem_child_success': {'type': 'str', }, 'xml_check_max_elem_child_violation': {'type': 'str', }, 'xml_check_max_elem_depth_success': {'type': 'str', }, 'xml_check_max_elem_depth_violation': {'type': 'str', }, 'xml_check_max_elem_name_len_success': {'type': 'str', }, 'xml_check_max_elem_name_len_violation': {'type': 'str', }, 'xml_check_max_entity_exp_success': {'type': 'str', }, 'xml_check_max_entity_exp_violation': {'type': 'str', }, 'xml_check_max_entity_exp_depth_success': {'type': 'str', }, 'xml_check_max_entity_exp_depth_violation': {'type': 'str', }, 'xml_check_max_namespace_success': {'type': 'str', }, 'xml_check_max_namespace_violation': {'type': 'str', }, 'xml_check_namespace_uri_len_success': {'type': 'str', }, 'xml_check_namespace_uri_len_violation': {'type': 'str', }, 'xml_check_sqlia_success': {'type': 'str', }, 'xml_check_sqlia_violation': {'type': 'str', }, 'xml_check_xss_success': {'type': 'str', }, 'xml_check_xss_violation': {'type': 'str', }, 'xml_content_check_schema_success': {'type': 'str', }, 'xml_content_check_schema_violation': {'type': 'str', }, 'xml_content_check_wsdl_success': {'type': 'str', }, 'xml_content_check_wsdl_violation': {'type': 'str', }, 'learning_list_full': {'type': 'str', }, 'action_allow': {'type': 'str', }, 'action_deny_200': {'type': 'str', }, 'action_deny_403': {'type': 'str', }, 'action_deny_redirect': {'type': 'str', }, 'action_deny_reset': {'type': 'str', }, 'action_drop': {'type': 'str', }, 'action_deny_custom_response': {'type': 'str', }, 'action_learn': {'type': 'str', }, 'action_log': {'type': 'str', }, 'policy_limit_exceeded': {'type': 'str', }, 'sessions_alloc': {'type': 'str', }, 'sessions_freed': {'type': 'str', }, 'out_of_sessions': {'type': 'str', }, 'too_many_sessions': {'type': 'str', }, 'regex_violation': {'type': 'str', }, 'request_check_command_injection_cookies_success': {'type': 'str', }, 'request_check_command_injection_cookies_violation': {'type': 'str', }, 'request_check_command_injection_headers_success': {'type': 'str', }, 'request_check_command_injection_headers_violation': {'type': 'str', }, 'request_check_command_injection_uri_query_success': {'type': 'str', }, 'request_check_command_injection_uri_query_violation': {'type': 'str', }, 'request_check_command_injection_form_body_success': {'type': 'str', }, 'request_check_command_injection_form_body_violation': {'type': 'str', }, 'cookie_security_decrypt_in_grace_period_violation': {'type': 'str', }, 'form_response_non_post_success': {'type': 'str', }, 'form_response_non_post_violation': {'type': 'str', }, 'form_response_non_post_sanitize': {'type': 'str', }, 'xml_check_max_entity_decl_success': {'type': 'str', }, 'xml_check_max_entity_decl_violation': {'type': 'str', }, 'xml_check_max_entity_depth_success': {'type': 'str', }, 'xml_check_max_entity_depth_violation': {'type': 'str', }, 'action_response_allow': {'type': 'str', }, 'action_response_deny_200': {'type': 'str', }, 'action_response_deny_403': {'type': 'str', }, 'action_response_deny_redirect': {'type': 'str', }, 'action_response_deny_reset': {'type': 'str', }, 'action_response_drop': {'type': 'str', }, 'action_response_deny_custom_response': {'type': 'str', }, 'action_response_learn': {'type': 'str', }, 'action_response_log': {'type': 'str', }, 'http_protocol_post_without_content_type_success': {'type': 'str', }, 'http_protocol_post_without_content_type_violation': {'type': 'str', }, 'http_protocol_body_without_content_type_success': {'type': 'str', }, 'http_protocol_body_without_content_type_violation': {'type': 'str', }, 'http_protocol_non_ssl_cookie_prefix_success': {'type': 'str', }, 'http_protocol_non_ssl_cookie_prefix_violation': {'type': 'str', }, 'cookie_security_add_samesite_success': {'type': 'str', }, 'cookie_security_add_samesite_violation': {'type': 'str', }}
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
                result["acos_info"] = info["global"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["global-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["global"]["stats"] if info != "NotFound" else info
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
