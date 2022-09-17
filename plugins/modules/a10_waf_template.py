#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_waf_template
description:
    - Manage WAF template configuration
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
    name:
        description:
        - "WAF Template Name"
        type: str
        required: True
    csp:
        description:
        - "Insert HTTP header Content-Security-Policy if necessary"
        type: bool
        required: False
    csp_value:
        description:
        - "CSP header value, e.g., 'script-src 'none''"
        type: str
        required: False
    csp_insert_type:
        description:
        - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-
          always'= Always insert the header even when there is a header with the same
          name;"
        type: str
        required: False
    http_redirect:
        description:
        - "Send HTTP redirect response (302 Found) to specifed URL (URL to redirect to
          when denying request)"
        type: str
        required: False
    http_resp_200:
        description:
        - "Send HTTP response with status code 200 OK"
        type: bool
        required: False
    resp_url_200:
        description:
        - "Response content to send client when denying request"
        type: str
        required: False
    reset_conn:
        description:
        - "Reset the client connection"
        type: bool
        required: False
    http_resp_403:
        description:
        - "Send HTTP response with status code 403 Forbidden (default)"
        type: bool
        required: False
    resp_url_403:
        description:
        - "Response content to send client when denying request"
        type: str
        required: False
    deploy_mode:
        description:
        - "'active'= Deploy WAF in active (blocking) mode; 'passive'= Deploy WAF in
          passive (log-only) mode; 'learning'= Deploy WAF in learning mode;"
        type: str
        required: False
    log_succ_reqs:
        description:
        - "Log successful waf requests"
        type: bool
        required: False
    learn_pr:
        description:
        - "Enable per-request logs for WAF learning"
        type: bool
        required: False
    parent:
        description:
        - "inherit from parent template"
        type: bool
        required: False
    parent_template_waf:
        description:
        - "WAF template (WAF Config name)"
        type: str
        required: False
    pcre_match_limit:
        description:
        - "Maximum number of matches allowed (default 30000)"
        type: int
        required: False
    pcre_match_recursion_limit:
        description:
        - "Maximum levels of recursive allowed (default 5000)"
        type: int
        required: False
    soap_format_check:
        description:
        - "Check XML document for SOAP format compliance"
        type: bool
        required: False
    logging:
        description:
        - "Logging template (Logging Config name)"
        type: str
        required: False
    wsdl_file:
        description:
        - "Specify name of WSDL file for verifying XML body contents"
        type: str
        required: False
    wsdl_resp_val_file:
        description:
        - "Specify name of WSDL file for verifying XML body contents"
        type: str
        required: False
    xml_schema_file:
        description:
        - "Specify name of XML-Schema file for verifying XML body contents"
        type: str
        required: False
    xml_schema_resp_val_file:
        description:
        - "Specify name of XML-Schema file for verifying XML body contents"
        type: str
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    user_tag:
        description:
        - "Customized tag"
        type: str
        required: False
    brute_force_protection:
        description:
        - "Field brute_force_protection"
        type: dict
        required: False
        suboptions:
            challenge_action_cookie:
                description:
                - "Use Set-Cookie to determine if client allows cookies"
                type: bool
            challenge_action_javascript:
                description:
                - "Add JavaScript to response to test if client allows JavaScript"
                type: bool
            challenge_action_captcha:
                description:
                - "Initiate a Captcha to verify client can respond"
                type: bool
            brute_force_challenge_limit:
                description:
                - "Maximum brute-force events before sending challenge (default 2) (Maximum brute-
          force events before locking out client (default 2))"
                type: int
            enable_disable_action:
                description:
                - "'enable'= Enable brute force protections; 'disable'= Disable brute force
          protections (default);"
                type: str
            brute_force_global:
                description:
                - "Brute-force triggers apply globally instead of per-client (Apply brute-force
          triggers globally)"
                type: bool
            brute_force_lockout_limit:
                description:
                - "Maximum brute-force events before locking out client (default 5)"
                type: int
            brute_force_lockout_period:
                description:
                - "Number of seconds client should be locked out (default 600)"
                type: int
            brute_force_resp_codes:
                description:
                - "Trigger brute-force check on HTTP response code"
                type: bool
            brute_force_resp_codes_file:
                description:
                - "Name of WAF policy list file"
                type: str
            brute_force_resp_headers:
                description:
                - "Trigger brute-force check on HTTP response header names"
                type: bool
            brute_force_resp_headers_file:
                description:
                - "Name of WAF policy list file"
                type: str
            brute_force_resp_string:
                description:
                - "Trigger brute-force check on HTTP response reason phrase"
                type: bool
            brute_force_resp_string_file:
                description:
                - "Name of WAF policy list file"
                type: str
            brute_force_test_period:
                description:
                - "Number of seconds for brute-force event counting (default 60)"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    http_limit_check:
        description:
        - "Field http_limit_check"
        type: dict
        required: False
        suboptions:
            disable:
                description:
                - "Disable all checks for HTTP limit"
                type: bool
            max_content_length:
                description:
                - "Max length of content (Maximum length of content allowed)"
                type: bool
            max_content_length_value:
                description:
                - "Max length of content (default 4096) (Maximum length of content allowed
          (default 4096))"
                type: int
            max_cookie_header_length:
                description:
                - "Max Cookie header length allowed in request (Maximum length of cookie header
          allowed)"
                type: bool
            max_cookie_header_length_value:
                description:
                - "Max Cookie header length allowed in request (default 4096) (Maximum length of
          cookie header allowed (default 4096))"
                type: int
            max_cookie_name_length:
                description:
                - "Max Cookie name length allowed in request (Maximum length of cookie name
          allowed)"
                type: bool
            max_cookie_name_length_value:
                description:
                - "Max Cookie name length allowed in request (default 64) (Maximum length of
          cookie name allowed (default 64))"
                type: int
            max_cookie_value_length:
                description:
                - "Max Cookie value length allowed in request (Maximum length of cookie value
          allowed)"
                type: bool
            max_cookie_value_length_value:
                description:
                - "Max Cookie value length allowed in request (default 4096) (Maximum length of
          cookie value allowed (default 4096))"
                type: int
            max_cookies:
                description:
                - "Max Cookies allowed in request (Maximum number of cookie allowed)"
                type: bool
            max_cookies_value:
                description:
                - "Max Cookies allowed in request (default 20) (Maximum number of cookie allowed
          (default 20))"
                type: int
            max_cookies_length:
                description:
                - "Total Cookies length allowed in request (Maximum length of all cookies in
          request)"
                type: bool
            max_cookies_length_value:
                description:
                - "Total Cookies length allowed in request (default 4096) (Maximum length of all
          cookies in request (default 4096))"
                type: int
            max_data_parse:
                description:
                - "Max data to be parsed for Web Application Firewall"
                type: bool
            max_data_parse_value:
                description:
                - "Max data to be parsed for Web Application Firewall (default 262144)"
                type: int
            max_entities:
                description:
                - "Maximum number of MIME entities allowed in request"
                type: bool
            max_entities_value:
                description:
                - "Maximum number of MIME entities allowed in request (default 10)"
                type: int
            max_header_length:
                description:
                - "Max header length allowed in request (Maximum length of header allowed)"
                type: bool
            max_header_length_value:
                description:
                - "Max header length allowed in request (default 4096) (Maximum length of header
          allowed (default 4096))"
                type: int
            max_header_name_length:
                description:
                - "Max header name length allowed in request (Maximum length of header name
          allowed)"
                type: bool
            max_header_name_length_value:
                description:
                - "Max header name length allowed in request (default 64) (Maximum length of
          header name allowed (default 64))"
                type: int
            max_header_value_length:
                description:
                - "Max header value length allowed in request (Maximum length of header value
          allowed)"
                type: bool
            max_header_value_length_value:
                description:
                - "Max header value length allowed in request (default 4096) (Maximum length of
          header value allowed (default 4096))"
                type: int
            max_headers:
                description:
                - "Total number of headers allowed in request (Maximum number of headers in
          request)"
                type: bool
            max_headers_value:
                description:
                - "Total number of headers allowed in request (default 64) (Maximum number of
          headers in request (default 64))"
                type: int
            max_headers_length:
                description:
                - "Total headers length allowed in request (Maximum length of all headers in
          request)"
                type: bool
            max_headers_length_value:
                description:
                - "Total headers length allowed in request (default 4096) (Maximum length of all
          headers in request (default 4096))"
                type: int
            max_param_name_length:
                description:
                - "Max query/POST parameter name length allowed in request (Maximum length of
          query/POST parameter names allowed)"
                type: bool
            max_param_name_length_value:
                description:
                - "Max query/POST parameter name length allowed in request (default 256) (Maximum
          length of query/POST parameter names allowed (default 256))"
                type: int
            max_param_value_length:
                description:
                - "Max query/POST parameter value length allowed in request (Maximum length of
          query/POST parameter value allowed)"
                type: bool
            max_param_value_length_value:
                description:
                - "Max query/POST parameter value length allowed in request (default 4096)
          (Maximum length of query/POST parameter value allowed (default 4096))"
                type: int
            max_params:
                description:
                - "Total query/POST parameters allowed in request (Maximum number of query/POST
          parameters in request)"
                type: bool
            max_params_value:
                description:
                - "Total query/POST parameters allowed in request (default 64) (Maximum number of
          query/POST parameters in request (default 64))"
                type: int
            max_params_length:
                description:
                - "Total query/POST parameters length allowed in request (Maximum length of all
          params in request)"
                type: bool
            max_params_length_value:
                description:
                - "Total query/POST parameters length allowed in request (default 4096) (Maximum
          length of all params in request (default 4096))"
                type: int
            max_post_length:
                description:
                - "Maximum content length allowed in POST request"
                type: bool
            max_post_length_value:
                description:
                - "Maximum content length allowed in POST request (default 20480)"
                type: int
            max_query_length:
                description:
                - "Max length of query string (Maximum length of query string allowed)"
                type: bool
            max_query_length_value:
                description:
                - "Max length of query string (default 4096) (Maximum length of query string
          allowed (default 4096))"
                type: int
            max_request_length:
                description:
                - "Max length of request (Maximum length of request allowed)"
                type: bool
            max_request_length_value:
                description:
                - "Max length of request (default 20480) (Maximum length of request allowed
          (default 20480))"
                type: int
            max_request_line_length:
                description:
                - "Max length of request line (Maximum length of request line)"
                type: bool
            max_request_line_length_value:
                description:
                - "Max length of request line (default 4096) (Maximum length of request line
          (default 4096))"
                type: int
            max_url_length:
                description:
                - "Max length of url (Maximum length of url allowed)"
                type: bool
            max_url_length_value:
                description:
                - "Max length of url (default 4096) (Maximum length of url allowed (default 4096))"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    http_protocol_check:
        description:
        - "Field http_protocol_check"
        type: dict
        required: False
        suboptions:
            disable:
                description:
                - "Disable all checks for HTTP protocol compliance"
                type: bool
            allowed_headers:
                description:
                - "Enable allowed-headers check (default disabled)"
                type: bool
            allowed_headers_list:
                description:
                - "Allowed HTTP headers. Default 'Host Referer User-Agent Accept Accept-Encoding
          ...' (see docs for full list) (Allowed HTTP headers (default 'Host Referer
          User-Agent Accept Accept-Encoding ...' (see docs for full list)))"
                type: str
            allowed_methods:
                description:
                - "Enable allowed-methods check (default disabled)"
                type: bool
            allowed_methods_list:
                description:
                - "List of allowed HTTP methods. Default is 'GET POST'. (List of HTTP methods
          allowed (default 'GET POST'))"
                type: str
            allowed_versions:
                description:
                - "Enable allowed-versions check (default disabled)"
                type: bool
            allowed_versions_list:
                description:
                - "List of allowed HTTP versions (default '1.0 1.1 2')"
                type: str
            bad_multipart_request:
                description:
                - "Check for bad multipart/form-data request body"
                type: bool
            body_without_content_type:
                description:
                - "Check for Body request without Content-Type header in request"
                type: bool
            get_with_content:
                description:
                - "Check for GET request with Content-Length headers in request"
                type: bool
            head_with_content:
                description:
                - "Check for HEAD request with Content-Length headers in request"
                type: bool
            host_header_with_ip:
                description:
                - "Check for Host header with IP address"
                type: bool
            invalid_url_encoding:
                description:
                - "Check for invalid URL encoding in request"
                type: bool
            malformed_content_length:
                description:
                - "Check for malformed content-length in request"
                type: bool
            malformed_header:
                description:
                - "Check for malformed HTTP header"
                type: bool
            malformed_parameter:
                description:
                - "Check for malformed HTTP query/POST parameter"
                type: bool
            malformed_request:
                description:
                - "Check for malformed HTTP request"
                type: bool
            malformed_request_line:
                description:
                - "Check for malformed HTTP request line"
                type: bool
            missing_header_value:
                description:
                - "Check for missing header value in request"
                type: bool
            missing_host_header:
                description:
                - "Check for missing Host header in HTTP/1.1 request"
                type: bool
            multiple_content_length:
                description:
                - "Check for multiple Content-Length headers in request"
                type: bool
            post_with_0_content:
                description:
                - "Check for POST request with Content-Length 0"
                type: bool
            post_without_content:
                description:
                - "Check for POST request without Content-Length/Chunked Encoding headers in
          request"
                type: bool
            post_without_content_type:
                description:
                - "Check for POST request without Content-Type header in request"
                type: bool
            non_ssl_cookie_prefix:
                description:
                - "Check for Bad __Secure- or __Host- Cookie Name prefixes in non-ssl request"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    cookie_security:
        description:
        - "Field cookie_security"
        type: dict
        required: False
        suboptions:
            enable_disable_action:
                description:
                - "'enable'= Enable cookie security (default); 'disable'= Disable cookie security;"
                type: str
            allow_missing_cookie:
                description:
                - "Allow requests with missing cookies"
                type: bool
            allow_unrecognized_cookie:
                description:
                - "Allow requests with unrecognized cookies"
                type: bool
            cookie_policy:
                description:
                - "Field cookie_policy"
                type: list
            set_cookie_policy:
                description:
                - "Field set_cookie_policy"
                type: list
            tamper_protection_http_only:
                description:
                - "Add HttpOnly flag to cookies not in set-cookie-policy list (default on)"
                type: bool
            tamper_protection_secure:
                description:
                - "Add Secure flag to cookies not in set-cookie-policy list (default on)"
                type: bool
            tamper_protection_samesite:
                description:
                - "'none'= none; 'lax'= lax; 'strict'= strict;"
                type: str
            tamper_protection_secret:
                description:
                - "Cookie encryption secret"
                type: str
            tamper_protection_secret_encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED secret string)"
                type: str
            tamper_protection_grace_period:
                description:
                - "Allow unrecognized cookies for a period of time after cookie encryption being
          applied (default 120 minutes)"
                type: int
            tamper_protection_session_cookie_only:
                description:
                - "Only encrypt session cookies"
                type: bool
            tamper_protection_sign:
                description:
                - "Sign cookies"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    evasion_check:
        description:
        - "Field evasion_check"
        type: dict
        required: False
        suboptions:
            apache_whitespace:
                description:
                - "Check for whitespace characters in URL"
                type: bool
            decode_entities:
                description:
                - "Decode entities in internal url (default on)"
                type: bool
            decode_escaped_chars:
                description:
                - "Decode escaped characters such as \\r \\n \\' \\xXX \\u00YY in internal url
          (default on)"
                type: bool
            decode_plus_chars:
                description:
                - "Decode '+' as space in URL (default on)"
                type: bool
            decode_unicode_chars:
                description:
                - "Check for evasion attempt using %u encoding of Unicode chars to bypass (default
          on)"
                type: bool
            dir_traversal:
                description:
                - "Check for directory traversal attempt (default on)"
                type: bool
            high_ascii_bytes:
                description:
                - "Check for evasion attempt using ASCII bytes with values"
                type: bool
            invalid_hex_encoding:
                description:
                - "Check for evasion attempt using invalid hex characters (not in 0-9,a-f)"
                type: bool
            multiple_encoding_levels:
                description:
                - "Check for evasion attempt using multiple levels of encoding"
                type: bool
            multiple_slashes:
                description:
                - "Check for evasion attempt using multiple slashes/backslashes"
                type: bool
            max_levels:
                description:
                - "Max levels of encoding allowed in request (default 2)"
                type: int
            remove_comments:
                description:
                - "Remove comments from internal url"
                type: bool
            remove_spaces:
                description:
                - "Remove spaces from internal url (default on)"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    data_leak_prevention:
        description:
        - "Field data_leak_prevention"
        type: dict
        required: False
        suboptions:
            ccn_mask:
                description:
                - "Mask credit card numbers in response"
                type: bool
            ssn_mask:
                description:
                - "Mask US Social Security numbers in response"
                type: bool
            pcre_mask:
                description:
                - "Mask matched PCRE pattern in response"
                type: str
            keep_start:
                description:
                - "Number of unmasked characters at the beginning (default= 0)"
                type: int
            keep_end:
                description:
                - "Number of unmasked characters at the end (default= 0)"
                type: int
            mask:
                description:
                - "Character to mask the matched pattern (default= X)"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    form_protection:
        description:
        - "Field form_protection"
        type: dict
        required: False
        suboptions:
            enable_disable_action:
                description:
                - "'enable'= Enable web form protections (default); 'disable'= Disable web form
          protections;"
                type: str
            csrf_check:
                description:
                - "Tag the form to protect against Cross-site Request Forgery"
                type: bool
            field_consistency_check:
                description:
                - "Form input consistency check"
                type: bool
            password_check_non_masked:
                description:
                - "Check forms that have a password field with a textual type, resulting in this
          field not being masked"
                type: bool
            password_check_non_ssl:
                description:
                - "Check forms that has a password field if the form is not sent over an SSL
          connection"
                type: bool
            password_check_autocomplete:
                description:
                - "Check to protect against server-generated form which contain password fields
          that allow autocomplete"
                type: bool
            form_check_non_ssl:
                description:
                - "Check whether SSL is used for request with forms"
                type: bool
            form_check_caching:
                description:
                - "Disable caching for response with forms"
                type: bool
            form_check_non_post:
                description:
                - "Check whether POST is used for request with forms"
                type: bool
            form_check_request_non_post:
                description:
                - "Check whether POST is used for request with forms"
                type: bool
            form_check_response_non_post:
                description:
                - "Check whether form method POST is used for response with forms"
                type: bool
            form_check_response_non_post_sanitize:
                description:
                - "Change form method GET to POST (Use with caution= make sure server application
          still work)"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    response_cloaking:
        description:
        - "Field response_cloaking"
        type: dict
        required: False
        suboptions:
            filter_headers:
                description:
                - "Removes web server's identifying headers"
                type: bool
            hide_status_codes:
                description:
                - "Hides response status codes that are not allowed (default 4xx, 5xx)"
                type: bool
            hide_status_codes_file:
                description:
                - "Name of WAF policy list file"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    request_check:
        description:
        - "Field request_check"
        type: dict
        required: False
        suboptions:
            bot_check:
                description:
                - "Check User-Agent for known bots"
                type: bool
            bot_check_policy_file:
                description:
                - "Name of WAF policy list file"
                type: str
            command_injection_check:
                description:
                - "Check to protect against command injection attacks"
                type: str
            command_injection_check_policy_file:
                description:
                - "Name of WAF policy command injection list file"
                type: str
            redirect_whitelist:
                description:
                - "Check Redirect URL against list of previously learned redirects"
                type: bool
            referer_check:
                description:
                - "Check referer to protect against CSRF attacks"
                type: bool
            referer_domain_list:
                description:
                - "List of referer domains allowed"
                type: str
            referer_safe_url:
                description:
                - " Safe URL to redirect to if referer is missing"
                type: str
            referer_domain_list_only:
                description:
                - "List of referer domains allowed"
                type: str
            session_check:
                description:
                - "Enable session checking via session cookie"
                type: bool
            lifetime:
                description:
                - "Session lifetime in minutes (default 10)"
                type: int
            sqlia_check:
                description:
                - "'reject'= Reject requests with SQLIA patterns;"
                type: str
            sqlia_check_policy_file:
                description:
                - "Name of WAF policy list file"
                type: str
            url_blacklist:
                description:
                - "specify name of WAF policy list file to blacklist"
                type: bool
            waf_blacklist_file:
                description:
                - "Name of WAF policy list file"
                type: str
            url_whitelist:
                description:
                - "specify name of WAF policy list file to whitelist"
                type: bool
            waf_whitelist_file:
                description:
                - "Name of WAF policy list file"
                type: str
            url_learned_list:
                description:
                - "Check URL against list of previously learned URLs"
                type: bool
            xss_check:
                description:
                - "'reject'= Reject requests with bad cookies;"
                type: str
            xss_check_policy_file:
                description:
                - "Name of WAF policy list file"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    violation_log_mask:
        description:
        - "Field violation_log_mask"
        type: dict
        required: False
        suboptions:
            query_param_name_equal_type:
                description:
                - "'equals'= Mask the query value if the query name equals to the string;"
                type: str
            query_param_name_value:
                description:
                - "The list of Query parameter names"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    json_check:
        description:
        - "Field json_check"
        type: dict
        required: False
        suboptions:
            format_check:
                description:
                - "Check HTTP body for JSON format compliance"
                type: bool
            max_array_values:
                description:
                - "Maximum number of values in an array in a JSON request body (default 256)
          (Maximum number of values in a JSON array (default 256))"
                type: int
            max_depth:
                description:
                - "Maximum recursion depth in a value in a JSON requesnt body (default 16)
          (Maximum recursion depth in a JSON value (default 16))"
                type: int
            max_object_members:
                description:
                - "Maximum number of members in an object in a JSON request body (default 256)
          (Maximum number of members in a JSON object (default 256))"
                type: int
            max_string_length:
                description:
                - "Maximum length of a string in a JSON request body (default 64) (Maximum length
          of a JSON string (default 64))"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    xml_check:
        description:
        - "Field xml_check"
        type: dict
        required: False
        suboptions:
            disable:
                description:
                - "Disable all checks for XML limit"
                type: bool
            max_attr:
                description:
                - "Maximum number of attributes of an XML element (default 256)"
                type: int
            max_attr_name_len:
                description:
                - "Maximum length of an attribute name (default 128)"
                type: int
            max_attr_value_len:
                description:
                - "Maximum length of an attribute text value (default 128)"
                type: int
            max_cdata_len:
                description:
                - "Maximum length of an CDATA section of an element (default 65535)"
                type: int
            max_elem:
                description:
                - "Maximum number of XML elements (default 1024)"
                type: int
            max_elem_child:
                description:
                - "Maximum number of children of an XML element (default 1024)"
                type: int
            max_elem_depth:
                description:
                - "Maximum recursion level for element definition (default 256)"
                type: int
            max_elem_name_len:
                description:
                - "Maximum length for an element name (default 128)"
                type: int
            max_entity_decl:
                description:
                - "Maximum number of entity declarations (default 1024)"
                type: int
            max_entity_depth:
                description:
                - "Maximum depth of entities (default 32)"
                type: int
            max_entity_exp:
                description:
                - "Maximum number of entity expansions (default 1024)"
                type: int
            max_entity_exp_depth:
                description:
                - "Maximum nested depth of entity expansions (default 32)"
                type: int
            max_namespace:
                description:
                - "Maximum number of namespace declarations (default 16)"
                type: int
            max_namespace_uri_len:
                description:
                - "Maximum length of a namespace URI (default 256)"
                type: int
            format:
                description:
                - "Check HTTP body for XML format compliance"
                type: bool
            sqlia:
                description:
                - "Check XML data against SQLIA policy"
                type: bool
            xss:
                description:
                - "Check XML data against XSS policy"
                type: bool
            uuid:
                description:
                - "uuid of the object"
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
                - "Cookie Security - signing skipped - RAM Cache"
                type: str
            cookie_security_signature_check_success:
                description:
                - "Cookie Security - signature check successful"
                type: str
            cookie_security_signature_check_violation:
                description:
                - "Cookie Security - signature check violation"
                type: str
            cookie_security_add_http_only_success:
                description:
                - "Cookie Security - http-only flag added"
                type: str
            cookie_security_add_http_only_violation:
                description:
                - "Cookie Security - http-only flag violation"
                type: str
            cookie_security_add_secure_success:
                description:
                - "Cookie Security - secure flag added"
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
                - "Cookie Security - disallowed session Set-Cookies"
                type: str
            cookie_security_allowed_persistent_set_cookies:
                description:
                - "Cookie Security - disallowed persistent Set-Cookies"
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
                - "CSP header missing"
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
                - "XML Limit Entity Decl check passed"
                type: str
            xml_check_max_entity_exp_violation:
                description:
                - "XML Limit Entity Decl violation"
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
            response_action_allow:
                description:
                - "Response Action allowed"
                type: str
            response_action_deny_200:
                description:
                - "Response Deny with 200"
                type: str
            response_action_deny_403:
                description:
                - "Response Deny with 403"
                type: str
            response_action_deny_redirect:
                description:
                - "Response Deny with Redirect"
                type: str
            response_action_deny_reset:
                description:
                - "Response Deny with Resets"
                type: str
            response_action_drop:
                description:
                - "Number of Dropped Responses"
                type: str
            response_action_deny_custom_response:
                description:
                - "Response Deny with custom response"
                type: str
            response_action_learn:
                description:
                - "Response Learning Updates"
                type: str
            response_action_log:
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
            name:
                description:
                - "WAF Template Name"
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
AVAILABLE_PROPERTIES = ["brute_force_protection", "cookie_security", "csp", "csp_insert_type", "csp_value", "data_leak_prevention", "deploy_mode", "evasion_check", "form_protection", "http_limit_check", "http_protocol_check", "http_redirect", "http_resp_200", "http_resp_403", "json_check", "learn_pr", "log_succ_reqs", "logging", "name", "parent", "parent_template_waf", "pcre_match_limit", "pcre_match_recursion_limit", "request_check", "reset_conn", "resp_url_200", "resp_url_403", "response_cloaking", "soap_format_check", "stats", "user_tag", "uuid", "violation_log_mask", "wsdl_file", "wsdl_resp_val_file", "xml_check", "xml_schema_file", "xml_schema_resp_val_file", ]


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
    rv.update({'name': {'type': 'str', 'required': True, },
        'csp': {'type': 'bool', },
        'csp_value': {'type': 'str', },
        'csp_insert_type': {'type': 'str', 'choices': ['insert-if-not-exist', 'insert-always']},
        'http_redirect': {'type': 'str', },
        'http_resp_200': {'type': 'bool', },
        'resp_url_200': {'type': 'str', },
        'reset_conn': {'type': 'bool', },
        'http_resp_403': {'type': 'bool', },
        'resp_url_403': {'type': 'str', },
        'deploy_mode': {'type': 'str', 'choices': ['active', 'passive', 'learning']},
        'log_succ_reqs': {'type': 'bool', },
        'learn_pr': {'type': 'bool', },
        'parent': {'type': 'bool', },
        'parent_template_waf': {'type': 'str', },
        'pcre_match_limit': {'type': 'int', },
        'pcre_match_recursion_limit': {'type': 'int', },
        'soap_format_check': {'type': 'bool', },
        'logging': {'type': 'str', },
        'wsdl_file': {'type': 'str', },
        'wsdl_resp_val_file': {'type': 'str', },
        'xml_schema_file': {'type': 'str', },
        'xml_schema_resp_val_file': {'type': 'str', },
        'uuid': {'type': 'str', },
        'user_tag': {'type': 'str', },
        'brute_force_protection': {'type': 'dict', 'challenge_action_cookie': {'type': 'bool', }, 'challenge_action_javascript': {'type': 'bool', }, 'challenge_action_captcha': {'type': 'bool', }, 'brute_force_challenge_limit': {'type': 'int', }, 'enable_disable_action': {'type': 'str', 'choices': ['enable', 'disable']}, 'brute_force_global': {'type': 'bool', }, 'brute_force_lockout_limit': {'type': 'int', }, 'brute_force_lockout_period': {'type': 'int', }, 'brute_force_resp_codes': {'type': 'bool', }, 'brute_force_resp_codes_file': {'type': 'str', }, 'brute_force_resp_headers': {'type': 'bool', }, 'brute_force_resp_headers_file': {'type': 'str', }, 'brute_force_resp_string': {'type': 'bool', }, 'brute_force_resp_string_file': {'type': 'str', }, 'brute_force_test_period': {'type': 'int', }, 'uuid': {'type': 'str', }},
        'http_limit_check': {'type': 'dict', 'disable': {'type': 'bool', }, 'max_content_length': {'type': 'bool', }, 'max_content_length_value': {'type': 'int', }, 'max_cookie_header_length': {'type': 'bool', }, 'max_cookie_header_length_value': {'type': 'int', }, 'max_cookie_name_length': {'type': 'bool', }, 'max_cookie_name_length_value': {'type': 'int', }, 'max_cookie_value_length': {'type': 'bool', }, 'max_cookie_value_length_value': {'type': 'int', }, 'max_cookies': {'type': 'bool', }, 'max_cookies_value': {'type': 'int', }, 'max_cookies_length': {'type': 'bool', }, 'max_cookies_length_value': {'type': 'int', }, 'max_data_parse': {'type': 'bool', }, 'max_data_parse_value': {'type': 'int', }, 'max_entities': {'type': 'bool', }, 'max_entities_value': {'type': 'int', }, 'max_header_length': {'type': 'bool', }, 'max_header_length_value': {'type': 'int', }, 'max_header_name_length': {'type': 'bool', }, 'max_header_name_length_value': {'type': 'int', }, 'max_header_value_length': {'type': 'bool', }, 'max_header_value_length_value': {'type': 'int', }, 'max_headers': {'type': 'bool', }, 'max_headers_value': {'type': 'int', }, 'max_headers_length': {'type': 'bool', }, 'max_headers_length_value': {'type': 'int', }, 'max_param_name_length': {'type': 'bool', }, 'max_param_name_length_value': {'type': 'int', }, 'max_param_value_length': {'type': 'bool', }, 'max_param_value_length_value': {'type': 'int', }, 'max_params': {'type': 'bool', }, 'max_params_value': {'type': 'int', }, 'max_params_length': {'type': 'bool', }, 'max_params_length_value': {'type': 'int', }, 'max_post_length': {'type': 'bool', }, 'max_post_length_value': {'type': 'int', }, 'max_query_length': {'type': 'bool', }, 'max_query_length_value': {'type': 'int', }, 'max_request_length': {'type': 'bool', }, 'max_request_length_value': {'type': 'int', }, 'max_request_line_length': {'type': 'bool', }, 'max_request_line_length_value': {'type': 'int', }, 'max_url_length': {'type': 'bool', }, 'max_url_length_value': {'type': 'int', }, 'uuid': {'type': 'str', }},
        'http_protocol_check': {'type': 'dict', 'disable': {'type': 'bool', }, 'allowed_headers': {'type': 'bool', }, 'allowed_headers_list': {'type': 'str', }, 'allowed_methods': {'type': 'bool', }, 'allowed_methods_list': {'type': 'str', }, 'allowed_versions': {'type': 'bool', }, 'allowed_versions_list': {'type': 'str', 'choices': ['0.9', '1.0', '1.1', '2']}, 'bad_multipart_request': {'type': 'bool', }, 'body_without_content_type': {'type': 'bool', }, 'get_with_content': {'type': 'bool', }, 'head_with_content': {'type': 'bool', }, 'host_header_with_ip': {'type': 'bool', }, 'invalid_url_encoding': {'type': 'bool', }, 'malformed_content_length': {'type': 'bool', }, 'malformed_header': {'type': 'bool', }, 'malformed_parameter': {'type': 'bool', }, 'malformed_request': {'type': 'bool', }, 'malformed_request_line': {'type': 'bool', }, 'missing_header_value': {'type': 'bool', }, 'missing_host_header': {'type': 'bool', }, 'multiple_content_length': {'type': 'bool', }, 'post_with_0_content': {'type': 'bool', }, 'post_without_content': {'type': 'bool', }, 'post_without_content_type': {'type': 'bool', }, 'non_ssl_cookie_prefix': {'type': 'bool', }, 'uuid': {'type': 'str', }},
        'cookie_security': {'type': 'dict', 'enable_disable_action': {'type': 'str', 'choices': ['enable', 'disable']}, 'allow_missing_cookie': {'type': 'bool', }, 'allow_unrecognized_cookie': {'type': 'bool', }, 'cookie_policy': {'type': 'list', 'cookie_policy_name': {'type': 'str', }, 'cookie_policy_allow': {'type': 'bool', }, 'cookie_policy_disallow': {'type': 'bool', }}, 'set_cookie_policy': {'type': 'list', 'set_cookie_policy_name': {'type': 'str', }, 'set_cookie_policy_allow': {'type': 'bool', }, 'set_cookie_policy_disallow': {'type': 'bool', }, 'set_cookie_policy_http_only': {'type': 'bool', }, 'set_cookie_policy_secure': {'type': 'bool', }, 'set_cookie_policy_samesite': {'type': 'str', 'choices': ['none', 'lax', 'strict']}, 'set_cookie_policy_sign': {'type': 'bool', }, 'set_cookie_policy_secret': {'type': 'str', }, 'set_cookie_policy_secret_encrypted': {'type': 'str', }}, 'tamper_protection_http_only': {'type': 'bool', }, 'tamper_protection_secure': {'type': 'bool', }, 'tamper_protection_samesite': {'type': 'str', 'choices': ['none', 'lax', 'strict']}, 'tamper_protection_secret': {'type': 'str', }, 'tamper_protection_secret_encrypted': {'type': 'str', }, 'tamper_protection_grace_period': {'type': 'int', }, 'tamper_protection_session_cookie_only': {'type': 'bool', }, 'tamper_protection_sign': {'type': 'bool', }, 'uuid': {'type': 'str', }},
        'evasion_check': {'type': 'dict', 'apache_whitespace': {'type': 'bool', }, 'decode_entities': {'type': 'bool', }, 'decode_escaped_chars': {'type': 'bool', }, 'decode_plus_chars': {'type': 'bool', }, 'decode_unicode_chars': {'type': 'bool', }, 'dir_traversal': {'type': 'bool', }, 'high_ascii_bytes': {'type': 'bool', }, 'invalid_hex_encoding': {'type': 'bool', }, 'multiple_encoding_levels': {'type': 'bool', }, 'multiple_slashes': {'type': 'bool', }, 'max_levels': {'type': 'int', }, 'remove_comments': {'type': 'bool', }, 'remove_spaces': {'type': 'bool', }, 'uuid': {'type': 'str', }},
        'data_leak_prevention': {'type': 'dict', 'ccn_mask': {'type': 'bool', }, 'ssn_mask': {'type': 'bool', }, 'pcre_mask': {'type': 'str', }, 'keep_start': {'type': 'int', }, 'keep_end': {'type': 'int', }, 'mask': {'type': 'str', }, 'uuid': {'type': 'str', }},
        'form_protection': {'type': 'dict', 'enable_disable_action': {'type': 'str', 'choices': ['enable', 'disable']}, 'csrf_check': {'type': 'bool', }, 'field_consistency_check': {'type': 'bool', }, 'password_check_non_masked': {'type': 'bool', }, 'password_check_non_ssl': {'type': 'bool', }, 'password_check_autocomplete': {'type': 'bool', }, 'form_check_non_ssl': {'type': 'bool', }, 'form_check_caching': {'type': 'bool', }, 'form_check_non_post': {'type': 'bool', }, 'form_check_request_non_post': {'type': 'bool', }, 'form_check_response_non_post': {'type': 'bool', }, 'form_check_response_non_post_sanitize': {'type': 'bool', }, 'uuid': {'type': 'str', }},
        'response_cloaking': {'type': 'dict', 'filter_headers': {'type': 'bool', }, 'hide_status_codes': {'type': 'bool', }, 'hide_status_codes_file': {'type': 'str', }, 'uuid': {'type': 'str', }},
        'request_check': {'type': 'dict', 'bot_check': {'type': 'bool', }, 'bot_check_policy_file': {'type': 'str', }, 'command_injection_check': {'type': 'str', 'choices': ['cookies', 'headers', 'form-body', 'uri-query']}, 'command_injection_check_policy_file': {'type': 'str', }, 'redirect_whitelist': {'type': 'bool', }, 'referer_check': {'type': 'bool', }, 'referer_domain_list': {'type': 'str', }, 'referer_safe_url': {'type': 'str', }, 'referer_domain_list_only': {'type': 'str', }, 'session_check': {'type': 'bool', }, 'lifetime': {'type': 'int', }, 'sqlia_check': {'type': 'str', 'choices': ['reject']}, 'sqlia_check_policy_file': {'type': 'str', }, 'url_blacklist': {'type': 'bool', }, 'waf_blacklist_file': {'type': 'str', }, 'url_whitelist': {'type': 'bool', }, 'waf_whitelist_file': {'type': 'str', }, 'url_learned_list': {'type': 'bool', }, 'xss_check': {'type': 'str', 'choices': ['reject']}, 'xss_check_policy_file': {'type': 'str', }, 'uuid': {'type': 'str', }},
        'violation_log_mask': {'type': 'dict', 'query_param_name_equal_type': {'type': 'str', 'choices': ['equals']}, 'query_param_name_value': {'type': 'str', }, 'uuid': {'type': 'str', }},
        'json_check': {'type': 'dict', 'format_check': {'type': 'bool', }, 'max_array_values': {'type': 'int', }, 'max_depth': {'type': 'int', }, 'max_object_members': {'type': 'int', }, 'max_string_length': {'type': 'int', }, 'uuid': {'type': 'str', }},
        'xml_check': {'type': 'dict', 'disable': {'type': 'bool', }, 'max_attr': {'type': 'int', }, 'max_attr_name_len': {'type': 'int', }, 'max_attr_value_len': {'type': 'int', }, 'max_cdata_len': {'type': 'int', }, 'max_elem': {'type': 'int', }, 'max_elem_child': {'type': 'int', }, 'max_elem_depth': {'type': 'int', }, 'max_elem_name_len': {'type': 'int', }, 'max_entity_decl': {'type': 'int', }, 'max_entity_depth': {'type': 'int', }, 'max_entity_exp': {'type': 'int', }, 'max_entity_exp_depth': {'type': 'int', }, 'max_namespace': {'type': 'int', }, 'max_namespace_uri_len': {'type': 'int', }, 'format': {'type': 'bool', }, 'sqlia': {'type': 'bool', }, 'xss': {'type': 'bool', }, 'uuid': {'type': 'str', }},
        'stats': {'type': 'dict', 'total_req': {'type': 'str', }, 'req_allowed': {'type': 'str', }, 'req_denied': {'type': 'str', }, 'resp_denied': {'type': 'str', }, 'brute_force_success': {'type': 'str', }, 'brute_force_violation': {'type': 'str', }, 'brute_force_challenge_cookie_sent': {'type': 'str', }, 'brute_force_challenge_cookie_success': {'type': 'str', }, 'brute_force_challenge_cookie_violation': {'type': 'str', }, 'brute_force_challenge_javascript_sent': {'type': 'str', }, 'brute_force_challenge_javascript_success': {'type': 'str', }, 'brute_force_challenge_javascript_violation': {'type': 'str', }, 'brute_force_challenge_captcha_sent': {'type': 'str', }, 'brute_force_challenge_captcha_success': {'type': 'str', }, 'brute_force_challenge_captcha_violation': {'type': 'str', }, 'brute_force_lockout_limit_success': {'type': 'str', }, 'brute_force_lockout_limit_violation': {'type': 'str', }, 'brute_force_challenge_limit_success': {'type': 'str', }, 'brute_force_challenge_limit_violation': {'type': 'str', }, 'brute_force_response_codes_triggered': {'type': 'str', }, 'brute_force_response_headers_triggered': {'type': 'str', }, 'brute_force_response_string_triggered': {'type': 'str', }, 'cookie_security_encrypt_success': {'type': 'str', }, 'cookie_security_encrypt_violation': {'type': 'str', }, 'cookie_security_encrypt_limit_exceeded': {'type': 'str', }, 'cookie_security_encrypt_skip_rcache': {'type': 'str', }, 'cookie_security_decrypt_success': {'type': 'str', }, 'cookie_security_decrypt_violation': {'type': 'str', }, 'cookie_security_sign_success': {'type': 'str', }, 'cookie_security_sign_violation': {'type': 'str', }, 'cookie_security_sign_limit_exceeded': {'type': 'str', }, 'cookie_security_sign_skip_rcache': {'type': 'str', }, 'cookie_security_signature_check_success': {'type': 'str', }, 'cookie_security_signature_check_violation': {'type': 'str', }, 'cookie_security_add_http_only_success': {'type': 'str', }, 'cookie_security_add_http_only_violation': {'type': 'str', }, 'cookie_security_add_secure_success': {'type': 'str', }, 'cookie_security_add_secure_violation': {'type': 'str', }, 'cookie_security_missing_cookie_success': {'type': 'str', }, 'cookie_security_missing_cookie_violation': {'type': 'str', }, 'cookie_security_unrecognized_cookie_success': {'type': 'str', }, 'cookie_security_unrecognized_cookie_violation': {'type': 'str', }, 'cookie_security_cookie_policy_success': {'type': 'str', }, 'cookie_security_cookie_policy_violation': {'type': 'str', }, 'cookie_security_persistent_cookies': {'type': 'str', }, 'cookie_security_persistent_cookies_encrypted': {'type': 'str', }, 'cookie_security_persistent_cookies_signed': {'type': 'str', }, 'cookie_security_session_cookies': {'type': 'str', }, 'cookie_security_session_cookies_encrypted': {'type': 'str', }, 'cookie_security_session_cookies_signed': {'type': 'str', }, 'cookie_security_allowed_session_cookies': {'type': 'str', }, 'cookie_security_allowed_persistent_cookies': {'type': 'str', }, 'cookie_security_disallowed_session_cookies': {'type': 'str', }, 'cookie_security_disallowed_persistent_cookies': {'type': 'str', }, 'cookie_security_allowed_session_set_cookies': {'type': 'str', }, 'cookie_security_allowed_persistent_set_cookies': {'type': 'str', }, 'cookie_security_disallowed_session_set_cookies': {'type': 'str', }, 'cookie_security_disallowed_persistent_set_cookies': {'type': 'str', }, 'csp_header_violation': {'type': 'str', }, 'csp_header_success': {'type': 'str', }, 'csp_header_inserted': {'type': 'str', }, 'form_csrf_tag_success': {'type': 'str', }, 'form_csrf_tag_violation': {'type': 'str', }, 'form_consistency_success': {'type': 'str', }, 'form_consistency_violation': {'type': 'str', }, 'form_tag_inserted': {'type': 'str', }, 'form_non_ssl_success': {'type': 'str', }, 'form_non_ssl_violation': {'type': 'str', }, 'form_request_non_post_success': {'type': 'str', }, 'form_request_non_post_violation': {'type': 'str', }, 'form_check_success': {'type': 'str', }, 'form_check_violation': {'type': 'str', }, 'form_check_sanitize': {'type': 'str', }, 'form_non_masked_password_success': {'type': 'str', }, 'form_non_masked_password_violation': {'type': 'str', }, 'form_non_ssl_password_success': {'type': 'str', }, 'form_non_ssl_password_violation': {'type': 'str', }, 'form_password_autocomplete_success': {'type': 'str', }, 'form_password_autocomplete_violation': {'type': 'str', }, 'form_set_no_cache_success': {'type': 'str', }, 'form_set_no_cache': {'type': 'str', }, 'dlp_ccn_success': {'type': 'str', }, 'dlp_ccn_amex_violation': {'type': 'str', }, 'dlp_ccn_amex_masked': {'type': 'str', }, 'dlp_ccn_diners_violation': {'type': 'str', }, 'dlp_ccn_diners_masked': {'type': 'str', }, 'dlp_ccn_visa_violation': {'type': 'str', }, 'dlp_ccn_visa_masked': {'type': 'str', }, 'dlp_ccn_mastercard_violation': {'type': 'str', }, 'dlp_ccn_mastercard_masked': {'type': 'str', }, 'dlp_ccn_discover_violation': {'type': 'str', }, 'dlp_ccn_discover_masked': {'type': 'str', }, 'dlp_ccn_jcb_violation': {'type': 'str', }, 'dlp_ccn_jcb_masked': {'type': 'str', }, 'dlp_ssn_success': {'type': 'str', }, 'dlp_ssn_violation': {'type': 'str', }, 'dlp_pcre_success': {'type': 'str', }, 'dlp_pcre_violation': {'type': 'str', }, 'dlp_pcre_masked': {'type': 'str', }, 'evasion_check_apache_whitespace_success': {'type': 'str', }, 'evasion_check_apache_whitespace_violation': {'type': 'str', }, 'evasion_check_decode_entities_success': {'type': 'str', }, 'evasion_check_decode_entities_violation': {'type': 'str', }, 'evasion_check_decode_escaped_chars_success': {'type': 'str', }, 'evasion_check_decode_escaped_chars_violation': {'type': 'str', }, 'evasion_check_decode_unicode_chars_success': {'type': 'str', }, 'evasion_check_decode_unicode_chars_violation': {'type': 'str', }, 'evasion_check_dir_traversal_success': {'type': 'str', }, 'evasion_check_dir_traversal_violation': {'type': 'str', }, 'evasion_check_high_ascii_bytes_success': {'type': 'str', }, 'evasion_check_high_ascii_bytes_violation': {'type': 'str', }, 'evasion_check_invalid_hex_encoding_success': {'type': 'str', }, 'evasion_check_invalid_hex_encoding_violation': {'type': 'str', }, 'evasion_check_multiple_encoding_levels_success': {'type': 'str', }, 'evasion_check_multiple_encoding_levels_violation': {'type': 'str', }, 'evasion_check_multiple_slashes_success': {'type': 'str', }, 'evasion_check_multiple_slashes_violation': {'type': 'str', }, 'evasion_check_max_levels_success': {'type': 'str', }, 'evasion_check_max_levels_violation': {'type': 'str', }, 'evasion_check_remove_comments_success': {'type': 'str', }, 'evasion_check_remove_comments_violation': {'type': 'str', }, 'evasion_check_remove_spaces_success': {'type': 'str', }, 'evasion_check_remove_spaces_violation': {'type': 'str', }, 'http_limit_max_content_length_success': {'type': 'str', }, 'http_limit_max_content_length_violation': {'type': 'str', }, 'http_limit_max_cookie_header_length_success': {'type': 'str', }, 'http_limit_max_cookie_header_length_violation': {'type': 'str', }, 'http_limit_max_cookie_name_length_success': {'type': 'str', }, 'http_limit_max_cookie_name_length_violation': {'type': 'str', }, 'http_limit_max_cookie_value_length_success': {'type': 'str', }, 'http_limit_max_cookie_value_length_violation': {'type': 'str', }, 'http_limit_max_cookies_success': {'type': 'str', }, 'http_limit_max_cookies_violation': {'type': 'str', }, 'http_limit_max_cookies_length_success': {'type': 'str', }, 'http_limit_max_cookies_length_violation': {'type': 'str', }, 'http_limit_max_data_parse_success': {'type': 'str', }, 'http_limit_max_data_parse_violation': {'type': 'str', }, 'http_limit_max_entities_success': {'type': 'str', }, 'http_limit_max_entities_violation': {'type': 'str', }, 'http_limit_max_header_length_success': {'type': 'str', }, 'http_limit_max_header_length_violation': {'type': 'str', }, 'http_limit_max_header_name_length_success': {'type': 'str', }, 'http_limit_max_header_name_length_violation': {'type': 'str', }, 'http_limit_max_header_value_length_success': {'type': 'str', }, 'http_limit_max_header_value_length_violation': {'type': 'str', }, 'http_limit_max_headers_success': {'type': 'str', }, 'http_limit_max_headers_violation': {'type': 'str', }, 'http_limit_max_headers_length_success': {'type': 'str', }, 'http_limit_max_headers_length_violation': {'type': 'str', }, 'http_limit_max_param_name_length_success': {'type': 'str', }, 'http_limit_max_param_name_length_violation': {'type': 'str', }, 'http_limit_max_param_value_length_success': {'type': 'str', }, 'http_limit_max_param_value_length_violation': {'type': 'str', }, 'http_limit_max_params_success': {'type': 'str', }, 'http_limit_max_params_violation': {'type': 'str', }, 'http_limit_max_params_length_success': {'type': 'str', }, 'http_limit_max_params_length_violation': {'type': 'str', }, 'http_limit_max_post_length_success': {'type': 'str', }, 'http_limit_max_post_length_violation': {'type': 'str', }, 'http_limit_max_query_length_success': {'type': 'str', }, 'http_limit_max_query_length_violation': {'type': 'str', }, 'http_limit_max_request_length_success': {'type': 'str', }, 'http_limit_max_request_length_violation': {'type': 'str', }, 'http_limit_max_request_line_length_success': {'type': 'str', }, 'http_limit_max_request_line_length_violation': {'type': 'str', }, 'max_url_length_success': {'type': 'str', }, 'max_url_length_violation': {'type': 'str', }, 'http_protocol_allowed_headers_success': {'type': 'str', }, 'http_protocol_allowed_headers_violation': {'type': 'str', }, 'http_protocol_allowed_versions_success': {'type': 'str', }, 'http_protocol_allowed_versions_violation': {'type': 'str', }, 'http_protocol_allowed_method_check_success': {'type': 'str', }, 'http_protocol_allowed_method_check_violation': {'type': 'str', }, 'http_protocol_bad_multipart_request_success': {'type': 'str', }, 'http_protocol_bad_multipart_request_violation': {'type': 'str', }, 'http_protocol_get_with_content_success': {'type': 'str', }, 'http_protocol_get_with_content_violation': {'type': 'str', }, 'http_protocol_head_with_content_success': {'type': 'str', }, 'http_protocol_head_with_content_violation': {'type': 'str', }, 'http_protocol_host_header_with_ip_success': {'type': 'str', }, 'http_protocol_host_header_with_ip_violation': {'type': 'str', }, 'http_protocol_invalid_url_encoding_success': {'type': 'str', }, 'http_protocol_invalid_url_encoding_violation': {'type': 'str', }, 'http_protocol_malformed_content_length_success': {'type': 'str', }, 'http_protocol_malformed_content_length_violation': {'type': 'str', }, 'http_protocol_malformed_header_success': {'type': 'str', }, 'http_protocol_malformed_header_violation': {'type': 'str', }, 'http_protocol_malformed_parameter_success': {'type': 'str', }, 'http_protocol_malformed_parameter_violation': {'type': 'str', }, 'http_protocol_malformed_request_success': {'type': 'str', }, 'http_protocol_malformed_request_violation': {'type': 'str', }, 'http_protocol_malformed_request_line_success': {'type': 'str', }, 'http_protocol_malformed_request_line_violation': {'type': 'str', }, 'http_protocol_missing_header_value_success': {'type': 'str', }, 'http_protocol_missing_header_value_violation': {'type': 'str', }, 'http_protocol_missing_host_header_success': {'type': 'str', }, 'http_protocol_missing_host_header_violation': {'type': 'str', }, 'http_protocol_multiple_content_length_success': {'type': 'str', }, 'http_protocol_multiple_content_length_violation': {'type': 'str', }, 'http_protocol_post_with_0_content_success': {'type': 'str', }, 'http_protocol_post_with_0_content_violation': {'type': 'str', }, 'http_protocol_post_without_content_success': {'type': 'str', }, 'http_protocol_post_without_content_violation': {'type': 'str', }, 'http_protocol_success': {'type': 'str', }, 'http_protocol_violation': {'type': 'str', }, 'json_check_format_success': {'type': 'str', }, 'json_check_format_violation': {'type': 'str', }, 'json_check_max_array_value_count_success': {'type': 'str', }, 'json_check_max_array_value_count_violation': {'type': 'str', }, 'json_check_max_depth_success': {'type': 'str', }, 'json_check_max_depth_violation': {'type': 'str', }, 'json_check_max_object_member_count_success': {'type': 'str', }, 'json_check_max_object_member_count_violation': {'type': 'str', }, 'json_check_max_string_success': {'type': 'str', }, 'json_check_max_string_violation': {'type': 'str', }, 'request_check_bot_success': {'type': 'str', }, 'request_check_bot_violation': {'type': 'str', }, 'request_check_redirect_wlist_success': {'type': 'str', }, 'request_check_redirect_wlist_violation': {'type': 'str', }, 'request_check_redirect_wlist_learn': {'type': 'str', }, 'request_check_referer_success': {'type': 'str', }, 'request_check_referer_violation': {'type': 'str', }, 'request_check_referer_redirect': {'type': 'str', }, 'request_check_session_check_none': {'type': 'str', }, 'request_check_session_check_success': {'type': 'str', }, 'request_check_session_check_violation': {'type': 'str', }, 'request_check_sqlia_url_success': {'type': 'str', }, 'request_check_sqlia_url_violation': {'type': 'str', }, 'request_check_sqlia_url_sanitize': {'type': 'str', }, 'request_check_sqlia_post_body_success': {'type': 'str', }, 'request_check_sqlia_post_body_violation': {'type': 'str', }, 'request_check_sqlia_post_body_sanitize': {'type': 'str', }, 'request_check_url_list_success': {'type': 'str', }, 'request_check_url_list_violation': {'type': 'str', }, 'request_check_url_list_learn': {'type': 'str', }, 'request_check_url_whitelist_success': {'type': 'str', }, 'request_check_url_whitelist_violation': {'type': 'str', }, 'request_check_url_blacklist_success': {'type': 'str', }, 'request_check_url_blacklist_violation': {'type': 'str', }, 'request_check_xss_cookie_success': {'type': 'str', }, 'request_check_xss_cookie_violation': {'type': 'str', }, 'request_check_xss_cookie_sanitize': {'type': 'str', }, 'request_check_xss_url_success': {'type': 'str', }, 'request_check_xss_url_violation': {'type': 'str', }, 'request_check_xss_url_sanitize': {'type': 'str', }, 'request_check_xss_post_body_success': {'type': 'str', }, 'request_check_xss_post_body_violation': {'type': 'str', }, 'request_check_xss_post_body_sanitize': {'type': 'str', }, 'response_cloaking_hide_status_code_success': {'type': 'str', }, 'response_cloaking_hide_status_code_violation': {'type': 'str', }, 'response_cloaking_filter_headers_success': {'type': 'str', }, 'response_cloaking_filter_headers_violation': {'type': 'str', }, 'soap_check_success': {'type': 'str', }, 'soap_check_violation': {'type': 'str', }, 'xml_check_format_success': {'type': 'str', }, 'xml_check_format_violation': {'type': 'str', }, 'xml_check_max_attr_success': {'type': 'str', }, 'xml_check_max_attr_violation': {'type': 'str', }, 'xml_check_max_attr_name_len_success': {'type': 'str', }, 'xml_check_max_attr_name_len_violation': {'type': 'str', }, 'xml_check_max_attr_value_len_success': {'type': 'str', }, 'xml_check_max_attr_value_len_violation': {'type': 'str', }, 'xml_check_max_cdata_len_success': {'type': 'str', }, 'xml_check_max_cdata_len_violation': {'type': 'str', }, 'xml_check_max_elem_success': {'type': 'str', }, 'xml_check_max_elem_violation': {'type': 'str', }, 'xml_check_max_elem_child_success': {'type': 'str', }, 'xml_check_max_elem_child_violation': {'type': 'str', }, 'xml_check_max_elem_depth_success': {'type': 'str', }, 'xml_check_max_elem_depth_violation': {'type': 'str', }, 'xml_check_max_elem_name_len_success': {'type': 'str', }, 'xml_check_max_elem_name_len_violation': {'type': 'str', }, 'xml_check_max_entity_exp_success': {'type': 'str', }, 'xml_check_max_entity_exp_violation': {'type': 'str', }, 'xml_check_max_entity_exp_depth_success': {'type': 'str', }, 'xml_check_max_entity_exp_depth_violation': {'type': 'str', }, 'xml_check_max_namespace_success': {'type': 'str', }, 'xml_check_max_namespace_violation': {'type': 'str', }, 'xml_check_namespace_uri_len_success': {'type': 'str', }, 'xml_check_namespace_uri_len_violation': {'type': 'str', }, 'xml_check_sqlia_success': {'type': 'str', }, 'xml_check_sqlia_violation': {'type': 'str', }, 'xml_check_xss_success': {'type': 'str', }, 'xml_check_xss_violation': {'type': 'str', }, 'xml_content_check_schema_success': {'type': 'str', }, 'xml_content_check_schema_violation': {'type': 'str', }, 'xml_content_check_wsdl_success': {'type': 'str', }, 'xml_content_check_wsdl_violation': {'type': 'str', }, 'learning_list_full': {'type': 'str', }, 'action_allow': {'type': 'str', }, 'action_deny_200': {'type': 'str', }, 'action_deny_403': {'type': 'str', }, 'action_deny_redirect': {'type': 'str', }, 'action_deny_reset': {'type': 'str', }, 'action_drop': {'type': 'str', }, 'action_deny_custom_response': {'type': 'str', }, 'action_learn': {'type': 'str', }, 'action_log': {'type': 'str', }, 'policy_limit_exceeded': {'type': 'str', }, 'sessions_alloc': {'type': 'str', }, 'sessions_freed': {'type': 'str', }, 'out_of_sessions': {'type': 'str', }, 'too_many_sessions': {'type': 'str', }, 'regex_violation': {'type': 'str', }, 'request_check_command_injection_cookies_success': {'type': 'str', }, 'request_check_command_injection_cookies_violation': {'type': 'str', }, 'request_check_command_injection_headers_success': {'type': 'str', }, 'request_check_command_injection_headers_violation': {'type': 'str', }, 'request_check_command_injection_uri_query_success': {'type': 'str', }, 'request_check_command_injection_uri_query_violation': {'type': 'str', }, 'request_check_command_injection_form_body_success': {'type': 'str', }, 'request_check_command_injection_form_body_violation': {'type': 'str', }, 'cookie_security_decrypt_in_grace_period_violation': {'type': 'str', }, 'form_response_non_post_success': {'type': 'str', }, 'form_response_non_post_violation': {'type': 'str', }, 'form_response_non_post_sanitize': {'type': 'str', }, 'xml_check_max_entity_decl_success': {'type': 'str', }, 'xml_check_max_entity_decl_violation': {'type': 'str', }, 'xml_check_max_entity_depth_success': {'type': 'str', }, 'xml_check_max_entity_depth_violation': {'type': 'str', }, 'response_action_allow': {'type': 'str', }, 'response_action_deny_200': {'type': 'str', }, 'response_action_deny_403': {'type': 'str', }, 'response_action_deny_redirect': {'type': 'str', }, 'response_action_deny_reset': {'type': 'str', }, 'response_action_drop': {'type': 'str', }, 'response_action_deny_custom_response': {'type': 'str', }, 'response_action_learn': {'type': 'str', }, 'response_action_log': {'type': 'str', }, 'http_protocol_post_without_content_type_success': {'type': 'str', }, 'http_protocol_post_without_content_type_violation': {'type': 'str', }, 'http_protocol_body_without_content_type_success': {'type': 'str', }, 'http_protocol_body_without_content_type_violation': {'type': 'str', }, 'http_protocol_non_ssl_cookie_prefix_success': {'type': 'str', }, 'http_protocol_non_ssl_cookie_prefix_violation': {'type': 'str', }, 'cookie_security_add_samesite_success': {'type': 'str', }, 'cookie_security_add_samesite_violation': {'type': 'str', }, 'name': {'type': 'str', 'required': True, }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/waf/template/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/","%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/waf/template/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["template"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["template"].get(k) != v:
            change_results["changed"] = True
            config_changes["template"][k] = v

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
    payload = utils.build_json("template", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["template"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["template-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["template"]["stats"] if info != "NotFound" else info
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
