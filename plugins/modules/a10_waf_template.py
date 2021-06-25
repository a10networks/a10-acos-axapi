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
    allowed_http_methods:
        description:
        - "List of allowed HTTP methods. Default is 'GET POST'. (List of HTTP methods
          allowed (default 'GET POST'))"
        type: str
        required: False
    bot_check:
        description:
        - "Check User-Agent for known bots"
        type: bool
        required: False
    bot_check_policy_file:
        description:
        - "Name of WAF policy list file"
        type: str
        required: False
    brute_force_challenge_limit:
        description:
        - "Maximum brute-force events before sending challenge (default 2) (Maximum brute-
          force events before locking out client (default 2))"
        type: int
        required: False
    brute_force_global:
        description:
        - "Brute-force triggers apply globally instead of per-client (Apply brute-force
          triggers globally)"
        type: bool
        required: False
    brute_force_lockout_limit:
        description:
        - "Maximum brute-force events before locking out client (default 5)"
        type: int
        required: False
    brute_force_lockout_period:
        description:
        - "Number of seconds client should be locked out (default 600)"
        type: int
        required: False
    brute_force_test_period:
        description:
        - "Number of seconds for brute-force event counting (default 60)"
        type: int
        required: False
    brute_force_check:
        description:
        - "Enable brute-force attack mitigation"
        type: bool
        required: False
    brute_force_resp_codes:
        description:
        - "Trigger brute-force check on HTTP response code"
        type: bool
        required: False
    brute_force_resp_codes_file:
        description:
        - "Name of WAF policy list file"
        type: str
        required: False
    brute_force_resp_string:
        description:
        - "Trigger brute-force check on HTTP response line"
        type: bool
        required: False
    brute_force_resp_string_file:
        description:
        - "Name of WAF policy list file"
        type: str
        required: False
    brute_force_resp_headers:
        description:
        - "Trigger brute-force check on HTTP response header names"
        type: bool
        required: False
    brute_force_resp_headers_file:
        description:
        - "Name of WAF policy list file"
        type: str
        required: False
    disable:
        description:
        - "Disable buffer overflow protection"
        type: bool
        required: False
    max_cookie_len:
        description:
        - "Max Cookie length allowed in request (default 4096) (Maximum length of cookie
          allowed (default 4096))"
        type: int
        required: False
    max_cookie_name_len:
        description:
        - "Max Cookie Name length allowed in request (default 64) ( Maximum length of
          cookie name allowed (default 64))"
        type: int
        required: False
    max_cookie_value_len:
        description:
        - "Max Cookie Value length allowed in request (default 4096) (Maximum length of
          cookie value allowed (default 4096))"
        type: int
        required: False
    max_cookies_len:
        description:
        - "Max Total Cookies length allowed in request (default 4096) (Maximum total
          length of cookies allowed (default 4096))"
        type: int
        required: False
    max_data_parse:
        description:
        - "Max data parsed for Web Application Firewall (default 65536) (Maximum data
          parsed for Web Application Firewall (default 65536))"
        type: int
        required: False
    max_hdr_name_len:
        description:
        - "Max header name length allowed in request (default 63) (Maximum length of
          header name allowed (default 63))"
        type: int
        required: False
    max_hdr_value_len:
        description:
        - "Max header value length allowed in request (default 4096) (Maximum length of
          header value allowed (default 4096))"
        type: int
        required: False
    max_hdrs_len:
        description:
        - "Max headers length allowed in request (default 4096) (Maximum length of headers
          allowed (default 4096))"
        type: int
        required: False
    max_line_len:
        description:
        - "Max Line length allowed in request (default 1024) (Maximum length of Request
          line allowed (default 1024))"
        type: int
        required: False
    max_parameter_name_len:
        description:
        - "Max HTML parameter name length in an HTTP request (default 256) (Maximum HTML
          parameter name length in an HTTP request (default 256))"
        type: int
        required: False
    max_parameter_total_len:
        description:
        - "Max HTML parameter total length in an HTTP request (default 4096) (Maximum HTML
          parameter total length in an HTTP request (default 4096))"
        type: int
        required: False
    max_parameter_value_len:
        description:
        - "Max HTML parameter value length in an HTTP request (default 4096) (Maximum HTML
          parameter value in an HTTP request (default 4096))"
        type: int
        required: False
    max_post_size:
        description:
        - "Max content length allowed in POST request (default 20480) (Maximum size
          allowed content in an HTTP POST request (default 20480))"
        type: int
        required: False
    max_query_len:
        description:
        - "Max Query length allowed in request (default 1024) (Maximum length of Request
          query allowed (default 1024))"
        type: int
        required: False
    max_url_len:
        description:
        - "Max URL length allowed in request (default 1024) (Maximum length of URL allowed
          (default 1024))"
        type: int
        required: False
    ccn_mask:
        description:
        - "Mask credit card numbers in response"
        type: bool
        required: False
    cookie_name:
        description:
        - "Cookie name (simple string or PCRE pattern)"
        type: str
        required: False
    cookie_encryption_secret:
        description:
        - "Cookie encryption secret"
        type: str
        required: False
    secret_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED secret string)"
        type: str
        required: False
    challenge_action_cookie:
        description:
        - "Use Set-Cookie to determine if client allows cookies"
        type: bool
        required: False
    challenge_action_javascript:
        description:
        - "Add JavaScript to response to test if client allows JavaScript"
        type: bool
        required: False
    csrf_check:
        description:
        - "Tag the form to protect against Cross-site Request Forgery"
        type: bool
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
    deny_non_masked_passwords:
        description:
        - "Denies forms that have a password field with a textual type, resulting in this
          field not being masked"
        type: bool
        required: False
    deny_non_ssl_passwords:
        description:
        - "Denies any form that has a password field if the form is not sent over an SSL
          connection"
        type: bool
        required: False
    deny_password_autocomplete:
        description:
        - "Check to protect against server-generated form which contain password fields
          that allow autocomplete"
        type: bool
        required: False
    deploy_mode:
        description:
        - "'active'= Deploy WAF in active (blocking) mode; 'passive'= Deploy WAF in
          passive (log-only) mode; 'learning'= Deploy WAF in learning mode;"
        type: str
        required: False
    filter_resp_hdrs:
        description:
        - "Removes web server's identifying headers"
        type: bool
        required: False
    form_consistency_check:
        description:
        - "Form input consistency check"
        type: bool
        required: False
    form_deny_non_post:
        description:
        - "Deny request with forms if the method is not POST"
        type: bool
        required: False
    form_deny_non_ssl:
        description:
        - "Deny request with forms if the protocol is not SSL"
        type: bool
        required: False
    form_set_no_cache:
        description:
        - "Disable caching of form-containing responses"
        type: bool
        required: False
    hide_resp_codes:
        description:
        - "Hides response codes that are not allowed (default 4xx, 5xx)"
        type: bool
        required: False
    hide_resp_codes_file:
        description:
        - "Name of WAF policy list file"
        type: str
        required: False
    http_check:
        description:
        - "Check request for HTTP protocol compliance"
        type: bool
        required: False
    json_format_check:
        description:
        - "Check HTTP body for JSON format compliance"
        type: bool
        required: False
    max_array_value_count:
        description:
        - "Maximum number of values in an array in a JSON request body (default 256)
          (Maximum number of values in a JSON array (default 256))"
        type: int
        required: False
    max_depth:
        description:
        - "Maximum recursion depth in a value in a JSON requesnt body (default 16)
          (Maximum recursion depth in a JSON value (default 16))"
        type: int
        required: False
    max_object_member_count:
        description:
        - "Maximum number of members in an object in a JSON request body (default 256)
          (Maximum number of members in a JSON object (default 256))"
        type: int
        required: False
    max_string:
        description:
        - "Maximum length of a string in a JSON request body (default 64) (Maximum length
          of a JSON string (default 64))"
        type: int
        required: False
    log_succ_reqs:
        description:
        - "Log successful waf requests"
        type: bool
        required: False
    max_cookies:
        description:
        - "Maximum number of cookies allowed in request (default 20)"
        type: int
        required: False
    max_entities:
        description:
        - "Maximum number of MIME entities allowed in request (default 10)"
        type: int
        required: False
    max_hdrs:
        description:
        - "Maximum number of headers allowed in request (default 20)"
        type: int
        required: False
    max_parameters:
        description:
        - "Maximum number of HTML parameters allowed in request (default 64)"
        type: int
        required: False
    pcre_mask:
        description:
        - "Mask matched PCRE pattern in response"
        type: str
        required: False
    keep_start:
        description:
        - "Number of unmasked characters at the beginning (default= 0)"
        type: int
        required: False
    keep_end:
        description:
        - "Number of unmasked characters at the end (default= 0)"
        type: int
        required: False
    mask:
        description:
        - "Character to mask the matched pattern (default= X)"
        type: str
        required: False
    redirect_wlist:
        description:
        - "Check Redirect URL against list of previously learned redirects"
        type: bool
        required: False
    referer_check:
        description:
        - "Check referer to protect against CSRF attacks"
        type: bool
        required: False
    referer_domain_list:
        description:
        - "List of referer domains allowed"
        type: str
        required: False
    referer_safe_url:
        description:
        - " Safe URL to redirect to if referer is missing"
        type: str
        required: False
    referer_domain_list_only:
        description:
        - "List of referer domains allowed"
        type: str
        required: False
    session_check:
        description:
        - "Enable session checking via session cookie"
        type: bool
        required: False
    lifetime:
        description:
        - "Session lifetime in minutes (default 10)"
        type: int
        required: False
    soap_format_check:
        description:
        - "Check XML document for SOAP format compliance"
        type: bool
        required: False
    sqlia_check:
        description:
        - "'reject'= Reject requests with SQLIA patterns; 'sanitize'= Remove bad SQL from
          request;"
        type: str
        required: False
    sqlia_check_policy_file:
        description:
        - "Name of WAF policy list file"
        type: str
        required: False
    ssn_mask:
        description:
        - "Mask US Social Security numbers in response"
        type: bool
        required: False
    logging:
        description:
        - "Logging template (Logging Config name)"
        type: str
        required: False
    uri_blist_check:
        description:
        - "specify name of WAF policy list file to blacklist"
        type: bool
        required: False
    waf_blist_file:
        description:
        - "Name of WAF policy list file"
        type: str
        required: False
    uri_wlist_check:
        description:
        - "specify name of WAF policy list file to whitelist"
        type: bool
        required: False
    waf_wlist_file:
        description:
        - "Name of WAF policy list file"
        type: str
        required: False
    url_check:
        description:
        - "Check URL against list of previously learned URLs"
        type: bool
        required: False
    decode_entities:
        description:
        - "Decode entities in internal url"
        type: bool
        required: False
    decode_escaped_chars:
        description:
        - "Decode escaped characters such as \\r \\n \\' \\xXX \\u00YY in internal url"
        type: bool
        required: False
    decode_hex_chars:
        description:
        - "Decode hex chars such as \\%xx and \\%u00yy in internal url"
        type: bool
        required: False
    remove_comments:
        description:
        - "Remove comments from internal url"
        type: bool
        required: False
    remove_selfref:
        description:
        - "Remove self-references such as /./ and /path/../ from internal url"
        type: bool
        required: False
    remove_spaces:
        description:
        - "Remove spaces from internal url"
        type: bool
        required: False
    xml_format_check:
        description:
        - "Check HTTP body for XML format compliance"
        type: bool
        required: False
    max_attr:
        description:
        - "Maximum number of attributes of an XML element (default 256)"
        type: int
        required: False
    max_attr_name_len:
        description:
        - "Maximum length of an attribute name (default 128)"
        type: int
        required: False
    max_attr_value_len:
        description:
        - "Maximum length of an attribute text value (default 128)"
        type: int
        required: False
    max_cdata_len:
        description:
        - "Maximum length of an CDATA section of an element (default 65535)"
        type: int
        required: False
    max_elem:
        description:
        - "Maximum number of XML elements (default 1024)"
        type: int
        required: False
    max_elem_child:
        description:
        - "Maximum number of children of an XML element (default 1024)"
        type: int
        required: False
    max_elem_depth:
        description:
        - "Maximum recursion level for element definition (default 256)"
        type: int
        required: False
    max_elem_name_len:
        description:
        - "Maximum length for an element name (default 128)"
        type: int
        required: False
    max_entity_exp:
        description:
        - "Maximum number of entity expansions (default 1024)"
        type: int
        required: False
    max_entity_exp_depth:
        description:
        - "Maximum nested depth of entity expansion (default 32)"
        type: int
        required: False
    max_namespace:
        description:
        - "Maximum number of namespace declarations (default 16)"
        type: int
        required: False
    max_namespace_uri_len:
        description:
        - "Maximum length of a namespace URI (default 256)"
        type: int
        required: False
    xml_sqlia_check:
        description:
        - "Check XML data against SQLIA policy"
        type: bool
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
    xml_xss_check:
        description:
        - "Check XML data against XSS policy"
        type: bool
        required: False
    xss_check:
        description:
        - "'reject'= Reject requests with bad cookies; 'sanitize'= Remove bad cookies from
          request;"
        type: str
        required: False
    xss_check_policy_file:
        description:
        - "Name of WAF policy list file"
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

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule
import copy

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["allowed_http_methods", "bot_check", "bot_check_policy_file", "brute_force_challenge_limit", "brute_force_check", "brute_force_global", "brute_force_lockout_limit", "brute_force_lockout_period", "brute_force_resp_codes", "brute_force_resp_codes_file", "brute_force_resp_headers", "brute_force_resp_headers_file", "brute_force_resp_string", "brute_force_resp_string_file", "brute_force_test_period", "ccn_mask", "challenge_action_cookie", "challenge_action_javascript", "cookie_encryption_secret", "cookie_name", "csrf_check", "decode_entities", "decode_escaped_chars", "decode_hex_chars", "deny_non_masked_passwords", "deny_non_ssl_passwords", "deny_password_autocomplete", "deploy_mode", "disable", "filter_resp_hdrs", "form_consistency_check", "form_deny_non_post", "form_deny_non_ssl", "form_set_no_cache", "hide_resp_codes", "hide_resp_codes_file", "http_check", "http_redirect", "http_resp_200", "http_resp_403", "json_format_check", "keep_end", "keep_start", "lifetime", "log_succ_reqs", "logging", "mask", "max_array_value_count", "max_attr", "max_attr_name_len", "max_attr_value_len", "max_cdata_len", "max_cookie_len", "max_cookie_name_len", "max_cookie_value_len", "max_cookies", "max_cookies_len", "max_data_parse", "max_depth", "max_elem", "max_elem_child", "max_elem_depth", "max_elem_name_len", "max_entities", "max_entity_exp", "max_entity_exp_depth", "max_hdr_name_len", "max_hdr_value_len", "max_hdrs", "max_hdrs_len", "max_line_len", "max_namespace", "max_namespace_uri_len", "max_object_member_count", "max_parameter_name_len", "max_parameter_total_len", "max_parameter_value_len", "max_parameters", "max_post_size", "max_query_len", "max_string", "max_url_len", "name", "pcre_mask", "redirect_wlist", "referer_check", "referer_domain_list", "referer_domain_list_only", "referer_safe_url", "remove_comments", "remove_selfref", "remove_spaces", "reset_conn", "resp_url_200", "resp_url_403", "secret_encrypted", "session_check", "soap_format_check", "sqlia_check", "sqlia_check_policy_file", "ssn_mask", "stats", "uri_blist_check", "uri_wlist_check", "url_check", "user_tag", "uuid", "waf_blist_file", "waf_wlist_file", "wsdl_file", "wsdl_resp_val_file", "xml_format_check", "xml_schema_file", "xml_schema_resp_val_file", "xml_sqlia_check", "xml_xss_check", "xss_check", "xss_check_policy_file", ]


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
        'allowed_http_methods': {'type': 'str', },
        'bot_check': {'type': 'bool', },
        'bot_check_policy_file': {'type': 'str', },
        'brute_force_challenge_limit': {'type': 'int', },
        'brute_force_global': {'type': 'bool', },
        'brute_force_lockout_limit': {'type': 'int', },
        'brute_force_lockout_period': {'type': 'int', },
        'brute_force_test_period': {'type': 'int', },
        'brute_force_check': {'type': 'bool', },
        'brute_force_resp_codes': {'type': 'bool', },
        'brute_force_resp_codes_file': {'type': 'str', },
        'brute_force_resp_string': {'type': 'bool', },
        'brute_force_resp_string_file': {'type': 'str', },
        'brute_force_resp_headers': {'type': 'bool', },
        'brute_force_resp_headers_file': {'type': 'str', },
        'disable': {'type': 'bool', },
        'max_cookie_len': {'type': 'int', },
        'max_cookie_name_len': {'type': 'int', },
        'max_cookie_value_len': {'type': 'int', },
        'max_cookies_len': {'type': 'int', },
        'max_data_parse': {'type': 'int', },
        'max_hdr_name_len': {'type': 'int', },
        'max_hdr_value_len': {'type': 'int', },
        'max_hdrs_len': {'type': 'int', },
        'max_line_len': {'type': 'int', },
        'max_parameter_name_len': {'type': 'int', },
        'max_parameter_total_len': {'type': 'int', },
        'max_parameter_value_len': {'type': 'int', },
        'max_post_size': {'type': 'int', },
        'max_query_len': {'type': 'int', },
        'max_url_len': {'type': 'int', },
        'ccn_mask': {'type': 'bool', },
        'cookie_name': {'type': 'str', },
        'cookie_encryption_secret': {'type': 'str', },
        'secret_encrypted': {'type': 'str', },
        'challenge_action_cookie': {'type': 'bool', },
        'challenge_action_javascript': {'type': 'bool', },
        'csrf_check': {'type': 'bool', },
        'http_redirect': {'type': 'str', },
        'http_resp_200': {'type': 'bool', },
        'resp_url_200': {'type': 'str', },
        'reset_conn': {'type': 'bool', },
        'http_resp_403': {'type': 'bool', },
        'resp_url_403': {'type': 'str', },
        'deny_non_masked_passwords': {'type': 'bool', },
        'deny_non_ssl_passwords': {'type': 'bool', },
        'deny_password_autocomplete': {'type': 'bool', },
        'deploy_mode': {'type': 'str', 'choices': ['active', 'passive', 'learning']},
        'filter_resp_hdrs': {'type': 'bool', },
        'form_consistency_check': {'type': 'bool', },
        'form_deny_non_post': {'type': 'bool', },
        'form_deny_non_ssl': {'type': 'bool', },
        'form_set_no_cache': {'type': 'bool', },
        'hide_resp_codes': {'type': 'bool', },
        'hide_resp_codes_file': {'type': 'str', },
        'http_check': {'type': 'bool', },
        'json_format_check': {'type': 'bool', },
        'max_array_value_count': {'type': 'int', },
        'max_depth': {'type': 'int', },
        'max_object_member_count': {'type': 'int', },
        'max_string': {'type': 'int', },
        'log_succ_reqs': {'type': 'bool', },
        'max_cookies': {'type': 'int', },
        'max_entities': {'type': 'int', },
        'max_hdrs': {'type': 'int', },
        'max_parameters': {'type': 'int', },
        'pcre_mask': {'type': 'str', },
        'keep_start': {'type': 'int', },
        'keep_end': {'type': 'int', },
        'mask': {'type': 'str', },
        'redirect_wlist': {'type': 'bool', },
        'referer_check': {'type': 'bool', },
        'referer_domain_list': {'type': 'str', },
        'referer_safe_url': {'type': 'str', },
        'referer_domain_list_only': {'type': 'str', },
        'session_check': {'type': 'bool', },
        'lifetime': {'type': 'int', },
        'soap_format_check': {'type': 'bool', },
        'sqlia_check': {'type': 'str', 'choices': ['reject', 'sanitize']},
        'sqlia_check_policy_file': {'type': 'str', },
        'ssn_mask': {'type': 'bool', },
        'logging': {'type': 'str', },
        'uri_blist_check': {'type': 'bool', },
        'waf_blist_file': {'type': 'str', },
        'uri_wlist_check': {'type': 'bool', },
        'waf_wlist_file': {'type': 'str', },
        'url_check': {'type': 'bool', },
        'decode_entities': {'type': 'bool', },
        'decode_escaped_chars': {'type': 'bool', },
        'decode_hex_chars': {'type': 'bool', },
        'remove_comments': {'type': 'bool', },
        'remove_selfref': {'type': 'bool', },
        'remove_spaces': {'type': 'bool', },
        'xml_format_check': {'type': 'bool', },
        'max_attr': {'type': 'int', },
        'max_attr_name_len': {'type': 'int', },
        'max_attr_value_len': {'type': 'int', },
        'max_cdata_len': {'type': 'int', },
        'max_elem': {'type': 'int', },
        'max_elem_child': {'type': 'int', },
        'max_elem_depth': {'type': 'int', },
        'max_elem_name_len': {'type': 'int', },
        'max_entity_exp': {'type': 'int', },
        'max_entity_exp_depth': {'type': 'int', },
        'max_namespace': {'type': 'int', },
        'max_namespace_uri_len': {'type': 'int', },
        'xml_sqlia_check': {'type': 'bool', },
        'wsdl_file': {'type': 'str', },
        'wsdl_resp_val_file': {'type': 'str', },
        'xml_schema_file': {'type': 'str', },
        'xml_schema_resp_val_file': {'type': 'str', },
        'xml_xss_check': {'type': 'bool', },
        'xss_check': {'type': 'str', 'choices': ['reject', 'sanitize']},
        'xss_check_policy_file': {'type': 'str', },
        'uuid': {'type': 'str', },
        'user_tag': {'type': 'str', },
        'stats': {'type': 'dict', 'total_req': {'type': 'str', }, 'req_allowed': {'type': 'str', }, 'req_denied': {'type': 'str', }, 'bot_check_succ': {'type': 'str', }, 'bot_check_fail': {'type': 'str', }, 'form_consistency_succ': {'type': 'str', }, 'form_consistency_fail': {'type': 'str', }, 'form_csrf_tag_succ': {'type': 'str', }, 'form_csrf_tag_fail': {'type': 'str', }, 'url_check_succ': {'type': 'str', }, 'url_check_fail': {'type': 'str', }, 'url_check_learn': {'type': 'str', }, 'buf_ovf_url_len_fail': {'type': 'str', }, 'buf_ovf_cookie_len_fail': {'type': 'str', }, 'buf_ovf_hdrs_len_fail': {'type': 'str', }, 'buf_ovf_post_size_fail': {'type': 'str', }, 'max_cookies_fail': {'type': 'str', }, 'max_hdrs_fail': {'type': 'str', }, 'http_method_check_succ': {'type': 'str', }, 'http_method_check_fail': {'type': 'str', }, 'http_check_succ': {'type': 'str', }, 'http_check_fail': {'type': 'str', }, 'referer_check_succ': {'type': 'str', }, 'referer_check_fail': {'type': 'str', }, 'referer_check_redirect': {'type': 'str', }, 'uri_wlist_succ': {'type': 'str', }, 'uri_wlist_fail': {'type': 'str', }, 'uri_blist_succ': {'type': 'str', }, 'uri_blist_fail': {'type': 'str', }, 'post_form_check_succ': {'type': 'str', }, 'post_form_check_sanitize': {'type': 'str', }, 'post_form_check_reject': {'type': 'str', }, 'ccn_mask_amex': {'type': 'str', }, 'ccn_mask_diners': {'type': 'str', }, 'ccn_mask_visa': {'type': 'str', }, 'ccn_mask_mastercard': {'type': 'str', }, 'ccn_mask_discover': {'type': 'str', }, 'ccn_mask_jcb': {'type': 'str', }, 'ssn_mask': {'type': 'str', }, 'pcre_mask': {'type': 'str', }, 'cookie_encrypt_succ': {'type': 'str', }, 'cookie_encrypt_fail': {'type': 'str', }, 'cookie_encrypt_limit_exceeded': {'type': 'str', }, 'cookie_encrypt_skip_rcache': {'type': 'str', }, 'cookie_decrypt_succ': {'type': 'str', }, 'cookie_decrypt_fail': {'type': 'str', }, 'sqlia_chk_url_succ': {'type': 'str', }, 'sqlia_chk_url_sanitize': {'type': 'str', }, 'sqlia_chk_url_reject': {'type': 'str', }, 'sqlia_chk_post_succ': {'type': 'str', }, 'sqlia_chk_post_sanitize': {'type': 'str', }, 'sqlia_chk_post_reject': {'type': 'str', }, 'xss_chk_cookie_succ': {'type': 'str', }, 'xss_chk_cookie_sanitize': {'type': 'str', }, 'xss_chk_cookie_reject': {'type': 'str', }, 'xss_chk_url_succ': {'type': 'str', }, 'xss_chk_url_sanitize': {'type': 'str', }, 'xss_chk_url_reject': {'type': 'str', }, 'xss_chk_post_succ': {'type': 'str', }, 'xss_chk_post_sanitize': {'type': 'str', }, 'xss_chk_post_reject': {'type': 'str', }, 'resp_code_hidden': {'type': 'str', }, 'resp_hdrs_filtered': {'type': 'str', }, 'learn_updates': {'type': 'str', }, 'num_drops': {'type': 'str', }, 'num_resets': {'type': 'str', }, 'form_non_ssl_reject': {'type': 'str', }, 'form_non_post_reject': {'type': 'str', }, 'sess_check_none': {'type': 'str', }, 'sess_check_succ': {'type': 'str', }, 'sess_check_fail': {'type': 'str', }, 'soap_check_succ': {'type': 'str', }, 'soap_check_failure': {'type': 'str', }, 'wsdl_fail': {'type': 'str', }, 'wsdl_succ': {'type': 'str', }, 'xml_schema_fail': {'type': 'str', }, 'xml_schema_succ': {'type': 'str', }, 'xml_sqlia_chk_fail': {'type': 'str', }, 'xml_sqlia_chk_succ': {'type': 'str', }, 'xml_xss_chk_fail': {'type': 'str', }, 'xml_xss_chk_succ': {'type': 'str', }, 'json_check_failure': {'type': 'str', }, 'json_check_succ': {'type': 'str', }, 'xml_check_failure': {'type': 'str', }, 'xml_check_succ': {'type': 'str', }, 'buf_ovf_cookie_value_len_fail': {'type': 'str', }, 'buf_ovf_cookies_len_fail': {'type': 'str', }, 'buf_ovf_hdr_name_len_fail': {'type': 'str', }, 'buf_ovf_hdr_value_len_fail': {'type': 'str', }, 'buf_ovf_max_data_parse_fail': {'type': 'str', }, 'buf_ovf_line_len_fail': {'type': 'str', }, 'buf_ovf_parameter_name_len_fail': {'type': 'str', }, 'buf_ovf_parameter_value_len_fail': {'type': 'str', }, 'buf_ovf_parameter_total_len_fail': {'type': 'str', }, 'buf_ovf_query_len_fail': {'type': 'str', }, 'max_entities_fail': {'type': 'str', }, 'max_parameters_fail': {'type': 'str', }, 'buf_ovf_cookie_name_len_fail': {'type': 'str', }, 'xml_limit_attr': {'type': 'str', }, 'xml_limit_attr_name_len': {'type': 'str', }, 'xml_limit_attr_value_len': {'type': 'str', }, 'xml_limit_cdata_len': {'type': 'str', }, 'xml_limit_elem': {'type': 'str', }, 'xml_limit_elem_child': {'type': 'str', }, 'xml_limit_elem_depth': {'type': 'str', }, 'xml_limit_elem_name_len': {'type': 'str', }, 'xml_limit_entity_exp': {'type': 'str', }, 'xml_limit_entity_exp_depth': {'type': 'str', }, 'xml_limit_namespace': {'type': 'str', }, 'xml_limit_namespace_uri_len': {'type': 'str', }, 'json_limit_array_value_count': {'type': 'str', }, 'json_limit_depth': {'type': 'str', }, 'json_limit_object_member_count': {'type': 'str', }, 'json_limit_string': {'type': 'str', }, 'form_non_masked_password': {'type': 'str', }, 'form_non_ssl_password': {'type': 'str', }, 'form_password_autocomplete': {'type': 'str', }, 'redirect_wlist_succ': {'type': 'str', }, 'redirect_wlist_fail': {'type': 'str', }, 'redirect_wlist_learn': {'type': 'str', }, 'form_set_no_cache': {'type': 'str', }, 'resp_denied': {'type': 'str', }, 'sessions_alloc': {'type': 'str', }, 'sessions_freed': {'type': 'str', }, 'out_of_sessions': {'type': 'str', }, 'too_many_sessions': {'type': 'str', }, 'called': {'type': 'str', }, 'permitted': {'type': 'str', }, 'brute_force_success': {'type': 'str', }, 'brute_force_fail': {'type': 'str', }, 'challenge_cookie_sent': {'type': 'str', }, 'challenge_javascript_sent': {'type': 'str', }, 'challenge_captcha_sent': {'type': 'str', }, 'name': {'type': 'str', 'required': True, }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/waf/template/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def _get(module, url, params={}):

    resp = None
    try:
        resp = module.client.get(url, params=params)
    except a10_ex.NotFound:
        resp = "Not Found"

    call_result = {
        "endpoint": url,
        "http_method": "GET",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _post(module, url, params={}, file_content=None, file_name=None):
    resp = module.client.post(url, params=params)
    resp = resp if resp else {}
    call_result = {
        "endpoint": url,
        "http_method": "POST",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _delete(module, url):
    call_result = {
        "endpoint": url,
        "http_method": "DELETE",
        "request_body": {},
        "response_body": module.client.delete(url),
    }
    return call_result


def _switch_device_context(module, device_id):
    call_result = {
        "endpoint": "/axapi/v3/device-context",
        "http_method": "POST",
        "request_body": {"device-id": device_id},
        "response_body": module.client.change_context(device_id)
    }
    return call_result


def _active_partition(module, a10_partition):
    call_result = {
        "endpoint": "/axapi/v3/active-partition",
        "http_method": "POST",
        "request_body": {"curr_part_name": a10_partition},
        "response_body": module.client.activate_partition(a10_partition)
    }
    return call_result


def get(module):
    return _get(module, existing_url(module))


def get_list(module):
    return _get(module, list_url(module))


def get_stats(module):
    query_params = {}
    if module.params.get("stats"):
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, stats_url(module), params=query_params)



def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")


def _build_dict_from_param(param):
    rv = {}

    for k, v in param.items():
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
    url_base = "/axapi/v3/waf/template/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


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


def create(module, result, payload):
    try:
        call_result = _post(module, new_url(module), payload)
        result["axapi_calls"].append(call_result)
        result["modified_values"].update(
                **call_result["response_body"])
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config, payload):
    try:
        call_result = _post(module, existing_url(module), payload)
        result["axapi_calls"].append(call_result)
        if call_result["response_body"] == existing_config:
            result["changed"] = False
        else:
            result["modified_values"].update(
                **call_result["response_body"])
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def present(module, result, existing_config):
    payload = build_json("template", module)
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
        call_result = _delete(module, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

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
    result = dict(
        changed=False,
        messages="",
        modified_values={},
        axapi_calls=[]
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

    valid = True

    run_errors = []
    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

    if a10_partition:
        result["axapi_calls"].append(
            _active_partition(module, a10_partition))

    if a10_device_context_id:
         result["axapi_calls"].append(
            _switch_device_context(module, a10_device_context_id))

    existing_config = get(module)
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
            result["axapi_calls"].append(get(module))
        elif module.params.get("get_type") == "list":
            result["axapi_calls"].append(get_list(module))
        elif module.params.get("get_type") == "stats":
            result["axapi_calls"].append(get_stats(module))
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
