#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_template
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - WAF Template Name
    
    allowed-http-methods:
        description:
            - List of allowed HTTP methods. Default is "GET POST". (List of HTTP methods allowed (default "GET POST"))
    
    bot-check:
        description:
            - Check User-Agent for known bots
    
    bot-check-policy-file:
        description:
            - Name of WAF policy list file
    
    brute-force-challenge-limit:
        description:
            - Maximum brute-force events before sending challenge (default 2) (Maximum brute-force events before locking out client (default 2))
    
    brute-force-global:
        description:
            - Brute-force triggers apply globally instead of per-client (Apply brute-force triggers globally)
    
    brute-force-lockout-limit:
        description:
            - Maximum brute-force events before locking out client (default 5)
    
    brute-force-lockout-period:
        description:
            - Number of seconds client should be locked out (default 600)
    
    brute-force-test-period:
        description:
            - Number of seconds for brute-force event counting (default 60)
    
    brute-force-check:
        description:
            - Enable brute-force attack mitigation
    
    brute-force-resp-codes:
        description:
            - Trigger brute-force check on HTTP response code
    
    brute-force-resp-codes-file:
        description:
            - Name of WAF policy list file
    
    brute-force-resp-string:
        description:
            - Trigger brute-force check on HTTP response line
    
    brute-force-resp-string-file:
        description:
            - Name of WAF policy list file
    
    brute-force-resp-headers:
        description:
            - Trigger brute-force check on HTTP response header names
    
    brute-force-resp-headers-file:
        description:
            - Name of WAF policy list file
    
    disable:
        description:
            - Disable buffer overflow protection
    
    max-cookie-len:
        description:
            - Max Cookie length allowed in request (default 4096) (Maximum length of cookie allowed (default 4096))
    
    max-cookie-name-len:
        description:
            - Max Cookie Name length allowed in request (default 64) ( Maximum length of cookie name allowed (default 64))
    
    max-cookie-value-len:
        description:
            - Max Cookie Value length allowed in request (default 4096) (Maximum length of cookie value allowed (default 4096))
    
    max-cookies-len:
        description:
            - Max Total Cookies length allowed in request (default 4096) (Maximum total length of cookies allowed (default 4096))
    
    max-data-parse:
        description:
            - Max data parsed for Web Application Firewall (default 65536) (Maximum data parsed for Web Application Firewall (default 65536))
    
    max-hdr-name-len:
        description:
            - Max header name length allowed in request (default 63) (Maximum length of header name allowed (default 63))
    
    max-hdr-value-len:
        description:
            - Max header value length allowed in request (default 4096) (Maximum length of header value allowed (default 4096))
    
    max-hdrs-len:
        description:
            - Max headers length allowed in request (default 4096) (Maximum length of headers allowed (default 4096))
    
    max-line-len:
        description:
            - Max Line length allowed in request (default 1024) (Maximum length of Request line allowed (default 1024))
    
    max-parameter-name-len:
        description:
            - Max HTML parameter name length in an HTTP request (default 256) (Maximum HTML parameter name length in an HTTP request (default 256))
    
    max-parameter-total-len:
        description:
            - Max HTML parameter total length in an HTTP request (default 4096) (Maximum HTML parameter total length in an HTTP request (default 4096))
    
    max-parameter-value-len:
        description:
            - Max HTML parameter value length in an HTTP request (default 4096) (Maximum HTML parameter value in an HTTP request (default 4096))
    
    max-post-size:
        description:
            - Max content length allowed in POST request (default 20480) (Maximum size allowed content in an HTTP POST request (default 20480))
    
    max-query-len:
        description:
            - Max Query length allowed in request (default 1024) (Maximum length of Request query allowed (default 1024))
    
    max-url-len:
        description:
            - Max URL length allowed in request (default 1024) (Maximum length of URL allowed (default 1024))
    
    ccn-mask:
        description:
            - Mask credit card numbers in response
    
    cookie-name:
        description:
            - Cookie name (simple string or PCRE pattern)
    
    cookie-encryption-secret:
        description:
            - Cookie encryption secret
    
    secret-encrypted:
        description:
            - Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED secret string)
    
    challenge-action-cookie:
        description:
            - Use Set-Cookie to determine if client allows cookies
    
    challenge-action-javascript:
        description:
            - Add JavaScript to response to test if client allows JavaScript
    
    challenge-action-captcha:
        description:
            - Initiate a Captcha to verify client can respond
    
    csrf-check:
        description:
            - Tag the form to protect against Cross-site Request Forgery
    
    http-redirect:
        description:
            - Send HTTP redirect response (302 Found) to specifed URL (URL to redirect to when denying request)
    
    http-resp-200:
        description:
            - Send HTTP response with status code 200 OK
    
    resp-url-200:
        description:
            - Response content to send client when denying request
    
    reset-conn:
        description:
            - Reset the client connection
    
    http-resp-403:
        description:
            - Send HTTP response with status code 403 Forbidden (default)
    
    resp-url-403:
        description:
            - Response content to send client when denying request
    
    deny-non-masked-passwords:
        description:
            - Denies forms that have a password field with a textual type, resulting in this field not being masked
    
    deny-non-ssl-passwords:
        description:
            - Denies any form that has a password field if the form is not sent over an SSL connection
    
    deny-password-autocomplete:
        description:
            - Check to protect against server-generated form which contain password fields that allow autocomplete
    
    deploy-mode:
        description:
            - 'active': Deploy WAF in active (blocking) mode; 'passive': Deploy WAF in passive (log-only) mode; 'learning': Deploy WAF in learning mode; choices:['active', 'passive', 'learning']
    
    filter-resp-hdrs:
        description:
            - Removes web server's identifying headers
    
    form-consistency-check:
        description:
            - Form input consistency check
    
    form-deny-non-post:
        description:
            - Deny request with forms if the method is not POST
    
    form-deny-non-ssl:
        description:
            - Deny request with forms if the protocol is not SSL
    
    form-set-no-cache:
        description:
            - Disable caching of form-containing responses
    
    hide-resp-codes:
        description:
            - Hides response codes that are not allowed (default 4xx, 5xx)
    
    hide-resp-codes-file:
        description:
            - Name of WAF policy list file
    
    http-check:
        description:
            - Check request for HTTP protocol compliance
    
    json-format-check:
        description:
            - Check HTTP body for JSON format compliance
    
    max-array-value-count:
        description:
            - Maximum number of values in an array in a JSON request body (default 256) (Maximum number of values in a JSON array (default 256))
    
    max-depth:
        description:
            - Maximum recursion depth in a value in a JSON requesnt body (default 16) (Maximum recursion depth in a JSON value (default 16))
    
    max-object-member-count:
        description:
            - Maximum number of members in an object in a JSON request body (default 256) (Maximum number of members in a JSON object (default 256))
    
    max-string:
        description:
            - Maximum length of a string in a JSON request body (default 64) (Maximum length of a JSON string (default 64))
    
    log-succ-reqs:
        description:
            - Log successful waf requests
    
    max-cookies:
        description:
            - Maximum number of cookies allowed in request (default 20)
    
    max-entities:
        description:
            - Maximum number of MIME entities allowed in request (default 10)
    
    max-hdrs:
        description:
            - Maximum number of headers allowed in request (default 20)
    
    max-parameters:
        description:
            - Maximum number of HTML parameters allowed in request (default 64)
    
    pcre-mask:
        description:
            - Mask matched PCRE pattern in response
    
    keep-start:
        description:
            - Number of unmasked characters at the beginning (default: 0)
    
    keep-end:
        description:
            - Number of unmasked characters at the end (default: 0)
    
    mask:
        description:
            - Character to mask the matched pattern (default: X)
    
    redirect-wlist:
        description:
            - Check Redirect URL against list of previously learned redirects
    
    referer-check:
        description:
            - Check referer to protect against CSRF attacks
    
    referer-domain-list:
        description:
            - List of referer domains allowed
    
    referer-safe-url:
        description:
            -  Safe URL to redirect to if referer is missing
    
    referer-domain-list-only:
        description:
            - List of referer domains allowed
    
    session-check:
        description:
            - Enable session checking via session cookie
    
    lifetime:
        description:
            - Session lifetime in minutes (default 10)
    
    soap-format-check:
        description:
            - Check XML document for SOAP format compliance
    
    sqlia-check:
        description:
            - 'reject': Reject requests with SQLIA patterns; 'sanitize': Remove bad SQL from request; choices:['reject', 'sanitize']
    
    sqlia-check-policy-file:
        description:
            - Name of WAF policy list file
    
    ssn-mask:
        description:
            - Mask US Social Security numbers in response
    
    logging:
        description:
            - Logging template (Logging Config name)
    
    uri-blist-check:
        description:
            - specify name of WAF policy list file to blacklist
    
    waf-blist-file:
        description:
            - Name of WAF policy list file
    
    uri-wlist-check:
        description:
            - specify name of WAF policy list file to whitelist
    
    waf-wlist-file:
        description:
            - Name of WAF policy list file
    
    url-check:
        description:
            - Check URL against list of previously learned URLs
    
    decode-entities:
        description:
            - Decode entities in internal url
    
    decode-escaped-chars:
        description:
            - Decode escaped characters such as \r \n \" \xXX \u00YY in internal url
    
    decode-hex-chars:
        description:
            - Decode hex chars such as \%xx and \%u00yy in internal url
    
    remove-comments:
        description:
            - Remove comments from internal url
    
    remove-selfref:
        description:
            - Remove self-references such as /./ and /path/../ from internal url
    
    remove-spaces:
        description:
            - Remove spaces from internal url
    
    xml-format-check:
        description:
            - Check HTTP body for XML format compliance
    
    max-attr:
        description:
            - Maximum number of attributes of an XML element (default 256)
    
    max-attr-name-len:
        description:
            - Maximum length of an attribute name (default 128)
    
    max-attr-value-len:
        description:
            - Maximum length of an attribute text value (default 128)
    
    max-cdata-len:
        description:
            - Maximum length of an CDATA section of an element (default 65535)
    
    max-elem:
        description:
            - Maximum number of XML elements (default 1024)
    
    max-elem-child:
        description:
            - Maximum number of children of an XML element (default 1024)
    
    max-elem-depth:
        description:
            - Maximum recursion level for element definition (default 256)
    
    max-elem-name-len:
        description:
            - Maximum length for an element name (default 128)
    
    max-entity-exp:
        description:
            - Maximum number of entity expansions (default 1024)
    
    max-entity-exp-depth:
        description:
            - Maximum nested depth of entity expansion (default 32)
    
    max-namespace:
        description:
            - Maximum number of namespace declarations (default 16)
    
    max-namespace-uri-len:
        description:
            - Maximum length of a namespace URI (default 256)
    
    xml-sqlia-check:
        description:
            - Check XML data against SQLIA policy
    
    wsdl-file:
        description:
            - Specify name of WSDL file for verifying XML body contents
    
    wsdl-resp-val-file:
        description:
            - Specify name of WSDL file for verifying XML body contents
    
    xml-schema-file:
        description:
            - Specify name of XML-Schema file for verifying XML body contents
    
    xml-schema-resp-val-file:
        description:
            - Specify name of XML-Schema file for verifying XML body contents
    
    xml-xss-check:
        description:
            - Check XML data against XSS policy
    
    xss-check:
        description:
            - 'reject': Reject requests with bad cookies; 'sanitize': Remove bad cookies from request; choices:['reject', 'sanitize']
    
    xss-check-policy-file:
        description:
            - Name of WAF policy list file
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"allowed_http_methods","bot_check","bot_check_policy_file","brute_force_challenge_limit","brute_force_check","brute_force_global","brute_force_lockout_limit","brute_force_lockout_period","brute_force_resp_codes","brute_force_resp_codes_file","brute_force_resp_headers","brute_force_resp_headers_file","brute_force_resp_string","brute_force_resp_string_file","brute_force_test_period","ccn_mask","challenge_action_captcha","challenge_action_cookie","challenge_action_javascript","cookie_encryption_secret","cookie_name","csrf_check","decode_entities","decode_escaped_chars","decode_hex_chars","deny_non_masked_passwords","deny_non_ssl_passwords","deny_password_autocomplete","deploy_mode","disable","filter_resp_hdrs","form_consistency_check","form_deny_non_post","form_deny_non_ssl","form_set_no_cache","hide_resp_codes","hide_resp_codes_file","http_check","http_redirect","http_resp_200","http_resp_403","json_format_check","keep_end","keep_start","lifetime","log_succ_reqs","logging","mask","max_array_value_count","max_attr","max_attr_name_len","max_attr_value_len","max_cdata_len","max_cookie_len","max_cookie_name_len","max_cookie_value_len","max_cookies","max_cookies_len","max_data_parse","max_depth","max_elem","max_elem_child","max_elem_depth","max_elem_name_len","max_entities","max_entity_exp","max_entity_exp_depth","max_hdr_name_len","max_hdr_value_len","max_hdrs","max_hdrs_len","max_line_len","max_namespace","max_namespace_uri_len","max_object_member_count","max_parameter_name_len","max_parameter_total_len","max_parameter_value_len","max_parameters","max_post_size","max_query_len","max_string","max_url_len","name","pcre_mask","redirect_wlist","referer_check","referer_domain_list","referer_domain_list_only","referer_safe_url","remove_comments","remove_selfref","remove_spaces","reset_conn","resp_url_200","resp_url_403","secret_encrypted","session_check","soap_format_check","sqlia_check","sqlia_check_policy_file","ssn_mask","uri_blist_check","uri_wlist_check","url_check","user_tag","uuid","waf_blist_file","waf_wlist_file","wsdl_file","wsdl_resp_val_file","xml_format_check","xml_schema_file","xml_schema_resp_val_file","xml_sqlia_check","xml_xss_check","xss_check","xss_check_policy_file",}

# our imports go at the top so we fail fast.
from a10_ansible.axapi_http import client_factory
from a10_ansible import errors as a10_ex

def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        
        allowed_http_methods=dict(
            type='str' 
        ),
        bot_check=dict(
            type='str' 
        ),
        bot_check_policy_file=dict(
            type='str' 
        ),
        brute_force_challenge_limit=dict(
            type='str' 
        ),
        brute_force_check=dict(
            type='str' 
        ),
        brute_force_global=dict(
            type='str' 
        ),
        brute_force_lockout_limit=dict(
            type='str' 
        ),
        brute_force_lockout_period=dict(
            type='str' 
        ),
        brute_force_resp_codes=dict(
            type='str' 
        ),
        brute_force_resp_codes_file=dict(
            type='str' 
        ),
        brute_force_resp_headers=dict(
            type='str' 
        ),
        brute_force_resp_headers_file=dict(
            type='str' 
        ),
        brute_force_resp_string=dict(
            type='str' 
        ),
        brute_force_resp_string_file=dict(
            type='str' 
        ),
        brute_force_test_period=dict(
            type='str' 
        ),
        ccn_mask=dict(
            type='str' 
        ),
        challenge_action_captcha=dict(
            type='str' 
        ),
        challenge_action_cookie=dict(
            type='str' 
        ),
        challenge_action_javascript=dict(
            type='str' 
        ),
        cookie_encryption_secret=dict(
            type='str' 
        ),
        cookie_name=dict(
            type='str' 
        ),
        csrf_check=dict(
            type='str' 
        ),
        decode_entities=dict(
            type='str' 
        ),
        decode_escaped_chars=dict(
            type='str' 
        ),
        decode_hex_chars=dict(
            type='str' 
        ),
        deny_non_masked_passwords=dict(
            type='str' 
        ),
        deny_non_ssl_passwords=dict(
            type='str' 
        ),
        deny_password_autocomplete=dict(
            type='str' 
        ),
        deploy_mode=dict(
            type='enum' , choices=['active', 'passive', 'learning']
        ),
        disable=dict(
            type='str' 
        ),
        filter_resp_hdrs=dict(
            type='str' 
        ),
        form_consistency_check=dict(
            type='str' 
        ),
        form_deny_non_post=dict(
            type='str' 
        ),
        form_deny_non_ssl=dict(
            type='str' 
        ),
        form_set_no_cache=dict(
            type='str' 
        ),
        hide_resp_codes=dict(
            type='str' 
        ),
        hide_resp_codes_file=dict(
            type='str' 
        ),
        http_check=dict(
            type='str' 
        ),
        http_redirect=dict(
            type='str' 
        ),
        http_resp_200=dict(
            type='str' 
        ),
        http_resp_403=dict(
            type='str' 
        ),
        json_format_check=dict(
            type='str' 
        ),
        keep_end=dict(
            type='str' 
        ),
        keep_start=dict(
            type='str' 
        ),
        lifetime=dict(
            type='str' 
        ),
        log_succ_reqs=dict(
            type='str' 
        ),
        logging=dict(
            type='str' 
        ),
        mask=dict(
            type='str' 
        ),
        max_array_value_count=dict(
            type='str' 
        ),
        max_attr=dict(
            type='str' 
        ),
        max_attr_name_len=dict(
            type='str' 
        ),
        max_attr_value_len=dict(
            type='str' 
        ),
        max_cdata_len=dict(
            type='str' 
        ),
        max_cookie_len=dict(
            type='str' 
        ),
        max_cookie_name_len=dict(
            type='str' 
        ),
        max_cookie_value_len=dict(
            type='str' 
        ),
        max_cookies=dict(
            type='str' 
        ),
        max_cookies_len=dict(
            type='str' 
        ),
        max_data_parse=dict(
            type='str' 
        ),
        max_depth=dict(
            type='str' 
        ),
        max_elem=dict(
            type='str' 
        ),
        max_elem_child=dict(
            type='str' 
        ),
        max_elem_depth=dict(
            type='str' 
        ),
        max_elem_name_len=dict(
            type='str' 
        ),
        max_entities=dict(
            type='str' 
        ),
        max_entity_exp=dict(
            type='str' 
        ),
        max_entity_exp_depth=dict(
            type='str' 
        ),
        max_hdr_name_len=dict(
            type='str' 
        ),
        max_hdr_value_len=dict(
            type='str' 
        ),
        max_hdrs=dict(
            type='str' 
        ),
        max_hdrs_len=dict(
            type='str' 
        ),
        max_line_len=dict(
            type='str' 
        ),
        max_namespace=dict(
            type='str' 
        ),
        max_namespace_uri_len=dict(
            type='str' 
        ),
        max_object_member_count=dict(
            type='str' 
        ),
        max_parameter_name_len=dict(
            type='str' 
        ),
        max_parameter_total_len=dict(
            type='str' 
        ),
        max_parameter_value_len=dict(
            type='str' 
        ),
        max_parameters=dict(
            type='str' 
        ),
        max_post_size=dict(
            type='str' 
        ),
        max_query_len=dict(
            type='str' 
        ),
        max_string=dict(
            type='str' 
        ),
        max_url_len=dict(
            type='str' 
        ),
        name=dict(
            type='str' , required=True
        ),
        pcre_mask=dict(
            type='str' 
        ),
        redirect_wlist=dict(
            type='str' 
        ),
        referer_check=dict(
            type='str' 
        ),
        referer_domain_list=dict(
            type='str' 
        ),
        referer_domain_list_only=dict(
            type='str' 
        ),
        referer_safe_url=dict(
            type='str' 
        ),
        remove_comments=dict(
            type='str' 
        ),
        remove_selfref=dict(
            type='str' 
        ),
        remove_spaces=dict(
            type='str' 
        ),
        reset_conn=dict(
            type='str' 
        ),
        resp_url_200=dict(
            type='str' 
        ),
        resp_url_403=dict(
            type='str' 
        ),
        secret_encrypted=dict(
            type='str' 
        ),
        session_check=dict(
            type='str' 
        ),
        soap_format_check=dict(
            type='str' 
        ),
        sqlia_check=dict(
            type='enum' , choices=['reject', 'sanitize']
        ),
        sqlia_check_policy_file=dict(
            type='str' 
        ),
        ssn_mask=dict(
            type='str' 
        ),
        uri_blist_check=dict(
            type='str' 
        ),
        uri_wlist_check=dict(
            type='str' 
        ),
        url_check=dict(
            type='str' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        waf_blist_file=dict(
            type='str' 
        ),
        waf_wlist_file=dict(
            type='str' 
        ),
        wsdl_file=dict(
            type='str' 
        ),
        wsdl_resp_val_file=dict(
            type='str' 
        ),
        xml_format_check=dict(
            type='str' 
        ),
        xml_schema_file=dict(
            type='str' 
        ),
        xml_schema_resp_val_file=dict(
            type='str' 
        ),
        xml_sqlia_check=dict(
            type='str' 
        ),
        xml_xss_check=dict(
            type='str' 
        ),
        xss_check=dict(
            type='enum' , choices=['reject', 'sanitize']
        ),
        xss_check_policy_file=dict(
            type='str' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/waf/template/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/waf/template/{name}"
    f_dict = {}
    
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def build_envelope(title, data):
    return {
        title: data
    }

def build_json(title, module):
    rv = {}
    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v:
            rx = x.replace("_", "-")
            rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if params.get(x)])
    
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

def exists(module):
    try:
        module.client.get(existing_url(module))
        return True
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("template", module)
    try:
        post_result = module.client.post(new_url(module), payload)
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

def update(module, result):
    payload = build_json("template", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
        result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result):
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result)

def absent(module, result):
    return delete(module, result)



def run_command(module):
    run_errors = []

    result = dict(
        changed=False,
        original_message="",
        message=""
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    # TODO(remove hardcoded port #)
    a10_port = 443
    a10_protocol = "https"

    valid, validation_errors = validate(module.params)
    map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)

    if state == 'present':
        result = present(module, result)
    elif state == 'absent':
        result = absent(module, result)
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec())
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()