#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_http
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - HTTP Template Name
    
    compression-auto-disable-on-high-cpu:
        description:
            - Auto-disable software compression on high cpu usage (Disable compression if cpu usage is above threshold. Default is off.)
    
    compression-content-type:
        
    
    compression-enable:
        description:
            - Enable Compression
    
    compression-exclude-content-type:
        
    
    compression-exclude-uri:
        
    
    compression-keep-accept-encoding:
        description:
            - Keep accept encoding
    
    compression-keep-accept-encoding-enable:
        description:
            - Enable Server Accept Encoding
    
    compression-level:
        description:
            - compression level, default 1 (compression level value, default is 1)
    
    compression-minimum-content-length:
        description:
            - Minimum Content Length (Minimum content length for compression in bytes. Default is 120.)
    
    failover-url:
        description:
            - Failover to this URL (Failover URL Name)
    
    host-switching:
        
    
    insert-client-ip:
        description:
            - Insert Client IP address into HTTP header
    
    insert-client-ip-header-name:
        description:
            - HTTP Header Name for inserting Client IP
    
    client-ip-hdr-replace:
        description:
            - Replace the existing header
    
    insert-client-port:
        description:
            - Insert Client Port address into HTTP header
    
    insert-client-port-header-name:
        description:
            - HTTP Header Name for inserting Client Port
    
    client-port-hdr-replace:
        description:
            - Replace the existing header
    
    log-retry:
        description:
            - log when HTTP request retry
    
    non-http-bypass:
        description:
            - Bypass non-http traffic instead of dropping
    
    bypass-sg:
        description:
            - Select service group for non-http traffic (Service Group Name)
    
    redirect:
        description:
            - Automatically send a redirect response
    
    rd-simple-loc:
        description:
            - Redirect location tag absolute URI string
    
    rd-secure:
        description:
            - Use HTTPS
    
    rd-port:
        description:
            - Port (Port Number)
    
    rd-resp-code:
        description:
            - '301': Moved Permanently; '302': Found; '303': See Other; '307': Temporary Redirect; choices:['301', '302', '303', '307']
    
    redirect-rewrite:
        
    
    request-header-erase-list:
        
    
    request-header-insert-list:
        
    
    response-content-replace-list:
        
    
    response-header-erase-list:
        
    
    response-header-insert-list:
        
    
    retry-on-5xx:
        description:
            - Retry http request on HTTP 5xx code
    
    retry-on-5xx-val:
        description:
            - Number of times to retry (default is 3)
    
    retry-on-5xx-per-req:
        description:
            - Retry http request on HTTP 5xx code for each request
    
    retry-on-5xx-per-req-val:
        description:
            - Number of times to retry (default is 3)
    
    strict-transaction-switch:
        description:
            - Force server selection on every HTTP request
    
    template:
        
    
    term-11client-hdr-conn-close:
        description:
            - Terminate HTTP 1.1 client when req has Connection: close
    
    persist-on-401:
        description:
            - Persist to the same server if the response code is 401
    
    100-cont-wait-for-req-complete:
        description:
            - When REQ has Expect 100 and response is not 100, then wait for whole request to be sent
    
    url-hash-persist:
        description:
            - Use URL's hash value to select server
    
    url-hash-offset:
        description:
            - Skip part of URL to calculate hash value (Offset of the URL string)
    
    url-hash-first:
        description:
            - Use the begining part of URL to calculate hash value (URL string length to calculate hash value)
    
    url-hash-last:
        description:
            - Use the end part of URL to calculate hash value (URL string length to calculate hash value)
    
    use-server-status:
        description:
            - Use Server-Status header to do URL hashing
    
    url-switching:
        
    
    req-hdr-wait-time:
        description:
            - HTTP request header wait time before abort connection
    
    req-hdr-wait-time-val:
        description:
            - Number of seconds wait for client request header (default is 7)
    
    request-line-case-insensitive:
        description:
            - Parse http request line as case insensitive
    
    keep-client-alive:
        description:
            - Keep client alive
    
    cookie-format:
        description:
            - 'rfc6265': Follow rfc6265; choices:['rfc6265']
    
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
AVAILABLE_PROPERTIES = {"100_cont_wait_for_req_complete","bypass_sg","client_ip_hdr_replace","client_port_hdr_replace","compression_auto_disable_on_high_cpu","compression_content_type","compression_enable","compression_exclude_content_type","compression_exclude_uri","compression_keep_accept_encoding","compression_keep_accept_encoding_enable","compression_level","compression_minimum_content_length","cookie_format","failover_url","host_switching","insert_client_ip","insert_client_ip_header_name","insert_client_port","insert_client_port_header_name","keep_client_alive","log_retry","name","non_http_bypass","persist_on_401","rd_port","rd_resp_code","rd_secure","rd_simple_loc","redirect","redirect_rewrite","req_hdr_wait_time","req_hdr_wait_time_val","request_header_erase_list","request_header_insert_list","request_line_case_insensitive","response_content_replace_list","response_header_erase_list","response_header_insert_list","retry_on_5xx","retry_on_5xx_per_req","retry_on_5xx_per_req_val","retry_on_5xx_val","strict_transaction_switch","template","term_11client_hdr_conn_close","url_hash_first","url_hash_last","url_hash_offset","url_hash_persist","url_switching","use_server_status","user_tag","uuid",}

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
        
        100_cont_wait_for_req_complete=dict(
            type='str' 
        ),
        bypass_sg=dict(
            type='str' 
        ),
        client_ip_hdr_replace=dict(
            type='str' 
        ),
        client_port_hdr_replace=dict(
            type='str' 
        ),
        compression_auto_disable_on_high_cpu=dict(
            type='str' 
        ),
        compression_content_type=dict(
            type='str' 
        ),
        compression_enable=dict(
            type='str' 
        ),
        compression_exclude_content_type=dict(
            type='str' 
        ),
        compression_exclude_uri=dict(
            type='str' 
        ),
        compression_keep_accept_encoding=dict(
            type='str' 
        ),
        compression_keep_accept_encoding_enable=dict(
            type='str' 
        ),
        compression_level=dict(
            type='str' 
        ),
        compression_minimum_content_length=dict(
            type='str' 
        ),
        cookie_format=dict(
            type='enum' , choices=['rfc6265']
        ),
        failover_url=dict(
            type='str' 
        ),
        host_switching=dict(
            type='str' 
        ),
        insert_client_ip=dict(
            type='str' 
        ),
        insert_client_ip_header_name=dict(
            type='str' 
        ),
        insert_client_port=dict(
            type='str' 
        ),
        insert_client_port_header_name=dict(
            type='str' 
        ),
        keep_client_alive=dict(
            type='str' 
        ),
        log_retry=dict(
            type='str' 
        ),
        name=dict(
            type='str' , required=True
        ),
        non_http_bypass=dict(
            type='str' 
        ),
        persist_on_401=dict(
            type='str' 
        ),
        rd_port=dict(
            type='str' 
        ),
        rd_resp_code=dict(
            type='enum' , choices=['301', '302', '303', '307']
        ),
        rd_secure=dict(
            type='str' 
        ),
        rd_simple_loc=dict(
            type='str' 
        ),
        redirect=dict(
            type='str' 
        ),
        redirect_rewrite=dict(
            type='str' 
        ),
        req_hdr_wait_time=dict(
            type='str' 
        ),
        req_hdr_wait_time_val=dict(
            type='str' 
        ),
        request_header_erase_list=dict(
            type='str' 
        ),
        request_header_insert_list=dict(
            type='str' 
        ),
        request_line_case_insensitive=dict(
            type='str' 
        ),
        response_content_replace_list=dict(
            type='str' 
        ),
        response_header_erase_list=dict(
            type='str' 
        ),
        response_header_insert_list=dict(
            type='str' 
        ),
        retry_on_5xx=dict(
            type='str' 
        ),
        retry_on_5xx_per_req=dict(
            type='str' 
        ),
        retry_on_5xx_per_req_val=dict(
            type='str' 
        ),
        retry_on_5xx_val=dict(
            type='str' 
        ),
        strict_transaction_switch=dict(
            type='str' 
        ),
        template=dict(
            type='str' 
        ),
        term_11client_hdr_conn_close=dict(
            type='str' 
        ),
        url_hash_first=dict(
            type='str' 
        ),
        url_hash_last=dict(
            type='str' 
        ),
        url_hash_offset=dict(
            type='str' 
        ),
        url_hash_persist=dict(
            type='str' 
        ),
        url_switching=dict(
            type='str' 
        ),
        use_server_status=dict(
            type='str' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/http/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/http/{name}"
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
    payload = build_json("http", module)
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
    payload = build_json("http", module)
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