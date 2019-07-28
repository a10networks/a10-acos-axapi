#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_template_http
description:
    - HTTP
short_description: Configures A10 slb.template.http
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
    partition:
        description:
        - Destination/target partition for object/command
    keep_client_alive:
        description:
        - "Keep client alive"
        required: False
    compression_auto_disable_on_high_cpu:
        description:
        - "Auto-disable software compression on high cpu usage (Disable compression if cpu usage is above threshold. Default is off.)"
        required: False
    req_hdr_wait_time:
        description:
        - "HTTP request header wait time before abort connection"
        required: False
    compression_exclude_uri:
        description:
        - "Field compression_exclude_uri"
        required: False
        suboptions:
            exclude_uri:
                description:
                - "Compression exclude uri"
    compression_enable:
        description:
        - "Enable Compression"
        required: False
    compression_keep_accept_encoding:
        description:
        - "Keep accept encoding"
        required: False
    failover_url:
        description:
        - "Failover to this URL (Failover URL Name)"
        required: False
    redirect_rewrite:
        description:
        - "Field redirect_rewrite"
        required: False
        suboptions:
            redirect_secure_port:
                description:
                - "Port (Port Number)"
            redirect_secure:
                description:
                - "Use HTTPS"
            match_list:
                description:
                - "Field match_list"
    request_header_erase_list:
        description:
        - "Field request_header_erase_list"
        required: False
        suboptions:
            request_header_erase:
                description:
                - "Erase a header from HTTP request (Header Name)"
    rd_port:
        description:
        - "Port (Port Number)"
        required: False
    host_switching:
        description:
        - "Field host_switching"
        required: False
        suboptions:
            host_switching_type:
                description:
                - "'contains'= Select service group if hostname contains another string; 'ends-with'= Select service group if hostname ends with another string; 'equals'= Select service group if hostname equals another string; 'starts-with'= Select service group if hostname starts with another string; 'regex-match'= Select service group if URL string matches with regular expression; 'host-hits-enable'= Enables Host Hits counters; "
            host_service_group:
                description:
                - "Create a Service Group comprising Servers (Service Group Name)"
            host_match_string:
                description:
                - "Hostname String"
    url_hash_last:
        description:
        - "Use the end part of URL to calculate hash value (URL string length to calculate hash value)"
        required: False
    client_ip_hdr_replace:
        description:
        - "Replace the existing header"
        required: False
    use_server_status:
        description:
        - "Use Server-Status header to do URL hashing"
        required: False
    req_hdr_wait_time_val:
        description:
        - "Number of seconds wait for client request header (default is 7)"
        required: False
    response_header_insert_list:
        description:
        - "Field response_header_insert_list"
        required: False
        suboptions:
            response_header_insert_type:
                description:
                - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-always'= Always insert the header even when there is a header with the same name; "
            response_header_insert:
                description:
                - "Insert a header into HTTP response (Header Content (Format= '[name]=[value]'))"
    persist_on_401:
        description:
        - "Persist to the same server if the response code is 401"
        required: False
    redirect:
        description:
        - "Automatically send a redirect response"
        required: False
    insert_client_port:
        description:
        - "Insert Client Port address into HTTP header"
        required: False
    retry_on_5xx_per_req_val:
        description:
        - "Number of times to retry (default is 3)"
        required: False
    url_hash_offset:
        description:
        - "Skip part of URL to calculate hash value (Offset of the URL string)"
        required: False
    rd_simple_loc:
        description:
        - "Redirect location tag absolute URI string"
        required: False
    log_retry:
        description:
        - "log when HTTP request retry"
        required: False
    non_http_bypass:
        description:
        - "Bypass non-http traffic instead of dropping"
        required: False
    retry_on_5xx_per_req:
        description:
        - "Retry http request on HTTP 5xx code for each request"
        required: False
    insert_client_ip:
        description:
        - "Insert Client IP address into HTTP header"
        required: False
    template:
        description:
        - "Field template"
        required: False
        suboptions:
            logging:
                description:
                - "Logging template (Logging Config name)"
    url_switching:
        description:
        - "Field url_switching"
        required: False
        suboptions:
            url_service_group:
                description:
                - "Create a Service Group comprising Servers (Service Group Name)"
            url_match_string:
                description:
                - "URL String"
            url_switching_type:
                description:
                - "'contains'= Select service group if URL string contains another string; 'ends-with'= Select service group if URL string ends with another string; 'equals'= Select service group if URL string equals another string; 'starts-with'= Select service group if URL string starts with another string; 'regex-match'= Select service group if URL string matches with regular expression; 'url-case-insensitive'= Case insensitive URL switching; 'url-hits-enable'= Enables URL Hits; "
    insert_client_port_header_name:
        description:
        - "HTTP Header Name for inserting Client Port"
        required: False
    strict_transaction_switch:
        description:
        - "Force server selection on every HTTP request"
        required: False
    response_content_replace_list:
        description:
        - "Field response_content_replace_list"
        required: False
        suboptions:
            response_new_string:
                description:
                - "String will be in the http content"
            response_content_replace:
                description:
                - "replace the data from HTTP response content (String in the http content need to be replaced)"
    http_100_cont_wait_for_req_complete:
        description:
        - "When REQ has Expect 100 and response is not 100, then wait for whole request to be sent"
        required: False
    max_concurrent_streams:
        description:
        - "(http2 only) Max concurrent streams, default 100"
        required: False
    request_header_insert_list:
        description:
        - "Field request_header_insert_list"
        required: False
        suboptions:
            request_header_insert:
                description:
                - "Insert a header into HTTP request (Header Content (Format= '[name]=[value]'))"
            request_header_insert_type:
                description:
                - "'insert-if-not-exist'= Only insert the header when it does not exist; 'insert-always'= Always insert the header even when there is a header with the same name; "
    compression_minimum_content_length:
        description:
        - "Minimum Content Length (Minimum content length for compression in bytes. Default is 120.)"
        required: False
    compression_level:
        description:
        - "compression level, default 1 (compression level value, default is 1)"
        required: False
    request_line_case_insensitive:
        description:
        - "Parse http request line as case insensitive"
        required: False
    url_hash_persist:
        description:
        - "Use URL's hash value to select server"
        required: False
    response_header_erase_list:
        description:
        - "Field response_header_erase_list"
        required: False
        suboptions:
            response_header_erase:
                description:
                - "Erase a header from HTTP response (Header Name)"
    uuid:
        description:
        - "uuid of the object"
        required: False
    bypass_sg:
        description:
        - "Select service group for non-http traffic (Service Group Name)"
        required: False
    name:
        description:
        - "HTTP Template Name"
        required: True
    retry_on_5xx_val:
        description:
        - "Number of times to retry (default is 3)"
        required: False
    url_hash_first:
        description:
        - "Use the begining part of URL to calculate hash value (URL string length to calculate hash value)"
        required: False
    compression_keep_accept_encoding_enable:
        description:
        - "Enable Server Accept Encoding"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    compression_content_type:
        description:
        - "Field compression_content_type"
        required: False
        suboptions:
            content_type:
                description:
                - "Compression content-type"
    client_port_hdr_replace:
        description:
        - "Replace the existing header"
        required: False
    insert_client_ip_header_name:
        description:
        - "HTTP Header Name for inserting Client IP"
        required: False
    rd_secure:
        description:
        - "Use HTTPS"
        required: False
    retry_on_5xx:
        description:
        - "Retry http request on HTTP 5xx code"
        required: False
    cookie_format:
        description:
        - "'rfc6265'= Follow rfc6265; "
        required: False
    term_11client_hdr_conn_close:
        description:
        - "Terminate HTTP 1.1 client when req has Connection= close"
        required: False
    compression_exclude_content_type:
        description:
        - "Field compression_exclude_content_type"
        required: False
        suboptions:
            exclude_content_type:
                description:
                - "Compression exclude content-type (Compression exclude content type)"
    rd_resp_code:
        description:
        - "'301'= Moved Permanently; '302'= Found; '303'= See Other; '307'= Temporary Redirect; "
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
AVAILABLE_PROPERTIES = ["http_100_cont_wait_for_req_complete","bypass_sg","client_ip_hdr_replace","client_port_hdr_replace","compression_auto_disable_on_high_cpu","compression_content_type","compression_enable","compression_exclude_content_type","compression_exclude_uri","compression_keep_accept_encoding","compression_keep_accept_encoding_enable","compression_level","compression_minimum_content_length","cookie_format","failover_url","host_switching","insert_client_ip","insert_client_ip_header_name","insert_client_port","insert_client_port_header_name","keep_client_alive","log_retry","max_concurrent_streams","name","non_http_bypass","persist_on_401","rd_port","rd_resp_code","rd_secure","rd_simple_loc","redirect","redirect_rewrite","req_hdr_wait_time","req_hdr_wait_time_val","request_header_erase_list","request_header_insert_list","request_line_case_insensitive","response_content_replace_list","response_header_erase_list","response_header_insert_list","retry_on_5xx","retry_on_5xx_per_req","retry_on_5xx_per_req_val","retry_on_5xx_val","strict_transaction_switch","template","term_11client_hdr_conn_close","url_hash_first","url_hash_last","url_hash_offset","url_hash_persist","url_switching","use_server_status","user_tag","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        partition=dict(type='str', required=False)
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        keep_client_alive=dict(type='bool',),
        compression_auto_disable_on_high_cpu=dict(type='int',),
        req_hdr_wait_time=dict(type='bool',),
        compression_exclude_uri=dict(type='list',exclude_uri=dict(type='str',)),
        compression_enable=dict(type='bool',),
        compression_keep_accept_encoding=dict(type='bool',),
        failover_url=dict(type='str',),
        redirect_rewrite=dict(type='dict',redirect_secure_port=dict(type='int',),redirect_secure=dict(type='bool',),match_list=dict(type='list',rewrite_to=dict(type='str',),redirect_match=dict(type='str',))),
        request_header_erase_list=dict(type='list',request_header_erase=dict(type='str',)),
        rd_port=dict(type='int',),
        host_switching=dict(type='list',host_switching_type=dict(type='str',choices=['contains','ends-with','equals','starts-with','regex-match','host-hits-enable']),host_service_group=dict(type='str',),host_match_string=dict(type='str',)),
        url_hash_last=dict(type='int',),
        client_ip_hdr_replace=dict(type='bool',),
        use_server_status=dict(type='bool',),
        req_hdr_wait_time_val=dict(type='int',),
        response_header_insert_list=dict(type='list',response_header_insert_type=dict(type='str',choices=['insert-if-not-exist','insert-always']),response_header_insert=dict(type='str',)),
        persist_on_401=dict(type='bool',),
        redirect=dict(type='bool',),
        insert_client_port=dict(type='bool',),
        retry_on_5xx_per_req_val=dict(type='int',),
        url_hash_offset=dict(type='int',),
        rd_simple_loc=dict(type='str',),
        log_retry=dict(type='bool',),
        non_http_bypass=dict(type='bool',),
        retry_on_5xx_per_req=dict(type='bool',),
        insert_client_ip=dict(type='bool',),
        template=dict(type='dict',logging=dict(type='str',)),
        url_switching=dict(type='list',url_service_group=dict(type='str',),url_match_string=dict(type='str',),url_switching_type=dict(type='str',choices=['contains','ends-with','equals','starts-with','regex-match','url-case-insensitive','url-hits-enable'])),
        insert_client_port_header_name=dict(type='str',),
        strict_transaction_switch=dict(type='bool',),
        response_content_replace_list=dict(type='list',response_new_string=dict(type='str',),response_content_replace=dict(type='str',)),
        http_100_cont_wait_for_req_complete=dict(type='bool',),
        max_concurrent_streams=dict(type='int',),
        request_header_insert_list=dict(type='list',request_header_insert=dict(type='str',),request_header_insert_type=dict(type='str',choices=['insert-if-not-exist','insert-always'])),
        compression_minimum_content_length=dict(type='int',),
        compression_level=dict(type='int',),
        request_line_case_insensitive=dict(type='bool',),
        url_hash_persist=dict(type='bool',),
        response_header_erase_list=dict(type='list',response_header_erase=dict(type='str',)),
        uuid=dict(type='str',),
        bypass_sg=dict(type='str',),
        name=dict(type='str',required=True,),
        retry_on_5xx_val=dict(type='int',),
        url_hash_first=dict(type='int',),
        compression_keep_accept_encoding_enable=dict(type='bool',),
        user_tag=dict(type='str',),
        compression_content_type=dict(type='list',content_type=dict(type='str',)),
        client_port_hdr_replace=dict(type='bool',),
        insert_client_ip_header_name=dict(type='str',),
        rd_secure=dict(type='bool',),
        retry_on_5xx=dict(type='bool',),
        cookie_format=dict(type='str',choices=['rfc6265']),
        term_11client_hdr_conn_close=dict(type='bool',),
        compression_exclude_content_type=dict(type='list',exclude_content_type=dict(type='str',)),
        rd_resp_code=dict(type='str',choices=['301','302','303','307'])
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
    present_keys = sorted([x for x in requires_one_of if x in params])
    
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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("http", module)
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

def update(module, result, existing_config):
    payload = build_json("http", module)
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
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result, existing_config)

def absent(module, result):
    return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("http", module)
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
        message=""
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]
    
    partition = module.params["partition"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    if partition:
        module.client.activate_partition(partition)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
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