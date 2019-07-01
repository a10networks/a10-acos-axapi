#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_spdy_proxy
description:
    - Show SPDY Proxy Statistics
short_description: Configures A10 slb.spdy-proxy
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'curr_proxy'= Curr Proxy Conns; 'total_proxy'= Total Proxy Conns; 'curr_http_proxy'= Curr HTTP Proxy Conns; 'total_http_proxy'= Total HTTP Proxy Conns; 'total_v2_proxy'= Version 2 Streams; 'total_v3_proxy'= Version 3 Streams; 'curr_stream'= Curr Streams; 'total_stream'= Total Streams; 'total_stream_succ'= Streams(succ); 'client_rst'= client_rst; 'server_rst'= Server RST sent; 'client_goaway'= client_goaway; 'server_goaway'= Server GOAWAY sent; 'tcp_err'= TCP sock error; 'inflate_ctx'= Inflate context; 'deflate_ctx'= Deflate context; 'ping_sent'= PING sent; 'stream_not_found'= STREAM not found; 'client_fin'= Client FIN; 'server_fin'= Server FIN; 'stream_close'= Stream close; 'stream_err'= Stream err; 'session_err'= Session err; 'control_frame'= Control frame received; 'syn_frame'= SYN stream frame received; 'syn_reply_frame'= SYN reply frame received; 'headers_frame'= Headers frame received; 'settings_frame'= Setting frame received; 'window_frame'= Window update frame received; 'ping_frame'= Ping frame received; 'data_frame'= Data frame received; 'data_no_stream'= Data no stream found; 'data_no_stream_no_goaway'= Data no stream and no goaway; 'data_no_stream_goaway_close'= Data no stream and no goaway and close session; 'est_cb_no_tuple'= Est callback no tuple; 'data_cb_no_tuple'= Data callback no tuple; 'ctx_alloc_fail'= Context alloc fail; 'fin_close_session'= FIN close session; 'server_rst_close_stream'= Server RST close stream; 'stream_found'= Stream found; 'close_stream_session_not_found'= Close stream session not found; 'close_stream_stream_not_found'= Close stream stream not found; 'close_stream_already_closed'= Closing closed stream; 'close_stream_session_close'= Stream close session close; 'close_session_already_closed'= Closing closed session; 'max_concurrent_stream_limit'= Max concurrent stream limit; 'stream_alloc_fail'= Stream alloc fail; 'http_conn_alloc_fail'= HTTP connection allocation fail; 'request_header_alloc_fail'= Request/Header allocation fail; 'name_value_total_len_ex'= Name value total length exceeded; 'name_value_zero_len'= Name value zero name length; 'name_value_invalid_http_ver'= Name value invalid http version; 'name_value_connection'= Name value connection; 'name_value_keepalive'= Name value keep alive; 'name_value_proxy_conn'= Name value proxy-connection; 'name_value_trasnfer_encod'= Name value transfer encoding; 'name_value_no_must_have'= Name value no must have; 'decompress_fail'= Decompress fail; 'syn_after_goaway'= SYN after goaway; 'stream_lt_prev'= Stream id less than previous; 'syn_stream_exist_or_even'= Stream already exists; 'syn_unidir'= Unidirectional SYN; 'syn_reply_alr_rcvd'= SYN reply already received; 'client_rst_nostream'= Close RST stream not found; 'window_no_stream'= Window update no stream found; 'invalid_window_size'= Invalid window size; 'unknown_control_frame'= Unknown control frame; 'data_on_closed_stream'= Data on closed stream; 'invalid_frame_size'= Invalid frame size; 'invalid_version'= Invalid version; 'header_after_session_close'= Header after session close; 'compress_ctx_alloc_fail'= Compression context allocation fail; 'header_compress_fail'= Header compress fail; 'http_data_session_close'= HTTP data session close; 'http_data_stream_not_found'= HTTP data stream not found; 'close_stream_not_http_proxy'= Close Stream not http-proxy; 'session_needs_requeue'= Session needs requeue; 'new_stream_session_del'= New Stream after Session delete; 'fin_stream_closed'= HTTP FIN stream already closed; 'http_close_stream_closed'= HTTP close stream already closed; 'http_err_stream_closed'= HTTP error stream already closed; 'http_hdr_stream_close'= HTTP header stream already closed; 'http_data_stream_close'= HTTP data stream already closed; 'session_close'= Session close; "
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
        partition=dict(type='str', required=False),
        get_type=dict(type='str', choices=["single", "list"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','curr_proxy','total_proxy','curr_http_proxy','total_http_proxy','total_v2_proxy','total_v3_proxy','curr_stream','total_stream','total_stream_succ','client_rst','server_rst','client_goaway','server_goaway','tcp_err','inflate_ctx','deflate_ctx','ping_sent','stream_not_found','client_fin','server_fin','stream_close','stream_err','session_err','control_frame','syn_frame','syn_reply_frame','headers_frame','settings_frame','window_frame','ping_frame','data_frame','data_no_stream','data_no_stream_no_goaway','data_no_stream_goaway_close','est_cb_no_tuple','data_cb_no_tuple','ctx_alloc_fail','fin_close_session','server_rst_close_stream','stream_found','close_stream_session_not_found','close_stream_stream_not_found','close_stream_already_closed','close_stream_session_close','close_session_already_closed','max_concurrent_stream_limit','stream_alloc_fail','http_conn_alloc_fail','request_header_alloc_fail','name_value_total_len_ex','name_value_zero_len','name_value_invalid_http_ver','name_value_connection','name_value_keepalive','name_value_proxy_conn','name_value_trasnfer_encod','name_value_no_must_have','decompress_fail','syn_after_goaway','stream_lt_prev','syn_stream_exist_or_even','syn_unidir','syn_reply_alr_rcvd','client_rst_nostream','window_no_stream','invalid_window_size','unknown_control_frame','data_on_closed_stream','invalid_frame_size','invalid_version','header_after_session_close','compress_ctx_alloc_fail','header_compress_fail','http_data_session_close','http_data_stream_not_found','close_stream_not_http_proxy','session_needs_requeue','new_stream_session_del','fin_stream_closed','http_close_stream_closed','http_err_stream_closed','http_hdr_stream_close','http_data_stream_close','session_close'])),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/spdy-proxy"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/spdy-proxy"

    f_dict = {}

    return url_base.format(**f_dict)

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

def get_list(module):
    return module.client.get(list_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("spdy-proxy", module)
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
    payload = build_json("spdy-proxy", module)
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
    payload = build_json("spdy-proxy", module)
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
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
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