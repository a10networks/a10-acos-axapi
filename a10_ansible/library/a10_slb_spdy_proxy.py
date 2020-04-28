#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_slb_spdy_proxy
description:
    - Configure SPDY Proxy
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
          - noop
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
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            l4_cpu_list:
                description:
                - "Field l4_cpu_list"
            cpu_count:
                description:
                - "Field cpu_count"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'curr_proxy'= Curr Proxy Conns; 'total_proxy'= Total Proxy Conns; 'curr_http_proxy'= Curr HTTP Proxy Conns; 'total_http_proxy'= Total HTTP Proxy Conns; 'total_v2_proxy'= Version 2 Streams; 'total_v3_proxy'= Version 3 Streams; 'curr_stream'= Curr Streams; 'total_stream'= Total Streams; 'total_stream_succ'= Streams(succ); 'client_rst'= client_rst; 'server_rst'= Server RST sent; 'client_goaway'= client_goaway; 'server_goaway'= Server GOAWAY sent; 'tcp_err'= TCP sock error; 'inflate_ctx'= Inflate context; 'deflate_ctx'= Deflate context; 'ping_sent'= PING sent; 'stream_not_found'= STREAM not found; 'client_fin'= Client FIN; 'server_fin'= Server FIN; 'stream_close'= Stream close; 'stream_err'= Stream err; 'session_err'= Session err; 'control_frame'= Control frame received; 'syn_frame'= SYN stream frame received; 'syn_reply_frame'= SYN reply frame received; 'headers_frame'= Headers frame received; 'settings_frame'= Setting frame received; 'window_frame'= Window update frame received; 'ping_frame'= Ping frame received; 'data_frame'= Data frame received; 'data_no_stream'= Data no stream found; 'data_no_stream_no_goaway'= Data no stream and no goaway; 'data_no_stream_goaway_close'= Data no stream and no goaway and close session; 'est_cb_no_tuple'= Est callback no tuple; 'data_cb_no_tuple'= Data callback no tuple; 'ctx_alloc_fail'= Context alloc fail; 'fin_close_session'= FIN close session; 'server_rst_close_stream'= Server RST close stream; 'stream_found'= Stream found; 'close_stream_session_not_found'= Close stream session not found; 'close_stream_stream_not_found'= Close stream stream not found; 'close_stream_already_closed'= Closing closed stream; 'close_stream_session_close'= Stream close session close; 'close_session_already_closed'= Closing closed session; 'max_concurrent_stream_limit'= Max concurrent stream limit; 'stream_alloc_fail'= Stream alloc fail; 'http_conn_alloc_fail'= HTTP connection allocation fail; 'request_header_alloc_fail'= Request/Header allocation fail; 'name_value_total_len_ex'= Name value total length exceeded; 'name_value_zero_len'= Name value zero name length; 'name_value_invalid_http_ver'= Name value invalid http version; 'name_value_connection'= Name value connection; 'name_value_keepalive'= Name value keep alive; 'name_value_proxy_conn'= Name value proxy-connection; 'name_value_trasnfer_encod'= Name value transfer encoding; 'name_value_no_must_have'= Name value no must have; 'decompress_fail'= Decompress fail; 'syn_after_goaway'= SYN after goaway; 'stream_lt_prev'= Stream id less than previous; 'syn_stream_exist_or_even'= Stream already exists; 'syn_unidir'= Unidirectional SYN; 'syn_reply_alr_rcvd'= SYN reply already received; 'client_rst_nostream'= Close RST stream not found; 'window_no_stream'= Window update no stream found; 'invalid_window_size'= Invalid window size; 'unknown_control_frame'= Unknown control frame; 'data_on_closed_stream'= Data on closed stream; 'invalid_frame_size'= Invalid frame size; 'invalid_version'= Invalid version; 'header_after_session_close'= Header after session close; 'compress_ctx_alloc_fail'= Compression context allocation fail; 'header_compress_fail'= Header compress fail; 'http_data_session_close'= HTTP data session close; 'http_data_stream_not_found'= HTTP data stream not found; 'close_stream_not_http_proxy'= Close Stream not http-proxy; 'session_needs_requeue'= Session needs requeue; 'new_stream_session_del'= New Stream after Session delete; 'fin_stream_closed'= HTTP FIN stream already closed; 'http_close_stream_closed'= HTTP close stream already closed; 'http_err_stream_closed'= HTTP error stream already closed; 'http_hdr_stream_close'= HTTP header stream already closed; 'http_data_stream_close'= HTTP data stream already closed; 'session_close'= Session close; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            name_value_total_len_ex:
                description:
                - "Name value total length exceeded"
            data_cb_no_tuple:
                description:
                - "Data callback no tuple"
            server_rst:
                description:
                - "Server RST sent"
            server_fin:
                description:
                - "Server FIN"
            total_proxy:
                description:
                - "Total Proxy Conns"
            curr_http_proxy:
                description:
                - "Curr HTTP Proxy Conns"
            total_v2_proxy:
                description:
                - "Version 2 Streams"
            window_frame:
                description:
                - "Window update frame received"
            close_stream_stream_not_found:
                description:
                - "Close stream stream not found"
            client_rst:
                description:
                - "Field client_rst"
            est_cb_no_tuple:
                description:
                - "Est callback no tuple"
            stream_alloc_fail:
                description:
                - "Stream alloc fail"
            max_concurrent_stream_limit:
                description:
                - "Max concurrent stream limit"
            deflate_ctx:
                description:
                - "Deflate context"
            client_goaway:
                description:
                - "Field client_goaway"
            total_v3_proxy:
                description:
                - "Version 3 Streams"
            compress_ctx_alloc_fail:
                description:
                - "Compression context allocation fail"
            server_goaway:
                description:
                - "Server GOAWAY sent"
            syn_after_goaway:
                description:
                - "SYN after goaway"
            invalid_version:
                description:
                - "Invalid version"
            total_http_proxy:
                description:
                - "Total HTTP Proxy Conns"
            close_stream_session_close:
                description:
                - "Stream close session close"
            decompress_fail:
                description:
                - "Decompress fail"
            ping_frame:
                description:
                - "Ping frame received"
            ping_sent:
                description:
                - "PING sent"
            invalid_frame_size:
                description:
                - "Invalid frame size"
            http_err_stream_closed:
                description:
                - "HTTP error stream already closed"
            header_after_session_close:
                description:
                - "Header after session close"
            http_data_stream_close:
                description:
                - "HTTP data stream already closed"
            control_frame:
                description:
                - "Control frame received"
            stream_not_found:
                description:
                - "STREAM not found"
            fin_stream_closed:
                description:
                - "HTTP FIN stream already closed"
            stream_close:
                description:
                - "Stream close"
            total_stream:
                description:
                - "Total Streams"
            inflate_ctx:
                description:
                - "Inflate context"
            session_needs_requeue:
                description:
                - "Session needs requeue"
            data_no_stream:
                description:
                - "Data no stream found"
            data_no_stream_no_goaway:
                description:
                - "Data no stream and no goaway"
            ctx_alloc_fail:
                description:
                - "Context alloc fail"
            close_stream_session_not_found:
                description:
                - "Close stream session not found"
            stream_found:
                description:
                - "Stream found"
            syn_stream_exist_or_even:
                description:
                - "Stream already exists"
            close_session_already_closed:
                description:
                - "Closing closed session"
            headers_frame:
                description:
                - "Headers frame received"
            syn_reply_alr_rcvd:
                description:
                - "SYN reply already received"
            invalid_window_size:
                description:
                - "Invalid window size"
            header_compress_fail:
                description:
                - "Header compress fail"
            tcp_err:
                description:
                - "TCP sock error"
            curr_proxy:
                description:
                - "Curr Proxy Conns"
            name_value_keepalive:
                description:
                - "Name value keep alive"
            settings_frame:
                description:
                - "Setting frame received"
            syn_frame:
                description:
                - "SYN stream frame received"
            window_no_stream:
                description:
                - "Window update no stream found"
            data_frame:
                description:
                - "Data frame received"
            server_rst_close_stream:
                description:
                - "Server RST close stream"
            new_stream_session_del:
                description:
                - "New Stream after Session delete"
            request_header_alloc_fail:
                description:
                - "Request/Header allocation fail"
            unknown_control_frame:
                description:
                - "Unknown control frame"
            http_data_stream_not_found:
                description:
                - "HTTP data stream not found"
            http_close_stream_closed:
                description:
                - "HTTP close stream already closed"
            curr_stream:
                description:
                - "Curr Streams"
            close_stream_already_closed:
                description:
                - "Closing closed stream"
            name_value_zero_len:
                description:
                - "Name value zero name length"
            data_on_closed_stream:
                description:
                - "Data on closed stream"
            name_value_trasnfer_encod:
                description:
                - "Name value transfer encoding"
            http_conn_alloc_fail:
                description:
                - "HTTP connection allocation fail"
            fin_close_session:
                description:
                - "FIN close session"
            name_value_no_must_have:
                description:
                - "Name value no must have"
            name_value_proxy_conn:
                description:
                - "Name value proxy-connection"
            syn_reply_frame:
                description:
                - "SYN reply frame received"
            name_value_invalid_http_ver:
                description:
                - "Name value invalid http version"
            session_err:
                description:
                - "Session err"
            client_rst_nostream:
                description:
                - "Close RST stream not found"
            http_hdr_stream_close:
                description:
                - "HTTP header stream already closed"
            name_value_connection:
                description:
                - "Name value connection"
            client_fin:
                description:
                - "Client FIN"
            data_no_stream_goaway_close:
                description:
                - "Data no stream and no goaway and close session"
            total_stream_succ:
                description:
                - "Streams(succ)"
            syn_unidir:
                description:
                - "Unidirectional SYN"
            http_data_session_close:
                description:
                - "HTTP data session close"
            stream_lt_prev:
                description:
                - "Stream id less than previous"
            close_stream_not_http_proxy:
                description:
                - "Close Stream not http-proxy"
            stream_err:
                description:
                - "Stream err"
            session_close:
                description:
                - "Session close"
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
AVAILABLE_PROPERTIES = ["oper","sampling_enable","stats","uuid",]

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
        state=dict(type='str', default="present", choices=['present', 'absent', 'noop']),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict',l4_cpu_list=dict(type='list',name_value_total_len_ex=dict(type='int',),data_cb_no_tuple=dict(type='int',),server_rst=dict(type='int',),server_fin=dict(type='int',),total_proxy=dict(type='int',),curr_http_proxy=dict(type='int',),total_v2_proxy=dict(type='int',),window_frame=dict(type='int',),close_stream_stream_not_found=dict(type='int',),client_rst=dict(type='int',),est_cb_no_tuple=dict(type='int',),stream_alloc_fail=dict(type='int',),max_concurrent_stream_limit=dict(type='int',),deflate_ctx=dict(type='int',),client_goaway=dict(type='int',),total_v3_proxy=dict(type='int',),compress_ctx_alloc_fail=dict(type='int',),server_goaway=dict(type='int',),syn_after_goaway=dict(type='int',),invalid_version=dict(type='int',),total_http_proxy=dict(type='int',),close_stream_session_close=dict(type='int',),decompress_fail=dict(type='int',),ping_frame=dict(type='int',),ping_sent=dict(type='int',),invalid_frame_size=dict(type='int',),http_err_stream_closed=dict(type='int',),header_after_session_close=dict(type='int',),http_data_stream_close=dict(type='int',),control_frame=dict(type='int',),stream_not_found=dict(type='int',),fin_stream_closed=dict(type='int',),stream_close=dict(type='int',),total_stream=dict(type='int',),inflate_ctx=dict(type='int',),session_needs_requeue=dict(type='int',),data_no_stream=dict(type='int',),data_no_stream_no_goaway=dict(type='int',),ctx_alloc_fail=dict(type='int',),close_stream_session_not_found=dict(type='int',),stream_found=dict(type='int',),syn_stream_exist_or_even=dict(type='int',),close_session_already_closed=dict(type='int',),headers_frame=dict(type='int',),syn_reply_alr_rcvd=dict(type='int',),invalid_window_size=dict(type='int',),header_compress_fail=dict(type='int',),tcp_err=dict(type='int',),curr_proxy=dict(type='int',),name_value_keepalive=dict(type='int',),settings_frame=dict(type='int',),syn_frame=dict(type='int',),window_no_stream=dict(type='int',),data_frame=dict(type='int',),server_rst_close_stream=dict(type='int',),new_stream_session_del=dict(type='int',),request_header_alloc_fail=dict(type='int',),unknown_control_frame=dict(type='int',),http_data_stream_not_found=dict(type='int',),http_close_stream_closed=dict(type='int',),curr_stream=dict(type='int',),close_stream_already_closed=dict(type='int',),name_value_zero_len=dict(type='int',),data_on_closed_stream=dict(type='int',),name_value_trasnfer_encod=dict(type='int',),http_conn_alloc_fail=dict(type='int',),fin_close_session=dict(type='int',),name_value_no_must_have=dict(type='int',),name_value_proxy_conn=dict(type='int',),syn_reply_frame=dict(type='int',),name_value_invalid_http_ver=dict(type='int',),session_err=dict(type='int',),client_rst_nostream=dict(type='int',),http_hdr_stream_close=dict(type='int',),name_value_connection=dict(type='int',),client_fin=dict(type='int',),data_no_stream_goaway_close=dict(type='int',),total_stream_succ=dict(type='int',),syn_unidir=dict(type='int',),http_data_session_close=dict(type='int',),stream_lt_prev=dict(type='int',),close_stream_not_http_proxy=dict(type='int',),stream_err=dict(type='int',),session_close=dict(type='int',)),cpu_count=dict(type='int',)),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','curr_proxy','total_proxy','curr_http_proxy','total_http_proxy','total_v2_proxy','total_v3_proxy','curr_stream','total_stream','total_stream_succ','client_rst','server_rst','client_goaway','server_goaway','tcp_err','inflate_ctx','deflate_ctx','ping_sent','stream_not_found','client_fin','server_fin','stream_close','stream_err','session_err','control_frame','syn_frame','syn_reply_frame','headers_frame','settings_frame','window_frame','ping_frame','data_frame','data_no_stream','data_no_stream_no_goaway','data_no_stream_goaway_close','est_cb_no_tuple','data_cb_no_tuple','ctx_alloc_fail','fin_close_session','server_rst_close_stream','stream_found','close_stream_session_not_found','close_stream_stream_not_found','close_stream_already_closed','close_stream_session_close','close_session_already_closed','max_concurrent_stream_limit','stream_alloc_fail','http_conn_alloc_fail','request_header_alloc_fail','name_value_total_len_ex','name_value_zero_len','name_value_invalid_http_ver','name_value_connection','name_value_keepalive','name_value_proxy_conn','name_value_trasnfer_encod','name_value_no_must_have','decompress_fail','syn_after_goaway','stream_lt_prev','syn_stream_exist_or_even','syn_unidir','syn_reply_alr_rcvd','client_rst_nostream','window_no_stream','invalid_window_size','unknown_control_frame','data_on_closed_stream','invalid_frame_size','invalid_version','header_after_session_close','compress_ctx_alloc_fail','header_compress_fail','http_data_session_close','http_data_stream_not_found','close_stream_not_http_proxy','session_needs_requeue','new_stream_session_del','fin_stream_closed','http_close_stream_closed','http_err_stream_closed','http_hdr_stream_close','http_data_stream_close','session_close'])),
        stats=dict(type='dict',name_value_total_len_ex=dict(type='str',),data_cb_no_tuple=dict(type='str',),server_rst=dict(type='str',),server_fin=dict(type='str',),total_proxy=dict(type='str',),curr_http_proxy=dict(type='str',),total_v2_proxy=dict(type='str',),window_frame=dict(type='str',),close_stream_stream_not_found=dict(type='str',),client_rst=dict(type='str',),est_cb_no_tuple=dict(type='str',),stream_alloc_fail=dict(type='str',),max_concurrent_stream_limit=dict(type='str',),deflate_ctx=dict(type='str',),client_goaway=dict(type='str',),total_v3_proxy=dict(type='str',),compress_ctx_alloc_fail=dict(type='str',),server_goaway=dict(type='str',),syn_after_goaway=dict(type='str',),invalid_version=dict(type='str',),total_http_proxy=dict(type='str',),close_stream_session_close=dict(type='str',),decompress_fail=dict(type='str',),ping_frame=dict(type='str',),ping_sent=dict(type='str',),invalid_frame_size=dict(type='str',),http_err_stream_closed=dict(type='str',),header_after_session_close=dict(type='str',),http_data_stream_close=dict(type='str',),control_frame=dict(type='str',),stream_not_found=dict(type='str',),fin_stream_closed=dict(type='str',),stream_close=dict(type='str',),total_stream=dict(type='str',),inflate_ctx=dict(type='str',),session_needs_requeue=dict(type='str',),data_no_stream=dict(type='str',),data_no_stream_no_goaway=dict(type='str',),ctx_alloc_fail=dict(type='str',),close_stream_session_not_found=dict(type='str',),stream_found=dict(type='str',),syn_stream_exist_or_even=dict(type='str',),close_session_already_closed=dict(type='str',),headers_frame=dict(type='str',),syn_reply_alr_rcvd=dict(type='str',),invalid_window_size=dict(type='str',),header_compress_fail=dict(type='str',),tcp_err=dict(type='str',),curr_proxy=dict(type='str',),name_value_keepalive=dict(type='str',),settings_frame=dict(type='str',),syn_frame=dict(type='str',),window_no_stream=dict(type='str',),data_frame=dict(type='str',),server_rst_close_stream=dict(type='str',),new_stream_session_del=dict(type='str',),request_header_alloc_fail=dict(type='str',),unknown_control_frame=dict(type='str',),http_data_stream_not_found=dict(type='str',),http_close_stream_closed=dict(type='str',),curr_stream=dict(type='str',),close_stream_already_closed=dict(type='str',),name_value_zero_len=dict(type='str',),data_on_closed_stream=dict(type='str',),name_value_trasnfer_encod=dict(type='str',),http_conn_alloc_fail=dict(type='str',),fin_close_session=dict(type='str',),name_value_no_must_have=dict(type='str',),name_value_proxy_conn=dict(type='str',),syn_reply_frame=dict(type='str',),name_value_invalid_http_ver=dict(type='str',),session_err=dict(type='str',),client_rst_nostream=dict(type='str',),http_hdr_stream_close=dict(type='str',),name_value_connection=dict(type='str',),client_fin=dict(type='str',),data_no_stream_goaway_close=dict(type='str',),total_stream_succ=dict(type='str',),syn_unidir=dict(type='str',),http_data_session_close=dict(type='str',),stream_lt_prev=dict(type='str',),close_stream_not_http_proxy=dict(type='str',),stream_err=dict(type='str',),session_close=dict(type='str',)),
        uuid=dict(type='str',)
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/spdy-proxy"

    f_dict = {}

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

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

def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k,v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v 
        return module.client.get(oper_url(module),
                                 params=query_params)
    return module.client.get(oper_url(module))

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
    url_base = "/axapi/v3/slb/spdy-proxy"

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
        for k, v in payload["spdy-proxy"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["spdy-proxy"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["spdy-proxy"][k] = v
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
    payload = build_json("spdy-proxy", module)
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
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