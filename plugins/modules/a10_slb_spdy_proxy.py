#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_spdy_proxy
description:
    - Configure SPDY Proxy
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
                - "'all'= all; 'curr_proxy'= Curr Proxy Conns; 'total_proxy'= Total Proxy Conns;
          'curr_http_proxy'= Curr HTTP Proxy Conns; 'total_http_proxy'= Total HTTP Proxy
          Conns; 'total_v2_proxy'= Version 2 Streams; 'total_v3_proxy'= Version 3
          Streams; 'curr_stream'= Curr Streams; 'total_stream'= Total Streams;
          'total_stream_succ'= Streams(succ); 'client_rst'= client_rst; 'server_rst'=
          Server RST sent; 'client_goaway'= client_goaway; 'server_goaway'= Server GOAWAY
          sent; 'tcp_err'= TCP sock error; 'inflate_ctx'= Inflate context; 'deflate_ctx'=
          Deflate context; 'ping_sent'= PING sent; 'stream_not_found'= STREAM not found;
          'client_fin'= Client FIN; 'server_fin'= Server FIN; 'stream_close'= Stream
          close; 'stream_err'= Stream err; 'session_err'= Session err; 'control_frame'=
          Control frame received; 'syn_frame'= SYN stream frame received;
          'syn_reply_frame'= SYN reply frame received; 'headers_frame'= Headers frame
          received; 'settings_frame'= Setting frame received; 'window_frame'= Window
          update frame received; 'ping_frame'= Ping frame received; 'data_frame'= Data
          frame received; 'data_no_stream'= Data no stream found;
          'data_no_stream_no_goaway'= Data no stream and no goaway;
          'data_no_stream_goaway_close'= Data no stream and no goaway and close session;
          'est_cb_no_tuple'= Est callback no tuple; 'data_cb_no_tuple'= Data callback no
          tuple; 'ctx_alloc_fail'= Context alloc fail; 'fin_close_session'= FIN close
          session; 'server_rst_close_stream'= Server RST close stream; 'stream_found'=
          Stream found; 'close_stream_session_not_found'= Close stream session not found;
          'close_stream_stream_not_found'= Close stream stream not found;
          'close_stream_already_closed'= Closing closed stream;
          'close_stream_session_close'= Stream close session close;
          'close_session_already_closed'= Closing closed session;
          'max_concurrent_stream_limit'= Max concurrent stream limit;
          'stream_alloc_fail'= Stream alloc fail; 'http_conn_alloc_fail'= HTTP connection
          allocation fail; 'request_header_alloc_fail'= Request/Header allocation fail;
          'name_value_total_len_ex'= Name value total length exceeded;
          'name_value_zero_len'= Name value zero name length;
          'name_value_invalid_http_ver'= Name value invalid http version;
          'name_value_connection'= Name value connection; 'name_value_keepalive'= Name
          value keep alive; 'name_value_proxy_conn'= Name value proxy-connection;
          'name_value_trasnfer_encod'= Name value transfer encoding;
          'name_value_no_must_have'= Name value no must have; 'decompress_fail'=
          Decompress fail; 'syn_after_goaway'= SYN after goaway; 'stream_lt_prev'= Stream
          id less than previous; 'syn_stream_exist_or_even'= Stream already exists;
          'syn_unidir'= Unidirectional SYN; 'syn_reply_alr_rcvd'= SYN reply already
          received; 'client_rst_nostream'= Close RST stream not found;
          'window_no_stream'= Window update no stream found; 'invalid_window_size'=
          Invalid window size; 'unknown_control_frame'= Unknown control frame;
          'data_on_closed_stream'= Data on closed stream; 'invalid_frame_size'= Invalid
          frame size; 'invalid_version'= Invalid version; 'header_after_session_close'=
          Header after session close; 'compress_ctx_alloc_fail'= Compression context
          allocation fail; 'header_compress_fail'= Header compress fail;
          'http_data_session_close'= HTTP data session close;
          'http_data_stream_not_found'= HTTP data stream not found;
          'close_stream_not_http_proxy'= Close Stream not http-proxy;
          'session_needs_requeue'= Session needs requeue; 'new_stream_session_del'= New
          Stream after Session delete; 'fin_stream_closed'= HTTP FIN stream already
          closed; 'http_close_stream_closed'= HTTP close stream already closed;
          'http_err_stream_closed'= HTTP error stream already closed;
          'http_hdr_stream_close'= HTTP header stream already closed;
          'http_data_stream_close'= HTTP data stream already closed; 'session_close'=
          Session close;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            l4_cpu_list:
                description:
                - "Field l4_cpu_list"
                type: list
            cpu_count:
                description:
                - "Field cpu_count"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            curr_proxy:
                description:
                - "Curr Proxy Conns"
                type: str
            total_proxy:
                description:
                - "Total Proxy Conns"
                type: str
            curr_http_proxy:
                description:
                - "Curr HTTP Proxy Conns"
                type: str
            total_http_proxy:
                description:
                - "Total HTTP Proxy Conns"
                type: str
            total_v2_proxy:
                description:
                - "Version 2 Streams"
                type: str
            total_v3_proxy:
                description:
                - "Version 3 Streams"
                type: str
            curr_stream:
                description:
                - "Curr Streams"
                type: str
            total_stream:
                description:
                - "Total Streams"
                type: str
            total_stream_succ:
                description:
                - "Streams(succ)"
                type: str
            client_rst:
                description:
                - "Field client_rst"
                type: str
            server_rst:
                description:
                - "Server RST sent"
                type: str
            client_goaway:
                description:
                - "Field client_goaway"
                type: str
            server_goaway:
                description:
                - "Server GOAWAY sent"
                type: str
            tcp_err:
                description:
                - "TCP sock error"
                type: str
            inflate_ctx:
                description:
                - "Inflate context"
                type: str
            deflate_ctx:
                description:
                - "Deflate context"
                type: str
            ping_sent:
                description:
                - "PING sent"
                type: str
            stream_not_found:
                description:
                - "STREAM not found"
                type: str
            client_fin:
                description:
                - "Client FIN"
                type: str
            server_fin:
                description:
                - "Server FIN"
                type: str
            stream_close:
                description:
                - "Stream close"
                type: str
            stream_err:
                description:
                - "Stream err"
                type: str
            session_err:
                description:
                - "Session err"
                type: str
            control_frame:
                description:
                - "Control frame received"
                type: str
            syn_frame:
                description:
                - "SYN stream frame received"
                type: str
            syn_reply_frame:
                description:
                - "SYN reply frame received"
                type: str
            headers_frame:
                description:
                - "Headers frame received"
                type: str
            settings_frame:
                description:
                - "Setting frame received"
                type: str
            window_frame:
                description:
                - "Window update frame received"
                type: str
            ping_frame:
                description:
                - "Ping frame received"
                type: str
            data_frame:
                description:
                - "Data frame received"
                type: str
            data_no_stream:
                description:
                - "Data no stream found"
                type: str
            data_no_stream_no_goaway:
                description:
                - "Data no stream and no goaway"
                type: str
            data_no_stream_goaway_close:
                description:
                - "Data no stream and no goaway and close session"
                type: str
            est_cb_no_tuple:
                description:
                - "Est callback no tuple"
                type: str
            data_cb_no_tuple:
                description:
                - "Data callback no tuple"
                type: str
            ctx_alloc_fail:
                description:
                - "Context alloc fail"
                type: str
            fin_close_session:
                description:
                - "FIN close session"
                type: str
            server_rst_close_stream:
                description:
                - "Server RST close stream"
                type: str
            stream_found:
                description:
                - "Stream found"
                type: str
            close_stream_session_not_found:
                description:
                - "Close stream session not found"
                type: str
            close_stream_stream_not_found:
                description:
                - "Close stream stream not found"
                type: str
            close_stream_already_closed:
                description:
                - "Closing closed stream"
                type: str
            close_stream_session_close:
                description:
                - "Stream close session close"
                type: str
            close_session_already_closed:
                description:
                - "Closing closed session"
                type: str
            max_concurrent_stream_limit:
                description:
                - "Max concurrent stream limit"
                type: str
            stream_alloc_fail:
                description:
                - "Stream alloc fail"
                type: str
            http_conn_alloc_fail:
                description:
                - "HTTP connection allocation fail"
                type: str
            request_header_alloc_fail:
                description:
                - "Request/Header allocation fail"
                type: str
            name_value_total_len_ex:
                description:
                - "Name value total length exceeded"
                type: str
            name_value_zero_len:
                description:
                - "Name value zero name length"
                type: str
            name_value_invalid_http_ver:
                description:
                - "Name value invalid http version"
                type: str
            name_value_connection:
                description:
                - "Name value connection"
                type: str
            name_value_keepalive:
                description:
                - "Name value keep alive"
                type: str
            name_value_proxy_conn:
                description:
                - "Name value proxy-connection"
                type: str
            name_value_trasnfer_encod:
                description:
                - "Name value transfer encoding"
                type: str
            name_value_no_must_have:
                description:
                - "Name value no must have"
                type: str
            decompress_fail:
                description:
                - "Decompress fail"
                type: str
            syn_after_goaway:
                description:
                - "SYN after goaway"
                type: str
            stream_lt_prev:
                description:
                - "Stream id less than previous"
                type: str
            syn_stream_exist_or_even:
                description:
                - "Stream already exists"
                type: str
            syn_unidir:
                description:
                - "Unidirectional SYN"
                type: str
            syn_reply_alr_rcvd:
                description:
                - "SYN reply already received"
                type: str
            client_rst_nostream:
                description:
                - "Close RST stream not found"
                type: str
            window_no_stream:
                description:
                - "Window update no stream found"
                type: str
            invalid_window_size:
                description:
                - "Invalid window size"
                type: str
            unknown_control_frame:
                description:
                - "Unknown control frame"
                type: str
            data_on_closed_stream:
                description:
                - "Data on closed stream"
                type: str
            invalid_frame_size:
                description:
                - "Invalid frame size"
                type: str
            invalid_version:
                description:
                - "Invalid version"
                type: str
            header_after_session_close:
                description:
                - "Header after session close"
                type: str
            compress_ctx_alloc_fail:
                description:
                - "Compression context allocation fail"
                type: str
            header_compress_fail:
                description:
                - "Header compress fail"
                type: str
            http_data_session_close:
                description:
                - "HTTP data session close"
                type: str
            http_data_stream_not_found:
                description:
                - "HTTP data stream not found"
                type: str
            close_stream_not_http_proxy:
                description:
                - "Close Stream not http-proxy"
                type: str
            session_needs_requeue:
                description:
                - "Session needs requeue"
                type: str
            new_stream_session_del:
                description:
                - "New Stream after Session delete"
                type: str
            fin_stream_closed:
                description:
                - "HTTP FIN stream already closed"
                type: str
            http_close_stream_closed:
                description:
                - "HTTP close stream already closed"
                type: str
            http_err_stream_closed:
                description:
                - "HTTP error stream already closed"
                type: str
            http_hdr_stream_close:
                description:
                - "HTTP header stream already closed"
                type: str
            http_data_stream_close:
                description:
                - "HTTP data stream already closed"
                type: str
            session_close:
                description:
                - "Session close"
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
AVAILABLE_PROPERTIES = ["oper", "sampling_enable", "stats", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False,
                           ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False,
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
                    'all', 'curr_proxy', 'total_proxy', 'curr_http_proxy', 'total_http_proxy', 'total_v2_proxy', 'total_v3_proxy', 'curr_stream', 'total_stream', 'total_stream_succ', 'client_rst', 'server_rst', 'client_goaway', 'server_goaway', 'tcp_err', 'inflate_ctx', 'deflate_ctx', 'ping_sent',
                    'stream_not_found', 'client_fin', 'server_fin', 'stream_close', 'stream_err', 'session_err', 'control_frame', 'syn_frame', 'syn_reply_frame', 'headers_frame', 'settings_frame', 'window_frame', 'ping_frame', 'data_frame', 'data_no_stream', 'data_no_stream_no_goaway',
                    'data_no_stream_goaway_close', 'est_cb_no_tuple', 'data_cb_no_tuple', 'ctx_alloc_fail', 'fin_close_session', 'server_rst_close_stream', 'stream_found', 'close_stream_session_not_found', 'close_stream_stream_not_found', 'close_stream_already_closed', 'close_stream_session_close',
                    'close_session_already_closed', 'max_concurrent_stream_limit', 'stream_alloc_fail', 'http_conn_alloc_fail', 'request_header_alloc_fail', 'name_value_total_len_ex', 'name_value_zero_len', 'name_value_invalid_http_ver', 'name_value_connection', 'name_value_keepalive',
                    'name_value_proxy_conn', 'name_value_trasnfer_encod', 'name_value_no_must_have', 'decompress_fail', 'syn_after_goaway', 'stream_lt_prev', 'syn_stream_exist_or_even', 'syn_unidir', 'syn_reply_alr_rcvd', 'client_rst_nostream', 'window_no_stream', 'invalid_window_size',
                    'unknown_control_frame', 'data_on_closed_stream', 'invalid_frame_size', 'invalid_version', 'header_after_session_close', 'compress_ctx_alloc_fail', 'header_compress_fail', 'http_data_session_close', 'http_data_stream_not_found', 'close_stream_not_http_proxy',
                    'session_needs_requeue', 'new_stream_session_del', 'fin_stream_closed', 'http_close_stream_closed', 'http_err_stream_closed', 'http_hdr_stream_close', 'http_data_stream_close', 'session_close'
                    ]
                }
            },
        'oper': {
            'type': 'dict',
            'l4_cpu_list': {
                'type': 'list',
                'curr_proxy': {
                    'type': 'int',
                    },
                'total_proxy': {
                    'type': 'int',
                    },
                'curr_http_proxy': {
                    'type': 'int',
                    },
                'total_http_proxy': {
                    'type': 'int',
                    },
                'total_v2_proxy': {
                    'type': 'int',
                    },
                'total_v3_proxy': {
                    'type': 'int',
                    },
                'curr_stream': {
                    'type': 'int',
                    },
                'total_stream': {
                    'type': 'int',
                    },
                'total_stream_succ': {
                    'type': 'int',
                    },
                'client_rst': {
                    'type': 'int',
                    },
                'server_rst': {
                    'type': 'int',
                    },
                'client_goaway': {
                    'type': 'int',
                    },
                'server_goaway': {
                    'type': 'int',
                    },
                'tcp_err': {
                    'type': 'int',
                    },
                'inflate_ctx': {
                    'type': 'int',
                    },
                'deflate_ctx': {
                    'type': 'int',
                    },
                'ping_sent': {
                    'type': 'int',
                    },
                'stream_not_found': {
                    'type': 'int',
                    },
                'client_fin': {
                    'type': 'int',
                    },
                'server_fin': {
                    'type': 'int',
                    },
                'stream_close': {
                    'type': 'int',
                    },
                'stream_err': {
                    'type': 'int',
                    },
                'session_err': {
                    'type': 'int',
                    },
                'control_frame': {
                    'type': 'int',
                    },
                'syn_frame': {
                    'type': 'int',
                    },
                'syn_reply_frame': {
                    'type': 'int',
                    },
                'headers_frame': {
                    'type': 'int',
                    },
                'settings_frame': {
                    'type': 'int',
                    },
                'window_frame': {
                    'type': 'int',
                    },
                'ping_frame': {
                    'type': 'int',
                    },
                'data_frame': {
                    'type': 'int',
                    },
                'data_no_stream': {
                    'type': 'int',
                    },
                'data_no_stream_no_goaway': {
                    'type': 'int',
                    },
                'data_no_stream_goaway_close': {
                    'type': 'int',
                    },
                'est_cb_no_tuple': {
                    'type': 'int',
                    },
                'data_cb_no_tuple': {
                    'type': 'int',
                    },
                'ctx_alloc_fail': {
                    'type': 'int',
                    },
                'fin_close_session': {
                    'type': 'int',
                    },
                'server_rst_close_stream': {
                    'type': 'int',
                    },
                'stream_found': {
                    'type': 'int',
                    },
                'close_stream_session_not_found': {
                    'type': 'int',
                    },
                'close_stream_stream_not_found': {
                    'type': 'int',
                    },
                'close_stream_already_closed': {
                    'type': 'int',
                    },
                'close_stream_session_close': {
                    'type': 'int',
                    },
                'close_session_already_closed': {
                    'type': 'int',
                    },
                'max_concurrent_stream_limit': {
                    'type': 'int',
                    },
                'stream_alloc_fail': {
                    'type': 'int',
                    },
                'http_conn_alloc_fail': {
                    'type': 'int',
                    },
                'request_header_alloc_fail': {
                    'type': 'int',
                    },
                'name_value_total_len_ex': {
                    'type': 'int',
                    },
                'name_value_zero_len': {
                    'type': 'int',
                    },
                'name_value_invalid_http_ver': {
                    'type': 'int',
                    },
                'name_value_connection': {
                    'type': 'int',
                    },
                'name_value_keepalive': {
                    'type': 'int',
                    },
                'name_value_proxy_conn': {
                    'type': 'int',
                    },
                'name_value_trasnfer_encod': {
                    'type': 'int',
                    },
                'name_value_no_must_have': {
                    'type': 'int',
                    },
                'decompress_fail': {
                    'type': 'int',
                    },
                'syn_after_goaway': {
                    'type': 'int',
                    },
                'stream_lt_prev': {
                    'type': 'int',
                    },
                'syn_stream_exist_or_even': {
                    'type': 'int',
                    },
                'syn_unidir': {
                    'type': 'int',
                    },
                'syn_reply_alr_rcvd': {
                    'type': 'int',
                    },
                'client_rst_nostream': {
                    'type': 'int',
                    },
                'window_no_stream': {
                    'type': 'int',
                    },
                'invalid_window_size': {
                    'type': 'int',
                    },
                'unknown_control_frame': {
                    'type': 'int',
                    },
                'data_on_closed_stream': {
                    'type': 'int',
                    },
                'invalid_frame_size': {
                    'type': 'int',
                    },
                'invalid_version': {
                    'type': 'int',
                    },
                'header_after_session_close': {
                    'type': 'int',
                    },
                'compress_ctx_alloc_fail': {
                    'type': 'int',
                    },
                'header_compress_fail': {
                    'type': 'int',
                    },
                'http_data_session_close': {
                    'type': 'int',
                    },
                'http_data_stream_not_found': {
                    'type': 'int',
                    },
                'close_stream_not_http_proxy': {
                    'type': 'int',
                    },
                'session_needs_requeue': {
                    'type': 'int',
                    },
                'new_stream_session_del': {
                    'type': 'int',
                    },
                'fin_stream_closed': {
                    'type': 'int',
                    },
                'http_close_stream_closed': {
                    'type': 'int',
                    },
                'http_err_stream_closed': {
                    'type': 'int',
                    },
                'http_hdr_stream_close': {
                    'type': 'int',
                    },
                'http_data_stream_close': {
                    'type': 'int',
                    },
                'session_close': {
                    'type': 'int',
                    }
                },
            'cpu_count': {
                'type': 'int',
                }
            },
        'stats': {
            'type': 'dict',
            'curr_proxy': {
                'type': 'str',
                },
            'total_proxy': {
                'type': 'str',
                },
            'curr_http_proxy': {
                'type': 'str',
                },
            'total_http_proxy': {
                'type': 'str',
                },
            'total_v2_proxy': {
                'type': 'str',
                },
            'total_v3_proxy': {
                'type': 'str',
                },
            'curr_stream': {
                'type': 'str',
                },
            'total_stream': {
                'type': 'str',
                },
            'total_stream_succ': {
                'type': 'str',
                },
            'client_rst': {
                'type': 'str',
                },
            'server_rst': {
                'type': 'str',
                },
            'client_goaway': {
                'type': 'str',
                },
            'server_goaway': {
                'type': 'str',
                },
            'tcp_err': {
                'type': 'str',
                },
            'inflate_ctx': {
                'type': 'str',
                },
            'deflate_ctx': {
                'type': 'str',
                },
            'ping_sent': {
                'type': 'str',
                },
            'stream_not_found': {
                'type': 'str',
                },
            'client_fin': {
                'type': 'str',
                },
            'server_fin': {
                'type': 'str',
                },
            'stream_close': {
                'type': 'str',
                },
            'stream_err': {
                'type': 'str',
                },
            'session_err': {
                'type': 'str',
                },
            'control_frame': {
                'type': 'str',
                },
            'syn_frame': {
                'type': 'str',
                },
            'syn_reply_frame': {
                'type': 'str',
                },
            'headers_frame': {
                'type': 'str',
                },
            'settings_frame': {
                'type': 'str',
                },
            'window_frame': {
                'type': 'str',
                },
            'ping_frame': {
                'type': 'str',
                },
            'data_frame': {
                'type': 'str',
                },
            'data_no_stream': {
                'type': 'str',
                },
            'data_no_stream_no_goaway': {
                'type': 'str',
                },
            'data_no_stream_goaway_close': {
                'type': 'str',
                },
            'est_cb_no_tuple': {
                'type': 'str',
                },
            'data_cb_no_tuple': {
                'type': 'str',
                },
            'ctx_alloc_fail': {
                'type': 'str',
                },
            'fin_close_session': {
                'type': 'str',
                },
            'server_rst_close_stream': {
                'type': 'str',
                },
            'stream_found': {
                'type': 'str',
                },
            'close_stream_session_not_found': {
                'type': 'str',
                },
            'close_stream_stream_not_found': {
                'type': 'str',
                },
            'close_stream_already_closed': {
                'type': 'str',
                },
            'close_stream_session_close': {
                'type': 'str',
                },
            'close_session_already_closed': {
                'type': 'str',
                },
            'max_concurrent_stream_limit': {
                'type': 'str',
                },
            'stream_alloc_fail': {
                'type': 'str',
                },
            'http_conn_alloc_fail': {
                'type': 'str',
                },
            'request_header_alloc_fail': {
                'type': 'str',
                },
            'name_value_total_len_ex': {
                'type': 'str',
                },
            'name_value_zero_len': {
                'type': 'str',
                },
            'name_value_invalid_http_ver': {
                'type': 'str',
                },
            'name_value_connection': {
                'type': 'str',
                },
            'name_value_keepalive': {
                'type': 'str',
                },
            'name_value_proxy_conn': {
                'type': 'str',
                },
            'name_value_trasnfer_encod': {
                'type': 'str',
                },
            'name_value_no_must_have': {
                'type': 'str',
                },
            'decompress_fail': {
                'type': 'str',
                },
            'syn_after_goaway': {
                'type': 'str',
                },
            'stream_lt_prev': {
                'type': 'str',
                },
            'syn_stream_exist_or_even': {
                'type': 'str',
                },
            'syn_unidir': {
                'type': 'str',
                },
            'syn_reply_alr_rcvd': {
                'type': 'str',
                },
            'client_rst_nostream': {
                'type': 'str',
                },
            'window_no_stream': {
                'type': 'str',
                },
            'invalid_window_size': {
                'type': 'str',
                },
            'unknown_control_frame': {
                'type': 'str',
                },
            'data_on_closed_stream': {
                'type': 'str',
                },
            'invalid_frame_size': {
                'type': 'str',
                },
            'invalid_version': {
                'type': 'str',
                },
            'header_after_session_close': {
                'type': 'str',
                },
            'compress_ctx_alloc_fail': {
                'type': 'str',
                },
            'header_compress_fail': {
                'type': 'str',
                },
            'http_data_session_close': {
                'type': 'str',
                },
            'http_data_stream_not_found': {
                'type': 'str',
                },
            'close_stream_not_http_proxy': {
                'type': 'str',
                },
            'session_needs_requeue': {
                'type': 'str',
                },
            'new_stream_session_del': {
                'type': 'str',
                },
            'fin_stream_closed': {
                'type': 'str',
                },
            'http_close_stream_closed': {
                'type': 'str',
                },
            'http_err_stream_closed': {
                'type': 'str',
                },
            'http_hdr_stream_close': {
                'type': 'str',
                },
            'http_data_stream_close': {
                'type': 'str',
                },
            'session_close': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/spdy-proxy"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/spdy-proxy"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["spdy-proxy"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["spdy-proxy"].get(k) != v:
            change_results["changed"] = True
            config_changes["spdy-proxy"][k] = v

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
    payload = utils.build_json("spdy-proxy", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(changed=False, messages="", modified_values={}, axapi_calls=[], ansible_facts={}, acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

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
            result["axapi_calls"].append(api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(api_client.switch_device_context(module.client, a10_device_context_id))

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
                result["acos_info"] = info["spdy-proxy"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["spdy-proxy-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["spdy-proxy"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["spdy-proxy"]["stats"] if info != "NotFound" else info
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
