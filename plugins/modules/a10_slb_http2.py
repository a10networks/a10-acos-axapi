#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_http2
description:
    - Configure http2
author: A10 Networks
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
          'connection_preface_rcvd'= Connection preface rcvd; 'control_frame'= Control
          Frame Rcvd; 'headers_frame'= HEADERS Frame Rcvd; 'continuation_frame'=
          CONTINUATION Frame Rcvd; 'rst_frame_rcvd'= RST_STREAM Frame Rcvd;
          'settings_frame'= SETTINGS Frame Rcvd; 'window_update_frame'= WINDOW_UPDATE
          Frame Rcvd; 'ping_frame'= PING Frame Rcvd; 'goaway_frame'= GOAWAY Frame Rcvd;
          'priority_frame'= PRIORITY Frame Rcvd; 'data_frame'= DATA Frame Recvd;
          'unknown_frame'= Unknown Frame Recvd; 'connection_preface_sent'= Connection
          preface sent; 'settings_frame_sent'= SETTINGS Frame Sent; 'settings_ack_sent'=
          SETTINGS ACK Frame Sent; 'empty_settings_sent'= Empty SETTINGS Frame Sent;
          'ping_frame_sent'= PING Frame Sent; 'window_update_frame_sent'= WINDOW_UPDATE
          Frame Sent; 'rst_frame_sent'= RST_STREAM Frame Sent; 'goaway_frame_sent'=
          GOAWAY Frame Sent; 'header_to_app'= HEADER Frame to HTTP; 'data_to_app'= DATA
          Frame to HTTP; 'protocol_error'= Protocol Error; 'internal_error'= Internal
          Error; 'proxy_alloc_error'= HTTP2 Proxy alloc Error; 'split_buff_fail'=
          Splitting Buffer Failed; 'invalid_frame_size'= Invalid Frame Size Rcvd;
          'error_max_invalid_stream'= Max Invalid Stream Rcvd; 'data_no_stream'= DATA
          Frame Rcvd on non-existent stream; 'flow_control_error'= Flow Control Error;
          'settings_timeout'= Settings Timeout; 'frame_size_error'= Frame Size Error;
          'refused_stream'= Refused Stream; 'cancel'= cancel; 'compression_error'=
          compression error; 'connect_error'= connect error; 'enhance_your_calm'= enhance
          your calm error; 'inadequate_security'= inadequate security;
          'http_1_1_required'= HTTP1.1 Required; 'deflate_alloc_fail'= deflate alloc
          fail; 'inflate_alloc_fail'= inflate alloc fail; 'inflate_header_fail'= Inflate
          Header Fail; 'bad_connection_preface'= Bad Connection Preface;
          'cant_allocate_control_frame'= Cant allocate control frame;
          'cant_allocate_settings_frame'= Cant allocate SETTINGS frame;
          'bad_frame_type_for_stream_state'= Bad frame type for stream state;
          'wrong_stream_state'= Wrong Stream State; 'data_queue_alloc_error'= Data Queue
          Alloc Error; 'buff_alloc_error'= Buff alloc error; 'cant_allocate_rst_frame'=
          Cant allocate RST_STREAM frame; 'cant_allocate_goaway_frame'= Cant allocate
          GOAWAY frame; 'cant_allocate_ping_frame'= Cant allocate PING frame;
          'cant_allocate_stream'= Cant allocate stream; 'cant_allocate_window_frame'=
          Cant allocate WINDOW_UPDATE frame; 'header_no_stream'= header no stream;
          'header_padlen_gt_frame_payload'= Header padlen greater than frame payload
          size; 'streams_gt_max_concur_streams'= Streams greater than max allowed
          concurrent streams; 'idle_state_unexpected_frame'= Unxpected frame received in
          idle state; 'reserved_local_state_unexpected_frame'= Unexpected frame received
          in reserved local state; 'reserved_remote_state_unexpected_frame'= Unexpected
          frame received in reserved remote state;
          'half_closed_remote_state_unexpected_frame'= Unexpected frame received in half
          closed remote state; 'closed_state_unexpected_frame'= Unexpected frame received
          in closed state; 'zero_window_size_on_stream'= Window Update with zero
          increment rcvd; 'exceeds_max_window_size_stream'= Window Update with increment
          that results in exceeding max window; 'stream_closed'= stream closed;
          'continuation_before_headers'= CONTINUATION frame with no headers frame;
          'invalid_frame_during_headers'= frame before headers were complete;
          'headers_after_continuation'= headers frame before CONTINUATION was complete;
          'push_promise_frame_sent'= Push Promise Frame Sent; 'invalid_push_promise'=
          unexpected PUSH_PROMISE frame; 'invalid_stream_id'= received invalid stream ID;
          'headers_interleaved'= headers interleaved on streams;
          'trailers_no_end_stream'= trailers not marked as end-of-stream;
          'invalid_setting_value'= invalid setting-frame value; 'invalid_window_update'=
          window-update value out of range; 'frame_header_bytes_received'= frame header
          bytes received; 'frame_header_bytes_sent'= frame header bytes sent;
          'control_bytes_received'= HTTP/2 control frame bytes received;
          'control_bytes_sent'= HTTP/2 control frame bytes sent; 'header_bytes_received'=
          HTTP/2 header bytes received; 'header_bytes_sent'= HTTP/2 header bytes sent;
          'data_bytes_received'= HTTP/2 data bytes received; 'data_bytes_sent'= HTTP/2
          data bytes sent; 'total_bytes_received'= HTTP/2 total bytes received;
          'total_bytes_sent'= HTTP/2 total bytes sent; 'peak_proxy'= Peak Proxy Conns;
          'control_frame_sent'= Control Frame Sent; 'continuation_frame_sent'=
          CONTINUATION Frame Sent; 'data_frame_sent'= DATA Frame Sent;
          'headers_frame_sent'= HEADERS Frame Sent; 'priority_frame_sent'= PRIORITY Frame
          Sent; 'settings_ack_rcvd'= SETTINGS ACK Frame Rcvd; 'empty_settings_rcvd'=
          Empty SETTINGS Frame Rcvd; 'alloc_fail_total'= Alloc Fail - Total;
          'err_rcvd_total'= Error Rcvd - Total; 'err_sent_total'= Error Rent - Total;
          'err_sent_proto_err'= Error Sent - PROTOCOL_ERROR; 'err_sent_internal_err'=
          Error Sent - INTERNAL_ERROR; 'err_sent_flow_control'= Error Sent -
          FLOW_CONTROL_ERROR; 'err_sent_setting_timeout'= Error Sent - SETTINGS_TIMEOUT;
          'err_sent_stream_closed'= Error Sent - STREAM_CLOSED;
          'err_sent_frame_size_err'= Error Sent - FRAME_SIZE_ERROR;
          'err_sent_refused_stream'= Error Sent - REFUSED_STREAM; 'err_sent_cancel'=
          Error Sent - CANCEL; 'err_sent_compression_err'= Error Sent -
          COMPRESSION_ERROR; 'err_sent_connect_err'= Error Sent - CONNECT_ERROR;
          'err_sent_your_calm'= Error Sent - ENHANCE_YOUR_CALM;
          'err_sent_inadequate_security'= Error Sent - INADEQUATE_SECURITY;
          'err_sent_http11_required'= Error Sent - HTTP_1_1_REQUIRED; 'http2_rejected'=
          HTTP2 Rejected; 'current_stream'= Current Streams; 'stream_create'= Stream
          Create; 'stream_free'= Stream Free; 'end_stream_rcvd'= End Stream Recieved;
          'end_stream_sent'= End Stream Sent;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            http2_cpu_list:
                description:
                - "Field http2_cpu_list"
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
            connection_preface_rcvd:
                description:
                - "Connection preface rcvd"
                type: str
            control_frame:
                description:
                - "Control Frame Rcvd"
                type: str
            headers_frame:
                description:
                - "HEADERS Frame Rcvd"
                type: str
            continuation_frame:
                description:
                - "CONTINUATION Frame Rcvd"
                type: str
            rst_frame_rcvd:
                description:
                - "RST_STREAM Frame Rcvd"
                type: str
            settings_frame:
                description:
                - "SETTINGS Frame Rcvd"
                type: str
            window_update_frame:
                description:
                - "WINDOW_UPDATE Frame Rcvd"
                type: str
            ping_frame:
                description:
                - "PING Frame Rcvd"
                type: str
            goaway_frame:
                description:
                - "GOAWAY Frame Rcvd"
                type: str
            priority_frame:
                description:
                - "PRIORITY Frame Rcvd"
                type: str
            data_frame:
                description:
                - "DATA Frame Recvd"
                type: str
            unknown_frame:
                description:
                - "Unknown Frame Recvd"
                type: str
            connection_preface_sent:
                description:
                - "Connection preface sent"
                type: str
            settings_frame_sent:
                description:
                - "SETTINGS Frame Sent"
                type: str
            settings_ack_sent:
                description:
                - "SETTINGS ACK Frame Sent"
                type: str
            empty_settings_sent:
                description:
                - "Empty SETTINGS Frame Sent"
                type: str
            ping_frame_sent:
                description:
                - "PING Frame Sent"
                type: str
            window_update_frame_sent:
                description:
                - "WINDOW_UPDATE Frame Sent"
                type: str
            rst_frame_sent:
                description:
                - "RST_STREAM Frame Sent"
                type: str
            goaway_frame_sent:
                description:
                - "GOAWAY Frame Sent"
                type: str
            header_to_app:
                description:
                - "HEADER Frame to HTTP"
                type: str
            data_to_app:
                description:
                - "DATA Frame to HTTP"
                type: str
            protocol_error:
                description:
                - "Protocol Error"
                type: str
            internal_error:
                description:
                - "Internal Error"
                type: str
            proxy_alloc_error:
                description:
                - "HTTP2 Proxy alloc Error"
                type: str
            split_buff_fail:
                description:
                - "Splitting Buffer Failed"
                type: str
            invalid_frame_size:
                description:
                - "Invalid Frame Size Rcvd"
                type: str
            error_max_invalid_stream:
                description:
                - "Max Invalid Stream Rcvd"
                type: str
            data_no_stream:
                description:
                - "DATA Frame Rcvd on non-existent stream"
                type: str
            flow_control_error:
                description:
                - "Flow Control Error"
                type: str
            settings_timeout:
                description:
                - "Settings Timeout"
                type: str
            frame_size_error:
                description:
                - "Frame Size Error"
                type: str
            refused_stream:
                description:
                - "Refused Stream"
                type: str
            cancel:
                description:
                - "cancel"
                type: str
            compression_error:
                description:
                - "compression error"
                type: str
            connect_error:
                description:
                - "connect error"
                type: str
            enhance_your_calm:
                description:
                - "enhance your calm error"
                type: str
            inadequate_security:
                description:
                - "inadequate security"
                type: str
            http_1_1_required:
                description:
                - "HTTP1.1 Required"
                type: str
            deflate_alloc_fail:
                description:
                - "deflate alloc fail"
                type: str
            inflate_alloc_fail:
                description:
                - "inflate alloc fail"
                type: str
            inflate_header_fail:
                description:
                - "Inflate Header Fail"
                type: str
            bad_connection_preface:
                description:
                - "Bad Connection Preface"
                type: str
            cant_allocate_control_frame:
                description:
                - "Cant allocate control frame"
                type: str
            cant_allocate_settings_frame:
                description:
                - "Cant allocate SETTINGS frame"
                type: str
            bad_frame_type_for_stream_state:
                description:
                - "Bad frame type for stream state"
                type: str
            wrong_stream_state:
                description:
                - "Wrong Stream State"
                type: str
            data_queue_alloc_error:
                description:
                - "Data Queue Alloc Error"
                type: str
            buff_alloc_error:
                description:
                - "Buff alloc error"
                type: str
            cant_allocate_rst_frame:
                description:
                - "Cant allocate RST_STREAM frame"
                type: str
            cant_allocate_goaway_frame:
                description:
                - "Cant allocate GOAWAY frame"
                type: str
            cant_allocate_ping_frame:
                description:
                - "Cant allocate PING frame"
                type: str
            cant_allocate_stream:
                description:
                - "Cant allocate stream"
                type: str
            cant_allocate_window_frame:
                description:
                - "Cant allocate WINDOW_UPDATE frame"
                type: str
            header_no_stream:
                description:
                - "header no stream"
                type: str
            header_padlen_gt_frame_payload:
                description:
                - "Header padlen greater than frame payload size"
                type: str
            streams_gt_max_concur_streams:
                description:
                - "Streams greater than max allowed concurrent streams"
                type: str
            idle_state_unexpected_frame:
                description:
                - "Unxpected frame received in idle state"
                type: str
            reserved_local_state_unexpected_frame:
                description:
                - "Unexpected frame received in reserved local state"
                type: str
            reserved_remote_state_unexpected_frame:
                description:
                - "Unexpected frame received in reserved remote state"
                type: str
            half_closed_remote_state_unexpected_frame:
                description:
                - "Unexpected frame received in half closed remote state"
                type: str
            closed_state_unexpected_frame:
                description:
                - "Unexpected frame received in closed state"
                type: str
            zero_window_size_on_stream:
                description:
                - "Window Update with zero increment rcvd"
                type: str
            exceeds_max_window_size_stream:
                description:
                - "Window Update with increment that results in exceeding max window"
                type: str
            stream_closed:
                description:
                - "stream closed"
                type: str
            continuation_before_headers:
                description:
                - "CONTINUATION frame with no headers frame"
                type: str
            invalid_frame_during_headers:
                description:
                - "frame before headers were complete"
                type: str
            headers_after_continuation:
                description:
                - "headers frame before CONTINUATION was complete"
                type: str
            push_promise_frame_sent:
                description:
                - "Push Promise Frame Sent"
                type: str
            invalid_push_promise:
                description:
                - "unexpected PUSH_PROMISE frame"
                type: str
            invalid_stream_id:
                description:
                - "received invalid stream ID"
                type: str
            headers_interleaved:
                description:
                - "headers interleaved on streams"
                type: str
            trailers_no_end_stream:
                description:
                - "trailers not marked as end-of-stream"
                type: str
            invalid_setting_value:
                description:
                - "invalid setting-frame value"
                type: str
            invalid_window_update:
                description:
                - "window-update value out of range"
                type: str
            frame_header_bytes_received:
                description:
                - "frame header bytes received"
                type: str
            frame_header_bytes_sent:
                description:
                - "frame header bytes sent"
                type: str
            control_bytes_received:
                description:
                - "HTTP/2 control frame bytes received"
                type: str
            control_bytes_sent:
                description:
                - "HTTP/2 control frame bytes sent"
                type: str
            header_bytes_received:
                description:
                - "HTTP/2 header bytes received"
                type: str
            header_bytes_sent:
                description:
                - "HTTP/2 header bytes sent"
                type: str
            data_bytes_received:
                description:
                - "HTTP/2 data bytes received"
                type: str
            data_bytes_sent:
                description:
                - "HTTP/2 data bytes sent"
                type: str
            total_bytes_received:
                description:
                - "HTTP/2 total bytes received"
                type: str
            total_bytes_sent:
                description:
                - "HTTP/2 total bytes sent"
                type: str
            peak_proxy:
                description:
                - "Peak Proxy Conns"
                type: str
            control_frame_sent:
                description:
                - "Control Frame Sent"
                type: str
            continuation_frame_sent:
                description:
                - "CONTINUATION Frame Sent"
                type: str
            data_frame_sent:
                description:
                - "DATA Frame Sent"
                type: str
            headers_frame_sent:
                description:
                - "HEADERS Frame Sent"
                type: str
            priority_frame_sent:
                description:
                - "PRIORITY Frame Sent"
                type: str
            settings_ack_rcvd:
                description:
                - "SETTINGS ACK Frame Rcvd"
                type: str
            empty_settings_rcvd:
                description:
                - "Empty SETTINGS Frame Rcvd"
                type: str
            alloc_fail_total:
                description:
                - "Alloc Fail - Total"
                type: str
            err_rcvd_total:
                description:
                - "Error Rcvd - Total"
                type: str
            err_sent_total:
                description:
                - "Error Rent - Total"
                type: str
            err_sent_proto_err:
                description:
                - "Error Sent - PROTOCOL_ERROR"
                type: str
            err_sent_internal_err:
                description:
                - "Error Sent - INTERNAL_ERROR"
                type: str
            err_sent_flow_control:
                description:
                - "Error Sent - FLOW_CONTROL_ERROR"
                type: str
            err_sent_setting_timeout:
                description:
                - "Error Sent - SETTINGS_TIMEOUT"
                type: str
            err_sent_stream_closed:
                description:
                - "Error Sent - STREAM_CLOSED"
                type: str
            err_sent_frame_size_err:
                description:
                - "Error Sent - FRAME_SIZE_ERROR"
                type: str
            err_sent_refused_stream:
                description:
                - "Error Sent - REFUSED_STREAM"
                type: str
            err_sent_cancel:
                description:
                - "Error Sent - CANCEL"
                type: str
            err_sent_compression_err:
                description:
                - "Error Sent - COMPRESSION_ERROR"
                type: str
            err_sent_connect_err:
                description:
                - "Error Sent - CONNECT_ERROR"
                type: str
            err_sent_your_calm:
                description:
                - "Error Sent - ENHANCE_YOUR_CALM"
                type: str
            err_sent_inadequate_security:
                description:
                - "Error Sent - INADEQUATE_SECURITY"
                type: str
            err_sent_http11_required:
                description:
                - "Error Sent - HTTP_1_1_REQUIRED"
                type: str
            http2_rejected:
                description:
                - "HTTP2 Rejected"
                type: str
            current_stream:
                description:
                - "Current Streams"
                type: str
            stream_create:
                description:
                - "Stream Create"
                type: str
            stream_free:
                description:
                - "Stream Free"
                type: str
            end_stream_rcvd:
                description:
                - "End Stream Recieved"
                type: str
            end_stream_sent:
                description:
                - "End Stream Sent"
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
                    'all', 'curr_proxy', 'total_proxy', 'connection_preface_rcvd', 'control_frame', 'headers_frame', 'continuation_frame', 'rst_frame_rcvd', 'settings_frame', 'window_update_frame', 'ping_frame', 'goaway_frame', 'priority_frame', 'data_frame', 'unknown_frame', 'connection_preface_sent', 'settings_frame_sent', 'settings_ack_sent',
                    'empty_settings_sent', 'ping_frame_sent', 'window_update_frame_sent', 'rst_frame_sent', 'goaway_frame_sent', 'header_to_app', 'data_to_app', 'protocol_error', 'internal_error', 'proxy_alloc_error', 'split_buff_fail', 'invalid_frame_size', 'error_max_invalid_stream', 'data_no_stream', 'flow_control_error', 'settings_timeout',
                    'frame_size_error', 'refused_stream', 'cancel', 'compression_error', 'connect_error', 'enhance_your_calm', 'inadequate_security', 'http_1_1_required', 'deflate_alloc_fail', 'inflate_alloc_fail', 'inflate_header_fail', 'bad_connection_preface', 'cant_allocate_control_frame', 'cant_allocate_settings_frame',
                    'bad_frame_type_for_stream_state', 'wrong_stream_state', 'data_queue_alloc_error', 'buff_alloc_error', 'cant_allocate_rst_frame', 'cant_allocate_goaway_frame', 'cant_allocate_ping_frame', 'cant_allocate_stream', 'cant_allocate_window_frame', 'header_no_stream', 'header_padlen_gt_frame_payload', 'streams_gt_max_concur_streams',
                    'idle_state_unexpected_frame', 'reserved_local_state_unexpected_frame', 'reserved_remote_state_unexpected_frame', 'half_closed_remote_state_unexpected_frame', 'closed_state_unexpected_frame', 'zero_window_size_on_stream', 'exceeds_max_window_size_stream', 'stream_closed', 'continuation_before_headers',
                    'invalid_frame_during_headers', 'headers_after_continuation', 'push_promise_frame_sent', 'invalid_push_promise', 'invalid_stream_id', 'headers_interleaved', 'trailers_no_end_stream', 'invalid_setting_value', 'invalid_window_update', 'frame_header_bytes_received', 'frame_header_bytes_sent', 'control_bytes_received',
                    'control_bytes_sent', 'header_bytes_received', 'header_bytes_sent', 'data_bytes_received', 'data_bytes_sent', 'total_bytes_received', 'total_bytes_sent', 'peak_proxy', 'control_frame_sent', 'continuation_frame_sent', 'data_frame_sent', 'headers_frame_sent', 'priority_frame_sent', 'settings_ack_rcvd', 'empty_settings_rcvd',
                    'alloc_fail_total', 'err_rcvd_total', 'err_sent_total', 'err_sent_proto_err', 'err_sent_internal_err', 'err_sent_flow_control', 'err_sent_setting_timeout', 'err_sent_stream_closed', 'err_sent_frame_size_err', 'err_sent_refused_stream', 'err_sent_cancel', 'err_sent_compression_err', 'err_sent_connect_err', 'err_sent_your_calm',
                    'err_sent_inadequate_security', 'err_sent_http11_required', 'http2_rejected', 'current_stream', 'stream_create', 'stream_free', 'end_stream_rcvd', 'end_stream_sent'
                    ]
                }
            },
        'oper': {
            'type': 'dict',
            'http2_cpu_list': {
                'type': 'list',
                'curr_proxy': {
                    'type': 'int',
                    },
                'peak_proxy': {
                    'type': 'int',
                    },
                'total_proxy': {
                    'type': 'int',
                    },
                'connection_preface_rcvd': {
                    'type': 'int',
                    },
                'connection_preface_sent': {
                    'type': 'int',
                    },
                'control_frame': {
                    'type': 'int',
                    },
                'control_frame_sent': {
                    'type': 'int',
                    },
                'continuation_frame': {
                    'type': 'int',
                    },
                'continuation_frame_sent': {
                    'type': 'int',
                    },
                'data_frame': {
                    'type': 'int',
                    },
                'data_frame_sent': {
                    'type': 'int',
                    },
                'data_to_app': {
                    'type': 'int',
                    },
                'goaway_frame': {
                    'type': 'int',
                    },
                'goaway_frame_sent': {
                    'type': 'int',
                    },
                'headers_frame': {
                    'type': 'int',
                    },
                'headers_frame_sent': {
                    'type': 'int',
                    },
                'header_to_app': {
                    'type': 'int',
                    },
                'ping_frame': {
                    'type': 'int',
                    },
                'ping_frame_sent': {
                    'type': 'int',
                    },
                'priority_frame': {
                    'type': 'int',
                    },
                'priority_frame_sent': {
                    'type': 'int',
                    },
                'rst_frame_rcvd': {
                    'type': 'int',
                    },
                'rst_frame_sent': {
                    'type': 'int',
                    },
                'settings_frame': {
                    'type': 'int',
                    },
                'settings_frame_sent': {
                    'type': 'int',
                    },
                'settings_ack_rcvd': {
                    'type': 'int',
                    },
                'settings_ack_sent': {
                    'type': 'int',
                    },
                'empty_settings_rcvd': {
                    'type': 'int',
                    },
                'empty_settings_sent': {
                    'type': 'int',
                    },
                'window_update_frame': {
                    'type': 'int',
                    },
                'window_update_frame_sent': {
                    'type': 'int',
                    },
                'unknown_frame': {
                    'type': 'int',
                    },
                'split_buff_fail': {
                    'type': 'int',
                    },
                'invalid_frame_size': {
                    'type': 'int',
                    },
                'error_max_invalid_stream': {
                    'type': 'int',
                    },
                'data_no_stream': {
                    'type': 'int',
                    },
                'bad_connection_preface': {
                    'type': 'int',
                    },
                'bad_frame_type_for_stream_state': {
                    'type': 'int',
                    },
                'wrong_stream_state': {
                    'type': 'int',
                    },
                'alloc_fail_total': {
                    'type': 'int',
                    },
                'proxy_alloc_error': {
                    'type': 'int',
                    },
                'deflate_alloc_fail': {
                    'type': 'int',
                    },
                'inflate_alloc_fail': {
                    'type': 'int',
                    },
                'data_queue_alloc_error': {
                    'type': 'int',
                    },
                'buff_alloc_error': {
                    'type': 'int',
                    },
                'cant_allocate_control_frame': {
                    'type': 'int',
                    },
                'cant_allocate_settings_frame': {
                    'type': 'int',
                    },
                'cant_allocate_rst_frame': {
                    'type': 'int',
                    },
                'cant_allocate_goaway_frame': {
                    'type': 'int',
                    },
                'cant_allocate_ping_frame': {
                    'type': 'int',
                    },
                'cant_allocate_stream': {
                    'type': 'int',
                    },
                'cant_allocate_window_frame': {
                    'type': 'int',
                    },
                'inflate_header_fail': {
                    'type': 'int',
                    },
                'header_no_stream': {
                    'type': 'int',
                    },
                'header_padlen_gt_frame_payload': {
                    'type': 'int',
                    },
                'streams_gt_max_concur_streams': {
                    'type': 'int',
                    },
                'idle_state_unexpected_frame': {
                    'type': 'int',
                    },
                'reserved_local_state_unexpected_frame': {
                    'type': 'int',
                    },
                'reserved_remote_state_unexpected_frame': {
                    'type': 'int',
                    },
                'half_closed_remote_state_unexpected_frame': {
                    'type': 'int',
                    },
                'closed_state_unexpected_frame': {
                    'type': 'int',
                    },
                'zero_window_size_on_stream': {
                    'type': 'int',
                    },
                'exceeds_max_window_size_stream': {
                    'type': 'int',
                    },
                'continuation_before_headers': {
                    'type': 'int',
                    },
                'invalid_frame_during_headers': {
                    'type': 'int',
                    },
                'headers_after_continuation': {
                    'type': 'int',
                    },
                'invalid_push_promise': {
                    'type': 'int',
                    },
                'invalid_stream_id': {
                    'type': 'int',
                    },
                'headers_interleaved': {
                    'type': 'int',
                    },
                'trailers_no_end_stream': {
                    'type': 'int',
                    },
                'invalid_setting_value': {
                    'type': 'int',
                    },
                'invalid_window_update': {
                    'type': 'int',
                    },
                'err_rcvd_total': {
                    'type': 'int',
                    },
                'protocol_error': {
                    'type': 'int',
                    },
                'internal_error': {
                    'type': 'int',
                    },
                'flow_control_error': {
                    'type': 'int',
                    },
                'settings_timeout': {
                    'type': 'int',
                    },
                'stream_closed': {
                    'type': 'int',
                    },
                'frame_size_error': {
                    'type': 'int',
                    },
                'refused_stream': {
                    'type': 'int',
                    },
                'cancel': {
                    'type': 'int',
                    },
                'compression_error': {
                    'type': 'int',
                    },
                'connect_error': {
                    'type': 'int',
                    },
                'enhance_your_calm': {
                    'type': 'int',
                    },
                'inadequate_security': {
                    'type': 'int',
                    },
                'http_1_1_required': {
                    'type': 'int',
                    },
                'err_sent_total': {
                    'type': 'int',
                    },
                'err_sent_proto_err': {
                    'type': 'int',
                    },
                'err_sent_internal_err': {
                    'type': 'int',
                    },
                'err_sent_flow_control': {
                    'type': 'int',
                    },
                'err_sent_setting_timeout': {
                    'type': 'int',
                    },
                'err_sent_stream_closed': {
                    'type': 'int',
                    },
                'err_sent_frame_size_err': {
                    'type': 'int',
                    },
                'err_sent_refused_stream': {
                    'type': 'int',
                    },
                'err_sent_cancel': {
                    'type': 'int',
                    },
                'err_sent_compression_err': {
                    'type': 'int',
                    },
                'err_sent_connect_err': {
                    'type': 'int',
                    },
                'err_sent_your_calm': {
                    'type': 'int',
                    },
                'err_sent_inadequate_security': {
                    'type': 'int',
                    },
                'err_sent_http11_required': {
                    'type': 'int',
                    },
                'frame_header_bytes_received': {
                    'type': 'int',
                    },
                'frame_header_bytes_sent': {
                    'type': 'int',
                    },
                'control_bytes_received': {
                    'type': 'int',
                    },
                'control_bytes_sent': {
                    'type': 'int',
                    },
                'header_bytes_received': {
                    'type': 'int',
                    },
                'header_bytes_sent': {
                    'type': 'int',
                    },
                'data_bytes_received': {
                    'type': 'int',
                    },
                'data_bytes_sent': {
                    'type': 'int',
                    },
                'total_bytes_received': {
                    'type': 'int',
                    },
                'total_bytes_sent': {
                    'type': 'int',
                    },
                'push_promise_frame_sent': {
                    'type': 'int',
                    },
                'http2_rejected': {
                    'type': 'int',
                    },
                'current_stream': {
                    'type': 'int',
                    },
                'stream_create': {
                    'type': 'int',
                    },
                'stream_free': {
                    'type': 'int',
                    },
                'end_stream_rcvd': {
                    'type': 'int',
                    },
                'end_stream_sent': {
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
            'connection_preface_rcvd': {
                'type': 'str',
                },
            'control_frame': {
                'type': 'str',
                },
            'headers_frame': {
                'type': 'str',
                },
            'continuation_frame': {
                'type': 'str',
                },
            'rst_frame_rcvd': {
                'type': 'str',
                },
            'settings_frame': {
                'type': 'str',
                },
            'window_update_frame': {
                'type': 'str',
                },
            'ping_frame': {
                'type': 'str',
                },
            'goaway_frame': {
                'type': 'str',
                },
            'priority_frame': {
                'type': 'str',
                },
            'data_frame': {
                'type': 'str',
                },
            'unknown_frame': {
                'type': 'str',
                },
            'connection_preface_sent': {
                'type': 'str',
                },
            'settings_frame_sent': {
                'type': 'str',
                },
            'settings_ack_sent': {
                'type': 'str',
                },
            'empty_settings_sent': {
                'type': 'str',
                },
            'ping_frame_sent': {
                'type': 'str',
                },
            'window_update_frame_sent': {
                'type': 'str',
                },
            'rst_frame_sent': {
                'type': 'str',
                },
            'goaway_frame_sent': {
                'type': 'str',
                },
            'header_to_app': {
                'type': 'str',
                },
            'data_to_app': {
                'type': 'str',
                },
            'protocol_error': {
                'type': 'str',
                },
            'internal_error': {
                'type': 'str',
                },
            'proxy_alloc_error': {
                'type': 'str',
                },
            'split_buff_fail': {
                'type': 'str',
                },
            'invalid_frame_size': {
                'type': 'str',
                },
            'error_max_invalid_stream': {
                'type': 'str',
                },
            'data_no_stream': {
                'type': 'str',
                },
            'flow_control_error': {
                'type': 'str',
                },
            'settings_timeout': {
                'type': 'str',
                },
            'frame_size_error': {
                'type': 'str',
                },
            'refused_stream': {
                'type': 'str',
                },
            'cancel': {
                'type': 'str',
                },
            'compression_error': {
                'type': 'str',
                },
            'connect_error': {
                'type': 'str',
                },
            'enhance_your_calm': {
                'type': 'str',
                },
            'inadequate_security': {
                'type': 'str',
                },
            'http_1_1_required': {
                'type': 'str',
                },
            'deflate_alloc_fail': {
                'type': 'str',
                },
            'inflate_alloc_fail': {
                'type': 'str',
                },
            'inflate_header_fail': {
                'type': 'str',
                },
            'bad_connection_preface': {
                'type': 'str',
                },
            'cant_allocate_control_frame': {
                'type': 'str',
                },
            'cant_allocate_settings_frame': {
                'type': 'str',
                },
            'bad_frame_type_for_stream_state': {
                'type': 'str',
                },
            'wrong_stream_state': {
                'type': 'str',
                },
            'data_queue_alloc_error': {
                'type': 'str',
                },
            'buff_alloc_error': {
                'type': 'str',
                },
            'cant_allocate_rst_frame': {
                'type': 'str',
                },
            'cant_allocate_goaway_frame': {
                'type': 'str',
                },
            'cant_allocate_ping_frame': {
                'type': 'str',
                },
            'cant_allocate_stream': {
                'type': 'str',
                },
            'cant_allocate_window_frame': {
                'type': 'str',
                },
            'header_no_stream': {
                'type': 'str',
                },
            'header_padlen_gt_frame_payload': {
                'type': 'str',
                },
            'streams_gt_max_concur_streams': {
                'type': 'str',
                },
            'idle_state_unexpected_frame': {
                'type': 'str',
                },
            'reserved_local_state_unexpected_frame': {
                'type': 'str',
                },
            'reserved_remote_state_unexpected_frame': {
                'type': 'str',
                },
            'half_closed_remote_state_unexpected_frame': {
                'type': 'str',
                },
            'closed_state_unexpected_frame': {
                'type': 'str',
                },
            'zero_window_size_on_stream': {
                'type': 'str',
                },
            'exceeds_max_window_size_stream': {
                'type': 'str',
                },
            'stream_closed': {
                'type': 'str',
                },
            'continuation_before_headers': {
                'type': 'str',
                },
            'invalid_frame_during_headers': {
                'type': 'str',
                },
            'headers_after_continuation': {
                'type': 'str',
                },
            'push_promise_frame_sent': {
                'type': 'str',
                },
            'invalid_push_promise': {
                'type': 'str',
                },
            'invalid_stream_id': {
                'type': 'str',
                },
            'headers_interleaved': {
                'type': 'str',
                },
            'trailers_no_end_stream': {
                'type': 'str',
                },
            'invalid_setting_value': {
                'type': 'str',
                },
            'invalid_window_update': {
                'type': 'str',
                },
            'frame_header_bytes_received': {
                'type': 'str',
                },
            'frame_header_bytes_sent': {
                'type': 'str',
                },
            'control_bytes_received': {
                'type': 'str',
                },
            'control_bytes_sent': {
                'type': 'str',
                },
            'header_bytes_received': {
                'type': 'str',
                },
            'header_bytes_sent': {
                'type': 'str',
                },
            'data_bytes_received': {
                'type': 'str',
                },
            'data_bytes_sent': {
                'type': 'str',
                },
            'total_bytes_received': {
                'type': 'str',
                },
            'total_bytes_sent': {
                'type': 'str',
                },
            'peak_proxy': {
                'type': 'str',
                },
            'control_frame_sent': {
                'type': 'str',
                },
            'continuation_frame_sent': {
                'type': 'str',
                },
            'data_frame_sent': {
                'type': 'str',
                },
            'headers_frame_sent': {
                'type': 'str',
                },
            'priority_frame_sent': {
                'type': 'str',
                },
            'settings_ack_rcvd': {
                'type': 'str',
                },
            'empty_settings_rcvd': {
                'type': 'str',
                },
            'alloc_fail_total': {
                'type': 'str',
                },
            'err_rcvd_total': {
                'type': 'str',
                },
            'err_sent_total': {
                'type': 'str',
                },
            'err_sent_proto_err': {
                'type': 'str',
                },
            'err_sent_internal_err': {
                'type': 'str',
                },
            'err_sent_flow_control': {
                'type': 'str',
                },
            'err_sent_setting_timeout': {
                'type': 'str',
                },
            'err_sent_stream_closed': {
                'type': 'str',
                },
            'err_sent_frame_size_err': {
                'type': 'str',
                },
            'err_sent_refused_stream': {
                'type': 'str',
                },
            'err_sent_cancel': {
                'type': 'str',
                },
            'err_sent_compression_err': {
                'type': 'str',
                },
            'err_sent_connect_err': {
                'type': 'str',
                },
            'err_sent_your_calm': {
                'type': 'str',
                },
            'err_sent_inadequate_security': {
                'type': 'str',
                },
            'err_sent_http11_required': {
                'type': 'str',
                },
            'http2_rejected': {
                'type': 'str',
                },
            'current_stream': {
                'type': 'str',
                },
            'stream_create': {
                'type': 'str',
                },
            'stream_free': {
                'type': 'str',
                },
            'end_stream_rcvd': {
                'type': 'str',
                },
            'end_stream_sent': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/http2"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/http2"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["http2"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["http2"].get(k) != v:
            change_results["changed"] = True
            config_changes["http2"][k] = v

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
    payload = utils.build_json("http2", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["http2"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["http2-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["http2"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["http2"]["stats"] if info != "NotFound" else info
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
