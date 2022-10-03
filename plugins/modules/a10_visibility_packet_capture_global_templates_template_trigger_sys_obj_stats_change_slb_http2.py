#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_visibility_packet_capture_global_templates_template_trigger_sys_obj_stats_change_slb_http2
description:
    - Configure triggers for slb.http2 object
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
    template_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    dummy:
        description:
        - "dummy to make intermediate obj to single"
        type: bool
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    trigger_stats_inc:
        description:
        - "Field trigger_stats_inc"
        type: dict
        required: False
        suboptions:
            protocol_error:
                description:
                - "Enable automatic packet-capture for Protocol Error"
                type: bool
            internal_error:
                description:
                - "Enable automatic packet-capture for Internal Error"
                type: bool
            proxy_alloc_error:
                description:
                - "Enable automatic packet-capture for HTTP2 Proxy alloc Error"
                type: bool
            split_buff_fail:
                description:
                - "Enable automatic packet-capture for Splitting Buffer Failed"
                type: bool
            invalid_frame_size:
                description:
                - "Enable automatic packet-capture for Invalid Frame Size Rcvd"
                type: bool
            error_max_invalid_stream:
                description:
                - "Enable automatic packet-capture for Max Invalid Stream Rcvd"
                type: bool
            data_no_stream:
                description:
                - "Enable automatic packet-capture for DATA Frame Rcvd on non-existent stream"
                type: bool
            flow_control_error:
                description:
                - "Enable automatic packet-capture for Flow Control Error"
                type: bool
            settings_timeout:
                description:
                - "Enable automatic packet-capture for Settings Timeout"
                type: bool
            frame_size_error:
                description:
                - "Enable automatic packet-capture for Frame Size Error"
                type: bool
            refused_stream:
                description:
                - "Enable automatic packet-capture for Refused Stream"
                type: bool
            cancel:
                description:
                - "Enable automatic packet-capture for cancel"
                type: bool
            compression_error:
                description:
                - "Enable automatic packet-capture for compression error"
                type: bool
            connect_error:
                description:
                - "Enable automatic packet-capture for connect error"
                type: bool
            enhance_your_calm:
                description:
                - "Enable automatic packet-capture for enhance your calm error"
                type: bool
            inadequate_security:
                description:
                - "Enable automatic packet-capture for inadequate security"
                type: bool
            http_1_1_required:
                description:
                - "Enable automatic packet-capture for HTTP1.1 Required"
                type: bool
            deflate_alloc_fail:
                description:
                - "Enable automatic packet-capture for deflate alloc fail"
                type: bool
            inflate_alloc_fail:
                description:
                - "Enable automatic packet-capture for inflate alloc fail"
                type: bool
            inflate_header_fail:
                description:
                - "Enable automatic packet-capture for Inflate Header Fail"
                type: bool
            bad_connection_preface:
                description:
                - "Enable automatic packet-capture for Bad Connection Preface"
                type: bool
            cant_allocate_control_frame:
                description:
                - "Enable automatic packet-capture for Cant allocate control frame"
                type: bool
            cant_allocate_settings_frame:
                description:
                - "Enable automatic packet-capture for Cant allocate SETTINGS frame"
                type: bool
            bad_frame_type_for_stream_state:
                description:
                - "Enable automatic packet-capture for Bad frame type for stream state"
                type: bool
            wrong_stream_state:
                description:
                - "Enable automatic packet-capture for Wrong Stream State"
                type: bool
            data_queue_alloc_error:
                description:
                - "Enable automatic packet-capture for Data Queue Alloc Error"
                type: bool
            buff_alloc_error:
                description:
                - "Enable automatic packet-capture for Buff alloc error"
                type: bool
            cant_allocate_rst_frame:
                description:
                - "Enable automatic packet-capture for Cant allocate RST_STREAM frame"
                type: bool
            cant_allocate_goaway_frame:
                description:
                - "Enable automatic packet-capture for Cant allocate GOAWAY frame"
                type: bool
            cant_allocate_ping_frame:
                description:
                - "Enable automatic packet-capture for Cant allocate PING frame"
                type: bool
            cant_allocate_stream:
                description:
                - "Enable automatic packet-capture for Cant allocate stream"
                type: bool
            cant_allocate_window_frame:
                description:
                - "Enable automatic packet-capture for Cant allocate WINDOW_UPDATE frame"
                type: bool
            header_no_stream:
                description:
                - "Enable automatic packet-capture for header no stream"
                type: bool
            header_padlen_gt_frame_payload:
                description:
                - "Enable automatic packet-capture for Header padlen greater than frame payload
          size"
                type: bool
            streams_gt_max_concur_streams:
                description:
                - "Enable automatic packet-capture for Streams greater than max allowed concurrent
          streams"
                type: bool
            idle_state_unexpected_frame:
                description:
                - "Enable automatic packet-capture for Unxpected frame received in idle state"
                type: bool
            reserved_local_state_unexpected_frame:
                description:
                - "Enable automatic packet-capture for Unexpected frame received in reserved local
          state"
                type: bool
            reserved_remote_state_unexpected_frame:
                description:
                - "Enable automatic packet-capture for Unexpected frame received in reserved
          remote state"
                type: bool
            half_closed_remote_state_unexpected_fra:
                description:
                - "Enable automatic packet-capture for Unexpected frame received in half closed
          remote state"
                type: bool
            closed_state_unexpected_frame:
                description:
                - "Enable automatic packet-capture for Unexpected frame received in closed state"
                type: bool
            zero_window_size_on_stream:
                description:
                - "Enable automatic packet-capture for Window Update with zero increment rcvd"
                type: bool
            exceeds_max_window_size_stream:
                description:
                - "Enable automatic packet-capture for Window Update with increment that results
          in exceeding max window"
                type: bool
            continuation_before_headers:
                description:
                - "Enable automatic packet-capture for CONTINUATION frame with no headers frame"
                type: bool
            invalid_frame_during_headers:
                description:
                - "Enable automatic packet-capture for frame before headers were complete"
                type: bool
            headers_after_continuation:
                description:
                - "Enable automatic packet-capture for headers frame before CONTINUATION was
          complete"
                type: bool
            invalid_push_promise:
                description:
                - "Enable automatic packet-capture for unexpected PUSH_PROMISE frame"
                type: bool
            invalid_stream_id:
                description:
                - "Enable automatic packet-capture for received invalid stream ID"
                type: bool
            headers_interleaved:
                description:
                - "Enable automatic packet-capture for headers interleaved on streams"
                type: bool
            trailers_no_end_stream:
                description:
                - "Enable automatic packet-capture for trailers not marked as end-of-stream"
                type: bool
            invalid_setting_value:
                description:
                - "Enable automatic packet-capture for invalid setting-frame value"
                type: bool
            invalid_window_update:
                description:
                - "Enable automatic packet-capture for window-update value out of range"
                type: bool
            alloc_fail_total:
                description:
                - "Enable automatic packet-capture for Alloc Fail - Total"
                type: bool
            err_rcvd_total:
                description:
                - "Enable automatic packet-capture for Error Rcvd - Total"
                type: bool
            err_sent_total:
                description:
                - "Enable automatic packet-capture for Error Rent - Total"
                type: bool
            err_sent_proto_err:
                description:
                - "Enable automatic packet-capture for Error Sent - PROTOCOL_ERROR"
                type: bool
            err_sent_internal_err:
                description:
                - "Enable automatic packet-capture for Error Sent - INTERNAL_ERROR"
                type: bool
            err_sent_flow_control:
                description:
                - "Enable automatic packet-capture for Error Sent - FLOW_CONTROL_ERROR"
                type: bool
            err_sent_setting_timeout:
                description:
                - "Enable automatic packet-capture for Error Sent - SETTINGS_TIMEOUT"
                type: bool
            err_sent_stream_closed:
                description:
                - "Enable automatic packet-capture for Error Sent - STREAM_CLOSED"
                type: bool
            err_sent_frame_size_err:
                description:
                - "Enable automatic packet-capture for Error Sent - FRAME_SIZE_ERROR"
                type: bool
            err_sent_refused_stream:
                description:
                - "Enable automatic packet-capture for Error Sent - REFUSED_STREAM"
                type: bool
            err_sent_cancel:
                description:
                - "Enable automatic packet-capture for Error Sent - CANCEL"
                type: bool
            err_sent_compression_err:
                description:
                - "Enable automatic packet-capture for Error Sent - COMPRESSION_ERROR"
                type: bool
            err_sent_connect_err:
                description:
                - "Enable automatic packet-capture for Error Sent - CONNECT_ERROR"
                type: bool
            err_sent_your_calm:
                description:
                - "Enable automatic packet-capture for Error Sent - ENHANCE_YOUR_CALM"
                type: bool
            err_sent_inadequate_security:
                description:
                - "Enable automatic packet-capture for Error Sent - INADEQUATE_SECURITY"
                type: bool
            err_sent_http11_required:
                description:
                - "Enable automatic packet-capture for Error Sent - HTTP_1_1_REQUIRED"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    trigger_stats_rate:
        description:
        - "Field trigger_stats_rate"
        type: dict
        required: False
        suboptions:
            threshold_exceeded_by:
                description:
                - "Set the threshold to the number of times greater than the previous duration to
          start the capture, default is 5"
                type: int
            duration:
                description:
                - "Time in seconds to look for the anomaly, default is 60"
                type: int
            protocol_error:
                description:
                - "Enable automatic packet-capture for Protocol Error"
                type: bool
            internal_error:
                description:
                - "Enable automatic packet-capture for Internal Error"
                type: bool
            proxy_alloc_error:
                description:
                - "Enable automatic packet-capture for HTTP2 Proxy alloc Error"
                type: bool
            split_buff_fail:
                description:
                - "Enable automatic packet-capture for Splitting Buffer Failed"
                type: bool
            invalid_frame_size:
                description:
                - "Enable automatic packet-capture for Invalid Frame Size Rcvd"
                type: bool
            error_max_invalid_stream:
                description:
                - "Enable automatic packet-capture for Max Invalid Stream Rcvd"
                type: bool
            data_no_stream:
                description:
                - "Enable automatic packet-capture for DATA Frame Rcvd on non-existent stream"
                type: bool
            flow_control_error:
                description:
                - "Enable automatic packet-capture for Flow Control Error"
                type: bool
            settings_timeout:
                description:
                - "Enable automatic packet-capture for Settings Timeout"
                type: bool
            frame_size_error:
                description:
                - "Enable automatic packet-capture for Frame Size Error"
                type: bool
            refused_stream:
                description:
                - "Enable automatic packet-capture for Refused Stream"
                type: bool
            cancel:
                description:
                - "Enable automatic packet-capture for cancel"
                type: bool
            compression_error:
                description:
                - "Enable automatic packet-capture for compression error"
                type: bool
            connect_error:
                description:
                - "Enable automatic packet-capture for connect error"
                type: bool
            enhance_your_calm:
                description:
                - "Enable automatic packet-capture for enhance your calm error"
                type: bool
            inadequate_security:
                description:
                - "Enable automatic packet-capture for inadequate security"
                type: bool
            http_1_1_required:
                description:
                - "Enable automatic packet-capture for HTTP1.1 Required"
                type: bool
            deflate_alloc_fail:
                description:
                - "Enable automatic packet-capture for deflate alloc fail"
                type: bool
            inflate_alloc_fail:
                description:
                - "Enable automatic packet-capture for inflate alloc fail"
                type: bool
            inflate_header_fail:
                description:
                - "Enable automatic packet-capture for Inflate Header Fail"
                type: bool
            bad_connection_preface:
                description:
                - "Enable automatic packet-capture for Bad Connection Preface"
                type: bool
            cant_allocate_control_frame:
                description:
                - "Enable automatic packet-capture for Cant allocate control frame"
                type: bool
            cant_allocate_settings_frame:
                description:
                - "Enable automatic packet-capture for Cant allocate SETTINGS frame"
                type: bool
            bad_frame_type_for_stream_state:
                description:
                - "Enable automatic packet-capture for Bad frame type for stream state"
                type: bool
            wrong_stream_state:
                description:
                - "Enable automatic packet-capture for Wrong Stream State"
                type: bool
            data_queue_alloc_error:
                description:
                - "Enable automatic packet-capture for Data Queue Alloc Error"
                type: bool
            buff_alloc_error:
                description:
                - "Enable automatic packet-capture for Buff alloc error"
                type: bool
            cant_allocate_rst_frame:
                description:
                - "Enable automatic packet-capture for Cant allocate RST_STREAM frame"
                type: bool
            cant_allocate_goaway_frame:
                description:
                - "Enable automatic packet-capture for Cant allocate GOAWAY frame"
                type: bool
            cant_allocate_ping_frame:
                description:
                - "Enable automatic packet-capture for Cant allocate PING frame"
                type: bool
            cant_allocate_stream:
                description:
                - "Enable automatic packet-capture for Cant allocate stream"
                type: bool
            cant_allocate_window_frame:
                description:
                - "Enable automatic packet-capture for Cant allocate WINDOW_UPDATE frame"
                type: bool
            header_no_stream:
                description:
                - "Enable automatic packet-capture for header no stream"
                type: bool
            header_padlen_gt_frame_payload:
                description:
                - "Enable automatic packet-capture for Header padlen greater than frame payload
          size"
                type: bool
            streams_gt_max_concur_streams:
                description:
                - "Enable automatic packet-capture for Streams greater than max allowed concurrent
          streams"
                type: bool
            idle_state_unexpected_frame:
                description:
                - "Enable automatic packet-capture for Unxpected frame received in idle state"
                type: bool
            reserved_local_state_unexpected_frame:
                description:
                - "Enable automatic packet-capture for Unexpected frame received in reserved local
          state"
                type: bool
            reserved_remote_state_unexpected_frame:
                description:
                - "Enable automatic packet-capture for Unexpected frame received in reserved
          remote state"
                type: bool
            half_closed_remote_state_unexpected_fra:
                description:
                - "Enable automatic packet-capture for Unexpected frame received in half closed
          remote state"
                type: bool
            closed_state_unexpected_frame:
                description:
                - "Enable automatic packet-capture for Unexpected frame received in closed state"
                type: bool
            zero_window_size_on_stream:
                description:
                - "Enable automatic packet-capture for Window Update with zero increment rcvd"
                type: bool
            exceeds_max_window_size_stream:
                description:
                - "Enable automatic packet-capture for Window Update with increment that results
          in exceeding max window"
                type: bool
            continuation_before_headers:
                description:
                - "Enable automatic packet-capture for CONTINUATION frame with no headers frame"
                type: bool
            invalid_frame_during_headers:
                description:
                - "Enable automatic packet-capture for frame before headers were complete"
                type: bool
            headers_after_continuation:
                description:
                - "Enable automatic packet-capture for headers frame before CONTINUATION was
          complete"
                type: bool
            invalid_push_promise:
                description:
                - "Enable automatic packet-capture for unexpected PUSH_PROMISE frame"
                type: bool
            invalid_stream_id:
                description:
                - "Enable automatic packet-capture for received invalid stream ID"
                type: bool
            headers_interleaved:
                description:
                - "Enable automatic packet-capture for headers interleaved on streams"
                type: bool
            trailers_no_end_stream:
                description:
                - "Enable automatic packet-capture for trailers not marked as end-of-stream"
                type: bool
            invalid_setting_value:
                description:
                - "Enable automatic packet-capture for invalid setting-frame value"
                type: bool
            invalid_window_update:
                description:
                - "Enable automatic packet-capture for window-update value out of range"
                type: bool
            alloc_fail_total:
                description:
                - "Enable automatic packet-capture for Alloc Fail - Total"
                type: bool
            err_rcvd_total:
                description:
                - "Enable automatic packet-capture for Error Rcvd - Total"
                type: bool
            err_sent_total:
                description:
                - "Enable automatic packet-capture for Error Rent - Total"
                type: bool
            err_sent_proto_err:
                description:
                - "Enable automatic packet-capture for Error Sent - PROTOCOL_ERROR"
                type: bool
            err_sent_internal_err:
                description:
                - "Enable automatic packet-capture for Error Sent - INTERNAL_ERROR"
                type: bool
            err_sent_flow_control:
                description:
                - "Enable automatic packet-capture for Error Sent - FLOW_CONTROL_ERROR"
                type: bool
            err_sent_setting_timeout:
                description:
                - "Enable automatic packet-capture for Error Sent - SETTINGS_TIMEOUT"
                type: bool
            err_sent_stream_closed:
                description:
                - "Enable automatic packet-capture for Error Sent - STREAM_CLOSED"
                type: bool
            err_sent_frame_size_err:
                description:
                - "Enable automatic packet-capture for Error Sent - FRAME_SIZE_ERROR"
                type: bool
            err_sent_refused_stream:
                description:
                - "Enable automatic packet-capture for Error Sent - REFUSED_STREAM"
                type: bool
            err_sent_cancel:
                description:
                - "Enable automatic packet-capture for Error Sent - CANCEL"
                type: bool
            err_sent_compression_err:
                description:
                - "Enable automatic packet-capture for Error Sent - COMPRESSION_ERROR"
                type: bool
            err_sent_connect_err:
                description:
                - "Enable automatic packet-capture for Error Sent - CONNECT_ERROR"
                type: bool
            err_sent_your_calm:
                description:
                - "Enable automatic packet-capture for Error Sent - ENHANCE_YOUR_CALM"
                type: bool
            err_sent_inadequate_security:
                description:
                - "Enable automatic packet-capture for Error Sent - INADEQUATE_SECURITY"
                type: bool
            err_sent_http11_required:
                description:
                - "Enable automatic packet-capture for Error Sent - HTTP_1_1_REQUIRED"
                type: bool
            uuid:
                description:
                - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["dummy", "trigger_stats_inc", "trigger_stats_rate", "uuid", ]


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
        'dummy': {
            'type': 'bool',
            },
        'uuid': {
            'type': 'str',
            },
        'trigger_stats_inc': {
            'type': 'dict',
            'protocol_error': {
                'type': 'bool',
                },
            'internal_error': {
                'type': 'bool',
                },
            'proxy_alloc_error': {
                'type': 'bool',
                },
            'split_buff_fail': {
                'type': 'bool',
                },
            'invalid_frame_size': {
                'type': 'bool',
                },
            'error_max_invalid_stream': {
                'type': 'bool',
                },
            'data_no_stream': {
                'type': 'bool',
                },
            'flow_control_error': {
                'type': 'bool',
                },
            'settings_timeout': {
                'type': 'bool',
                },
            'frame_size_error': {
                'type': 'bool',
                },
            'refused_stream': {
                'type': 'bool',
                },
            'cancel': {
                'type': 'bool',
                },
            'compression_error': {
                'type': 'bool',
                },
            'connect_error': {
                'type': 'bool',
                },
            'enhance_your_calm': {
                'type': 'bool',
                },
            'inadequate_security': {
                'type': 'bool',
                },
            'http_1_1_required': {
                'type': 'bool',
                },
            'deflate_alloc_fail': {
                'type': 'bool',
                },
            'inflate_alloc_fail': {
                'type': 'bool',
                },
            'inflate_header_fail': {
                'type': 'bool',
                },
            'bad_connection_preface': {
                'type': 'bool',
                },
            'cant_allocate_control_frame': {
                'type': 'bool',
                },
            'cant_allocate_settings_frame': {
                'type': 'bool',
                },
            'bad_frame_type_for_stream_state': {
                'type': 'bool',
                },
            'wrong_stream_state': {
                'type': 'bool',
                },
            'data_queue_alloc_error': {
                'type': 'bool',
                },
            'buff_alloc_error': {
                'type': 'bool',
                },
            'cant_allocate_rst_frame': {
                'type': 'bool',
                },
            'cant_allocate_goaway_frame': {
                'type': 'bool',
                },
            'cant_allocate_ping_frame': {
                'type': 'bool',
                },
            'cant_allocate_stream': {
                'type': 'bool',
                },
            'cant_allocate_window_frame': {
                'type': 'bool',
                },
            'header_no_stream': {
                'type': 'bool',
                },
            'header_padlen_gt_frame_payload': {
                'type': 'bool',
                },
            'streams_gt_max_concur_streams': {
                'type': 'bool',
                },
            'idle_state_unexpected_frame': {
                'type': 'bool',
                },
            'reserved_local_state_unexpected_frame': {
                'type': 'bool',
                },
            'reserved_remote_state_unexpected_frame': {
                'type': 'bool',
                },
            'half_closed_remote_state_unexpected_fra': {
                'type': 'bool',
                },
            'closed_state_unexpected_frame': {
                'type': 'bool',
                },
            'zero_window_size_on_stream': {
                'type': 'bool',
                },
            'exceeds_max_window_size_stream': {
                'type': 'bool',
                },
            'continuation_before_headers': {
                'type': 'bool',
                },
            'invalid_frame_during_headers': {
                'type': 'bool',
                },
            'headers_after_continuation': {
                'type': 'bool',
                },
            'invalid_push_promise': {
                'type': 'bool',
                },
            'invalid_stream_id': {
                'type': 'bool',
                },
            'headers_interleaved': {
                'type': 'bool',
                },
            'trailers_no_end_stream': {
                'type': 'bool',
                },
            'invalid_setting_value': {
                'type': 'bool',
                },
            'invalid_window_update': {
                'type': 'bool',
                },
            'alloc_fail_total': {
                'type': 'bool',
                },
            'err_rcvd_total': {
                'type': 'bool',
                },
            'err_sent_total': {
                'type': 'bool',
                },
            'err_sent_proto_err': {
                'type': 'bool',
                },
            'err_sent_internal_err': {
                'type': 'bool',
                },
            'err_sent_flow_control': {
                'type': 'bool',
                },
            'err_sent_setting_timeout': {
                'type': 'bool',
                },
            'err_sent_stream_closed': {
                'type': 'bool',
                },
            'err_sent_frame_size_err': {
                'type': 'bool',
                },
            'err_sent_refused_stream': {
                'type': 'bool',
                },
            'err_sent_cancel': {
                'type': 'bool',
                },
            'err_sent_compression_err': {
                'type': 'bool',
                },
            'err_sent_connect_err': {
                'type': 'bool',
                },
            'err_sent_your_calm': {
                'type': 'bool',
                },
            'err_sent_inadequate_security': {
                'type': 'bool',
                },
            'err_sent_http11_required': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'trigger_stats_rate': {
            'type': 'dict',
            'threshold_exceeded_by': {
                'type': 'int',
                },
            'duration': {
                'type': 'int',
                },
            'protocol_error': {
                'type': 'bool',
                },
            'internal_error': {
                'type': 'bool',
                },
            'proxy_alloc_error': {
                'type': 'bool',
                },
            'split_buff_fail': {
                'type': 'bool',
                },
            'invalid_frame_size': {
                'type': 'bool',
                },
            'error_max_invalid_stream': {
                'type': 'bool',
                },
            'data_no_stream': {
                'type': 'bool',
                },
            'flow_control_error': {
                'type': 'bool',
                },
            'settings_timeout': {
                'type': 'bool',
                },
            'frame_size_error': {
                'type': 'bool',
                },
            'refused_stream': {
                'type': 'bool',
                },
            'cancel': {
                'type': 'bool',
                },
            'compression_error': {
                'type': 'bool',
                },
            'connect_error': {
                'type': 'bool',
                },
            'enhance_your_calm': {
                'type': 'bool',
                },
            'inadequate_security': {
                'type': 'bool',
                },
            'http_1_1_required': {
                'type': 'bool',
                },
            'deflate_alloc_fail': {
                'type': 'bool',
                },
            'inflate_alloc_fail': {
                'type': 'bool',
                },
            'inflate_header_fail': {
                'type': 'bool',
                },
            'bad_connection_preface': {
                'type': 'bool',
                },
            'cant_allocate_control_frame': {
                'type': 'bool',
                },
            'cant_allocate_settings_frame': {
                'type': 'bool',
                },
            'bad_frame_type_for_stream_state': {
                'type': 'bool',
                },
            'wrong_stream_state': {
                'type': 'bool',
                },
            'data_queue_alloc_error': {
                'type': 'bool',
                },
            'buff_alloc_error': {
                'type': 'bool',
                },
            'cant_allocate_rst_frame': {
                'type': 'bool',
                },
            'cant_allocate_goaway_frame': {
                'type': 'bool',
                },
            'cant_allocate_ping_frame': {
                'type': 'bool',
                },
            'cant_allocate_stream': {
                'type': 'bool',
                },
            'cant_allocate_window_frame': {
                'type': 'bool',
                },
            'header_no_stream': {
                'type': 'bool',
                },
            'header_padlen_gt_frame_payload': {
                'type': 'bool',
                },
            'streams_gt_max_concur_streams': {
                'type': 'bool',
                },
            'idle_state_unexpected_frame': {
                'type': 'bool',
                },
            'reserved_local_state_unexpected_frame': {
                'type': 'bool',
                },
            'reserved_remote_state_unexpected_frame': {
                'type': 'bool',
                },
            'half_closed_remote_state_unexpected_fra': {
                'type': 'bool',
                },
            'closed_state_unexpected_frame': {
                'type': 'bool',
                },
            'zero_window_size_on_stream': {
                'type': 'bool',
                },
            'exceeds_max_window_size_stream': {
                'type': 'bool',
                },
            'continuation_before_headers': {
                'type': 'bool',
                },
            'invalid_frame_during_headers': {
                'type': 'bool',
                },
            'headers_after_continuation': {
                'type': 'bool',
                },
            'invalid_push_promise': {
                'type': 'bool',
                },
            'invalid_stream_id': {
                'type': 'bool',
                },
            'headers_interleaved': {
                'type': 'bool',
                },
            'trailers_no_end_stream': {
                'type': 'bool',
                },
            'invalid_setting_value': {
                'type': 'bool',
                },
            'invalid_window_update': {
                'type': 'bool',
                },
            'alloc_fail_total': {
                'type': 'bool',
                },
            'err_rcvd_total': {
                'type': 'bool',
                },
            'err_sent_total': {
                'type': 'bool',
                },
            'err_sent_proto_err': {
                'type': 'bool',
                },
            'err_sent_internal_err': {
                'type': 'bool',
                },
            'err_sent_flow_control': {
                'type': 'bool',
                },
            'err_sent_setting_timeout': {
                'type': 'bool',
                },
            'err_sent_stream_closed': {
                'type': 'bool',
                },
            'err_sent_frame_size_err': {
                'type': 'bool',
                },
            'err_sent_refused_stream': {
                'type': 'bool',
                },
            'err_sent_cancel': {
                'type': 'bool',
                },
            'err_sent_compression_err': {
                'type': 'bool',
                },
            'err_sent_connect_err': {
                'type': 'bool',
                },
            'err_sent_your_calm': {
                'type': 'bool',
                },
            'err_sent_inadequate_security': {
                'type': 'bool',
                },
            'err_sent_http11_required': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            }
        })
    # Parent keys
    rv.update(dict(template_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/packet-capture/global-templates/template/{template_name}/trigger-sys-obj-stats-change/slb-http2"

    f_dict = {}
    if '/' in module.params["template_name"]:
        f_dict["template_name"] = module.params["template_name"].replace("/", "%2F")
    else:
        f_dict["template_name"] = module.params["template_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/packet-capture/global-templates/template/{template_name}/trigger-sys-obj-stats-change/slb-http2"

    f_dict = {}
    f_dict["template_name"] = module.params["template_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["slb-http2"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["slb-http2"].get(k) != v:
            change_results["changed"] = True
            config_changes["slb-http2"][k] = v

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
    payload = utils.build_json("slb-http2", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["slb-http2"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["slb-http2-list"] if info != "NotFound" else info
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
