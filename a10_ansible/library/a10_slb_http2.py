#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_slb_http2
description:
    - Configure http2
short_description: Configures A10 slb.http2
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
            cpu_count:
                description:
                - "Field cpu_count"
            http2_cpu_list:
                description:
                - "Field http2_cpu_list"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'curr_proxy'= Curr Proxy Conns; 'total_proxy'= Total Proxy Conns; 'connection_preface_rcvd'= Connection preface rcvd; 'control_frame'= Control Frame Rcvd; 'headers_frame'= HEADERS Frame Rcvd; 'continuation_frame'= CONTINUATION Frame Rcvd; 'rst_frame_rcvd'= RST_STREAM Frame Rcvd; 'settings_frame'= SETTINGS Frame Rcvd; 'window_update_frame'= WINDOW_UPDATE Frame Rcvd; 'ping_frame'= PING Frame Rcvd; 'goaway_frame'= GOAWAY Frame Rcvd; 'priority_frame'= PRIORITY Frame Rcvd; 'data_frame'= DATA Frame Recvd; 'unknown_frame'= Unknown Frame Recvd; 'connection_preface_sent'= Connection preface sent; 'settings_frame_sent'= SETTINGS Frame Sent; 'settings_ack_sent'= SETTINGS ACK Frame Sent; 'empty_settings_sent'= Empty SETTINGS Frame Sent; 'ping_frame_sent'= PING Frame Sent; 'window_update_frame_sent'= WINDOW_UPDATE Frame Sent; 'rst_frame_sent'= RST_STREAM Frame Sent; 'goaway_frame_sent'= GOAWAY Frame Sent; 'header_to_app'= HEADER Frame to HTTP; 'data_to_app'= DATA Frame to HTTP; 'protocol_error'= Protocol Error; 'internal_error'= Internal Error; 'proxy_alloc_error'= HTTP2 Proxy alloc Error; 'split_buff_fail'= Splitting Buffer Failed; 'invalid_frame_size'= Invalid Frame Size Rcvd; 'error_max_invalid_stream'= Max Invalid Stream Rcvd; 'data_no_stream'= DATA Frame Rcvd on non-existent stream; 'flow_control_error'= Flow Control Error; 'settings_timeout'= Settings Timeout; 'frame_size_error'= Frame Size Error; 'refused_stream'= Refused Stream; 'cancel'= cancel; 'compression_error'= compression error; 'connect_error'= connect error; 'enhance_your_calm'= enhance your calm error; 'inadequate_security'= inadequate security; 'http_1_1_required'= HTTP1.1 Required; 'deflate_alloc_fail'= deflate alloc fail; 'inflate_alloc_fail'= inflate alloc fail; 'inflate_header_fail'= Inflate Header Fail; 'bad_connection_preface'= Bad Connection Preface; 'cant_allocate_control_frame'= Cant allocate control frame; 'cant_allocate_settings_frame'= Cant allocate SETTINGS frame; 'bad_frame_type_for_stream_state'= Bad frame type for stream state; 'wrong_stream_state'= Wrong Stream State; 'data_queue_alloc_error'= Data Queue Alloc Error; 'buff_alloc_error'= Buff alloc error; 'cant_allocate_rst_frame'= Cant allocate RST_STREAM frame; 'cant_allocate_goaway_frame'= Cant allocate GOAWAY frame; 'cant_allocate_ping_frame'= Cant allocate PING frame; 'cant_allocate_stream'= Cant allocate stream; 'cant_allocate_window_frame'= Cant allocate WINDOW_UPDATE frame; 'header_no_stream'= header no stream; 'header_padlen_gt_frame_payload'= Header padlen greater than frame payload size; 'streams_gt_max_concur_streams'= Streams greater than max allowed concurrent streams; 'idle_state_unexpected_frame'= Unxpected frame received in idle state; 'reserved_local_state_unexpected_frame'= Unexpected frame received in reserved local state; 'reserved_remote_state_unexpected_frame'= Unexpected frame received in reserved remote state; 'half_closed_remote_state_unexpected_frame'= Unexpected frame received in half closed remote state; 'closed_state_unexpected_frame'= Unexpected frame received in closed state; 'zero_window_size_on_stream'= Window Update with zero increment rcvd; 'exceeds_max_window_size_stream'= Window Update with increment that results in exceeding max window; 'stream_closed'= stream closed; 'continuation_before_headers'= CONTINUATION frame with no headers frame; 'invalid_frame_during_headers'= frame before headers were complete; 'headers_after_continuation'= headers frame before CONTINUATION was complete; 'invalid_push_promise'= unexpected PUSH_PROMISE frame; 'invalid_stream_id'= received invalid stream ID; 'headers_interleaved'= headers interleaved on streams; 'trailers_no_end_stream'= trailers not marked as end-of-stream; 'invalid_setting_value'= invalid setting-frame value; 'invalid_window_update'= window-update value out of range; 'frame_header_bytes_received'= frame header bytes received; 'frame_header_bytes_sent'= frame header bytes sent; 'control_bytes_received'= HTTP/2 control frame bytes received; 'control_bytes_sent'= HTTP/2 control frame bytes sent; 'header_bytes_received'= HTTP/2 header bytes received; 'header_bytes_sent'= HTTP/2 header bytes sent; 'data_bytes_received'= HTTP/2 data bytes received; 'data_bytes_sent'= HTTP/2 data bytes sent; 'total_bytes_received'= HTTP/2 total bytes received; 'total_bytes_sent'= HTTP/2 total bytes sent; 'peak_proxy'= Peak Proxy Conns; 'control_frame_sent'= Control Frame Sent; 'continuation_frame_sent'= CONTINUATION Frame Sent; 'data_frame_sent'= DATA Frame Sent; 'headers_frame_sent'= HEADERS Frame Sent; 'priority_frame_sent'= PRIORITY Frame Sent; 'settings_ack_rcvd'= SETTINGS ACK Frame Rcvd; 'empty_settings_rcvd'= Empty SETTINGS Frame Rcvd; 'alloc_fail_total'= Alloc Fail - Total; 'err_rcvd_total'= Error Rcvd - Total; 'err_sent_total'= Error Rent - Total; 'err_sent_proto_err'= Error Sent - PROTOCOL_ERROR; 'err_sent_internal_err'= Error Sent - INTERNAL_ERROR; 'err_sent_flow_control'= Error Sent - FLOW_CONTROL_ERROR; 'err_sent_setting_timeout'= Error Sent - SETTINGS_TIMEOUT; 'err_sent_stream_closed'= Error Sent - STREAM_CLOSED; 'err_sent_frame_size_err'= Error Sent - FRAME_SIZE_ERROR; 'err_sent_refused_stream'= Error Sent - REFUSED_STREAM; 'err_sent_cancel'= Error Sent - CANCEL; 'err_sent_compression_err'= Error Sent - COMPRESSION_ERROR; 'err_sent_connect_err'= Error Sent - CONNECT_ERROR; 'err_sent_your_calm'= Error Sent - ENHANCE_YOUR_CALM; 'err_sent_inadequate_security'= Error Sent - INADEQUATE_SECURITY; 'err_sent_http11_required'= Error Sent - HTTP_1_1_REQUIRED; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            total_proxy:
                description:
                - "Total Proxy Conns"
            headers_frame:
                description:
                - "HEADERS Frame Rcvd"
            cant_allocate_ping_frame:
                description:
                - "Cant allocate PING frame"
            err_sent_inadequate_security:
                description:
                - "Error Sent - INADEQUATE_SECURITY"
            err_sent_frame_size_err:
                description:
                - "Error Sent - FRAME_SIZE_ERROR"
            headers_after_continuation:
                description:
                - "headers frame before CONTINUATION was complete"
            invalid_window_update:
                description:
                - "window-update value out of range"
            goaway_frame:
                description:
                - "GOAWAY Frame Rcvd"
            refused_stream:
                description:
                - "Refused Stream"
            control_frame:
                description:
                - "Control Frame Rcvd"
            data_no_stream:
                description:
                - "DATA Frame Rcvd on non-existent stream"
            rst_frame_rcvd:
                description:
                - "RST_STREAM Frame Rcvd"
            half_closed_remote_state_unexpected_frame:
                description:
                - "Unexpected frame received in half closed remote state"
            reserved_local_state_unexpected_frame:
                description:
                - "Unexpected frame received in reserved local state"
            http_1_1_required:
                description:
                - "HTTP1.1 Required"
            continuation_frame:
                description:
                - "CONTINUATION Frame Rcvd"
            cant_allocate_settings_frame:
                description:
                - "Cant allocate SETTINGS frame"
            connection_preface_sent:
                description:
                - "Connection preface sent"
            settings_frame:
                description:
                - "SETTINGS Frame Rcvd"
            unknown_frame:
                description:
                - "Unknown Frame Recvd"
            streams_gt_max_concur_streams:
                description:
                - "Streams greater than max allowed concurrent streams"
            bad_connection_preface:
                description:
                - "Bad Connection Preface"
            error_max_invalid_stream:
                description:
                - "Max Invalid Stream Rcvd"
            stream_closed:
                description:
                - "stream closed"
            header_padlen_gt_frame_payload:
                description:
                - "Header padlen greater than frame payload size"
            protocol_error:
                description:
                - "Protocol Error"
            split_buff_fail:
                description:
                - "Splitting Buffer Failed"
            invalid_stream_id:
                description:
                - "received invalid stream ID"
            inflate_alloc_fail:
                description:
                - "inflate alloc fail"
            cancel:
                description:
                - "cancel"
            err_sent_http11_required:
                description:
                - "Error Sent - HTTP_1_1_REQUIRED"
            err_sent_your_calm:
                description:
                - "Error Sent - ENHANCE_YOUR_CALM"
            trailers_no_end_stream:
                description:
                - "trailers not marked as end-of-stream"
            wrong_stream_state:
                description:
                - "Wrong Stream State"
            idle_state_unexpected_frame:
                description:
                - "Unxpected frame received in idle state"
            frame_header_bytes_received:
                description:
                - "frame header bytes received"
            inflate_header_fail:
                description:
                - "Inflate Header Fail"
            ping_frame:
                description:
                - "PING Frame Rcvd"
            data_bytes_sent:
                description:
                - "HTTP/2 data bytes sent"
            header_to_app:
                description:
                - "HEADER Frame to HTTP"
            total_bytes_sent:
                description:
                - "HTTP/2 total bytes sent"
            peak_proxy:
                description:
                - "Peak Proxy Conns"
            err_sent_setting_timeout:
                description:
                - "Error Sent - SETTINGS_TIMEOUT"
            ping_frame_sent:
                description:
                - "PING Frame Sent"
            invalid_frame_during_headers:
                description:
                - "frame before headers were complete"
            reserved_remote_state_unexpected_frame:
                description:
                - "Unexpected frame received in reserved remote state"
            priority_frame_sent:
                description:
                - "PRIORITY Frame Sent"
            curr_proxy:
                description:
                - "Curr Proxy Conns"
            deflate_alloc_fail:
                description:
                - "deflate alloc fail"
            settings_frame_sent:
                description:
                - "SETTINGS Frame Sent"
            compression_error:
                description:
                - "compression error"
            settings_timeout:
                description:
                - "Settings Timeout"
            empty_settings_rcvd:
                description:
                - "Empty SETTINGS Frame Rcvd"
            err_sent_total:
                description:
                - "Error Rent - Total"
            control_bytes_received:
                description:
                - "HTTP/2 control frame bytes received"
            continuation_before_headers:
                description:
                - "CONTINUATION frame with no headers frame"
            err_sent_stream_closed:
                description:
                - "Error Sent - STREAM_CLOSED"
            bad_frame_type_for_stream_state:
                description:
                - "Bad frame type for stream state"
            err_sent_refused_stream:
                description:
                - "Error Sent - REFUSED_STREAM"
            connect_error:
                description:
                - "connect error"
            data_frame_sent:
                description:
                - "DATA Frame Sent"
            proxy_alloc_error:
                description:
                - "HTTP2 Proxy alloc Error"
            cant_allocate_goaway_frame:
                description:
                - "Cant allocate GOAWAY frame"
            buff_alloc_error:
                description:
                - "Buff alloc error"
            window_update_frame:
                description:
                - "WINDOW_UPDATE Frame Rcvd"
            err_sent_flow_control:
                description:
                - "Error Sent - FLOW_CONTROL_ERROR"
            inadequate_security:
                description:
                - "inadequate security"
            zero_window_size_on_stream:
                description:
                - "Window Update with zero increment rcvd"
            frame_header_bytes_sent:
                description:
                - "frame header bytes sent"
            cant_allocate_window_frame:
                description:
                - "Cant allocate WINDOW_UPDATE frame"
            control_frame_sent:
                description:
                - "Control Frame Sent"
            goaway_frame_sent:
                description:
                - "GOAWAY Frame Sent"
            window_update_frame_sent:
                description:
                - "WINDOW_UPDATE Frame Sent"
            rst_frame_sent:
                description:
                - "RST_STREAM Frame Sent"
            invalid_frame_size:
                description:
                - "Invalid Frame Size Rcvd"
            header_no_stream:
                description:
                - "header no stream"
            settings_ack_rcvd:
                description:
                - "SETTINGS ACK Frame Rcvd"
            data_queue_alloc_error:
                description:
                - "Data Queue Alloc Error"
            err_sent_compression_err:
                description:
                - "Error Sent - COMPRESSION_ERROR"
            internal_error:
                description:
                - "Internal Error"
            header_bytes_sent:
                description:
                - "HTTP/2 header bytes sent"
            empty_settings_sent:
                description:
                - "Empty SETTINGS Frame Sent"
            err_sent_cancel:
                description:
                - "Error Sent - CANCEL"
            continuation_frame_sent:
                description:
                - "CONTINUATION Frame Sent"
            total_bytes_received:
                description:
                - "HTTP/2 total bytes received"
            priority_frame:
                description:
                - "PRIORITY Frame Rcvd"
            enhance_your_calm:
                description:
                - "enhance your calm error"
            data_to_app:
                description:
                - "DATA Frame to HTTP"
            cant_allocate_rst_frame:
                description:
                - "Cant allocate RST_STREAM frame"
            cant_allocate_control_frame:
                description:
                - "Cant allocate control frame"
            flow_control_error:
                description:
                - "Flow Control Error"
            control_bytes_sent:
                description:
                - "HTTP/2 control frame bytes sent"
            invalid_push_promise:
                description:
                - "unexpected PUSH_PROMISE frame"
            closed_state_unexpected_frame:
                description:
                - "Unexpected frame received in closed state"
            err_sent_connect_err:
                description:
                - "Error Sent - CONNECT_ERROR"
            header_bytes_received:
                description:
                - "HTTP/2 header bytes received"
            data_bytes_received:
                description:
                - "HTTP/2 data bytes received"
            settings_ack_sent:
                description:
                - "SETTINGS ACK Frame Sent"
            connection_preface_rcvd:
                description:
                - "Connection preface rcvd"
            exceeds_max_window_size_stream:
                description:
                - "Window Update with increment that results in exceeding max window"
            cant_allocate_stream:
                description:
                - "Cant allocate stream"
            data_frame:
                description:
                - "DATA Frame Recvd"
            invalid_setting_value:
                description:
                - "invalid setting-frame value"
            err_rcvd_total:
                description:
                - "Error Rcvd - Total"
            frame_size_error:
                description:
                - "Frame Size Error"
            err_sent_internal_err:
                description:
                - "Error Sent - INTERNAL_ERROR"
            alloc_fail_total:
                description:
                - "Alloc Fail - Total"
            err_sent_proto_err:
                description:
                - "Error Sent - PROTOCOL_ERROR"
            headers_frame_sent:
                description:
                - "HEADERS Frame Sent"
            headers_interleaved:
                description:
                - "headers interleaved on streams"
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
        state=dict(type='str', default="present", choices=["present", "absent", "noop"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict', cpu_count=dict(type='int', ),http2_cpu_list=dict(type='list', total_proxy=dict(type='int', ),headers_frame=dict(type='int', ),cant_allocate_ping_frame=dict(type='int', ),err_sent_inadequate_security=dict(type='int', ),err_sent_frame_size_err=dict(type='int', ),headers_after_continuation=dict(type='int', ),invalid_window_update=dict(type='int', ),goaway_frame=dict(type='int', ),refused_stream=dict(type='int', ),control_frame=dict(type='int', ),data_no_stream=dict(type='int', ),rst_frame_rcvd=dict(type='int', ),half_closed_remote_state_unexpected_frame=dict(type='int', ),reserved_local_state_unexpected_frame=dict(type='int', ),http_1_1_required=dict(type='int', ),continuation_frame=dict(type='int', ),cant_allocate_settings_frame=dict(type='int', ),connection_preface_sent=dict(type='int', ),settings_frame=dict(type='int', ),unknown_frame=dict(type='int', ),streams_gt_max_concur_streams=dict(type='int', ),bad_connection_preface=dict(type='int', ),error_max_invalid_stream=dict(type='int', ),stream_closed=dict(type='int', ),header_padlen_gt_frame_payload=dict(type='int', ),protocol_error=dict(type='int', ),split_buff_fail=dict(type='int', ),invalid_stream_id=dict(type='int', ),inflate_alloc_fail=dict(type='int', ),cancel=dict(type='int', ),err_sent_http11_required=dict(type='int', ),err_sent_your_calm=dict(type='int', ),trailers_no_end_stream=dict(type='int', ),wrong_stream_state=dict(type='int', ),idle_state_unexpected_frame=dict(type='int', ),frame_header_bytes_received=dict(type='int', ),inflate_header_fail=dict(type='int', ),ping_frame=dict(type='int', ),data_bytes_sent=dict(type='int', ),header_to_app=dict(type='int', ),total_bytes_sent=dict(type='int', ),peak_proxy=dict(type='int', ),err_sent_setting_timeout=dict(type='int', ),ping_frame_sent=dict(type='int', ),invalid_frame_during_headers=dict(type='int', ),reserved_remote_state_unexpected_frame=dict(type='int', ),priority_frame_sent=dict(type='int', ),curr_proxy=dict(type='int', ),deflate_alloc_fail=dict(type='int', ),settings_frame_sent=dict(type='int', ),compression_error=dict(type='int', ),settings_timeout=dict(type='int', ),empty_settings_rcvd=dict(type='int', ),err_sent_total=dict(type='int', ),control_bytes_received=dict(type='int', ),continuation_before_headers=dict(type='int', ),err_sent_stream_closed=dict(type='int', ),bad_frame_type_for_stream_state=dict(type='int', ),err_sent_refused_stream=dict(type='int', ),connect_error=dict(type='int', ),data_frame_sent=dict(type='int', ),proxy_alloc_error=dict(type='int', ),cant_allocate_goaway_frame=dict(type='int', ),err_sent_compression_err=dict(type='int', ),buff_alloc_error=dict(type='int', ),window_update_frame=dict(type='int', ),err_sent_flow_control=dict(type='int', ),inadequate_security=dict(type='int', ),zero_window_size_on_stream=dict(type='int', ),cant_allocate_window_frame=dict(type='int', ),control_frame_sent=dict(type='int', ),goaway_frame_sent=dict(type='int', ),window_update_frame_sent=dict(type='int', ),rst_frame_sent=dict(type='int', ),invalid_frame_size=dict(type='int', ),settings_ack_rcvd=dict(type='int', ),header_no_stream=dict(type='int', ),data_queue_alloc_error=dict(type='int', ),frame_header_bytes_sent=dict(type='int', ),internal_error=dict(type='int', ),header_bytes_sent=dict(type='int', ),empty_settings_sent=dict(type='int', ),err_sent_cancel=dict(type='int', ),continuation_frame_sent=dict(type='int', ),total_bytes_received=dict(type='int', ),priority_frame=dict(type='int', ),enhance_your_calm=dict(type='int', ),data_to_app=dict(type='int', ),cant_allocate_rst_frame=dict(type='int', ),cant_allocate_control_frame=dict(type='int', ),flow_control_error=dict(type='int', ),control_bytes_sent=dict(type='int', ),invalid_push_promise=dict(type='int', ),closed_state_unexpected_frame=dict(type='int', ),err_sent_connect_err=dict(type='int', ),header_bytes_received=dict(type='int', ),data_bytes_received=dict(type='int', ),settings_ack_sent=dict(type='int', ),connection_preface_rcvd=dict(type='int', ),exceeds_max_window_size_stream=dict(type='int', ),cant_allocate_stream=dict(type='int', ),data_frame=dict(type='int', ),invalid_setting_value=dict(type='int', ),err_rcvd_total=dict(type='int', ),frame_size_error=dict(type='int', ),err_sent_internal_err=dict(type='int', ),alloc_fail_total=dict(type='int', ),err_sent_proto_err=dict(type='int', ),headers_frame_sent=dict(type='int', ),headers_interleaved=dict(type='int', ))),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all','curr_proxy','total_proxy','connection_preface_rcvd','control_frame','headers_frame','continuation_frame','rst_frame_rcvd','settings_frame','window_update_frame','ping_frame','goaway_frame','priority_frame','data_frame','unknown_frame','connection_preface_sent','settings_frame_sent','settings_ack_sent','empty_settings_sent','ping_frame_sent','window_update_frame_sent','rst_frame_sent','goaway_frame_sent','header_to_app','data_to_app','protocol_error','internal_error','proxy_alloc_error','split_buff_fail','invalid_frame_size','error_max_invalid_stream','data_no_stream','flow_control_error','settings_timeout','frame_size_error','refused_stream','cancel','compression_error','connect_error','enhance_your_calm','inadequate_security','http_1_1_required','deflate_alloc_fail','inflate_alloc_fail','inflate_header_fail','bad_connection_preface','cant_allocate_control_frame','cant_allocate_settings_frame','bad_frame_type_for_stream_state','wrong_stream_state','data_queue_alloc_error','buff_alloc_error','cant_allocate_rst_frame','cant_allocate_goaway_frame','cant_allocate_ping_frame','cant_allocate_stream','cant_allocate_window_frame','header_no_stream','header_padlen_gt_frame_payload','streams_gt_max_concur_streams','idle_state_unexpected_frame','reserved_local_state_unexpected_frame','reserved_remote_state_unexpected_frame','half_closed_remote_state_unexpected_frame','closed_state_unexpected_frame','zero_window_size_on_stream','exceeds_max_window_size_stream','stream_closed','continuation_before_headers','invalid_frame_during_headers','headers_after_continuation','invalid_push_promise','invalid_stream_id','headers_interleaved','trailers_no_end_stream','invalid_setting_value','invalid_window_update','frame_header_bytes_received','frame_header_bytes_sent','control_bytes_received','control_bytes_sent','header_bytes_received','header_bytes_sent','data_bytes_received','data_bytes_sent','total_bytes_received','total_bytes_sent','peak_proxy','control_frame_sent','continuation_frame_sent','data_frame_sent','headers_frame_sent','priority_frame_sent','settings_ack_rcvd','empty_settings_rcvd','alloc_fail_total','err_rcvd_total','err_sent_total','err_sent_proto_err','err_sent_internal_err','err_sent_flow_control','err_sent_setting_timeout','err_sent_stream_closed','err_sent_frame_size_err','err_sent_refused_stream','err_sent_cancel','err_sent_compression_err','err_sent_connect_err','err_sent_your_calm','err_sent_inadequate_security','err_sent_http11_required'])),
        stats=dict(type='dict', total_proxy=dict(type='str', ),headers_frame=dict(type='str', ),cant_allocate_ping_frame=dict(type='str', ),err_sent_inadequate_security=dict(type='str', ),err_sent_frame_size_err=dict(type='str', ),headers_after_continuation=dict(type='str', ),invalid_window_update=dict(type='str', ),goaway_frame=dict(type='str', ),refused_stream=dict(type='str', ),control_frame=dict(type='str', ),data_no_stream=dict(type='str', ),rst_frame_rcvd=dict(type='str', ),half_closed_remote_state_unexpected_frame=dict(type='str', ),reserved_local_state_unexpected_frame=dict(type='str', ),http_1_1_required=dict(type='str', ),continuation_frame=dict(type='str', ),cant_allocate_settings_frame=dict(type='str', ),connection_preface_sent=dict(type='str', ),settings_frame=dict(type='str', ),unknown_frame=dict(type='str', ),streams_gt_max_concur_streams=dict(type='str', ),bad_connection_preface=dict(type='str', ),error_max_invalid_stream=dict(type='str', ),stream_closed=dict(type='str', ),header_padlen_gt_frame_payload=dict(type='str', ),protocol_error=dict(type='str', ),split_buff_fail=dict(type='str', ),invalid_stream_id=dict(type='str', ),inflate_alloc_fail=dict(type='str', ),cancel=dict(type='str', ),err_sent_http11_required=dict(type='str', ),err_sent_your_calm=dict(type='str', ),trailers_no_end_stream=dict(type='str', ),wrong_stream_state=dict(type='str', ),idle_state_unexpected_frame=dict(type='str', ),frame_header_bytes_received=dict(type='str', ),inflate_header_fail=dict(type='str', ),ping_frame=dict(type='str', ),data_bytes_sent=dict(type='str', ),header_to_app=dict(type='str', ),total_bytes_sent=dict(type='str', ),peak_proxy=dict(type='str', ),err_sent_setting_timeout=dict(type='str', ),ping_frame_sent=dict(type='str', ),invalid_frame_during_headers=dict(type='str', ),reserved_remote_state_unexpected_frame=dict(type='str', ),priority_frame_sent=dict(type='str', ),curr_proxy=dict(type='str', ),deflate_alloc_fail=dict(type='str', ),settings_frame_sent=dict(type='str', ),compression_error=dict(type='str', ),settings_timeout=dict(type='str', ),empty_settings_rcvd=dict(type='str', ),err_sent_total=dict(type='str', ),control_bytes_received=dict(type='str', ),continuation_before_headers=dict(type='str', ),err_sent_stream_closed=dict(type='str', ),bad_frame_type_for_stream_state=dict(type='str', ),err_sent_refused_stream=dict(type='str', ),connect_error=dict(type='str', ),data_frame_sent=dict(type='str', ),proxy_alloc_error=dict(type='str', ),cant_allocate_goaway_frame=dict(type='str', ),buff_alloc_error=dict(type='str', ),window_update_frame=dict(type='str', ),err_sent_flow_control=dict(type='str', ),inadequate_security=dict(type='str', ),zero_window_size_on_stream=dict(type='str', ),frame_header_bytes_sent=dict(type='str', ),cant_allocate_window_frame=dict(type='str', ),control_frame_sent=dict(type='str', ),goaway_frame_sent=dict(type='str', ),window_update_frame_sent=dict(type='str', ),rst_frame_sent=dict(type='str', ),invalid_frame_size=dict(type='str', ),header_no_stream=dict(type='str', ),settings_ack_rcvd=dict(type='str', ),data_queue_alloc_error=dict(type='str', ),err_sent_compression_err=dict(type='str', ),internal_error=dict(type='str', ),header_bytes_sent=dict(type='str', ),empty_settings_sent=dict(type='str', ),err_sent_cancel=dict(type='str', ),continuation_frame_sent=dict(type='str', ),total_bytes_received=dict(type='str', ),priority_frame=dict(type='str', ),enhance_your_calm=dict(type='str', ),data_to_app=dict(type='str', ),cant_allocate_rst_frame=dict(type='str', ),cant_allocate_control_frame=dict(type='str', ),flow_control_error=dict(type='str', ),control_bytes_sent=dict(type='str', ),invalid_push_promise=dict(type='str', ),closed_state_unexpected_frame=dict(type='str', ),err_sent_connect_err=dict(type='str', ),header_bytes_received=dict(type='str', ),data_bytes_received=dict(type='str', ),settings_ack_sent=dict(type='str', ),connection_preface_rcvd=dict(type='str', ),exceeds_max_window_size_stream=dict(type='str', ),cant_allocate_stream=dict(type='str', ),data_frame=dict(type='str', ),invalid_setting_value=dict(type='str', ),err_rcvd_total=dict(type='str', ),frame_size_error=dict(type='str', ),err_sent_internal_err=dict(type='str', ),alloc_fail_total=dict(type='str', ),err_sent_proto_err=dict(type='str', ),headers_frame_sent=dict(type='str', ),headers_interleaved=dict(type='str', )),
        uuid=dict(type='str', )
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/http2"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/http2"

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

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["http2"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["http2"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["http2"][k] = v
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
    payload = build_json("http2", module)
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