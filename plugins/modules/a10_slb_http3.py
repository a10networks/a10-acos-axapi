#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_http3
description:
    - Configure http3
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
                - "'all'= all; 'client_conn_curr'= Current HTTP/3 Client Connections;
          'server_conn_curr'= Current HTTP/3 Server Connections; 'client_conn_total'=
          Total HTTP/3 Client Connections; 'server_conn_total'= Total HTTP/3 Server
          Connections; 'client_conn_peak'= Peak HTTP/3 Client Connections;
          'server_conn_peak'= Peak HTTP/3 Server Connections;
          'client_request_streams_curr'= Current Request Streams on client side;
          'server_request_streams_curr'= Current Request Streams on server side;
          'client_request_streams_total'= Total Request Streams on client side;
          'server_request_streams_total'= Total Request Streams on server side;
          'client_request_push_curr'= Current Push Streams on client side;
          'server_request_push_curr'= Current Push Streams on server side;
          'client_request_push_total'= Total Push Streams on client side;
          'server_request_push_total'= Total Push Streams on server side;
          'client_request_other_curr'= Current Other Streams on client side (control,
          decoder, encoder); 'server_request_other_curr'= urrent Other Streams on server
          side (control, decoder, encoder); 'client_request_other_total'= Total Other
          Streams on client side (control, decoder, encoder);
          'server_request_other_total'= Total Other Streams on server side (control,
          decoder, encoder); 'client_frame_type_headers_rcvd'= HEADERS Frame received on
          client side; 'client_frame_type_headers_sent'= HEADERS Frame sent on client
          side; 'client_frame_type_data_rcvd'= DATA Frame received on client side;
          'client_frame_type_data_sent'= DATA Frame sent on client side;
          'client_frame_type_cancel_push_rcvd'= CANCEL PUSH Frame received on client
          side; 'client_frame_type_cancel_push_sent'= CANCEL PUSH Frame sent on client
          side; 'client_frame_type_settings_rcvd'= SETTINGS Frame received on client
          side; 'client_frame_type_settings_sent'= SETTINGS Frame sent on client side;
          'client_frame_type_push_promise_rcvd'= PUSH PROMISE Frame received on client
          side; 'client_frame_type_push_promise_sent'= PUSH PROMISE Frame sent on client
          side; 'client_frame_type_goaway_rcvd'= GOAWAY Frame received on client side;
          'client_frame_type_goaway_sent'= GOAWAY Frame sent on client side;
          'client_frame_type_max_push_id_rcvd'= MAX PUSH ID Frame received on client
          side; 'client_frame_type_max_push_id_sent'= MAX PUSH ID Frame sent on client
          side; 'client_frame_type_unknown_rcvd'= Unknown Frame received on client side;
          'client_header_frames_to_app'= HEADER Frames passed to HTTP layer on client
          side; 'client_data_frames_to_app'= DATA Frames passed to HTTP layer on client
          side; 'client_header_bytes_rcvd'= Bytes received in HEADER frames on client
          side; 'client_header_bytes_sent'= Bytes sent in HEADER frames on client side;
          'client_data_bytes_rcvd'= Bytes received in DATA frames on client side;
          'client_data_bytes_sent'= Bytes sent in DATA frames on client side;
          'client_other_frame_bytes_rcvd'= Bytes received in other frames (SETTINGS,
          GOAWAY, PUSH_PROMISE etc) on client side; 'client_other_frame_bytes_sent'=
          Bytes sent in other frames (SETTINGS, GOAWAY, PUSH_PROMISE etc) on client side;
          'client_heading_bytes_rcvd'= Bytes received in HEADERS/DATA frame/stream
          heading on client side; 'client_heading_bytes_sent'= Bytes sent in HEADERS/DATA
          frame/stream heading on client side; 'client_total_bytes_rcvd'= Total Bytes
          received on client side; 'client_total_bytes_sent'= Total Bytes sent on client
          side; 'server_frame_type_headers_rcvd'= HEADERS Frame received on server side;
          'server_frame_type_headers_sent'= HEADERS Frame sent on server side;
          'server_frame_type_data_rcvd'= DATA Frame received on server side;
          'server_frame_type_data_sent'= DATA Frame sent on server side;
          'server_frame_type_cancel_push_rcvd'= CANCEL PUSH Frame received on server
          side; 'server_frame_type_cancel_push_sent'= CANCEL PUSH Frame sent on server
          side; 'server_frame_type_settings_rcvd'= SETTINGS Frame received on server
          side; 'server_frame_type_settings_sent'= SETTINGS Frame sent on server side;
          'server_frame_type_push_promise_rcvd'= PUSH PROMISE Frame received on server
          side; 'server_frame_type_push_promise_sent'= PUSH PROMISE Frame sent on server
          side; 'server_frame_type_goaway_rcvd'= GOAWAY Frame received on server side;
          'server_frame_type_goaway_sent'= GOAWAY Frame sent on server side;
          'server_frame_type_max_push_id_rcvd'= MAX PUSH ID Frame received on server
          side; 'server_frame_type_max_push_id_sent'= MAX PUSH ID Frame sent on server
          side; 'server_frame_type_unknown_rcvd'= Unknown Frame received on server side;
          'server_header_frames_to_app'= HEADER Frames passed to HTTP layer on server
          side; 'server_data_frames_to_app'= DATA Frames passed to HTTP layer on server
          side; 'server_header_bytes_rcvd'= Bytes received in HEADER frames on server
          side; 'server_header_bytes_sent'= Bytes sent in HEADER frames on server side;
          'server_data_bytes_rcvd'= Bytes received in DATA frames on server side;
          'server_data_bytes_sent'= Bytes sent in DATA frames on server side;
          'server_other_frame_bytes_rcvd'= Bytes received in other frames (SETTINGS,
          GOAWAY, PUSH_PROMISE etc) on server side; 'server_other_frame_bytes_sent'=
          Bytes sent in other frames (SETTINGS, GOAWAY, PUSH_PROMISE etc) on server side;
          'server_heading_bytes_rcvd'= Bytes received in HEADERS/DATA frame/stream
          heading on server side; 'server_heading_bytes_sent'= Bytes sent in HEADERS/DATA
          frame/stream heading on server side; 'server_total_bytes_rcvd'= Total Bytes
          received on server side; 'server_total_bytes_sent'= Total Bytes sent on server
          side; 'invalid_argument'= Invalid Argument; 'invalid_state'= Invalid State;
          'wouldblock'= Wouldblock; 'stream_in_use'= Stream In Use; 'push_id_blocked'=
          Push Id Blocked; 'malformed_http_header'= Malformed Http Header;
          'remove_http_header'= Remove Http Header; 'malformed_http_messaging'= Malformed
          Http Messaging; 'too_late'= Too Late; 'qpack_fatal'= Qpack Fatal;
          'qpack_header_too_large'= Qpack Header Too Large; 'ignore_stream'= Ignore
          Stream; 'stream_not_found'= Stream Not Found; 'ignore_push_promise'= Ignore
          Push Promise; 'qpack_decompression_failed'= Qpack Decompression Failed;
          'qpack_encoder_stream_error'= Qpack Encoder Stream Error;
          'qpack_decoder_stream_error'= Qpack Decoder Stream Error;
          'h3_frame_unexpected'= H3 Frame Unexpected; 'h3_frame_error'= H3 Frame Error;
          'h3_missing_settings'= H3 Missing Settings; 'h3_internal_error'= H3 Internal
          Error; 'h3_closed_critical_stream'= H3 Closed Critical Stream;
          'h3_general_protocol_error'= H3 General Protocol Error; 'h3_id_error'= H3 Id
          Error; 'h3_settings_error'= H3 Settings Error; 'h3_stream_creation_error'= H3
          Stream Creation Error; 'fatal'= Fatal Error; 'conn_alloc_error'= HTTP/3
          Connection Allocation Error; 'alloc_fail_total'= Memory Allocation Failures;
          'http3_rejected'= HTTP3 Rejected;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            client_conn_curr:
                description:
                - "Current HTTP/3 Client Connections"
                type: str
            server_conn_curr:
                description:
                - "Current HTTP/3 Server Connections"
                type: str
            client_conn_total:
                description:
                - "Total HTTP/3 Client Connections"
                type: str
            server_conn_total:
                description:
                - "Total HTTP/3 Server Connections"
                type: str
            client_conn_peak:
                description:
                - "Peak HTTP/3 Client Connections"
                type: str
            server_conn_peak:
                description:
                - "Peak HTTP/3 Server Connections"
                type: str
            client_request_streams_curr:
                description:
                - "Current Request Streams on client side"
                type: str
            server_request_streams_curr:
                description:
                - "Current Request Streams on server side"
                type: str
            client_request_streams_total:
                description:
                - "Total Request Streams on client side"
                type: str
            server_request_streams_total:
                description:
                - "Total Request Streams on server side"
                type: str
            client_request_push_curr:
                description:
                - "Current Push Streams on client side"
                type: str
            server_request_push_curr:
                description:
                - "Current Push Streams on server side"
                type: str
            client_request_push_total:
                description:
                - "Total Push Streams on client side"
                type: str
            server_request_push_total:
                description:
                - "Total Push Streams on server side"
                type: str
            client_request_other_curr:
                description:
                - "Current Other Streams on client side (control, decoder, encoder)"
                type: str
            server_request_other_curr:
                description:
                - "urrent Other Streams on server side (control, decoder, encoder)"
                type: str
            client_request_other_total:
                description:
                - "Total Other Streams on client side (control, decoder, encoder)"
                type: str
            server_request_other_total:
                description:
                - "Total Other Streams on server side (control, decoder, encoder)"
                type: str
            client_frame_type_headers_rcvd:
                description:
                - "HEADERS Frame received on client side"
                type: str
            client_frame_type_headers_sent:
                description:
                - "HEADERS Frame sent on client side"
                type: str
            client_frame_type_data_rcvd:
                description:
                - "DATA Frame received on client side"
                type: str
            client_frame_type_data_sent:
                description:
                - "DATA Frame sent on client side"
                type: str
            client_frame_type_cancel_push_rcvd:
                description:
                - "CANCEL PUSH Frame received on client side"
                type: str
            client_frame_type_cancel_push_sent:
                description:
                - "CANCEL PUSH Frame sent on client side"
                type: str
            client_frame_type_settings_rcvd:
                description:
                - "SETTINGS Frame received on client side"
                type: str
            client_frame_type_settings_sent:
                description:
                - "SETTINGS Frame sent on client side"
                type: str
            client_frame_type_push_promise_rcvd:
                description:
                - "PUSH PROMISE Frame received on client side"
                type: str
            client_frame_type_push_promise_sent:
                description:
                - "PUSH PROMISE Frame sent on client side"
                type: str
            client_frame_type_goaway_rcvd:
                description:
                - "GOAWAY Frame received on client side"
                type: str
            client_frame_type_goaway_sent:
                description:
                - "GOAWAY Frame sent on client side"
                type: str
            client_frame_type_max_push_id_rcvd:
                description:
                - "MAX PUSH ID Frame received on client side"
                type: str
            client_frame_type_max_push_id_sent:
                description:
                - "MAX PUSH ID Frame sent on client side"
                type: str
            client_frame_type_unknown_rcvd:
                description:
                - "Unknown Frame received on client side"
                type: str
            client_header_frames_to_app:
                description:
                - "HEADER Frames passed to HTTP layer on client side"
                type: str
            client_data_frames_to_app:
                description:
                - "DATA Frames passed to HTTP layer on client side"
                type: str
            client_header_bytes_rcvd:
                description:
                - "Bytes received in HEADER frames on client side"
                type: str
            client_header_bytes_sent:
                description:
                - "Bytes sent in HEADER frames on client side"
                type: str
            client_data_bytes_rcvd:
                description:
                - "Bytes received in DATA frames on client side"
                type: str
            client_data_bytes_sent:
                description:
                - "Bytes sent in DATA frames on client side"
                type: str
            client_other_frame_bytes_rcvd:
                description:
                - "Bytes received in other frames (SETTINGS, GOAWAY, PUSH_PROMISE etc) on client
          side"
                type: str
            client_other_frame_bytes_sent:
                description:
                - "Bytes sent in other frames (SETTINGS, GOAWAY, PUSH_PROMISE etc) on client side"
                type: str
            client_heading_bytes_rcvd:
                description:
                - "Bytes received in HEADERS/DATA frame/stream heading on client side"
                type: str
            client_heading_bytes_sent:
                description:
                - "Bytes sent in HEADERS/DATA frame/stream heading on client side"
                type: str
            client_total_bytes_rcvd:
                description:
                - "Total Bytes received on client side"
                type: str
            client_total_bytes_sent:
                description:
                - "Total Bytes sent on client side"
                type: str
            server_frame_type_headers_rcvd:
                description:
                - "HEADERS Frame received on server side"
                type: str
            server_frame_type_headers_sent:
                description:
                - "HEADERS Frame sent on server side"
                type: str
            server_frame_type_data_rcvd:
                description:
                - "DATA Frame received on server side"
                type: str
            server_frame_type_data_sent:
                description:
                - "DATA Frame sent on server side"
                type: str
            server_frame_type_cancel_push_rcvd:
                description:
                - "CANCEL PUSH Frame received on server side"
                type: str
            server_frame_type_cancel_push_sent:
                description:
                - "CANCEL PUSH Frame sent on server side"
                type: str
            server_frame_type_settings_rcvd:
                description:
                - "SETTINGS Frame received on server side"
                type: str
            server_frame_type_settings_sent:
                description:
                - "SETTINGS Frame sent on server side"
                type: str
            server_frame_type_push_promise_rcvd:
                description:
                - "PUSH PROMISE Frame received on server side"
                type: str
            server_frame_type_push_promise_sent:
                description:
                - "PUSH PROMISE Frame sent on server side"
                type: str
            server_frame_type_goaway_rcvd:
                description:
                - "GOAWAY Frame received on server side"
                type: str
            server_frame_type_goaway_sent:
                description:
                - "GOAWAY Frame sent on server side"
                type: str
            server_frame_type_max_push_id_rcvd:
                description:
                - "MAX PUSH ID Frame received on server side"
                type: str
            server_frame_type_max_push_id_sent:
                description:
                - "MAX PUSH ID Frame sent on server side"
                type: str
            server_frame_type_unknown_rcvd:
                description:
                - "Unknown Frame received on server side"
                type: str
            server_header_frames_to_app:
                description:
                - "HEADER Frames passed to HTTP layer on server side"
                type: str
            server_data_frames_to_app:
                description:
                - "DATA Frames passed to HTTP layer on server side"
                type: str
            server_header_bytes_rcvd:
                description:
                - "Bytes received in HEADER frames on server side"
                type: str
            server_header_bytes_sent:
                description:
                - "Bytes sent in HEADER frames on server side"
                type: str
            server_data_bytes_rcvd:
                description:
                - "Bytes received in DATA frames on server side"
                type: str
            server_data_bytes_sent:
                description:
                - "Bytes sent in DATA frames on server side"
                type: str
            server_other_frame_bytes_rcvd:
                description:
                - "Bytes received in other frames (SETTINGS, GOAWAY, PUSH_PROMISE etc) on server
          side"
                type: str
            server_other_frame_bytes_sent:
                description:
                - "Bytes sent in other frames (SETTINGS, GOAWAY, PUSH_PROMISE etc) on server side"
                type: str
            server_heading_bytes_rcvd:
                description:
                - "Bytes received in HEADERS/DATA frame/stream heading on server side"
                type: str
            server_heading_bytes_sent:
                description:
                - "Bytes sent in HEADERS/DATA frame/stream heading on server side"
                type: str
            server_total_bytes_rcvd:
                description:
                - "Total Bytes received on server side"
                type: str
            server_total_bytes_sent:
                description:
                - "Total Bytes sent on server side"
                type: str
            invalid_argument:
                description:
                - "Invalid Argument"
                type: str
            invalid_state:
                description:
                - "Invalid State"
                type: str
            wouldblock:
                description:
                - "Wouldblock"
                type: str
            stream_in_use:
                description:
                - "Stream In Use"
                type: str
            push_id_blocked:
                description:
                - "Push Id Blocked"
                type: str
            malformed_http_header:
                description:
                - "Malformed Http Header"
                type: str
            remove_http_header:
                description:
                - "Remove Http Header"
                type: str
            malformed_http_messaging:
                description:
                - "Malformed Http Messaging"
                type: str
            too_late:
                description:
                - "Too Late"
                type: str
            qpack_fatal:
                description:
                - "Qpack Fatal"
                type: str
            qpack_header_too_large:
                description:
                - "Qpack Header Too Large"
                type: str
            ignore_stream:
                description:
                - "Ignore Stream"
                type: str
            stream_not_found:
                description:
                - "Stream Not Found"
                type: str
            ignore_push_promise:
                description:
                - "Ignore Push Promise"
                type: str
            qpack_decompression_failed:
                description:
                - "Qpack Decompression Failed"
                type: str
            qpack_encoder_stream_error:
                description:
                - "Qpack Encoder Stream Error"
                type: str
            qpack_decoder_stream_error:
                description:
                - "Qpack Decoder Stream Error"
                type: str
            h3_frame_unexpected:
                description:
                - "H3 Frame Unexpected"
                type: str
            h3_frame_error:
                description:
                - "H3 Frame Error"
                type: str
            h3_missing_settings:
                description:
                - "H3 Missing Settings"
                type: str
            h3_internal_error:
                description:
                - "H3 Internal Error"
                type: str
            h3_closed_critical_stream:
                description:
                - "H3 Closed Critical Stream"
                type: str
            h3_general_protocol_error:
                description:
                - "H3 General Protocol Error"
                type: str
            h3_id_error:
                description:
                - "H3 Id Error"
                type: str
            h3_settings_error:
                description:
                - "H3 Settings Error"
                type: str
            h3_stream_creation_error:
                description:
                - "H3 Stream Creation Error"
                type: str
            fatal:
                description:
                - "Fatal Error"
                type: str
            conn_alloc_error:
                description:
                - "HTTP/3 Connection Allocation Error"
                type: str
            alloc_fail_total:
                description:
                - "Memory Allocation Failures"
                type: str
            http3_rejected:
                description:
                - "HTTP3 Rejected"
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
AVAILABLE_PROPERTIES = ["sampling_enable", "stats", "uuid", ]


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
                    'all', 'client_conn_curr', 'server_conn_curr', 'client_conn_total', 'server_conn_total', 'client_conn_peak', 'server_conn_peak', 'client_request_streams_curr', 'server_request_streams_curr', 'client_request_streams_total', 'server_request_streams_total', 'client_request_push_curr', 'server_request_push_curr',
                    'client_request_push_total', 'server_request_push_total', 'client_request_other_curr', 'server_request_other_curr', 'client_request_other_total', 'server_request_other_total', 'client_frame_type_headers_rcvd', 'client_frame_type_headers_sent', 'client_frame_type_data_rcvd', 'client_frame_type_data_sent',
                    'client_frame_type_cancel_push_rcvd', 'client_frame_type_cancel_push_sent', 'client_frame_type_settings_rcvd', 'client_frame_type_settings_sent', 'client_frame_type_push_promise_rcvd', 'client_frame_type_push_promise_sent', 'client_frame_type_goaway_rcvd', 'client_frame_type_goaway_sent', 'client_frame_type_max_push_id_rcvd',
                    'client_frame_type_max_push_id_sent', 'client_frame_type_unknown_rcvd', 'client_header_frames_to_app', 'client_data_frames_to_app', 'client_header_bytes_rcvd', 'client_header_bytes_sent', 'client_data_bytes_rcvd', 'client_data_bytes_sent', 'client_other_frame_bytes_rcvd', 'client_other_frame_bytes_sent',
                    'client_heading_bytes_rcvd', 'client_heading_bytes_sent', 'client_total_bytes_rcvd', 'client_total_bytes_sent', 'server_frame_type_headers_rcvd', 'server_frame_type_headers_sent', 'server_frame_type_data_rcvd', 'server_frame_type_data_sent', 'server_frame_type_cancel_push_rcvd', 'server_frame_type_cancel_push_sent',
                    'server_frame_type_settings_rcvd', 'server_frame_type_settings_sent', 'server_frame_type_push_promise_rcvd', 'server_frame_type_push_promise_sent', 'server_frame_type_goaway_rcvd', 'server_frame_type_goaway_sent', 'server_frame_type_max_push_id_rcvd', 'server_frame_type_max_push_id_sent', 'server_frame_type_unknown_rcvd',
                    'server_header_frames_to_app', 'server_data_frames_to_app', 'server_header_bytes_rcvd', 'server_header_bytes_sent', 'server_data_bytes_rcvd', 'server_data_bytes_sent', 'server_other_frame_bytes_rcvd', 'server_other_frame_bytes_sent', 'server_heading_bytes_rcvd', 'server_heading_bytes_sent', 'server_total_bytes_rcvd',
                    'server_total_bytes_sent', 'invalid_argument', 'invalid_state', 'wouldblock', 'stream_in_use', 'push_id_blocked', 'malformed_http_header', 'remove_http_header', 'malformed_http_messaging', 'too_late', 'qpack_fatal', 'qpack_header_too_large', 'ignore_stream', 'stream_not_found', 'ignore_push_promise',
                    'qpack_decompression_failed', 'qpack_encoder_stream_error', 'qpack_decoder_stream_error', 'h3_frame_unexpected', 'h3_frame_error', 'h3_missing_settings', 'h3_internal_error', 'h3_closed_critical_stream', 'h3_general_protocol_error', 'h3_id_error', 'h3_settings_error', 'h3_stream_creation_error', 'fatal', 'conn_alloc_error',
                    'alloc_fail_total', 'http3_rejected'
                    ]
                }
            },
        'stats': {
            'type': 'dict',
            'client_conn_curr': {
                'type': 'str',
                },
            'server_conn_curr': {
                'type': 'str',
                },
            'client_conn_total': {
                'type': 'str',
                },
            'server_conn_total': {
                'type': 'str',
                },
            'client_conn_peak': {
                'type': 'str',
                },
            'server_conn_peak': {
                'type': 'str',
                },
            'client_request_streams_curr': {
                'type': 'str',
                },
            'server_request_streams_curr': {
                'type': 'str',
                },
            'client_request_streams_total': {
                'type': 'str',
                },
            'server_request_streams_total': {
                'type': 'str',
                },
            'client_request_push_curr': {
                'type': 'str',
                },
            'server_request_push_curr': {
                'type': 'str',
                },
            'client_request_push_total': {
                'type': 'str',
                },
            'server_request_push_total': {
                'type': 'str',
                },
            'client_request_other_curr': {
                'type': 'str',
                },
            'server_request_other_curr': {
                'type': 'str',
                },
            'client_request_other_total': {
                'type': 'str',
                },
            'server_request_other_total': {
                'type': 'str',
                },
            'client_frame_type_headers_rcvd': {
                'type': 'str',
                },
            'client_frame_type_headers_sent': {
                'type': 'str',
                },
            'client_frame_type_data_rcvd': {
                'type': 'str',
                },
            'client_frame_type_data_sent': {
                'type': 'str',
                },
            'client_frame_type_cancel_push_rcvd': {
                'type': 'str',
                },
            'client_frame_type_cancel_push_sent': {
                'type': 'str',
                },
            'client_frame_type_settings_rcvd': {
                'type': 'str',
                },
            'client_frame_type_settings_sent': {
                'type': 'str',
                },
            'client_frame_type_push_promise_rcvd': {
                'type': 'str',
                },
            'client_frame_type_push_promise_sent': {
                'type': 'str',
                },
            'client_frame_type_goaway_rcvd': {
                'type': 'str',
                },
            'client_frame_type_goaway_sent': {
                'type': 'str',
                },
            'client_frame_type_max_push_id_rcvd': {
                'type': 'str',
                },
            'client_frame_type_max_push_id_sent': {
                'type': 'str',
                },
            'client_frame_type_unknown_rcvd': {
                'type': 'str',
                },
            'client_header_frames_to_app': {
                'type': 'str',
                },
            'client_data_frames_to_app': {
                'type': 'str',
                },
            'client_header_bytes_rcvd': {
                'type': 'str',
                },
            'client_header_bytes_sent': {
                'type': 'str',
                },
            'client_data_bytes_rcvd': {
                'type': 'str',
                },
            'client_data_bytes_sent': {
                'type': 'str',
                },
            'client_other_frame_bytes_rcvd': {
                'type': 'str',
                },
            'client_other_frame_bytes_sent': {
                'type': 'str',
                },
            'client_heading_bytes_rcvd': {
                'type': 'str',
                },
            'client_heading_bytes_sent': {
                'type': 'str',
                },
            'client_total_bytes_rcvd': {
                'type': 'str',
                },
            'client_total_bytes_sent': {
                'type': 'str',
                },
            'server_frame_type_headers_rcvd': {
                'type': 'str',
                },
            'server_frame_type_headers_sent': {
                'type': 'str',
                },
            'server_frame_type_data_rcvd': {
                'type': 'str',
                },
            'server_frame_type_data_sent': {
                'type': 'str',
                },
            'server_frame_type_cancel_push_rcvd': {
                'type': 'str',
                },
            'server_frame_type_cancel_push_sent': {
                'type': 'str',
                },
            'server_frame_type_settings_rcvd': {
                'type': 'str',
                },
            'server_frame_type_settings_sent': {
                'type': 'str',
                },
            'server_frame_type_push_promise_rcvd': {
                'type': 'str',
                },
            'server_frame_type_push_promise_sent': {
                'type': 'str',
                },
            'server_frame_type_goaway_rcvd': {
                'type': 'str',
                },
            'server_frame_type_goaway_sent': {
                'type': 'str',
                },
            'server_frame_type_max_push_id_rcvd': {
                'type': 'str',
                },
            'server_frame_type_max_push_id_sent': {
                'type': 'str',
                },
            'server_frame_type_unknown_rcvd': {
                'type': 'str',
                },
            'server_header_frames_to_app': {
                'type': 'str',
                },
            'server_data_frames_to_app': {
                'type': 'str',
                },
            'server_header_bytes_rcvd': {
                'type': 'str',
                },
            'server_header_bytes_sent': {
                'type': 'str',
                },
            'server_data_bytes_rcvd': {
                'type': 'str',
                },
            'server_data_bytes_sent': {
                'type': 'str',
                },
            'server_other_frame_bytes_rcvd': {
                'type': 'str',
                },
            'server_other_frame_bytes_sent': {
                'type': 'str',
                },
            'server_heading_bytes_rcvd': {
                'type': 'str',
                },
            'server_heading_bytes_sent': {
                'type': 'str',
                },
            'server_total_bytes_rcvd': {
                'type': 'str',
                },
            'server_total_bytes_sent': {
                'type': 'str',
                },
            'invalid_argument': {
                'type': 'str',
                },
            'invalid_state': {
                'type': 'str',
                },
            'wouldblock': {
                'type': 'str',
                },
            'stream_in_use': {
                'type': 'str',
                },
            'push_id_blocked': {
                'type': 'str',
                },
            'malformed_http_header': {
                'type': 'str',
                },
            'remove_http_header': {
                'type': 'str',
                },
            'malformed_http_messaging': {
                'type': 'str',
                },
            'too_late': {
                'type': 'str',
                },
            'qpack_fatal': {
                'type': 'str',
                },
            'qpack_header_too_large': {
                'type': 'str',
                },
            'ignore_stream': {
                'type': 'str',
                },
            'stream_not_found': {
                'type': 'str',
                },
            'ignore_push_promise': {
                'type': 'str',
                },
            'qpack_decompression_failed': {
                'type': 'str',
                },
            'qpack_encoder_stream_error': {
                'type': 'str',
                },
            'qpack_decoder_stream_error': {
                'type': 'str',
                },
            'h3_frame_unexpected': {
                'type': 'str',
                },
            'h3_frame_error': {
                'type': 'str',
                },
            'h3_missing_settings': {
                'type': 'str',
                },
            'h3_internal_error': {
                'type': 'str',
                },
            'h3_closed_critical_stream': {
                'type': 'str',
                },
            'h3_general_protocol_error': {
                'type': 'str',
                },
            'h3_id_error': {
                'type': 'str',
                },
            'h3_settings_error': {
                'type': 'str',
                },
            'h3_stream_creation_error': {
                'type': 'str',
                },
            'fatal': {
                'type': 'str',
                },
            'conn_alloc_error': {
                'type': 'str',
                },
            'alloc_fail_total': {
                'type': 'str',
                },
            'http3_rejected': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/http3"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/http3"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["http3"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["http3"].get(k) != v:
            change_results["changed"] = True
            config_changes["http3"][k] = v

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
    payload = utils.build_json("http3", module.params, AVAILABLE_PROPERTIES)
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

        if state == 'present' or state == 'absent':
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
            if module.params.get("get_type") == "single" or module.params.get("get_type") is None:
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["http3"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["http3-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["http3"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


"""
    Custom class which override the _check_required_arguments function to check check required arguments based on state and get_type.
"""


class AcosAnsibleModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        super(AcosAnsibleModule, self).__init__(*args, **kwargs)

    def _check_required_arguments(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        # skip validation if state is 'noop' and get_type is 'list'
        if not (param.get("state") == "noop" and param.get("get_type") == "list"):
            missing = []
            if spec is None:
                return missing
            # Check for missing required parameters in the provided argument spec
            for (k, v) in spec.items():
                required = v.get('required', False)
                if required and k not in param:
                    missing.append(k)
            if missing:
                self.fail_json(msg="Missing required parameters: {}".format(", ".join(missing)))


def main():
    module = AcosAnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
