#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_l7_http
description:
    - DDOS HTTP Statistics
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
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            req_processed:
                description:
                - "Packets Processed"
                type: str
            req_ofo:
                description:
                - "Out-Of-Order Request"
                type: str
            ofo_timer_expired:
                description:
                - "Out-Of-Order Timeout"
                type: str
            ofo_queue_exceed:
                description:
                - "Out-Of-Order Queue Exceeded"
                type: str
            ofo:
                description:
                - "Out-Of-Order Packets"
                type: str
            partial_hdr:
                description:
                - "Partial Header"
                type: str
            http_idle_timeout:
                description:
                - "Http Idle Timeout"
                type: str
            new_syn:
                description:
                - "TCP SYN"
                type: str
            retrans:
                description:
                - "TCP Retransmit"
                type: str
            retrans_fin:
                description:
                - "TCP Retransmit FIN"
                type: str
            retrans_push:
                description:
                - "TCP Retransmit PSH"
                type: str
            retrans_rst:
                description:
                - "TCP Retransmit RST"
                type: str
            req_retrans:
                description:
                - "Retransmit Request"
                type: str
            request:
                description:
                - "Request Total"
                type: str
            req_content_len:
                description:
                - "Request Content-Length Received"
                type: str
            src_req_rate_exceed:
                description:
                - "Src Request Rate Exceeded"
                type: str
            dst_req_rate_exceed:
                description:
                - "Dst Request Rate Exceeded"
                type: str
            lower_than_mss_exceed:
                description:
                - "Min Payload Size Fail Exceeded"
                type: str
            parsereq_fail:
                description:
                - "Parse Request Failed"
                type: str
            neg_req_remain:
                description:
                - "Negative Request Remain"
                type: str
            neg_rsp_remain:
                description:
                - "Negative Response Remain"
                type: str
            invalid_header:
                description:
                - "HTTP Header Invalid"
                type: str
            too_many_headers:
                description:
                - "HTTP Header Too Many"
                type: str
            header_name_too_long:
                description:
                - "HTTP Header Name Too Long"
                type: str
            invalid_hdr_name:
                description:
                - "HTTP Header Name Invalid"
                type: str
            invalid_hdr_val:
                description:
                - "HTTP Header Value Invalid"
                type: str
            line_too_long:
                description:
                - "Line Too Long"
                type: str
            client_rst:
                description:
                - "Client TCP RST Received"
                type: str
            hps_server_rst:
                description:
                - "Server TCP RST Received"
                type: str
            ddos_policy_violation:
                description:
                - "Policy Violation"
                type: str
            policy_drop:
                description:
                - "Policy Dropped"
                type: str
            error_condition:
                description:
                - "Error Condition"
                type: str
            http11:
                description:
                - "Request HTTP 1.1"
                type: str
            http10:
                description:
                - "Request HTTP 1.0"
                type: str
            rsp_chunk:
                description:
                - "Response Chunk"
                type: str
            http_get:
                description:
                - "Request Method GET"
                type: str
            http_head:
                description:
                - "Request Method HEAD"
                type: str
            http_put:
                description:
                - "Request Method PUT"
                type: str
            http_post:
                description:
                - "Request Method POST"
                type: str
            http_trace:
                description:
                - "Request Method TRACE"
                type: str
            http_options:
                description:
                - "Request Method OPTIONS"
                type: str
            http_connect:
                description:
                - "Request Method CONNECT"
                type: str
            http_del:
                description:
                - "Request Method DELETE"
                type: str
            http_unknown:
                description:
                - "Request Method UNKNOWN"
                type: str
            hps_req_sz_1k:
                description:
                - "Request Payload Size Less Than or Equal to 1K"
                type: str
            hps_req_sz_2k:
                description:
                - "Request Payload Size Less Than or Equal to 2K"
                type: str
            hps_req_sz_4k:
                description:
                - "Request Payload Size Less Than or Equal to 4K"
                type: str
            hps_req_sz_8k:
                description:
                - "Request Payload Size Less Than or Equal to 8K"
                type: str
            hps_req_sz_16k:
                description:
                - "Request Payload Size Less Than or Equal to 16K"
                type: str
            hps_req_sz_32k:
                description:
                - "Request Payload Size Less Than or Equal to 32K"
                type: str
            hps_req_sz_64k:
                description:
                - "Request Payload Size Less Than or Equal to 64K"
                type: str
            hps_req_sz_256k:
                description:
                - "Request Payload Size Less Than or Equal to 256K"
                type: str
            hps_req_sz_256k_plus:
                description:
                - "Request Payload Size Larger Than 256K"
                type: str
            hps_rsp_11:
                description:
                - "Response HTTP 1.1"
                type: str
            hps_rsp_10:
                description:
                - "Response HTTP 1.0"
                type: str
            hps_rsp_sz_1k:
                description:
                - "Response Payload Size Less Than or Equal to 1K"
                type: str
            hps_rsp_sz_2k:
                description:
                - "Response Payload Size Less Than or Equal to 2K"
                type: str
            hps_rsp_sz_4k:
                description:
                - "Response Payload Size Less Than or Equal to 4K"
                type: str
            hps_rsp_sz_8k:
                description:
                - "Response Payload Size Less Than or Equal to 8K"
                type: str
            hps_rsp_sz_16k:
                description:
                - "Response Payload Size Less Than or Equal to 16K"
                type: str
            hps_rsp_sz_32k:
                description:
                - "Response Payload Size Less Than or Equal to 32K"
                type: str
            hps_rsp_sz_64k:
                description:
                - "Response Payload Size Less Than or Equal to 64K"
                type: str
            hps_rsp_sz_256k:
                description:
                - "Response Payload Size Less Than or Equal to 256K"
                type: str
            hps_rsp_sz_256k_plus:
                description:
                - "Response Payload Size Larger Than 256K"
                type: str
            hps_rsp_status_1xx:
                description:
                - "Status Code 1XX"
                type: str
            hps_rsp_status_2xx:
                description:
                - "Status Code 2XX"
                type: str
            hps_rsp_status_3xx:
                description:
                - "Status Code 3XX"
                type: str
            hps_rsp_status_4xx:
                description:
                - "Status Code 4XX"
                type: str
            hps_rsp_status_5xx:
                description:
                - "Status Code 5XX"
                type: str
            hps_rsp_status_504_AX:
                description:
                - "Status Code 504 AX-Gen"
                type: str
            hps_rsp_status_6xx:
                description:
                - "Status Code 6XX"
                type: str
            hps_rsp_status_unknown:
                description:
                - "Status Code Unknown"
                type: str
            chunk_sz_512:
                description:
                - "Payload Chunk Size Less Than or Equal to 512"
                type: str
            chunk_sz_1k:
                description:
                - "Payload Chunk Size Less Than or Equal to 1K"
                type: str
            chunk_sz_2k:
                description:
                - "Payload Chunk Size Less Than or Equal to 2K"
                type: str
            chunk_sz_4k:
                description:
                - "Payload Chunk Size Less Than or Equal to 4K"
                type: str
            chunk_sz_gt_4k:
                description:
                - "Payload Chunk Size Larger Than 4K"
                type: str
            chunk_bad:
                description:
                - "Bad HTTP Chunk"
                type: str
            challenge_fail:
                description:
                - "Challenge Failed"
                type: str
            challenge_ud_sent:
                description:
                - "Challenge URL Redirect Sent"
                type: str
            challenge_ud_fail:
                description:
                - "Challenge URL Redirect Failed"
                type: str
            challenge_js_sent:
                description:
                - "Challenge Javascript Sent"
                type: str
            challenge_js_fail:
                description:
                - "Challenge Javascript Failed"
                type: str
            malform_bad_chunk:
                description:
                - "Malform Bad Chunk"
                type: str
            malform_content_len_too_long:
                description:
                - "Malform Content Length Too Long"
                type: str
            malform_header_name_too_long:
                description:
                - "Malform Header Name Too Long"
                type: str
            malform_line_too_long:
                description:
                - "Malform Line Too Long"
                type: str
            malform_req_line_too_long:
                description:
                - "Malform Request Line Too Long"
                type: str
            malform_too_many_headers:
                description:
                - "Malform Too Many Headers"
                type: str
            window_small:
                description:
                - "Window Size Small"
                type: str
            window_small_drop:
                description:
                - "Window Size Small Dropped"
                type: str
            alloc_fail:
                description:
                - "Alloc Failed"
                type: str
            use_hdr_ip_as_source:
                description:
                - "Use IP In Header As Src"
                type: str
            agent_filter_match:
                description:
                - "Agent Filter Match"
                type: str
            agent_filter_blacklist:
                description:
                - "Agent Filter Blacklisted"
                type: str
            referer_filter_match:
                description:
                - "Referer Filter Match"
                type: str
            referer_filter_blacklist:
                description:
                - "Referer Filter Blacklisted"
                type: str
            dst_filter_match:
                description:
                - "Dst Filter Match"
                type: str
            dst_filter_not_match:
                description:
                - "Dst Filter No Match"
                type: str
            dst_filter_action_blacklist:
                description:
                - "Dst Filter Action Blacklist"
                type: str
            dst_filter_action_drop:
                description:
                - "Dst Filter Action Drop"
                type: str
            dst_filter_action_default_pass:
                description:
                - "Dst Filter Action Default Pass"
                type: str
            dst_post_rate_exceed:
                description:
                - "Dst Post Rate Exceeded"
                type: str
            src_post_rate_exceed:
                description:
                - "Src Post Rate Exceeded"
                type: str
            dst_resp_rate_exceed:
                description:
                - "Dst Response Rate Exceeded"
                type: str
            dst_filter_action_whitelist:
                description:
                - "Dst Filter Action WL"
                type: str
            src_filter_match:
                description:
                - "Src Filter Match"
                type: str
            src_filter_not_match:
                description:
                - "Src Filter No Match"
                type: str
            src_filter_action_blacklist:
                description:
                - "Src Filter Action Blacklist"
                type: str
            src_filter_action_drop:
                description:
                - "Src Filter Action Drop"
                type: str
            src_filter_action_default_pass:
                description:
                - "Src Filter Action Default Pass"
                type: str
            src_filter_action_whitelist:
                description:
                - "Src Filter Action WL"
                type: str
            src_dst_filter_match:
                description:
                - "SrcDst Filter Match"
                type: str
            src_dst_filter_not_match:
                description:
                - "SrcDst Filter No Match"
                type: str
            src_dst_filter_action_blacklist:
                description:
                - "SrcDst Filter Action Blacklist"
                type: str
            src_dst_filter_action_drop:
                description:
                - "SrcDst Filter Action Drop"
                type: str
            src_dst_filter_action_default_pass:
                description:
                - "SrcDst Filter Action Default Pass"
                type: str
            src_dst_filter_action_whitelist:
                description:
                - "SrcDst Filter Action WL"
                type: str
            dst_filter_rate_exceed:
                description:
                - "Dst Filter Rate Exceed"
                type: str
            dst_filter_action_ignore:
                description:
                - "Dst Filter Action Ignore"
                type: str
            dst_filter_action_reset:
                description:
                - "Dst Filter Action Reset"
                type: str
            uri_filter_match:
                description:
                - "URI Filter Match"
                type: str
            http_auth_drop:
                description:
                - "HTTP Auth Dropped"
                type: str
            http_auth_resp:
                description:
                - "HTTP Auth Responded"
                type: str
            header_processing_time_0:
                description:
                - "Header Process Time Less Than 1s"
                type: str
            header_processing_time_1:
                description:
                - "Header Process Time Less Than 10s"
                type: str
            header_processing_time_2:
                description:
                - "Header Process Time Less Than 30s"
                type: str
            header_processing_time_3:
                description:
                - "Header Process Time Larger or Equal to 30s"
                type: str
            header_processing_incomplete:
                description:
                - "Header Process Incomplete"
                type: str
            malform_req_line_too_small:
                description:
                - "Malform Request Line Too Small"
                type: str
            malform_req_line_invalid_method:
                description:
                - "Malform Request Line Invalid Method"
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
AVAILABLE_PROPERTIES = ["stats", "uuid", ]


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
        'stats': {
            'type': 'dict',
            'req_processed': {
                'type': 'str',
                },
            'req_ofo': {
                'type': 'str',
                },
            'ofo_timer_expired': {
                'type': 'str',
                },
            'ofo_queue_exceed': {
                'type': 'str',
                },
            'ofo': {
                'type': 'str',
                },
            'partial_hdr': {
                'type': 'str',
                },
            'http_idle_timeout': {
                'type': 'str',
                },
            'new_syn': {
                'type': 'str',
                },
            'retrans': {
                'type': 'str',
                },
            'retrans_fin': {
                'type': 'str',
                },
            'retrans_push': {
                'type': 'str',
                },
            'retrans_rst': {
                'type': 'str',
                },
            'req_retrans': {
                'type': 'str',
                },
            'request': {
                'type': 'str',
                },
            'req_content_len': {
                'type': 'str',
                },
            'src_req_rate_exceed': {
                'type': 'str',
                },
            'dst_req_rate_exceed': {
                'type': 'str',
                },
            'lower_than_mss_exceed': {
                'type': 'str',
                },
            'parsereq_fail': {
                'type': 'str',
                },
            'neg_req_remain': {
                'type': 'str',
                },
            'neg_rsp_remain': {
                'type': 'str',
                },
            'invalid_header': {
                'type': 'str',
                },
            'too_many_headers': {
                'type': 'str',
                },
            'header_name_too_long': {
                'type': 'str',
                },
            'invalid_hdr_name': {
                'type': 'str',
                },
            'invalid_hdr_val': {
                'type': 'str',
                },
            'line_too_long': {
                'type': 'str',
                },
            'client_rst': {
                'type': 'str',
                },
            'hps_server_rst': {
                'type': 'str',
                },
            'ddos_policy_violation': {
                'type': 'str',
                },
            'policy_drop': {
                'type': 'str',
                },
            'error_condition': {
                'type': 'str',
                },
            'http11': {
                'type': 'str',
                },
            'http10': {
                'type': 'str',
                },
            'rsp_chunk': {
                'type': 'str',
                },
            'http_get': {
                'type': 'str',
                },
            'http_head': {
                'type': 'str',
                },
            'http_put': {
                'type': 'str',
                },
            'http_post': {
                'type': 'str',
                },
            'http_trace': {
                'type': 'str',
                },
            'http_options': {
                'type': 'str',
                },
            'http_connect': {
                'type': 'str',
                },
            'http_del': {
                'type': 'str',
                },
            'http_unknown': {
                'type': 'str',
                },
            'hps_req_sz_1k': {
                'type': 'str',
                },
            'hps_req_sz_2k': {
                'type': 'str',
                },
            'hps_req_sz_4k': {
                'type': 'str',
                },
            'hps_req_sz_8k': {
                'type': 'str',
                },
            'hps_req_sz_16k': {
                'type': 'str',
                },
            'hps_req_sz_32k': {
                'type': 'str',
                },
            'hps_req_sz_64k': {
                'type': 'str',
                },
            'hps_req_sz_256k': {
                'type': 'str',
                },
            'hps_req_sz_256k_plus': {
                'type': 'str',
                },
            'hps_rsp_11': {
                'type': 'str',
                },
            'hps_rsp_10': {
                'type': 'str',
                },
            'hps_rsp_sz_1k': {
                'type': 'str',
                },
            'hps_rsp_sz_2k': {
                'type': 'str',
                },
            'hps_rsp_sz_4k': {
                'type': 'str',
                },
            'hps_rsp_sz_8k': {
                'type': 'str',
                },
            'hps_rsp_sz_16k': {
                'type': 'str',
                },
            'hps_rsp_sz_32k': {
                'type': 'str',
                },
            'hps_rsp_sz_64k': {
                'type': 'str',
                },
            'hps_rsp_sz_256k': {
                'type': 'str',
                },
            'hps_rsp_sz_256k_plus': {
                'type': 'str',
                },
            'hps_rsp_status_1xx': {
                'type': 'str',
                },
            'hps_rsp_status_2xx': {
                'type': 'str',
                },
            'hps_rsp_status_3xx': {
                'type': 'str',
                },
            'hps_rsp_status_4xx': {
                'type': 'str',
                },
            'hps_rsp_status_5xx': {
                'type': 'str',
                },
            'hps_rsp_status_504_AX': {
                'type': 'str',
                },
            'hps_rsp_status_6xx': {
                'type': 'str',
                },
            'hps_rsp_status_unknown': {
                'type': 'str',
                },
            'chunk_sz_512': {
                'type': 'str',
                },
            'chunk_sz_1k': {
                'type': 'str',
                },
            'chunk_sz_2k': {
                'type': 'str',
                },
            'chunk_sz_4k': {
                'type': 'str',
                },
            'chunk_sz_gt_4k': {
                'type': 'str',
                },
            'chunk_bad': {
                'type': 'str',
                },
            'challenge_fail': {
                'type': 'str',
                },
            'challenge_ud_sent': {
                'type': 'str',
                },
            'challenge_ud_fail': {
                'type': 'str',
                },
            'challenge_js_sent': {
                'type': 'str',
                },
            'challenge_js_fail': {
                'type': 'str',
                },
            'malform_bad_chunk': {
                'type': 'str',
                },
            'malform_content_len_too_long': {
                'type': 'str',
                },
            'malform_header_name_too_long': {
                'type': 'str',
                },
            'malform_line_too_long': {
                'type': 'str',
                },
            'malform_req_line_too_long': {
                'type': 'str',
                },
            'malform_too_many_headers': {
                'type': 'str',
                },
            'window_small': {
                'type': 'str',
                },
            'window_small_drop': {
                'type': 'str',
                },
            'alloc_fail': {
                'type': 'str',
                },
            'use_hdr_ip_as_source': {
                'type': 'str',
                },
            'agent_filter_match': {
                'type': 'str',
                },
            'agent_filter_blacklist': {
                'type': 'str',
                },
            'referer_filter_match': {
                'type': 'str',
                },
            'referer_filter_blacklist': {
                'type': 'str',
                },
            'dst_filter_match': {
                'type': 'str',
                },
            'dst_filter_not_match': {
                'type': 'str',
                },
            'dst_filter_action_blacklist': {
                'type': 'str',
                },
            'dst_filter_action_drop': {
                'type': 'str',
                },
            'dst_filter_action_default_pass': {
                'type': 'str',
                },
            'dst_post_rate_exceed': {
                'type': 'str',
                },
            'src_post_rate_exceed': {
                'type': 'str',
                },
            'dst_resp_rate_exceed': {
                'type': 'str',
                },
            'dst_filter_action_whitelist': {
                'type': 'str',
                },
            'src_filter_match': {
                'type': 'str',
                },
            'src_filter_not_match': {
                'type': 'str',
                },
            'src_filter_action_blacklist': {
                'type': 'str',
                },
            'src_filter_action_drop': {
                'type': 'str',
                },
            'src_filter_action_default_pass': {
                'type': 'str',
                },
            'src_filter_action_whitelist': {
                'type': 'str',
                },
            'src_dst_filter_match': {
                'type': 'str',
                },
            'src_dst_filter_not_match': {
                'type': 'str',
                },
            'src_dst_filter_action_blacklist': {
                'type': 'str',
                },
            'src_dst_filter_action_drop': {
                'type': 'str',
                },
            'src_dst_filter_action_default_pass': {
                'type': 'str',
                },
            'src_dst_filter_action_whitelist': {
                'type': 'str',
                },
            'dst_filter_rate_exceed': {
                'type': 'str',
                },
            'dst_filter_action_ignore': {
                'type': 'str',
                },
            'dst_filter_action_reset': {
                'type': 'str',
                },
            'uri_filter_match': {
                'type': 'str',
                },
            'http_auth_drop': {
                'type': 'str',
                },
            'http_auth_resp': {
                'type': 'str',
                },
            'header_processing_time_0': {
                'type': 'str',
                },
            'header_processing_time_1': {
                'type': 'str',
                },
            'header_processing_time_2': {
                'type': 'str',
                },
            'header_processing_time_3': {
                'type': 'str',
                },
            'header_processing_incomplete': {
                'type': 'str',
                },
            'malform_req_line_too_small': {
                'type': 'str',
                },
            'malform_req_line_invalid_method': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/l7-http"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/l7-http"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config):
    if existing_config:
        result["changed"] = True
    return result


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
    payload = utils.build_json("l7-http", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["l7-http"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["l7-http-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["l7-http"]["stats"] if info != "NotFound" else info
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
