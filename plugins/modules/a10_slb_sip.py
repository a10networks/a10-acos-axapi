#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_sip
description:
    - Configure SIP
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
                - "'all'= all; 'msg_proxy_current'= Number of current sip proxy connections;
          'msg_proxy_total'= Total number of sip proxy connections;
          'msg_proxy_mem_allocd'= msg_proxy_mem_allocd; 'msg_proxy_mem_cached'=
          msg_proxy_mem_cached; 'msg_proxy_mem_freed'= msg_proxy_mem_freed;
          'msg_proxy_client_recv'= Number of SIP messages received from client;
          'msg_proxy_client_send_success'= Number of SIP messages received from client
          and forwarded to server; 'msg_proxy_client_incomplete'= Number of packet which
          contains incomplete message; 'msg_proxy_client_drop'= Number of AX drop;
          'msg_proxy_client_connection'= Connecting server; 'msg_proxy_client_fail'=
          Number of SIP messages received from client but failed to forward to server;
          'msg_proxy_client_fail_parse'= msg_proxy_client_fail_parse;
          'msg_proxy_client_fail_process'= msg_proxy_client_fail_process;
          'msg_proxy_client_fail_snat'= msg_proxy_client_fail_snat;
          'msg_proxy_client_exceed_tmp_buff'= msg_proxy_client_exceed_tmp_buff;
          'msg_proxy_client_fail_send_pkt'= msg_proxy_client_fail_send_pkt;
          'msg_proxy_client_fail_start_server_Conn'=
          msg_proxy_client_fail_start_server_Conn; 'msg_proxy_server_recv'= Number of SIP
          messages received from server; 'msg_proxy_server_send_success'= Number of SIP
          messages received from server and forwarded to client;
          'msg_proxy_server_incomplete'= Number of packet which contains incomplete
          message; 'msg_proxy_server_drop'= Number of AX drop; 'msg_proxy_server_fail'=
          Number of SIP messages received from server but failed to forward to client;
          'msg_proxy_server_fail_parse'= msg_proxy_server_fail_parse;
          'msg_proxy_server_fail_process'= msg_proxy_server_fail_process;
          'msg_proxy_server_fail_selec_connt'= msg_proxy_server_fail_selec_connt;
          'msg_proxy_server_fail_snat'= msg_proxy_server_fail_snat;
          'msg_proxy_server_exceed_tmp_buff'= msg_proxy_server_exceed_tmp_buff;
          'msg_proxy_server_fail_send_pkt'= msg_proxy_server_fail_send_pkt;
          'msg_proxy_create_server_conn'= Number of server connection system tries to
          create; 'msg_proxy_start_server_conn'= Number of server connection created
          successfully; 'msg_proxy_fail_start_server_conn'= Number of server connection
          create failed; 'msg_proxy_server_conn_fail_snat'=
          msg_proxy_server_conn_fail_snat; 'msg_proxy_fail_construct_server_conn'=
          msg_proxy_fail_construct_server_conn; 'msg_proxy_fail_reserve_pconn'=
          msg_proxy_fail_reserve_pconn; 'msg_proxy_start_server_conn_failed'=
          msg_proxy_start_server_conn_failed; 'msg_proxy_server_conn_already_exists'=
          msg_proxy_server_conn_already_exists; 'msg_proxy_fail_insert_server_conn'=
          msg_proxy_fail_insert_server_conn; 'msg_proxy_parse_msg_fail'=
          msg_proxy_parse_msg_fail; 'msg_proxy_process_msg_fail'=
          msg_proxy_process_msg_fail; 'msg_proxy_no_vport'= msg_proxy_no_vport;
          'msg_proxy_fail_select_server'= msg_proxy_fail_select_server;
          'msg_proxy_fail_alloc_mem'= msg_proxy_fail_alloc_mem;
          'msg_proxy_unexpected_err'= msg_proxy_unexpected_err;
          'msg_proxy_l7_cpu_failed'= msg_proxy_l7_cpu_failed; 'msg_proxy_l4_to_l7'=
          msg_proxy_l4_to_l7; 'msg_proxy_l4_from_l7'= msg_proxy_l4_from_l7;
          'msg_proxy_to_l4_send_pkt'= msg_proxy_to_l4_send_pkt;
          'msg_proxy_l4_from_l4_send'= msg_proxy_l4_from_l4_send; 'msg_proxy_l7_to_L4'=
          msg_proxy_l7_to_L4; 'msg_proxy_mag_back'= msg_proxy_mag_back;
          'msg_proxy_fail_dcmsg'= msg_proxy_fail_dcmsg; 'msg_proxy_deprecated_conn'=
          msg_proxy_deprecated_conn; 'msg_proxy_hold_msg'= msg_proxy_hold_msg;
          'msg_proxy_split_pkt'= msg_proxy_split_pkt; 'msg_proxy_pipline_msg'=
          msg_proxy_pipline_msg; 'msg_proxy_client_reset'= msg_proxy_client_reset;
          'msg_proxy_server_reset'= msg_proxy_server_reset; 'session_created'= SIP
          Session created; 'session_freed'= SIP Session freed; 'session_in_rml'=
          session_in_rml; 'session_invalid'= session_invalid; 'conn_allocd'= conn_allocd;
          'conn_freed'= conn_freed; 'session_callid_allocd'= session_callid_allocd;
          'session_callid_freed'= session_callid_freed; 'line_mem_allocd'=
          line_mem_allocd; 'line_mem_freed'= line_mem_freed; 'table_mem_allocd'=
          table_mem_allocd; 'table_mem_freed'= table_mem_freed; 'cmsg_no_uri_header'=
          cmsg_no_uri_header; 'cmsg_no_uri_session'= cmsg_no_uri_session;
          'sg_no_uri_header'= sg_no_uri_header; 'smsg_no_uri_session'=
          smsg_no_uri_session; 'line_too_long'= line_too_long; 'fail_read_start_line'=
          fail_read_start_line; 'fail_parse_start_line'= fail_parse_start_line;
          'invalid_start_line'= invalid_start_line; 'request_unknown_version'=
          request_unknown_version; 'response_unknown_version'= response_unknown_version;
          'request_unknown'= request_unknown; 'fail_parse_headers'= fail_parse_headers;
          'too_many_headers'= too_many_headers; 'invalid_header'= invalid_header;
          'header_name_too_long'= header_name_too_long; 'body_too_big'= body_too_big;
          'fail_get_counter'= fail_get_counter; 'msg_no_call_id'= msg_no_call_id;
          'identify_dir_failed'= identify_dir_failed; 'no_sip_request'= no_sip_request;
          'deprecated_msg'= deprecated_msg; 'fail_insert_callid_session'=
          fail_insert_callid_session; 'fail_insert_uri_session'= fail_insert_uri_session;
          'fail_insert_header'= fail_insert_header; 'select_server_conn'=
          select_server_conn; 'select_server_conn_by_callid'=
          select_server_conn_by_callid; 'select_server_conn_by_uri'=
          select_server_conn_by_uri; 'select_server_conn_by_rev_tuple'=
          select_server_conn_by_rev_tuple; 'select_server_conn_failed'=
          select_server_conn_failed; 'select_client_conn'= select_client_conn;
          'X_forward_for_select_client'= X_forward_for_select_client;
          'call_id_select_client'= call_id_select_client; 'uri_select_client'=
          uri_select_client; 'client_select_failed'= client_select_failed; 'acl_denied'=
          acl_denied; 'assemble_frag_failed'= assemble_frag_failed; 'wrong_ip_version'=
          wrong_ip_version; 'size_too_large'= size_too_large; 'fail_split_fragment'=
          fail_split_fragment; 'client_keepalive_received'= client_keepalive_received;
          'server_keepalive_received'= server_keepalive_received;
          'client_keepalive_send'= client_keepalive_send; 'server_keepalive_send'=
          server_keepalive_send; 'ax_health_check_received'= ax_health_check_received;
          'client_request'= client_request; 'client_request_ok'= client_request_ok;
          'concatenate_msg'= concatenate_msg; 'save_uri'= save_uri; 'save_uri_ok'=
          save_uri_ok; 'save_call_id'= save_call_id; 'save_call_id_ok'= save_call_id_ok;
          'msg_translation'= msg_translation; 'msg_translation_fail'=
          msg_translation_fail; 'msg_trans_start_line'= msg_trans_start_line;
          'msg_trans_start_headers'= msg_trans_start_headers; 'msg_trans_body'=
          msg_trans_body; 'request_register'= request_register; 'request_invite'=
          request_invite; 'request_ack'= request_ack; 'request_cancel'= request_cancel;
          'request_bye'= request_bye; 'request_options'= request_options;
          'request_prack'= request_prack; 'request_subscribe'= request_subscribe;
          'request_notify'= request_notify; 'request_publish'= request_publish;
          'request_info'= request_info; 'request_refer'= request_refer;
          'request_message'= request_message; 'request_update'= request_update;
          'response_unknown'= response_unknown; 'response_1XX'= response_1XX;
          'response_2XX'= response_2XX; 'response_3XX'= response_3XX; 'response_4XX'=
          response_4XX; 'response_5XX'= response_5XX; 'response_6XX'= response_6XX;
          'ha_send_sip_session'= ha_send_sip_session; 'ha_send_sip_session_ok'=
          ha_send_sip_session_ok; 'ha_fail_get_msg_header'= ha_fail_get_msg_header;
          'ha_recv_sip_session'= ha_recv_sip_session; 'ha_insert_sip_session_ok'=
          ha_insert_sip_session_ok; 'ha_update_sip_session_ok'= ha_update_sip_session_ok;
          'ha_invalid_pkt'= ha_invalid_pkt; 'ha_fail_alloc_sip_session'=
          ha_fail_alloc_sip_session; 'ha_fail_alloc_call_id'= ha_fail_alloc_call_id;
          'ha_fail_clone_sip_session'= ha_fail_clone_sip_session; 'save_smp_call_id_rtp'=
          save_smp_call_id_rtp; 'update_smp_call_id_rtp'= update_smp_call_id_rtp;
          'smp_call_id_rtp_session_match'= smp_call_id_rtp_session_match;
          'smp_call_id_rtp_session_not_match'= smp_call_id_rtp_session_not_match;
          'process_error_when_message_switch'= process_error_when_message_switch;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            sip_cpu_list:
                description:
                - "Field sip_cpu_list"
                type: list
            cpu_count:
                description:
                - "Field cpu_count"
                type: int
            filter_type:
                description:
                - "Field filter_type"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            msg_proxy_current:
                description:
                - "Number of current sip proxy connections"
                type: str
            msg_proxy_total:
                description:
                - "Total number of sip proxy connections"
                type: str
            msg_proxy_client_recv:
                description:
                - "Number of SIP messages received from client"
                type: str
            msg_proxy_client_send_success:
                description:
                - "Number of SIP messages received from client and forwarded to server"
                type: str
            msg_proxy_client_incomplete:
                description:
                - "Number of packet which contains incomplete message"
                type: str
            msg_proxy_client_drop:
                description:
                - "Number of AX drop"
                type: str
            msg_proxy_client_connection:
                description:
                - "Connecting server"
                type: str
            msg_proxy_client_fail:
                description:
                - "Number of SIP messages received from client but failed to forward to server"
                type: str
            msg_proxy_server_recv:
                description:
                - "Number of SIP messages received from server"
                type: str
            msg_proxy_server_send_success:
                description:
                - "Number of SIP messages received from server and forwarded to client"
                type: str
            msg_proxy_server_incomplete:
                description:
                - "Number of packet which contains incomplete message"
                type: str
            msg_proxy_server_drop:
                description:
                - "Number of AX drop"
                type: str
            msg_proxy_server_fail:
                description:
                - "Number of SIP messages received from server but failed to forward to client"
                type: str
            msg_proxy_create_server_conn:
                description:
                - "Number of server connection system tries to create"
                type: str
            msg_proxy_start_server_conn:
                description:
                - "Number of server connection created successfully"
                type: str
            msg_proxy_fail_start_server_conn:
                description:
                - "Number of server connection create failed"
                type: str
            session_created:
                description:
                - "SIP Session created"
                type: str
            session_freed:
                description:
                - "SIP Session freed"
                type: str

'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "oper",
    "sampling_enable",
    "stats",
    "uuid",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str',
                   default="present",
                   choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
            required=False,
        ),
        a10_device_context_id=dict(
            type='int',
            choices=[1, 2, 3, 4, 5, 6, 7, 8],
            required=False,
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
                    'all', 'msg_proxy_current', 'msg_proxy_total',
                    'msg_proxy_mem_allocd', 'msg_proxy_mem_cached',
                    'msg_proxy_mem_freed', 'msg_proxy_client_recv',
                    'msg_proxy_client_send_success',
                    'msg_proxy_client_incomplete', 'msg_proxy_client_drop',
                    'msg_proxy_client_connection', 'msg_proxy_client_fail',
                    'msg_proxy_client_fail_parse',
                    'msg_proxy_client_fail_process',
                    'msg_proxy_client_fail_snat',
                    'msg_proxy_client_exceed_tmp_buff',
                    'msg_proxy_client_fail_send_pkt',
                    'msg_proxy_client_fail_start_server_Conn',
                    'msg_proxy_server_recv', 'msg_proxy_server_send_success',
                    'msg_proxy_server_incomplete', 'msg_proxy_server_drop',
                    'msg_proxy_server_fail', 'msg_proxy_server_fail_parse',
                    'msg_proxy_server_fail_process',
                    'msg_proxy_server_fail_selec_connt',
                    'msg_proxy_server_fail_snat',
                    'msg_proxy_server_exceed_tmp_buff',
                    'msg_proxy_server_fail_send_pkt',
                    'msg_proxy_create_server_conn',
                    'msg_proxy_start_server_conn',
                    'msg_proxy_fail_start_server_conn',
                    'msg_proxy_server_conn_fail_snat',
                    'msg_proxy_fail_construct_server_conn',
                    'msg_proxy_fail_reserve_pconn',
                    'msg_proxy_start_server_conn_failed',
                    'msg_proxy_server_conn_already_exists',
                    'msg_proxy_fail_insert_server_conn',
                    'msg_proxy_parse_msg_fail', 'msg_proxy_process_msg_fail',
                    'msg_proxy_no_vport', 'msg_proxy_fail_select_server',
                    'msg_proxy_fail_alloc_mem', 'msg_proxy_unexpected_err',
                    'msg_proxy_l7_cpu_failed', 'msg_proxy_l4_to_l7',
                    'msg_proxy_l4_from_l7', 'msg_proxy_to_l4_send_pkt',
                    'msg_proxy_l4_from_l4_send', 'msg_proxy_l7_to_L4',
                    'msg_proxy_mag_back', 'msg_proxy_fail_dcmsg',
                    'msg_proxy_deprecated_conn', 'msg_proxy_hold_msg',
                    'msg_proxy_split_pkt', 'msg_proxy_pipline_msg',
                    'msg_proxy_client_reset', 'msg_proxy_server_reset',
                    'session_created', 'session_freed', 'session_in_rml',
                    'session_invalid', 'conn_allocd', 'conn_freed',
                    'session_callid_allocd', 'session_callid_freed',
                    'line_mem_allocd', 'line_mem_freed', 'table_mem_allocd',
                    'table_mem_freed', 'cmsg_no_uri_header',
                    'cmsg_no_uri_session', 'sg_no_uri_header',
                    'smsg_no_uri_session', 'line_too_long',
                    'fail_read_start_line', 'fail_parse_start_line',
                    'invalid_start_line', 'request_unknown_version',
                    'response_unknown_version', 'request_unknown',
                    'fail_parse_headers', 'too_many_headers', 'invalid_header',
                    'header_name_too_long', 'body_too_big', 'fail_get_counter',
                    'msg_no_call_id', 'identify_dir_failed', 'no_sip_request',
                    'deprecated_msg', 'fail_insert_callid_session',
                    'fail_insert_uri_session', 'fail_insert_header',
                    'select_server_conn', 'select_server_conn_by_callid',
                    'select_server_conn_by_uri',
                    'select_server_conn_by_rev_tuple',
                    'select_server_conn_failed', 'select_client_conn',
                    'X_forward_for_select_client', 'call_id_select_client',
                    'uri_select_client', 'client_select_failed', 'acl_denied',
                    'assemble_frag_failed', 'wrong_ip_version',
                    'size_too_large', 'fail_split_fragment',
                    'client_keepalive_received', 'server_keepalive_received',
                    'client_keepalive_send', 'server_keepalive_send',
                    'ax_health_check_received', 'client_request',
                    'client_request_ok', 'concatenate_msg', 'save_uri',
                    'save_uri_ok', 'save_call_id', 'save_call_id_ok',
                    'msg_translation', 'msg_translation_fail',
                    'msg_trans_start_line', 'msg_trans_start_headers',
                    'msg_trans_body', 'request_register', 'request_invite',
                    'request_ack', 'request_cancel', 'request_bye',
                    'request_options', 'request_prack', 'request_subscribe',
                    'request_notify', 'request_publish', 'request_info',
                    'request_refer', 'request_message', 'request_update',
                    'response_unknown', 'response_1XX', 'response_2XX',
                    'response_3XX', 'response_4XX', 'response_5XX',
                    'response_6XX', 'ha_send_sip_session',
                    'ha_send_sip_session_ok', 'ha_fail_get_msg_header',
                    'ha_recv_sip_session', 'ha_insert_sip_session_ok',
                    'ha_update_sip_session_ok', 'ha_invalid_pkt',
                    'ha_fail_alloc_sip_session', 'ha_fail_alloc_call_id',
                    'ha_fail_clone_sip_session', 'save_smp_call_id_rtp',
                    'update_smp_call_id_rtp', 'smp_call_id_rtp_session_match',
                    'smp_call_id_rtp_session_not_match',
                    'process_error_when_message_switch'
                ]
            }
        },
        'oper': {
            'type': 'dict',
            'sip_cpu_list': {
                'type': 'list',
                'msg_proxy_current': {
                    'type': 'int',
                },
                'msg_proxy_total': {
                    'type': 'int',
                },
                'msg_proxy_mem_allocd': {
                    'type': 'int',
                },
                'msg_proxy_mem_cached': {
                    'type': 'int',
                },
                'msg_proxy_mem_freed': {
                    'type': 'int',
                },
                'msg_proxy_client_recv': {
                    'type': 'int',
                },
                'msg_proxy_client_send_success': {
                    'type': 'int',
                },
                'msg_proxy_client_incomplete': {
                    'type': 'int',
                },
                'msg_proxy_client_drop': {
                    'type': 'int',
                },
                'msg_proxy_client_connection': {
                    'type': 'int',
                },
                'msg_proxy_client_fail': {
                    'type': 'int',
                },
                'msg_proxy_client_fail_parse': {
                    'type': 'int',
                },
                'msg_proxy_client_fail_process': {
                    'type': 'int',
                },
                'msg_proxy_client_fail_snat': {
                    'type': 'int',
                },
                'msg_proxy_client_exceed_tmp_buff': {
                    'type': 'int',
                },
                'msg_proxy_client_fail_send_pkt': {
                    'type': 'int',
                },
                'msg_proxy_client_fail_start_server_Conn': {
                    'type': 'int',
                },
                'msg_proxy_server_recv': {
                    'type': 'int',
                },
                'msg_proxy_server_send_success': {
                    'type': 'int',
                },
                'msg_proxy_server_incomplete': {
                    'type': 'int',
                },
                'msg_proxy_server_drop': {
                    'type': 'int',
                },
                'msg_proxy_server_fail': {
                    'type': 'int',
                },
                'msg_proxy_server_fail_parse': {
                    'type': 'int',
                },
                'msg_proxy_server_fail_process': {
                    'type': 'int',
                },
                'msg_proxy_server_fail_selec_connt': {
                    'type': 'int',
                },
                'msg_proxy_server_fail_snat': {
                    'type': 'int',
                },
                'msg_proxy_server_exceed_tmp_buff': {
                    'type': 'int',
                },
                'msg_proxy_server_fail_send_pkt': {
                    'type': 'int',
                },
                'msg_proxy_create_server_conn': {
                    'type': 'int',
                },
                'msg_proxy_start_server_conn': {
                    'type': 'int',
                },
                'msg_proxy_fail_start_server_conn': {
                    'type': 'int',
                },
                'msg_proxy_server_conn_fail_snat': {
                    'type': 'int',
                },
                'msg_proxy_fail_construct_server_conn': {
                    'type': 'int',
                },
                'msg_proxy_fail_reserve_pconn': {
                    'type': 'int',
                },
                'msg_proxy_start_server_conn_failed': {
                    'type': 'int',
                },
                'msg_proxy_server_conn_already_exists': {
                    'type': 'int',
                },
                'msg_proxy_fail_insert_server_conn': {
                    'type': 'int',
                },
                'msg_proxy_parse_msg_fail': {
                    'type': 'int',
                },
                'msg_proxy_process_msg_fail': {
                    'type': 'int',
                },
                'msg_proxy_no_vport': {
                    'type': 'int',
                },
                'msg_proxy_fail_select_server': {
                    'type': 'int',
                },
                'msg_proxy_fail_alloc_mem': {
                    'type': 'int',
                },
                'msg_proxy_unexpected_err': {
                    'type': 'int',
                },
                'msg_proxy_l7_cpu_failed': {
                    'type': 'int',
                },
                'msg_proxy_l4_to_l7': {
                    'type': 'int',
                },
                'msg_proxy_l4_from_l7': {
                    'type': 'int',
                },
                'msg_proxy_to_l4_send_pkt': {
                    'type': 'int',
                },
                'msg_proxy_l4_from_l4_send': {
                    'type': 'int',
                },
                'msg_proxy_l7_to_L4': {
                    'type': 'int',
                },
                'msg_proxy_mag_back': {
                    'type': 'int',
                },
                'msg_proxy_fail_dcmsg': {
                    'type': 'int',
                },
                'msg_proxy_deprecated_conn': {
                    'type': 'int',
                },
                'msg_proxy_hold_msg': {
                    'type': 'int',
                },
                'msg_proxy_split_pkt': {
                    'type': 'int',
                },
                'msg_proxy_pipline_msg': {
                    'type': 'int',
                },
                'msg_proxy_client_reset': {
                    'type': 'int',
                },
                'msg_proxy_server_reset': {
                    'type': 'int',
                },
                'session_created': {
                    'type': 'int',
                },
                'session_freed': {
                    'type': 'int',
                },
                'session_in_rml': {
                    'type': 'int',
                },
                'session_invalid': {
                    'type': 'int',
                },
                'conn_allocd': {
                    'type': 'int',
                },
                'conn_freed': {
                    'type': 'int',
                },
                'session_callid_allocd': {
                    'type': 'int',
                },
                'session_callid_freed': {
                    'type': 'int',
                },
                'line_mem_allocd': {
                    'type': 'int',
                },
                'line_mem_freed': {
                    'type': 'int',
                },
                'table_mem_allocd': {
                    'type': 'int',
                },
                'table_mem_freed': {
                    'type': 'int',
                },
                'cmsg_no_uri_header': {
                    'type': 'int',
                },
                'cmsg_no_uri_session': {
                    'type': 'int',
                },
                'sg_no_uri_header': {
                    'type': 'int',
                },
                'smsg_no_uri_session': {
                    'type': 'int',
                },
                'line_too_long': {
                    'type': 'int',
                },
                'fail_read_start_line': {
                    'type': 'int',
                },
                'fail_parse_start_line': {
                    'type': 'int',
                },
                'invalid_start_line': {
                    'type': 'int',
                },
                'request_unknown_version': {
                    'type': 'int',
                },
                'response_unknown_version': {
                    'type': 'int',
                },
                'request_unknown': {
                    'type': 'int',
                },
                'fail_parse_headers': {
                    'type': 'int',
                },
                'too_many_headers': {
                    'type': 'int',
                },
                'invalid_header': {
                    'type': 'int',
                },
                'header_name_too_long': {
                    'type': 'int',
                },
                'body_too_big': {
                    'type': 'int',
                },
                'fail_get_counter': {
                    'type': 'int',
                },
                'msg_no_call_id': {
                    'type': 'int',
                },
                'identify_dir_failed': {
                    'type': 'int',
                },
                'no_sip_request': {
                    'type': 'int',
                },
                'deprecated_msg': {
                    'type': 'int',
                },
                'fail_insert_callid_session': {
                    'type': 'int',
                },
                'fail_insert_uri_session': {
                    'type': 'int',
                },
                'fail_insert_header': {
                    'type': 'int',
                },
                'select_server_conn': {
                    'type': 'int',
                },
                'select_server_conn_by_callid': {
                    'type': 'int',
                },
                'select_server_conn_by_uri': {
                    'type': 'int',
                },
                'select_server_conn_by_rev_tuple': {
                    'type': 'int',
                },
                'select_server_conn_failed': {
                    'type': 'int',
                },
                'select_client_conn': {
                    'type': 'int',
                },
                'X_forward_for_select_client': {
                    'type': 'int',
                },
                'call_id_select_client': {
                    'type': 'int',
                },
                'uri_select_client': {
                    'type': 'int',
                },
                'client_select_failed': {
                    'type': 'int',
                },
                'acl_denied': {
                    'type': 'int',
                },
                'assemble_frag_failed': {
                    'type': 'int',
                },
                'wrong_ip_version': {
                    'type': 'int',
                },
                'size_too_large': {
                    'type': 'int',
                },
                'fail_split_fragment': {
                    'type': 'int',
                },
                'client_keepalive_received': {
                    'type': 'int',
                },
                'server_keepalive_received': {
                    'type': 'int',
                },
                'client_keepalive_send': {
                    'type': 'int',
                },
                'server_keepalive_send': {
                    'type': 'int',
                },
                'ax_health_check_received': {
                    'type': 'int',
                },
                'client_request': {
                    'type': 'int',
                },
                'client_request_ok': {
                    'type': 'int',
                },
                'concatenate_msg': {
                    'type': 'int',
                },
                'save_uri': {
                    'type': 'int',
                },
                'save_uri_ok': {
                    'type': 'int',
                },
                'save_call_id': {
                    'type': 'int',
                },
                'save_call_id_ok': {
                    'type': 'int',
                },
                'msg_translation': {
                    'type': 'int',
                },
                'msg_translation_fail': {
                    'type': 'int',
                },
                'msg_trans_start_line': {
                    'type': 'int',
                },
                'msg_trans_start_headers': {
                    'type': 'int',
                },
                'msg_trans_body': {
                    'type': 'int',
                },
                'request_register': {
                    'type': 'int',
                },
                'request_invite': {
                    'type': 'int',
                },
                'request_ack': {
                    'type': 'int',
                },
                'request_cancel': {
                    'type': 'int',
                },
                'request_bye': {
                    'type': 'int',
                },
                'request_options': {
                    'type': 'int',
                },
                'request_prack': {
                    'type': 'int',
                },
                'request_subscribe': {
                    'type': 'int',
                },
                'request_notify': {
                    'type': 'int',
                },
                'request_publish': {
                    'type': 'int',
                },
                'request_info': {
                    'type': 'int',
                },
                'request_refer': {
                    'type': 'int',
                },
                'request_message': {
                    'type': 'int',
                },
                'request_update': {
                    'type': 'int',
                },
                'response_unknown': {
                    'type': 'int',
                },
                'response_1XX': {
                    'type': 'int',
                },
                'response_2XX': {
                    'type': 'int',
                },
                'response_3XX': {
                    'type': 'int',
                },
                'response_4XX': {
                    'type': 'int',
                },
                'response_5XX': {
                    'type': 'int',
                },
                'response_6XX': {
                    'type': 'int',
                },
                'ha_send_sip_session': {
                    'type': 'int',
                },
                'ha_send_sip_session_ok': {
                    'type': 'int',
                },
                'ha_fail_get_msg_header': {
                    'type': 'int',
                },
                'ha_recv_sip_session': {
                    'type': 'int',
                },
                'ha_insert_sip_session_ok': {
                    'type': 'int',
                },
                'ha_update_sip_session_ok': {
                    'type': 'int',
                },
                'ha_invalid_pkt': {
                    'type': 'int',
                },
                'ha_fail_alloc_sip_session': {
                    'type': 'int',
                },
                'ha_fail_alloc_call_id': {
                    'type': 'int',
                },
                'ha_fail_clone_sip_session': {
                    'type': 'int',
                },
                'save_smp_call_id_rtp': {
                    'type': 'int',
                },
                'update_smp_call_id_rtp': {
                    'type': 'int',
                },
                'smp_call_id_rtp_session_match': {
                    'type': 'int',
                },
                'smp_call_id_rtp_session_not_match': {
                    'type': 'int',
                },
                'process_error_when_message_switch': {
                    'type': 'int',
                }
            },
            'cpu_count': {
                'type': 'int',
            },
            'filter_type': {
                'type': 'str',
                'choices': ['detail', 'debug']
            }
        },
        'stats': {
            'type': 'dict',
            'msg_proxy_current': {
                'type': 'str',
            },
            'msg_proxy_total': {
                'type': 'str',
            },
            'msg_proxy_client_recv': {
                'type': 'str',
            },
            'msg_proxy_client_send_success': {
                'type': 'str',
            },
            'msg_proxy_client_incomplete': {
                'type': 'str',
            },
            'msg_proxy_client_drop': {
                'type': 'str',
            },
            'msg_proxy_client_connection': {
                'type': 'str',
            },
            'msg_proxy_client_fail': {
                'type': 'str',
            },
            'msg_proxy_server_recv': {
                'type': 'str',
            },
            'msg_proxy_server_send_success': {
                'type': 'str',
            },
            'msg_proxy_server_incomplete': {
                'type': 'str',
            },
            'msg_proxy_server_drop': {
                'type': 'str',
            },
            'msg_proxy_server_fail': {
                'type': 'str',
            },
            'msg_proxy_create_server_conn': {
                'type': 'str',
            },
            'msg_proxy_start_server_conn': {
                'type': 'str',
            },
            'msg_proxy_fail_start_server_conn': {
                'type': 'str',
            },
            'session_created': {
                'type': 'str',
            },
            'session_freed': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/sip"

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
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
    return module.client.get(oper_url(module))


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
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

    for k, v in param.items():
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
    return {title: data}


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/sip"

    f_dict = {}

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


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
        for k, v in payload["sip"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["sip"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["sip"][k] = v
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
    payload = build_json("sip", module)
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

    result = dict(changed=False, original_message="", message="", result={})

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

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
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
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
