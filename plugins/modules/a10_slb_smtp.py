#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_smtp
description:
    - Configure SMTP
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
                - "'all'= all; 'curr_proxy'= Current proxy conns; 'total_proxy'= Total proxy
          conns; 'request'= SMTP requests; 'request_success'= SMTP requests (success);
          'no_proxy'= No proxy error; 'client_reset'= Client reset; 'server_reset'=
          Server reset; 'no_tuple'= No tuple error; 'parse_req_fail'= Parse request
          failure; 'server_select_fail'= Server selection failure; 'forward_req_fail'=
          Forward request failure; 'forward_req_data_fail'= Forward REQ data failure;
          'req_retran'= Request retransmit; 'req_ofo'= Request pkt out-of-order;
          'server_reselect'= Server reselection; 'server_prem_close'= Server premature
          close; 'new_server_conn'= Server connection made; 'snat_fail'= Source NAT
          failure; 'tcp_out_reset'= TCP out reset; 'recv_client_command_EHLO'= Recv
          client EHLO; 'recv_client_command_HELO'= Recv client HELO;
          'recv_client_command_MAIL'= Recv client MAIL; 'recv_client_command_RCPT'= Recv
          client RCPT; 'recv_client_command_DATA'= Recv client DATA;
          'recv_client_command_RSET'= Recv client RSET; 'recv_client_command_VRFY'= Recv
          client VRFY; 'recv_client_command_EXPN'= Recv client EXPN;
          'recv_client_command_HELP'= Recv client HELP; 'recv_client_command_NOOP'= Recv
          client NOOP; 'recv_client_command_QUIT'= Recv client QUIT;
          'recv_client_command_STARTTLS'= Recv client STARTTLS;
          'recv_client_command_others'= Recv client other cmds;
          'recv_server_service_not_ready'= Recv server serv-not-rdy;
          'recv_server_unknow_reply_code'= Recv server unknown-code;
          'send_client_service_ready'= Sent client serv-rdy;
          'send_client_service_not_ready'= Sent client serv-not-rdy;
          'send_client_close_connection'= Sent client close-conn; 'send_client_go_ahead'=
          Sent client go-ahead; 'send_client_start_TLS_first'= Sent client STARTTLS-1st;
          'send_client_TLS_not_available'= Sent client TLS-not-aval;
          'send_client_no_command'= Sent client no-such-cmd; 'send_server_cmd_reset'=
          Sent server RSET; 'TLS_established'= SSL session established; 'L4_switch'= L4
          switching; 'Aflex_switch'= aFleX switching; 'Aflex_switch_ok'= aFleX switching
          (succ); 'client_domain_switch'= Client domain switching;
          'client_domain_switch_ok'= Client domain sw (succ); 'LB_switch'= LB switching;
          'LB_switch_ok'= LB switching (succ); 'read_request_line_fail'= Read request
          line fail; 'get_all_headers_fail'= Get all headers fail; 'too_many_headers'=
          Too many headers; 'line_too_long'= Line too long; 'line_across_packet'= Line
          across packets; 'line_extend'= Line extend; 'line_extend_fail'= Line extend
          fail; 'line_table_extend'= Table extend; 'line_table_extend_fail'= Table extend
          fail; 'parse_request_line_fail'= Parse request line fail;
          'insert_resonse_line_fail'= Ins response line fail; 'remove_resonse_line_fail'=
          Del response line fail; 'parse_resonse_line_fail'= Parse response line fail;
          'Aflex_lb_reselect'= aFleX lb reselect; 'Aflex_lb_reselect_ok'= aFleX lb
          reselect (succ); 'server_STARTTLS_init'= Init server side STARTTLS;
          'server_STARTTLS_fail'= Server side STARTTLS fail; 'rserver_STARTTLS_disable'=
          real server not support STARTTLS; 'recv_client_command_TURN'= Recv client TURN;
          'recv_client_command_ETRN'= Recv client ETRN;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            smtp_cpu_list:
                description:
                - "Field smtp_cpu_list"
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
                - "Current proxy conns"
                type: str
            total_proxy:
                description:
                - "Total proxy conns"
                type: str
            request:
                description:
                - "SMTP requests"
                type: str
            request_success:
                description:
                - "SMTP requests (success)"
                type: str
            no_proxy:
                description:
                - "No proxy error"
                type: str
            client_reset:
                description:
                - "Client reset"
                type: str
            server_reset:
                description:
                - "Server reset"
                type: str
            no_tuple:
                description:
                - "No tuple error"
                type: str
            parse_req_fail:
                description:
                - "Parse request failure"
                type: str
            server_select_fail:
                description:
                - "Server selection failure"
                type: str
            forward_req_fail:
                description:
                - "Forward request failure"
                type: str
            forward_req_data_fail:
                description:
                - "Forward REQ data failure"
                type: str
            req_retran:
                description:
                - "Request retransmit"
                type: str
            req_ofo:
                description:
                - "Request pkt out-of-order"
                type: str
            server_reselect:
                description:
                - "Server reselection"
                type: str
            server_prem_close:
                description:
                - "Server premature close"
                type: str
            new_server_conn:
                description:
                - "Server connection made"
                type: str
            snat_fail:
                description:
                - "Source NAT failure"
                type: str
            tcp_out_reset:
                description:
                - "TCP out reset"
                type: str
            recv_client_command_EHLO:
                description:
                - "Recv client EHLO"
                type: str
            recv_client_command_HELO:
                description:
                - "Recv client HELO"
                type: str
            recv_client_command_MAIL:
                description:
                - "Recv client MAIL"
                type: str
            recv_client_command_RCPT:
                description:
                - "Recv client RCPT"
                type: str
            recv_client_command_DATA:
                description:
                - "Recv client DATA"
                type: str
            recv_client_command_RSET:
                description:
                - "Recv client RSET"
                type: str
            recv_client_command_VRFY:
                description:
                - "Recv client VRFY"
                type: str
            recv_client_command_EXPN:
                description:
                - "Recv client EXPN"
                type: str
            recv_client_command_HELP:
                description:
                - "Recv client HELP"
                type: str
            recv_client_command_NOOP:
                description:
                - "Recv client NOOP"
                type: str
            recv_client_command_QUIT:
                description:
                - "Recv client QUIT"
                type: str
            recv_client_command_STARTTLS:
                description:
                - "Recv client STARTTLS"
                type: str
            recv_client_command_others:
                description:
                - "Recv client other cmds"
                type: str
            recv_server_service_not_ready:
                description:
                - "Recv server serv-not-rdy"
                type: str
            recv_server_unknow_reply_code:
                description:
                - "Recv server unknown-code"
                type: str
            send_client_service_ready:
                description:
                - "Sent client serv-rdy"
                type: str
            send_client_service_not_ready:
                description:
                - "Sent client serv-not-rdy"
                type: str
            send_client_close_connection:
                description:
                - "Sent client close-conn"
                type: str
            send_client_go_ahead:
                description:
                - "Sent client go-ahead"
                type: str
            send_client_start_TLS_first:
                description:
                - "Sent client STARTTLS-1st"
                type: str
            send_client_TLS_not_available:
                description:
                - "Sent client TLS-not-aval"
                type: str
            send_client_no_command:
                description:
                - "Sent client no-such-cmd"
                type: str
            send_server_cmd_reset:
                description:
                - "Sent server RSET"
                type: str
            TLS_established:
                description:
                - "SSL session established"
                type: str
            L4_switch:
                description:
                - "L4 switching"
                type: str
            Aflex_switch:
                description:
                - "aFleX switching"
                type: str
            Aflex_switch_ok:
                description:
                - "aFleX switching (succ)"
                type: str
            client_domain_switch:
                description:
                - "Client domain switching"
                type: str
            client_domain_switch_ok:
                description:
                - "Client domain sw (succ)"
                type: str
            LB_switch:
                description:
                - "LB switching"
                type: str
            LB_switch_ok:
                description:
                - "LB switching (succ)"
                type: str
            read_request_line_fail:
                description:
                - "Read request line fail"
                type: str
            get_all_headers_fail:
                description:
                - "Get all headers fail"
                type: str
            too_many_headers:
                description:
                - "Too many headers"
                type: str
            line_too_long:
                description:
                - "Line too long"
                type: str
            line_across_packet:
                description:
                - "Line across packets"
                type: str
            line_extend:
                description:
                - "Line extend"
                type: str
            line_extend_fail:
                description:
                - "Line extend fail"
                type: str
            line_table_extend:
                description:
                - "Table extend"
                type: str
            line_table_extend_fail:
                description:
                - "Table extend fail"
                type: str
            parse_request_line_fail:
                description:
                - "Parse request line fail"
                type: str
            insert_resonse_line_fail:
                description:
                - "Ins response line fail"
                type: str
            remove_resonse_line_fail:
                description:
                - "Del response line fail"
                type: str
            parse_resonse_line_fail:
                description:
                - "Parse response line fail"
                type: str
            Aflex_lb_reselect:
                description:
                - "aFleX lb reselect"
                type: str
            Aflex_lb_reselect_ok:
                description:
                - "aFleX lb reselect (succ)"
                type: str
            server_STARTTLS_init:
                description:
                - "Init server side STARTTLS"
                type: str
            server_STARTTLS_fail:
                description:
                - "Server side STARTTLS fail"
                type: str
            rserver_STARTTLS_disable:
                description:
                - "real server not support STARTTLS"
                type: str
            recv_client_command_TURN:
                description:
                - "Recv client TURN"
                type: str
            recv_client_command_ETRN:
                description:
                - "Recv client ETRN"
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

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "oper",
    "sampling_enable",
    "stats",
    "uuid",
]


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
            type='str',
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
                    'all', 'curr_proxy', 'total_proxy', 'request',
                    'request_success', 'no_proxy', 'client_reset',
                    'server_reset', 'no_tuple', 'parse_req_fail',
                    'server_select_fail', 'forward_req_fail',
                    'forward_req_data_fail', 'req_retran', 'req_ofo',
                    'server_reselect', 'server_prem_close', 'new_server_conn',
                    'snat_fail', 'tcp_out_reset', 'recv_client_command_EHLO',
                    'recv_client_command_HELO', 'recv_client_command_MAIL',
                    'recv_client_command_RCPT', 'recv_client_command_DATA',
                    'recv_client_command_RSET', 'recv_client_command_VRFY',
                    'recv_client_command_EXPN', 'recv_client_command_HELP',
                    'recv_client_command_NOOP', 'recv_client_command_QUIT',
                    'recv_client_command_STARTTLS',
                    'recv_client_command_others',
                    'recv_server_service_not_ready',
                    'recv_server_unknow_reply_code',
                    'send_client_service_ready',
                    'send_client_service_not_ready',
                    'send_client_close_connection', 'send_client_go_ahead',
                    'send_client_start_TLS_first',
                    'send_client_TLS_not_available', 'send_client_no_command',
                    'send_server_cmd_reset', 'TLS_established', 'L4_switch',
                    'Aflex_switch', 'Aflex_switch_ok', 'client_domain_switch',
                    'client_domain_switch_ok', 'LB_switch', 'LB_switch_ok',
                    'read_request_line_fail', 'get_all_headers_fail',
                    'too_many_headers', 'line_too_long', 'line_across_packet',
                    'line_extend', 'line_extend_fail', 'line_table_extend',
                    'line_table_extend_fail', 'parse_request_line_fail',
                    'insert_resonse_line_fail', 'remove_resonse_line_fail',
                    'parse_resonse_line_fail', 'Aflex_lb_reselect',
                    'Aflex_lb_reselect_ok', 'server_STARTTLS_init',
                    'server_STARTTLS_fail', 'rserver_STARTTLS_disable',
                    'recv_client_command_TURN', 'recv_client_command_ETRN'
                ]
            }
        },
        'oper': {
            'type': 'dict',
            'smtp_cpu_list': {
                'type': 'list',
                'curr_proxy': {
                    'type': 'int',
                },
                'total_proxy': {
                    'type': 'int',
                },
                'request': {
                    'type': 'int',
                },
                'request_success': {
                    'type': 'int',
                },
                'no_proxy': {
                    'type': 'int',
                },
                'client_reset': {
                    'type': 'int',
                },
                'server_reset': {
                    'type': 'int',
                },
                'no_tuple': {
                    'type': 'int',
                },
                'parse_req_fail': {
                    'type': 'int',
                },
                'server_select_fail': {
                    'type': 'int',
                },
                'forward_req_fail': {
                    'type': 'int',
                },
                'forward_req_data_fail': {
                    'type': 'int',
                },
                'req_retran': {
                    'type': 'int',
                },
                'req_ofo': {
                    'type': 'int',
                },
                'server_reselect': {
                    'type': 'int',
                },
                'server_prem_close': {
                    'type': 'int',
                },
                'new_server_conn': {
                    'type': 'int',
                },
                'snat_fail': {
                    'type': 'int',
                },
                'tcp_out_reset': {
                    'type': 'int',
                },
                'recv_client_command_EHLO': {
                    'type': 'int',
                },
                'recv_client_command_HELO': {
                    'type': 'int',
                },
                'recv_client_command_MAIL': {
                    'type': 'int',
                },
                'recv_client_command_RCPT': {
                    'type': 'int',
                },
                'recv_client_command_DATA': {
                    'type': 'int',
                },
                'recv_client_command_RSET': {
                    'type': 'int',
                },
                'recv_client_command_VRFY': {
                    'type': 'int',
                },
                'recv_client_command_EXPN': {
                    'type': 'int',
                },
                'recv_client_command_HELP': {
                    'type': 'int',
                },
                'recv_client_command_NOOP': {
                    'type': 'int',
                },
                'recv_client_command_QUIT': {
                    'type': 'int',
                },
                'recv_client_command_STARTTLS': {
                    'type': 'int',
                },
                'recv_client_command_TURN': {
                    'type': 'int',
                },
                'recv_client_command_ETRN': {
                    'type': 'int',
                },
                'recv_client_command_others': {
                    'type': 'int',
                },
                'recv_server_service_not_ready': {
                    'type': 'int',
                },
                'recv_server_unknow_reply_code': {
                    'type': 'int',
                },
                'send_client_service_ready': {
                    'type': 'int',
                },
                'send_client_service_not_ready': {
                    'type': 'int',
                },
                'send_client_close_connection': {
                    'type': 'int',
                },
                'send_client_go_ahead': {
                    'type': 'int',
                },
                'send_client_start_TLS_first': {
                    'type': 'int',
                },
                'send_client_TLS_not_available': {
                    'type': 'int',
                },
                'send_client_no_command': {
                    'type': 'int',
                },
                'send_server_cmd_reset': {
                    'type': 'int',
                },
                'TLS_established': {
                    'type': 'int',
                },
                'L4_switch': {
                    'type': 'int',
                },
                'Aflex_switch': {
                    'type': 'int',
                },
                'Aflex_switch_ok': {
                    'type': 'int',
                },
                'client_domain_switch': {
                    'type': 'int',
                },
                'client_domain_switch_ok': {
                    'type': 'int',
                },
                'LB_switch': {
                    'type': 'int',
                },
                'LB_switch_ok': {
                    'type': 'int',
                },
                'read_request_line_fail': {
                    'type': 'int',
                },
                'get_all_headers_fail': {
                    'type': 'int',
                },
                'too_many_headers': {
                    'type': 'int',
                },
                'line_too_long': {
                    'type': 'int',
                },
                'line_across_packet': {
                    'type': 'int',
                },
                'line_extend': {
                    'type': 'int',
                },
                'line_extend_fail': {
                    'type': 'int',
                },
                'line_table_extend': {
                    'type': 'int',
                },
                'line_table_extend_fail': {
                    'type': 'int',
                },
                'parse_request_line_fail': {
                    'type': 'int',
                },
                'insert_resonse_line_fail': {
                    'type': 'int',
                },
                'remove_resonse_line_fail': {
                    'type': 'int',
                },
                'parse_resonse_line_fail': {
                    'type': 'int',
                },
                'Aflex_lb_reselect': {
                    'type': 'int',
                },
                'Aflex_lb_reselect_ok': {
                    'type': 'int',
                },
                'server_STARTTLS_init': {
                    'type': 'int',
                },
                'server_STARTTLS_fail': {
                    'type': 'int',
                },
                'rserver_STARTTLS_disable': {
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
            'request': {
                'type': 'str',
            },
            'request_success': {
                'type': 'str',
            },
            'no_proxy': {
                'type': 'str',
            },
            'client_reset': {
                'type': 'str',
            },
            'server_reset': {
                'type': 'str',
            },
            'no_tuple': {
                'type': 'str',
            },
            'parse_req_fail': {
                'type': 'str',
            },
            'server_select_fail': {
                'type': 'str',
            },
            'forward_req_fail': {
                'type': 'str',
            },
            'forward_req_data_fail': {
                'type': 'str',
            },
            'req_retran': {
                'type': 'str',
            },
            'req_ofo': {
                'type': 'str',
            },
            'server_reselect': {
                'type': 'str',
            },
            'server_prem_close': {
                'type': 'str',
            },
            'new_server_conn': {
                'type': 'str',
            },
            'snat_fail': {
                'type': 'str',
            },
            'tcp_out_reset': {
                'type': 'str',
            },
            'recv_client_command_EHLO': {
                'type': 'str',
            },
            'recv_client_command_HELO': {
                'type': 'str',
            },
            'recv_client_command_MAIL': {
                'type': 'str',
            },
            'recv_client_command_RCPT': {
                'type': 'str',
            },
            'recv_client_command_DATA': {
                'type': 'str',
            },
            'recv_client_command_RSET': {
                'type': 'str',
            },
            'recv_client_command_VRFY': {
                'type': 'str',
            },
            'recv_client_command_EXPN': {
                'type': 'str',
            },
            'recv_client_command_HELP': {
                'type': 'str',
            },
            'recv_client_command_NOOP': {
                'type': 'str',
            },
            'recv_client_command_QUIT': {
                'type': 'str',
            },
            'recv_client_command_STARTTLS': {
                'type': 'str',
            },
            'recv_client_command_others': {
                'type': 'str',
            },
            'recv_server_service_not_ready': {
                'type': 'str',
            },
            'recv_server_unknow_reply_code': {
                'type': 'str',
            },
            'send_client_service_ready': {
                'type': 'str',
            },
            'send_client_service_not_ready': {
                'type': 'str',
            },
            'send_client_close_connection': {
                'type': 'str',
            },
            'send_client_go_ahead': {
                'type': 'str',
            },
            'send_client_start_TLS_first': {
                'type': 'str',
            },
            'send_client_TLS_not_available': {
                'type': 'str',
            },
            'send_client_no_command': {
                'type': 'str',
            },
            'send_server_cmd_reset': {
                'type': 'str',
            },
            'TLS_established': {
                'type': 'str',
            },
            'L4_switch': {
                'type': 'str',
            },
            'Aflex_switch': {
                'type': 'str',
            },
            'Aflex_switch_ok': {
                'type': 'str',
            },
            'client_domain_switch': {
                'type': 'str',
            },
            'client_domain_switch_ok': {
                'type': 'str',
            },
            'LB_switch': {
                'type': 'str',
            },
            'LB_switch_ok': {
                'type': 'str',
            },
            'read_request_line_fail': {
                'type': 'str',
            },
            'get_all_headers_fail': {
                'type': 'str',
            },
            'too_many_headers': {
                'type': 'str',
            },
            'line_too_long': {
                'type': 'str',
            },
            'line_across_packet': {
                'type': 'str',
            },
            'line_extend': {
                'type': 'str',
            },
            'line_extend_fail': {
                'type': 'str',
            },
            'line_table_extend': {
                'type': 'str',
            },
            'line_table_extend_fail': {
                'type': 'str',
            },
            'parse_request_line_fail': {
                'type': 'str',
            },
            'insert_resonse_line_fail': {
                'type': 'str',
            },
            'remove_resonse_line_fail': {
                'type': 'str',
            },
            'parse_resonse_line_fail': {
                'type': 'str',
            },
            'Aflex_lb_reselect': {
                'type': 'str',
            },
            'Aflex_lb_reselect_ok': {
                'type': 'str',
            },
            'server_STARTTLS_init': {
                'type': 'str',
            },
            'server_STARTTLS_fail': {
                'type': 'str',
            },
            'rserver_STARTTLS_disable': {
                'type': 'str',
            },
            'recv_client_command_TURN': {
                'type': 'str',
            },
            'recv_client_command_ETRN': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/smtp"

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


def _get(module, url, params={}):

    resp = None
    try:
        resp = module.client.get(url, params=params)
    except a10_ex.NotFound:
        resp = "Not Found"

    call_result = {
        "endpoint": url,
        "http_method": "GET",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _post(module, url, params={}, file_content=None, file_name=None):
    resp = module.client.post(url, params=params)
    resp = resp if resp else {}
    call_result = {
        "endpoint": url,
        "http_method": "POST",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _delete(module, url):
    call_result = {
        "endpoint": url,
        "http_method": "DELETE",
        "request_body": {},
        "response_body": module.client.delete(url),
    }
    return call_result


def _switch_device_context(module, device_id):
    call_result = {
        "endpoint": "/axapi/v3/device-context",
        "http_method": "POST",
        "request_body": {
            "device-id": device_id
        },
        "response_body": module.client.change_context(device_id)
    }
    return call_result


def _active_partition(module, a10_partition):
    call_result = {
        "endpoint": "/axapi/v3/active-partition",
        "http_method": "POST",
        "request_body": {
            "curr_part_name": a10_partition
        },
        "response_body": module.client.activate_partition(a10_partition)
    }
    return call_result


def get(module):
    return _get(module, existing_url(module))


def get_list(module):
    return _get(module, list_url(module))


def get_oper(module):
    query_params = {}
    if module.params.get("oper"):
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, oper_url(module), params=query_params)


def get_stats(module):
    query_params = {}
    if module.params.get("stats"):
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, stats_url(module), params=query_params)


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
    url_base = "/axapi/v3/slb/smtp"

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
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["smtp"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["smtp"].get(k) != v:
            change_results["changed"] = True
            config_changes["smtp"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload):
    try:
        call_result = _post(module, new_url(module), payload)
        result["axapi_calls"].append(call_result)
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        module.client.session.close()
    return result


def update(module, result, existing_config, payload):
    try:
        call_result = _post(module, existing_url(module), payload)
        result["axapi_calls"].append(call_result)
        if call_result["response_body"] == existing_config:
            result["changed"] = False
        else:
            result["modified_values"].update(**call_result["response_body"])
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        module.client.session.close()
    return result


def present(module, result, existing_config):
    payload = build_json("smtp", module)
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
        call_result = _delete(module, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        module.client.session.close()
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

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
    finally:
        module.client.session.close()
    return result


def run_command(module):
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[])

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

    run_errors = []
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
        result["axapi_calls"].append(_active_partition(module, a10_partition))

    if a10_device_context_id:
        result["axapi_calls"].append(
            _switch_device_context(module, a10_device_context_id))

    existing_config = get(module)
    result["axapi_calls"].append(existing_config)
    if existing_config['response_body'] != 'Not Found':
        existing_config = existing_config["response_body"]
    else:
        existing_config = None

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["axapi_calls"].append(get(module))
        elif module.params.get("get_type") == "list":
            result["axapi_calls"].append(get_list(module))
        elif module.params.get("get_type") == "oper":
            result["axapi_calls"].append(get_oper(module))
        elif module.params.get("get_type") == "stats":
            result["axapi_calls"].append(get_stats(module))

    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
