#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_smpp
description:
    - Configure SMPP
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
                - "'all'= all; 'msg_proxy_current'= Curr SMPP Proxy; 'msg_proxy_total'= Total SMPP
          Proxy; 'msg_proxy_mem_allocd'= msg_proxy_mem_allocd; 'msg_proxy_mem_cached'=
          msg_proxy_mem_cached; 'msg_proxy_mem_freed'= msg_proxy_mem_freed;
          'msg_proxy_client_recv'= Client message rcvd; 'msg_proxy_client_send_success'=
          Sent to server; 'msg_proxy_client_incomplete'= Incomplete;
          'msg_proxy_client_drop'= AX responds directly; 'msg_proxy_client_connection'=
          Connecting server; 'msg_proxy_client_fail'= Number of SMPP messages received
          from client but failed to forward to server; 'msg_proxy_client_fail_parse'=
          msg_proxy_client_fail_parse; 'msg_proxy_client_fail_process'=
          msg_proxy_client_fail_process; 'msg_proxy_client_fail_snat'=
          msg_proxy_client_fail_snat; 'msg_proxy_client_exceed_tmp_buff'=
          msg_proxy_client_exceed_tmp_buff; 'msg_proxy_client_fail_send_pkt'=
          msg_proxy_client_fail_send_pkt; 'msg_proxy_client_fail_start_server_Conn'=
          msg_proxy_client_fail_start_server_Conn; 'msg_proxy_server_recv'= Server
          message rcvd; 'msg_proxy_server_send_success'= Sent to client;
          'msg_proxy_server_incomplete'= Incomplete; 'msg_proxy_server_drop'= Number of
          the packet AX drop; 'msg_proxy_server_fail'= Number of SMPP messages received
          from server but failed to forward to client; 'msg_proxy_server_fail_parse'=
          msg_proxy_server_fail_parse; 'msg_proxy_server_fail_process'=
          msg_proxy_server_fail_process; 'msg_proxy_server_fail_selec_connt'=
          msg_proxy_server_fail_selec_connt; 'msg_proxy_server_fail_snat'=
          msg_proxy_server_fail_snat; 'msg_proxy_server_exceed_tmp_buff'=
          msg_proxy_server_exceed_tmp_buff; 'msg_proxy_server_fail_send_pkt'=
          msg_proxy_server_fail_send_pkt; 'msg_proxy_create_server_conn'= Server conn
          created; 'msg_proxy_start_server_conn'= Number of server connection created
          successfully; 'msg_proxy_fail_start_server_conn'= Number of server connection
          created failed; 'msg_proxy_server_conn_fail_snat'=
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
          'msg_proxy_server_reset'= msg_proxy_server_reset; 'payload_allocd'=
          payload_allocd; 'payload_freed'= payload_freed; 'pkt_too_small'= pkt_too_small;
          'invalid_seq'= invalid_seq; 'AX_response_directly'= Number of packet which AX
          responds directly; 'select_client_conn'= Client conn selection;
          'select_client_by_req'= Select by request; 'select_client_from_list'= Select by
          roundbin; 'select_client_by_conn'= Select by conn; 'select_client_fail'= Select
          failed; 'select_server_conn'= Server conn selection; 'select_server_by_req'=
          Select by request; 'select_server_from_list'= Select by roundbin;
          'select_server_by_conn'= Select server conn by client conn;
          'select_server_fail'= Fail to select server conn; 'bind_conn'= bind_conn;
          'unbind_conn'= unbind_conn; 'enquire_link_recv'= enquire_link_recv;
          'enquire_link_resp_recv'= enquire_link_resp_recv; 'enquire_link_send'=
          enquire_link_send; 'enquire_link_resp_send'= enquire_link_resp_send;
          'client_conn_put_in_list'= client_conn_put_in_list;
          'client_conn_get_from_list'= client_conn_get_from_list;
          'server_conn_put_in_list'= server_conn_put_in_list;
          'server_conn_get_from_list'= server_conn_get_from_list;
          'server_conn_fail_bind'= server_conn_fail_bind; 'single_msg'= single_msg;
          'fail_bind_msg'= fail_bind_msg;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            smpp_cpu_fields:
                description:
                - "Field smpp_cpu_fields"
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
                - "Curr SMPP Proxy"
                type: str
            msg_proxy_total:
                description:
                - "Total SMPP Proxy"
                type: str
            msg_proxy_client_recv:
                description:
                - "Client message rcvd"
                type: str
            msg_proxy_client_send_success:
                description:
                - "Sent to server"
                type: str
            msg_proxy_client_incomplete:
                description:
                - "Incomplete"
                type: str
            msg_proxy_client_drop:
                description:
                - "AX responds directly"
                type: str
            msg_proxy_client_connection:
                description:
                - "Connecting server"
                type: str
            msg_proxy_client_fail:
                description:
                - "Number of SMPP messages received from client but failed to forward to server"
                type: str
            msg_proxy_server_recv:
                description:
                - "Server message rcvd"
                type: str
            msg_proxy_server_send_success:
                description:
                - "Sent to client"
                type: str
            msg_proxy_server_incomplete:
                description:
                - "Incomplete"
                type: str
            msg_proxy_server_drop:
                description:
                - "Number of the packet AX drop"
                type: str
            msg_proxy_server_fail:
                description:
                - "Number of SMPP messages received from server but failed to forward to client"
                type: str
            msg_proxy_create_server_conn:
                description:
                - "Server conn created"
                type: str
            msg_proxy_start_server_conn:
                description:
                - "Number of server connection created successfully"
                type: str
            msg_proxy_fail_start_server_conn:
                description:
                - "Number of server connection created failed"
                type: str
            AX_response_directly:
                description:
                - "Number of packet which AX responds directly"
                type: str
            select_client_conn:
                description:
                - "Client conn selection"
                type: str
            select_client_by_req:
                description:
                - "Select by request"
                type: str
            select_client_from_list:
                description:
                - "Select by roundbin"
                type: str
            select_client_by_conn:
                description:
                - "Select by conn"
                type: str
            select_client_fail:
                description:
                - "Select failed"
                type: str
            select_server_conn:
                description:
                - "Server conn selection"
                type: str
            select_server_by_req:
                description:
                - "Select by request"
                type: str
            select_server_from_list:
                description:
                - "Select by roundbin"
                type: str
            select_server_by_conn:
                description:
                - "Select server conn by client conn"
                type: str
            select_server_fail:
                description:
                - "Fail to select server conn"
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
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_client import \
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
                    'payload_allocd', 'payload_freed', 'pkt_too_small',
                    'invalid_seq', 'AX_response_directly',
                    'select_client_conn', 'select_client_by_req',
                    'select_client_from_list', 'select_client_by_conn',
                    'select_client_fail', 'select_server_conn',
                    'select_server_by_req', 'select_server_from_list',
                    'select_server_by_conn', 'select_server_fail', 'bind_conn',
                    'unbind_conn', 'enquire_link_recv',
                    'enquire_link_resp_recv', 'enquire_link_send',
                    'enquire_link_resp_send', 'client_conn_put_in_list',
                    'client_conn_get_from_list', 'server_conn_put_in_list',
                    'server_conn_get_from_list', 'server_conn_fail_bind',
                    'single_msg', 'fail_bind_msg'
                ]
            }
        },
        'oper': {
            'type': 'dict',
            'smpp_cpu_fields': {
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
                'payload_allocd': {
                    'type': 'int',
                },
                'payload_freed': {
                    'type': 'int',
                },
                'pkt_too_small': {
                    'type': 'int',
                },
                'invalid_seq': {
                    'type': 'int',
                },
                'AX_response_directly': {
                    'type': 'int',
                },
                'select_client_conn': {
                    'type': 'int',
                },
                'select_client_by_req': {
                    'type': 'int',
                },
                'select_client_from_list': {
                    'type': 'int',
                },
                'select_client_by_conn': {
                    'type': 'int',
                },
                'select_client_fail': {
                    'type': 'int',
                },
                'select_server_conn': {
                    'type': 'int',
                },
                'select_server_by_req': {
                    'type': 'int',
                },
                'select_server_from_list': {
                    'type': 'int',
                },
                'select_server_by_conn': {
                    'type': 'int',
                },
                'select_server_fail': {
                    'type': 'int',
                },
                'bind_conn': {
                    'type': 'int',
                },
                'unbind_conn': {
                    'type': 'int',
                },
                'enquire_link_recv': {
                    'type': 'int',
                },
                'enquire_link_resp_recv': {
                    'type': 'int',
                },
                'enquire_link_send': {
                    'type': 'int',
                },
                'enquire_link_resp_send': {
                    'type': 'int',
                },
                'client_conn_put_in_list': {
                    'type': 'int',
                },
                'client_conn_get_from_list': {
                    'type': 'int',
                },
                'server_conn_put_in_list': {
                    'type': 'int',
                },
                'server_conn_get_from_list': {
                    'type': 'int',
                },
                'server_conn_fail_bind': {
                    'type': 'int',
                },
                'single_msg': {
                    'type': 'int',
                },
                'fail_bind_msg': {
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
            'AX_response_directly': {
                'type': 'str',
            },
            'select_client_conn': {
                'type': 'str',
            },
            'select_client_by_req': {
                'type': 'str',
            },
            'select_client_from_list': {
                'type': 'str',
            },
            'select_client_by_conn': {
                'type': 'str',
            },
            'select_client_fail': {
                'type': 'str',
            },
            'select_server_conn': {
                'type': 'str',
            },
            'select_server_by_req': {
                'type': 'str',
            },
            'select_server_from_list': {
                'type': 'str',
            },
            'select_server_by_conn': {
                'type': 'str',
            },
            'select_server_fail': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/smpp"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/smpp"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["smpp"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["smpp"].get(k) != v:
            change_results["changed"] = True
            config_changes["smpp"][k] = v

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
    payload = utils.build_json("smpp", module.params, AVAILABLE_PROPERTIES)
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

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params,
                                                  requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(
                api_client.switch_device_context(module.client,
                                                 a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
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
                result["axapi_calls"].append(
                    api_client.get(module.client, existing_url(module)))
            elif module.params.get("get_type") == "list":
                result["axapi_calls"].append(
                    api_client.get_list(module.client, existing_url(module)))
            elif module.params.get("get_type") == "oper":
                result["axapi_calls"].append(
                    api_client.get_oper(module.client, existing_url(module)))
            elif module.params.get("get_type") == "stats":
                result["axapi_calls"].append(
                    api_client.get_stats(module.client, existing_url(module)))
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.session.session_id:
            module.client.session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
