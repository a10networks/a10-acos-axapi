#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_generic_proxy
description:
    - Configure Generic Proxy
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
                - "'all'= all; 'num'= Number; 'curr'= Current; 'total'= Total; 'svrsel_fail'=
          Number of server selection failed; 'no_route'= Number of no routes;
          'snat_fail'= Number of snat failures; 'client_fail'= Number of client failures;
          'server_fail'= Number of server failures; 'no_sess'= Number of no sessions;
          'user_session'= Number of user sessions; 'acr_out'= Number of ACRs out;
          'acr_in'= Number of ACRs in; 'aca_out'= Number of ACAs out; 'aca_in'= Number of
          ACAs in; 'cea_out'= Number of CEAs out; 'cea_in'= Number of CEAs in; 'cer_out'=
          Number of CERs out; 'cer_in'= Number of CERs in; 'dwr_out'= Number of DWRs out;
          'dwr_in'= Number of DWRs in; 'dwa_out'= Number of DWAs out; 'dwa_in'= Number of
          DWAs in; 'str_out'= Number of STRs out; 'str_in'= Number of STRs in; 'sta_out'=
          Number of STAs out; 'sta_in'= Number of STAs in; 'asr_out'= Number of ASRs out;
          'asr_in'= Number of ASRs in; 'asa_out'= Number of ASAs out; 'asa_in'= Number of
          ASAs in; 'other_out'= Number of other messages out; 'other_in'= Number of other
          messages in; 'total_http_req_enter_gen'= Total number of HTTP requests enter
          generic proxy; 'mismatch_fwd_id'= Diameter mismatch fwd session id;
          'mismatch_rev_id'= Diameter mismatch rev session id; 'unkwn_cmd_code'= Diameter
          unkown cmd code; 'no_session_id'= Diameter no session id avp; 'no_fwd_tuple'=
          Diameter no fwd tuple matched; 'no_rev_tuple'= Diameter no rev tuple matched;
          'dcmsg_fwd_in'= Diameter cross cpu fwd in; 'dcmsg_fwd_out'= Diameter cross cpu
          fwd out; 'dcmsg_rev_in'= Diameter cross cpu rev in; 'dcmsg_rev_out'= Diameter
          cross cpu rev out; 'dcmsg_error'= Diameter cross cpu error;
          'retry_client_request'= Diameter retry client request;
          'retry_client_request_fail'= Diameter retry client request fail;
          'reply_unknown_session_id'= Reply with unknown session ID error info;
          'ccr_out'= Number of CCRs out; 'ccr_in'= Number of CCRs in; 'cca_out'= Number
          of CCAs out; 'cca_in'= Number of CCAs in; 'ccr_i'= Number of CCRs initial;
          'ccr_u'= Number of CCRs update; 'ccr_t'= Number of CCRs terminate; 'cca_t'=
          Number of CCAs terminate; 'terminate_on_cca_t'= Diameter terminate on cca_t;
          'forward_unknown_session_id'= Forward server side message with unknown session
          id; 'update_latest_server'= Update to the latest server that used a session id;
          'client_select_fail'= Fail to select client; 'close_conn_when_vport_down'=
          Close client conn when virtual port is down; 'invalid_avp'= AVP value contains
          illegal chars; 'reselect_fwd_tuple'= Original client tuple does not exist so
          reselect another one; 'reselect_fwd_tuple_other_cpu'= Original client tuple
          does not exist so reselect another one on other CPUs; 'reselect_rev_tuple'=
          Original server tuple does not exist so reselect another one;
          'conn_closed_by_client'= Client initiates TCP close/reset;
          'conn_closed_by_server'= Server initiates TCP close/reset;
          'reply_invalid_avp_value'= Reply with invalid AVP error info;
          'reply_unable_to_deliver'= Reply with unable to deliver error info;
          'reply_error_info_fail'= Fail to reply error info to peer; 'dpr_out'= Number of
          DPRs out; 'dpr_in'= Number of DPRs in; 'dpa_out'= Number of DPAs out; 'dpa_in'=
          Number of DPAs in; 'diameter_too_busy_in'= Number of DIAMETER_TOO_BUSY in;
          'diameter_too_busy_out'= Number of DIAMETER_TOO_BUSY out;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            generic_proxy_cpu_list:
                description:
                - "Field generic_proxy_cpu_list"
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
            num:
                description:
                - "Number"
                type: str
            curr:
                description:
                - "Current"
                type: str
            total:
                description:
                - "Total"
                type: str
            svrsel_fail:
                description:
                - "Number of server selection failed"
                type: str
            no_route:
                description:
                - "Number of no routes"
                type: str
            snat_fail:
                description:
                - "Number of snat failures"
                type: str
            client_fail:
                description:
                - "Number of client failures"
                type: str
            server_fail:
                description:
                - "Number of server failures"
                type: str
            no_sess:
                description:
                - "Number of no sessions"
                type: str
            user_session:
                description:
                - "Number of user sessions"
                type: str
            acr_out:
                description:
                - "Number of ACRs out"
                type: str
            acr_in:
                description:
                - "Number of ACRs in"
                type: str
            aca_out:
                description:
                - "Number of ACAs out"
                type: str
            aca_in:
                description:
                - "Number of ACAs in"
                type: str
            cea_out:
                description:
                - "Number of CEAs out"
                type: str
            cea_in:
                description:
                - "Number of CEAs in"
                type: str
            cer_out:
                description:
                - "Number of CERs out"
                type: str
            cer_in:
                description:
                - "Number of CERs in"
                type: str
            dwr_out:
                description:
                - "Number of DWRs out"
                type: str
            dwr_in:
                description:
                - "Number of DWRs in"
                type: str
            dwa_out:
                description:
                - "Number of DWAs out"
                type: str
            dwa_in:
                description:
                - "Number of DWAs in"
                type: str
            str_out:
                description:
                - "Number of STRs out"
                type: str
            str_in:
                description:
                - "Number of STRs in"
                type: str
            sta_out:
                description:
                - "Number of STAs out"
                type: str
            sta_in:
                description:
                - "Number of STAs in"
                type: str
            asr_out:
                description:
                - "Number of ASRs out"
                type: str
            asr_in:
                description:
                - "Number of ASRs in"
                type: str
            asa_out:
                description:
                - "Number of ASAs out"
                type: str
            asa_in:
                description:
                - "Number of ASAs in"
                type: str
            other_out:
                description:
                - "Number of other messages out"
                type: str
            other_in:
                description:
                - "Number of other messages in"
                type: str
            total_http_req_enter_gen:
                description:
                - "Total number of HTTP requests enter generic proxy"
                type: str
            mismatch_fwd_id:
                description:
                - "Diameter mismatch fwd session id"
                type: str
            mismatch_rev_id:
                description:
                - "Diameter mismatch rev session id"
                type: str
            unkwn_cmd_code:
                description:
                - "Diameter unkown cmd code"
                type: str
            no_session_id:
                description:
                - "Diameter no session id avp"
                type: str
            no_fwd_tuple:
                description:
                - "Diameter no fwd tuple matched"
                type: str
            no_rev_tuple:
                description:
                - "Diameter no rev tuple matched"
                type: str
            dcmsg_fwd_in:
                description:
                - "Diameter cross cpu fwd in"
                type: str
            dcmsg_fwd_out:
                description:
                - "Diameter cross cpu fwd out"
                type: str
            dcmsg_rev_in:
                description:
                - "Diameter cross cpu rev in"
                type: str
            dcmsg_rev_out:
                description:
                - "Diameter cross cpu rev out"
                type: str
            dcmsg_error:
                description:
                - "Diameter cross cpu error"
                type: str
            retry_client_request:
                description:
                - "Diameter retry client request"
                type: str
            retry_client_request_fail:
                description:
                - "Diameter retry client request fail"
                type: str
            reply_unknown_session_id:
                description:
                - "Reply with unknown session ID error info"
                type: str
            ccr_out:
                description:
                - "Number of CCRs out"
                type: str
            ccr_in:
                description:
                - "Number of CCRs in"
                type: str
            cca_out:
                description:
                - "Number of CCAs out"
                type: str
            cca_in:
                description:
                - "Number of CCAs in"
                type: str
            ccr_i:
                description:
                - "Number of CCRs initial"
                type: str
            ccr_u:
                description:
                - "Number of CCRs update"
                type: str
            ccr_t:
                description:
                - "Number of CCRs terminate"
                type: str
            cca_t:
                description:
                - "Number of CCAs terminate"
                type: str
            terminate_on_cca_t:
                description:
                - "Diameter terminate on cca_t"
                type: str
            forward_unknown_session_id:
                description:
                - "Forward server side message with unknown session id"
                type: str
            update_latest_server:
                description:
                - "Update to the latest server that used a session id"
                type: str
            client_select_fail:
                description:
                - "Fail to select client"
                type: str
            close_conn_when_vport_down:
                description:
                - "Close client conn when virtual port is down"
                type: str
            invalid_avp:
                description:
                - "AVP value contains illegal chars"
                type: str
            reselect_fwd_tuple:
                description:
                - "Original client tuple does not exist so reselect another one"
                type: str
            reselect_fwd_tuple_other_cpu:
                description:
                - "Original client tuple does not exist so reselect another one on other CPUs"
                type: str
            reselect_rev_tuple:
                description:
                - "Original server tuple does not exist so reselect another one"
                type: str
            conn_closed_by_client:
                description:
                - "Client initiates TCP close/reset"
                type: str
            conn_closed_by_server:
                description:
                - "Server initiates TCP close/reset"
                type: str
            reply_invalid_avp_value:
                description:
                - "Reply with invalid AVP error info"
                type: str
            reply_unable_to_deliver:
                description:
                - "Reply with unable to deliver error info"
                type: str
            reply_error_info_fail:
                description:
                - "Fail to reply error info to peer"
                type: str
            dpr_out:
                description:
                - "Number of DPRs out"
                type: str
            dpr_in:
                description:
                - "Number of DPRs in"
                type: str
            dpa_out:
                description:
                - "Number of DPAs out"
                type: str
            dpa_in:
                description:
                - "Number of DPAs in"
                type: str
            diameter_too_busy_in:
                description:
                - "Number of DIAMETER_TOO_BUSY in"
                type: str
            diameter_too_busy_out:
                description:
                - "Number of DIAMETER_TOO_BUSY out"
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
                    'all', 'num', 'curr', 'total', 'svrsel_fail', 'no_route', 'snat_fail', 'client_fail', 'server_fail', 'no_sess', 'user_session', 'acr_out', 'acr_in', 'aca_out', 'aca_in', 'cea_out', 'cea_in', 'cer_out', 'cer_in', 'dwr_out', 'dwr_in', 'dwa_out', 'dwa_in', 'str_out', 'str_in', 'sta_out', 'sta_in', 'asr_out', 'asr_in', 'asa_out',
                    'asa_in', 'other_out', 'other_in', 'total_http_req_enter_gen', 'mismatch_fwd_id', 'mismatch_rev_id', 'unkwn_cmd_code', 'no_session_id', 'no_fwd_tuple', 'no_rev_tuple', 'dcmsg_fwd_in', 'dcmsg_fwd_out', 'dcmsg_rev_in', 'dcmsg_rev_out', 'dcmsg_error', 'retry_client_request', 'retry_client_request_fail', 'reply_unknown_session_id',
                    'ccr_out', 'ccr_in', 'cca_out', 'cca_in', 'ccr_i', 'ccr_u', 'ccr_t', 'cca_t', 'terminate_on_cca_t', 'forward_unknown_session_id', 'update_latest_server', 'client_select_fail', 'close_conn_when_vport_down', 'invalid_avp', 'reselect_fwd_tuple', 'reselect_fwd_tuple_other_cpu', 'reselect_rev_tuple', 'conn_closed_by_client',
                    'conn_closed_by_server', 'reply_invalid_avp_value', 'reply_unable_to_deliver', 'reply_error_info_fail', 'dpr_out', 'dpr_in', 'dpa_out', 'dpa_in', 'diameter_too_busy_in', 'diameter_too_busy_out'
                    ]
                }
            },
        'oper': {
            'type': 'dict',
            'generic_proxy_cpu_list': {
                'type': 'list',
                'curr_proxy_conns': {
                    'type': 'int',
                    },
                'total_proxy_conns': {
                    'type': 'int',
                    },
                'total_http_conn_generic_proxy': {
                    'type': 'int',
                    },
                'client_fail': {
                    'type': 'int',
                    },
                'server_fail': {
                    'type': 'int',
                    },
                'server_selection_fail': {
                    'type': 'int',
                    },
                'no_route_fail': {
                    'type': 'int',
                    },
                'source_nat_fail': {
                    'type': 'int',
                    },
                'user_session': {
                    'type': 'str',
                    },
                'acr_out': {
                    'type': 'int',
                    },
                'acr_in': {
                    'type': 'int',
                    },
                'aca_out': {
                    'type': 'int',
                    },
                'aca_in': {
                    'type': 'int',
                    },
                'dpr_out': {
                    'type': 'int',
                    },
                'dpr_in': {
                    'type': 'int',
                    },
                'dpa_out': {
                    'type': 'int',
                    },
                'dpa_in': {
                    'type': 'int',
                    },
                'cea_out': {
                    'type': 'int',
                    },
                'cea_in': {
                    'type': 'int',
                    },
                'cer_out': {
                    'type': 'int',
                    },
                'cer_in': {
                    'type': 'int',
                    },
                'dwa_out': {
                    'type': 'int',
                    },
                'dwa_in': {
                    'type': 'int',
                    },
                'dwr_out': {
                    'type': 'int',
                    },
                'dwr_in': {
                    'type': 'int',
                    },
                'str_out': {
                    'type': 'int',
                    },
                'str_in': {
                    'type': 'int',
                    },
                'sta_out': {
                    'type': 'int',
                    },
                'sta_in': {
                    'type': 'int',
                    },
                'asr_out': {
                    'type': 'int',
                    },
                'asr_in': {
                    'type': 'int',
                    },
                'asa_out': {
                    'type': 'int',
                    },
                'asa_in': {
                    'type': 'int',
                    },
                'other_out': {
                    'type': 'int',
                    },
                'other_in': {
                    'type': 'int',
                    },
                'mismatch_fwd_id': {
                    'type': 'int',
                    },
                'mismatch_rev_id': {
                    'type': 'int',
                    },
                'unkwn_cmd_code': {
                    'type': 'int',
                    },
                'no_session_id': {
                    'type': 'int',
                    },
                'no_fwd_tuple': {
                    'type': 'int',
                    },
                'no_rev_tuple': {
                    'type': 'int',
                    },
                'dcmsg_fwd_in': {
                    'type': 'int',
                    },
                'dcmsg_fwd_out': {
                    'type': 'int',
                    },
                'dcmsg_rev_in': {
                    'type': 'int',
                    },
                'dcmsg_rev_out': {
                    'type': 'int',
                    },
                'dcmsg_error': {
                    'type': 'int',
                    },
                'retry_client_request': {
                    'type': 'int',
                    },
                'retry_client_request_fail': {
                    'type': 'int',
                    },
                'reply_unknown_session_id': {
                    'type': 'int',
                    },
                'ccr_out': {
                    'type': 'int',
                    },
                'ccr_in': {
                    'type': 'int',
                    },
                'cca_out': {
                    'type': 'int',
                    },
                'cca_in': {
                    'type': 'int',
                    },
                'ccr_i': {
                    'type': 'int',
                    },
                'ccr_u': {
                    'type': 'int',
                    },
                'ccr_t': {
                    'type': 'int',
                    },
                'cca_t': {
                    'type': 'int',
                    },
                'terminate_on_cca_t': {
                    'type': 'int',
                    },
                'forward_unknown_session_id': {
                    'type': 'int',
                    },
                'update_latest_server': {
                    'type': 'int',
                    },
                'client_select_fail': {
                    'type': 'int',
                    },
                'close_conn_when_vport_down': {
                    'type': 'int',
                    },
                'invalid_avp': {
                    'type': 'int',
                    },
                'reselect_fwd_tuple': {
                    'type': 'int',
                    },
                'reselect_fwd_tuple_other_cpu': {
                    'type': 'int',
                    },
                'reselect_rev_tuple': {
                    'type': 'int',
                    },
                'conn_closed_by_client': {
                    'type': 'int',
                    },
                'conn_closed_by_server': {
                    'type': 'int',
                    },
                'reply_invalid_avp_value': {
                    'type': 'int',
                    },
                'reply_unable_to_deliver': {
                    'type': 'int',
                    },
                'reply_error_info_fail': {
                    'type': 'int',
                    },
                'diameter_too_busy_in': {
                    'type': 'int',
                    },
                'diameter_too_busy_out': {
                    'type': 'int',
                    }
                },
            'cpu_count': {
                'type': 'int',
                }
            },
        'stats': {
            'type': 'dict',
            'num': {
                'type': 'str',
                },
            'curr': {
                'type': 'str',
                },
            'total': {
                'type': 'str',
                },
            'svrsel_fail': {
                'type': 'str',
                },
            'no_route': {
                'type': 'str',
                },
            'snat_fail': {
                'type': 'str',
                },
            'client_fail': {
                'type': 'str',
                },
            'server_fail': {
                'type': 'str',
                },
            'no_sess': {
                'type': 'str',
                },
            'user_session': {
                'type': 'str',
                },
            'acr_out': {
                'type': 'str',
                },
            'acr_in': {
                'type': 'str',
                },
            'aca_out': {
                'type': 'str',
                },
            'aca_in': {
                'type': 'str',
                },
            'cea_out': {
                'type': 'str',
                },
            'cea_in': {
                'type': 'str',
                },
            'cer_out': {
                'type': 'str',
                },
            'cer_in': {
                'type': 'str',
                },
            'dwr_out': {
                'type': 'str',
                },
            'dwr_in': {
                'type': 'str',
                },
            'dwa_out': {
                'type': 'str',
                },
            'dwa_in': {
                'type': 'str',
                },
            'str_out': {
                'type': 'str',
                },
            'str_in': {
                'type': 'str',
                },
            'sta_out': {
                'type': 'str',
                },
            'sta_in': {
                'type': 'str',
                },
            'asr_out': {
                'type': 'str',
                },
            'asr_in': {
                'type': 'str',
                },
            'asa_out': {
                'type': 'str',
                },
            'asa_in': {
                'type': 'str',
                },
            'other_out': {
                'type': 'str',
                },
            'other_in': {
                'type': 'str',
                },
            'total_http_req_enter_gen': {
                'type': 'str',
                },
            'mismatch_fwd_id': {
                'type': 'str',
                },
            'mismatch_rev_id': {
                'type': 'str',
                },
            'unkwn_cmd_code': {
                'type': 'str',
                },
            'no_session_id': {
                'type': 'str',
                },
            'no_fwd_tuple': {
                'type': 'str',
                },
            'no_rev_tuple': {
                'type': 'str',
                },
            'dcmsg_fwd_in': {
                'type': 'str',
                },
            'dcmsg_fwd_out': {
                'type': 'str',
                },
            'dcmsg_rev_in': {
                'type': 'str',
                },
            'dcmsg_rev_out': {
                'type': 'str',
                },
            'dcmsg_error': {
                'type': 'str',
                },
            'retry_client_request': {
                'type': 'str',
                },
            'retry_client_request_fail': {
                'type': 'str',
                },
            'reply_unknown_session_id': {
                'type': 'str',
                },
            'ccr_out': {
                'type': 'str',
                },
            'ccr_in': {
                'type': 'str',
                },
            'cca_out': {
                'type': 'str',
                },
            'cca_in': {
                'type': 'str',
                },
            'ccr_i': {
                'type': 'str',
                },
            'ccr_u': {
                'type': 'str',
                },
            'ccr_t': {
                'type': 'str',
                },
            'cca_t': {
                'type': 'str',
                },
            'terminate_on_cca_t': {
                'type': 'str',
                },
            'forward_unknown_session_id': {
                'type': 'str',
                },
            'update_latest_server': {
                'type': 'str',
                },
            'client_select_fail': {
                'type': 'str',
                },
            'close_conn_when_vport_down': {
                'type': 'str',
                },
            'invalid_avp': {
                'type': 'str',
                },
            'reselect_fwd_tuple': {
                'type': 'str',
                },
            'reselect_fwd_tuple_other_cpu': {
                'type': 'str',
                },
            'reselect_rev_tuple': {
                'type': 'str',
                },
            'conn_closed_by_client': {
                'type': 'str',
                },
            'conn_closed_by_server': {
                'type': 'str',
                },
            'reply_invalid_avp_value': {
                'type': 'str',
                },
            'reply_unable_to_deliver': {
                'type': 'str',
                },
            'reply_error_info_fail': {
                'type': 'str',
                },
            'dpr_out': {
                'type': 'str',
                },
            'dpr_in': {
                'type': 'str',
                },
            'dpa_out': {
                'type': 'str',
                },
            'dpa_in': {
                'type': 'str',
                },
            'diameter_too_busy_in': {
                'type': 'str',
                },
            'diameter_too_busy_out': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/generic-proxy"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/generic-proxy"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["generic-proxy"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["generic-proxy"].get(k) != v:
            change_results["changed"] = True
            config_changes["generic-proxy"][k] = v

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
    payload = utils.build_json("generic-proxy", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["generic-proxy"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["generic-proxy-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["generic-proxy"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["generic-proxy"]["stats"] if info != "NotFound" else info
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
