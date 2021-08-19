#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_icap
description:
    - Configure ICAP
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
                - "'all'= all; 'reqmod_request'= Reqmod Request Stats; 'respmod_request'= Respmod
          Request Stats; 'reqmod_request_after_100'= Reqmod Request Sent After 100 Cont
          Stats; 'respmod_request_after_100'= Respmod Request Sent After 100 Cont Stats;
          'reqmod_response'= Reqmod Response Stats; 'respmod_response'= Respmod Response
          Stats; 'reqmod_response_after_100'= Reqmod Response After 100 Cont Stats;
          'respmod_response_after_100'= Respmod Response After 100 Cont Stats;
          'chunk_no_allow_204'= Chunk so no Allow 204 Stats; 'len_exceed_no_allow_204'=
          Length Exceeded so no Allow 204 Stats; 'result_continue'= Result Continue
          Stats; 'result_icap_response'= Result ICAP Response Stats;
          'result_100_continue'= Result 100 Continue Stats; 'result_other'= Result Other
          Stats; 'status_2xx'= Status 2xx Stats; 'status_200'= Status 200 Stats;
          'status_201'= Status 201 Stats; 'status_202'= Status 202 Stats; 'status_203'=
          Status 203 Stats; 'status_204'= Status 204 Stats; 'status_205'= Status 205
          Stats; 'status_206'= Status 206 Stats; 'status_207'= Status 207 Stats;
          'status_1xx'= Status 1xx Stats; 'status_100'= Status 100 Stats; 'status_101'=
          Status 101 Stats; 'status_102'= Status 102 Stats; 'status_3xx'= Status 3xx
          Stats; 'status_300'= Status 300 Stats; 'status_301'= Status 301 Stats;
          'status_302'= Status 302 Stats; 'status_303'= Status 303 Stats; 'status_304'=
          Status 304 Stats; 'status_305'= Status 305 Stats; 'status_306'= Status 306
          Stats; 'status_307'= Status 307 Stats; 'status_4xx'= Status 4xx Stats;
          'status_400'= Status 400 Stats; 'status_401'= Status 401 Stats; 'status_402'=
          Status 402 Stats; 'status_403'= Status 403 Stats; 'status_404'= Status 404
          Stats; 'status_405'= Status 405 Stats; 'status_406'= Status 406 Stats;
          'status_407'= Status 407 Stats; 'status_408'= Status 408 Stats; 'status_409'=
          Status 409 Stats; 'status_410'= Status 410 Stats; 'status_411'= Status 411
          Stats; 'status_412'= Status 412 Stats; 'status_413'= Status 413 Stats;
          'status_414'= Status 414 Stats; 'status_415'= Status 415 Stats; 'status_416'=
          Status 416 Stats; 'status_417'= Status 417 Stats; 'status_418'= Status 418
          Stats; 'status_419'= Status 419 Stats; 'status_420'= Status 420 Stats;
          'status_422'= Status 422 Stats; 'status_423'= Status 423 Stats; 'status_424'=
          Status 424 Stats; 'status_425'= Status 425 Stats; 'status_426'= Status 426
          Stats; 'status_449'= Status 449 Stats; 'status_450'= Status 450 Stats;
          'status_5xx'= Status 5xx Stats; 'status_500'= Status 500 Stats; 'status_501'=
          Status 501 Stats; 'status_502'= Status 502 Stats; 'status_503'= Status 503
          Stats; 'status_504'= Status 504 Stats; 'status_505'= Status 505 Stats;
          'status_506'= Status 506 Stats; 'status_507'= Status 507 Stats; 'status_508'=
          Status 508 Stats; 'status_509'= Status 509 Stats; 'status_510'= Status 510
          Stats; 'status_6xx'= Status 6xx Stats; 'status_unknown'= Status Unknown Stats;
          'send_option_req'= Send Option Req Stats; 'app_serv_conn_no_pcb_err'= App
          Server Conn no ES PCB Err Stats; 'app_serv_conn_err'= App Server Conn Err
          Stats; 'chunk1_hdr_err'= Chunk Hdr Err1 Stats; 'chunk2_hdr_err'= Chunk Hdr Err2
          Stats; 'chunk_bad_trail_err'= Chunk Bad Trail Err Stats;
          'no_payload_next_buff_err'= No Payload In Next Buff Err Stats;
          'no_payload_buff_err'= No Payload Buff Err Stats; 'resp_hdr_incomplete_err'=
          Resp Hdr Incomplete Err Stats; 'serv_sel_fail_err'= Server Select Fail Err
          Stats; 'start_icap_conn_fail_err'= Start ICAP conn fail Stats;
          'prep_req_fail_err'= Prepare ICAP req fail Err Stats; 'icap_ver_err'= ICAP Ver
          Err Stats; 'icap_line_err'= ICAP Line Err Stats; 'encap_hdr_incomplete_err'=
          Encap HDR Incomplete Err Stats; 'no_icap_resp_err'= No ICAP Resp Err Stats;
          'resp_line_read_err'= Resp Line Read Err Stats; 'resp_line_parse_err'= Resp
          Line Parse Err Stats; 'resp_hdr_err'= Resp Hdr Err Stats;
          'req_hdr_incomplete_err'= Req Hdr Incomplete Err Stats; 'no_status_code_err'=
          No Status Code Err Stats; 'http_resp_line_read_err'= HTTP Response Line Read
          Err Stats; 'http_resp_line_parse_err'= HTTP Response Line Parse Err Stats;
          'http_resp_hdr_err'= HTTP Resp Hdr Err Stats; 'recv_option_resp'= Send Option
          Req Stats;"
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
            reqmod_request:
                description:
                - "Reqmod Request Stats"
                type: str
            respmod_request:
                description:
                - "Respmod Request Stats"
                type: str
            reqmod_request_after_100:
                description:
                - "Reqmod Request Sent After 100 Cont Stats"
                type: str
            respmod_request_after_100:
                description:
                - "Respmod Request Sent After 100 Cont Stats"
                type: str
            reqmod_response:
                description:
                - "Reqmod Response Stats"
                type: str
            respmod_response:
                description:
                - "Respmod Response Stats"
                type: str
            reqmod_response_after_100:
                description:
                - "Reqmod Response After 100 Cont Stats"
                type: str
            respmod_response_after_100:
                description:
                - "Respmod Response After 100 Cont Stats"
                type: str
            chunk_no_allow_204:
                description:
                - "Chunk so no Allow 204 Stats"
                type: str
            len_exceed_no_allow_204:
                description:
                - "Length Exceeded so no Allow 204 Stats"
                type: str
            result_continue:
                description:
                - "Result Continue Stats"
                type: str
            result_icap_response:
                description:
                - "Result ICAP Response Stats"
                type: str
            result_100_continue:
                description:
                - "Result 100 Continue Stats"
                type: str
            result_other:
                description:
                - "Result Other Stats"
                type: str
            status_2xx:
                description:
                - "Status 2xx Stats"
                type: str
            status_200:
                description:
                - "Status 200 Stats"
                type: str
            status_201:
                description:
                - "Status 201 Stats"
                type: str
            status_202:
                description:
                - "Status 202 Stats"
                type: str
            status_203:
                description:
                - "Status 203 Stats"
                type: str
            status_204:
                description:
                - "Status 204 Stats"
                type: str
            status_205:
                description:
                - "Status 205 Stats"
                type: str
            status_206:
                description:
                - "Status 206 Stats"
                type: str
            status_207:
                description:
                - "Status 207 Stats"
                type: str
            status_1xx:
                description:
                - "Status 1xx Stats"
                type: str
            status_100:
                description:
                - "Status 100 Stats"
                type: str
            status_101:
                description:
                - "Status 101 Stats"
                type: str
            status_102:
                description:
                - "Status 102 Stats"
                type: str
            status_3xx:
                description:
                - "Status 3xx Stats"
                type: str
            status_300:
                description:
                - "Status 300 Stats"
                type: str
            status_301:
                description:
                - "Status 301 Stats"
                type: str
            status_302:
                description:
                - "Status 302 Stats"
                type: str
            status_303:
                description:
                - "Status 303 Stats"
                type: str
            status_304:
                description:
                - "Status 304 Stats"
                type: str
            status_305:
                description:
                - "Status 305 Stats"
                type: str
            status_306:
                description:
                - "Status 306 Stats"
                type: str
            status_307:
                description:
                - "Status 307 Stats"
                type: str
            status_4xx:
                description:
                - "Status 4xx Stats"
                type: str
            status_400:
                description:
                - "Status 400 Stats"
                type: str
            status_401:
                description:
                - "Status 401 Stats"
                type: str
            status_402:
                description:
                - "Status 402 Stats"
                type: str
            status_403:
                description:
                - "Status 403 Stats"
                type: str
            status_404:
                description:
                - "Status 404 Stats"
                type: str
            status_405:
                description:
                - "Status 405 Stats"
                type: str
            status_406:
                description:
                - "Status 406 Stats"
                type: str
            status_407:
                description:
                - "Status 407 Stats"
                type: str
            status_408:
                description:
                - "Status 408 Stats"
                type: str
            status_409:
                description:
                - "Status 409 Stats"
                type: str
            status_410:
                description:
                - "Status 410 Stats"
                type: str
            status_411:
                description:
                - "Status 411 Stats"
                type: str
            status_412:
                description:
                - "Status 412 Stats"
                type: str
            status_413:
                description:
                - "Status 413 Stats"
                type: str
            status_414:
                description:
                - "Status 414 Stats"
                type: str
            status_415:
                description:
                - "Status 415 Stats"
                type: str
            status_416:
                description:
                - "Status 416 Stats"
                type: str
            status_417:
                description:
                - "Status 417 Stats"
                type: str
            status_418:
                description:
                - "Status 418 Stats"
                type: str
            status_419:
                description:
                - "Status 419 Stats"
                type: str
            status_420:
                description:
                - "Status 420 Stats"
                type: str
            status_422:
                description:
                - "Status 422 Stats"
                type: str
            status_423:
                description:
                - "Status 423 Stats"
                type: str
            status_424:
                description:
                - "Status 424 Stats"
                type: str
            status_425:
                description:
                - "Status 425 Stats"
                type: str
            status_426:
                description:
                - "Status 426 Stats"
                type: str
            status_449:
                description:
                - "Status 449 Stats"
                type: str
            status_450:
                description:
                - "Status 450 Stats"
                type: str
            status_5xx:
                description:
                - "Status 5xx Stats"
                type: str
            status_500:
                description:
                - "Status 500 Stats"
                type: str
            status_501:
                description:
                - "Status 501 Stats"
                type: str
            status_502:
                description:
                - "Status 502 Stats"
                type: str
            status_503:
                description:
                - "Status 503 Stats"
                type: str
            status_504:
                description:
                - "Status 504 Stats"
                type: str
            status_505:
                description:
                - "Status 505 Stats"
                type: str
            status_506:
                description:
                - "Status 506 Stats"
                type: str
            status_507:
                description:
                - "Status 507 Stats"
                type: str
            status_508:
                description:
                - "Status 508 Stats"
                type: str
            status_509:
                description:
                - "Status 509 Stats"
                type: str
            status_510:
                description:
                - "Status 510 Stats"
                type: str
            status_6xx:
                description:
                - "Status 6xx Stats"
                type: str
            status_unknown:
                description:
                - "Status Unknown Stats"
                type: str
            send_option_req:
                description:
                - "Send Option Req Stats"
                type: str
            app_serv_conn_no_pcb_err:
                description:
                - "App Server Conn no ES PCB Err Stats"
                type: str
            app_serv_conn_err:
                description:
                - "App Server Conn Err Stats"
                type: str
            chunk1_hdr_err:
                description:
                - "Chunk Hdr Err1 Stats"
                type: str
            chunk2_hdr_err:
                description:
                - "Chunk Hdr Err2 Stats"
                type: str
            chunk_bad_trail_err:
                description:
                - "Chunk Bad Trail Err Stats"
                type: str
            no_payload_next_buff_err:
                description:
                - "No Payload In Next Buff Err Stats"
                type: str
            no_payload_buff_err:
                description:
                - "No Payload Buff Err Stats"
                type: str
            resp_hdr_incomplete_err:
                description:
                - "Resp Hdr Incomplete Err Stats"
                type: str
            serv_sel_fail_err:
                description:
                - "Server Select Fail Err Stats"
                type: str
            start_icap_conn_fail_err:
                description:
                - "Start ICAP conn fail Stats"
                type: str
            prep_req_fail_err:
                description:
                - "Prepare ICAP req fail Err Stats"
                type: str
            icap_ver_err:
                description:
                - "ICAP Ver Err Stats"
                type: str
            icap_line_err:
                description:
                - "ICAP Line Err Stats"
                type: str
            encap_hdr_incomplete_err:
                description:
                - "Encap HDR Incomplete Err Stats"
                type: str
            no_icap_resp_err:
                description:
                - "No ICAP Resp Err Stats"
                type: str
            resp_line_read_err:
                description:
                - "Resp Line Read Err Stats"
                type: str
            resp_line_parse_err:
                description:
                - "Resp Line Parse Err Stats"
                type: str
            resp_hdr_err:
                description:
                - "Resp Hdr Err Stats"
                type: str
            req_hdr_incomplete_err:
                description:
                - "Req Hdr Incomplete Err Stats"
                type: str
            no_status_code_err:
                description:
                - "No Status Code Err Stats"
                type: str
            http_resp_line_read_err:
                description:
                - "HTTP Response Line Read Err Stats"
                type: str
            http_resp_line_parse_err:
                description:
                - "HTTP Response Line Parse Err Stats"
                type: str
            http_resp_hdr_err:
                description:
                - "HTTP Resp Hdr Err Stats"
                type: str
            recv_option_resp:
                description:
                - "Send Option Req Stats"
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
                    'all', 'reqmod_request', 'respmod_request',
                    'reqmod_request_after_100', 'respmod_request_after_100',
                    'reqmod_response', 'respmod_response',
                    'reqmod_response_after_100', 'respmod_response_after_100',
                    'chunk_no_allow_204', 'len_exceed_no_allow_204',
                    'result_continue', 'result_icap_response',
                    'result_100_continue', 'result_other', 'status_2xx',
                    'status_200', 'status_201', 'status_202', 'status_203',
                    'status_204', 'status_205', 'status_206', 'status_207',
                    'status_1xx', 'status_100', 'status_101', 'status_102',
                    'status_3xx', 'status_300', 'status_301', 'status_302',
                    'status_303', 'status_304', 'status_305', 'status_306',
                    'status_307', 'status_4xx', 'status_400', 'status_401',
                    'status_402', 'status_403', 'status_404', 'status_405',
                    'status_406', 'status_407', 'status_408', 'status_409',
                    'status_410', 'status_411', 'status_412', 'status_413',
                    'status_414', 'status_415', 'status_416', 'status_417',
                    'status_418', 'status_419', 'status_420', 'status_422',
                    'status_423', 'status_424', 'status_425', 'status_426',
                    'status_449', 'status_450', 'status_5xx', 'status_500',
                    'status_501', 'status_502', 'status_503', 'status_504',
                    'status_505', 'status_506', 'status_507', 'status_508',
                    'status_509', 'status_510', 'status_6xx', 'status_unknown',
                    'send_option_req', 'app_serv_conn_no_pcb_err',
                    'app_serv_conn_err', 'chunk1_hdr_err', 'chunk2_hdr_err',
                    'chunk_bad_trail_err', 'no_payload_next_buff_err',
                    'no_payload_buff_err', 'resp_hdr_incomplete_err',
                    'serv_sel_fail_err', 'start_icap_conn_fail_err',
                    'prep_req_fail_err', 'icap_ver_err', 'icap_line_err',
                    'encap_hdr_incomplete_err', 'no_icap_resp_err',
                    'resp_line_read_err', 'resp_line_parse_err',
                    'resp_hdr_err', 'req_hdr_incomplete_err',
                    'no_status_code_err', 'http_resp_line_read_err',
                    'http_resp_line_parse_err', 'http_resp_hdr_err',
                    'recv_option_resp'
                ]
            }
        },
        'oper': {
            'type': 'dict',
            'l4_cpu_list': {
                'type': 'list',
                'reqmod_request': {
                    'type': 'int',
                },
                'respmod_request': {
                    'type': 'int',
                },
                'reqmod_request_after_100': {
                    'type': 'int',
                },
                'respmod_request_after_100': {
                    'type': 'int',
                },
                'reqmod_response': {
                    'type': 'int',
                },
                'respmod_response': {
                    'type': 'int',
                },
                'reqmod_response_after_100': {
                    'type': 'int',
                },
                'respmod_response_after_100': {
                    'type': 'int',
                },
                'chunk_no_allow_204': {
                    'type': 'int',
                },
                'len_exceed_no_allow_204': {
                    'type': 'int',
                },
                'result_continue': {
                    'type': 'int',
                },
                'result_icap_response': {
                    'type': 'int',
                },
                'result_100_continue': {
                    'type': 'int',
                },
                'result_other': {
                    'type': 'int',
                },
                'status_2xx': {
                    'type': 'int',
                },
                'status_200': {
                    'type': 'int',
                },
                'status_201': {
                    'type': 'int',
                },
                'status_202': {
                    'type': 'int',
                },
                'status_203': {
                    'type': 'int',
                },
                'status_204': {
                    'type': 'int',
                },
                'status_205': {
                    'type': 'int',
                },
                'status_206': {
                    'type': 'int',
                },
                'status_207': {
                    'type': 'int',
                },
                'status_1xx': {
                    'type': 'int',
                },
                'status_100': {
                    'type': 'int',
                },
                'status_101': {
                    'type': 'int',
                },
                'status_102': {
                    'type': 'int',
                },
                'status_3xx': {
                    'type': 'int',
                },
                'status_300': {
                    'type': 'int',
                },
                'status_301': {
                    'type': 'int',
                },
                'status_302': {
                    'type': 'int',
                },
                'status_303': {
                    'type': 'int',
                },
                'status_304': {
                    'type': 'int',
                },
                'status_305': {
                    'type': 'int',
                },
                'status_306': {
                    'type': 'int',
                },
                'status_307': {
                    'type': 'int',
                },
                'status_4xx': {
                    'type': 'int',
                },
                'status_400': {
                    'type': 'int',
                },
                'status_401': {
                    'type': 'int',
                },
                'status_402': {
                    'type': 'int',
                },
                'status_403': {
                    'type': 'int',
                },
                'status_404': {
                    'type': 'int',
                },
                'status_405': {
                    'type': 'int',
                },
                'status_406': {
                    'type': 'int',
                },
                'status_407': {
                    'type': 'int',
                },
                'status_408': {
                    'type': 'int',
                },
                'status_409': {
                    'type': 'int',
                },
                'status_410': {
                    'type': 'int',
                },
                'status_411': {
                    'type': 'int',
                },
                'status_412': {
                    'type': 'int',
                },
                'status_413': {
                    'type': 'int',
                },
                'status_414': {
                    'type': 'int',
                },
                'status_415': {
                    'type': 'int',
                },
                'status_416': {
                    'type': 'int',
                },
                'status_417': {
                    'type': 'int',
                },
                'status_418': {
                    'type': 'int',
                },
                'status_419': {
                    'type': 'int',
                },
                'status_420': {
                    'type': 'int',
                },
                'status_422': {
                    'type': 'int',
                },
                'status_423': {
                    'type': 'int',
                },
                'status_424': {
                    'type': 'int',
                },
                'status_425': {
                    'type': 'int',
                },
                'status_426': {
                    'type': 'int',
                },
                'status_449': {
                    'type': 'int',
                },
                'status_450': {
                    'type': 'int',
                },
                'status_5xx': {
                    'type': 'int',
                },
                'status_500': {
                    'type': 'int',
                },
                'status_501': {
                    'type': 'int',
                },
                'status_502': {
                    'type': 'int',
                },
                'status_503': {
                    'type': 'int',
                },
                'status_504': {
                    'type': 'int',
                },
                'status_505': {
                    'type': 'int',
                },
                'status_506': {
                    'type': 'int',
                },
                'status_507': {
                    'type': 'int',
                },
                'status_508': {
                    'type': 'int',
                },
                'status_509': {
                    'type': 'int',
                },
                'status_510': {
                    'type': 'int',
                },
                'status_6xx': {
                    'type': 'int',
                },
                'status_unknown': {
                    'type': 'int',
                },
                'send_option_req': {
                    'type': 'int',
                },
                'app_serv_conn_no_pcb_err': {
                    'type': 'int',
                },
                'app_serv_conn_err': {
                    'type': 'int',
                },
                'chunk1_hdr_err': {
                    'type': 'int',
                },
                'chunk2_hdr_err': {
                    'type': 'int',
                },
                'chunk_bad_trail_err': {
                    'type': 'int',
                },
                'no_payload_next_buff_err': {
                    'type': 'int',
                },
                'no_payload_buff_err': {
                    'type': 'int',
                },
                'resp_hdr_incomplete_err': {
                    'type': 'int',
                },
                'serv_sel_fail_err': {
                    'type': 'int',
                },
                'start_icap_conn_fail_err': {
                    'type': 'int',
                },
                'prep_req_fail_err': {
                    'type': 'int',
                },
                'icap_ver_err': {
                    'type': 'int',
                },
                'icap_line_err': {
                    'type': 'int',
                },
                'encap_hdr_incomplete_err': {
                    'type': 'int',
                },
                'no_icap_resp_err': {
                    'type': 'int',
                },
                'resp_line_read_err': {
                    'type': 'int',
                },
                'resp_line_parse_err': {
                    'type': 'int',
                },
                'resp_hdr_err': {
                    'type': 'int',
                },
                'req_hdr_incomplete_err': {
                    'type': 'int',
                },
                'no_status_code_err': {
                    'type': 'int',
                },
                'http_resp_line_read_err': {
                    'type': 'int',
                },
                'http_resp_line_parse_err': {
                    'type': 'int',
                },
                'http_resp_hdr_err': {
                    'type': 'int',
                },
                'recv_option_resp': {
                    'type': 'int',
                }
            },
            'cpu_count': {
                'type': 'int',
            }
        },
        'stats': {
            'type': 'dict',
            'reqmod_request': {
                'type': 'str',
            },
            'respmod_request': {
                'type': 'str',
            },
            'reqmod_request_after_100': {
                'type': 'str',
            },
            'respmod_request_after_100': {
                'type': 'str',
            },
            'reqmod_response': {
                'type': 'str',
            },
            'respmod_response': {
                'type': 'str',
            },
            'reqmod_response_after_100': {
                'type': 'str',
            },
            'respmod_response_after_100': {
                'type': 'str',
            },
            'chunk_no_allow_204': {
                'type': 'str',
            },
            'len_exceed_no_allow_204': {
                'type': 'str',
            },
            'result_continue': {
                'type': 'str',
            },
            'result_icap_response': {
                'type': 'str',
            },
            'result_100_continue': {
                'type': 'str',
            },
            'result_other': {
                'type': 'str',
            },
            'status_2xx': {
                'type': 'str',
            },
            'status_200': {
                'type': 'str',
            },
            'status_201': {
                'type': 'str',
            },
            'status_202': {
                'type': 'str',
            },
            'status_203': {
                'type': 'str',
            },
            'status_204': {
                'type': 'str',
            },
            'status_205': {
                'type': 'str',
            },
            'status_206': {
                'type': 'str',
            },
            'status_207': {
                'type': 'str',
            },
            'status_1xx': {
                'type': 'str',
            },
            'status_100': {
                'type': 'str',
            },
            'status_101': {
                'type': 'str',
            },
            'status_102': {
                'type': 'str',
            },
            'status_3xx': {
                'type': 'str',
            },
            'status_300': {
                'type': 'str',
            },
            'status_301': {
                'type': 'str',
            },
            'status_302': {
                'type': 'str',
            },
            'status_303': {
                'type': 'str',
            },
            'status_304': {
                'type': 'str',
            },
            'status_305': {
                'type': 'str',
            },
            'status_306': {
                'type': 'str',
            },
            'status_307': {
                'type': 'str',
            },
            'status_4xx': {
                'type': 'str',
            },
            'status_400': {
                'type': 'str',
            },
            'status_401': {
                'type': 'str',
            },
            'status_402': {
                'type': 'str',
            },
            'status_403': {
                'type': 'str',
            },
            'status_404': {
                'type': 'str',
            },
            'status_405': {
                'type': 'str',
            },
            'status_406': {
                'type': 'str',
            },
            'status_407': {
                'type': 'str',
            },
            'status_408': {
                'type': 'str',
            },
            'status_409': {
                'type': 'str',
            },
            'status_410': {
                'type': 'str',
            },
            'status_411': {
                'type': 'str',
            },
            'status_412': {
                'type': 'str',
            },
            'status_413': {
                'type': 'str',
            },
            'status_414': {
                'type': 'str',
            },
            'status_415': {
                'type': 'str',
            },
            'status_416': {
                'type': 'str',
            },
            'status_417': {
                'type': 'str',
            },
            'status_418': {
                'type': 'str',
            },
            'status_419': {
                'type': 'str',
            },
            'status_420': {
                'type': 'str',
            },
            'status_422': {
                'type': 'str',
            },
            'status_423': {
                'type': 'str',
            },
            'status_424': {
                'type': 'str',
            },
            'status_425': {
                'type': 'str',
            },
            'status_426': {
                'type': 'str',
            },
            'status_449': {
                'type': 'str',
            },
            'status_450': {
                'type': 'str',
            },
            'status_5xx': {
                'type': 'str',
            },
            'status_500': {
                'type': 'str',
            },
            'status_501': {
                'type': 'str',
            },
            'status_502': {
                'type': 'str',
            },
            'status_503': {
                'type': 'str',
            },
            'status_504': {
                'type': 'str',
            },
            'status_505': {
                'type': 'str',
            },
            'status_506': {
                'type': 'str',
            },
            'status_507': {
                'type': 'str',
            },
            'status_508': {
                'type': 'str',
            },
            'status_509': {
                'type': 'str',
            },
            'status_510': {
                'type': 'str',
            },
            'status_6xx': {
                'type': 'str',
            },
            'status_unknown': {
                'type': 'str',
            },
            'send_option_req': {
                'type': 'str',
            },
            'app_serv_conn_no_pcb_err': {
                'type': 'str',
            },
            'app_serv_conn_err': {
                'type': 'str',
            },
            'chunk1_hdr_err': {
                'type': 'str',
            },
            'chunk2_hdr_err': {
                'type': 'str',
            },
            'chunk_bad_trail_err': {
                'type': 'str',
            },
            'no_payload_next_buff_err': {
                'type': 'str',
            },
            'no_payload_buff_err': {
                'type': 'str',
            },
            'resp_hdr_incomplete_err': {
                'type': 'str',
            },
            'serv_sel_fail_err': {
                'type': 'str',
            },
            'start_icap_conn_fail_err': {
                'type': 'str',
            },
            'prep_req_fail_err': {
                'type': 'str',
            },
            'icap_ver_err': {
                'type': 'str',
            },
            'icap_line_err': {
                'type': 'str',
            },
            'encap_hdr_incomplete_err': {
                'type': 'str',
            },
            'no_icap_resp_err': {
                'type': 'str',
            },
            'resp_line_read_err': {
                'type': 'str',
            },
            'resp_line_parse_err': {
                'type': 'str',
            },
            'resp_hdr_err': {
                'type': 'str',
            },
            'req_hdr_incomplete_err': {
                'type': 'str',
            },
            'no_status_code_err': {
                'type': 'str',
            },
            'http_resp_line_read_err': {
                'type': 'str',
            },
            'http_resp_line_parse_err': {
                'type': 'str',
            },
            'http_resp_hdr_err': {
                'type': 'str',
            },
            'recv_option_resp': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/icap"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/icap"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["icap"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["icap"].get(k) != v:
            change_results["changed"] = True
            config_changes["icap"][k] = v

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
    payload = utils.build_json("icap", module.params, AVAILABLE_PROPERTIES)
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
