#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_icap
description:
    - Configure ICAP
short_description: Configures A10 slb.icap
author: A10 Networks 2018
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
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
            l4_cpu_list:
                description:
                - "Field l4_cpu_list"
            cpu_count:
                description:
                - "Field cpu_count"
    sampling_enable:
        description:
        - "Field sampling_enable"
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
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            status_449:
                description:
                - "Status 449 Stats"
            no_payload_buff_err:
                description:
                - "No Payload Buff Err Stats"
            prep_req_fail_err:
                description:
                - "Prepare ICAP req fail Err Stats"
            icap_ver_err:
                description:
                - "ICAP Ver Err Stats"
            resp_line_parse_err:
                description:
                - "Resp Line Parse Err Stats"
            app_serv_conn_no_pcb_err:
                description:
                - "App Server Conn no ES PCB Err Stats"
            status_450:
                description:
                - "Status 450 Stats"
            status_510:
                description:
                - "Status 510 Stats"
            encap_hdr_incomplete_err:
                description:
                - "Encap HDR Incomplete Err Stats"
            chunk_no_allow_204:
                description:
                - "Chunk so no Allow 204 Stats"
            http_resp_line_parse_err:
                description:
                - "HTTP Response Line Parse Err Stats"
            status_207:
                description:
                - "Status 207 Stats"
            status_206:
                description:
                - "Status 206 Stats"
            status_205:
                description:
                - "Status 205 Stats"
            status_204:
                description:
                - "Status 204 Stats"
            status_203:
                description:
                - "Status 203 Stats"
            status_202:
                description:
                - "Status 202 Stats"
            status_201:
                description:
                - "Status 201 Stats"
            status_200:
                description:
                - "Status 200 Stats"
            no_status_code_err:
                description:
                - "No Status Code Err Stats"
            resp_hdr_incomplete_err:
                description:
                - "Resp Hdr Incomplete Err Stats"
            respmod_request_after_100:
                description:
                - "Respmod Request Sent After 100 Cont Stats"
            reqmod_response:
                description:
                - "Reqmod Response Stats"
            status_406:
                description:
                - "Status 406 Stats"
            reqmod_response_after_100:
                description:
                - "Reqmod Response After 100 Cont Stats"
            status_4xx:
                description:
                - "Status 4xx Stats"
            no_payload_next_buff_err:
                description:
                - "No Payload In Next Buff Err Stats"
            status_3xx:
                description:
                - "Status 3xx Stats"
            reqmod_request:
                description:
                - "Reqmod Request Stats"
            recv_option_resp:
                description:
                - "Send Option Req Stats"
            no_icap_resp_err:
                description:
                - "No ICAP Resp Err Stats"
            respmod_request:
                description:
                - "Respmod Request Stats"
            app_serv_conn_err:
                description:
                - "App Server Conn Err Stats"
            result_continue:
                description:
                - "Result Continue Stats"
            len_exceed_no_allow_204:
                description:
                - "Length Exceeded so no Allow 204 Stats"
            status_306:
                description:
                - "Status 306 Stats"
            status_307:
                description:
                - "Status 307 Stats"
            status_304:
                description:
                - "Status 304 Stats"
            status_305:
                description:
                - "Status 305 Stats"
            status_302:
                description:
                - "Status 302 Stats"
            status_303:
                description:
                - "Status 303 Stats"
            status_300:
                description:
                - "Status 300 Stats"
            status_301:
                description:
                - "Status 301 Stats"
            start_icap_conn_fail_err:
                description:
                - "Start ICAP conn fail Stats"
            status_418:
                description:
                - "Status 418 Stats"
            result_100_continue:
                description:
                - "Result 100 Continue Stats"
            status_419:
                description:
                - "Status 419 Stats"
            result_other:
                description:
                - "Result Other Stats"
            chunk_bad_trail_err:
                description:
                - "Chunk Bad Trail Err Stats"
            respmod_response_after_100:
                description:
                - "Respmod Response After 100 Cont Stats"
            status_412:
                description:
                - "Status 412 Stats"
            status_413:
                description:
                - "Status 413 Stats"
            status_410:
                description:
                - "Status 410 Stats"
            status_411:
                description:
                - "Status 411 Stats"
            status_416:
                description:
                - "Status 416 Stats"
            status_417:
                description:
                - "Status 417 Stats"
            status_414:
                description:
                - "Status 414 Stats"
            status_415:
                description:
                - "Status 415 Stats"
            chunk2_hdr_err:
                description:
                - "Chunk Hdr Err2 Stats"
            status_unknown:
                description:
                - "Status Unknown Stats"
            status_100:
                description:
                - "Status 100 Stats"
            status_101:
                description:
                - "Status 101 Stats"
            status_102:
                description:
                - "Status 102 Stats"
            status_509:
                description:
                - "Status 509 Stats"
            send_option_req:
                description:
                - "Send Option Req Stats"
            http_resp_line_read_err:
                description:
                - "HTTP Response Line Read Err Stats"
            status_6xx:
                description:
                - "Status 6xx Stats"
            status_5xx:
                description:
                - "Status 5xx Stats"
            http_resp_hdr_err:
                description:
                - "HTTP Resp Hdr Err Stats"
            status_401:
                description:
                - "Status 401 Stats"
            status_400:
                description:
                - "Status 400 Stats"
            status_403:
                description:
                - "Status 403 Stats"
            status_402:
                description:
                - "Status 402 Stats"
            status_405:
                description:
                - "Status 405 Stats"
            status_404:
                description:
                - "Status 404 Stats"
            status_407:
                description:
                - "Status 407 Stats"
            status_2xx:
                description:
                - "Status 2xx Stats"
            status_409:
                description:
                - "Status 409 Stats"
            status_408:
                description:
                - "Status 408 Stats"
            respmod_response:
                description:
                - "Respmod Response Stats"
            status_505:
                description:
                - "Status 505 Stats"
            resp_line_read_err:
                description:
                - "Resp Line Read Err Stats"
            req_hdr_incomplete_err:
                description:
                - "Req Hdr Incomplete Err Stats"
            status_1xx:
                description:
                - "Status 1xx Stats"
            resp_hdr_err:
                description:
                - "Resp Hdr Err Stats"
            serv_sel_fail_err:
                description:
                - "Server Select Fail Err Stats"
            chunk1_hdr_err:
                description:
                - "Chunk Hdr Err1 Stats"
            status_423:
                description:
                - "Status 423 Stats"
            status_422:
                description:
                - "Status 422 Stats"
            status_420:
                description:
                - "Status 420 Stats"
            status_426:
                description:
                - "Status 426 Stats"
            status_425:
                description:
                - "Status 425 Stats"
            status_424:
                description:
                - "Status 424 Stats"
            status_508:
                description:
                - "Status 508 Stats"
            result_icap_response:
                description:
                - "Result ICAP Response Stats"
            status_500:
                description:
                - "Status 500 Stats"
            status_501:
                description:
                - "Status 501 Stats"
            status_502:
                description:
                - "Status 502 Stats"
            status_503:
                description:
                - "Status 503 Stats"
            status_504:
                description:
                - "Status 504 Stats"
            reqmod_request_after_100:
                description:
                - "Reqmod Request Sent After 100 Cont Stats"
            status_506:
                description:
                - "Status 506 Stats"
            status_507:
                description:
                - "Status 507 Stats"
            icap_line_err:
                description:
                - "ICAP Line Err Stats"
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
        'oper': {
            'type': 'dict',
            'l4_cpu_list': {
                'type': 'list',
                'status_449': {
                    'type': 'int',
                },
                'no_payload_buff_err': {
                    'type': 'int',
                },
                'prep_req_fail_err': {
                    'type': 'int',
                },
                'icap_ver_err': {
                    'type': 'int',
                },
                'resp_line_parse_err': {
                    'type': 'int',
                },
                'app_serv_conn_no_pcb_err': {
                    'type': 'int',
                },
                'status_450': {
                    'type': 'int',
                },
                'status_510': {
                    'type': 'int',
                },
                'encap_hdr_incomplete_err': {
                    'type': 'int',
                },
                'chunk_no_allow_204': {
                    'type': 'int',
                },
                'http_resp_line_parse_err': {
                    'type': 'int',
                },
                'status_207': {
                    'type': 'int',
                },
                'status_206': {
                    'type': 'int',
                },
                'status_205': {
                    'type': 'int',
                },
                'status_204': {
                    'type': 'int',
                },
                'status_203': {
                    'type': 'int',
                },
                'status_202': {
                    'type': 'int',
                },
                'status_201': {
                    'type': 'int',
                },
                'status_200': {
                    'type': 'int',
                },
                'no_status_code_err': {
                    'type': 'int',
                },
                'resp_hdr_incomplete_err': {
                    'type': 'int',
                },
                'respmod_request_after_100': {
                    'type': 'int',
                },
                'reqmod_response': {
                    'type': 'int',
                },
                'status_406': {
                    'type': 'int',
                },
                'reqmod_response_after_100': {
                    'type': 'int',
                },
                'status_4xx': {
                    'type': 'int',
                },
                'no_payload_next_buff_err': {
                    'type': 'int',
                },
                'status_3xx': {
                    'type': 'int',
                },
                'reqmod_request': {
                    'type': 'int',
                },
                'recv_option_resp': {
                    'type': 'int',
                },
                'no_icap_resp_err': {
                    'type': 'int',
                },
                'respmod_request': {
                    'type': 'int',
                },
                'app_serv_conn_err': {
                    'type': 'int',
                },
                'result_continue': {
                    'type': 'int',
                },
                'len_exceed_no_allow_204': {
                    'type': 'int',
                },
                'status_306': {
                    'type': 'int',
                },
                'status_307': {
                    'type': 'int',
                },
                'status_304': {
                    'type': 'int',
                },
                'status_305': {
                    'type': 'int',
                },
                'status_302': {
                    'type': 'int',
                },
                'status_303': {
                    'type': 'int',
                },
                'status_300': {
                    'type': 'int',
                },
                'status_301': {
                    'type': 'int',
                },
                'start_icap_conn_fail_err': {
                    'type': 'int',
                },
                'status_418': {
                    'type': 'int',
                },
                'result_100_continue': {
                    'type': 'int',
                },
                'status_419': {
                    'type': 'int',
                },
                'result_other': {
                    'type': 'int',
                },
                'chunk_bad_trail_err': {
                    'type': 'int',
                },
                'respmod_response_after_100': {
                    'type': 'int',
                },
                'status_412': {
                    'type': 'int',
                },
                'status_413': {
                    'type': 'int',
                },
                'status_410': {
                    'type': 'int',
                },
                'status_411': {
                    'type': 'int',
                },
                'status_416': {
                    'type': 'int',
                },
                'status_417': {
                    'type': 'int',
                },
                'status_414': {
                    'type': 'int',
                },
                'status_415': {
                    'type': 'int',
                },
                'chunk2_hdr_err': {
                    'type': 'int',
                },
                'status_unknown': {
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
                'status_509': {
                    'type': 'int',
                },
                'send_option_req': {
                    'type': 'int',
                },
                'http_resp_line_read_err': {
                    'type': 'int',
                },
                'status_6xx': {
                    'type': 'int',
                },
                'status_5xx': {
                    'type': 'int',
                },
                'http_resp_hdr_err': {
                    'type': 'int',
                },
                'status_401': {
                    'type': 'int',
                },
                'status_400': {
                    'type': 'int',
                },
                'status_403': {
                    'type': 'int',
                },
                'status_402': {
                    'type': 'int',
                },
                'status_405': {
                    'type': 'int',
                },
                'status_404': {
                    'type': 'int',
                },
                'status_407': {
                    'type': 'int',
                },
                'status_2xx': {
                    'type': 'int',
                },
                'status_409': {
                    'type': 'int',
                },
                'status_408': {
                    'type': 'int',
                },
                'respmod_response': {
                    'type': 'int',
                },
                'status_505': {
                    'type': 'int',
                },
                'resp_line_read_err': {
                    'type': 'int',
                },
                'req_hdr_incomplete_err': {
                    'type': 'int',
                },
                'status_1xx': {
                    'type': 'int',
                },
                'resp_hdr_err': {
                    'type': 'int',
                },
                'serv_sel_fail_err': {
                    'type': 'int',
                },
                'chunk1_hdr_err': {
                    'type': 'int',
                },
                'status_423': {
                    'type': 'int',
                },
                'status_422': {
                    'type': 'int',
                },
                'status_420': {
                    'type': 'int',
                },
                'status_426': {
                    'type': 'int',
                },
                'status_425': {
                    'type': 'int',
                },
                'status_424': {
                    'type': 'int',
                },
                'status_508': {
                    'type': 'int',
                },
                'result_icap_response': {
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
                'reqmod_request_after_100': {
                    'type': 'int',
                },
                'status_506': {
                    'type': 'int',
                },
                'status_507': {
                    'type': 'int',
                },
                'icap_line_err': {
                    'type': 'int',
                }
            },
            'cpu_count': {
                'type': 'int',
            }
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
        'stats': {
            'type': 'dict',
            'status_449': {
                'type': 'str',
            },
            'no_payload_buff_err': {
                'type': 'str',
            },
            'prep_req_fail_err': {
                'type': 'str',
            },
            'icap_ver_err': {
                'type': 'str',
            },
            'resp_line_parse_err': {
                'type': 'str',
            },
            'app_serv_conn_no_pcb_err': {
                'type': 'str',
            },
            'status_450': {
                'type': 'str',
            },
            'status_510': {
                'type': 'str',
            },
            'encap_hdr_incomplete_err': {
                'type': 'str',
            },
            'chunk_no_allow_204': {
                'type': 'str',
            },
            'http_resp_line_parse_err': {
                'type': 'str',
            },
            'status_207': {
                'type': 'str',
            },
            'status_206': {
                'type': 'str',
            },
            'status_205': {
                'type': 'str',
            },
            'status_204': {
                'type': 'str',
            },
            'status_203': {
                'type': 'str',
            },
            'status_202': {
                'type': 'str',
            },
            'status_201': {
                'type': 'str',
            },
            'status_200': {
                'type': 'str',
            },
            'no_status_code_err': {
                'type': 'str',
            },
            'resp_hdr_incomplete_err': {
                'type': 'str',
            },
            'respmod_request_after_100': {
                'type': 'str',
            },
            'reqmod_response': {
                'type': 'str',
            },
            'status_406': {
                'type': 'str',
            },
            'reqmod_response_after_100': {
                'type': 'str',
            },
            'status_4xx': {
                'type': 'str',
            },
            'no_payload_next_buff_err': {
                'type': 'str',
            },
            'status_3xx': {
                'type': 'str',
            },
            'reqmod_request': {
                'type': 'str',
            },
            'recv_option_resp': {
                'type': 'str',
            },
            'no_icap_resp_err': {
                'type': 'str',
            },
            'respmod_request': {
                'type': 'str',
            },
            'app_serv_conn_err': {
                'type': 'str',
            },
            'result_continue': {
                'type': 'str',
            },
            'len_exceed_no_allow_204': {
                'type': 'str',
            },
            'status_306': {
                'type': 'str',
            },
            'status_307': {
                'type': 'str',
            },
            'status_304': {
                'type': 'str',
            },
            'status_305': {
                'type': 'str',
            },
            'status_302': {
                'type': 'str',
            },
            'status_303': {
                'type': 'str',
            },
            'status_300': {
                'type': 'str',
            },
            'status_301': {
                'type': 'str',
            },
            'start_icap_conn_fail_err': {
                'type': 'str',
            },
            'status_418': {
                'type': 'str',
            },
            'result_100_continue': {
                'type': 'str',
            },
            'status_419': {
                'type': 'str',
            },
            'result_other': {
                'type': 'str',
            },
            'chunk_bad_trail_err': {
                'type': 'str',
            },
            'respmod_response_after_100': {
                'type': 'str',
            },
            'status_412': {
                'type': 'str',
            },
            'status_413': {
                'type': 'str',
            },
            'status_410': {
                'type': 'str',
            },
            'status_411': {
                'type': 'str',
            },
            'status_416': {
                'type': 'str',
            },
            'status_417': {
                'type': 'str',
            },
            'status_414': {
                'type': 'str',
            },
            'status_415': {
                'type': 'str',
            },
            'chunk2_hdr_err': {
                'type': 'str',
            },
            'status_unknown': {
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
            'status_509': {
                'type': 'str',
            },
            'send_option_req': {
                'type': 'str',
            },
            'http_resp_line_read_err': {
                'type': 'str',
            },
            'status_6xx': {
                'type': 'str',
            },
            'status_5xx': {
                'type': 'str',
            },
            'http_resp_hdr_err': {
                'type': 'str',
            },
            'status_401': {
                'type': 'str',
            },
            'status_400': {
                'type': 'str',
            },
            'status_403': {
                'type': 'str',
            },
            'status_402': {
                'type': 'str',
            },
            'status_405': {
                'type': 'str',
            },
            'status_404': {
                'type': 'str',
            },
            'status_407': {
                'type': 'str',
            },
            'status_2xx': {
                'type': 'str',
            },
            'status_409': {
                'type': 'str',
            },
            'status_408': {
                'type': 'str',
            },
            'respmod_response': {
                'type': 'str',
            },
            'status_505': {
                'type': 'str',
            },
            'resp_line_read_err': {
                'type': 'str',
            },
            'req_hdr_incomplete_err': {
                'type': 'str',
            },
            'status_1xx': {
                'type': 'str',
            },
            'resp_hdr_err': {
                'type': 'str',
            },
            'serv_sel_fail_err': {
                'type': 'str',
            },
            'chunk1_hdr_err': {
                'type': 'str',
            },
            'status_423': {
                'type': 'str',
            },
            'status_422': {
                'type': 'str',
            },
            'status_420': {
                'type': 'str',
            },
            'status_426': {
                'type': 'str',
            },
            'status_425': {
                'type': 'str',
            },
            'status_424': {
                'type': 'str',
            },
            'status_508': {
                'type': 'str',
            },
            'result_icap_response': {
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
            'reqmod_request_after_100': {
                'type': 'str',
            },
            'status_506': {
                'type': 'str',
            },
            'status_507': {
                'type': 'str',
            },
            'icap_line_err': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/icap"

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
    url_base = "/axapi/v3/slb/icap"

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
        for k, v in payload["icap"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["icap"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["icap"][k] = v
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
    payload = build_json("icap", module)
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
