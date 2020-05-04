#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

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
                - "'all'= all; 'reqmod_request'= Reqmod Request Stats; 'respmod_request'= Respmod Request Stats; 'reqmod_request_after_100'= Reqmod Request Sent After 100 Cont Stats; 'respmod_request_after_100'= Respmod Request Sent After 100 Cont Stats; 'reqmod_response'= Reqmod Response Stats; 'respmod_response'= Respmod Response Stats; 'reqmod_response_after_100'= Reqmod Response After 100 Cont Stats; 'respmod_response_after_100'= Respmod Response After 100 Cont Stats; 'chunk_no_allow_204'= Chunk so no Allow 204 Stats; 'len_exceed_no_allow_204'= Length Exceeded so no Allow 204 Stats; 'result_continue'= Result Continue Stats; 'result_icap_response'= Result ICAP Response Stats; 'result_100_continue'= Result 100 Continue Stats; 'result_other'= Result Other Stats; 'status_2xx'= Status 2xx Stats; 'status_200'= Status 200 Stats; 'status_201'= Status 201 Stats; 'status_202'= Status 202 Stats; 'status_203'= Status 203 Stats; 'status_204'= Status 204 Stats; 'status_205'= Status 205 Stats; 'status_206'= Status 206 Stats; 'status_207'= Status 207 Stats; 'status_1xx'= Status 1xx Stats; 'status_100'= Status 100 Stats; 'status_101'= Status 101 Stats; 'status_102'= Status 102 Stats; 'status_3xx'= Status 3xx Stats; 'status_300'= Status 300 Stats; 'status_301'= Status 301 Stats; 'status_302'= Status 302 Stats; 'status_303'= Status 303 Stats; 'status_304'= Status 304 Stats; 'status_305'= Status 305 Stats; 'status_306'= Status 306 Stats; 'status_307'= Status 307 Stats; 'status_4xx'= Status 4xx Stats; 'status_400'= Status 400 Stats; 'status_401'= Status 401 Stats; 'status_402'= Status 402 Stats; 'status_403'= Status 403 Stats; 'status_404'= Status 404 Stats; 'status_405'= Status 405 Stats; 'status_406'= Status 406 Stats; 'status_407'= Status 407 Stats; 'status_408'= Status 408 Stats; 'status_409'= Status 409 Stats; 'status_410'= Status 410 Stats; 'status_411'= Status 411 Stats; 'status_412'= Status 412 Stats; 'status_413'= Status 413 Stats; 'status_414'= Status 414 Stats; 'status_415'= Status 415 Stats; 'status_416'= Status 416 Stats; 'status_417'= Status 417 Stats; 'status_418'= Status 418 Stats; 'status_419'= Status 419 Stats; 'status_420'= Status 420 Stats; 'status_422'= Status 422 Stats; 'status_423'= Status 423 Stats; 'status_424'= Status 424 Stats; 'status_425'= Status 425 Stats; 'status_426'= Status 426 Stats; 'status_449'= Status 449 Stats; 'status_450'= Status 450 Stats; 'status_5xx'= Status 5xx Stats; 'status_500'= Status 500 Stats; 'status_501'= Status 501 Stats; 'status_502'= Status 502 Stats; 'status_503'= Status 503 Stats; 'status_504'= Status 504 Stats; 'status_505'= Status 505 Stats; 'status_506'= Status 506 Stats; 'status_507'= Status 507 Stats; 'status_508'= Status 508 Stats; 'status_509'= Status 509 Stats; 'status_510'= Status 510 Stats; 'status_6xx'= Status 6xx Stats; 'status_unknown'= Status Unknown Stats; 'send_option_req'= Send Option Req Stats; 'app_serv_conn_no_pcb_err'= App Server Conn no ES PCB Err Stats; 'app_serv_conn_err'= App Server Conn Err Stats; 'chunk1_hdr_err'= Chunk Hdr Err1 Stats; 'chunk2_hdr_err'= Chunk Hdr Err2 Stats; 'chunk_bad_trail_err'= Chunk Bad Trail Err Stats; 'no_payload_next_buff_err'= No Payload In Next Buff Err Stats; 'no_payload_buff_err'= No Payload Buff Err Stats; 'resp_hdr_incomplete_err'= Resp Hdr Incomplete Err Stats; 'serv_sel_fail_err'= Server Select Fail Err Stats; 'start_icap_conn_fail_err'= Start ICAP conn fail Stats; 'prep_req_fail_err'= Prepare ICAP req fail Err Stats; 'icap_ver_err'= ICAP Ver Err Stats; 'icap_line_err'= ICAP Line Err Stats; 'encap_hdr_incomplete_err'= Encap HDR Incomplete Err Stats; 'no_icap_resp_err'= No ICAP Resp Err Stats; 'resp_line_read_err'= Resp Line Read Err Stats; 'resp_line_parse_err'= Resp Line Parse Err Stats; 'resp_hdr_err'= Resp Hdr Err Stats; 'req_hdr_incomplete_err'= Req Hdr Incomplete Err Stats; 'no_status_code_err'= No Status Code Err Stats; 'http_resp_line_read_err'= HTTP Response Line Read Err Stats; 'http_resp_line_parse_err'= HTTP Response Line Parse Err Stats; 'http_resp_hdr_err'= HTTP Resp Hdr Err Stats; 'recv_option_resp'= Send Option Req Stats; "
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
        oper=dict(type='dict', l4_cpu_list=dict(type='list', status_449=dict(type='int', ),no_payload_buff_err=dict(type='int', ),prep_req_fail_err=dict(type='int', ),icap_ver_err=dict(type='int', ),resp_line_parse_err=dict(type='int', ),app_serv_conn_no_pcb_err=dict(type='int', ),status_450=dict(type='int', ),status_510=dict(type='int', ),encap_hdr_incomplete_err=dict(type='int', ),chunk_no_allow_204=dict(type='int', ),http_resp_line_parse_err=dict(type='int', ),status_207=dict(type='int', ),status_206=dict(type='int', ),status_205=dict(type='int', ),status_204=dict(type='int', ),status_203=dict(type='int', ),status_202=dict(type='int', ),status_201=dict(type='int', ),status_200=dict(type='int', ),no_status_code_err=dict(type='int', ),resp_hdr_incomplete_err=dict(type='int', ),respmod_request_after_100=dict(type='int', ),reqmod_response=dict(type='int', ),status_406=dict(type='int', ),reqmod_response_after_100=dict(type='int', ),status_4xx=dict(type='int', ),no_payload_next_buff_err=dict(type='int', ),status_3xx=dict(type='int', ),reqmod_request=dict(type='int', ),recv_option_resp=dict(type='int', ),no_icap_resp_err=dict(type='int', ),respmod_request=dict(type='int', ),app_serv_conn_err=dict(type='int', ),result_continue=dict(type='int', ),len_exceed_no_allow_204=dict(type='int', ),status_306=dict(type='int', ),status_307=dict(type='int', ),status_304=dict(type='int', ),status_305=dict(type='int', ),status_302=dict(type='int', ),status_303=dict(type='int', ),status_300=dict(type='int', ),status_301=dict(type='int', ),start_icap_conn_fail_err=dict(type='int', ),status_418=dict(type='int', ),result_100_continue=dict(type='int', ),status_419=dict(type='int', ),result_other=dict(type='int', ),chunk_bad_trail_err=dict(type='int', ),respmod_response_after_100=dict(type='int', ),status_412=dict(type='int', ),status_413=dict(type='int', ),status_410=dict(type='int', ),status_411=dict(type='int', ),status_416=dict(type='int', ),status_417=dict(type='int', ),status_414=dict(type='int', ),status_415=dict(type='int', ),chunk2_hdr_err=dict(type='int', ),status_unknown=dict(type='int', ),status_100=dict(type='int', ),status_101=dict(type='int', ),status_102=dict(type='int', ),status_509=dict(type='int', ),send_option_req=dict(type='int', ),http_resp_line_read_err=dict(type='int', ),status_6xx=dict(type='int', ),status_5xx=dict(type='int', ),http_resp_hdr_err=dict(type='int', ),status_401=dict(type='int', ),status_400=dict(type='int', ),status_403=dict(type='int', ),status_402=dict(type='int', ),status_405=dict(type='int', ),status_404=dict(type='int', ),status_407=dict(type='int', ),status_2xx=dict(type='int', ),status_409=dict(type='int', ),status_408=dict(type='int', ),respmod_response=dict(type='int', ),status_505=dict(type='int', ),resp_line_read_err=dict(type='int', ),req_hdr_incomplete_err=dict(type='int', ),status_1xx=dict(type='int', ),resp_hdr_err=dict(type='int', ),serv_sel_fail_err=dict(type='int', ),chunk1_hdr_err=dict(type='int', ),status_423=dict(type='int', ),status_422=dict(type='int', ),status_420=dict(type='int', ),status_426=dict(type='int', ),status_425=dict(type='int', ),status_424=dict(type='int', ),status_508=dict(type='int', ),result_icap_response=dict(type='int', ),status_500=dict(type='int', ),status_501=dict(type='int', ),status_502=dict(type='int', ),status_503=dict(type='int', ),status_504=dict(type='int', ),reqmod_request_after_100=dict(type='int', ),status_506=dict(type='int', ),status_507=dict(type='int', ),icap_line_err=dict(type='int', )),cpu_count=dict(type='int', )),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all','reqmod_request','respmod_request','reqmod_request_after_100','respmod_request_after_100','reqmod_response','respmod_response','reqmod_response_after_100','respmod_response_after_100','chunk_no_allow_204','len_exceed_no_allow_204','result_continue','result_icap_response','result_100_continue','result_other','status_2xx','status_200','status_201','status_202','status_203','status_204','status_205','status_206','status_207','status_1xx','status_100','status_101','status_102','status_3xx','status_300','status_301','status_302','status_303','status_304','status_305','status_306','status_307','status_4xx','status_400','status_401','status_402','status_403','status_404','status_405','status_406','status_407','status_408','status_409','status_410','status_411','status_412','status_413','status_414','status_415','status_416','status_417','status_418','status_419','status_420','status_422','status_423','status_424','status_425','status_426','status_449','status_450','status_5xx','status_500','status_501','status_502','status_503','status_504','status_505','status_506','status_507','status_508','status_509','status_510','status_6xx','status_unknown','send_option_req','app_serv_conn_no_pcb_err','app_serv_conn_err','chunk1_hdr_err','chunk2_hdr_err','chunk_bad_trail_err','no_payload_next_buff_err','no_payload_buff_err','resp_hdr_incomplete_err','serv_sel_fail_err','start_icap_conn_fail_err','prep_req_fail_err','icap_ver_err','icap_line_err','encap_hdr_incomplete_err','no_icap_resp_err','resp_line_read_err','resp_line_parse_err','resp_hdr_err','req_hdr_incomplete_err','no_status_code_err','http_resp_line_read_err','http_resp_line_parse_err','http_resp_hdr_err','recv_option_resp'])),
        stats=dict(type='dict', status_449=dict(type='str', ),no_payload_buff_err=dict(type='str', ),prep_req_fail_err=dict(type='str', ),icap_ver_err=dict(type='str', ),resp_line_parse_err=dict(type='str', ),app_serv_conn_no_pcb_err=dict(type='str', ),status_450=dict(type='str', ),status_510=dict(type='str', ),encap_hdr_incomplete_err=dict(type='str', ),chunk_no_allow_204=dict(type='str', ),http_resp_line_parse_err=dict(type='str', ),status_207=dict(type='str', ),status_206=dict(type='str', ),status_205=dict(type='str', ),status_204=dict(type='str', ),status_203=dict(type='str', ),status_202=dict(type='str', ),status_201=dict(type='str', ),status_200=dict(type='str', ),no_status_code_err=dict(type='str', ),resp_hdr_incomplete_err=dict(type='str', ),respmod_request_after_100=dict(type='str', ),reqmod_response=dict(type='str', ),status_406=dict(type='str', ),reqmod_response_after_100=dict(type='str', ),status_4xx=dict(type='str', ),no_payload_next_buff_err=dict(type='str', ),status_3xx=dict(type='str', ),reqmod_request=dict(type='str', ),recv_option_resp=dict(type='str', ),no_icap_resp_err=dict(type='str', ),respmod_request=dict(type='str', ),app_serv_conn_err=dict(type='str', ),result_continue=dict(type='str', ),len_exceed_no_allow_204=dict(type='str', ),status_306=dict(type='str', ),status_307=dict(type='str', ),status_304=dict(type='str', ),status_305=dict(type='str', ),status_302=dict(type='str', ),status_303=dict(type='str', ),status_300=dict(type='str', ),status_301=dict(type='str', ),start_icap_conn_fail_err=dict(type='str', ),status_418=dict(type='str', ),result_100_continue=dict(type='str', ),status_419=dict(type='str', ),result_other=dict(type='str', ),chunk_bad_trail_err=dict(type='str', ),respmod_response_after_100=dict(type='str', ),status_412=dict(type='str', ),status_413=dict(type='str', ),status_410=dict(type='str', ),status_411=dict(type='str', ),status_416=dict(type='str', ),status_417=dict(type='str', ),status_414=dict(type='str', ),status_415=dict(type='str', ),chunk2_hdr_err=dict(type='str', ),status_unknown=dict(type='str', ),status_100=dict(type='str', ),status_101=dict(type='str', ),status_102=dict(type='str', ),status_509=dict(type='str', ),send_option_req=dict(type='str', ),http_resp_line_read_err=dict(type='str', ),status_6xx=dict(type='str', ),status_5xx=dict(type='str', ),http_resp_hdr_err=dict(type='str', ),status_401=dict(type='str', ),status_400=dict(type='str', ),status_403=dict(type='str', ),status_402=dict(type='str', ),status_405=dict(type='str', ),status_404=dict(type='str', ),status_407=dict(type='str', ),status_2xx=dict(type='str', ),status_409=dict(type='str', ),status_408=dict(type='str', ),respmod_response=dict(type='str', ),status_505=dict(type='str', ),resp_line_read_err=dict(type='str', ),req_hdr_incomplete_err=dict(type='str', ),status_1xx=dict(type='str', ),resp_hdr_err=dict(type='str', ),serv_sel_fail_err=dict(type='str', ),chunk1_hdr_err=dict(type='str', ),status_423=dict(type='str', ),status_422=dict(type='str', ),status_420=dict(type='str', ),status_426=dict(type='str', ),status_425=dict(type='str', ),status_424=dict(type='str', ),status_508=dict(type='str', ),result_icap_response=dict(type='str', ),status_500=dict(type='str', ),status_501=dict(type='str', ),status_502=dict(type='str', ),status_503=dict(type='str', ),status_504=dict(type='str', ),reqmod_request_after_100=dict(type='str', ),status_506=dict(type='str', ),status_507=dict(type='str', ),icap_line_err=dict(type='str', )),
        uuid=dict(type='str', )
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/icap"

    f_dict = {}

    return url_base.format(**f_dict)

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
                    if result["changed"] != True:
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