#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_slb_fast_http_proxy
description:
    - Configure Fast-HTTP Proxy
short_description: Configures A10 slb.fast-http-proxy
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
            debug_fields:
                description:
                - "Field debug_fields"
            cpu_count:
                description:
                - "Field cpu_count"
            fast_http_proxy_cpu_list:
                description:
                - "Field fast_http_proxy_cpu_list"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'num'= Num; 'curr_proxy'= Curr Proxy Conns; 'total_proxy'= Total Proxy Conns; 'req'= HTTP requests; 'req_succ'= HTTP requests(succ); 'noproxy'= No proxy error; 'client_rst'= Client RST; 'server_rst'= Server RST; 'notuple'= No tuple error; 'parsereq_fail'= Parse req fail; 'svrsel_fail'= Server selection fail; 'fwdreq_fail'= Fwd req fail; 'fwdreq_fail_buff'= Fwd req fail - buff; 'fwdreq_fail_rport'= Fwd req fail - rport; 'fwdreq_fail_route'= Fwd req fail - route; 'fwdreq_fail_persist'= Fwd req fail - persist; 'fwdreq_fail_server'= Fwd req fail - server; 'fwdreq_fail_tuple'= Fwd req fail - tuple; 'fwdreqdata_fail'= Fwd req data fail; 'req_retran'= Packets retrans; 'req_ofo'= Packets ofo; 'server_resel'= Server reselection; 'svr_prem_close'= Server premature close; 'new_svrconn'= Server conn made; 'snat_fail'= Source NAT failure; 'tcpoutrst'= Out RSTs; 'full_proxy'= Full proxy tot; 'full_proxy_post'= Full proxy POST; 'full_proxy_pipeline'= Full proxy pipeline; 'full_proxy_fpga_err'= Full proxy fpga err; 'req_over_limit'= Request over limit; 'req_rate_over_limit'= Request rate over limit; 'l4_switching'= L4 switching; 'cookie_switching'= Cookie switching; 'aflex_switching'= aFleX switching; 'http_policy_switching'= HTTP Policy switching; 'url_switching'= URL switching; 'host_switching'= Host switching; 'lb_switching'= Normal LB switching; 'l4_switching_ok'= L4 switching (succ); 'cookie_switching_ok'= Cookie switching (succ); 'aflex_switching_ok'= aFleX switching (succ); 'http_policy_switching_ok'= HTTP Policy switching (succ); 'url_switching_ok'= URL switching (succ); 'host_switching_ok'= Host switching (succ); 'lb_switching_ok'= Normal LB switch. (succ); 'l4_switching_enqueue'= L4 switching (enQ); 'cookie_switching_enqueue'= Cookie switching (enQ); 'aflex_switching_enqueue'= aFleX switching (enQ); 'http_policy_switching_enqueue'= HTTP Policy switching (enQ); 'url_switching_enqueue'= URL switching (enQ); 'host_switching_enqueue'= Host switching (enQ); 'lb_switching_enqueue'= Normal LB switch. (enQ); 'retry_503'= Retry on 503; 'aflex_retry'= aFleX http retry; 'aflex_lb_reselect'= aFleX lb reselect; 'aflex_lb_reselect_ok'= aFleX lb reselect (succ); 'client_rst_request'= Client RST - request; 'client_rst_connecting'= Client RST - connecting; 'client_rst_connected'= Client RST - connected; 'client_rst_response'= Client RST - response; 'server_rst_request'= Server RST - request; 'server_rst_connecting'= Server RST - connecting; 'server_rst_connected'= Server RST - connected; 'server_rst_response'= Server RST - response; 'invalid_header'= Invalid header; 'too_many_headers'= Too many headers; 'line_too_long'= Line too long; 'header_name_too_long'= Header name too long; 'wrong_resp_header'= Wrong response header; 'header_insert'= Header insert; 'header_delete'= Header delete; 'insert_client_ip'= Insert client IP; 'negative_req_remain'= Negative request remain; 'negative_resp_remain'= Negative response remain; 'large_cookie'= Large cookies; 'large_cookie_header'= Large cookie headers; 'huge_cookie'= Huge cookies; 'huge_cookie_header'= Huge cookie headers; 'parse_cookie_fail'= Parse cookie fail; 'parse_setcookie_fail'= Parse set-cookie fail; 'asm_cookie_fail'= Assemble cookie fail; 'asm_cookie_header_fail'= Asm cookie header fail; 'asm_setcookie_fail'= Assemble set-cookie fail; 'asm_setcookie_header_fail'= Asm set-cookie hdr fail; 'client_req_unexp_flag'= Client req unexp flags; 'connecting_fin'= Connecting FIN; 'connecting_fin_retrans'= Connecting FIN retran; 'connecting_fin_ofo'= Connecting FIN ofo; 'connecting_rst'= Connecting RST; 'connecting_rst_retrans'= Connecting RST retran; 'connecting_rst_ofo'= Connecting RST ofo; 'connecting_ack'= Connecting ACK; 'pkts_ofo'= Packets ofo; 'pkts_retrans'= Packets retrans; 'pkts_retrans_ack_finwait'= retrans ACK FWAIT; 'pkts_retrans_fin'= retrans FIN; 'pkts_retrans_rst'= retrans RST; 'pkts_retrans_push'= retrans PSH; 'stale_sess'= Stale sess; 'server_resel_failed'= Server re-select failed; 'compression_before'= Tot data before compress; 'compression_after'= Tot data after compress; 'response_1xx'= Status code 1XX; 'response_100'= Status code 100; 'response_101'= Status code 101; 'response_102'= Status code 102; 'response_2xx'= Status code 2XX; 'response_200'= Status code 200; 'response_201'= Status code 201; 'response_202'= Status code 202; 'response_203'= Status code 203; 'response_204'= Status code 204; 'response_205'= Status code 205; 'response_206'= Status code 206; 'response_207'= Status code 207; 'response_3xx'= Status code 3XX; 'response_300'= Status code 300; 'response_301'= Status code 301; 'response_302'= Status code 302; 'response_303'= Status code 303; 'response_304'= Status code 304; 'response_305'= Status code 305; 'response_306'= Status code 306; 'response_307'= Status code 307; 'response_4xx'= Status code 4XX; 'response_400'= Status code 400; 'response_401'= Status code 401; 'response_402'= Status code 402; 'response_403'= Status code 403; 'response_404'= Status code 404; 'response_405'= Status code 405; 'response_406'= Status code 406; 'response_407'= Status code 407; 'response_408'= Status code 408; 'response_409'= Status code 409; 'response_410'= Status code 410; 'response_411'= Status code 411; 'response_412'= Status code 412; 'response_413'= Status code 413; 'response_414'= Status code 414; 'response_415'= Status code 415; 'response_416'= Status code 416; 'response_417'= Status code 417; 'response_418'= Status code 418; 'response_422'= Status code 422; 'response_423'= Status code 423; 'response_424'= Status code 424; 'response_425'= Status code 425; 'response_426'= Status code 426; 'response_449'= Status code 449; 'response_450'= Status code 450; 'response_5xx'= Status code 5XX; 'response_500'= Status code 500; 'response_501'= Status code 501; 'response_502'= Status code 502; 'response_503'= Status code 503; 'response_504'= Status code 504; 'response_505'= Status code 505; 'response_506'= Status code 506; 'response_507'= Status code 507; 'response_508'= Status code 508; 'response_509'= Status code 509; 'response_510'= Status code 510; 'response_6xx'= Status code 6XX; 'response_unknown'= Status code unknown; 'req_http10'= Request 1.0; 'req_http11'= Request 1.1; 'response_http10'= Resp 1.0; 'response_http11'= Resp 1.1; 'req_get'= Method GET; 'req_head'= Method HEAD; 'req_put'= Method PUT; 'req_post'= Method POST; 'req_trace'= Method TRACE; 'req_options'= Method OPTIONS; 'req_connect'= Method CONNECT; 'req_delete'= Method DELETE; 'req_unknown'= Method UNKNOWN; 'req_content_len'= Req content len; 'rsp_content_len'= Resp content len; 'rsp_chunk'= Resp chunk encoding; 'req_chunk'= Req chunk encoding; 'compress_rsp'= Compress req; 'compress_del_accept_enc'= Compress del accept enc; 'compress_resp_already_compressed'= Resp already compressed; 'compress_content_type_excluded'= Compress cont type excl; 'compress_no_content_type'= Compress no cont type; 'compress_resp_lt_min'= Compress resp less than min; 'compress_resp_no_cl_or_ce'= Compress resp no CL/CE; 'compress_ratio_too_high'= Compress ratio too high; 'cache_rsp'= HTTP req (cache succ); 'close_on_ddos'= Close on DDoS; 'req_http10_keepalive'= 1.0 Keepalive; 'req_sz_1k'= Req less than equal to 1K; 'req_sz_2k'= Req less than equal to 2K; "
            counters2:
                description:
                - "'req_sz_4k'= Req less than equal to 4K; 'req_sz_8k'= Req less than equal to 8K; 'req_sz_16k'= Req less than equal to 16K; 'req_sz_32k'= Req less than equal to 32K; 'req_sz_64k'= Req less than equal to 64K; 'req_sz_256k'= Req less than equal to 256K; 'req_sz_gt_256k'= Req greater than 256K; 'rsp_sz_1k'= Resp less than equal to 1K; 'rsp_sz_2k'= Resp less than equal to 2K; 'rsp_sz_4k'= Resp less than equal to 4K; 'rsp_sz_8k'= Resp less than equal to 8K; 'rsp_sz_16k'= Resp less than equal to 16K; 'rsp_sz_32k'= Resp less than equal to 32K; 'rsp_sz_64k'= Resp less than equal to 64K; 'rsp_sz_256k'= Resp less than equal to 256K; 'rsp_sz_gt_256k'= Resp greater than 256K; 'chunk_sz_512'= Chunk less than equal to 512; 'chunk_sz_1k'= Chunk less than equal to 1K; 'chunk_sz_2k'= Chunk less than equal to 2K; 'chunk_sz_4k'= Chunk less than equal to 4K; 'chunk_sz_gt_4k'= Chunk greater than 4K; 'pconn_connecting'= pconn connecting; 'pconn_connected'= pconn connected; 'pconn_connecting_failed'= pconn conn failed; 'chunk_bad'= Bad Chunk; 'req_10u'= Rsp time less than 10u; 'req_20u'= Rsp time less than 20u; 'req_50u'= Rsp time less than 50u; 'req_100u'= Rsp time less than 100u; 'req_200u'= Rsp time less than 200u; 'req_500u'= Rsp time less than 500u; 'req_1m'= Rsp time less than 1m; 'req_2m'= Rsp time less than 2m; 'req_5m'= Rsp time less than 5m; 'req_10m'= Rsp time less than 10m; 'req_20m'= Rsp time less than 20m; 'req_50m'= Rsp time less than 50m; 'req_100m'= Rsp time less than 100m; 'req_200m'= Rsp time less than 200m; 'req_500m'= Rsp time less than 500m; 'req_1s'= Rsp time less than 1s; 'req_2s'= Rsp time less than 2s; 'req_5s'= Rsp time less than 5s; 'req_over_5s'= Rsp time greater than equal to 5s; 'insert_client_port'= Insert client Port; 'req_track'= Method TRACK; 'full_proxy_put'= Full proxy PUT; 'non_http_bypass'= Non-HTTP bypass; 'skip_insert_client_ip'= Skip Insert Client IP; 'skip_insert_client_port'= Skip Insert Client Port; 'decompression_before'= Tot data before decompress; 'decompression_after'= Tot data after decompress; 'http_pkts_in_seq'= Tot In-seq fHTTP packets; 'http_pkts_retx'= Tot Re-Tx fHTTP packets; 'http_client_retx'= Client Re-Tx fHTTP packets; 'http_server_retx'= Server Re-Tx fHTTP packets; 'http_pkts_ofo'= fHTTP Out of Order packets; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            new_svrconn:
                description:
                - "Server conn made"
            svrsel_fail:
                description:
                - "Server selection fail"
            total_proxy:
                description:
                - "Total Proxy Conns"
            fwdreqdata_fail:
                description:
                - "Fwd req data fail"
            client_rst:
                description:
                - "Client RST"
            req_retran:
                description:
                - "Packets retrans"
            close_on_ddos:
                description:
                - "Close on DDoS"
            req_over_limit:
                description:
                - "Request over limit"
            noproxy:
                description:
                - "No proxy error"
            svr_prem_close:
                description:
                - "Server premature close"
            parsereq_fail:
                description:
                - "Parse req fail"
            tcpoutrst:
                description:
                - "Out RSTs"
            full_proxy:
                description:
                - "Full proxy tot"
            full_proxy_put:
                description:
                - "Full proxy PUT"
            full_proxy_fpga_err:
                description:
                - "Full proxy fpga err"
            server_rst:
                description:
                - "Server RST"
            notuple:
                description:
                - "No tuple error"
            curr_proxy:
                description:
                - "Curr Proxy Conns"
            server_resel:
                description:
                - "Server reselection"
            req_ofo:
                description:
                - "Packets ofo"
            full_proxy_post:
                description:
                - "Full proxy POST"
            snat_fail:
                description:
                - "Source NAT failure"
            req_rate_over_limit:
                description:
                - "Request rate over limit"
            full_proxy_pipeline:
                description:
                - "Full proxy pipeline"
            req:
                description:
                - "HTTP requests"
            fwdreq_fail:
                description:
                - "Fwd req fail"
            req_succ:
                description:
                - "HTTP requests(succ)"
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
    from ansible_collections.a10.acos_axapi.plugins.module_utils import errors as a10_ex
    from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import client_factory, session_factory
    from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict', debug_fields=dict(type='bool', ), cpu_count=dict(type='int', ), fast_http_proxy_cpu_list=dict(type='list', new_svrconn=dict(type='int', ), snat_fail=dict(type='int', ), req_sz_32k=dict(type='int', ), total_proxy=dict(type='int', ), req_get=dict(type='int', ), fwdreqdata_fail=dict(type='int', ), aflex_switching_enqueue=dict(type='int', ), invalid_header=dict(type='int', ), response_501=dict(type='int', ), negative_resp_remain=dict(type='int', ), response_503=dict(type='int', ), response_502=dict(type='int', ), response_505=dict(type='int', ), response_504=dict(type='int', ), chunk_sz_2k=dict(type='int', ), response_506=dict(type='int', ), response_509=dict(type='int', ), response_508=dict(type='int', ), rsp_sz_8k=dict(type='int', ), compress_no_content_type=dict(type='int', ), pkts_retrans_rst=dict(type='int', ), req_put=dict(type='int', ), response_2xx=dict(type='int', ), req_over_limit=dict(type='int', ), req_sz_gt_256k=dict(type='int', ), svr_prem_close=dict(type='int', ), parsereq_fail=dict(type='int', ), tcpoutrst=dict(type='int', ), full_proxy=dict(type='int', ), connecting_rst_ofo=dict(type='int', ), response_102=dict(type='int', ), compress_resp_already_compressed=dict(type='int', ), req_post=dict(type='int', ), req_over_5s=dict(type='int', ), rsp_chunk=dict(type='int', ), lb_switching_ok=dict(type='int', ), req_ofo=dict(type='int', ), req_200m=dict(type='int', ), chunk_sz_1k=dict(type='int', ), full_proxy_post=dict(type='int', ), header_delete=dict(type='int', ), response_6xx=dict(type='int', ), fwdreq_fail_buff=dict(type='int', ), response_500=dict(type='int', ), req_succ=dict(type='int', ), aflex_lb_reselect=dict(type='int', ), rsp_sz_32k=dict(type='int', ), req_100u=dict(type='int', ), req_500m=dict(type='int', ), req_http10_keepalive=dict(type='int', ), aflex_retry=dict(type='int', ), req_100m=dict(type='int', ), response_3xx=dict(type='int', ), rsp_sz_gt_256k=dict(type='int', ), connecting_ack=dict(type='int', ), connecting_fin_ofo=dict(type='int', ), rsp_sz_2k=dict(type='int', ), response_507=dict(type='int', ), huge_cookie_header=dict(type='int', ), response_http11=dict(type='int', ), response_408=dict(type='int', ), client_rst=dict(type='int', ), client_rst_connected=dict(type='int', ), chunk_sz_512=dict(type='int', ), response_400=dict(type='int', ), response_401=dict(type='int', ), response_402=dict(type='int', ), response_403=dict(type='int', ), response_404=dict(type='int', ), response_405=dict(type='int', ), response_406=dict(type='int', ), response_407=dict(type='int', ), l4_switching=dict(type='int', ), req_sz_256k=dict(type='int', ), noproxy=dict(type='int', ), chunk_sz_gt_4k=dict(type='int', ), asm_setcookie_header_fail=dict(type='int', ), req=dict(type='int', ), client_req_unexp_flag=dict(type='int', ), fwdreq_fail_persist=dict(type='int', ), url_switching_ok=dict(type='int', ), cookie_switching_enqueue=dict(type='int', ), rsp_sz_64k=dict(type='int', ), large_cookie=dict(type='int', ), asm_setcookie_fail=dict(type='int', ), rsp_content_len=dict(type='int', ), client_rst_request=dict(type='int', ), host_switching_enqueue=dict(type='int', ), rsp_sz_1k=dict(type='int', ), full_proxy_fpga_err=dict(type='int', ), response_306=dict(type='int', ), connecting_fin_retrans=dict(type='int', ), wrong_resp_header=dict(type='int', ), compress_rsp=dict(type='int', ), curr_proxy=dict(type='int', ), req_chunk=dict(type='int', ), full_proxy_pipeline=dict(type='int', ), response_418=dict(type='int', ), response_413=dict(type='int', ), response_412=dict(type='int', ), response_411=dict(type='int', ), response_410=dict(type='int', ), response_417=dict(type='int', ), insert_client_ip=dict(type='int', ), response_415=dict(type='int', ), host_switching_ok=dict(type='int', ), pkts_ofo=dict(type='int', ), skip_insert_client_port=dict(type='int', ), req_1m=dict(type='int', ), compress_del_accept_enc=dict(type='int', ), compress_resp_lt_min=dict(type='int', ), compress_content_type_excluded=dict(type='int', ), skip_insert_client_ip=dict(type='int', ), server_rst_connected=dict(type='int', ), client_rst_connecting=dict(type='int', ), fwdreq_fail_tuple=dict(type='int', ), req_1s=dict(type='int', ), server_resel_failed=dict(type='int', ), pkts_retrans_fin=dict(type='int', ), response_510=dict(type='int', ), too_many_headers=dict(type='int', ), rsp_sz_4k=dict(type='int', ), response_426=dict(type='int', ), response_424=dict(type='int', ), response_425=dict(type='int', ), response_422=dict(type='int', ), response_1xx=dict(type='int', ), url_switching=dict(type='int', ), asm_cookie_fail=dict(type='int', ), url_switching_enqueue=dict(type='int', ), req_500u=dict(type='int', ), response_unknown=dict(type='int', ), cache_rsp=dict(type='int', ), req_2s=dict(type='int', ), response_5xx=dict(type='int', ), response_305=dict(type='int', ), response_304=dict(type='int', ), response_303=dict(type='int', ), req_rate_over_limit=dict(type='int', ), response_301=dict(type='int', ), response_300=dict(type='int', ), pconn_connected=dict(type='int', ), response_416=dict(type='int', ), fwdreq_fail_server=dict(type='int', ), req_trace=dict(type='int', ), fwdreq_fail_route=dict(type='int', ), response_4xx=dict(type='int', ), response_101=dict(type='int', ), response_414=dict(type='int', ), parse_cookie_fail=dict(type='int', ), req_track=dict(type='int', ), req_2m=dict(type='int', ), response_307=dict(type='int', ), full_proxy_put=dict(type='int', ), server_rst=dict(type='int', ), req_10u=dict(type='int', ), header_insert=dict(type='int', ), response_http10=dict(type='int', ), notuple=dict(type='int', ), req_sz_2k=dict(type='int', ), negative_req_remain=dict(type='int', ), rsp_sz_256k=dict(type='int', ), aflex_lb_reselect_ok=dict(type='int', ), l4_switching_ok=dict(type='int', ), connecting_rst=dict(type='int', ), asm_cookie_header_fail=dict(type='int', ), server_rst_request=dict(type='int', ), req_10m=dict(type='int', ), req_50u=dict(type='int', ), response_409=dict(type='int', ), req_unknown=dict(type='int', ), fwdreq_fail=dict(type='int', ), req_options=dict(type='int', ), lb_switching_enqueue=dict(type='int', ), lb_switching=dict(type='int', ), req_50m=dict(type='int', ), cookie_switching=dict(type='int', ), aflex_switching=dict(type='int', ), fwdreq_fail_rport=dict(type='int', ), server_rst_response=dict(type='int', ), svrsel_fail=dict(type='int', ), req_sz_8k=dict(type='int', ), retry_503=dict(type='int', ), huge_cookie=dict(type='int', ), large_cookie_header=dict(type='int', ), req_retran=dict(type='int', ), pkts_retrans_ack_finwait=dict(type='int', ), aflex_switching_ok=dict(type='int', ), header_name_too_long=dict(type='int', ), chunk_bad=dict(type='int', ), compress_resp_no_cl_or_ce=dict(type='int', ), close_on_ddos=dict(type='int', ), pkts_retrans=dict(type='int', ), req_200u=dict(type='int', ), response_423=dict(type='int', ), req_delete=dict(type='int', ), req_20u=dict(type='int', ), response_206=dict(type='int', ), chunk_sz_4k=dict(type='int', ), response_204=dict(type='int', ), response_205=dict(type='int', ), response_202=dict(type='int', ), response_203=dict(type='int', ), response_200=dict(type='int', ), response_201=dict(type='int', ), cookie_switching_ok=dict(type='int', ), req_content_len=dict(type='int', ), rsp_sz_16k=dict(type='int', ), req_http10=dict(type='int', ), req_http11=dict(type='int', ), req_connect=dict(type='int', ), parse_setcookie_fail=dict(type='int', ), non_http_bypass=dict(type='int', ), response_449=dict(type='int', ), req_sz_4k=dict(type='int', ), insert_client_port=dict(type='int', ), client_rst_response=dict(type='int', ), server_resel=dict(type='int', ), stale_sess=dict(type='int', ), req_sz_16k=dict(type='int', ), response_302=dict(type='int', ), req_sz_64k=dict(type='int', ), line_too_long=dict(type='int', ), compress_ratio_too_high=dict(type='int', ), pconn_connecting=dict(type='int', ), response_100=dict(type='int', ), host_switching=dict(type='int', ), http_pkts_ofo=dict(type='int', ), response_450=dict(type='int', ), connecting_rst_retrans=dict(type='int', ), server_rst_connecting=dict(type='int', ), req_5m=dict(type='int', ), pconn_connecting_failed=dict(type='int', ), req_sz_1k=dict(type='int', ), req_head=dict(type='int', ), req_20m=dict(type='int', ), req_5s=dict(type='int', ), connecting_fin=dict(type='int', ), response_207=dict(type='int', ), pkts_retrans_push=dict(type='int', ), l4_switching_enqueue=dict(type='int', ))),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'num', 'curr_proxy', 'total_proxy', 'req', 'req_succ', 'noproxy', 'client_rst', 'server_rst', 'notuple', 'parsereq_fail', 'svrsel_fail', 'fwdreq_fail', 'fwdreq_fail_buff', 'fwdreq_fail_rport', 'fwdreq_fail_route', 'fwdreq_fail_persist', 'fwdreq_fail_server', 'fwdreq_fail_tuple', 'fwdreqdata_fail', 'req_retran', 'req_ofo', 'server_resel', 'svr_prem_close', 'new_svrconn', 'snat_fail', 'tcpoutrst', 'full_proxy', 'full_proxy_post', 'full_proxy_pipeline', 'full_proxy_fpga_err', 'req_over_limit', 'req_rate_over_limit', 'l4_switching', 'cookie_switching', 'aflex_switching', 'http_policy_switching', 'url_switching', 'host_switching', 'lb_switching', 'l4_switching_ok', 'cookie_switching_ok', 'aflex_switching_ok', 'http_policy_switching_ok', 'url_switching_ok', 'host_switching_ok', 'lb_switching_ok', 'l4_switching_enqueue', 'cookie_switching_enqueue', 'aflex_switching_enqueue', 'http_policy_switching_enqueue', 'url_switching_enqueue', 'host_switching_enqueue', 'lb_switching_enqueue', 'retry_503', 'aflex_retry', 'aflex_lb_reselect', 'aflex_lb_reselect_ok', 'client_rst_request', 'client_rst_connecting', 'client_rst_connected', 'client_rst_response', 'server_rst_request', 'server_rst_connecting', 'server_rst_connected', 'server_rst_response', 'invalid_header', 'too_many_headers', 'line_too_long', 'header_name_too_long', 'wrong_resp_header', 'header_insert', 'header_delete', 'insert_client_ip', 'negative_req_remain', 'negative_resp_remain', 'large_cookie', 'large_cookie_header', 'huge_cookie', 'huge_cookie_header', 'parse_cookie_fail', 'parse_setcookie_fail', 'asm_cookie_fail', 'asm_cookie_header_fail', 'asm_setcookie_fail', 'asm_setcookie_header_fail', 'client_req_unexp_flag', 'connecting_fin', 'connecting_fin_retrans', 'connecting_fin_ofo', 'connecting_rst', 'connecting_rst_retrans', 'connecting_rst_ofo', 'connecting_ack', 'pkts_ofo', 'pkts_retrans', 'pkts_retrans_ack_finwait', 'pkts_retrans_fin', 'pkts_retrans_rst', 'pkts_retrans_push', 'stale_sess', 'server_resel_failed', 'compression_before', 'compression_after', 'response_1xx', 'response_100', 'response_101', 'response_102', 'response_2xx', 'response_200', 'response_201', 'response_202', 'response_203', 'response_204', 'response_205', 'response_206', 'response_207', 'response_3xx', 'response_300', 'response_301', 'response_302', 'response_303', 'response_304', 'response_305', 'response_306', 'response_307', 'response_4xx', 'response_400', 'response_401', 'response_402', 'response_403', 'response_404', 'response_405', 'response_406', 'response_407', 'response_408', 'response_409', 'response_410', 'response_411', 'response_412', 'response_413', 'response_414', 'response_415', 'response_416', 'response_417', 'response_418', 'response_422', 'response_423', 'response_424', 'response_425', 'response_426', 'response_449', 'response_450', 'response_5xx', 'response_500', 'response_501', 'response_502', 'response_503', 'response_504', 'response_505', 'response_506', 'response_507', 'response_508', 'response_509', 'response_510', 'response_6xx', 'response_unknown', 'req_http10', 'req_http11', 'response_http10', 'response_http11', 'req_get', 'req_head', 'req_put', 'req_post', 'req_trace', 'req_options', 'req_connect', 'req_delete', 'req_unknown', 'req_content_len', 'rsp_content_len', 'rsp_chunk', 'req_chunk', 'compress_rsp', 'compress_del_accept_enc', 'compress_resp_already_compressed', 'compress_content_type_excluded', 'compress_no_content_type', 'compress_resp_lt_min', 'compress_resp_no_cl_or_ce', 'compress_ratio_too_high', 'cache_rsp', 'close_on_ddos', 'req_http10_keepalive', 'req_sz_1k', 'req_sz_2k']), counters2=dict(type='str', choices=['req_sz_4k', 'req_sz_8k', 'req_sz_16k', 'req_sz_32k', 'req_sz_64k', 'req_sz_256k', 'req_sz_gt_256k', 'rsp_sz_1k', 'rsp_sz_2k', 'rsp_sz_4k', 'rsp_sz_8k', 'rsp_sz_16k', 'rsp_sz_32k', 'rsp_sz_64k', 'rsp_sz_256k', 'rsp_sz_gt_256k', 'chunk_sz_512', 'chunk_sz_1k', 'chunk_sz_2k', 'chunk_sz_4k', 'chunk_sz_gt_4k', 'pconn_connecting', 'pconn_connected', 'pconn_connecting_failed', 'chunk_bad', 'req_10u', 'req_20u', 'req_50u', 'req_100u', 'req_200u', 'req_500u', 'req_1m', 'req_2m', 'req_5m', 'req_10m', 'req_20m', 'req_50m', 'req_100m', 'req_200m', 'req_500m', 'req_1s', 'req_2s', 'req_5s', 'req_over_5s', 'insert_client_port', 'req_track', 'full_proxy_put', 'non_http_bypass', 'skip_insert_client_ip', 'skip_insert_client_port', 'decompression_before', 'decompression_after', 'http_pkts_in_seq', 'http_pkts_retx', 'http_client_retx', 'http_server_retx', 'http_pkts_ofo'])),
        stats=dict(type='dict', new_svrconn=dict(type='str', ), svrsel_fail=dict(type='str', ), total_proxy=dict(type='str', ), fwdreqdata_fail=dict(type='str', ), client_rst=dict(type='str', ), req_retran=dict(type='str', ), close_on_ddos=dict(type='str', ), req_over_limit=dict(type='str', ), noproxy=dict(type='str', ), svr_prem_close=dict(type='str', ), parsereq_fail=dict(type='str', ), tcpoutrst=dict(type='str', ), full_proxy=dict(type='str', ), full_proxy_put=dict(type='str', ), full_proxy_fpga_err=dict(type='str', ), server_rst=dict(type='str', ), notuple=dict(type='str', ), curr_proxy=dict(type='str', ), server_resel=dict(type='str', ), req_ofo=dict(type='str', ), full_proxy_post=dict(type='str', ), snat_fail=dict(type='str', ), req_rate_over_limit=dict(type='str', ), full_proxy_pipeline=dict(type='str', ), req=dict(type='str', ), fwdreq_fail=dict(type='str', ), req_succ=dict(type='str', )),
        uuid=dict(type='str', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/fast-http-proxy"

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

def build_envelope(title, data):
    return {
        title: data
    }

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/fast-http-proxy"

    f_dict = {}

    return url_base.format(**f_dict)

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
        for k, v in payload["fast-http-proxy"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["fast-http-proxy"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["fast-http-proxy"][k] = v
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
    payload = build_json("fast-http-proxy", module)
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

    result = dict(
        changed=False,
        original_message="",
        message="",
        result={}
    )

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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)
    
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