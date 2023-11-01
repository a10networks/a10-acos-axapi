#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_http_proxy
description:
    - Configure HTTP Proxy global
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
                - "'all'= all; 'num'= Num; 'curr_proxy'= Curr Proxy Conns; 'total_proxy'= Total
          Proxy Conns; 'req'= HTTP requests; 'req_succ'= HTTP requests(succ); 'noproxy'=
          No proxy error; 'client_rst'= Client RST; 'server_rst'= Server RST; 'notuple'=
          No tuple error; 'parsereq_fail'= Parse req fail; 'svrsel_fail'= Server
          selection fail; 'fwdreq_fail'= Fwd req fail; 'fwdreq_fail_buff'= Fwd req fail -
          buff; 'fwdreq_fail_rport'= Fwd req fail - rport; 'fwdreq_fail_route'= Fwd req
          fail - route; 'fwdreq_fail_persist'= Fwd req fail - persist;
          'fwdreq_fail_server'= Fwd req fail - server; 'fwdreq_fail_tuple'= Fwd req fail
          - tuple; 'fwdreqdata_fail'= fwdreqdata_fail; 'req_retran'= Packets retrans;
          'req_ofo'= Packets ofo; 'server_resel'= Server reselection; 'svr_prem_close'=
          Server premature close; 'new_svrconn'= Server conn made; 'snat_fail'= Source
          NAT failure; 'tcpoutrst'= Out RSTs; 'full_proxy'= Full proxy tot;
          'full_proxy_post'= Full proxy POST; 'full_proxy_pipeline'= Full proxy pipeline;
          'full_proxy_fpga_err'= Full proxy fpga err; 'req_over_limit'= Request over
          limit; 'req_rate_over_limit'= Request rate over limit; 'l4_switching'= L4
          switching; 'cookie_switching'= Cookie switching; 'aflex_switching'= aFleX
          switching; 'http_policy_switching'= HTTP Policy switching; 'url_switching'= URL
          switching; 'host_switching'= Host switching; 'lb_switching'= Normal LB
          switching; 'l4_switching_ok'= L4 switching (succ); 'cookie_switching_ok'=
          Cookie switching (succ); 'aflex_switching_ok'= aFleX switching (succ);
          'http_policy_switching_ok'= HTTP Policy switching (succ); 'url_switching_ok'=
          URL switching (succ); 'host_switching_ok'= Host switching (succ);
          'lb_switching_ok'= Normal LB switch. (succ); 'l4_switching_enqueue'= L4
          switching (enQ); 'cookie_switching_enqueue'= Cookie switching (enQ);
          'aflex_switching_enqueue'= aFleX switching (enQ);
          'http_policy_switching_enqueue'= HTTP Policy switching (enQ);
          'url_switching_enqueue'= URL switching (enQ); 'host_switching_enqueue'= Host
          switching (enQ); 'lb_switching_enqueue'= Normal LB switch. (enQ); 'retry_503'=
          Retry on 503; 'aflex_retry'= aFleX http retry; 'aflex_lb_reselect'= aFleX lb
          reselect; 'aflex_lb_reselect_ok'= aFleX lb reselect (succ);
          'client_rst_request'= Client RST - request; 'client_rst_connecting'= Client RST
          - connecting; 'client_rst_connected'= Client RST - connected;
          'client_rst_response'= Client RST - response; 'server_rst_request'= Server RST
          - request; 'server_rst_connecting'= Server RST - connecting;
          'server_rst_connected'= Server RST - connected; 'server_rst_response'= Server
          RST - response; 'invalid_header'= Invalid header; 'too_many_headers'= Too many
          headers; 'line_too_long'= Line too long; 'header_name_too_long'= Header name
          too long; 'wrong_resp_header'= Wrong response header; 'header_insert'= Header
          insert; 'header_delete'= Header delete; 'insert_client_ip'= Insert client IP;
          'negative_req_remain'= Negative request remain; 'negative_resp_remain'=
          Negative response remain; 'large_cookie'= Large cookies; 'large_cookie_header'=
          Large cookie headers; 'huge_cookie'= Huge cookies; 'huge_cookie_header'= Huge
          cookie headers; 'parse_cookie_fail'= Parse cookie fail; 'parse_setcookie_fail'=
          Parse set-cookie fail; 'asm_cookie_fail'= Assemble cookie fail;
          'asm_cookie_header_fail'= Asm cookie header fail; 'asm_setcookie_fail'=
          Assemble set-cookie fail; 'asm_setcookie_header_fail'= Asm set-cookie hdr fail;
          'client_req_unexp_flag'= Client req unexp flags; 'connecting_fin'= Connecting
          FIN; 'connecting_fin_retrans'= Connecting FIN retran; 'connecting_fin_ofo'=
          Connecting FIN ofo; 'connecting_rst'= Connecting RST; 'connecting_rst_retrans'=
          Connecting RST retran; 'connecting_rst_ofo'= Connecting RST ofo;
          'connecting_ack'= Connecting ACK; 'pkts_ofo'= Packets ofo; 'pkts_retrans'=
          Packets retrans; 'pkts_retrans_ack_finwait'= retrans ACK FWAIT;
          'pkts_retrans_fin'= retrans FIN; 'pkts_retrans_rst'= retrans RST;
          'pkts_retrans_push'= retrans PSH; 'stale_sess'= Stale sess;
          'server_resel_failed'= Server re-select failed; 'compression_before'= Tot data
          before compress; 'compression_after'= Tot data after compress; 'response_1xx'=
          Status code 1XX; 'response_100'= Status code 100; 'response_101'= Status code
          101; 'response_102'= Status code 102; 'response_2xx'= Status code 2XX;
          'response_200'= Status code 200; 'response_201'= Status code 201;
          'response_202'= Status code 202; 'response_203'= Status code 203;
          'response_204'= Status code 204; 'response_205'= Status code 205;
          'response_206'= Status code 206; 'response_207'= Status code 207;
          'response_3xx'= Status code 3XX; 'response_300'= Status code 300;
          'response_301'= Status code 301; 'response_302'= Status code 302;
          'response_303'= Status code 303; 'response_304'= Status code 304;
          'response_305'= Status code 305; 'response_306'= Status code 306;
          'response_307'= Status code 307; 'response_4xx'= Status code 4XX;
          'response_400'= Status code 400; 'response_401'= Status code 401;
          'response_402'= Status code 402; 'response_403'= Status code 403;
          'response_404'= Status code 404; 'response_405'= Status code 405;
          'response_406'= Status code 406; 'response_407'= Status code 407;
          'response_408'= Status code 408; 'response_409'= Status code 409;
          'response_410'= Status code 410; 'response_411'= Status code 411;
          'response_412'= Status code 412; 'response_413'= Status code 413;
          'response_414'= Status code 414; 'response_415'= Status code 415;
          'response_416'= Status code 416; 'response_417'= Status code 417;
          'response_418'= Status code 418; 'response_422'= Status code 422;
          'response_423'= Status code 423; 'response_424'= Status code 424;
          'response_425'= Status code 425; 'response_426'= Status code 426;
          'response_449'= Status code 449; 'response_450'= Status code 450;
          'response_5xx'= Status code 5XX; 'response_500'= Status code 500;
          'response_501'= Status code 501; 'response_502'= Status code 502;
          'response_503'= Status code 503; 'response_504'= Status code 504;
          'response_505'= Status code 505; 'response_506'= Status code 506;
          'response_507'= Status code 507; 'response_508'= Status code 508;
          'response_509'= Status code 509; 'response_510'= Status code 510;
          'response_6xx'= Status code 6XX; 'response_unknown'= Status code unknown;
          'req_http10'= Request 1.0; 'req_http11'= Request 1.1; 'response_http10'= Resp
          1.0; 'response_http11'= Resp 1.1; 'req_get'= Method GET; 'req_head'= Method
          HEAD; 'req_put'= Method PUT; 'req_post'= Method POST; 'req_trace'= Method
          TRACE; 'req_options'= Method OPTIONS; 'req_connect'= Method CONNECT;
          'req_delete'= Method DELETE; 'req_unknown'= Method UNKNOWN; 'req_content_len'=
          Req content len; 'rsp_content_len'= Resp content len; 'rsp_chunk'= Resp chunk
          encoding; 'req_chunk'= Req chunk encoding; 'compress_rsp'= Compress req;
          'compress_del_accept_enc'= Compress del accept enc;
          'compress_resp_already_compressed'= Resp already compressed;
          'compress_content_type_excluded'= Compress cont type excl;
          'compress_no_content_type'= Compress no cont type; 'compress_resp_lt_min'=
          Compress resp less than min; 'compress_resp_no_cl_or_ce'= Compress resp no
          CL/CE; 'compress_ratio_too_high'= Compress ratio too high; 'cache_rsp'= HTTP
          req (cache succ); 'close_on_ddos'= Close on DDoS; 'req_http10_keepalive'= 1.0
          Keepalive; 'req_sz_1k'= Req less than equal to 1K; 'req_sz_2k'= Req less than
          equal to 2K; 'req_sz_4k'= Req less than equal to 4K;"
                type: str
            counters2:
                description:
                - "'req_sz_8k'= Req less than equal to 8K; 'req_sz_16k'= Req less than equal to
          16K; 'req_sz_32k'= Req less than equal to 32K; 'req_sz_64k'= Req less than
          equal to 64K; 'req_sz_256k'= Req less than equal to 256K; 'req_sz_gt_256k'= Req
          greater than 256K; 'rsp_sz_1k'= Resp less than equal to 1K; 'rsp_sz_2k'= Resp
          less than equal to 2K; 'rsp_sz_4k'= Resp less than equal to 4K; 'rsp_sz_8k'=
          Resp less than equal to 8K; 'rsp_sz_16k'= Resp less than equal to 16K;
          'rsp_sz_32k'= Resp less than equal to 32K; 'rsp_sz_64k'= Resp less than equal
          to 64K; 'rsp_sz_256k'= Resp less than equal to 256K; 'rsp_sz_gt_256k'= Resp
          greater than 256K; 'chunk_sz_512'= Chunk less than equal to 512; 'chunk_sz_1k'=
          Chunk less than equal to 1K; 'chunk_sz_2k'= Chunk less than equal to 2K;
          'chunk_sz_4k'= Chunk less than equal to 4K; 'chunk_sz_gt_4k'= Chunk greater
          than 4K; 'pconn_connecting'= pconn connecting; 'pconn_connected'= pconn
          connected; 'pconn_connecting_failed'= pconn conn failed; 'chunk_bad'= Bad
          Chunk; 'req_10u'= Rsp time less than 10u; 'req_20u'= Rsp time less than 20u;
          'req_50u'= Rsp time less than 50u; 'req_100u'= Rsp time less than 100u;
          'req_200u'= Rsp time less than 200u; 'req_500u'= Rsp time less than 500u;
          'req_1m'= Rsp time less than 1m; 'req_2m'= Rsp time less than 2m; 'req_5m'= Rsp
          time less than 5m; 'req_10m'= Rsp time less than 10m; 'req_20m'= Rsp time less
          than 20m; 'req_50m'= Rsp time less than 50m; 'req_100m'= Rsp time less than
          100m; 'req_200m'= Rsp time less than 200m; 'req_500m'= Rsp time less than 500m;
          'req_1s'= Rsp time less than 1s; 'req_2s'= Rsp time less than 2s; 'req_5s'= Rsp
          time less than 5s; 'req_over_5s'= Rsp time greater than equal to 5s;
          'insert_client_port'= Insert client Port; 'req_track'= Method TRACK;
          'connect_req'= Total HTTP CONNECT requests; 'req_enter_ssli'= Total HTTP
          requests enter SSLi; 'non_http_bypass'= Non-HTTP bypass;
          'decompression_before'= Tot data before decompress; 'decompression_after'= Tot
          data after decompress; 'req_http2'= Request 2.0; 'response_http2'= Resp 2.0;
          'req_timeout_retry'= Retry on Req Timeout; 'req_timeout_close'= Close on Req
          Timeout; 'doh_req'= DoH Requests; 'doh_req_get'= DoH GET Requests;
          'doh_req_post'= DoH POST Requests; 'doh_non_doh_req'= DoH non DoH Requests;
          'doh_non_doh_req_get'= DoH non DoH GET Requests; 'doh_non_doh_req_post'= DoH
          non DoH POST Requests; 'doh_resp'= DoH Responses; 'doh_tc_resp'= DoH TC
          Responses; 'doh_udp_dns_req'= DoH UDP DNS Requests; 'doh_udp_dns_resp'= DoH UDP
          DNS Responses; 'doh_tcp_dns_req'= DoH TCP DNS Requests; 'doh_tcp_dns_resp'= DoH
          TCP DNS Responses; 'doh_req_send_failed'= DoH Request Send Failed;
          'doh_resp_send_failed'= DoH Response Send Failed; 'doh_malloc_fail'= DoH Memory
          alloc failed; 'doh_req_udp_retry'= DoH UDP Retry; 'doh_req_udp_retry_fail'= DoH
          UDP Retry failed; 'doh_req_tcp_retry'= DoH TCP Retry; 'doh_req_tcp_retry_fail'=
          DoH TCP Retry failed; 'doh_snat_failed'= DoH Source NAT failed;
          'doh_path_not_found'= DoH URI Path not found; 'doh_get_dns_arg_failed'= DoH GET
          dns arg not found in uri; 'doh_get_base64_decode_failed'= DoH GET base64url
          decode failed; 'doh_post_content_type_mismatch'= DoH POST content-type not
          found; 'doh_post_payload_not_found'= DoH POST payload not found;
          'doh_post_payload_extract_failed'= DoH POST payload extract failed;
          'doh_non_doh_method'= DoH Non DoH HTTP request method rcvd;
          'doh_tcp_send_failed'= DoH serv TCP DNS send failed; 'doh_udp_send_failed'= DoH
          serv UDP DNS send failed; 'doh_query_time_out'= DoH serv Query timed out;
          'doh_dns_query_type_a'= DoH Query type A; 'doh_dns_query_type_aaaa'= DoH Query
          type AAAA; 'doh_dns_query_type_ns'= DoH Query type NS;
          'doh_dns_query_type_cname'= DoH Query type CNAME; 'doh_dns_query_type_any'= DoH
          Query type ANY; 'doh_dns_query_type_srv'= DoH Query type SRV;
          'doh_dns_query_type_mx'= DoH Query type MX; 'doh_dns_query_type_soa'= DoH Query
          type SOA; 'doh_dns_query_type_others'= DoH Query type Others;
          'doh_resp_setup_failed'= DoH Response setup failed;
          'doh_resp_header_alloc_failed'= DoH Resp hdr alloc failed;
          'doh_resp_que_failed'= DoH Resp queue failed; 'doh_resp_udp_frags'= DoH UDP
          Frags Rcvd; 'doh_resp_tcp_frags'= DoH TCP Frags Rcvd; 'doh_serv_sel_failed'=
          DoH Server Select Failed; 'doh_retry_w_tcp'= DoH Retry with TCP SG;
          'doh_get_uri_too_long'= DoH GET URI too long; 'doh_post_payload_too_large'= DoH
          POST Payload too large; 'doh_dns_malformed_query'= DoH DNS Malformed Query;
          'doh_dns_resp_rcode_err_format'= DoH DNS Response rcode ERR_FORMAT;
          'doh_dns_resp_rcode_err_server'= DoH DNS Response rcode ERR_SERVER;
          'doh_dns_resp_rcode_err_name'= DoH DNS Response rcode ERR_NAME;
          'doh_dns_resp_rcode_err_type'= DoH DNS Response rcode ERR_TYPE;
          'doh_dns_resp_rcode_refuse'= DoH DNS Response rcode REFUSE;
          'doh_dns_resp_rcode_yxdomain'= DoH DNS Response rcode YXDOMAIN;
          'doh_dns_resp_rcode_yxrrset'= DoH DNS Response rcode YXRRSET;
          'doh_dns_resp_rcode_nxrrset'= DoH DNS Response rcode NXRRSET;
          'doh_dns_resp_rcode_notauth'= DoH DNS Response rcode NOTAUTH;
          'doh_dns_resp_rcode_notzone'= DoH DNS Response rcode NOTZONE;
          'doh_dns_resp_rcode_other'= DoH DNS Response rcode OTHER;
          'compression_before_br'= Tot data before brotli compress;
          'compression_after_br'= Tot data after brotli compress;
          'compression_before_total'= Tot data before compress;
          'compression_after_total'= Tot data after compress; 'decompression_before_br'=
          Tot data before brotli decompress; 'decompression_after_br'= Tot data after
          brotli decompress; 'decompression_before_total'= Tot data before decompress;
          'decompression_after_total'= Tot data after decompress; 'compress_rsp_br'=
          Compress req with brotli; 'compress_rsp_total'= Compress req;
          'h2up_content_length_alias'= HTTP2 content length alias;
          'malformed_h2up_header_value'= Malformed HTTP2 header value;
          'malformed_h2up_scheme_value'= Malformed HTTP2 scheme value;
          'h2up_with_transfer_encoding'= HTTP2 with transfer-encoding header;
          'multiple_content_length'= Multiple content-length headers;
          'multiple_transfer_encoding'= Multiple transfer-encoding headers;
          'transfer_encoding_and_content_length'= Transfer-encoding header with Content-
          Length header; 'get_and_payload'= GET method with content-length header or
          transfer-encoding header; 'h2up_with_host_and_auth'= HTTP2 with host header and
          authority header; 'req_http3'= Request 3.0; 'response_http3'= Resp 3.0;
          'header_filter_rule_hit'= Hit header filter rule; 'http1_client_idle_timeout'=
          HTTP1 client idle timeout; 'http2_client_idle_timeout'= HTTP2 client idle
          timeout; 'http_disallowed_methods'= HTTP disallowed methods;
          'http_allowed_methods'= HTTP allowed methods; 'req_http11_new_proxy'= Request
          1.1 (new proxy);"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            http_proxy_cpu_list:
                description:
                - "Field http_proxy_cpu_list"
                type: list
            cpu_count:
                description:
                - "Field cpu_count"
                type: int
            debug_fields:
                description:
                - "Field debug_fields"
                type: bool
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            curr_proxy:
                description:
                - "Curr Proxy Conns"
                type: str
            total_proxy:
                description:
                - "Total Proxy Conns"
                type: str
            req:
                description:
                - "HTTP requests"
                type: str
            req_succ:
                description:
                - "HTTP requests(succ)"
                type: str
            noproxy:
                description:
                - "No proxy error"
                type: str
            client_rst:
                description:
                - "Client RST"
                type: str
            server_rst:
                description:
                - "Server RST"
                type: str
            notuple:
                description:
                - "No tuple error"
                type: str
            parsereq_fail:
                description:
                - "Parse req fail"
                type: str
            svrsel_fail:
                description:
                - "Server selection fail"
                type: str
            fwdreq_fail:
                description:
                - "Fwd req fail"
                type: str
            fwdreqdata_fail:
                description:
                - "Field fwdreqdata_fail"
                type: str
            req_retran:
                description:
                - "Packets retrans"
                type: str
            req_ofo:
                description:
                - "Packets ofo"
                type: str
            server_resel:
                description:
                - "Server reselection"
                type: str
            svr_prem_close:
                description:
                - "Server premature close"
                type: str
            new_svrconn:
                description:
                - "Server conn made"
                type: str
            snat_fail:
                description:
                - "Source NAT failure"
                type: str
            req_over_limit:
                description:
                - "Request over limit"
                type: str
            req_rate_over_limit:
                description:
                - "Request rate over limit"
                type: str
            compression_before:
                description:
                - "Tot data before compress"
                type: str
            compression_after:
                description:
                - "Tot data after compress"
                type: str
            response_1xx:
                description:
                - "Status code 1XX"
                type: str
            response_100:
                description:
                - "Status code 100"
                type: str
            response_101:
                description:
                - "Status code 101"
                type: str
            response_102:
                description:
                - "Status code 102"
                type: str
            response_2xx:
                description:
                - "Status code 2XX"
                type: str
            response_200:
                description:
                - "Status code 200"
                type: str
            response_201:
                description:
                - "Status code 201"
                type: str
            response_202:
                description:
                - "Status code 202"
                type: str
            response_203:
                description:
                - "Status code 203"
                type: str
            response_204:
                description:
                - "Status code 204"
                type: str
            response_205:
                description:
                - "Status code 205"
                type: str
            response_206:
                description:
                - "Status code 206"
                type: str
            response_207:
                description:
                - "Status code 207"
                type: str
            response_3xx:
                description:
                - "Status code 3XX"
                type: str
            response_300:
                description:
                - "Status code 300"
                type: str
            response_301:
                description:
                - "Status code 301"
                type: str
            response_302:
                description:
                - "Status code 302"
                type: str
            response_303:
                description:
                - "Status code 303"
                type: str
            response_304:
                description:
                - "Status code 304"
                type: str
            response_305:
                description:
                - "Status code 305"
                type: str
            response_306:
                description:
                - "Status code 306"
                type: str
            response_307:
                description:
                - "Status code 307"
                type: str
            response_4xx:
                description:
                - "Status code 4XX"
                type: str
            response_400:
                description:
                - "Status code 400"
                type: str
            response_401:
                description:
                - "Status code 401"
                type: str
            response_402:
                description:
                - "Status code 402"
                type: str
            response_403:
                description:
                - "Status code 403"
                type: str
            response_404:
                description:
                - "Status code 404"
                type: str
            response_405:
                description:
                - "Status code 405"
                type: str
            response_406:
                description:
                - "Status code 406"
                type: str
            response_407:
                description:
                - "Status code 407"
                type: str
            response_408:
                description:
                - "Status code 408"
                type: str
            response_409:
                description:
                - "Status code 409"
                type: str
            response_410:
                description:
                - "Status code 410"
                type: str
            response_411:
                description:
                - "Status code 411"
                type: str
            response_412:
                description:
                - "Status code 412"
                type: str
            response_413:
                description:
                - "Status code 413"
                type: str
            response_414:
                description:
                - "Status code 414"
                type: str
            response_415:
                description:
                - "Status code 415"
                type: str
            response_416:
                description:
                - "Status code 416"
                type: str
            response_417:
                description:
                - "Status code 417"
                type: str
            response_418:
                description:
                - "Status code 418"
                type: str
            response_422:
                description:
                - "Status code 422"
                type: str
            response_423:
                description:
                - "Status code 423"
                type: str
            response_424:
                description:
                - "Status code 424"
                type: str
            response_425:
                description:
                - "Status code 425"
                type: str
            response_426:
                description:
                - "Status code 426"
                type: str
            response_449:
                description:
                - "Status code 449"
                type: str
            response_450:
                description:
                - "Status code 450"
                type: str
            response_5xx:
                description:
                - "Status code 5XX"
                type: str
            response_500:
                description:
                - "Status code 500"
                type: str
            response_501:
                description:
                - "Status code 501"
                type: str
            response_502:
                description:
                - "Status code 502"
                type: str
            response_503:
                description:
                - "Status code 503"
                type: str
            response_504:
                description:
                - "Status code 504"
                type: str
            response_505:
                description:
                - "Status code 505"
                type: str
            response_506:
                description:
                - "Status code 506"
                type: str
            response_507:
                description:
                - "Status code 507"
                type: str
            response_508:
                description:
                - "Status code 508"
                type: str
            response_509:
                description:
                - "Status code 509"
                type: str
            response_510:
                description:
                - "Status code 510"
                type: str
            response_6xx:
                description:
                - "Status code 6XX"
                type: str
            response_unknown:
                description:
                - "Status code unknown"
                type: str
            req_get:
                description:
                - "Method GET"
                type: str
            req_head:
                description:
                - "Method HEAD"
                type: str
            req_put:
                description:
                - "Method PUT"
                type: str
            req_post:
                description:
                - "Method POST"
                type: str
            req_trace:
                description:
                - "Method TRACE"
                type: str
            req_options:
                description:
                - "Method OPTIONS"
                type: str
            req_connect:
                description:
                - "Method CONNECT"
                type: str
            req_delete:
                description:
                - "Method DELETE"
                type: str
            req_unknown:
                description:
                - "Method UNKNOWN"
                type: str
            req_content_len:
                description:
                - "Req content len"
                type: str
            rsp_content_len:
                description:
                - "Resp content len"
                type: str
            rsp_chunk:
                description:
                - "Resp chunk encoding"
                type: str
            cache_rsp:
                description:
                - "HTTP req (cache succ)"
                type: str
            close_on_ddos:
                description:
                - "Close on DDoS"
                type: str
            req_sz_1k:
                description:
                - "Req less than equal to 1K"
                type: str
            req_sz_2k:
                description:
                - "Req less than equal to 2K"
                type: str
            req_sz_4k:
                description:
                - "Req less than equal to 4K"
                type: str
            req_sz_8k:
                description:
                - "Req less than equal to 8K"
                type: str
            req_sz_16k:
                description:
                - "Req less than equal to 16K"
                type: str
            req_sz_32k:
                description:
                - "Req less than equal to 32K"
                type: str
            req_sz_64k:
                description:
                - "Req less than equal to 64K"
                type: str
            req_sz_256k:
                description:
                - "Req less than equal to 256K"
                type: str
            req_sz_gt_256k:
                description:
                - "Req greater than 256K"
                type: str
            rsp_sz_1k:
                description:
                - "Resp less than equal to 1K"
                type: str
            rsp_sz_2k:
                description:
                - "Resp less than equal to 2K"
                type: str
            rsp_sz_4k:
                description:
                - "Resp less than equal to 4K"
                type: str
            rsp_sz_8k:
                description:
                - "Resp less than equal to 8K"
                type: str
            rsp_sz_16k:
                description:
                - "Resp less than equal to 16K"
                type: str
            rsp_sz_32k:
                description:
                - "Resp less than equal to 32K"
                type: str
            rsp_sz_64k:
                description:
                - "Resp less than equal to 64K"
                type: str
            rsp_sz_256k:
                description:
                - "Resp less than equal to 256K"
                type: str
            rsp_sz_gt_256k:
                description:
                - "Resp greater than 256K"
                type: str
            chunk_sz_512:
                description:
                - "Chunk less than equal to 512"
                type: str
            chunk_sz_1k:
                description:
                - "Chunk less than equal to 1K"
                type: str
            chunk_sz_2k:
                description:
                - "Chunk less than equal to 2K"
                type: str
            chunk_sz_4k:
                description:
                - "Chunk less than equal to 4K"
                type: str
            chunk_sz_gt_4k:
                description:
                - "Chunk greater than 4K"
                type: str
            req_10u:
                description:
                - "Rsp time less than 10u"
                type: str
            req_20u:
                description:
                - "Rsp time less than 20u"
                type: str
            req_50u:
                description:
                - "Rsp time less than 50u"
                type: str
            req_100u:
                description:
                - "Rsp time less than 100u"
                type: str
            req_200u:
                description:
                - "Rsp time less than 200u"
                type: str
            req_500u:
                description:
                - "Rsp time less than 500u"
                type: str
            req_1m:
                description:
                - "Rsp time less than 1m"
                type: str
            req_2m:
                description:
                - "Rsp time less than 2m"
                type: str
            req_5m:
                description:
                - "Rsp time less than 5m"
                type: str
            req_10m:
                description:
                - "Rsp time less than 10m"
                type: str
            req_20m:
                description:
                - "Rsp time less than 20m"
                type: str
            req_50m:
                description:
                - "Rsp time less than 50m"
                type: str
            req_100m:
                description:
                - "Rsp time less than 100m"
                type: str
            req_200m:
                description:
                - "Rsp time less than 200m"
                type: str
            req_500m:
                description:
                - "Rsp time less than 500m"
                type: str
            req_1s:
                description:
                - "Rsp time less than 1s"
                type: str
            req_2s:
                description:
                - "Rsp time less than 2s"
                type: str
            req_5s:
                description:
                - "Rsp time less than 5s"
                type: str
            req_over_5s:
                description:
                - "Rsp time greater than equal to 5s"
                type: str
            req_track:
                description:
                - "Method TRACK"
                type: str
            connect_req:
                description:
                - "Total HTTP CONNECT requests"
                type: str
            req_enter_ssli:
                description:
                - "Total HTTP requests enter SSLi"
                type: str
            decompression_before:
                description:
                - "Tot data before decompress"
                type: str
            decompression_after:
                description:
                - "Tot data after decompress"
                type: str
            req_http2:
                description:
                - "Request 2.0"
                type: str
            response_http2:
                description:
                - "Resp 2.0"
                type: str
            doh_req:
                description:
                - "DoH Requests"
                type: str
            doh_req_get:
                description:
                - "DoH GET Requests"
                type: str
            doh_req_post:
                description:
                - "DoH POST Requests"
                type: str
            doh_non_doh_req:
                description:
                - "DoH non DoH Requests"
                type: str
            doh_non_doh_req_get:
                description:
                - "DoH non DoH GET Requests"
                type: str
            doh_non_doh_req_post:
                description:
                - "DoH non DoH POST Requests"
                type: str
            doh_resp:
                description:
                - "DoH Responses"
                type: str
            doh_tc_resp:
                description:
                - "DoH TC Responses"
                type: str
            doh_udp_dns_req:
                description:
                - "DoH UDP DNS Requests"
                type: str
            doh_udp_dns_resp:
                description:
                - "DoH UDP DNS Responses"
                type: str
            doh_tcp_dns_req:
                description:
                - "DoH TCP DNS Requests"
                type: str
            doh_tcp_dns_resp:
                description:
                - "DoH TCP DNS Responses"
                type: str
            doh_req_send_failed:
                description:
                - "DoH Request Send Failed"
                type: str
            doh_resp_send_failed:
                description:
                - "DoH Response Send Failed"
                type: str
            doh_malloc_fail:
                description:
                - "DoH Memory alloc failed"
                type: str
            doh_req_udp_retry:
                description:
                - "DoH UDP Retry"
                type: str
            doh_req_udp_retry_fail:
                description:
                - "DoH UDP Retry failed"
                type: str
            doh_req_tcp_retry:
                description:
                - "DoH TCP Retry"
                type: str
            doh_req_tcp_retry_fail:
                description:
                - "DoH TCP Retry failed"
                type: str
            doh_snat_failed:
                description:
                - "DoH Source NAT failed"
                type: str
            doh_path_not_found:
                description:
                - "DoH URI Path not found"
                type: str
            doh_get_dns_arg_failed:
                description:
                - "DoH GET dns arg not found in uri"
                type: str
            doh_get_base64_decode_failed:
                description:
                - "DoH GET base64url decode failed"
                type: str
            doh_post_content_type_mismatch:
                description:
                - "DoH POST content-type not found"
                type: str
            doh_post_payload_not_found:
                description:
                - "DoH POST payload not found"
                type: str
            doh_post_payload_extract_failed:
                description:
                - "DoH POST payload extract failed"
                type: str
            doh_non_doh_method:
                description:
                - "DoH Non DoH HTTP request method rcvd"
                type: str
            doh_tcp_send_failed:
                description:
                - "DoH serv TCP DNS send failed"
                type: str
            doh_udp_send_failed:
                description:
                - "DoH serv UDP DNS send failed"
                type: str
            doh_query_time_out:
                description:
                - "DoH serv Query timed out"
                type: str
            doh_dns_query_type_a:
                description:
                - "DoH Query type A"
                type: str
            doh_dns_query_type_aaaa:
                description:
                - "DoH Query type AAAA"
                type: str
            doh_dns_query_type_ns:
                description:
                - "DoH Query type NS"
                type: str
            doh_dns_query_type_cname:
                description:
                - "DoH Query type CNAME"
                type: str
            doh_dns_query_type_any:
                description:
                - "DoH Query type ANY"
                type: str
            doh_dns_query_type_srv:
                description:
                - "DoH Query type SRV"
                type: str
            doh_dns_query_type_mx:
                description:
                - "DoH Query type MX"
                type: str
            doh_dns_query_type_soa:
                description:
                - "DoH Query type SOA"
                type: str
            doh_dns_query_type_others:
                description:
                - "DoH Query type Others"
                type: str
            doh_resp_setup_failed:
                description:
                - "DoH Response setup failed"
                type: str
            doh_resp_header_alloc_failed:
                description:
                - "DoH Resp hdr alloc failed"
                type: str
            doh_resp_que_failed:
                description:
                - "DoH Resp queue failed"
                type: str
            doh_resp_udp_frags:
                description:
                - "DoH UDP Frags Rcvd"
                type: str
            doh_resp_tcp_frags:
                description:
                - "DoH TCP Frags Rcvd"
                type: str
            doh_serv_sel_failed:
                description:
                - "DoH Server Select Failed"
                type: str
            doh_retry_w_tcp:
                description:
                - "DoH Retry with TCP SG"
                type: str
            doh_get_uri_too_long:
                description:
                - "DoH GET URI too long"
                type: str
            doh_post_payload_too_large:
                description:
                - "DoH POST Payload too large"
                type: str
            doh_dns_malformed_query:
                description:
                - "DoH DNS Malformed Query"
                type: str
            doh_dns_resp_rcode_err_format:
                description:
                - "DoH DNS Response rcode ERR_FORMAT"
                type: str
            doh_dns_resp_rcode_err_server:
                description:
                - "DoH DNS Response rcode ERR_SERVER"
                type: str
            doh_dns_resp_rcode_err_name:
                description:
                - "DoH DNS Response rcode ERR_NAME"
                type: str
            doh_dns_resp_rcode_err_type:
                description:
                - "DoH DNS Response rcode ERR_TYPE"
                type: str
            doh_dns_resp_rcode_refuse:
                description:
                - "DoH DNS Response rcode REFUSE"
                type: str
            doh_dns_resp_rcode_yxdomain:
                description:
                - "DoH DNS Response rcode YXDOMAIN"
                type: str
            doh_dns_resp_rcode_yxrrset:
                description:
                - "DoH DNS Response rcode YXRRSET"
                type: str
            doh_dns_resp_rcode_nxrrset:
                description:
                - "DoH DNS Response rcode NXRRSET"
                type: str
            doh_dns_resp_rcode_notauth:
                description:
                - "DoH DNS Response rcode NOTAUTH"
                type: str
            doh_dns_resp_rcode_notzone:
                description:
                - "DoH DNS Response rcode NOTZONE"
                type: str
            doh_dns_resp_rcode_other:
                description:
                - "DoH DNS Response rcode OTHER"
                type: str
            compression_before_br:
                description:
                - "Tot data before brotli compress"
                type: str
            compression_after_br:
                description:
                - "Tot data after brotli compress"
                type: str
            compression_before_total:
                description:
                - "Tot data before compress"
                type: str
            compression_after_total:
                description:
                - "Tot data after compress"
                type: str
            decompression_before_br:
                description:
                - "Tot data before brotli decompress"
                type: str
            decompression_after_br:
                description:
                - "Tot data after brotli decompress"
                type: str
            decompression_before_total:
                description:
                - "Tot data before decompress"
                type: str
            decompression_after_total:
                description:
                - "Tot data after decompress"
                type: str
            req_http3:
                description:
                - "Request 3.0"
                type: str
            response_http3:
                description:
                - "Resp 3.0"
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
                    'all', 'num', 'curr_proxy', 'total_proxy', 'req', 'req_succ', 'noproxy', 'client_rst', 'server_rst', 'notuple', 'parsereq_fail', 'svrsel_fail', 'fwdreq_fail', 'fwdreq_fail_buff', 'fwdreq_fail_rport', 'fwdreq_fail_route', 'fwdreq_fail_persist', 'fwdreq_fail_server', 'fwdreq_fail_tuple', 'fwdreqdata_fail', 'req_retran', 'req_ofo',
                    'server_resel', 'svr_prem_close', 'new_svrconn', 'snat_fail', 'tcpoutrst', 'full_proxy', 'full_proxy_post', 'full_proxy_pipeline', 'full_proxy_fpga_err', 'req_over_limit', 'req_rate_over_limit', 'l4_switching', 'cookie_switching', 'aflex_switching', 'http_policy_switching', 'url_switching', 'host_switching', 'lb_switching',
                    'l4_switching_ok', 'cookie_switching_ok', 'aflex_switching_ok', 'http_policy_switching_ok', 'url_switching_ok', 'host_switching_ok', 'lb_switching_ok', 'l4_switching_enqueue', 'cookie_switching_enqueue', 'aflex_switching_enqueue', 'http_policy_switching_enqueue', 'url_switching_enqueue', 'host_switching_enqueue',
                    'lb_switching_enqueue', 'retry_503', 'aflex_retry', 'aflex_lb_reselect', 'aflex_lb_reselect_ok', 'client_rst_request', 'client_rst_connecting', 'client_rst_connected', 'client_rst_response', 'server_rst_request', 'server_rst_connecting', 'server_rst_connected', 'server_rst_response', 'invalid_header', 'too_many_headers',
                    'line_too_long', 'header_name_too_long', 'wrong_resp_header', 'header_insert', 'header_delete', 'insert_client_ip', 'negative_req_remain', 'negative_resp_remain', 'large_cookie', 'large_cookie_header', 'huge_cookie', 'huge_cookie_header', 'parse_cookie_fail', 'parse_setcookie_fail', 'asm_cookie_fail', 'asm_cookie_header_fail',
                    'asm_setcookie_fail', 'asm_setcookie_header_fail', 'client_req_unexp_flag', 'connecting_fin', 'connecting_fin_retrans', 'connecting_fin_ofo', 'connecting_rst', 'connecting_rst_retrans', 'connecting_rst_ofo', 'connecting_ack', 'pkts_ofo', 'pkts_retrans', 'pkts_retrans_ack_finwait', 'pkts_retrans_fin', 'pkts_retrans_rst',
                    'pkts_retrans_push', 'stale_sess', 'server_resel_failed', 'compression_before', 'compression_after', 'response_1xx', 'response_100', 'response_101', 'response_102', 'response_2xx', 'response_200', 'response_201', 'response_202', 'response_203', 'response_204', 'response_205', 'response_206', 'response_207', 'response_3xx',
                    'response_300', 'response_301', 'response_302', 'response_303', 'response_304', 'response_305', 'response_306', 'response_307', 'response_4xx', 'response_400', 'response_401', 'response_402', 'response_403', 'response_404', 'response_405', 'response_406', 'response_407', 'response_408', 'response_409', 'response_410',
                    'response_411', 'response_412', 'response_413', 'response_414', 'response_415', 'response_416', 'response_417', 'response_418', 'response_422', 'response_423', 'response_424', 'response_425', 'response_426', 'response_449', 'response_450', 'response_5xx', 'response_500', 'response_501', 'response_502', 'response_503',
                    'response_504', 'response_505', 'response_506', 'response_507', 'response_508', 'response_509', 'response_510', 'response_6xx', 'response_unknown', 'req_http10', 'req_http11', 'response_http10', 'response_http11', 'req_get', 'req_head', 'req_put', 'req_post', 'req_trace', 'req_options', 'req_connect', 'req_delete',
                    'req_unknown', 'req_content_len', 'rsp_content_len', 'rsp_chunk', 'req_chunk', 'compress_rsp', 'compress_del_accept_enc', 'compress_resp_already_compressed', 'compress_content_type_excluded', 'compress_no_content_type', 'compress_resp_lt_min', 'compress_resp_no_cl_or_ce', 'compress_ratio_too_high', 'cache_rsp', 'close_on_ddos',
                    'req_http10_keepalive', 'req_sz_1k', 'req_sz_2k', 'req_sz_4k'
                    ]
                },
            'counters2': {
                'type':
                'str',
                'choices': [
                    'req_sz_8k', 'req_sz_16k', 'req_sz_32k', 'req_sz_64k', 'req_sz_256k', 'req_sz_gt_256k', 'rsp_sz_1k', 'rsp_sz_2k', 'rsp_sz_4k', 'rsp_sz_8k', 'rsp_sz_16k', 'rsp_sz_32k', 'rsp_sz_64k', 'rsp_sz_256k', 'rsp_sz_gt_256k', 'chunk_sz_512', 'chunk_sz_1k', 'chunk_sz_2k', 'chunk_sz_4k', 'chunk_sz_gt_4k', 'pconn_connecting',
                    'pconn_connected', 'pconn_connecting_failed', 'chunk_bad', 'req_10u', 'req_20u', 'req_50u', 'req_100u', 'req_200u', 'req_500u', 'req_1m', 'req_2m', 'req_5m', 'req_10m', 'req_20m', 'req_50m', 'req_100m', 'req_200m', 'req_500m', 'req_1s', 'req_2s', 'req_5s', 'req_over_5s', 'insert_client_port', 'req_track', 'connect_req',
                    'req_enter_ssli', 'non_http_bypass', 'decompression_before', 'decompression_after', 'req_http2', 'response_http2', 'req_timeout_retry', 'req_timeout_close', 'doh_req', 'doh_req_get', 'doh_req_post', 'doh_non_doh_req', 'doh_non_doh_req_get', 'doh_non_doh_req_post', 'doh_resp', 'doh_tc_resp', 'doh_udp_dns_req', 'doh_udp_dns_resp',
                    'doh_tcp_dns_req', 'doh_tcp_dns_resp', 'doh_req_send_failed', 'doh_resp_send_failed', 'doh_malloc_fail', 'doh_req_udp_retry', 'doh_req_udp_retry_fail', 'doh_req_tcp_retry', 'doh_req_tcp_retry_fail', 'doh_snat_failed', 'doh_path_not_found', 'doh_get_dns_arg_failed', 'doh_get_base64_decode_failed',
                    'doh_post_content_type_mismatch', 'doh_post_payload_not_found', 'doh_post_payload_extract_failed', 'doh_non_doh_method', 'doh_tcp_send_failed', 'doh_udp_send_failed', 'doh_query_time_out', 'doh_dns_query_type_a', 'doh_dns_query_type_aaaa', 'doh_dns_query_type_ns', 'doh_dns_query_type_cname', 'doh_dns_query_type_any',
                    'doh_dns_query_type_srv', 'doh_dns_query_type_mx', 'doh_dns_query_type_soa', 'doh_dns_query_type_others', 'doh_resp_setup_failed', 'doh_resp_header_alloc_failed', 'doh_resp_que_failed', 'doh_resp_udp_frags', 'doh_resp_tcp_frags', 'doh_serv_sel_failed', 'doh_retry_w_tcp', 'doh_get_uri_too_long', 'doh_post_payload_too_large',
                    'doh_dns_malformed_query', 'doh_dns_resp_rcode_err_format', 'doh_dns_resp_rcode_err_server', 'doh_dns_resp_rcode_err_name', 'doh_dns_resp_rcode_err_type', 'doh_dns_resp_rcode_refuse', 'doh_dns_resp_rcode_yxdomain', 'doh_dns_resp_rcode_yxrrset', 'doh_dns_resp_rcode_nxrrset', 'doh_dns_resp_rcode_notauth',
                    'doh_dns_resp_rcode_notzone', 'doh_dns_resp_rcode_other', 'compression_before_br', 'compression_after_br', 'compression_before_total', 'compression_after_total', 'decompression_before_br', 'decompression_after_br', 'decompression_before_total', 'decompression_after_total', 'compress_rsp_br', 'compress_rsp_total',
                    'h2up_content_length_alias', 'malformed_h2up_header_value', 'malformed_h2up_scheme_value', 'h2up_with_transfer_encoding', 'multiple_content_length', 'multiple_transfer_encoding', 'transfer_encoding_and_content_length', 'get_and_payload', 'h2up_with_host_and_auth', 'req_http3', 'response_http3', 'header_filter_rule_hit',
                    'http1_client_idle_timeout', 'http2_client_idle_timeout', 'http_disallowed_methods', 'http_allowed_methods', 'req_http11_new_proxy'
                    ]
                }
            },
        'oper': {
            'type': 'dict',
            'http_proxy_cpu_list': {
                'type': 'list',
                'curr_proxy': {
                    'type': 'int',
                    },
                'total_proxy': {
                    'type': 'int',
                    },
                'req': {
                    'type': 'int',
                    },
                'connect_req': {
                    'type': 'int',
                    },
                'req_enter_ssli': {
                    'type': 'int',
                    },
                'req_succ': {
                    'type': 'int',
                    },
                'cache_rsp': {
                    'type': 'int',
                    },
                'noproxy': {
                    'type': 'int',
                    },
                'notuple': {
                    'type': 'int',
                    },
                'parsereq_fail': {
                    'type': 'int',
                    },
                'svrsel_fail': {
                    'type': 'int',
                    },
                'fwdreqdata_fail': {
                    'type': 'int',
                    },
                'req_retran': {
                    'type': 'int',
                    },
                'req_ofo': {
                    'type': 'int',
                    },
                'server_resel': {
                    'type': 'int',
                    },
                'svr_prem_close': {
                    'type': 'int',
                    },
                'new_svrconn': {
                    'type': 'int',
                    },
                'snat_fail': {
                    'type': 'int',
                    },
                'compression_before': {
                    'type': 'int',
                    },
                'compression_after': {
                    'type': 'int',
                    },
                'req_over_limit': {
                    'type': 'int',
                    },
                'req_rate_over_limit': {
                    'type': 'int',
                    },
                'close_on_ddos': {
                    'type': 'int',
                    },
                'decompression_before': {
                    'type': 'int',
                    },
                'decompression_after': {
                    'type': 'int',
                    },
                'client_rst': {
                    'type': 'int',
                    },
                'server_rst': {
                    'type': 'int',
                    },
                'fwdreq_fail': {
                    'type': 'int',
                    },
                'fwdreq_fail_buff': {
                    'type': 'int',
                    },
                'fwdreq_fail_rport': {
                    'type': 'int',
                    },
                'fwdreq_fail_route': {
                    'type': 'int',
                    },
                'fwdreq_fail_persist': {
                    'type': 'int',
                    },
                'fwdreq_fail_server': {
                    'type': 'int',
                    },
                'fwdreq_fail_tuple': {
                    'type': 'int',
                    },
                'l4_switching': {
                    'type': 'int',
                    },
                'cookie_switching': {
                    'type': 'int',
                    },
                'aflex_switching': {
                    'type': 'int',
                    },
                'url_switching': {
                    'type': 'int',
                    },
                'host_switching': {
                    'type': 'int',
                    },
                'lb_switching': {
                    'type': 'int',
                    },
                'l4_switching_ok': {
                    'type': 'int',
                    },
                'cookie_switching_ok': {
                    'type': 'int',
                    },
                'aflex_switching_ok': {
                    'type': 'int',
                    },
                'url_switching_ok': {
                    'type': 'int',
                    },
                'host_switching_ok': {
                    'type': 'int',
                    },
                'lb_switching_ok': {
                    'type': 'int',
                    },
                'l4_switching_enqueue': {
                    'type': 'int',
                    },
                'cookie_switching_enqueue': {
                    'type': 'int',
                    },
                'aflex_switching_enqueue': {
                    'type': 'int',
                    },
                'url_switching_enqueue': {
                    'type': 'int',
                    },
                'host_switching_enqueue': {
                    'type': 'int',
                    },
                'lb_switching_enqueue': {
                    'type': 'int',
                    },
                'non_http_bypass': {
                    'type': 'int',
                    },
                'client_rst_request': {
                    'type': 'int',
                    },
                'client_rst_connecting': {
                    'type': 'int',
                    },
                'client_rst_connected': {
                    'type': 'int',
                    },
                'client_rst_response': {
                    'type': 'int',
                    },
                'server_rst_request': {
                    'type': 'int',
                    },
                'server_rst_connecting': {
                    'type': 'int',
                    },
                'server_rst_connected': {
                    'type': 'int',
                    },
                'server_rst_response': {
                    'type': 'int',
                    },
                'client_req_unexp_flag': {
                    'type': 'int',
                    },
                'connecting_fin': {
                    'type': 'int',
                    },
                'connecting_fin_retrans': {
                    'type': 'int',
                    },
                'connecting_fin_ofo': {
                    'type': 'int',
                    },
                'connecting_rst': {
                    'type': 'int',
                    },
                'connecting_rst_retrans': {
                    'type': 'int',
                    },
                'connecting_rst_ofo': {
                    'type': 'int',
                    },
                'connecting_ack': {
                    'type': 'int',
                    },
                'pkts_ofo': {
                    'type': 'int',
                    },
                'pkts_retrans': {
                    'type': 'int',
                    },
                'stale_sess': {
                    'type': 'int',
                    },
                'server_resel_failed': {
                    'type': 'int',
                    },
                'large_cookie': {
                    'type': 'int',
                    },
                'large_cookie_header': {
                    'type': 'int',
                    },
                'huge_cookie': {
                    'type': 'int',
                    },
                'huge_cookie_header': {
                    'type': 'int',
                    },
                'parse_cookie_fail': {
                    'type': 'int',
                    },
                'parse_setcookie_fail': {
                    'type': 'int',
                    },
                'asm_cookie_fail': {
                    'type': 'int',
                    },
                'asm_cookie_header_fail': {
                    'type': 'int',
                    },
                'asm_setcookie_fail': {
                    'type': 'int',
                    },
                'asm_setcookie_header_fail': {
                    'type': 'int',
                    },
                'invalid_header': {
                    'type': 'int',
                    },
                'too_many_headers': {
                    'type': 'int',
                    },
                'line_too_long': {
                    'type': 'int',
                    },
                'header_name_too_long': {
                    'type': 'int',
                    },
                'wrong_resp_header': {
                    'type': 'int',
                    },
                'header_insert': {
                    'type': 'int',
                    },
                'header_delete': {
                    'type': 'int',
                    },
                'insert_client_ip': {
                    'type': 'int',
                    },
                'insert_client_port': {
                    'type': 'int',
                    },
                'skip_insert_client_ip': {
                    'type': 'int',
                    },
                'skip_insert_client_port': {
                    'type': 'int',
                    },
                'negative_req_remain': {
                    'type': 'int',
                    },
                'negative_resp_remain': {
                    'type': 'int',
                    },
                'retry_503': {
                    'type': 'int',
                    },
                'aflex_retry': {
                    'type': 'int',
                    },
                'aflex_lb_reselect': {
                    'type': 'int',
                    },
                'aflex_lb_reselect_ok': {
                    'type': 'int',
                    },
                'req_http10': {
                    'type': 'int',
                    },
                'req_http11': {
                    'type': 'int',
                    },
                'req_http2': {
                    'type': 'int',
                    },
                'response_http2': {
                    'type': 'int',
                    },
                'req_get': {
                    'type': 'int',
                    },
                'req_head': {
                    'type': 'int',
                    },
                'req_put': {
                    'type': 'int',
                    },
                'req_post': {
                    'type': 'int',
                    },
                'req_trace': {
                    'type': 'int',
                    },
                'req_track': {
                    'type': 'int',
                    },
                'req_options': {
                    'type': 'int',
                    },
                'req_connect': {
                    'type': 'int',
                    },
                'req_delete': {
                    'type': 'int',
                    },
                'req_unknown': {
                    'type': 'int',
                    },
                'response_http10': {
                    'type': 'int',
                    },
                'response_http11': {
                    'type': 'int',
                    },
                'response_1xx': {
                    'type': 'int',
                    },
                'response_100': {
                    'type': 'int',
                    },
                'response_101': {
                    'type': 'int',
                    },
                'response_102': {
                    'type': 'int',
                    },
                'response_2xx': {
                    'type': 'int',
                    },
                'response_200': {
                    'type': 'int',
                    },
                'response_201': {
                    'type': 'int',
                    },
                'response_202': {
                    'type': 'int',
                    },
                'response_203': {
                    'type': 'int',
                    },
                'response_204': {
                    'type': 'int',
                    },
                'response_205': {
                    'type': 'int',
                    },
                'response_206': {
                    'type': 'int',
                    },
                'response_207': {
                    'type': 'int',
                    },
                'response_3xx': {
                    'type': 'int',
                    },
                'response_300': {
                    'type': 'int',
                    },
                'response_301': {
                    'type': 'int',
                    },
                'response_302': {
                    'type': 'int',
                    },
                'response_303': {
                    'type': 'int',
                    },
                'response_304': {
                    'type': 'int',
                    },
                'response_305': {
                    'type': 'int',
                    },
                'response_306': {
                    'type': 'int',
                    },
                'response_307': {
                    'type': 'int',
                    },
                'response_4xx': {
                    'type': 'int',
                    },
                'response_400': {
                    'type': 'int',
                    },
                'response_401': {
                    'type': 'int',
                    },
                'response_402': {
                    'type': 'int',
                    },
                'response_403': {
                    'type': 'int',
                    },
                'response_404': {
                    'type': 'int',
                    },
                'response_405': {
                    'type': 'int',
                    },
                'response_406': {
                    'type': 'int',
                    },
                'response_407': {
                    'type': 'int',
                    },
                'response_408': {
                    'type': 'int',
                    },
                'response_409': {
                    'type': 'int',
                    },
                'response_410': {
                    'type': 'int',
                    },
                'response_411': {
                    'type': 'int',
                    },
                'response_412': {
                    'type': 'int',
                    },
                'response_413': {
                    'type': 'int',
                    },
                'response_414': {
                    'type': 'int',
                    },
                'response_415': {
                    'type': 'int',
                    },
                'response_416': {
                    'type': 'int',
                    },
                'response_417': {
                    'type': 'int',
                    },
                'response_418': {
                    'type': 'int',
                    },
                'response_422': {
                    'type': 'int',
                    },
                'response_423': {
                    'type': 'int',
                    },
                'response_424': {
                    'type': 'int',
                    },
                'response_425': {
                    'type': 'int',
                    },
                'response_426': {
                    'type': 'int',
                    },
                'response_449': {
                    'type': 'int',
                    },
                'response_450': {
                    'type': 'int',
                    },
                'response_5xx': {
                    'type': 'int',
                    },
                'response_500': {
                    'type': 'int',
                    },
                'response_501': {
                    'type': 'int',
                    },
                'response_502': {
                    'type': 'int',
                    },
                'response_503': {
                    'type': 'int',
                    },
                'response_504': {
                    'type': 'int',
                    },
                'response_504_ax': {
                    'type': 'int',
                    },
                'response_505': {
                    'type': 'int',
                    },
                'response_506': {
                    'type': 'int',
                    },
                'response_507': {
                    'type': 'int',
                    },
                'response_508': {
                    'type': 'int',
                    },
                'response_509': {
                    'type': 'int',
                    },
                'response_510': {
                    'type': 'int',
                    },
                'response_6xx': {
                    'type': 'int',
                    },
                'response_unknown': {
                    'type': 'int',
                    },
                'req_10u': {
                    'type': 'int',
                    },
                'req_20u': {
                    'type': 'int',
                    },
                'req_50u': {
                    'type': 'int',
                    },
                'req_100u': {
                    'type': 'int',
                    },
                'req_200u': {
                    'type': 'int',
                    },
                'req_500u': {
                    'type': 'int',
                    },
                'req_1m': {
                    'type': 'int',
                    },
                'req_2m': {
                    'type': 'int',
                    },
                'req_5m': {
                    'type': 'int',
                    },
                'req_10m': {
                    'type': 'int',
                    },
                'req_20m': {
                    'type': 'int',
                    },
                'req_50m': {
                    'type': 'int',
                    },
                'req_100m': {
                    'type': 'int',
                    },
                'req_200m': {
                    'type': 'int',
                    },
                'req_500m': {
                    'type': 'int',
                    },
                'req_1s': {
                    'type': 'int',
                    },
                'req_2s': {
                    'type': 'int',
                    },
                'req_5s': {
                    'type': 'int',
                    },
                'req_over_5s': {
                    'type': 'int',
                    },
                'req_sz_1k': {
                    'type': 'int',
                    },
                'req_sz_2k': {
                    'type': 'int',
                    },
                'req_sz_4k': {
                    'type': 'int',
                    },
                'req_sz_8k': {
                    'type': 'int',
                    },
                'req_sz_16k': {
                    'type': 'int',
                    },
                'req_sz_32k': {
                    'type': 'int',
                    },
                'req_sz_64k': {
                    'type': 'int',
                    },
                'req_sz_256k': {
                    'type': 'int',
                    },
                'req_sz_gt_256k': {
                    'type': 'int',
                    },
                'rsp_sz_1k': {
                    'type': 'int',
                    },
                'rsp_sz_2k': {
                    'type': 'int',
                    },
                'rsp_sz_4k': {
                    'type': 'int',
                    },
                'rsp_sz_8k': {
                    'type': 'int',
                    },
                'rsp_sz_16k': {
                    'type': 'int',
                    },
                'rsp_sz_32k': {
                    'type': 'int',
                    },
                'rsp_sz_64k': {
                    'type': 'int',
                    },
                'rsp_sz_256k': {
                    'type': 'int',
                    },
                'rsp_sz_gt_256k': {
                    'type': 'int',
                    },
                'chunk_sz_512': {
                    'type': 'int',
                    },
                'chunk_sz_1k': {
                    'type': 'int',
                    },
                'chunk_sz_2k': {
                    'type': 'int',
                    },
                'chunk_sz_4k': {
                    'type': 'int',
                    },
                'chunk_sz_gt_4k': {
                    'type': 'int',
                    },
                'pkts_retrans_ack_finwait': {
                    'type': 'int',
                    },
                'pkts_retrans_fin': {
                    'type': 'int',
                    },
                'pkts_retrans_rst': {
                    'type': 'int',
                    },
                'pkts_retrans_push': {
                    'type': 'int',
                    },
                'pconn_connecting': {
                    'type': 'int',
                    },
                'pconn_connected': {
                    'type': 'int',
                    },
                'pconn_connecting_failed': {
                    'type': 'int',
                    },
                'compress_rsp': {
                    'type': 'int',
                    },
                'compress_del_accept_enc': {
                    'type': 'int',
                    },
                'compress_resp_already_compressed': {
                    'type': 'int',
                    },
                'compress_content_type_excluded': {
                    'type': 'int',
                    },
                'compress_no_content_type': {
                    'type': 'int',
                    },
                'compress_resp_lt_min': {
                    'type': 'int',
                    },
                'compress_resp_no_cl_or_ce': {
                    'type': 'int',
                    },
                'compress_ratio_too_high': {
                    'type': 'int',
                    },
                'rsp_content_len': {
                    'type': 'int',
                    },
                'req_content_len': {
                    'type': 'int',
                    },
                'rsp_chunk': {
                    'type': 'int',
                    },
                'req_http10_keepalive': {
                    'type': 'int',
                    },
                'chunk_bad': {
                    'type': 'int',
                    },
                'ws_handshake_req': {
                    'type': 'int',
                    },
                'ws_handshake_resp': {
                    'type': 'int',
                    },
                'ws_client_packets': {
                    'type': 'int',
                    },
                'ws_server_packets': {
                    'type': 'int',
                    },
                'req_timeout_retry': {
                    'type': 'int',
                    },
                'req_timeout_close': {
                    'type': 'int',
                    },
                'doh_req': {
                    'type': 'int',
                    },
                'doh_req_get': {
                    'type': 'int',
                    },
                'doh_req_post': {
                    'type': 'int',
                    },
                'doh_non_doh_req': {
                    'type': 'int',
                    },
                'doh_non_doh_req_get': {
                    'type': 'int',
                    },
                'doh_non_doh_req_post': {
                    'type': 'int',
                    },
                'doh_resp': {
                    'type': 'int',
                    },
                'doh_tc_resp': {
                    'type': 'int',
                    },
                'doh_udp_dns_req': {
                    'type': 'int',
                    },
                'doh_udp_dns_resp': {
                    'type': 'int',
                    },
                'doh_tcp_dns_req': {
                    'type': 'int',
                    },
                'doh_tcp_dns_resp': {
                    'type': 'int',
                    },
                'doh_req_send_failed': {
                    'type': 'int',
                    },
                'doh_resp_send_failed': {
                    'type': 'int',
                    },
                'doh_malloc_fail': {
                    'type': 'int',
                    },
                'doh_req_udp_retry': {
                    'type': 'int',
                    },
                'doh_req_udp_retry_fail': {
                    'type': 'int',
                    },
                'doh_req_tcp_retry': {
                    'type': 'int',
                    },
                'doh_req_tcp_retry_fail': {
                    'type': 'int',
                    },
                'doh_snat_failed': {
                    'type': 'int',
                    },
                'doh_path_not_found': {
                    'type': 'int',
                    },
                'doh_get_dns_arg_failed': {
                    'type': 'int',
                    },
                'doh_get_base64_decode_failed': {
                    'type': 'int',
                    },
                'doh_post_content_type_mismatch': {
                    'type': 'int',
                    },
                'doh_post_payload_not_found': {
                    'type': 'int',
                    },
                'doh_post_payload_extract_failed': {
                    'type': 'int',
                    },
                'doh_non_doh_method': {
                    'type': 'int',
                    },
                'doh_tcp_send_failed': {
                    'type': 'int',
                    },
                'doh_udp_send_failed': {
                    'type': 'int',
                    },
                'doh_query_time_out': {
                    'type': 'int',
                    },
                'doh_dns_query_type_a': {
                    'type': 'int',
                    },
                'doh_dns_query_type_aaaa': {
                    'type': 'int',
                    },
                'doh_dns_query_type_ns': {
                    'type': 'int',
                    },
                'doh_dns_query_type_cname': {
                    'type': 'int',
                    },
                'doh_dns_query_type_any': {
                    'type': 'int',
                    },
                'doh_dns_query_type_srv': {
                    'type': 'int',
                    },
                'doh_dns_query_type_mx': {
                    'type': 'int',
                    },
                'doh_dns_query_type_soa': {
                    'type': 'int',
                    },
                'doh_dns_query_type_others': {
                    'type': 'int',
                    },
                'doh_resp_setup_failed': {
                    'type': 'int',
                    },
                'doh_resp_header_alloc_failed': {
                    'type': 'int',
                    },
                'doh_resp_que_failed': {
                    'type': 'int',
                    },
                'doh_resp_udp_frags': {
                    'type': 'int',
                    },
                'doh_resp_tcp_frags': {
                    'type': 'int',
                    },
                'doh_serv_sel_failed': {
                    'type': 'int',
                    },
                'doh_retry_w_tcp': {
                    'type': 'int',
                    },
                'doh_get_uri_too_long': {
                    'type': 'int',
                    },
                'doh_post_payload_too_large': {
                    'type': 'int',
                    },
                'doh_dns_malformed_query': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_err_format': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_err_server': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_err_name': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_err_type': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_refuse': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_yxdomain': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_yxrrset': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_nxrrset': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_notauth': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_notzone': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_other': {
                    'type': 'int',
                    },
                'compression_before_br': {
                    'type': 'int',
                    },
                'compression_after_br': {
                    'type': 'int',
                    },
                'compression_before_total': {
                    'type': 'int',
                    },
                'compression_after_total': {
                    'type': 'int',
                    },
                'decompression_before_br': {
                    'type': 'int',
                    },
                'decompression_after_br': {
                    'type': 'int',
                    },
                'decompression_before_total': {
                    'type': 'int',
                    },
                'decompression_after_total': {
                    'type': 'int',
                    },
                'compress_rsp_br': {
                    'type': 'int',
                    },
                'compress_rsp_total': {
                    'type': 'int',
                    },
                'h2up_content_length_alias': {
                    'type': 'int',
                    },
                'malformed_h2up_header_value': {
                    'type': 'int',
                    },
                'malformed_h2up_scheme_value': {
                    'type': 'int',
                    },
                'h2up_with_transfer_encoding': {
                    'type': 'int',
                    },
                'multiple_content_length': {
                    'type': 'int',
                    },
                'multiple_transfer_encoding': {
                    'type': 'int',
                    },
                'transfer_encoding_and_content_length': {
                    'type': 'int',
                    },
                'get_and_payload': {
                    'type': 'int',
                    },
                'h2up_with_host_and_auth': {
                    'type': 'int',
                    },
                'header_filter_rule_hit': {
                    'type': 'int',
                    },
                'http1_client_idle_timeout': {
                    'type': 'int',
                    },
                'http2_client_idle_timeout': {
                    'type': 'int',
                    },
                'http_disallowed_methods': {
                    'type': 'int',
                    },
                'http_allowed_methods': {
                    'type': 'int',
                    },
                'req_http11_new_proxy': {
                    'type': 'int',
                    }
                },
            'cpu_count': {
                'type': 'int',
                },
            'debug_fields': {
                'type': 'bool',
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
            'req': {
                'type': 'str',
                },
            'req_succ': {
                'type': 'str',
                },
            'noproxy': {
                'type': 'str',
                },
            'client_rst': {
                'type': 'str',
                },
            'server_rst': {
                'type': 'str',
                },
            'notuple': {
                'type': 'str',
                },
            'parsereq_fail': {
                'type': 'str',
                },
            'svrsel_fail': {
                'type': 'str',
                },
            'fwdreq_fail': {
                'type': 'str',
                },
            'fwdreqdata_fail': {
                'type': 'str',
                },
            'req_retran': {
                'type': 'str',
                },
            'req_ofo': {
                'type': 'str',
                },
            'server_resel': {
                'type': 'str',
                },
            'svr_prem_close': {
                'type': 'str',
                },
            'new_svrconn': {
                'type': 'str',
                },
            'snat_fail': {
                'type': 'str',
                },
            'req_over_limit': {
                'type': 'str',
                },
            'req_rate_over_limit': {
                'type': 'str',
                },
            'compression_before': {
                'type': 'str',
                },
            'compression_after': {
                'type': 'str',
                },
            'response_1xx': {
                'type': 'str',
                },
            'response_100': {
                'type': 'str',
                },
            'response_101': {
                'type': 'str',
                },
            'response_102': {
                'type': 'str',
                },
            'response_2xx': {
                'type': 'str',
                },
            'response_200': {
                'type': 'str',
                },
            'response_201': {
                'type': 'str',
                },
            'response_202': {
                'type': 'str',
                },
            'response_203': {
                'type': 'str',
                },
            'response_204': {
                'type': 'str',
                },
            'response_205': {
                'type': 'str',
                },
            'response_206': {
                'type': 'str',
                },
            'response_207': {
                'type': 'str',
                },
            'response_3xx': {
                'type': 'str',
                },
            'response_300': {
                'type': 'str',
                },
            'response_301': {
                'type': 'str',
                },
            'response_302': {
                'type': 'str',
                },
            'response_303': {
                'type': 'str',
                },
            'response_304': {
                'type': 'str',
                },
            'response_305': {
                'type': 'str',
                },
            'response_306': {
                'type': 'str',
                },
            'response_307': {
                'type': 'str',
                },
            'response_4xx': {
                'type': 'str',
                },
            'response_400': {
                'type': 'str',
                },
            'response_401': {
                'type': 'str',
                },
            'response_402': {
                'type': 'str',
                },
            'response_403': {
                'type': 'str',
                },
            'response_404': {
                'type': 'str',
                },
            'response_405': {
                'type': 'str',
                },
            'response_406': {
                'type': 'str',
                },
            'response_407': {
                'type': 'str',
                },
            'response_408': {
                'type': 'str',
                },
            'response_409': {
                'type': 'str',
                },
            'response_410': {
                'type': 'str',
                },
            'response_411': {
                'type': 'str',
                },
            'response_412': {
                'type': 'str',
                },
            'response_413': {
                'type': 'str',
                },
            'response_414': {
                'type': 'str',
                },
            'response_415': {
                'type': 'str',
                },
            'response_416': {
                'type': 'str',
                },
            'response_417': {
                'type': 'str',
                },
            'response_418': {
                'type': 'str',
                },
            'response_422': {
                'type': 'str',
                },
            'response_423': {
                'type': 'str',
                },
            'response_424': {
                'type': 'str',
                },
            'response_425': {
                'type': 'str',
                },
            'response_426': {
                'type': 'str',
                },
            'response_449': {
                'type': 'str',
                },
            'response_450': {
                'type': 'str',
                },
            'response_5xx': {
                'type': 'str',
                },
            'response_500': {
                'type': 'str',
                },
            'response_501': {
                'type': 'str',
                },
            'response_502': {
                'type': 'str',
                },
            'response_503': {
                'type': 'str',
                },
            'response_504': {
                'type': 'str',
                },
            'response_505': {
                'type': 'str',
                },
            'response_506': {
                'type': 'str',
                },
            'response_507': {
                'type': 'str',
                },
            'response_508': {
                'type': 'str',
                },
            'response_509': {
                'type': 'str',
                },
            'response_510': {
                'type': 'str',
                },
            'response_6xx': {
                'type': 'str',
                },
            'response_unknown': {
                'type': 'str',
                },
            'req_get': {
                'type': 'str',
                },
            'req_head': {
                'type': 'str',
                },
            'req_put': {
                'type': 'str',
                },
            'req_post': {
                'type': 'str',
                },
            'req_trace': {
                'type': 'str',
                },
            'req_options': {
                'type': 'str',
                },
            'req_connect': {
                'type': 'str',
                },
            'req_delete': {
                'type': 'str',
                },
            'req_unknown': {
                'type': 'str',
                },
            'req_content_len': {
                'type': 'str',
                },
            'rsp_content_len': {
                'type': 'str',
                },
            'rsp_chunk': {
                'type': 'str',
                },
            'cache_rsp': {
                'type': 'str',
                },
            'close_on_ddos': {
                'type': 'str',
                },
            'req_sz_1k': {
                'type': 'str',
                },
            'req_sz_2k': {
                'type': 'str',
                },
            'req_sz_4k': {
                'type': 'str',
                },
            'req_sz_8k': {
                'type': 'str',
                },
            'req_sz_16k': {
                'type': 'str',
                },
            'req_sz_32k': {
                'type': 'str',
                },
            'req_sz_64k': {
                'type': 'str',
                },
            'req_sz_256k': {
                'type': 'str',
                },
            'req_sz_gt_256k': {
                'type': 'str',
                },
            'rsp_sz_1k': {
                'type': 'str',
                },
            'rsp_sz_2k': {
                'type': 'str',
                },
            'rsp_sz_4k': {
                'type': 'str',
                },
            'rsp_sz_8k': {
                'type': 'str',
                },
            'rsp_sz_16k': {
                'type': 'str',
                },
            'rsp_sz_32k': {
                'type': 'str',
                },
            'rsp_sz_64k': {
                'type': 'str',
                },
            'rsp_sz_256k': {
                'type': 'str',
                },
            'rsp_sz_gt_256k': {
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
            'req_10u': {
                'type': 'str',
                },
            'req_20u': {
                'type': 'str',
                },
            'req_50u': {
                'type': 'str',
                },
            'req_100u': {
                'type': 'str',
                },
            'req_200u': {
                'type': 'str',
                },
            'req_500u': {
                'type': 'str',
                },
            'req_1m': {
                'type': 'str',
                },
            'req_2m': {
                'type': 'str',
                },
            'req_5m': {
                'type': 'str',
                },
            'req_10m': {
                'type': 'str',
                },
            'req_20m': {
                'type': 'str',
                },
            'req_50m': {
                'type': 'str',
                },
            'req_100m': {
                'type': 'str',
                },
            'req_200m': {
                'type': 'str',
                },
            'req_500m': {
                'type': 'str',
                },
            'req_1s': {
                'type': 'str',
                },
            'req_2s': {
                'type': 'str',
                },
            'req_5s': {
                'type': 'str',
                },
            'req_over_5s': {
                'type': 'str',
                },
            'req_track': {
                'type': 'str',
                },
            'connect_req': {
                'type': 'str',
                },
            'req_enter_ssli': {
                'type': 'str',
                },
            'decompression_before': {
                'type': 'str',
                },
            'decompression_after': {
                'type': 'str',
                },
            'req_http2': {
                'type': 'str',
                },
            'response_http2': {
                'type': 'str',
                },
            'doh_req': {
                'type': 'str',
                },
            'doh_req_get': {
                'type': 'str',
                },
            'doh_req_post': {
                'type': 'str',
                },
            'doh_non_doh_req': {
                'type': 'str',
                },
            'doh_non_doh_req_get': {
                'type': 'str',
                },
            'doh_non_doh_req_post': {
                'type': 'str',
                },
            'doh_resp': {
                'type': 'str',
                },
            'doh_tc_resp': {
                'type': 'str',
                },
            'doh_udp_dns_req': {
                'type': 'str',
                },
            'doh_udp_dns_resp': {
                'type': 'str',
                },
            'doh_tcp_dns_req': {
                'type': 'str',
                },
            'doh_tcp_dns_resp': {
                'type': 'str',
                },
            'doh_req_send_failed': {
                'type': 'str',
                },
            'doh_resp_send_failed': {
                'type': 'str',
                },
            'doh_malloc_fail': {
                'type': 'str',
                },
            'doh_req_udp_retry': {
                'type': 'str',
                },
            'doh_req_udp_retry_fail': {
                'type': 'str',
                },
            'doh_req_tcp_retry': {
                'type': 'str',
                },
            'doh_req_tcp_retry_fail': {
                'type': 'str',
                },
            'doh_snat_failed': {
                'type': 'str',
                },
            'doh_path_not_found': {
                'type': 'str',
                },
            'doh_get_dns_arg_failed': {
                'type': 'str',
                },
            'doh_get_base64_decode_failed': {
                'type': 'str',
                },
            'doh_post_content_type_mismatch': {
                'type': 'str',
                },
            'doh_post_payload_not_found': {
                'type': 'str',
                },
            'doh_post_payload_extract_failed': {
                'type': 'str',
                },
            'doh_non_doh_method': {
                'type': 'str',
                },
            'doh_tcp_send_failed': {
                'type': 'str',
                },
            'doh_udp_send_failed': {
                'type': 'str',
                },
            'doh_query_time_out': {
                'type': 'str',
                },
            'doh_dns_query_type_a': {
                'type': 'str',
                },
            'doh_dns_query_type_aaaa': {
                'type': 'str',
                },
            'doh_dns_query_type_ns': {
                'type': 'str',
                },
            'doh_dns_query_type_cname': {
                'type': 'str',
                },
            'doh_dns_query_type_any': {
                'type': 'str',
                },
            'doh_dns_query_type_srv': {
                'type': 'str',
                },
            'doh_dns_query_type_mx': {
                'type': 'str',
                },
            'doh_dns_query_type_soa': {
                'type': 'str',
                },
            'doh_dns_query_type_others': {
                'type': 'str',
                },
            'doh_resp_setup_failed': {
                'type': 'str',
                },
            'doh_resp_header_alloc_failed': {
                'type': 'str',
                },
            'doh_resp_que_failed': {
                'type': 'str',
                },
            'doh_resp_udp_frags': {
                'type': 'str',
                },
            'doh_resp_tcp_frags': {
                'type': 'str',
                },
            'doh_serv_sel_failed': {
                'type': 'str',
                },
            'doh_retry_w_tcp': {
                'type': 'str',
                },
            'doh_get_uri_too_long': {
                'type': 'str',
                },
            'doh_post_payload_too_large': {
                'type': 'str',
                },
            'doh_dns_malformed_query': {
                'type': 'str',
                },
            'doh_dns_resp_rcode_err_format': {
                'type': 'str',
                },
            'doh_dns_resp_rcode_err_server': {
                'type': 'str',
                },
            'doh_dns_resp_rcode_err_name': {
                'type': 'str',
                },
            'doh_dns_resp_rcode_err_type': {
                'type': 'str',
                },
            'doh_dns_resp_rcode_refuse': {
                'type': 'str',
                },
            'doh_dns_resp_rcode_yxdomain': {
                'type': 'str',
                },
            'doh_dns_resp_rcode_yxrrset': {
                'type': 'str',
                },
            'doh_dns_resp_rcode_nxrrset': {
                'type': 'str',
                },
            'doh_dns_resp_rcode_notauth': {
                'type': 'str',
                },
            'doh_dns_resp_rcode_notzone': {
                'type': 'str',
                },
            'doh_dns_resp_rcode_other': {
                'type': 'str',
                },
            'compression_before_br': {
                'type': 'str',
                },
            'compression_after_br': {
                'type': 'str',
                },
            'compression_before_total': {
                'type': 'str',
                },
            'compression_after_total': {
                'type': 'str',
                },
            'decompression_before_br': {
                'type': 'str',
                },
            'decompression_after_br': {
                'type': 'str',
                },
            'decompression_before_total': {
                'type': 'str',
                },
            'decompression_after_total': {
                'type': 'str',
                },
            'req_http3': {
                'type': 'str',
                },
            'response_http3': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/http-proxy"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/http-proxy"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["http-proxy"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["http-proxy"].get(k) != v:
            change_results["changed"] = True
            config_changes["http-proxy"][k] = v

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
    payload = utils.build_json("http-proxy", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["http-proxy"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["http-proxy-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["http-proxy"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["http-proxy"]["stats"] if info != "NotFound" else info
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
