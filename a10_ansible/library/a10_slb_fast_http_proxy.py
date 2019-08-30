#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_fast_http_proxy
description:
    - Show Fast-HTTP Proxy Statistics
short_description: Configures A10 slb.fast-http-proxy
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
    a10_protocol:
        description:
        - HTTP / HTTPS Protocol for AXAPI authentication
        required: True
    a10_port:
        description:
        - Port number AXAPI is running on
        required: True
    partition:
        description:
        - Destination/target partition for object/command
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
    uuid:
        description:
        - "uuid of the object"
        required: False

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["sampling_enable","uuid",]

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
        partition=dict(type='str', required=False),
        get_type=dict(type='str', choices=["single", "list"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','num','curr_proxy','total_proxy','req','req_succ','noproxy','client_rst','server_rst','notuple','parsereq_fail','svrsel_fail','fwdreq_fail','fwdreq_fail_buff','fwdreq_fail_rport','fwdreq_fail_route','fwdreq_fail_persist','fwdreq_fail_server','fwdreq_fail_tuple','fwdreqdata_fail','req_retran','req_ofo','server_resel','svr_prem_close','new_svrconn','snat_fail','tcpoutrst','full_proxy','full_proxy_post','full_proxy_pipeline','full_proxy_fpga_err','req_over_limit','req_rate_over_limit','l4_switching','cookie_switching','aflex_switching','http_policy_switching','url_switching','host_switching','lb_switching','l4_switching_ok','cookie_switching_ok','aflex_switching_ok','http_policy_switching_ok','url_switching_ok','host_switching_ok','lb_switching_ok','l4_switching_enqueue','cookie_switching_enqueue','aflex_switching_enqueue','http_policy_switching_enqueue','url_switching_enqueue','host_switching_enqueue','lb_switching_enqueue','retry_503','aflex_retry','aflex_lb_reselect','aflex_lb_reselect_ok','client_rst_request','client_rst_connecting','client_rst_connected','client_rst_response','server_rst_request','server_rst_connecting','server_rst_connected','server_rst_response','invalid_header','too_many_headers','line_too_long','header_name_too_long','wrong_resp_header','header_insert','header_delete','insert_client_ip','negative_req_remain','negative_resp_remain','large_cookie','large_cookie_header','huge_cookie','huge_cookie_header','parse_cookie_fail','parse_setcookie_fail','asm_cookie_fail','asm_cookie_header_fail','asm_setcookie_fail','asm_setcookie_header_fail','client_req_unexp_flag','connecting_fin','connecting_fin_retrans','connecting_fin_ofo','connecting_rst','connecting_rst_retrans','connecting_rst_ofo','connecting_ack','pkts_ofo','pkts_retrans','pkts_retrans_ack_finwait','pkts_retrans_fin','pkts_retrans_rst','pkts_retrans_push','stale_sess','server_resel_failed','compression_before','compression_after','response_1xx','response_100','response_101','response_102','response_2xx','response_200','response_201','response_202','response_203','response_204','response_205','response_206','response_207','response_3xx','response_300','response_301','response_302','response_303','response_304','response_305','response_306','response_307','response_4xx','response_400','response_401','response_402','response_403','response_404','response_405','response_406','response_407','response_408','response_409','response_410','response_411','response_412','response_413','response_414','response_415','response_416','response_417','response_418','response_422','response_423','response_424','response_425','response_426','response_449','response_450','response_5xx','response_500','response_501','response_502','response_503','response_504','response_505','response_506','response_507','response_508','response_509','response_510','response_6xx','response_unknown','req_http10','req_http11','response_http10','response_http11','req_get','req_head','req_put','req_post','req_trace','req_options','req_connect','req_delete','req_unknown','req_content_len','rsp_content_len','rsp_chunk','req_chunk','compress_rsp','compress_del_accept_enc','compress_resp_already_compressed','compress_content_type_excluded','compress_no_content_type','compress_resp_lt_min','compress_resp_no_cl_or_ce','compress_ratio_too_high','cache_rsp','close_on_ddos','req_http10_keepalive','req_sz_1k','req_sz_2k']),counters2=dict(type='str',choices=['req_sz_4k','req_sz_8k','req_sz_16k','req_sz_32k','req_sz_64k','req_sz_256k','req_sz_gt_256k','rsp_sz_1k','rsp_sz_2k','rsp_sz_4k','rsp_sz_8k','rsp_sz_16k','rsp_sz_32k','rsp_sz_64k','rsp_sz_256k','rsp_sz_gt_256k','chunk_sz_512','chunk_sz_1k','chunk_sz_2k','chunk_sz_4k','chunk_sz_gt_4k','pconn_connecting','pconn_connected','pconn_connecting_failed','chunk_bad','req_10u','req_20u','req_50u','req_100u','req_200u','req_500u','req_1m','req_2m','req_5m','req_10m','req_20m','req_50m','req_100m','req_200m','req_500m','req_1s','req_2s','req_5s','req_over_5s','insert_client_port','req_track','full_proxy_put','non_http_bypass','skip_insert_client_ip','skip_insert_client_port','decompression_before','decompression_after','http_pkts_in_seq','http_pkts_retx','http_client_retx','http_server_retx','http_pkts_ofo'])),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/fast-http-proxy"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/fast-http-proxy"

    f_dict = {}

    return url_base.format(**f_dict)

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
        if v:
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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("fast-http-proxy", module)
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.Exists:
        result["changed"] = False
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

def update(module, result, existing_config):
    payload = build_json("fast-http-proxy", module)
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
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result, existing_config)

def absent(module, result):
    return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("fast-http-proxy", module)
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
    
    partition = module.params["partition"]

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
    if partition:
        module.client.activate_partition(partition)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec())
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()