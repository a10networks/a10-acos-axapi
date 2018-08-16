#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_fast_http_proxy
description:
    - None
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "None"
            counters2:
                description:
                - "None"
    uuid:
        description:
        - "None"
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
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','num','curr_proxy','total_proxy','req','req_succ','noproxy','client_rst','server_rst','notuple','parsereq_fail','svrsel_fail','fwdreq_fail','fwdreq_fail_buff','fwdreq_fail_rport','fwdreq_fail_route','fwdreq_fail_persist','fwdreq_fail_server','fwdreq_fail_tuple','fwdreqdata_fail','req_retran','req_ofo','server_resel','svr_prem_close','new_svrconn','snat_fail','tcpoutrst','full_proxy','full_proxy_post','full_proxy_pipeline','full_proxy_fpga_err','req_over_limit','req_rate_over_limit','l4_switching','cookie_switching','aflex_switching','http_policy_switching','url_switching','host_switching','lb_switching','l4_switching_ok','cookie_switching_ok','aflex_switching_ok','http_policy_switching_ok','url_switching_ok','host_switching_ok','lb_switching_ok','l4_switching_enqueue','cookie_switching_enqueue','aflex_switching_enqueue','http_policy_switching_enqueue','url_switching_enqueue','host_switching_enqueue','lb_switching_enqueue','retry_503','aflex_retry','aflex_lb_reselect','aflex_lb_reselect_ok','client_rst_request','client_rst_connecting','client_rst_connected','client_rst_response','server_rst_request','server_rst_connecting','server_rst_connected','server_rst_response','invalid_header','too_many_headers','line_too_long','header_name_too_long','wrong_resp_header','header_insert','header_delete','insert_client_ip','negative_req_remain','negative_resp_remain','large_cookie','large_cookie_header','huge_cookie','huge_cookie_header','parse_cookie_fail','parse_setcookie_fail','asm_cookie_fail','asm_cookie_header_fail','asm_setcookie_fail','asm_setcookie_header_fail','client_req_unexp_flag','connecting_fin','connecting_fin_retrans','connecting_fin_ofo','connecting_rst','connecting_rst_retrans','connecting_rst_ofo','connecting_ack','pkts_ofo','pkts_retrans','pkts_retrans_ack_finwait','pkts_retrans_fin','pkts_retrans_rst','pkts_retrans_push','stale_sess','server_resel_failed','compression_before','compression_after','response_1xx','response_100','response_101','response_102','response_2xx','response_200','response_201','response_202','response_203','response_204','response_205','response_206','response_207','response_3xx','response_300','response_301','response_302','response_303','response_304','response_305','response_306','response_307','response_4xx','response_400','response_401','response_402','response_403','response_404','response_405','response_406','response_407','response_408','response_409','response_410','response_411','response_412','response_413','response_414','response_415','response_416','response_417','response_418','response_422','response_423','response_424','response_425','response_426','response_449','response_450','response_5xx','response_500','response_501','response_502','response_503','response_504','response_505','response_506','response_507','response_508','response_509','response_510','response_6xx','response_unknown','req_http10','req_http11','response_http10','response_http11','req_get','req_head','req_put','req_post','req_trace','req_options','req_connect','req_delete','req_unknown','req_content_len','rsp_content_len','rsp_chunk','req_chunk','compress_rsp','compress_del_accept_enc','compress_resp_already_compressed','compress_content_type_excluded','compress_no_content_type','compress_resp_lt_min','compress_resp_no_cl_or_ce','compress_ratio_too_high','cache_rsp','close_on_ddos','req_http10_keepalive','req_sz_1k','req_sz_2k']),counters2=dict(type='str',choices=['req_sz_4k','req_sz_8k','req_sz_16k','req_sz_32k','req_sz_64k','req_sz_256k','req_sz_gt_256k','rsp_sz_1k','rsp_sz_2k','rsp_sz_4k','rsp_sz_8k','rsp_sz_16k','rsp_sz_32k','rsp_sz_64k','rsp_sz_256k','rsp_sz_gt_256k','chunk_sz_512','chunk_sz_1k','chunk_sz_2k','chunk_sz_4k','chunk_sz_gt_4k','pconn_connecting','pconn_connected','pconn_connecting_failed','chunk_bad','req_10u','req_20u','req_50u','req_100u','req_200u','req_500u','req_1m','req_2m','req_5m','req_10m','req_20m','req_50m','req_100m','req_200m','req_500m','req_1s','req_2s','req_5s','req_over_5s','insert_client_port','req_track','full_proxy_put','non_http_bypass','skip_insert_client_ip','skip_insert_client_port','decompression_before','decompression_after'])),
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
        if isinstance(v, list):
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
            if isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if params.get(x)])
    
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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("fast-http-proxy", module)
    try:
        post_result = module.client.post(new_url(module), payload)
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
        post_result = module.client.put(existing_url(module), payload)
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

def run_command(module):
    run_errors = []

    result = dict(
        changed=False,
        original_message="",
        message=""
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    # TODO(remove hardcoded port #)
    a10_port = 443
    a10_protocol = "https"

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
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