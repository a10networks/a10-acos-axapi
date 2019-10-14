#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
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
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'reqmod_request'= Reqmod Request Stats; 'respmod_request'= Respmod Request Stats; 'reqmod_request_after_100'= Reqmod Request Sent After 100 Cont Stats; 'respmod_request_after_100'= Respmod Request Sent After 100 Cont Stats; 'reqmod_response'= Reqmod Response Stats; 'respmod_response'= Respmod Response Stats; 'reqmod_response_after_100'= Reqmod Response After 100 Cont Stats; 'respmod_response_after_100'= Respmod Response After 100 Cont Stats; 'chunk_no_allow_204'= Chunk so no Allow 204 Stats; 'len_exceed_no_allow_204'= Length Exceeded so no Allow 204 Stats; 'result_continue'= Result Continue Stats; 'result_icap_response'= Result ICAP Response Stats; 'result_100_continue'= Result 100 Continue Stats; 'result_other'= Result Other Stats; 'status_2xx'= Status 2xx Stats; 'status_200'= Status 200 Stats; 'status_201'= Status 201 Stats; 'status_202'= Status 202 Stats; 'status_203'= Status 203 Stats; 'status_204'= Status 204 Stats; 'status_205'= Status 205 Stats; 'status_206'= Status 206 Stats; 'status_207'= Status 207 Stats; 'status_1xx'= Status 1xx Stats; 'status_100'= Status 100 Stats; 'status_101'= Status 101 Stats; 'status_102'= Status 102 Stats; 'status_3xx'= Status 3xx Stats; 'status_300'= Status 300 Stats; 'status_301'= Status 301 Stats; 'status_302'= Status 302 Stats; 'status_303'= Status 303 Stats; 'status_304'= Status 304 Stats; 'status_305'= Status 305 Stats; 'status_306'= Status 306 Stats; 'status_307'= Status 307 Stats; 'status_4xx'= Status 4xx Stats; 'status_400'= Status 400 Stats; 'status_401'= Status 401 Stats; 'status_402'= Status 402 Stats; 'status_403'= Status 403 Stats; 'status_404'= Status 404 Stats; 'status_405'= Status 405 Stats; 'status_406'= Status 406 Stats; 'status_407'= Status 407 Stats; 'status_408'= Status 408 Stats; 'status_409'= Status 409 Stats; 'status_410'= Status 410 Stats; 'status_411'= Status 411 Stats; 'status_412'= Status 412 Stats; 'status_413'= Status 413 Stats; 'status_414'= Status 414 Stats; 'status_415'= Status 415 Stats; 'status_416'= Status 416 Stats; 'status_417'= Status 417 Stats; 'status_418'= Status 418 Stats; 'status_419'= Status 419 Stats; 'status_420'= Status 420 Stats; 'status_422'= Status 422 Stats; 'status_423'= Status 423 Stats; 'status_424'= Status 424 Stats; 'status_425'= Status 425 Stats; 'status_426'= Status 426 Stats; 'status_449'= Status 449 Stats; 'status_450'= Status 450 Stats; 'status_5xx'= Status 5xx Stats; 'status_500'= Status 500 Stats; 'status_501'= Status 501 Stats; 'status_502'= Status 502 Stats; 'status_503'= Status 503 Stats; 'status_504'= Status 504 Stats; 'status_505'= Status 505 Stats; 'status_506'= Status 506 Stats; 'status_507'= Status 507 Stats; 'status_508'= Status 508 Stats; 'status_509'= Status 509 Stats; 'status_510'= Status 510 Stats; 'status_6xx'= Status 6xx Stats; 'status_unknown'= Status Unknown Stats; 'send_option_req'= Send Option Req Stats; 'app_serv_conn_no_pcb_err'= App Server Conn no ES PCB Err Stats; 'app_serv_conn_err'= App Server Conn Err Stats; 'chunk1_hdr_err'= Chunk Hdr Err1 Stats; 'chunk2_hdr_err'= Chunk Hdr Err2 Stats; 'chunk_bad_trail_err'= Chunk Bad Trail Err Stats; 'no_payload_next_buff_err'= No Payload In Next Buff Err Stats; 'no_payload_buff_err'= No Payload Buff Err Stats; 'resp_hdr_incomplete_err'= Resp Hdr Incomplete Err Stats; 'serv_sel_fail_err'= Server Select Fail Err Stats; 'start_icap_conn_fail_err'= Start ICAP conn fail Stats; 'prep_req_fail_err'= Prepare ICAP req fail Err Stats; 'icap_ver_err'= ICAP Ver Err Stats; 'icap_line_err'= ICAP Line Err Stats; 'encap_hdr_incomplete_err'= Encap HDR Incomplete Err Stats; 'no_icap_resp_err'= No ICAP Resp Err Stats; 'resp_line_read_err'= Resp Line Read Err Stats; 'resp_line_parse_err'= Resp Line Parse Err Stats; 'resp_hdr_err'= Resp Hdr Err Stats; 'req_hdr_incomplete_err'= Req Hdr Incomplete Err Stats; 'no_status_code_err'= No Status Code Err Stats; 'http_resp_line_read_err'= HTTP Response Line Read Err Stats; 'http_resp_line_parse_err'= HTTP Response Line Parse Err Stats; 'http_resp_hdr_err'= HTTP Resp Hdr Err Stats; 'recv_option_resp'= Send Option Req Stats; "
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
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','reqmod_request','respmod_request','reqmod_request_after_100','respmod_request_after_100','reqmod_response','respmod_response','reqmod_response_after_100','respmod_response_after_100','chunk_no_allow_204','len_exceed_no_allow_204','result_continue','result_icap_response','result_100_continue','result_other','status_2xx','status_200','status_201','status_202','status_203','status_204','status_205','status_206','status_207','status_1xx','status_100','status_101','status_102','status_3xx','status_300','status_301','status_302','status_303','status_304','status_305','status_306','status_307','status_4xx','status_400','status_401','status_402','status_403','status_404','status_405','status_406','status_407','status_408','status_409','status_410','status_411','status_412','status_413','status_414','status_415','status_416','status_417','status_418','status_419','status_420','status_422','status_423','status_424','status_425','status_426','status_449','status_450','status_5xx','status_500','status_501','status_502','status_503','status_504','status_505','status_506','status_507','status_508','status_509','status_510','status_6xx','status_unknown','send_option_req','app_serv_conn_no_pcb_err','app_serv_conn_err','chunk1_hdr_err','chunk2_hdr_err','chunk_bad_trail_err','no_payload_next_buff_err','no_payload_buff_err','resp_hdr_incomplete_err','serv_sel_fail_err','start_icap_conn_fail_err','prep_req_fail_err','icap_ver_err','icap_line_err','encap_hdr_incomplete_err','no_icap_resp_err','resp_line_read_err','resp_line_parse_err','resp_hdr_err','req_hdr_incomplete_err','no_status_code_err','http_resp_line_read_err','http_resp_line_parse_err','http_resp_hdr_err','recv_option_resp'])),
        uuid=dict(type='str',)
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

def get_oper(module):
    return module.client.get(oper_url(module))

def get_stats(module):
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["icap"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
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
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    if module.check_mode:
        result["changed"] = True
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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