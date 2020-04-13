#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_generic_proxy
description:
    - Configure Generic Proxy
short_description: Configures A10 slb.generic-proxy
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
    device_id:
        description:
        - Device ID for configuration
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
                - "'all'= all; 'num'= Number; 'curr'= Current; 'total'= Total; 'svrsel_fail'= Number of server selection failed; 'no_route'= Number of no routes; 'snat_fail'= Number of snat failures; 'client_fail'= Number of client failures; 'server_fail'= Number of server failures; 'no_sess'= Number of no sessions; 'user_session'= Number of user sessions; 'acr_out'= Number of ACRs out; 'acr_in'= Number of ACRs in; 'aca_out'= Number of ACAs out; 'aca_in'= Number of ACAs in; 'cea_out'= Number of CEAs out; 'cea_in'= Number of CEAs in; 'cer_out'= Number of CERs out; 'cer_in'= Number of CERs in; 'dwr_out'= Number of DWRs out; 'dwr_in'= Number of DWRs in; 'dwa_out'= Number of DWAs out; 'dwa_in'= Number of DWAs in; 'str_out'= Number of STRs out; 'str_in'= Number of STRs in; 'sta_out'= Number of STAs out; 'sta_in'= Number of STAs in; 'asr_out'= Number of ASRs out; 'asr_in'= Number of ASRs in; 'asa_out'= Number of ASAs out; 'asa_in'= Number of ASAs in; 'other_out'= Number of other messages out; 'other_in'= Number of other messages in; 'total_http_req_enter_gen'= Total number of HTTP requests enter generic proxy; 'mismatch_fwd_id'= Diameter mismatch fwd session id; 'mismatch_rev_id'= Diameter mismatch rev session id; 'unkwn_cmd_code'= Diameter unkown cmd code; 'no_session_id'= Diameter no session id avp; 'no_fwd_tuple'= Diameter no fwd tuple matched; 'no_rev_tuple'= Diameter no rev tuple matched; 'dcmsg_fwd_in'= Diameter cross cpu fwd in; 'dcmsg_fwd_out'= Diameter cross cpu fwd out; 'dcmsg_rev_in'= Diameter cross cpu rev in; 'dcmsg_rev_out'= Diameter cross cpu rev out; 'dcmsg_error'= Diameter cross cpu error; 'retry_client_request'= Diameter retry client request; 'retry_client_request_fail'= Diameter retry client request fail; 'reply_unknown_session_id'= Reply with unknown session ID error info; 'ccr_out'= Number of CCRs out; 'ccr_in'= Number of CCRs in; 'cca_out'= Number of CCAs out; 'cca_in'= Number of CCAs in; 'ccr_i'= Number of CCRs initial; 'ccr_u'= Number of CCRs update; 'ccr_t'= Number of CCRs terminate; 'cca_t'= Number of CCAs terminate; 'terminate_on_cca_t'= Diameter terminate on cca_t; 'forward_unknown_session_id'= Forward server side message with unknown session id; 'update_latest_server'= Update to the latest server that used a session id; 'client_select_fail'= Fail to select client; 'close_conn_when_vport_down'= Close client conn when virtual port is down; 'invalid_avp'= AVP value contains illegal chars; 'reselect_fwd_tuple'= Original client tuple does not exist so reselect another one; 'reselect_fwd_tuple_other_cpu'= Original client tuple does not exist so reselect another one on other CPUs; 'reselect_rev_tuple'= Original server tuple does not exist so reselect another one; 'conn_closed_by_client'= Client initiates TCP close/reset; 'conn_closed_by_server'= Server initiates TCP close/reset; 'reply_invalid_avp_value'= Reply with invalid AVP error info; 'reply_unable_to_deliver'= Reply with unable to deliver error info; 'reply_error_info_fail'= Fail to reply error info to peer; 'dpr_out'= Number of DPRs out; 'dpr_in'= Number of DPRs in; 'dpa_out'= Number of DPAs out; 'dpa_in'= Number of DPAs in; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            ccr_in:
                description:
                - "Number of CCRs in"
            forward_unknown_session_id:
                description:
                - "Forward server side message with unknown session id"
            svrsel_fail:
                description:
                - "Number of server selection failed"
            curr:
                description:
                - "Current"
            acr_out:
                description:
                - "Number of ACRs out"
            dwr_in:
                description:
                - "Number of DWRs in"
            client_fail:
                description:
                - "Number of client failures"
            num:
                description:
                - "Number"
            no_route:
                description:
                - "Number of no routes"
            conn_closed_by_client:
                description:
                - "Client initiates TCP close/reset"
            total:
                description:
                - "Total"
            user_session:
                description:
                - "Number of user sessions"
            dcmsg_fwd_in:
                description:
                - "Diameter cross cpu fwd in"
            aca_out:
                description:
                - "Number of ACAs out"
            sta_in:
                description:
                - "Number of STAs in"
            server_fail:
                description:
                - "Number of server failures"
            dwa_in:
                description:
                - "Number of DWAs in"
            dwa_out:
                description:
                - "Number of DWAs out"
            client_select_fail:
                description:
                - "Fail to select client"
            asa_in:
                description:
                - "Number of ASAs in"
            dcmsg_fwd_out:
                description:
                - "Diameter cross cpu fwd out"
            reselect_fwd_tuple:
                description:
                - "Original client tuple does not exist so reselect another one"
            retry_client_request:
                description:
                - "Diameter retry client request"
            reply_unable_to_deliver:
                description:
                - "Reply with unable to deliver error info"
            reselect_rev_tuple:
                description:
                - "Original server tuple does not exist so reselect another one"
            dcmsg_rev_in:
                description:
                - "Diameter cross cpu rev in"
            retry_client_request_fail:
                description:
                - "Diameter retry client request fail"
            cca_out:
                description:
                - "Number of CCAs out"
            total_http_req_enter_gen:
                description:
                - "Total number of HTTP requests enter generic proxy"
            aca_in:
                description:
                - "Number of ACAs in"
            terminate_on_cca_t:
                description:
                - "Diameter terminate on cca_t"
            unkwn_cmd_code:
                description:
                - "Diameter unkown cmd code"
            cca_in:
                description:
                - "Number of CCAs in"
            dpa_out:
                description:
                - "Number of DPAs out"
            invalid_avp:
                description:
                - "AVP value contains illegal chars"
            other_out:
                description:
                - "Number of other messages out"
            cea_out:
                description:
                - "Number of CEAs out"
            dpr_in:
                description:
                - "Number of DPRs in"
            asr_in:
                description:
                - "Number of ASRs in"
            reply_error_info_fail:
                description:
                - "Fail to reply error info to peer"
            asr_out:
                description:
                - "Number of ASRs out"
            cer_in:
                description:
                - "Number of CERs in"
            str_in:
                description:
                - "Number of STRs in"
            sta_out:
                description:
                - "Number of STAs out"
            snat_fail:
                description:
                - "Number of snat failures"
            cca_t:
                description:
                - "Number of CCAs terminate"
            no_session_id:
                description:
                - "Diameter no session id avp"
            update_latest_server:
                description:
                - "Update to the latest server that used a session id"
            acr_in:
                description:
                - "Number of ACRs in"
            dcmsg_error:
                description:
                - "Diameter cross cpu error"
            ccr_t:
                description:
                - "Number of CCRs terminate"
            ccr_u:
                description:
                - "Number of CCRs update"
            cea_in:
                description:
                - "Number of CEAs in"
            dwr_out:
                description:
                - "Number of DWRs out"
            mismatch_fwd_id:
                description:
                - "Diameter mismatch fwd session id"
            ccr_out:
                description:
                - "Number of CCRs out"
            cer_out:
                description:
                - "Number of CERs out"
            other_in:
                description:
                - "Number of other messages in"
            mismatch_rev_id:
                description:
                - "Diameter mismatch rev session id"
            no_fwd_tuple:
                description:
                - "Diameter no fwd tuple matched"
            reselect_fwd_tuple_other_cpu:
                description:
                - "Original client tuple does not exist so reselect another one on other CPUs"
            asa_out:
                description:
                - "Number of ASAs out"
            dcmsg_rev_out:
                description:
                - "Diameter cross cpu rev out"
            no_sess:
                description:
                - "Number of no sessions"
            dpa_in:
                description:
                - "Number of DPAs in"
            reply_invalid_avp_value:
                description:
                - "Reply with invalid AVP error info"
            reply_unknown_session_id:
                description:
                - "Reply with unknown session ID error info"
            conn_closed_by_server:
                description:
                - "Server initiates TCP close/reset"
            close_conn_when_vport_down:
                description:
                - "Close client conn when virtual port is down"
            dpr_out:
                description:
                - "Number of DPRs out"
            no_rev_tuple:
                description:
                - "Diameter no rev tuple matched"
            ccr_i:
                description:
                - "Number of CCRs initial"
            str_out:
                description:
                - "Number of STRs out"
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
        device_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict',l4_cpu_list=dict(type='list',ccr_in=dict(type='int',),forward_unknown_session_id=dict(type='int',),acr_out=dict(type='int',),dwr_in=dict(type='int',),client_fail=dict(type='int',),server_selection_fail=dict(type='int',),curr_proxy_conns=dict(type='int',),conn_closed_by_client=dict(type='int',),server_fail=dict(type='int',),user_session=dict(type='str',),dcmsg_fwd_in=dict(type='int',),aca_out=dict(type='int',),dpr_in=dict(type='int',),update_latest_server=dict(type='int',),cer_out=dict(type='int',),total_http_conn_generic_proxy=dict(type='int',),dwa_out=dict(type='int',),client_select_fail=dict(type='int',),asa_in=dict(type='int',),dcmsg_fwd_out=dict(type='int',),reselect_fwd_tuple=dict(type='int',),retry_client_request=dict(type='int',),reply_unable_to_deliver=dict(type='int',),reselect_rev_tuple=dict(type='int',),dcmsg_rev_in=dict(type='int',),retry_client_request_fail=dict(type='int',),cca_out=dict(type='int',),no_route_fail=dict(type='int',),aca_in=dict(type='int',),terminate_on_cca_t=dict(type='int',),unkwn_cmd_code=dict(type='int',),cca_in=dict(type='int',),dpa_out=dict(type='int',),invalid_avp=dict(type='int',),other_out=dict(type='int',),cea_out=dict(type='int',),sta_in=dict(type='int',),asr_in=dict(type='int',),dwa_in=dict(type='int',),reply_error_info_fail=dict(type='int',),asr_out=dict(type='int',),cer_in=dict(type='int',),dpa_in=dict(type='int',),dpr_out=dict(type='int',),cca_t=dict(type='int',),no_session_id=dict(type='int',),str_out=dict(type='int',),acr_in=dict(type='int',),dcmsg_error=dict(type='int',),ccr_t=dict(type='int',),ccr_u=dict(type='int',),cea_in=dict(type='int',),dwr_out=dict(type='int',),mismatch_fwd_id=dict(type='int',),ccr_out=dict(type='int',),total_proxy_conns=dict(type='int',),other_in=dict(type='int',),mismatch_rev_id=dict(type='int',),no_fwd_tuple=dict(type='int',),reselect_fwd_tuple_other_cpu=dict(type='int',),asa_out=dict(type='int',),dcmsg_rev_out=dict(type='int',),str_in=dict(type='int',),reply_invalid_avp_value=dict(type='int',),reply_unknown_session_id=dict(type='int',),conn_closed_by_server=dict(type='int',),close_conn_when_vport_down=dict(type='int',),sta_out=dict(type='int',),no_rev_tuple=dict(type='int',),ccr_i=dict(type='int',),source_nat_fail=dict(type='int',)),cpu_count=dict(type='int',)),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','num','curr','total','svrsel_fail','no_route','snat_fail','client_fail','server_fail','no_sess','user_session','acr_out','acr_in','aca_out','aca_in','cea_out','cea_in','cer_out','cer_in','dwr_out','dwr_in','dwa_out','dwa_in','str_out','str_in','sta_out','sta_in','asr_out','asr_in','asa_out','asa_in','other_out','other_in','total_http_req_enter_gen','mismatch_fwd_id','mismatch_rev_id','unkwn_cmd_code','no_session_id','no_fwd_tuple','no_rev_tuple','dcmsg_fwd_in','dcmsg_fwd_out','dcmsg_rev_in','dcmsg_rev_out','dcmsg_error','retry_client_request','retry_client_request_fail','reply_unknown_session_id','ccr_out','ccr_in','cca_out','cca_in','ccr_i','ccr_u','ccr_t','cca_t','terminate_on_cca_t','forward_unknown_session_id','update_latest_server','client_select_fail','close_conn_when_vport_down','invalid_avp','reselect_fwd_tuple','reselect_fwd_tuple_other_cpu','reselect_rev_tuple','conn_closed_by_client','conn_closed_by_server','reply_invalid_avp_value','reply_unable_to_deliver','reply_error_info_fail','dpr_out','dpr_in','dpa_out','dpa_in'])),
        stats=dict(type='dict',ccr_in=dict(type='str',),forward_unknown_session_id=dict(type='str',),svrsel_fail=dict(type='str',),curr=dict(type='str',),acr_out=dict(type='str',),dwr_in=dict(type='str',),client_fail=dict(type='str',),num=dict(type='str',),no_route=dict(type='str',),conn_closed_by_client=dict(type='str',),total=dict(type='str',),user_session=dict(type='str',),dcmsg_fwd_in=dict(type='str',),aca_out=dict(type='str',),sta_in=dict(type='str',),server_fail=dict(type='str',),dwa_in=dict(type='str',),dwa_out=dict(type='str',),client_select_fail=dict(type='str',),asa_in=dict(type='str',),dcmsg_fwd_out=dict(type='str',),reselect_fwd_tuple=dict(type='str',),retry_client_request=dict(type='str',),reply_unable_to_deliver=dict(type='str',),reselect_rev_tuple=dict(type='str',),dcmsg_rev_in=dict(type='str',),retry_client_request_fail=dict(type='str',),cca_out=dict(type='str',),total_http_req_enter_gen=dict(type='str',),aca_in=dict(type='str',),terminate_on_cca_t=dict(type='str',),unkwn_cmd_code=dict(type='str',),cca_in=dict(type='str',),dpa_out=dict(type='str',),invalid_avp=dict(type='str',),other_out=dict(type='str',),cea_out=dict(type='str',),dpr_in=dict(type='str',),asr_in=dict(type='str',),reply_error_info_fail=dict(type='str',),asr_out=dict(type='str',),cer_in=dict(type='str',),str_in=dict(type='str',),sta_out=dict(type='str',),snat_fail=dict(type='str',),cca_t=dict(type='str',),no_session_id=dict(type='str',),update_latest_server=dict(type='str',),acr_in=dict(type='str',),dcmsg_error=dict(type='str',),ccr_t=dict(type='str',),ccr_u=dict(type='str',),cea_in=dict(type='str',),dwr_out=dict(type='str',),mismatch_fwd_id=dict(type='str',),ccr_out=dict(type='str',),cer_out=dict(type='str',),other_in=dict(type='str',),mismatch_rev_id=dict(type='str',),no_fwd_tuple=dict(type='str',),reselect_fwd_tuple_other_cpu=dict(type='str',),asa_out=dict(type='str',),dcmsg_rev_out=dict(type='str',),no_sess=dict(type='str',),dpa_in=dict(type='str',),reply_invalid_avp_value=dict(type='str',),reply_unknown_session_id=dict(type='str',),conn_closed_by_server=dict(type='str',),close_conn_when_vport_down=dict(type='str',),dpr_out=dict(type='str',),no_rev_tuple=dict(type='str',),ccr_i=dict(type='str',),str_out=dict(type='str',)),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/generic-proxy"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/generic-proxy"

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
        for k, v in payload["generic-proxy"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["generic-proxy"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["generic-proxy"][k] = v
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
    payload = build_json("generic-proxy", module)
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
    device_id = module.params["device_id"]

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
    
    if device_id:
        module.client.change_context(device_id)

    if a10_partition:
        module.client.activate_partition(a10_partition)

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