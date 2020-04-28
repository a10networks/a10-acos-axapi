#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_aam_authentication_service_group
description:
    - Authentication service group
short_description: Configures A10 aam.authentication.service-group
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - present
          - absent
          - noop
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
            pri_affinity_priority:
                description:
                - "Field pri_affinity_priority"
            name:
                description:
                - "Specify AAM service group name"
            stateless_current_rate:
                description:
                - "Field stateless_current_rate"
            servers_down:
                description:
                - "Field servers_down"
            stateless_state:
                description:
                - "Field stateless_state"
            servers_disable:
                description:
                - "Field servers_disable"
            stateless_type:
                description:
                - "Field stateless_type"
            servers_total:
                description:
                - "Field servers_total"
            state:
                description:
                - "Field state"
            member_list:
                description:
                - "Field member_list"
            servers_up:
                description:
                - "Field servers_up"
            stateless_current_usage:
                description:
                - "Field stateless_current_usage"
            hm_dsr_enable_all_vip:
                description:
                - "Field hm_dsr_enable_all_vip"
    health_check_disable:
        description:
        - "Disable health check"
        required: False
    protocol:
        description:
        - "'tcp'= TCP AAM service; 'udp'= UDP AAM service; "
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    lb_method:
        description:
        - "'round-robin'= Round robin on server level; "
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'server_selection_fail_drop'= Drops due to Service selection failure; 'server_selection_fail_reset'= Resets sent out for Service selection failure; 'service_peak_conn'= Peak connection count for the Service Group; 'service_healthy_host'= Service Group healthy host count; 'service_unhealthy_host'= Service Group unhealthy host count; 'service_req_count'= Service Group request count; 'service_resp_count'= Service Group response count; 'service_resp_2xx'= Service Group response 2xx count; 'service_resp_3xx'= Service Group response 3xx count; 'service_resp_4xx'= Service Group response 4xx count; 'service_resp_5xx'= Service Group response 5xx count; 'service_curr_conn_overflow'= Current connection counter overflow count; "
    member_list:
        description:
        - "Field member_list"
        required: False
        suboptions:
            member_priority:
                description:
                - "Priority of Port in the Group"
            uuid:
                description:
                - "uuid of the object"
            user_tag:
                description:
                - "Customized tag"
            sampling_enable:
                description:
                - "Field sampling_enable"
            member_state:
                description:
                - "'enable'= Enable member service port; 'disable'= Disable member service port; "
            port:
                description:
                - "Port number"
            name:
                description:
                - "Member name"
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            service_resp_2xx:
                description:
                - "Service Group response 2xx count"
            member_list:
                description:
                - "Field member_list"
            service_unhealthy_host:
                description:
                - "Service Group unhealthy host count"
            service_curr_conn_overflow:
                description:
                - "Current connection counter overflow count"
            name:
                description:
                - "Specify AAM service group name"
            server_selection_fail_drop:
                description:
                - "Drops due to Service selection failure"
            service_healthy_host:
                description:
                - "Service Group healthy host count"
            service_resp_count:
                description:
                - "Service Group response count"
            service_req_count:
                description:
                - "Service Group request count"
            service_resp_4xx:
                description:
                - "Service Group response 4xx count"
            service_peak_conn:
                description:
                - "Peak connection count for the Service Group"
            server_selection_fail_reset:
                description:
                - "Resets sent out for Service selection failure"
            service_resp_3xx:
                description:
                - "Service Group response 3xx count"
            service_resp_5xx:
                description:
                - "Service Group response 5xx count"
    health_check:
        description:
        - "Health Check (Monitor Name)"
        required: False
    name:
        description:
        - "Specify AAM service group name"
        required: True


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["health_check","health_check_disable","lb_method","member_list","name","oper","protocol","sampling_enable","stats","user_tag","uuid",]

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
        state=dict(type='str', default="present", choices=['present', 'absent', 'noop']),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict',pri_affinity_priority=dict(type='int',),name=dict(type='str',required=True,),stateless_current_rate=dict(type='int',),servers_down=dict(type='int',),stateless_state=dict(type='int',),servers_disable=dict(type='int',),stateless_type=dict(type='int',),servers_total=dict(type='int',),state=dict(type='str',choices=['All Up','Functional Up','Down','Disb','Unkn']),member_list=dict(type='list',oper=dict(type='dict',hm_key=dict(type='int',),alt_list=dict(type='list',alt_state=dict(type='str',),alt_rev_pkts=dict(type='int',),alt_port=dict(type='int',),alt_peak_conn=dict(type='int',),alt_curr_conn=dict(type='int',),alt_fwd_pkts=dict(type='int',),alt_total_conn=dict(type='int',),alt_name=dict(type='str',)),hm_index=dict(type='int',),state=dict(type='str',choices=['UP','DOWN','MAINTENANCE','DIS-UP','DIS-DOWN','DIS-MAINTENANCE']),drs_list=dict(type='list',drs_fwd_bts=dict(type='int',),drs_fwd_pkts=dict(type='int',),drs_rev_bts=dict(type='int',),drs_port=dict(type='int',),drs_curr_req=dict(type='int',),drs_name=dict(type='str',),drs_pers_conn=dict(type='int',),drs_priority=dict(type='int',),drs_total_req_succ=dict(type='int',),drs_hm_key=dict(type='int',),drs_hm_index=dict(type='int',),drs_rev_pkts=dict(type='int',),drs_total_conn=dict(type='int',),drs_state=dict(type='str',),drs_frsp_time=dict(type='int',),drs_peak_conn=dict(type='int',),drs_curr_conn=dict(type='int',),drs_rsp_time=dict(type='int',),drs_total_req=dict(type='int',),drs_srsp_time=dict(type='int',))),name=dict(type='str',required=True,),port=dict(type='int',required=True,)),servers_up=dict(type='int',),stateless_current_usage=dict(type='int',),hm_dsr_enable_all_vip=dict(type='int',)),
        health_check_disable=dict(type='bool',),
        protocol=dict(type='str',choices=['tcp','udp']),
        uuid=dict(type='str',),
        user_tag=dict(type='str',),
        lb_method=dict(type='str',choices=['round-robin']),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','server_selection_fail_drop','server_selection_fail_reset','service_peak_conn','service_healthy_host','service_unhealthy_host','service_req_count','service_resp_count','service_resp_2xx','service_resp_3xx','service_resp_4xx','service_resp_5xx','service_curr_conn_overflow'])),
        member_list=dict(type='list',member_priority=dict(type='int',),uuid=dict(type='str',),user_tag=dict(type='str',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','total_fwd_bytes','total_fwd_pkts','total_rev_bytes','total_rev_pkts','total_conn','total_rev_pkts_inspected','total_rev_pkts_inspected_status_code_2xx','total_rev_pkts_inspected_status_code_non_5xx','curr_req','total_req','total_req_succ','peak_conn','response_time','fastest_rsp_time','slowest_rsp_time','curr_ssl_conn','total_ssl_conn','curr_conn_overflow'])),member_state=dict(type='str',choices=['enable','disable']),port=dict(type='int',required=True,),name=dict(type='str',required=True,)),
        stats=dict(type='dict',service_resp_2xx=dict(type='str',),member_list=dict(type='list',stats=dict(type='dict',curr_req=dict(type='str',),total_rev_bytes=dict(type='str',),peak_conn=dict(type='str',),total_ssl_conn=dict(type='str',),total_conn=dict(type='str',),fastest_rsp_time=dict(type='str',),total_fwd_pkts=dict(type='str',),total_req=dict(type='str',),total_rev_pkts=dict(type='str',),curr_ssl_conn=dict(type='str',),total_req_succ=dict(type='str',),curr_conn=dict(type='str',),total_rev_pkts_inspected_status_code_non_5xx=dict(type='str',),total_rev_pkts_inspected_status_code_2xx=dict(type='str',),curr_conn_overflow=dict(type='str',),total_fwd_bytes=dict(type='str',),slowest_rsp_time=dict(type='str',),response_time=dict(type='str',),total_rev_pkts_inspected=dict(type='str',)),name=dict(type='str',required=True,),port=dict(type='int',required=True,)),service_unhealthy_host=dict(type='str',),service_curr_conn_overflow=dict(type='str',),name=dict(type='str',required=True,),server_selection_fail_drop=dict(type='str',),service_healthy_host=dict(type='str',),service_resp_count=dict(type='str',),service_req_count=dict(type='str',),service_resp_4xx=dict(type='str',),service_peak_conn=dict(type='str',),server_selection_fail_reset=dict(type='str',),service_resp_3xx=dict(type='str',),service_resp_5xx=dict(type='str',)),
        health_check=dict(type='str',),
        name=dict(type='str',required=True,)
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/service-group/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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
    url_base = "/axapi/v3/aam/authentication/service-group/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
        for k, v in payload["service-group"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["service-group"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["service-group"][k] = v
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
    payload = build_json("service-group", module)
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