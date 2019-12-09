#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_service_group_member
description:
    - Service Group Member
short_description: Configures A10 slb.service.group.member
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
    service_group_name:
        description:
        - Key to identify parent object
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            alt_list:
                description:
                - "Field alt_list"
            name:
                description:
                - "Member name"
            hm_index:
                description:
                - "Field hm_index"
            hm_key:
                description:
                - "Field hm_key"
            drs_list:
                description:
                - "Field drs_list"
            state:
                description:
                - "Field state"
            port:
                description:
                - "Port number"
    member_priority:
        description:
        - "Priority of Port in the Group (Priority of Port in the Group, default is 1)"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    fqdn_name:
        description:
        - "Server hostname - Not applicable if real server is already defined"
        required: False
    resolve_as:
        description:
        - "'resolve-to-ipv4'= Use A Query only to resolve FQDN; 'resolve-to-ipv6'= Use AAAA Query only to resolve FQDN; 'resolve-to-ipv4-and-ipv6'= Use A as well as AAAA Query to resolve FQDN; "
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'total_fwd_bytes'= Bytes processed in forward direction; 'total_fwd_pkts'= Packets processed in forward direction; 'total_rev_bytes'= Bytes processed in reverse direction; 'total_rev_pkts'= Packets processed in reverse direction; 'total_conn'= Total established connections; 'total_rev_pkts_inspected'= Total reverse packets inspected; 'total_rev_pkts_inspected_status_code_2xx'= Total reverse packets inspected status code 2xx; 'total_rev_pkts_inspected_status_code_non_5xx'= Total reverse packets inspected status code non 5xx; 'curr_req'= Current requests; 'total_req'= Total requests; 'total_req_succ'= Total requests successful; 'peak_conn'= Peak connections; 'response_time'= Response time; 'fastest_rsp_time'= Fastest response time; 'slowest_rsp_time'= Slowest response time; 'curr_ssl_conn'= Current SSL connections; 'total_ssl_conn'= Total SSL connections; 'curr_conn_overflow'= Current connection counter overflow count; 'state_flaps'= State flaps count; "
    member_template:
        description:
        - "Real server port template (Real server port template name)"
        required: False
    name:
        description:
        - "Member name"
        required: True
    host:
        description:
        - "IP Address - Not applicable if real server is already defined"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    member_state:
        description:
        - "'enable'= Enable member service port; 'disable'= Disable member service port; 'disable-with-health-check'= disable member service port, but health check work; "
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            curr_req:
                description:
                - "Current requests"
            peak_conn:
                description:
                - "Peak connections"
            total_req:
                description:
                - "Total requests"
            total_rev_pkts:
                description:
                - "Packets processed in reverse direction"
            curr_ssl_conn:
                description:
                - "Current SSL connections"
            curr_conn:
                description:
                - "Current established connections"
            total_rev_pkts_inspected_status_code_non_5xx:
                description:
                - "Total reverse packets inspected status code non 5xx"
            total_rev_bytes:
                description:
                - "Bytes processed in reverse direction"
            port:
                description:
                - "Port number"
            response_time:
                description:
                - "Response time"
            total_fwd_bytes:
                description:
                - "Bytes processed in forward direction"
            name:
                description:
                - "Member name"
            total_rev_pkts_inspected_status_code_2xx:
                description:
                - "Total reverse packets inspected status code 2xx"
            total_ssl_conn:
                description:
                - "Total SSL connections"
            total_conn:
                description:
                - "Total established connections"
            fastest_rsp_time:
                description:
                - "Fastest response time"
            total_fwd_pkts:
                description:
                - "Packets processed in forward direction"
            total_req_succ:
                description:
                - "Total requests successful"
            state_flaps:
                description:
                - "State flaps count"
            total_rev_pkts_inspected:
                description:
                - "Total reverse packets inspected"
            curr_conn_overflow:
                description:
                - "Current connection counter overflow count"
            slowest_rsp_time:
                description:
                - "Slowest response time"
    server_ipv6_addr:
        description:
        - "IPV6 Address - Not applicable if real server is already defined"
        required: False
    port:
        description:
        - "Port number"
        required: True
    member_stats_data_disable:
        description:
        - "Disable statistical data collection"
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
AVAILABLE_PROPERTIES = ["fqdn_name","host","member_priority","member_state","member_stats_data_disable","member_template","name","oper","port","resolve_as","sampling_enable","server_ipv6_addr","stats","user_tag","uuid",]

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
        oper=dict(type='dict',alt_list=dict(type='list',alt_state=dict(type='str',),alt_rev_pkts=dict(type='int',),alt_port=dict(type='int',),alt_peak_conn=dict(type='int',),alt_curr_conn=dict(type='int',),alt_fwd_pkts=dict(type='int',),alt_total_conn=dict(type='int',),alt_name=dict(type='str',)),name=dict(type='str',required=True,),hm_index=dict(type='int',),hm_key=dict(type='int',),drs_list=dict(type='list',drs_fwd_bts=dict(type='int',),drs_fwd_pkts=dict(type='int',),drs_rev_bts=dict(type='int',),drs_port=dict(type='int',),drs_curr_req=dict(type='int',),drs_name=dict(type='str',),drs_pers_conn=dict(type='int',),drs_priority=dict(type='int',),drs_total_req_succ=dict(type='int',),drs_hm_key=dict(type='int',),drs_hm_index=dict(type='int',),drs_rev_pkts=dict(type='int',),drs_total_conn=dict(type='int',),drs_state=dict(type='str',),drs_frsp_time=dict(type='int',),drs_peak_conn=dict(type='int',),drs_curr_conn=dict(type='int',),drs_rsp_time=dict(type='int',),drs_total_req=dict(type='int',),drs_srsp_time=dict(type='int',)),state=dict(type='str',choices=['UP','DOWN','MAINTENANCE','DIS-UP','DIS-DOWN','DIS-MAINTENANCE','DIS-DAMP']),port=dict(type='int',required=True,)),
        member_priority=dict(type='int',),
        uuid=dict(type='str',),
        fqdn_name=dict(type='str',),
        resolve_as=dict(type='str',choices=['resolve-to-ipv4','resolve-to-ipv6','resolve-to-ipv4-and-ipv6']),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','total_fwd_bytes','total_fwd_pkts','total_rev_bytes','total_rev_pkts','total_conn','total_rev_pkts_inspected','total_rev_pkts_inspected_status_code_2xx','total_rev_pkts_inspected_status_code_non_5xx','curr_req','total_req','total_req_succ','peak_conn','response_time','fastest_rsp_time','slowest_rsp_time','curr_ssl_conn','total_ssl_conn','curr_conn_overflow','state_flaps'])),
        member_template=dict(type='str',),
        name=dict(type='str',required=True,),
        host=dict(type='str',),
        user_tag=dict(type='str',),
        member_state=dict(type='str',choices=['enable','disable','disable-with-health-check']),
        stats=dict(type='dict',curr_req=dict(type='str',),peak_conn=dict(type='str',),total_req=dict(type='str',),total_rev_pkts=dict(type='str',),curr_ssl_conn=dict(type='str',),curr_conn=dict(type='str',),total_rev_pkts_inspected_status_code_non_5xx=dict(type='str',),total_rev_bytes=dict(type='str',),port=dict(type='int',required=True,),response_time=dict(type='str',),total_fwd_bytes=dict(type='str',),name=dict(type='str',required=True,),total_rev_pkts_inspected_status_code_2xx=dict(type='str',),total_ssl_conn=dict(type='str',),total_conn=dict(type='str',),fastest_rsp_time=dict(type='str',),total_fwd_pkts=dict(type='str',),total_req_succ=dict(type='str',),state_flaps=dict(type='str',),total_rev_pkts_inspected=dict(type='str',),curr_conn_overflow=dict(type='str',),slowest_rsp_time=dict(type='str',)),
        server_ipv6_addr=dict(type='str',),
        port=dict(type='int',required=True,),
        member_stats_data_disable=dict(type='bool',)
    ))
   
    # Parent keys
    rv.update(dict(
        service_group_name=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/service-group/{service_group_name}/member/{name}+{port}"

    f_dict = {}
    f_dict["name"] = ""
    f_dict["port"] = ""
    f_dict["service_group_name"] = module.params["service_group_name"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/service-group/{service_group_name}/member/{name}+{port}"

    f_dict = {}
    f_dict["name"] = module.params["name"]
    f_dict["port"] = module.params["port"]
    f_dict["service_group_name"] = module.params["service_group_name"]

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
        for k, v in payload["member"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["member"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["member"][k] = v
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
    payload = build_json("member", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

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
        result = absent(module, result, existing_config)
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