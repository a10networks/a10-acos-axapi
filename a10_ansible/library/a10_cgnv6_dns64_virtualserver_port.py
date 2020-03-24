#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_dns64_virtualserver_port
description:
    - Virtual Port
short_description: Configures A10 cgnv6.dns64.virtualserver.port
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
    dns64_virtualserver_name:
        description:
        - Key to identify parent object
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            protocol:
                description:
                - "'dns-udp'= DNS service over UDP; "
            loc_list:
                description:
                - "Field loc_list"
            loc_max_depth:
                description:
                - "Field loc_max_depth"
            level_str:
                description:
                - "Field level_str"
            loc_last:
                description:
                - "Field loc_last"
            state:
                description:
                - "Field state"
            geo_location:
                description:
                - "Field geo_location"
            port_number:
                description:
                - "Port"
            loc_success:
                description:
                - "Field loc_success"
            loc_error:
                description:
                - "Field loc_error"
            group_id:
                description:
                - "Field group_id"
            loc_override:
                description:
                - "Field loc_override"
    protocol:
        description:
        - "'dns-udp'= DNS service over UDP; "
        required: True
    uuid:
        description:
        - "uuid of the object"
        required: False
    precedence:
        description:
        - "Set auto NAT pool as higher precedence for source NAT"
        required: False
    auto:
        description:
        - "Configure auto NAT for the vport"
        required: False
    template_policy:
        description:
        - "Policy Template (Policy template name)"
        required: False
    service_group:
        description:
        - "Bind a Service Group to this Virtual Server (Service Group Name)"
        required: False
    port_number:
        description:
        - "Port"
        required: True
    action:
        description:
        - "'enable'= Enable; 'disable'= Disable; "
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'curr_conn'= Current connection; 'total_l4_conn'= Total L4 connections; 'total_l7_conn'= Total L7 connections; 'toatal_tcp_conn'= Total TCP connections; 'total_conn'= Total connections; 'total_fwd_bytes'= Total forward bytes; 'total_fwd_pkts'= Total forward packets; 'total_rev_bytes'= Total reverse bytes; 'total_rev_pkts'= Total reverse packets; 'total_dns_pkts'= Total DNS packets; 'total_mf_dns_pkts'= Total MF DNS packets; 'es_total_failure_actions'= Total failure actions; 'compression_bytes_before'= Data into compression engine; 'compression_bytes_after'= Data out of compression engine; 'compression_hit'= Number of requests compressed; 'compression_miss'= Number of requests NOT compressed; 'compression_miss_no_client'= Compression miss no client; 'compression_miss_template_exclusion'= Compression miss template exclusion; 'curr_req'= Current requests; 'total_req'= Total requests; 'total_req_succ'= Total successful requests; 'peak_conn'= Peak connections; 'curr_conn_rate'= Current connection rate; 'last_rsp_time'= Last response time; 'fastest_rsp_time'= Fastest response time; 'slowest_rsp_time'= Slowest response time; "
    user_tag:
        description:
        - "Customized tag"
        required: False
    template_dns:
        description:
        - "DNS template (DNS template name)"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            curr_req:
                description:
                - "Current requests"
            protocol:
                description:
                - "'dns-udp'= DNS service over UDP; "
            total_fwd_bytes:
                description:
                - "Total forward bytes"
            compression_miss:
                description:
                - "Number of requests NOT compressed"
            fastest_rsp_time:
                description:
                - "Fastest response time"
            total_fwd_pkts:
                description:
                - "Total forward packets"
            total_mf_dns_pkts:
                description:
                - "Total MF DNS packets"
            compression_miss_template_exclusion:
                description:
                - "Compression miss template exclusion"
            total_dns_pkts:
                description:
                - "Total DNS packets"
            peak_conn:
                description:
                - "Peak connections"
            compression_bytes_after:
                description:
                - "Data out of compression engine"
            total_req:
                description:
                - "Total requests"
            compression_bytes_before:
                description:
                - "Data into compression engine"
            last_rsp_time:
                description:
                - "Last response time"
            curr_conn:
                description:
                - "Current connection"
            port_number:
                description:
                - "Port"
            total_rev_bytes:
                description:
                - "Total reverse bytes"
            curr_conn_rate:
                description:
                - "Current connection rate"
            compression_miss_no_client:
                description:
                - "Compression miss no client"
            es_total_failure_actions:
                description:
                - "Total failure actions"
            total_conn:
                description:
                - "Total connections"
            compression_hit:
                description:
                - "Number of requests compressed"
            total_rev_pkts:
                description:
                - "Total reverse packets"
            total_l7_conn:
                description:
                - "Total L7 connections"
            total_req_succ:
                description:
                - "Total successful requests"
            total_l4_conn:
                description:
                - "Total L4 connections"
            slowest_rsp_time:
                description:
                - "Slowest response time"
            toatal_tcp_conn:
                description:
                - "Total TCP connections"
    pool:
        description:
        - "Specify NAT pool or pool group"
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
AVAILABLE_PROPERTIES = ["action","auto","oper","pool","port_number","precedence","protocol","sampling_enable","service_group","stats","template_dns","template_policy","user_tag","uuid",]

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
        oper=dict(type='dict',protocol=dict(type='str',required=True,choices=['dns-udp']),loc_list=dict(type='str',),loc_max_depth=dict(type='int',),level_str=dict(type='str',),loc_last=dict(type='str',),state=dict(type='str',choices=['All Up','Functional Up','Down','Disb','Unkn']),geo_location=dict(type='str',),port_number=dict(type='int',required=True,),loc_success=dict(type='int',),loc_error=dict(type='int',),group_id=dict(type='int',),loc_override=dict(type='int',)),
        protocol=dict(type='str',required=True,choices=['dns-udp']),
        uuid=dict(type='str',),
        precedence=dict(type='bool',),
        auto=dict(type='bool',),
        template_policy=dict(type='str',),
        service_group=dict(type='str',),
        port_number=dict(type='int',required=True,),
        action=dict(type='str',choices=['enable','disable']),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','curr_conn','total_l4_conn','total_l7_conn','toatal_tcp_conn','total_conn','total_fwd_bytes','total_fwd_pkts','total_rev_bytes','total_rev_pkts','total_dns_pkts','total_mf_dns_pkts','es_total_failure_actions','compression_bytes_before','compression_bytes_after','compression_hit','compression_miss','compression_miss_no_client','compression_miss_template_exclusion','curr_req','total_req','total_req_succ','peak_conn','curr_conn_rate','last_rsp_time','fastest_rsp_time','slowest_rsp_time'])),
        user_tag=dict(type='str',),
        template_dns=dict(type='str',),
        stats=dict(type='dict',curr_req=dict(type='str',),protocol=dict(type='str',required=True,choices=['dns-udp']),total_fwd_bytes=dict(type='str',),compression_miss=dict(type='str',),fastest_rsp_time=dict(type='str',),total_fwd_pkts=dict(type='str',),total_mf_dns_pkts=dict(type='str',),compression_miss_template_exclusion=dict(type='str',),total_dns_pkts=dict(type='str',),peak_conn=dict(type='str',),compression_bytes_after=dict(type='str',),total_req=dict(type='str',),compression_bytes_before=dict(type='str',),last_rsp_time=dict(type='str',),curr_conn=dict(type='str',),port_number=dict(type='int',required=True,),total_rev_bytes=dict(type='str',),curr_conn_rate=dict(type='str',),compression_miss_no_client=dict(type='str',),es_total_failure_actions=dict(type='str',),total_conn=dict(type='str',),compression_hit=dict(type='str',),total_rev_pkts=dict(type='str',),total_l7_conn=dict(type='str',),total_req_succ=dict(type='str',),total_l4_conn=dict(type='str',),slowest_rsp_time=dict(type='str',),toatal_tcp_conn=dict(type='str',)),
        pool=dict(type='str',)
    ))
   
    # Parent keys
    rv.update(dict(
        dns64_virtualserver_name=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/dns64-virtualserver/{dns64_virtualserver_name}/port/{port-number}+{protocol}"

    f_dict = {}
    f_dict["port-number"] = ""
    f_dict["protocol"] = ""
    f_dict["dns64_virtualserver_name"] = module.params["dns64_virtualserver_name"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/dns64-virtualserver/{dns64_virtualserver_name}/port/{port-number}+{protocol}"

    f_dict = {}
    f_dict["port-number"] = module.params["port_number"]
    f_dict["protocol"] = module.params["protocol"]
    f_dict["dns64_virtualserver_name"] = module.params["dns64_virtualserver_name"]

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
        for k, v in payload["port"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["port"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["port"][k] = v
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
    payload = build_json("port", module)
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