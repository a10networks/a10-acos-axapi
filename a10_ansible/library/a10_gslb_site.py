#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_gslb_site
description:
    - Specify a GSLB site
short_description: Configures A10 gslb.site
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
    ip_server_list:
        description:
        - "Field ip_server_list"
        required: False
        suboptions:
            ip_server_name:
                description:
                - "Specify the real server name"
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            ip_server_list:
                description:
                - "Field ip_server_list"
            state:
                description:
                - "Field state"
            gslb_site:
                description:
                - "Field gslb_site"
            client_ldns_list:
                description:
                - "Field client_ldns_list"
            site_name:
                description:
                - "Specify GSLB site name"
            type_last:
                description:
                - "Field type_last"
            slb_dev_list:
                description:
                - "Field slb_dev_list"
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            ip_server_list:
                description:
                - "Field ip_server_list"
            hits:
                description:
                - "Number of times the site was selected"
            slb_dev_list:
                description:
                - "Field slb_dev_list"
            site_name:
                description:
                - "Specify GSLB site name"
    uuid:
        description:
        - "uuid of the object"
        required: False
    weight:
        description:
        - "Specify a weight for the GSLB site (Weight, default is 1)"
        required: False
    site_name:
        description:
        - "Specify GSLB site name"
        required: True
    slb_dev_list:
        description:
        - "Field slb_dev_list"
        required: False
        suboptions:
            health_check_action:
                description:
                - "'health-check'= Enable health Check; 'health-check-disable'= Disable health check; "
            client_ip:
                description:
                - "Specify client IP address"
            uuid:
                description:
                - "uuid of the object"
            device_name:
                description:
                - "Specify SLB device name"
            proto_compatible:
                description:
                - "Run GSLB Protocol in compatible mode"
            user_tag:
                description:
                - "Customized tag"
            auto_map:
                description:
                - "Enable DNS Auto Mapping"
            proto_aging_time:
                description:
                - "Specify GSLB Protocol aging time, default is 60"
            rdt_value:
                description:
                - "Specify Round-delay-time"
            gateway_ip_addr:
                description:
                - "IP address"
            vip_server:
                description:
                - "Field vip_server"
            ip_address:
                description:
                - "IP address"
            proto_aging_fast:
                description:
                - "Fast GSLB Protocol aging"
            auto_detect:
                description:
                - "'ip'= Service IP only; 'port'= Service Port only; 'ip-and-port'= Both service IP and service port; 'disabled'= disable auto-detect; "
            max_client:
                description:
                - "Specify maximum number of clients, default is 32768"
            admin_preference:
                description:
                - "Specify administrative preference (Specify admin-preference value,default is 100)"
    controller:
        description:
        - "Specify the local controller for the GSLB site (Specify the hostname of the local controller)"
        required: False
    bw_cost:
        description:
        - "Specify cost of band-width"
        required: False
    auto_map:
        description:
        - "Enable DNS Auto Mapping"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'hits'= Number of times the site was selected; "
    disable:
        description:
        - "Disable all servers in the GSLB site"
        required: False
    limit:
        description:
        - "Specify the limit for bandwidth, default is unlimited"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    template:
        description:
        - "Specify template to collect site information (Specify template name)"
        required: False
    threshold:
        description:
        - "Specify the threshold for limit"
        required: False
    multiple_geo_locations:
        description:
        - "Field multiple_geo_locations"
        required: False
        suboptions:
            geo_location:
                description:
                - "Specify the geographic location of the GSLB site (Specify geo-location for this site)"
    easy_rdt:
        description:
        - "Field easy_rdt"
        required: False
        suboptions:
            range_factor:
                description:
                - "Factor of RDT Range, default is 25 (Range Factor of Smooth RDT)"
            smooth_factor:
                description:
                - "Factor of Smooth RDT, default is 10"
            mask:
                description:
                - "Client IP subnet mask, default is 32"
            overlap:
                description:
                - "Enable overlap for geo-location to do longest match"
            limit:
                description:
                - "Limit of valid RDT, default is 16383 (Limit, unit= millisecond)"
            ignore_count:
                description:
                - "Ignore count if RDT is out of range, default is 5"
            aging_time:
                description:
                - "Aging Time, Unit= min, default is 10"
            bind_geoloc:
                description:
                - "Bind RDT to geo-location"
            uuid:
                description:
                - "uuid of the object"
    active_rdt:
        description:
        - "Field active_rdt"
        required: False
        suboptions:
            range_factor:
                description:
                - "Factor of RDT Range, default is 25 (Range Factor of Smooth RDT)"
            smooth_factor:
                description:
                - "Factor of Smooth RDT, default is 10"
            mask:
                description:
                - "Client IP subnet mask, default is 32"
            overlap:
                description:
                - "Enable overlap for geo-location to do longest match"
            limit:
                description:
                - "Limit of valid RDT, default is 16383 (Limit, unit= millisecond)"
            ignore_count:
                description:
                - "Ignore count if RDT is out of range, default is 5"
            aging_time:
                description:
                - "Aging Time, Unit= min, default is 10"
            bind_geoloc:
                description:
                - "Bind RDT to geo-location"
            uuid:
                description:
                - "uuid of the object"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["active_rdt","auto_map","bw_cost","controller","disable","easy_rdt","ip_server_list","limit","multiple_geo_locations","oper","sampling_enable","site_name","slb_dev_list","stats","template","threshold","user_tag","uuid","weight",]

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
        ip_server_list=dict(type='list',ip_server_name=dict(type='str',required=True,),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),uuid=dict(type='str',)),
        oper=dict(type='dict',ip_server_list=dict(type='list',oper=dict(type='dict',state=dict(type='str',),ip_server=dict(type='str',),ip_server_port=dict(type='list',vport=dict(type='int',),vport_state=dict(type='str',)),ip_address=dict(type='str',)),ip_server_name=dict(type='str',required=True,)),state=dict(type='str',),gslb_site=dict(type='str',),client_ldns_list=dict(type='list',client_ip=dict(type='str',),age=dict(type='int',),rdt_sample1=dict(type='int',),rdt_sample2=dict(type='int',),rdt_sample3=dict(type='int',),rdt_sample4=dict(type='int',),rdt_sample5=dict(type='int',),rdt_sample6=dict(type='int',),rdt_sample7=dict(type='int',),rdt_sample8=dict(type='int',),ntype=dict(type='str',)),site_name=dict(type='str',required=True,),type_last=dict(type='list',ntype=dict(type='str',),last=dict(type='str',)),slb_dev_list=dict(type='list',oper=dict(type='dict',dev_gw_state=dict(type='str',),dev_name=dict(type='str',),dev_ip_cnt=dict(type='int',),dev_attr=dict(type='str',),dev_ip=dict(type='str',),dev_state=dict(type='str',),dev_session_num=dict(type='int',),dev_admin_preference=dict(type='int',),client_ldns_list=dict(type='list',client_ip=dict(type='str',),age=dict(type='int',),rdt_sample1=dict(type='int',),rdt_sample2=dict(type='int',),rdt_sample3=dict(type='int',),rdt_sample4=dict(type='int',),rdt_sample5=dict(type='int',),rdt_sample6=dict(type='int',),rdt_sample7=dict(type='int',),rdt_sample8=dict(type='int',),ntype=dict(type='str',)),dev_session_util=dict(type='int',)),device_name=dict(type='str',required=True,),vip_server=dict(type='dict',oper=dict(type='dict',),vip_server_v4_list=dict(type='list',oper=dict(type='dict',dev_vip_addr=dict(type='str',),dev_vip_state=dict(type='str',),dev_vip_port_list=dict(type='list',dev_vip_port_num=dict(type='int',),dev_vip_port_state=dict(type='str',))),ipv4=dict(type='str',required=True,)),vip_server_v6_list=dict(type='list',oper=dict(type='dict',dev_vip_addr=dict(type='str',),dev_vip_state=dict(type='str',),dev_vip_port_list=dict(type='list',dev_vip_port_num=dict(type='int',),dev_vip_port_state=dict(type='str',))),ipv6=dict(type='str',required=True,)),vip_server_name_list=dict(type='list',oper=dict(type='dict',dev_vip_addr=dict(type='str',),dev_vip_state=dict(type='str',),dev_vip_port_list=dict(type='list',dev_vip_port_num=dict(type='int',),dev_vip_port_state=dict(type='str',))),vip_name=dict(type='str',required=True,))))),
        stats=dict(type='dict',ip_server_list=dict(type='list',ip_server_name=dict(type='str',required=True,),stats=dict(type='dict',hits=dict(type='str',))),hits=dict(type='str',),slb_dev_list=dict(type='list',),site_name=dict(type='str',required=True,)),
        uuid=dict(type='str',),
        weight=dict(type='int',),
        site_name=dict(type='str',required=True,),
        slb_dev_list=dict(type='list',health_check_action=dict(type='str',choices=['health-check','health-check-disable']),client_ip=dict(type='str',),uuid=dict(type='str',),device_name=dict(type='str',required=True,),proto_compatible=dict(type='bool',),user_tag=dict(type='str',),auto_map=dict(type='bool',),proto_aging_time=dict(type='int',),rdt_value=dict(type='int',),gateway_ip_addr=dict(type='str',),vip_server=dict(type='dict',vip_server_v4_list=dict(type='list',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','dev_vip_hits'])),ipv4=dict(type='str',required=True,),uuid=dict(type='str',)),vip_server_v6_list=dict(type='list',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','dev_vip_hits'])),uuid=dict(type='str',),ipv6=dict(type='str',required=True,)),vip_server_name_list=dict(type='list',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','dev_vip_hits'])),vip_name=dict(type='str',required=True,),uuid=dict(type='str',))),ip_address=dict(type='str',),proto_aging_fast=dict(type='bool',),auto_detect=dict(type='str',choices=['ip','port','ip-and-port','disabled']),max_client=dict(type='int',),admin_preference=dict(type='int',)),
        controller=dict(type='str',),
        bw_cost=dict(type='bool',),
        auto_map=dict(type='bool',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),
        disable=dict(type='bool',),
        limit=dict(type='int',),
        user_tag=dict(type='str',),
        template=dict(type='str',),
        threshold=dict(type='int',),
        multiple_geo_locations=dict(type='list',geo_location=dict(type='str',)),
        easy_rdt=dict(type='dict',range_factor=dict(type='int',),smooth_factor=dict(type='int',),mask=dict(type='str',),overlap=dict(type='bool',),limit=dict(type='int',),ignore_count=dict(type='int',),aging_time=dict(type='int',),bind_geoloc=dict(type='bool',),uuid=dict(type='str',)),
        active_rdt=dict(type='dict',range_factor=dict(type='int',),smooth_factor=dict(type='int',),mask=dict(type='str',),overlap=dict(type='bool',),limit=dict(type='int',),ignore_count=dict(type='int',),aging_time=dict(type='int',),bind_geoloc=dict(type='bool',),uuid=dict(type='str',))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/site/{site-name}"

    f_dict = {}
    f_dict["site-name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/site/{site-name}"

    f_dict = {}
    f_dict["site-name"] = module.params["site_name"]

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
        for k, v in payload["site"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["site"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["site"][k] = v
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
    payload = build_json("site", module)
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