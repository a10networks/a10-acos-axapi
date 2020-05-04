#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_gslb_site_slb_dev
description:
    - Specify a SLB device for the GSLB site
short_description: Configures A10 gslb.site.slb-dev
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
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    site_name:
        description:
        - Key to identify parent object
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            dev_gw_state:
                description:
                - "Field dev_gw_state"
            vip_server:
                description:
                - "Field vip_server"
            dev_name:
                description:
                - "Field dev_name"
            dev_ip_cnt:
                description:
                - "Field dev_ip_cnt"
            dev_attr:
                description:
                - "Field dev_attr"
            dev_ip:
                description:
                - "Field dev_ip"
            device_name:
                description:
                - "Specify SLB device name"
            dev_state:
                description:
                - "Field dev_state"
            dev_session_num:
                description:
                - "Field dev_session_num"
            dev_admin_preference:
                description:
                - "Field dev_admin_preference"
            client_ldns_list:
                description:
                - "Field client_ldns_list"
            dev_session_util:
                description:
                - "Field dev_session_util"
    health_check_action:
        description:
        - "'health-check'= Enable health Check; 'health-check-disable'= Disable health check; "
        required: False
    client_ip:
        description:
        - "Specify client IP address"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    proto_aging_time:
        description:
        - "Specify GSLB Protocol aging time, default is 60"
        required: False
    device_name:
        description:
        - "Specify SLB device name"
        required: True
    proto_compatible:
        description:
        - "Run GSLB Protocol in compatible mode"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    auto_map:
        description:
        - "Enable DNS Auto Mapping"
        required: False
    msg_format_acos_2x:
        description:
        - "Run GSLB Protocol in compatible mode with a ACOS 2.x GSLB peer"
        required: False
    rdt_value:
        description:
        - "Specify Round-delay-time"
        required: False
    gateway_ip_addr:
        description:
        - "IP address"
        required: False
    vip_server:
        description:
        - "Field vip_server"
        required: False
        suboptions:
            vip_server_v4_list:
                description:
                - "Field vip_server_v4_list"
            vip_server_v6_list:
                description:
                - "Field vip_server_v6_list"
            vip_server_name_list:
                description:
                - "Field vip_server_name_list"
    ip_address:
        description:
        - "IP address"
        required: False
    proto_aging_fast:
        description:
        - "Fast GSLB Protocol aging"
        required: False
    auto_detect:
        description:
        - "'ip'= Service IP only; 'port'= Service Port only; 'ip-and-port'= Both service IP and service port; 'disabled'= disable auto-detect; "
        required: False
    max_client:
        description:
        - "Specify maximum number of clients, default is 32768"
        required: False
    admin_preference:
        description:
        - "Specify administrative preference (Specify admin-preference value,default is 100)"
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
AVAILABLE_PROPERTIES = ["admin_preference","auto_detect","auto_map","client_ip","device_name","gateway_ip_addr","health_check_action","ip_address","max_client","msg_format_acos_2x","oper","proto_aging_fast","proto_aging_time","proto_compatible","rdt_value","user_tag","uuid","vip_server",]

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
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict', dev_gw_state=dict(type='str', ),vip_server=dict(type='dict', oper=dict(type='dict', ),vip_server_v4_list=dict(type='list', oper=dict(type='dict', dev_vip_addr=dict(type='str', ),dev_vip_state=dict(type='str', ),dev_vip_port_list=dict(type='list', dev_vip_port_num=dict(type='int', ),dev_vip_port_state=dict(type='str', ))),ipv4=dict(type='str', required=True, )),vip_server_v6_list=dict(type='list', oper=dict(type='dict', dev_vip_addr=dict(type='str', ),dev_vip_state=dict(type='str', ),dev_vip_port_list=dict(type='list', dev_vip_port_num=dict(type='int', ),dev_vip_port_state=dict(type='str', ))),ipv6=dict(type='str', required=True, )),vip_server_name_list=dict(type='list', oper=dict(type='dict', dev_vip_addr=dict(type='str', ),dev_vip_state=dict(type='str', ),dev_vip_port_list=dict(type='list', dev_vip_port_num=dict(type='int', ),dev_vip_port_state=dict(type='str', ))),vip_name=dict(type='str', required=True, ))),dev_name=dict(type='str', ),dev_ip_cnt=dict(type='int', ),dev_attr=dict(type='str', ),dev_ip=dict(type='str', ),device_name=dict(type='str', required=True, ),dev_state=dict(type='str', ),dev_session_num=dict(type='int', ),dev_admin_preference=dict(type='int', ),client_ldns_list=dict(type='list', client_ip=dict(type='str', ),age=dict(type='int', ),rdt_sample1=dict(type='int', ),rdt_sample2=dict(type='int', ),rdt_sample3=dict(type='int', ),rdt_sample4=dict(type='int', ),rdt_sample5=dict(type='int', ),rdt_sample6=dict(type='int', ),rdt_sample7=dict(type='int', ),rdt_sample8=dict(type='int', ),ntype=dict(type='str', )),dev_session_util=dict(type='int', )),
        health_check_action=dict(type='str', choices=['health-check','health-check-disable']),
        client_ip=dict(type='str', ),
        uuid=dict(type='str', ),
        proto_aging_time=dict(type='int', ),
        device_name=dict(type='str', required=True, ),
        proto_compatible=dict(type='bool', ),
        user_tag=dict(type='str', ),
        auto_map=dict(type='bool', ),
        msg_format_acos_2x=dict(type='bool', ),
        rdt_value=dict(type='int', ),
        gateway_ip_addr=dict(type='str', ),
        vip_server=dict(type='dict', vip_server_v4_list=dict(type='list', sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all','dev_vip_hits'])),ipv4=dict(type='str', required=True, ),uuid=dict(type='str', )),vip_server_v6_list=dict(type='list', sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all','dev_vip_hits'])),uuid=dict(type='str', ),ipv6=dict(type='str', required=True, )),vip_server_name_list=dict(type='list', sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all','dev_vip_hits'])),vip_name=dict(type='str', required=True, ),uuid=dict(type='str', ))),
        ip_address=dict(type='str', ),
        proto_aging_fast=dict(type='bool', ),
        auto_detect=dict(type='str', choices=['ip','port','ip-and-port','disabled']),
        max_client=dict(type='int', ),
        admin_preference=dict(type='int', )
    ))
   
    # Parent keys
    rv.update(dict(
        site_name=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/site/{site_name}/slb-dev/{device-name}"

    f_dict = {}
    f_dict["device-name"] = ""
    f_dict["site_name"] = module.params["site_name"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/site/{site_name}/slb-dev/{device-name}"

    f_dict = {}
    f_dict["device-name"] = module.params["device_name"]
    f_dict["site_name"] = module.params["site_name"]

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["slb-dev"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["slb-dev"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["slb-dev"][k] = v
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
    payload = build_json("slb-dev", module)
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