#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_ospf
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    process-id:
        description:
            - OSPFv3 process tag
    
    abr-type-option:
        description:
            - 'cisco': Alternative ABR, Cisco implementation (RFC3509); 'ibm': Alternative ABR, IBM implementation (RFC3509); 'standard': Standard behavior (RFC2328); choices:['cisco', 'ibm', 'standard']
    
    auto-cost-reference-bandwidth:
        description:
            - Use reference bandwidth method to assign OSPF cost (The reference bandwidth in terms of Mbits per second)
    
    bfd-all-interfaces:
        description:
            - Enable BFD on all interfaces
    
    default-metric:
        description:
            - Set metric of redistributed routes (Default metric)
    
    distribute-internal-list:
        
    
    log-adjacency-changes:
        description:
            - 'detail': Log changes in adjacency state; 'disable': Disable logging; choices:['detail', 'disable']
    
    ha-standby-extra-cost:
        
    
    max-concurrent-dd:
        description:
            - Maximum number allowed to process DD concurrently (Number of DD process)
    
    passive-interface:
        
    
    router-id:
        description:
            - router-id for the OSPF process (OSPFv3 router-id in IPv4 address format)
    
    timers:
        
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    default-information:
        
    
    area-list:
        
    
    redistribute:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"abr_type_option","area_list","auto_cost_reference_bandwidth","bfd_all_interfaces","default_information","default_metric","distribute_internal_list","ha_standby_extra_cost","log_adjacency_changes","max_concurrent_dd","passive_interface","process_id","redistribute","router_id","timers","user_tag","uuid",}

# our imports go at the top so we fail fast.
from a10_ansible.axapi_http import client_factory
from a10_ansible import errors as a10_ex

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
        
        abr_type_option=dict(
            type='enum' , choices=['cisco', 'ibm', 'standard']
        ),
        area_list=dict(
            type='str' 
        ),
        auto_cost_reference_bandwidth=dict(
            type='str' 
        ),
        bfd_all_interfaces=dict(
            type='str' 
        ),
        default_information=dict(
            type='str' 
        ),
        default_metric=dict(
            type='str' 
        ),
        distribute_internal_list=dict(
            type='str' 
        ),
        ha_standby_extra_cost=dict(
            type='str' 
        ),
        log_adjacency_changes=dict(
            type='enum' , choices=['detail', 'disable']
        ),
        max_concurrent_dd=dict(
            type='str' 
        ),
        passive_interface=dict(
            type='str' 
        ),
        process_id=dict(
            type='str' , required=True
        ),
        redistribute=dict(
            type='str' 
        ),
        router_id=dict(
            type='str' 
        ),
        timers=dict(
            type='str' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/router/ipv6/ospf/{process-id}"
    f_dict = {}
    
    f_dict["process-id"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/ipv6/ospf/{process-id}"
    f_dict = {}
    
    f_dict["process-id"] = module.params["process-id"]

    return url_base.format(**f_dict)


def build_envelope(title, data):
    return {
        title: data
    }

def build_json(title, module):
    rv = {}
    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v:
            rx = x.replace("_", "-")
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

def exists(module):
    try:
        module.client.get(existing_url(module))
        return True
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("ospf", module)
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

def update(module, result):
    payload = build_json("ospf", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
        result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result):
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result)

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

    valid, validation_errors = validate(module.params)
    map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)

    if state == 'present':
        result = present(module, result)
    elif state == 'absent':
        result = absent(module, result)
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