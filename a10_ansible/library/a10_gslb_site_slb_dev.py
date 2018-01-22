#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_slb-dev
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    device-name:
        description:
            - Specify SLB device name
    
    ip-address:
        description:
            - IP address
    
    admin-preference:
        description:
            - Specify administrative preference (Specify admin-preference value,default is 100)
    
    client-ip:
        description:
            - Specify client IP address
    
    rdt-value:
        description:
            - Specify Round-delay-time
    
    auto-detect:
        description:
            - 'ip': Service IP only; 'port': Service Port only; 'ip-and-port': Both service IP and service port; 'disabled': disable auto-detect; choices:['ip', 'port', 'ip-and-port', 'disabled']
    
    auto-map:
        description:
            - Enable DNS Auto Mapping
    
    max-client:
        description:
            - Specify maximum number of clients, default is 32768
    
    proto-aging-time:
        description:
            - Specify GSLB Protocol aging time, default is 60
    
    proto-aging-fast:
        description:
            - Fast GSLB Protocol aging
    
    health-check-action:
        description:
            - 'health-check': Enable health Check; 'health-check-disable': Disable health check; choices:['health-check', 'health-check-disable']
    
    gateway-ip-addr:
        description:
            - IP address
    
    proto-compatible:
        description:
            - Run GSLB Protocol in compatible mode
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    vip-server:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"admin_preference","auto_detect","auto_map","client_ip","device_name","gateway_ip_addr","health_check_action","ip_address","max_client","proto_aging_fast","proto_aging_time","proto_compatible","rdt_value","user_tag","uuid","vip_server",}

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
        
        admin_preference=dict(
            type='str' 
        ),
        auto_detect=dict(
            type='enum' , choices=['ip', 'port', 'ip-and-port', 'disabled']
        ),
        auto_map=dict(
            type='str' 
        ),
        client_ip=dict(
            type='str' 
        ),
        device_name=dict(
            type='str' , required=True
        ),
        gateway_ip_addr=dict(
            type='str' 
        ),
        health_check_action=dict(
            type='enum' , choices=['health-check', 'health-check-disable']
        ),
        ip_address=dict(
            type='str' 
        ),
        max_client=dict(
            type='str' 
        ),
        proto_aging_fast=dict(
            type='str' 
        ),
        proto_aging_time=dict(
            type='str' 
        ),
        proto_compatible=dict(
            type='str' 
        ),
        rdt_value=dict(
            type='str' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        vip_server=dict(
            type='str' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/site/{site-name}/slb-dev/{device-name}"
    f_dict = {}
    
    f_dict["device-name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/site/{site-name}/slb-dev/{device-name}"
    f_dict = {}
    
    f_dict["device-name"] = module.params["device-name"]

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
    payload = build_json("slb-dev", module)
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
    payload = build_json("slb-dev", module)
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