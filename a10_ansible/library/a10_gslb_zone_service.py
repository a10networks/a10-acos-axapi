#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_service
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    service-port:
        description:
            - Port number of the service
    
    service-name:
        description:
            - Specify the service name for the zone, * for wildcard
    
    action:
        description:
            - 'drop': Drop query; 'forward': Forward packet; 'ignore': Send empty response; 'reject': Send refuse response; choices:['drop', 'forward', 'ignore', 'reject']
    
    forward-type:
        description:
            - 'both': Forward both query and response; 'query': Forward query; 'response': Forward response; choices:['both', 'query', 'response']
    
    disable:
        description:
            - Disable
    
    health-check-gateway:
        description:
            - 'enable': Enable Gateway Status Check; 'disable': Disable Gateway Status Check; choices:['enable', 'disable']
    
    health-check-port:
        
    
    policy:
        description:
            - Specify policy for this service (Specify policy name)
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    sampling-enable:
        
    
    dns-a-record:
        
    
    dns-cname-record-list:
        
    
    dns-mx-record-list:
        
    
    dns-ns-record-list:
        
    
    dns-ptr-record-list:
        
    
    dns-srv-record-list:
        
    
    dns-naptr-record-list:
        
    
    dns-txt-record-list:
        
    
    dns-record-list:
        
    
    geo-location-list:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"action","disable","dns_a_record","dns_cname_record_list","dns_mx_record_list","dns_naptr_record_list","dns_ns_record_list","dns_ptr_record_list","dns_record_list","dns_srv_record_list","dns_txt_record_list","forward_type","geo_location_list","health_check_gateway","health_check_port","policy","sampling_enable","service_name","service_port","user_tag","uuid",}

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
        
        action=dict(
            type='enum' , choices=['drop', 'forward', 'ignore', 'reject']
        ),
        disable=dict(
            type='str' 
        ),
        dns_a_record=dict(
            type='str' 
        ),
        dns_cname_record_list=dict(
            type='str' 
        ),
        dns_mx_record_list=dict(
            type='str' 
        ),
        dns_naptr_record_list=dict(
            type='str' 
        ),
        dns_ns_record_list=dict(
            type='str' 
        ),
        dns_ptr_record_list=dict(
            type='str' 
        ),
        dns_record_list=dict(
            type='str' 
        ),
        dns_srv_record_list=dict(
            type='str' 
        ),
        dns_txt_record_list=dict(
            type='str' 
        ),
        forward_type=dict(
            type='enum' , choices=['both', 'query', 'response']
        ),
        geo_location_list=dict(
            type='str' 
        ),
        health_check_gateway=dict(
            type='enum' , choices=['enable', 'disable']
        ),
        health_check_port=dict(
            type='str' 
        ),
        policy=dict(
            type='str' 
        ),
        sampling_enable=dict(
            type='str' 
        ),
        service_name=dict(
            type='str' , required=True
        ),
        service_port=dict(
            type='str' , required=True
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
    url_base = "/axapi/v3/gslb/zone/{name}/service/{service-port}+{service-name}"
    f_dict = {}
    
    f_dict["service-port"] = ""
    f_dict["service-name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/zone/{name}/service/{service-port}+{service-name}"
    f_dict = {}
    
    f_dict["service-port"] = module.params["service-port"]
    f_dict["service-name"] = module.params["service-name"]

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
    payload = build_json("service", module)
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
    payload = build_json("service", module)
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