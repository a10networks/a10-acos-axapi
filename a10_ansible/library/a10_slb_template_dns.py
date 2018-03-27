#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_slb_template_dns
description:
    - DNS template
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - DNS Template Name
    
    default-policy:
        description:
            - 'nocache': Cache disable; 'cache': Cache enable; choices:['nocache', 'cache']
    
    disable-dns-template:
        description:
            - Disable DNS template
    
    period:
        description:
            - Period in minutes
    
    drop:
        description:
            - Drop the malformed query
    
    forward:
        description:
            - Forward to service group (Service group name)
    
    max-query-length:
        description:
            - Define Maximum DNS Query Length, default is unlimited (Specify Maximum Length)
    
    max-cache-entry-size:
        description:
            - Define maximum cache entry size (Maximum cache entry size per VIP)
    
    max-cache-size:
        description:
            - Define maximum cache size (Maximum cache entry per VIP)
    
    enable-cache-sharing:
        description:
            - Enable DNS cache sharing
    
    redirect-to-tcp-port:
        description:
            - Direct the client to retry with TCP for DNS UDP request
    
    query-id-switch:
        description:
            - Use DNS query ID to create sesion
    
    dnssec-service-group:
        description:
            - Use different service group if DNSSEC DO bit set (Service Group Name)
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    class-list:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["class_list","default_policy","disable_dns_template","dnssec_service_group","drop","enable_cache_sharing","forward","max_cache_entry_size","max_cache_size","max_query_length","name","period","query_id_switch","redirect_to_tcp_port","user_tag","uuid",]

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
        
        class_list=dict(
            type='str' 
        ),
        default_policy=dict(
            type='str' , choices=['nocache', 'cache']
        ),
        disable_dns_template=dict(
            type='bool' 
        ),
        dnssec_service_group=dict(
            type='str' 
        ),
        drop=dict(
            type='bool' 
        ),
        enable_cache_sharing=dict(
            type='bool' 
        ),
        forward=dict(
            type='str' 
        ),
        max_cache_entry_size=dict(
            type='int' 
        ),
        max_cache_size=dict(
            type='int' 
        ),
        max_query_length=dict(
            type='int' 
        ),
        name=dict(
            type='str' , required=True
        ),
        period=dict(
            type='int' 
        ),
        query_id_switch=dict(
            type='bool' 
        ),
        redirect_to_tcp_port=dict(
            type='bool' 
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
    url_base = "/axapi/v3/slb/template/dns/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/dns/{name}"
    f_dict = {}
    
    f_dict["name"] = module.params["name"]

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
        # else:
        #     del module.params[x]

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
    payload = build_json("dns", module)
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
    payload = build_json("dns", module)
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

    valid = True

    if state == 'present':
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