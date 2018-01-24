#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_slb_template_virtual-server
description:
    - Virtual server template
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - Virtual server template name
    
    conn-limit:
        description:
            - Connection limit
    
    conn-limit-reset:
        description:
            - Send client reset when connection over limit
    
    conn-limit-no-logging:
        description:
            - Do not log connection over limit event
    
    conn-rate-limit:
        description:
            - Connection rate limit
    
    rate-interval:
        description:
            - '100ms': Use 100 ms as sampling interval; 'second': Use 1 second as sampling interval; choices:['100ms', 'second']
    
    conn-rate-limit-reset:
        description:
            - Send client reset when connection rate over limit
    
    conn-rate-limit-no-logging:
        description:
            - Do not log connection over limit event
    
    icmp-rate-limit:
        description:
            - ICMP rate limit (Normal rate limit. If exceeds this limit, drop the ICMP packet that goes over the limit)
    
    icmp-lockup:
        description:
            - Enter lockup state when ICMP rate exceeds lockup rate limit (Maximum rate limit. If exceeds this limit, drop all ICMP packet for a time period)
    
    icmp-lockup-period:
        description:
            - Lockup period (second)
    
    icmpv6-rate-limit:
        description:
            - ICMPv6 rate limit (Normal rate limit. If exceeds this limit, drop the ICMP packet that goes over the limit)
    
    icmpv6-lockup:
        description:
            - Enter lockup state when ICMP rate exceeds lockup rate limit (Maximum rate limit. If exceeds this limit, drop all ICMP packet for a time period)
    
    icmpv6-lockup-period:
        description:
            - Lockup period (second)
    
    tcp-stack-tfo-active-conn-limit:
        description:
            - The allowed active layer 7 tcp fast-open connection limit, default is zero (number)
    
    tcp-stack-tfo-cookie-time-limit:
        description:
            - The time limit (in seconds) that a layer 7 tcp fast-open cookie is valid, default is 60 seconds (number)
    
    tcp-stack-tfo-backoff-time:
        description:
            - The time tcp stack will wait before allowing new fast-open requests after security condition, default 600 seconds (number)
    
    subnet-gratuitous-arp:
        description:
            - Send gratuitous ARP for every IP in the subnet virtual server
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["conn_limit","conn_limit_no_logging","conn_limit_reset","conn_rate_limit","conn_rate_limit_no_logging","conn_rate_limit_reset","icmp_lockup","icmp_lockup_period","icmp_rate_limit","icmpv6_lockup","icmpv6_lockup_period","icmpv6_rate_limit","name","rate_interval","subnet_gratuitous_arp","tcp_stack_tfo_active_conn_limit","tcp_stack_tfo_backoff_time","tcp_stack_tfo_cookie_time_limit","user_tag","uuid",]

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
        
        conn_limit=dict(
            type='int' 
        ),
        conn_limit_no_logging=dict(
            type='bool' 
        ),
        conn_limit_reset=dict(
            type='bool' 
        ),
        conn_rate_limit=dict(
            type='int' 
        ),
        conn_rate_limit_no_logging=dict(
            type='bool' 
        ),
        conn_rate_limit_reset=dict(
            type='bool' 
        ),
        icmp_lockup=dict(
            type='int' 
        ),
        icmp_lockup_period=dict(
            type='int' 
        ),
        icmp_rate_limit=dict(
            type='int' 
        ),
        icmpv6_lockup=dict(
            type='int' 
        ),
        icmpv6_lockup_period=dict(
            type='int' 
        ),
        icmpv6_rate_limit=dict(
            type='int' 
        ),
        name=dict(
            type='str' , required=True
        ),
        rate_interval=dict(
            type='str' , choices=['100ms', 'second']
        ),
        subnet_gratuitous_arp=dict(
            type='bool' 
        ),
        tcp_stack_tfo_active_conn_limit=dict(
            type='int' 
        ),
        tcp_stack_tfo_backoff_time=dict(
            type='int' 
        ),
        tcp_stack_tfo_cookie_time_limit=dict(
            type='int' 
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
    url_base = "/axapi/v3/slb/template/virtual-server/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/virtual-server/{name}"
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
    payload = build_json("virtual-server", module)
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
    payload = build_json("virtual-server", module)
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