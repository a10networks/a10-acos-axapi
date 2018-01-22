#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_ospf-ip
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    ip-addr:
        description:
            - Address of interface
    
    authentication:
        description:
            - Enable authentication
    
    value:
        description:
            - 'message-digest': Use message-digest authentication; 'null': Use no authentication; choices:['message-digest', 'null']
    
    authentication-key:
        description:
            - Authentication password (key) (The OSPF password (key))
    
    cost:
        description:
            - Interface cost
    
    database-filter:
        description:
            - 'all': Filter all LSA; choices:['all']
    
    out:
        description:
            - Outgoing LSA
    
    dead-interval:
        description:
            - Interval after which a neighbor is declared dead (Seconds)
    
    hello-interval:
        description:
            - Time between HELLO packets (Seconds)
    
    message-digest-cfg:
        
    
    mtu-ignore:
        description:
            - Ignores the MTU in DBD packets
    
    priority:
        description:
            - Router priority
    
    retransmit-interval:
        description:
            - Time between retransmitting lost link state advertisements (Seconds)
    
    transmit-delay:
        description:
            - Link state transmit delay (Seconds)
    
    uuid:
        description:
            - uuid of the object
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"authentication","authentication_key","cost","database_filter","dead_interval","hello_interval","ip_addr","message_digest_cfg","mtu_ignore","out","priority","retransmit_interval","transmit_delay","uuid","value",}

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
        
        authentication=dict(
            type='str' 
        ),
        authentication_key=dict(
            type='str' 
        ),
        cost=dict(
            type='str' 
        ),
        database_filter=dict(
            type='enum' , choices=['all']
        ),
        dead_interval=dict(
            type='str' 
        ),
        hello_interval=dict(
            type='str' 
        ),
        ip_addr=dict(
            type='str' , required=True
        ),
        message_digest_cfg=dict(
            type='str' 
        ),
        mtu_ignore=dict(
            type='str' 
        ),
        out=dict(
            type='str' 
        ),
        priority=dict(
            type='str' 
        ),
        retransmit_interval=dict(
            type='str' 
        ),
        transmit_delay=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        value=dict(
            type='enum' , choices=['message-digest', 'null']
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/interface/lif/{ifnum}/ip/ospf/ospf-ip/{ip-addr}"
    f_dict = {}
    
    f_dict["ip-addr"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/lif/{ifnum}/ip/ospf/ospf-ip/{ip-addr}"
    f_dict = {}
    
    f_dict["ip-addr"] = module.params["ip-addr"]

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
    payload = build_json("ospf-ip", module)
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
    payload = build_json("ospf-ip", module)
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