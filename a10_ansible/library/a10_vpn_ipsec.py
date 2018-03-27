#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_ipsec
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - IPsec name
    
    ike-gateway:
        description:
            - Gateway to use for IPsec SA
    
    mode:
        description:
            - 'tunnel': Encapsulating the packet in IPsec tunnel mode (Default); choices:['tunnel']
    
    proto:
        description:
            - 'esp': Encapsulating security protocol (Default); choices:['esp']
    
    dh-group:
        description:
            - '0': Diffie-Hellman group 0 (Default); '1': Diffie-Hellman group 1 - 768-bits; '2': Diffie-Hellman group 2 - 1024-bits; '5': Diffie-Hellman group 5 - 1536-bits; '14': Diffie-Hellman group 14 - 2048-bits; '15': Diffie-Hellman group 15 - 3072-bits; '16': Diffie-Hellman group 16 - 4096-bits; '18': Diffie-Hellman group 18 - 8192-bits; '19': Diffie-Hellman group 19 - 256-bit Elliptic Curve; '20': Diffie-Hellman group 20 - 384-bit Elliptic Curve; choices:['0', '1', '2', '5', '14', '15', '16', '18', '19', '20']
    
    enc-cfg:
        
    
    lifetime:
        description:
            - IPsec SA age in seconds
    
    lifebytes:
        description:
            - IPsec SA age in megabytes (0 indicates unlimited bytes)
    
    anti-replay-window:
        description:
            - '0': Disable Anti-Replay Window Check; '32': Window size of 32; '64': Window size of 64; '128': Window size of 128; '256': Window size of 256; '512': Window size of 512; '1024': Window size of 1024; choices:['0', '32', '64', '128', '256', '512', '1024']
    
    up:
        description:
            - Initiates SA negotiation to bring the IPsec connection up
    
    sequence-number-disable:
        description:
            - Do not use incremental sequence number in the ESP header
    
    traffic-selector:
        
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    sampling-enable:
        
    
    bind-tunnel:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"anti_replay_window","bind_tunnel","dh_group","enc_cfg","ike_gateway","lifebytes","lifetime","mode","name","proto","sampling_enable","sequence_number_disable","traffic_selector","up","user_tag","uuid",}

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
        
        anti_replay_window=dict(
            type='enum' , choices=['0', '32', '64', '128', '256', '512', '1024']
        ),
        bind_tunnel=dict(
            type='str' 
        ),
        dh_group=dict(
            type='enum' , choices=['0', '1', '2', '5', '14', '15', '16', '18', '19', '20']
        ),
        enc_cfg=dict(
            type='str' 
        ),
        ike_gateway=dict(
            type='str' 
        ),
        lifebytes=dict(
            type='str' 
        ),
        lifetime=dict(
            type='str' 
        ),
        mode=dict(
            type='enum' , choices=['tunnel']
        ),
        name=dict(
            type='str' , required=True
        ),
        proto=dict(
            type='enum' , choices=['esp']
        ),
        sampling_enable=dict(
            type='str' 
        ),
        sequence_number_disable=dict(
            type='str' 
        ),
        traffic_selector=dict(
            type='str' 
        ),
        up=dict(
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
    url_base = "/axapi/v3/vpn/ipsec/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vpn/ipsec/{name}"
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
    payload = build_json("ipsec", module)
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
    payload = build_json("ipsec", module)
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