#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_ike-gateway
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - IKE-gateway name
    
    ike-version:
        description:
            - 'v1': IKEv1 key exchange; 'v2': IKEv2 key exchange; choices:['v1', 'v2']
    
    mode:
        description:
            - 'main': Negotiate Main mode (Default); 'aggressive': Negotiate Aggressive mode; choices:['main', 'aggressive']
    
    auth-method:
        description:
            - 'preshare-key': Authenticate the remote gateway using a pre-shared key (Default); 'rsa-signature': Authenticate the remote gateway using an RSA certificate; 'ecdsa-signature': Authenticate the remote gateway using an ECDSA certificate; choices:['preshare-key', 'rsa-signature', 'ecdsa-signature']
    
    preshare-key-value:
        description:
            - pre-shared key
    
    preshare-key-encrypted:
        description:
            - Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED pre-shared key string)
    
    key:
        description:
            - Private Key
    
    key-passphrase:
        description:
            - Private Key Pass Phrase
    
    key-passphrase-encrypted:
        description:
            - Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED key string)
    
    vrid:
        
    
    local-cert:
        
    
    remote-ca-cert:
        
    
    local-id:
        description:
            - Local Gateway Identity
    
    remote-id:
        description:
            - Remote Gateway Identity
    
    enc-cfg:
        
    
    dh-group:
        description:
            - '1': Diffie-Hellman group 1 - 768-bit(Default); '2': Diffie-Hellman group 2 - 1024-bit; '5': Diffie-Hellman group 5 - 1536-bit; '14': Diffie-Hellman group 14 - 2048-bit; '15': Diffie-Hellman group 15 - 3072-bit; '16': Diffie-Hellman group 16 - 4096-bit; '18': Diffie-Hellman group 18 - 8192-bit; '19': Diffie-Hellman group 19 - 256-bit Elliptic Curve; '20': Diffie-Hellman group 20 - 384-bit Elliptic Curve; choices:['1', '2', '5', '14', '15', '16', '18', '19', '20']
    
    local-address:
        
    
    remote-address:
        
    
    lifetime:
        description:
            - IKE SA age in seconds
    
    nat-traversal:
        
    
    dpd:
        
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    sampling-enable:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"auth_method","dh_group","dpd","enc_cfg","ike_version","key","key_passphrase","key_passphrase_encrypted","lifetime","local_address","local_cert","local_id","mode","name","nat_traversal","preshare_key_encrypted","preshare_key_value","remote_address","remote_ca_cert","remote_id","sampling_enable","user_tag","uuid","vrid",}

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
        
        auth_method=dict(
            type='enum' , choices=['preshare-key', 'rsa-signature', 'ecdsa-signature']
        ),
        dh_group=dict(
            type='enum' , choices=['1', '2', '5', '14', '15', '16', '18', '19', '20']
        ),
        dpd=dict(
            type='str' 
        ),
        enc_cfg=dict(
            type='str' 
        ),
        ike_version=dict(
            type='enum' , choices=['v1', 'v2']
        ),
        key=dict(
            type='str' 
        ),
        key_passphrase=dict(
            type='str' 
        ),
        key_passphrase_encrypted=dict(
            type='str' 
        ),
        lifetime=dict(
            type='str' 
        ),
        local_address=dict(
            type='str' 
        ),
        local_cert=dict(
            type='str' 
        ),
        local_id=dict(
            type='str' 
        ),
        mode=dict(
            type='enum' , choices=['main', 'aggressive']
        ),
        name=dict(
            type='str' , required=True
        ),
        nat_traversal=dict(
            type='str' 
        ),
        preshare_key_encrypted=dict(
            type='str' 
        ),
        preshare_key_value=dict(
            type='str' 
        ),
        remote_address=dict(
            type='str' 
        ),
        remote_ca_cert=dict(
            type='str' 
        ),
        remote_id=dict(
            type='str' 
        ),
        sampling_enable=dict(
            type='str' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        vrid=dict(
            type='str' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vpn/ike-gateway/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vpn/ike-gateway/{name}"
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
    payload = build_json("ike-gateway", module)
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
    payload = build_json("ike-gateway", module)
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