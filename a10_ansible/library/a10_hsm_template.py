#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_template
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    template-name:
        description:
            - Specify Template name
    
    softhsm-enum:
        description:
            - 'softHSM': software implementation of a cryptographic store; 'thalesHSM': Thales HSM; choices:['softHSM', 'thalesHSM']
    
    hsm-dev:
        
    
    rfs-ip:
        description:
            - Specify Thales Remote File System
    
    rfs-port:
        description:
            - Specify Port
    
    sec-world:
        description:
            - Security World Name
    
    protection:
        description:
            - Specify Protection Method
    
    protection-module:
        description:
            - Module
    
    protection-ocs:
        description:
            - Operator Card Set
    
    softcard:
        description:
            - Softcard
    
    protection-softcard-hash:
        description:
            - Hash
    
    password:
        description:
            - Specify HSM Passphrase
    
    password-string:
        description:
            - Password (minimum 4 characters)
    
    encrypted:
        description:
            - Do NOT use this option manually (This is an A10 reserved keyword) (The ENCRYPTED password string)
    
    worker:
        description:
            - Specify number of workers for each data CPU
    
    health-check-interval:
        description:
            - Specify Thales HSM Health Check Interval
    
    enroll-timeout:
        description:
            - Specify Enroll Timeout
    
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
AVAILABLE_PROPERTIES = {"encrypted","enroll_timeout","health_check_interval","hsm_dev","password","password_string","protection","protection_module","protection_ocs","protection_softcard_hash","rfs_ip","rfs_port","sec_world","softcard","softhsm_enum","template_name","user_tag","uuid","worker",}

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
        
        encrypted=dict(
            type='str' 
        ),
        enroll_timeout=dict(
            type='str' 
        ),
        health_check_interval=dict(
            type='str' 
        ),
        hsm_dev=dict(
            type='str' 
        ),
        password=dict(
            type='str' 
        ),
        password_string=dict(
            type='str' 
        ),
        protection=dict(
            type='str' 
        ),
        protection_module=dict(
            type='str' 
        ),
        protection_ocs=dict(
            type='str' 
        ),
        protection_softcard_hash=dict(
            type='str' 
        ),
        rfs_ip=dict(
            type='str' 
        ),
        rfs_port=dict(
            type='str' 
        ),
        sec_world=dict(
            type='str' 
        ),
        softcard=dict(
            type='str' 
        ),
        softhsm_enum=dict(
            type='enum' , choices=['softHSM', 'thalesHSM']
        ),
        template_name=dict(
            type='str' , required=True
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        worker=dict(
            type='str' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/hsm/template/{template-name}"
    f_dict = {}
    
    f_dict["template-name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/hsm/template/{template-name}"
    f_dict = {}
    
    f_dict["template-name"] = module.params["template-name"]

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
    payload = build_json("template", module)
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
    payload = build_json("template", module)
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