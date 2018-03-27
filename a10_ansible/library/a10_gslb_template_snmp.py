#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_snmp
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    snmp-name:
        description:
            - Specify name of snmp template
    
    version:
        description:
            - 'v1': Version 1; 'v2c': Version 2c; 'v3': Version 3; choices:['v1', 'v2c', 'v3']
    
    community:
        description:
            - Specify community for version 2c (Community name)
    
    security-level:
        description:
            - 'no-auth': No authentication; 'auth-no-priv': Authentication, but no privacy; 'auth-priv': Authentication and privacy; choices:['no-auth', 'auth-no-priv', 'auth-priv']
    
    oid:
        description:
            - Specify OID
    
    interface:
        description:
            - Specify Interface ID
    
    username:
        description:
            - Specify username (User name)
    
    auth-key:
        description:
            - Specify authentication key (Specify key)
    
    priv-key:
        description:
            - Specify privacy key (Specify key)
    
    host:
        description:
            - Specify host (Host name or ip address)
    
    port:
        description:
            - Specify port, default is 161 (Port Number, default is 161)
    
    interval:
        description:
            - Specify interval, default is 3 (Interval, unit: second, default is 3)
    
    auth-proto:
        description:
            - 'sha': SHA; 'md5': MD5; choices:['sha', 'md5']
    
    priv-proto:
        description:
            - 'aes': AES; 'des': DES; choices:['aes', 'des']
    
    context-name:
        description:
            - Specify context name
    
    context-engine-id:
        description:
            - Specify context engine ID
    
    security-engine-id:
        description:
            - Specify security engine ID
    
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
AVAILABLE_PROPERTIES = {"auth_key","auth_proto","community","context_engine_id","context_name","host","interface","interval","oid","port","priv_key","priv_proto","security_engine_id","security_level","snmp_name","user_tag","username","uuid","version",}

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
        
        auth_key=dict(
            type='str' 
        ),
        auth_proto=dict(
            type='enum' , choices=['sha', 'md5']
        ),
        community=dict(
            type='str' 
        ),
        context_engine_id=dict(
            type='str' 
        ),
        context_name=dict(
            type='str' 
        ),
        host=dict(
            type='str' 
        ),
        interface=dict(
            type='str' 
        ),
        interval=dict(
            type='str' 
        ),
        oid=dict(
            type='str' 
        ),
        port=dict(
            type='str' 
        ),
        priv_key=dict(
            type='str' 
        ),
        priv_proto=dict(
            type='enum' , choices=['aes', 'des']
        ),
        security_engine_id=dict(
            type='str' 
        ),
        security_level=dict(
            type='enum' , choices=['no-auth', 'auth-no-priv', 'auth-priv']
        ),
        snmp_name=dict(
            type='str' , required=True
        ),
        user_tag=dict(
            type='str' 
        ),
        username=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        version=dict(
            type='enum' , choices=['v1', 'v2c', 'v3']
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/template/snmp/{snmp-name}"
    f_dict = {}
    
    f_dict["snmp-name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/template/snmp/{snmp-name}"
    f_dict = {}
    
    f_dict["snmp-name"] = module.params["snmp-name"]

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
    payload = build_json("snmp", module)
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
    payload = build_json("snmp", module)
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