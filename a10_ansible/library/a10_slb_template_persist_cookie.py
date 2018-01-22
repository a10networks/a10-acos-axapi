#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_cookie
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - Cookie persistence (Cookie persistence template name)
    
    domain:
        description:
            - Set cookie domain
    
    dont-honor-conn-rules:
        description:
            - Do not observe connection rate rules
    
    expire:
        description:
            - Set cookie expiration time (Expiration in seconds)
    
    insert-always:
        description:
            - Insert persist cookie to every reponse
    
    encrypt-level:
        description:
            - Encryption level for cookie name / value
    
    pass-phrase:
        description:
            - Set passphrase for encryption
    
    encrypted:
        description:
            - Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED password string)
    
    cookie-name:
        description:
            - Set cookie name (Cookie name, default "sto-id")
    
    path:
        description:
            - Set cookie path (Cookie path, default is "/")
    
    pass-thru:
        description:
            - Pass thru mode - Server sends the persist cookie
    
    secure:
        description:
            - Enable secure attribute
    
    httponly:
        description:
            - Enable HttpOnly attribute
    
    match-type:
        description:
            - Persist for server, default is port
    
    server:
        description:
            - Persist to the same server, default is port
    
    server-service-group:
        description:
            - Persist to the same server and within the same service group
    
    scan-all-members:
        description:
            - Persist within the same server SCAN
    
    service-group:
        description:
            - Persist within the same service group
    
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
AVAILABLE_PROPERTIES = {"cookie_name","domain","dont_honor_conn_rules","encrypt_level","encrypted","expire","httponly","insert_always","match_type","name","pass_phrase","pass_thru","path","scan_all_members","secure","server","server_service_group","service_group","user_tag","uuid",}

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
        
        cookie_name=dict(
            type='str' 
        ),
        domain=dict(
            type='str' 
        ),
        dont_honor_conn_rules=dict(
            type='str' 
        ),
        encrypt_level=dict(
            type='str' 
        ),
        encrypted=dict(
            type='str' 
        ),
        expire=dict(
            type='str' 
        ),
        httponly=dict(
            type='str' 
        ),
        insert_always=dict(
            type='str' 
        ),
        match_type=dict(
            type='str' 
        ),
        name=dict(
            type='str' , required=True
        ),
        pass_phrase=dict(
            type='str' 
        ),
        pass_thru=dict(
            type='str' 
        ),
        path=dict(
            type='str' 
        ),
        scan_all_members=dict(
            type='str' 
        ),
        secure=dict(
            type='str' 
        ),
        server=dict(
            type='str' 
        ),
        server_service_group=dict(
            type='str' 
        ),
        service_group=dict(
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
    url_base = "/axapi/v3/slb/template/persist/cookie/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/persist/cookie/{name}"
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
    payload = build_json("cookie", module)
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
    payload = build_json("cookie", module)
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