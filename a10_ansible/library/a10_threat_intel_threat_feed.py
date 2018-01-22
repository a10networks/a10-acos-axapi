#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_threat-feed
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    type:
        description:
            - 'webroot': Configure Webroot module options; choices:['webroot']
    
    server:
        description:
            - Server IP or Hostname
    
    port:
        description:
            - Port to query server(default 443)
    
    server-timeout:
        description:
            - Server Timeout in seconds (default: 15s)
    
    rtu-update-disable:
        description:
            - Disables real time updates(default enable)
    
    update-interval:
        description:
            - Interval to check for database or RTU updates(default 120 mins)
    
    use-mgmt-port:
        description:
            - Use management interface for all communication with threat-intel server
    
    log-level:
        description:
            - 'disable': Disable all logging; 'error': Log error events; 'warning': Log warning events and above; 'info': Log info events and above; 'debug': Log debug events and above; 'trace': enable all logs; choices:['disable', 'error', 'warning', 'info', 'debug', 'trace']
    
    proxy-host:
        description:
            - Proxy server hostname or IP address
    
    proxy-port:
        description:
            - Port to connect on proxy server
    
    proxy-auth-type:
        description:
            - 'ntlm': NTLM authentication(default); 'basic': Basic authentication; choices:['ntlm', 'basic']
    
    domain:
        description:
            - Realm for NTLM authentication
    
    proxy-username:
        description:
            - Username for proxy authentication
    
    proxy-password:
        description:
            - Password for proxy authentication
    
    secret-string:
        description:
            - password value
    
    encrypted:
        description:
            - Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED secret string)
    
    enable:
        description:
            - Enable module
    
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
AVAILABLE_PROPERTIES = {"domain","enable","encrypted","log_level","port","proxy_auth_type","proxy_host","proxy_password","proxy_port","proxy_username","rtu_update_disable","secret_string","server","server_timeout","type","update_interval","use_mgmt_port","user_tag","uuid",}

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
        
        domain=dict(
            type='str' 
        ),
        enable=dict(
            type='str' 
        ),
        encrypted=dict(
            type='str' 
        ),
        log_level=dict(
            type='enum' , choices=['disable', 'error', 'warning', 'info', 'debug', 'trace']
        ),
        port=dict(
            type='str' 
        ),
        proxy_auth_type=dict(
            type='enum' , choices=['ntlm', 'basic']
        ),
        proxy_host=dict(
            type='str' 
        ),
        proxy_password=dict(
            type='str' 
        ),
        proxy_port=dict(
            type='str' 
        ),
        proxy_username=dict(
            type='str' 
        ),
        rtu_update_disable=dict(
            type='str' 
        ),
        secret_string=dict(
            type='str' 
        ),
        server=dict(
            type='str' 
        ),
        server_timeout=dict(
            type='str' 
        ),
        type=dict(
            type='enum' , required=True, choices=['webroot']
        ),
        update_interval=dict(
            type='str' 
        ),
        use_mgmt_port=dict(
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
    url_base = "/axapi/v3/threat-intel/threat-feed/{type}"
    f_dict = {}
    
    f_dict["type"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/threat-intel/threat-feed/{type}"
    f_dict = {}
    
    f_dict["type"] = module.params["type"]

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
    payload = build_json("threat-feed", module)
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
    payload = build_json("threat-feed", module)
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