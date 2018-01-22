#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_instance
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - Specify LDAP authentication server name
    
    host:
        
    
    base:
        description:
            - Specify the LDAP server's search base
    
    port:
        description:
            - Specify the LDAP server's authentication port, default is 389
    
    port-hm:
        description:
            - Check port's health status
    
    port-hm-disable:
        description:
            - Disable configured port health check configuration
    
    pwdmaxage:
        description:
            - Specify the LDAP server's default password expiration time (in seconds) (The LDAP server's default password expiration time (in seconds), default is 0 (no expiration))
    
    admin-dn:
        description:
            - The LDAP server's admin DN
    
    admin-secret:
        description:
            - Specify the LDAP server's admin secret password
    
    secret-string:
        description:
            - secret password
    
    encrypted:
        description:
            - Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED secret string)
    
    timeout:
        description:
            - Specify timout for LDAP, default is 10 seconds (The timeout, default is 10 seconds)
    
    dn-attribute:
        description:
            - Specify Distinguished Name attribute, default is CN
    
    default-domain:
        description:
            - Specify default domain for LDAP
    
    bind-with-dn:
        description:
            - Enforce using DN for LDAP binding(All user input name will be used to create DN)
    
    derive-bind-dn:
        
    
    health-check:
        description:
            - Check server's health status
    
    health-check-string:
        description:
            - Health monitor name
    
    health-check-disable:
        description:
            - Disable configured health check configuration
    
    protocol:
        description:
            - 'ldap': Use LDAP (default); 'ldaps': Use LDAP over SSL; 'starttls': Use LDAP StartTLS; choices:['ldap', 'ldaps', 'starttls']
    
    ca-cert:
        description:
            - Specify the LDAPS CA cert filename (Trusted LDAPS CA cert filename)
    
    ldaps-conn-reuse-idle-timeout:
        description:
            - Specify LDAPS connection reuse idle timeout value (in seconds) (Specify idle timeout value (in seconds), default is 0 (not reuse LDAPS connection))
    
    auth-type:
        description:
            - 'ad': Active Directory. Default; 'open-ldap': OpenLDAP; choices:['ad', 'open-ldap']
    
    prompt-pw-change-before-exp:
        description:
            - Prompt user to change password before expiration in N days. This option only takes effect when server type is AD (Prompt user to change password before expiration in N days, default is not to prompt the user)
    
    uuid:
        description:
            - uuid of the object
    
    sampling-enable:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"admin_dn","admin_secret","auth_type","base","bind_with_dn","ca_cert","default_domain","derive_bind_dn","dn_attribute","encrypted","health_check","health_check_disable","health_check_string","host","ldaps_conn_reuse_idle_timeout","name","port","port_hm","port_hm_disable","prompt_pw_change_before_exp","protocol","pwdmaxage","sampling_enable","secret_string","timeout","uuid",}

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
        
        admin_dn=dict(
            type='str' 
        ),
        admin_secret=dict(
            type='str' 
        ),
        auth_type=dict(
            type='enum' , choices=['ad', 'open-ldap']
        ),
        base=dict(
            type='str' 
        ),
        bind_with_dn=dict(
            type='str' 
        ),
        ca_cert=dict(
            type='str' 
        ),
        default_domain=dict(
            type='str' 
        ),
        derive_bind_dn=dict(
            type='str' 
        ),
        dn_attribute=dict(
            type='str' 
        ),
        encrypted=dict(
            type='str' 
        ),
        health_check=dict(
            type='str' 
        ),
        health_check_disable=dict(
            type='str' 
        ),
        health_check_string=dict(
            type='str' 
        ),
        host=dict(
            type='str' 
        ),
        ldaps_conn_reuse_idle_timeout=dict(
            type='str' 
        ),
        name=dict(
            type='str' , required=True
        ),
        port=dict(
            type='str' 
        ),
        port_hm=dict(
            type='str' 
        ),
        port_hm_disable=dict(
            type='str' 
        ),
        prompt_pw_change_before_exp=dict(
            type='str' 
        ),
        protocol=dict(
            type='enum' , choices=['ldap', 'ldaps', 'starttls']
        ),
        pwdmaxage=dict(
            type='str' 
        ),
        sampling_enable=dict(
            type='str' 
        ),
        secret_string=dict(
            type='str' 
        ),
        timeout=dict(
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
    url_base = "/axapi/v3/aam/authentication/server/ldap/instance/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/server/ldap/instance/{name}"
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
    payload = build_json("instance", module)
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
    payload = build_json("instance", module)
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