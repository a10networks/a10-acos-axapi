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
    
    name:
        description:
            - Authentication template name
    
    type:
        description:
            - 'saml': SAML authentication template; 'standard': Standard authentication template; choices:['saml', 'standard']
    
    auth-sess-mode:
        description:
            - 'cookie-based': Track auth-session by cookie (default); 'ip-based': Track auth-session by client IP; choices:['cookie-based', 'ip-based']
    
    saml-sp:
        description:
            - Specify SAML service provider
    
    saml-idp:
        description:
            - Specify SAML identity provider
    
    cookie-domain:
        
    
    cookie-domain-group:
        
    
    cookie-max-age:
        description:
            - Configure Max-Age for authentication session cookie (Configure Max-Age in seconds. Default is 604800 (1 week).)
    
    max-session-time:
        description:
            - Specify default SAML token lifetime (Specify lifetime (in seconds) of SAML token when it not provided by token attributes, default is 28800. (0 for indefinite))
    
    local-logging:
        description:
            - Enable local logging
    
    logon:
        description:
            - Specify authentication logon (Specify authentication logon template name)
    
    logout-idle-timeout:
        description:
            - Specify idle logout time (Specify idle timeout in seconds, default is 300)
    
    logout-url:
        description:
            - Specify logout url (Specify logout url string)
    
    forward-logout-disable:
        description:
            - Disable forward logout request to backend application server. The config-field logut-url must be configured first
    
    relay:
        description:
            - Specify authentication relay (Specify authentication relay template name)
    
    server:
        description:
            - Specify authentication server (Specify authentication server template name)
    
    service-group:
        description:
            - Bind an authentication service group to this template (Specify authentication service group name)
    
    account:
        description:
            - Specify AD domain account
    
    accounting-server:
        description:
            - Specify a RADIUS accounting server
    
    accounting-service-group:
        description:
            - Specify an authentication service group for RADIUS accounting
    
    redirect-hostname:
        description:
            - Hostname(Length 1-31) for transparent-proxy authentication
    
    modify-content-security-policy:
        description:
            - Put redirect-uri or service-principal-name into CSP header to avoid CPS break authentication process
    
    log:
        description:
            - 'use-partition-level-config': Use configuration of authentication-log enable command; 'enable': Enable authentication logs for this template; 'disable': Disable authentication logs for this template; choices:['use-partition-level-config', 'enable', 'disable']
    
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
AVAILABLE_PROPERTIES = {"account","accounting_server","accounting_service_group","auth_sess_mode","cookie_domain","cookie_domain_group","cookie_max_age","forward_logout_disable","local_logging","log","logon","logout_idle_timeout","logout_url","max_session_time","modify_content_security_policy","name","redirect_hostname","relay","saml_idp","saml_sp","server","service_group","type","user_tag","uuid",}

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
        
        account=dict(
            type='str' 
        ),
        accounting_server=dict(
            type='str' 
        ),
        accounting_service_group=dict(
            type='str' 
        ),
        auth_sess_mode=dict(
            type='enum' , choices=['cookie-based', 'ip-based']
        ),
        cookie_domain=dict(
            type='str' 
        ),
        cookie_domain_group=dict(
            type='str' 
        ),
        cookie_max_age=dict(
            type='str' 
        ),
        forward_logout_disable=dict(
            type='str' 
        ),
        local_logging=dict(
            type='str' 
        ),
        log=dict(
            type='enum' , choices=['use-partition-level-config', 'enable', 'disable']
        ),
        logon=dict(
            type='str' 
        ),
        logout_idle_timeout=dict(
            type='str' 
        ),
        logout_url=dict(
            type='str' 
        ),
        max_session_time=dict(
            type='str' 
        ),
        modify_content_security_policy=dict(
            type='str' 
        ),
        name=dict(
            type='str' , required=True
        ),
        redirect_hostname=dict(
            type='str' 
        ),
        relay=dict(
            type='str' 
        ),
        saml_idp=dict(
            type='str' 
        ),
        saml_sp=dict(
            type='str' 
        ),
        server=dict(
            type='str' 
        ),
        service_group=dict(
            type='str' 
        ),
        type=dict(
            type='enum' , choices=['saml', 'standard']
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
    url_base = "/axapi/v3/aam/authentication/template/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/template/{name}"
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