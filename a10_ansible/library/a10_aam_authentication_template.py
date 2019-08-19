#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_aam_authentication_template
description:
    - Authentication template
short_description: Configures A10 aam.authentication.template
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
        - present
        - absent
        required: True
    a10_host:
        description:
        - Host for AXAPI authentication
        required: True
    a10_username:
        description:
        - Username for AXAPI authentication
        required: True
    a10_password:
        description:
        - Password for AXAPI authentication
        required: True
    partition:
        description:
        - Destination/target partition for object/command
    max_session_time:
        description:
        - "Specify default SAML token lifetime (Specify lifetime (in seconds) of SAML token when it not provided by token attributes, default is 28800. (0 for indefinite))"
        required: False
    accounting_server:
        description:
        - "Specify a RADIUS accounting server"
        required: False
    saml_idp:
        description:
        - "Specify SAML identity provider"
        required: False
    cookie_max_age:
        description:
        - "Configure Max-Age for authentication session cookie (Configure Max-Age in seconds. Default is 604800 (1 week).)"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    local_logging:
        description:
        - "Enable local logging"
        required: False
    auth_sess_mode:
        description:
        - "'cookie-based'= Track auth-session by cookie (default); 'ip-based'= Track auth-session by client IP; "
        required: False
    service_group:
        description:
        - "Bind an authentication service group to this template (Specify authentication service group name)"
        required: False
    ntype:
        description:
        - "'saml'= SAML authentication template; 'standard'= Standard authentication template; "
        required: False
    modify_content_security_policy:
        description:
        - "Put redirect-uri or service-principal-name into CSP header to avoid CPS break authentication process"
        required: False
    relay:
        description:
        - "Specify authentication relay (Specify authentication relay template name)"
        required: False
    saml_sp:
        description:
        - "Specify SAML service provider"
        required: False
    cookie_domain:
        description:
        - "Field cookie_domain"
        required: False
        suboptions:
            cookie_dmn:
                description:
                - "Specify domain scope for the authentication (ex= .a10networks.com)"
    cookie_domain_group:
        description:
        - "Field cookie_domain_group"
        required: False
        suboptions:
            cookie_dmngrp:
                description:
                - "Specify group id to join in the cookie-domain"
    forward_logout_disable:
        description:
        - "Disable forward logout request to backend application server. The config-field logout-url must be configured first"
        required: False
    accounting_service_group:
        description:
        - "Specify an authentication service group for RADIUS accounting"
        required: False
    log:
        description:
        - "'use-partition-level-config'= Use configuration of authentication-log enable command; 'enable'= Enable authentication logs for this template; 'disable'= Disable authentication logs for this template; "
        required: False
    logout_idle_timeout:
        description:
        - "Specify idle logout time (Specify idle timeout in seconds, default is 300)"
        required: False
    account:
        description:
        - "Specify AD domain account"
        required: False
    name:
        description:
        - "Authentication template name"
        required: True
    logout_url:
        description:
        - "Specify logout url (Specify logout url string)"
        required: False
    jwt:
        description:
        - "Specify authentication jwt template"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    server:
        description:
        - "Specify authentication server (Specify authentication server template name)"
        required: False
    redirect_hostname:
        description:
        - "Hostname(Length 1-31) for transparent-proxy authentication"
        required: False
    logon:
        description:
        - "Specify authentication logon (Specify authentication logon template name)"
        required: False

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["account","accounting_server","accounting_service_group","auth_sess_mode","cookie_domain","cookie_domain_group","cookie_max_age","forward_logout_disable","jwt","local_logging","log","logon","logout_idle_timeout","logout_url","max_session_time","modify_content_security_policy","name","redirect_hostname","relay","saml_idp","saml_sp","server","service_group","ntype","user_tag","uuid",]

# our imports go at the top so we fail fast.
try:
    from a10_ansible import errors as a10_ex
    from a10_ansible.axapi_http import client_factory, session_factory
    from a10_ansible.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=["present", "absent", "noop"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        partition=dict(type='str', required=False),
        get_type=dict(type='str', choices=["single", "list"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        max_session_time=dict(type='int',),
        accounting_server=dict(type='str',),
        saml_idp=dict(type='str',),
        cookie_max_age=dict(type='int',),
        uuid=dict(type='str',),
        local_logging=dict(type='bool',),
        auth_sess_mode=dict(type='str',choices=['cookie-based','ip-based']),
        service_group=dict(type='str',),
        ntype=dict(type='str',choices=['saml','standard']),
        modify_content_security_policy=dict(type='bool',),
        relay=dict(type='str',),
        saml_sp=dict(type='str',),
        cookie_domain=dict(type='list',cookie_dmn=dict(type='str',)),
        cookie_domain_group=dict(type='list',cookie_dmngrp=dict(type='int',)),
        forward_logout_disable=dict(type='bool',),
        accounting_service_group=dict(type='str',),
        log=dict(type='str',choices=['use-partition-level-config','enable','disable']),
        logout_idle_timeout=dict(type='int',),
        account=dict(type='str',),
        name=dict(type='str',required=True,),
        logout_url=dict(type='str',),
        jwt=dict(type='str',),
        user_tag=dict(type='str',),
        server=dict(type='str',),
        redirect_hostname=dict(type='str',),
        logon=dict(type='str',)
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

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

def build_envelope(title, data):
    return {
        title: data
    }

def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")

def _build_dict_from_param(param):
    rv = {}

    for k,v in param.items():
        hk = _to_axapi(k)
        if isinstance(v, dict):
            v_dict = _build_dict_from_param(v)
            rv[hk] = v_dict
        elif isinstance(v, list):
            nv = [_build_dict_from_param(x) for x in v]
            rv[hk] = nv
        else:
            rv[hk] = v

    return rv

def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v:
            rx = _to_axapi(x)

            if isinstance(v, dict):
                nv = _build_dict_from_param(v)
                rv[rx] = nv
            elif isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params and params.get(x) is not None])
    
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

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("template", module)
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
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

def update(module, result, existing_config):
    payload = build_json("template", module)
    try:
        post_result = module.client.post(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result, existing_config):
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result, existing_config)

def absent(module, result):
    return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("template", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def run_command(module):
    run_errors = []

    result = dict(
        changed=False,
        original_message="",
        message="",
        result={}
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]
    
    partition = module.params["partition"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    if partition:
        module.client.activate_partition(partition)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
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