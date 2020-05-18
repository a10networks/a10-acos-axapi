#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
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
          - noop
          - present
          - absent
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        required: True
    ansible_protocol:
        description:
        - Protocol for AXAPI authentication
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
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


'''

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
    from ansible_collections.a10.acos_axapi.plugins.module_utils import errors as a10_ex
    from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import client_factory, session_factory
    from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', required=True),
        ansible_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        max_session_time=dict(type='int', ),
        accounting_server=dict(type='str', ),
        saml_idp=dict(type='str', ),
        cookie_max_age=dict(type='int', ),
        uuid=dict(type='str', ),
        local_logging=dict(type='bool', ),
        auth_sess_mode=dict(type='str', choices=['cookie-based', 'ip-based']),
        service_group=dict(type='str', ),
        ntype=dict(type='str', choices=['saml', 'standard']),
        modify_content_security_policy=dict(type='bool', ),
        relay=dict(type='str', ),
        saml_sp=dict(type='str', ),
        cookie_domain=dict(type='list', cookie_dmn=dict(type='str', )),
        cookie_domain_group=dict(type='list', cookie_dmngrp=dict(type='int', )),
        forward_logout_disable=dict(type='bool', ),
        accounting_service_group=dict(type='str', ),
        log=dict(type='str', choices=['use-partition-level-config', 'enable', 'disable']),
        logout_idle_timeout=dict(type='int', ),
        account=dict(type='str', ),
        name=dict(type='str', required=True, ),
        logout_url=dict(type='str', ),
        jwt=dict(type='str', ),
        user_tag=dict(type='str', ),
        server=dict(type='str', ),
        redirect_hostname=dict(type='str', ),
        logon=dict(type='str', )
    ))
   

    return rv

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

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

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

def build_envelope(title, data):
    return {
        title: data
    }

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authentication/template/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

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

def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v is not None:
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

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["template"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["template"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["template"][k] = v
            result.update(**existing_config)
    else:
        result.update(**payload)
    return result

def create(module, result, payload):
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def update(module, result, existing_config, payload):
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
    payload = build_json("template", module)
    changed_config = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return changed_config
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and not changed_config.get('changed'):
        return update(module, result, existing_config, payload)
    else:
        result["changed"] = True
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

def absent(module, result, existing_config):
    if module.check_mode:
        if existing_config:
            result["changed"] = True
            return result
        else:
            result["changed"] = False
            return result
    else:
        return delete(module, result)

def replace(module, result, existing_config, payload):
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
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    ansible_protocol = module.params["ansible_protocol"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, ansible_protocol, ansible_username, ansible_password)
    
    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)
    
    if state == 'present':
        result = present(module, result, existing_config)

    elif state == 'absent':
        result = absent(module, result, existing_config)
    
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
    module.client.session.close()
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()