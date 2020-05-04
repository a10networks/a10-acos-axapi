#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_aam_authentication_logon_form_based
description:
    - Form-based Authentication Logon
short_description: Configures A10 aam.authentication.logon.form-based
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
    a10_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_protocol:
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
    logon_page_cfg:
        description:
        - "Field logon_page_cfg"
        required: False
        suboptions:
            action_url:
                description:
                - "Specify form submission action url"
            username_variable:
                description:
                - "Specify username variable name in form submission"
            login_failure_message:
                description:
                - "Specify login failure message shown in logon page (Specify error string, default is 'Invalid username or password. Please try again.')"
            passcode_variable:
                description:
                - "Specify passcode variable name in form submission"
            disable_change_password_link:
                description:
                - "Don't display change password link on logon page forcibly even backend authentication server supports it (LDAP or Kerberos)"
            password_variable:
                description:
                - "Specify password variable name in form submission"
            authz_failure_message:
                description:
                - "Specify authorization failure message shown in logon page (Specify error string, default is 'Authorization failed. Please contact your system administrator.')"
    retry:
        description:
        - "Maximum number of consecutive failed logon attempts (default 3)"
        required: False
    name:
        description:
        - "Specify form-based authentication logon name"
        required: True
    next_token_variable:
        description:
        - "Specify next-token variable name in form submission"
        required: False
    challenge_variable:
        description:
        - "Specify challenge variable name in form submission"
        required: False
    notify_cp_page_cfg:
        description:
        - "Field notify_cp_page_cfg"
        required: False
        suboptions:
            notifychangepassword_change_url:
                description:
                - "Specify change password action url for notifychangepassword form"
            notifychangepassword_continue_url:
                description:
                - "Specify continue action url for notifychangepassword form"
    new_pin_variable:
        description:
        - "Specify new-pin variable name in form submission"
        required: False
    portal:
        description:
        - "Field portal"
        required: False
        suboptions:
            new_pin_page:
                description:
                - "Specify new PIN page name for RSA-RADIUS"
            challenge_page:
                description:
                - "Specify challenge page name for RSA-RADIUS"
            portal_name:
                description:
                - "Specify portal name"
            logon:
                description:
                - "Specify logon page name"
            next_token_page:
                description:
                - "Specify next token page name for RSA-RADIUS"
            notifychangepasswordpage:
                description:
                - "Specify change password notification page name"
            failpage:
                description:
                - "Specify logon fail page name (portal fail page name)"
            changepasswordpage:
                description:
                - "Specify change password page name"
            default_portal:
                description:
                - "Use default portal"
    user_tag:
        description:
        - "Customized tag"
        required: False
    account_lock:
        description:
        - "Lock the account when the failed logon attempts is exceeded"
        required: False
    duration:
        description:
        - "The time an account remains locked in seconds (default 1800)"
        required: False
    cp_page_cfg:
        description:
        - "Field cp_page_cfg"
        required: False
        suboptions:
            cp_cfm_pwd_var:
                description:
                - "Specify password confirm variable name"
            cp_new_pwd_var:
                description:
                - "Specify new password variable name"
            changepassword_url:
                description:
                - "Specify changepassword form submission action url (changepassword action url)"
            cp_cfm_pwd_enum:
                description:
                - "'changepassword-password-confirm-variable'= Specify password confirm variable name in form submission; "
            cp_new_pwd_enum:
                description:
                - "'changepassword-new-password-variable'= Specify new password variable name in form submission; "
            cp_old_pwd_enum:
                description:
                - "'changepassword-old-password-variable'= Specify old password variable name in form submission; "
            cp_user_var:
                description:
                - "Specify username variable name"
            cp_old_pwd_var:
                description:
                - "Specify old password variable name"
            cp_user_enum:
                description:
                - "'changepassword-username-variable'= Specify username variable name in form submission; "
    uuid:
        description:
        - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["account_lock","challenge_variable","cp_page_cfg","duration","logon_page_cfg","name","new_pin_variable","next_token_variable","notify_cp_page_cfg","portal","retry","user_tag","uuid",]

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
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        logon_page_cfg=dict(type='dict', action_url=dict(type='str', ),username_variable=dict(type='str', ),login_failure_message=dict(type='str', ),passcode_variable=dict(type='str', ),disable_change_password_link=dict(type='bool', ),password_variable=dict(type='str', ),authz_failure_message=dict(type='str', )),
        retry=dict(type='int', ),
        name=dict(type='str', required=True, ),
        next_token_variable=dict(type='str', ),
        challenge_variable=dict(type='str', ),
        notify_cp_page_cfg=dict(type='dict', notifychangepassword_change_url=dict(type='str', ),notifychangepassword_continue_url=dict(type='str', )),
        new_pin_variable=dict(type='str', ),
        portal=dict(type='dict', new_pin_page=dict(type='str', ),challenge_page=dict(type='str', ),portal_name=dict(type='str', ),logon=dict(type='str', ),next_token_page=dict(type='str', ),notifychangepasswordpage=dict(type='str', ),failpage=dict(type='str', ),changepasswordpage=dict(type='str', ),default_portal=dict(type='bool', )),
        user_tag=dict(type='str', ),
        account_lock=dict(type='bool', ),
        duration=dict(type='int', ),
        cp_page_cfg=dict(type='dict', cp_cfm_pwd_var=dict(type='str', ),cp_new_pwd_var=dict(type='str', ),changepassword_url=dict(type='str', ),cp_cfm_pwd_enum=dict(type='str', choices=['changepassword-password-confirm-variable']),cp_new_pwd_enum=dict(type='str', choices=['changepassword-new-password-variable']),cp_old_pwd_enum=dict(type='str', choices=['changepassword-old-password-variable']),cp_user_var=dict(type='str', ),cp_old_pwd_var=dict(type='str', ),cp_user_enum=dict(type='str', choices=['changepassword-username-variable'])),
        uuid=dict(type='str', )
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authentication/logon/form-based/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/logon/form-based/{name}"

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
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["form-based"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["form-based"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["form-based"][k] = v
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
    payload = build_json("form-based", module)
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
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]
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

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    
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