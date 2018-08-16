#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_aam_authentication_logon_form_based
description:
    - None
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
    logon_page_cfg:
        description:
        - "Field logon_page_cfg"
        required: False
        suboptions:
            action_url:
                description:
                - "None"
            username_variable:
                description:
                - "None"
            login_failure_message:
                description:
                - "None"
            passcode_variable:
                description:
                - "None"
            disable_change_password_link:
                description:
                - "None"
            password_variable:
                description:
                - "None"
            authz_failure_message:
                description:
                - "None"
    retry:
        description:
        - "None"
        required: False
    name:
        description:
        - "None"
        required: True
    next_token_variable:
        description:
        - "None"
        required: False
    challenge_variable:
        description:
        - "None"
        required: False
    notify_cp_page_cfg:
        description:
        - "Field notify_cp_page_cfg"
        required: False
        suboptions:
            notifychangepassword_change_url:
                description:
                - "None"
            notifychangepassword_continue_url:
                description:
                - "None"
    new_pin_variable:
        description:
        - "None"
        required: False
    portal:
        description:
        - "Field portal"
        required: False
        suboptions:
            new_pin_page:
                description:
                - "None"
            challenge_page:
                description:
                - "None"
            portal_name:
                description:
                - "None"
            logon:
                description:
                - "None"
            next_token_page:
                description:
                - "None"
            notifychangepasswordpage:
                description:
                - "None"
            failpage:
                description:
                - "None"
            changepasswordpage:
                description:
                - "None"
            default_portal:
                description:
                - "None"
    user_tag:
        description:
        - "None"
        required: False
    account_lock:
        description:
        - "None"
        required: False
    duration:
        description:
        - "None"
        required: False
    cp_page_cfg:
        description:
        - "Field cp_page_cfg"
        required: False
        suboptions:
            cp_cfm_pwd_var:
                description:
                - "None"
            cp_new_pwd_var:
                description:
                - "None"
            changepassword_url:
                description:
                - "None"
            cp_cfm_pwd_enum:
                description:
                - "None"
            cp_new_pwd_enum:
                description:
                - "None"
            cp_old_pwd_enum:
                description:
                - "None"
            cp_user_var:
                description:
                - "None"
            cp_old_pwd_var:
                description:
                - "None"
            cp_user_enum:
                description:
                - "None"
    uuid:
        description:
        - "None"
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
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        logon_page_cfg=dict(type='dict',action_url=dict(type='str',),username_variable=dict(type='str',),login_failure_message=dict(type='str',),passcode_variable=dict(type='str',),disable_change_password_link=dict(type='bool',),password_variable=dict(type='str',),authz_failure_message=dict(type='str',)),
        retry=dict(type='int',),
        name=dict(type='str',required=True,),
        next_token_variable=dict(type='str',),
        challenge_variable=dict(type='str',),
        notify_cp_page_cfg=dict(type='dict',notifychangepassword_change_url=dict(type='str',),notifychangepassword_continue_url=dict(type='str',)),
        new_pin_variable=dict(type='str',),
        portal=dict(type='dict',new_pin_page=dict(type='str',),challenge_page=dict(type='str',),portal_name=dict(type='str',),logon=dict(type='str',),next_token_page=dict(type='str',),notifychangepasswordpage=dict(type='str',),failpage=dict(type='str',),changepasswordpage=dict(type='str',),default_portal=dict(type='bool',)),
        user_tag=dict(type='str',),
        account_lock=dict(type='bool',),
        duration=dict(type='int',),
        cp_page_cfg=dict(type='dict',cp_cfm_pwd_var=dict(type='str',),cp_new_pwd_var=dict(type='str',),changepassword_url=dict(type='str',),cp_cfm_pwd_enum=dict(type='str',choices=['changepassword-password-confirm-variable']),cp_new_pwd_enum=dict(type='str',choices=['changepassword-new-password-variable']),cp_old_pwd_enum=dict(type='str',choices=['changepassword-old-password-variable']),cp_user_var=dict(type='str',),cp_old_pwd_var=dict(type='str',),cp_user_enum=dict(type='str',choices=['changepassword-username-variable'])),
        uuid=dict(type='str',)
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
        if isinstance(v, list):
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
            if isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
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

def get(module):
    return module.client.get(existing_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("form-based", module)
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

def update(module, result, existing_config):
    payload = build_json("form-based", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
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

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
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