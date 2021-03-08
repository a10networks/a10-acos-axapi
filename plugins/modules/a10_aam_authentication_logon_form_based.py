#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_aam_authentication_logon_form_based
description:
    - Form-based Authentication Logon
author: A10 Networks 2021
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        type: str
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        type: str
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        type: str
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        type: str
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        type: int
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        type: int
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        type: str
        required: False
    name:
        description:
        - "Specify form-based authentication logon name"
        type: str
        required: True
    portal:
        description:
        - "Field portal"
        type: dict
        required: False
        suboptions:
            default_portal:
                description:
                - "Use default portal"
                type: bool
            portal_name:
                description:
                - "Specify portal name"
                type: str
            logon:
                description:
                - "Specify logon page name"
                type: str
            failpage:
                description:
                - "Specify logon fail page name (portal fail page name)"
                type: str
            changepasswordpage:
                description:
                - "Specify change password page name"
                type: str
            notifychangepasswordpage:
                description:
                - "Specify change password notification page name"
                type: str
            challenge_page:
                description:
                - "Specify challenge page name for RSA-RADIUS"
                type: str
            new_pin_page:
                description:
                - "Specify new PIN page name for RSA-RADIUS"
                type: str
            next_token_page:
                description:
                - "Specify next token page name for RSA-RADIUS"
                type: str
    logon_page_cfg:
        description:
        - "Field logon_page_cfg"
        type: dict
        required: False
        suboptions:
            action_url:
                description:
                - "Specify form submission action url"
                type: str
            username_variable:
                description:
                - "Specify username variable name in form submission"
                type: str
            password_variable:
                description:
                - "Specify password variable name in form submission"
                type: str
            passcode_variable:
                description:
                - "Specify passcode variable name in form submission"
                type: str
            login_failure_message:
                description:
                - "Specify login failure message shown in logon page (Specify error string,
          default is 'Invalid username or password. Please try again.')"
                type: str
            authz_failure_message:
                description:
                - "Specify authorization failure message shown in logon page (Specify error
          string, default is 'Authorization failed. Please contact your system
          administrator.')"
                type: str
            disable_change_password_link:
                description:
                - "Don't display change password link on logon page forcibly even backend
          authentication server supports it (LDAP or Kerberos)"
                type: bool
    cp_page_cfg:
        description:
        - "Field cp_page_cfg"
        type: dict
        required: False
        suboptions:
            changepassword_url:
                description:
                - "Specify changepassword form submission action url (changepassword action url)"
                type: str
            cp_user_enum:
                description:
                - "'changepassword-username-variable'= Specify username variable name in form
          submission;"
                type: str
            cp_user_var:
                description:
                - "Specify username variable name"
                type: str
            cp_old_pwd_enum:
                description:
                - "'changepassword-old-password-variable'= Specify old password variable name in
          form submission;"
                type: str
            cp_old_pwd_var:
                description:
                - "Specify old password variable name"
                type: str
            cp_new_pwd_enum:
                description:
                - "'changepassword-new-password-variable'= Specify new password variable name in
          form submission;"
                type: str
            cp_new_pwd_var:
                description:
                - "Specify new password variable name"
                type: str
            cp_cfm_pwd_enum:
                description:
                - "'changepassword-password-confirm-variable'= Specify password confirm variable
          name in form submission;"
                type: str
            cp_cfm_pwd_var:
                description:
                - "Specify password confirm variable name"
                type: str
    notify_cp_page_cfg:
        description:
        - "Field notify_cp_page_cfg"
        type: dict
        required: False
        suboptions:
            notifychangepassword_change_url:
                description:
                - "Specify change password action url for notifychangepassword form"
                type: str
            notifychangepassword_continue_url:
                description:
                - "Specify continue action url for notifychangepassword form"
                type: str
    challenge_variable:
        description:
        - "Specify challenge variable name in form submission"
        type: str
        required: False
    new_pin_variable:
        description:
        - "Specify new-pin variable name in form submission"
        type: str
        required: False
    next_token_variable:
        description:
        - "Specify next-token variable name in form submission"
        type: str
        required: False
    retry:
        description:
        - "Maximum number of consecutive failed logon attempts (default 3)"
        type: int
        required: False
    account_lock:
        description:
        - "Lock the account when the failed logon attempts is exceeded"
        type: bool
        required: False
    duration:
        description:
        - "The time an account remains locked in seconds (default 1800)"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    user_tag:
        description:
        - "Customized tag"
        type: str
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
AVAILABLE_PROPERTIES = [
    "account_lock",
    "challenge_variable",
    "cp_page_cfg",
    "duration",
    "logon_page_cfg",
    "name",
    "new_pin_variable",
    "next_token_variable",
    "notify_cp_page_cfg",
    "portal",
    "retry",
    "user_tag",
    "uuid",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str',
                   default="present",
                   choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
            required=False,
        ),
        a10_device_context_id=dict(
            type='int',
            choices=[1, 2, 3, 4, 5, 6, 7, 8],
            required=False,
        ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'name': {
            'type': 'str',
            'required': True,
        },
        'portal': {
            'type': 'dict',
            'default_portal': {
                'type': 'bool',
            },
            'portal_name': {
                'type': 'str',
            },
            'logon': {
                'type': 'str',
            },
            'failpage': {
                'type': 'str',
            },
            'changepasswordpage': {
                'type': 'str',
            },
            'notifychangepasswordpage': {
                'type': 'str',
            },
            'challenge_page': {
                'type': 'str',
            },
            'new_pin_page': {
                'type': 'str',
            },
            'next_token_page': {
                'type': 'str',
            }
        },
        'logon_page_cfg': {
            'type': 'dict',
            'action_url': {
                'type': 'str',
            },
            'username_variable': {
                'type': 'str',
            },
            'password_variable': {
                'type': 'str',
            },
            'passcode_variable': {
                'type': 'str',
            },
            'login_failure_message': {
                'type': 'str',
            },
            'authz_failure_message': {
                'type': 'str',
            },
            'disable_change_password_link': {
                'type': 'bool',
            }
        },
        'cp_page_cfg': {
            'type': 'dict',
            'changepassword_url': {
                'type': 'str',
            },
            'cp_user_enum': {
                'type': 'str',
                'choices': ['changepassword-username-variable']
            },
            'cp_user_var': {
                'type': 'str',
            },
            'cp_old_pwd_enum': {
                'type': 'str',
                'choices': ['changepassword-old-password-variable']
            },
            'cp_old_pwd_var': {
                'type': 'str',
            },
            'cp_new_pwd_enum': {
                'type': 'str',
                'choices': ['changepassword-new-password-variable']
            },
            'cp_new_pwd_var': {
                'type': 'str',
            },
            'cp_cfm_pwd_enum': {
                'type': 'str',
                'choices': ['changepassword-password-confirm-variable']
            },
            'cp_cfm_pwd_var': {
                'type': 'str',
            }
        },
        'notify_cp_page_cfg': {
            'type': 'dict',
            'notifychangepassword_change_url': {
                'type': 'str',
            },
            'notifychangepassword_continue_url': {
                'type': 'str',
            }
        },
        'challenge_variable': {
            'type': 'str',
        },
        'new_pin_variable': {
            'type': 'str',
        },
        'next_token_variable': {
            'type': 'str',
        },
        'retry': {
            'type': 'int',
        },
        'account_lock': {
            'type': 'bool',
        },
        'duration': {
            'type': 'int',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        }
    })
    return rv


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

    for k, v in param.items():
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
    return {title: data}


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authentication/logon/form-based/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


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
                    if result["changed"] is not True:
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

    result = dict(changed=False, original_message="", message="", result={})

    state = module.params["state"]
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    if ansible_port == 80:
        protocol = "http"
    elif ansible_port == 443:
        protocol = "https"

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
