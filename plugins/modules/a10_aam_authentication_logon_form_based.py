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
            captcha_variable:
                description:
                - "Specify captcha variable name in form submission"
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

RETURN = r'''
modified_values:
    description:
    - Values modified (or potential changes if using check_mode) as a result of task operation
    returned: changed
    type: dict
axapi_calls:
    description: Sequential list of AXAPI calls made by the task
    returned: always
    type: list
    elements: dict
    contains:
        endpoint:
            description: The AXAPI endpoint being accessed.
            type: str
            sample:
                - /axapi/v3/slb/virtual_server
                - /axapi/v3/file/ssl-cert
        http_method:
            description:
            - HTTP method being used by the primary task to interact with the AXAPI endpoint.
            type: str
            sample:
                - POST
                - GET
        request_body:
            description: Params used to query the AXAPI
            type: complex
        response_body:
            description: Response from the AXAPI
            type: complex
'''

EXAMPLES = """
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["account_lock", "challenge_variable", "cp_page_cfg", "duration", "logon_page_cfg", "name", "new_pin_variable", "next_token_variable", "notify_cp_page_cfg", "portal", "retry", "user_tag", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({'name': {'type': 'str', 'required': True, },
        'portal': {'type': 'dict', 'default_portal': {'type': 'bool', }, 'portal_name': {'type': 'str', }, 'logon': {'type': 'str', }, 'failpage': {'type': 'str', }, 'changepasswordpage': {'type': 'str', }, 'notifychangepasswordpage': {'type': 'str', }, 'challenge_page': {'type': 'str', }, 'new_pin_page': {'type': 'str', }, 'next_token_page': {'type': 'str', }},
        'logon_page_cfg': {'type': 'dict', 'action_url': {'type': 'str', }, 'username_variable': {'type': 'str', }, 'password_variable': {'type': 'str', }, 'passcode_variable': {'type': 'str', }, 'captcha_variable': {'type': 'str', }, 'login_failure_message': {'type': 'str', }, 'authz_failure_message': {'type': 'str', }, 'disable_change_password_link': {'type': 'bool', }},
        'cp_page_cfg': {'type': 'dict', 'changepassword_url': {'type': 'str', }, 'cp_user_enum': {'type': 'str', 'choices': ['changepassword-username-variable']}, 'cp_user_var': {'type': 'str', }, 'cp_old_pwd_enum': {'type': 'str', 'choices': ['changepassword-old-password-variable']}, 'cp_old_pwd_var': {'type': 'str', }, 'cp_new_pwd_enum': {'type': 'str', 'choices': ['changepassword-new-password-variable']}, 'cp_new_pwd_var': {'type': 'str', }, 'cp_cfm_pwd_enum': {'type': 'str', 'choices': ['changepassword-password-confirm-variable']}, 'cp_cfm_pwd_var': {'type': 'str', }},
        'notify_cp_page_cfg': {'type': 'dict', 'notifychangepassword_change_url': {'type': 'str', }, 'notifychangepassword_continue_url': {'type': 'str', }},
        'challenge_variable': {'type': 'str', },
        'new_pin_variable': {'type': 'str', },
        'next_token_variable': {'type': 'str', },
        'retry': {'type': 'int', },
        'account_lock': {'type': 'bool', },
        'duration': {'type': 'int', },
        'uuid': {'type': 'str', },
        'user_tag': {'type': 'str', }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/logon/form-based/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/","%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authentication/logon/form-based/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["form-based"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["form-based"].get(k) != v:
            change_results["changed"] = True
            config_changes["form-based"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(
        **call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(
            **call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("form-based", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def delete(module, result):
    try:
        call_result = api_client.delete(module.client, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

    return delete(module, result)


def run_command(module):
    result = dict(
        changed=False,
        messages="",
        modified_values={},
        axapi_calls=[],
        ansible_facts={},
        acos_info={}
    )

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

    module.client = client_factory(ansible_host, ansible_port,
                                   protocol, ansible_username,
                                   ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params, requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)


    try:
        if a10_partition:
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
             result["axapi_calls"].append(
                api_client.switch_device_context(module.client, a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
        result["axapi_calls"].append(existing_config)
        if existing_config['response_body'] != 'NotFound':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["form-based"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["form-based-list"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

if __name__ == '__main__':
    main()
