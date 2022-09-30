#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_aam_authentication_template
description:
    - Authentication template
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
        - "Authentication template name"
        type: str
        required: True
    ntype:
        description:
        - "'saml'= SAML authentication template; 'standard'= Standard authentication
          template; 'oauth'= Oauth 2.0 authentication template;"
        type: str
        required: False
    auth_sess_mode:
        description:
        - "'cookie-based'= Track auth-session by cookie (default); 'ip-based'= Track auth-
          session by client IP;"
        type: str
        required: False
    saml_sp:
        description:
        - "Specify SAML service provider"
        type: str
        required: False
    saml_idp:
        description:
        - "Specify SAML identity provider"
        type: str
        required: False
    oauth_authorization_server:
        description:
        - "Specify OAUTH authorization server"
        type: str
        required: False
    oauth_client:
        description:
        - "Specify OAUTH client"
        type: str
        required: False
    cookie_domain:
        description:
        - "Field cookie_domain"
        type: list
        required: False
        suboptions:
            cookie_dmn:
                description:
                - "Specify domain scope for the authentication (ex= .a10networks.com)"
                type: str
    cookie_domain_group:
        description:
        - "Field cookie_domain_group"
        type: list
        required: False
        suboptions:
            cookie_dmngrp:
                description:
                - "Specify group id to join in the cookie-domain"
                type: int
    cookie_max_age:
        description:
        - "Configure Max-Age for authentication session cookie (Configure Max-Age in
          seconds, 0 for no Max-Age/Expires attributes. Default is 604800 (1 week).)"
        type: int
        required: False
    cookie_secure_enable:
        description:
        - "Enable secure attribute for AAM cookies"
        type: bool
        required: False
    cookie_httponly_enable:
        description:
        - "Enable httponly attribute for AAM cookies"
        type: bool
        required: False
    cookie_samesite:
        description:
        - "'strict'= Specify SameSite attribute as Strict for AAM cookie; 'lax'= Specify
          SameSite attribute as Lax for AAM cookie; 'none'= Specify SameSite attribute as
          None for AAM cookie;"
        type: str
        required: False
    max_session_time:
        description:
        - "Specify default SAML token lifetime (Specify lifetime (in seconds) of SAML
          token when it not provided by token attributes, default is 28800. (0 for
          indefinite))"
        type: int
        required: False
    local_logging:
        description:
        - "Enable local logging"
        type: bool
        required: False
    logon:
        description:
        - "Specify authentication logon (Specify authentication logon template name)"
        type: str
        required: False
    logout_idle_timeout:
        description:
        - "Specify idle logout time (Specify idle timeout in seconds, default is 300)"
        type: int
        required: False
    logout_url:
        description:
        - "Specify logout url (Specify logout url string)"
        type: str
        required: False
    forward_logout_disable:
        description:
        - "Disable forward logout request to backend application server. The config-field
          logout-url must be configured first"
        type: bool
        required: False
    relay:
        description:
        - "Specify authentication relay (Specify authentication relay template name)"
        type: str
        required: False
    jwt:
        description:
        - "Specify authentication jwt template"
        type: str
        required: False
    server:
        description:
        - "Specify authentication server (Specify authentication server template name)"
        type: str
        required: False
    service_group:
        description:
        - "Bind an authentication service group to this template (Specify authentication
          service group name)"
        type: str
        required: False
    account:
        description:
        - "Specify AD domain account"
        type: str
        required: False
    captcha:
        description:
        - "Specify captcha profile (Specify captcha proflie name)"
        type: str
        required: False
    accounting_server:
        description:
        - "Specify a RADIUS accounting server"
        type: str
        required: False
    accounting_service_group:
        description:
        - "Specify an authentication service group for RADIUS accounting"
        type: str
        required: False
    redirect_hostname:
        description:
        - "Hostname(Length 1-31) for transparent-proxy authentication"
        type: str
        required: False
    modify_content_security_policy:
        description:
        - "Put redirect-uri or service-principal-name into CSP header to avoid CPS break
          authentication process"
        type: bool
        required: False
    log:
        description:
        - "'use-partition-level-config'= Use configuration of authentication-log enable
          command; 'enable'= Enable authentication logs for this template; 'disable'=
          Disable authentication logs for this template;"
        type: str
        required: False
    chain:
        description:
        - "Field chain"
        type: list
        required: False
        suboptions:
            chain_server:
                description:
                - "Specify authentication server (Specify authentication server template name)"
                type: str
            chain_server_priority:
                description:
                - "Set server priority, higher the number higher the priority. Default is 3.
          (Chain server priority, higher the number higher the priority. Default is 3.)"
                type: int
            chain_sg:
                description:
                - "Bind an authentication service group to this template (Specify authentication
          service group name)"
                type: str
            chain_sg_priority:
                description:
                - "Set service-group priority, higher the number higher the priority. Default is
          3. (Chain service-group priority, higher the number higher the priority.
          Default is 3.)"
                type: int
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
AVAILABLE_PROPERTIES = [
    "account",
    "accounting_server",
    "accounting_service_group",
    "auth_sess_mode",
    "captcha",
    "chain",
    "cookie_domain",
    "cookie_domain_group",
    "cookie_httponly_enable",
    "cookie_max_age",
    "cookie_samesite",
    "cookie_secure_enable",
    "forward_logout_disable",
    "jwt",
    "local_logging",
    "log",
    "logon",
    "logout_idle_timeout",
    "logout_url",
    "max_session_time",
    "modify_content_security_policy",
    "name",
    "oauth_authorization_server",
    "oauth_client",
    "redirect_hostname",
    "relay",
    "saml_idp",
    "saml_sp",
    "server",
    "service_group",
    "ntype",
    "user_tag",
    "uuid",
]


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
            type='str',
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
        'ntype': {
            'type': 'str',
            'choices': ['saml', 'standard', 'oauth']
        },
        'auth_sess_mode': {
            'type': 'str',
            'choices': ['cookie-based', 'ip-based']
        },
        'saml_sp': {
            'type': 'str',
        },
        'saml_idp': {
            'type': 'str',
        },
        'oauth_authorization_server': {
            'type': 'str',
        },
        'oauth_client': {
            'type': 'str',
        },
        'cookie_domain': {
            'type': 'list',
            'cookie_dmn': {
                'type': 'str',
            }
        },
        'cookie_domain_group': {
            'type': 'list',
            'cookie_dmngrp': {
                'type': 'int',
            }
        },
        'cookie_max_age': {
            'type': 'int',
        },
        'cookie_secure_enable': {
            'type': 'bool',
        },
        'cookie_httponly_enable': {
            'type': 'bool',
        },
        'cookie_samesite': {
            'type': 'str',
            'choices': ['strict', 'lax', 'none']
        },
        'max_session_time': {
            'type': 'int',
        },
        'local_logging': {
            'type': 'bool',
        },
        'logon': {
            'type': 'str',
        },
        'logout_idle_timeout': {
            'type': 'int',
        },
        'logout_url': {
            'type': 'str',
        },
        'forward_logout_disable': {
            'type': 'bool',
        },
        'relay': {
            'type': 'str',
        },
        'jwt': {
            'type': 'str',
        },
        'server': {
            'type': 'str',
        },
        'service_group': {
            'type': 'str',
        },
        'account': {
            'type': 'str',
        },
        'captcha': {
            'type': 'str',
        },
        'accounting_server': {
            'type': 'str',
        },
        'accounting_service_group': {
            'type': 'str',
        },
        'redirect_hostname': {
            'type': 'str',
        },
        'modify_content_security_policy': {
            'type': 'bool',
        },
        'log': {
            'type': 'str',
            'choices': ['use-partition-level-config', 'enable', 'disable']
        },
        'chain': {
            'type': 'list',
            'chain_server': {
                'type': 'str',
            },
            'chain_server_priority': {
                'type': 'int',
            },
            'chain_sg': {
                'type': 'str',
            },
            'chain_sg_priority': {
                'type': 'int',
            }
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
    url_base = "/axapi/v3/aam/authentication/template/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authentication/template/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["template"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["template"].get(k) != v:
            change_results["changed"] = True
            config_changes["template"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(**call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("template", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[],
                  ansible_facts={},
                  acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params,
                                                  requires_one_of)
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
                api_client.switch_device_context(module.client,
                                                 a10_device_context_id))

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
                get_result = api_client.get(module.client,
                                            existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info[
                    "template"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "template-list"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
