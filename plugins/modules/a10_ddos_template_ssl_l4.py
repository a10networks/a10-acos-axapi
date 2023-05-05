#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_template_ssl_l4
description:
    - SSL-L4 template Configuration
author: A10 Networks
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
    ssl_l4_tmpl_name:
        description:
        - "Field ssl_l4_tmpl_name"
        type: str
        required: True
    action:
        description:
        - "'drop'= drop; 'reset'= reset;"
        type: str
        required: False
    disable:
        description:
        - "Disable this template"
        type: bool
        required: False
    renegotiation:
        description:
        - "Configure renegotiation limiting for SSL (Number of renegotiation allowed)"
        type: int
        required: False
    request_rate_limit:
        description:
        - "Configure rate limiting for SSL"
        type: int
        required: False
    allow_non_tls:
        description:
        - "Allow Non-TLS (SSLv3 and lower) traffic (Warning= security may be compromised)"
        type: bool
        required: False
    multi_pu_threshold_distribution:
        description:
        - "Field multi_pu_threshold_distribution"
        type: dict
        required: False
        suboptions:
            multi_pu_threshold_distribution_value:
                description:
                - "Destination side rate limit only. Default= 0"
                type: int
            multi_pu_threshold_distribution_disable:
                description:
                - "'disable'= Destination side rate limit only. Default= Enable;"
                type: str
    auth_config_cfg:
        description:
        - "Field auth_config_cfg"
        type: dict
        required: False
        suboptions:
            timeout:
                description:
                - "Connection timeout"
                type: int
            trials:
                description:
                - "Number of failed handshakes"
                type: int
            auth_handshake_fail_action:
                description:
                - "'blacklist-src'= Blacklist-src when auth handshake fails;"
                type: str
    cert_cfg:
        description:
        - "Field cert_cfg"
        type: dict
        required: False
        suboptions:
            cert:
                description:
                - "SSL certificate"
                type: str
            key:
                description:
                - "SSL key"
                type: str
            key_passphrase:
                description:
                - "Password Phrase"
                type: str
            key_encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
                type: str
    server_name_list:
        description:
        - "Field server_name_list"
        type: list
        required: False
        suboptions:
            server_name:
                description:
                - "Server name indication in Client hello extension (Server name String)"
                type: str
            server_cert:
                description:
                - "Server Certificate associated to SNI (Server Certificate Name)"
                type: str
            server_key:
                description:
                - "Server Private Key associated to SNI (Server Private Key Name)"
                type: str
            server_passphrase:
                description:
                - "Password Phrase"
                type: str
            server_encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
                type: str
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
    ssl_traffic_check:
        description:
        - "Field ssl_traffic_check"
        type: dict
        required: False
        suboptions:
            header_inspection:
                description:
                - "Inspect ssl header"
                type: bool
            header_action:
                description:
                - "'drop'= Drop packets with bad ssl header; 'ignore'= Forward packets with bad
          ssl header;"
                type: str
            check_resumed_connection:
                description:
                - "Apply checks to SSL connections initialized by ACK packets"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str

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
AVAILABLE_PROPERTIES = ["action", "allow_non_tls", "auth_config_cfg", "cert_cfg", "disable", "multi_pu_threshold_distribution", "renegotiation", "request_rate_limit", "server_name_list", "ssl_l4_tmpl_name", "ssl_traffic_check", "user_tag", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False,
                           ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False,
                                   ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
        )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'ssl_l4_tmpl_name': {
            'type': 'str',
            'required': True,
            },
        'action': {
            'type': 'str',
            'choices': ['drop', 'reset']
            },
        'disable': {
            'type': 'bool',
            },
        'renegotiation': {
            'type': 'int',
            },
        'request_rate_limit': {
            'type': 'int',
            },
        'allow_non_tls': {
            'type': 'bool',
            },
        'multi_pu_threshold_distribution': {
            'type': 'dict',
            'multi_pu_threshold_distribution_value': {
                'type': 'int',
                },
            'multi_pu_threshold_distribution_disable': {
                'type': 'str',
                'choices': ['disable']
                }
            },
        'auth_config_cfg': {
            'type': 'dict',
            'timeout': {
                'type': 'int',
                },
            'trials': {
                'type': 'int',
                },
            'auth_handshake_fail_action': {
                'type': 'str',
                'choices': ['blacklist-src']
                }
            },
        'cert_cfg': {
            'type': 'dict',
            'cert': {
                'type': 'str',
                },
            'key': {
                'type': 'str',
                },
            'key_passphrase': {
                'type': 'str',
                },
            'key_encrypted': {
                'type': 'str',
                }
            },
        'server_name_list': {
            'type': 'list',
            'server_name': {
                'type': 'str',
                },
            'server_cert': {
                'type': 'str',
                },
            'server_key': {
                'type': 'str',
                },
            'server_passphrase': {
                'type': 'str',
                },
            'server_encrypted': {
                'type': 'str',
                }
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'ssl_traffic_check': {
            'type': 'dict',
            'header_inspection': {
                'type': 'bool',
                },
            'header_action': {
                'type': 'str',
                'choices': ['drop', 'ignore']
                },
            'check_resumed_connection': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/template/ssl-l4/{ssl_l4_tmpl_name}"

    f_dict = {}
    if '/' in str(module.params["ssl_l4_tmpl_name"]):
        f_dict["ssl_l4_tmpl_name"] = module.params["ssl_l4_tmpl_name"].replace("/", "%2F")
    else:
        f_dict["ssl_l4_tmpl_name"] = module.params["ssl_l4_tmpl_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/template/ssl-l4"

    f_dict = {}
    f_dict["ssl_l4_tmpl_name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["ssl-l4"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["ssl-l4"].get(k) != v:
            change_results["changed"] = True
            config_changes["ssl-l4"][k] = v

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
    payload = utils.build_json("ssl-l4", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(changed=False, messages="", modified_values={}, axapi_calls=[], ansible_facts={}, acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

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
            result["axapi_calls"].append(api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(api_client.switch_device_context(module.client, a10_device_context_id))

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
                result["acos_info"] = info["ssl-l4"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["ssl-l4-list"] if info != "NotFound" else info
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
