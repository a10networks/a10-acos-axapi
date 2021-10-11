#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_fw_template_logging
description:
    - Logging Template
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
        - "Logging Template Name"
        type: str
        required: True
    resolution:
        description:
        - "'seconds'= Logging timestamp resolution in seconds (default);
          '10-milliseconds'= Logging timestamp resolution in 10s of milli-seconds;"
        type: str
        required: False
    include_dest_fqdn:
        description:
        - "Include destination FQDN string"
        type: bool
        required: False
    merged_style:
        description:
        - "Merge creation and deletion of session logs to one"
        type: bool
        required: False
    log:
        description:
        - "Field log"
        type: dict
        required: False
        suboptions:
            http_requests:
                description:
                - "'host'= Log the HTTP Host Header; 'url'= Log the HTTP Request URL;"
                type: str
    include_radius_attribute:
        description:
        - "Field include_radius_attribute"
        type: dict
        required: False
        suboptions:
            attr_cfg:
                description:
                - "Field attr_cfg"
                type: list
            no_quote:
                description:
                - "No quotation marks for RADIUS attributes in logs"
                type: bool
            framed_ipv6_prefix:
                description:
                - "Include radius attributes for the prefix"
                type: bool
            prefix_length:
                description:
                - "'32'= Prefix length 32; '48'= Prefix length 48; '64'= Prefix length 64; '80'=
          Prefix length 80; '96'= Prefix length 96; '112'= Prefix length 112;"
                type: str
            insert_if_not_existing:
                description:
                - "Configure what string is to be inserted for custom RADIUS attributes"
                type: bool
            zero_in_custom_attr:
                description:
                - "Insert 0000 for standard and custom attributes in log string"
                type: bool
    include_http:
        description:
        - "Field include_http"
        type: dict
        required: False
        suboptions:
            header_cfg:
                description:
                - "Field header_cfg"
                type: list
            l4_session_info:
                description:
                - "Log the L4 session information of the HTTP request"
                type: bool
            method:
                description:
                - "Log the HTTP Request Method"
                type: bool
            request_number:
                description:
                - "HTTP Request Number"
                type: bool
            file_extension:
                description:
                - "HTTP file extension"
                type: bool
    rule:
        description:
        - "Field rule"
        type: dict
        required: False
        suboptions:
            rule_http_requests:
                description:
                - "Field rule_http_requests"
                type: dict
    facility:
        description:
        - "'kernel'= 0= Kernel; 'user'= 1= User-level; 'mail'= 2= Mail; 'daemon'= 3=
          System daemons; 'security-authorization'= 4= Security/authorization; 'syslog'=
          5= Syslog internal; 'line-printer'= 6= Line printer; 'news'= 7= Network news;
          'uucp'= 8= UUCP subsystem; 'cron'= 9= Time-related; 'security-authorization-
          private'= 10= Private security/authorization; 'ftp'= 11= FTP; 'ntp'= 12= NTP;
          'audit'= 13= Audit; 'alert'= 14= Alert; 'clock'= 15= Clock-related; 'local0'=
          16= Local use 0; 'local1'= 17= Local use 1; 'local2'= 18= Local use 2;
          'local3'= 19= Local use 3; 'local4'= 20= Local use 4; 'local5'= 21= Local use
          5; 'local6'= 22= Local use 6; 'local7'= 23= Local use 7;"
        type: str
        required: False
    severity:
        description:
        - "'emergency'= 0= Emergency; 'alert'= 1= Alert; 'critical'= 2= Critical; 'error'=
          3= Error; 'warning'= 4= Warning; 'notice'= 5= Notice; 'informational'= 6=
          Informational; 'debug'= 7= Debug;"
        type: str
        required: False
    format:
        description:
        - "'ascii'= A10 Text logging format (ASCII); 'cef'= Common Event Format for
          logging (default);"
        type: str
        required: False
    service_group:
        description:
        - "Bind a Service Group to the logging template (Service Group Name)"
        type: str
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
    source_address:
        description:
        - "Field source_address"
        type: dict
        required: False
        suboptions:
            ip:
                description:
                - "Specify source IP address"
                type: str
            ipv6:
                description:
                - "Specify source IPv6 address"
                type: str
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
AVAILABLE_PROPERTIES = [
    "facility",
    "format",
    "include_dest_fqdn",
    "include_http",
    "include_radius_attribute",
    "log",
    "merged_style",
    "name",
    "resolution",
    "rule",
    "service_group",
    "severity",
    "source_address",
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
        'resolution': {
            'type': 'str',
            'choices': ['seconds', '10-milliseconds']
        },
        'include_dest_fqdn': {
            'type': 'bool',
        },
        'merged_style': {
            'type': 'bool',
        },
        'log': {
            'type': 'dict',
            'http_requests': {
                'type': 'str',
                'choices': ['host', 'url']
            }
        },
        'include_radius_attribute': {
            'type': 'dict',
            'attr_cfg': {
                'type': 'list',
                'attr': {
                    'type':
                    'str',
                    'choices': [
                        'imei', 'imsi', 'msisdn', 'custom1', 'custom2',
                        'custom3'
                    ]
                },
                'attr_event': {
                    'type': 'str',
                    'choices': ['http-requests', 'sessions']
                }
            },
            'no_quote': {
                'type': 'bool',
            },
            'framed_ipv6_prefix': {
                'type': 'bool',
            },
            'prefix_length': {
                'type': 'str',
                'choices': ['32', '48', '64', '80', '96', '112']
            },
            'insert_if_not_existing': {
                'type': 'bool',
            },
            'zero_in_custom_attr': {
                'type': 'bool',
            }
        },
        'include_http': {
            'type': 'dict',
            'header_cfg': {
                'type': 'list',
                'http_header': {
                    'type':
                    'str',
                    'choices': [
                        'cookie', 'referer', 'user-agent', 'header1',
                        'header2', 'header3'
                    ]
                },
                'max_length': {
                    'type': 'int',
                },
                'custom_header_name': {
                    'type': 'str',
                },
                'custom_max_length': {
                    'type': 'int',
                }
            },
            'l4_session_info': {
                'type': 'bool',
            },
            'method': {
                'type': 'bool',
            },
            'request_number': {
                'type': 'bool',
            },
            'file_extension': {
                'type': 'bool',
            }
        },
        'rule': {
            'type': 'dict',
            'rule_http_requests': {
                'type': 'dict',
                'dest_port': {
                    'type': 'list',
                    'dest_port_number': {
                        'type': 'int',
                    },
                    'include_byte_count': {
                        'type': 'bool',
                    }
                },
                'log_every_http_request': {
                    'type': 'bool',
                },
                'max_url_len': {
                    'type': 'int',
                },
                'include_all_headers': {
                    'type': 'bool',
                },
                'disable_sequence_check': {
                    'type': 'bool',
                }
            }
        },
        'facility': {
            'type':
            'str',
            'choices': [
                'kernel', 'user', 'mail', 'daemon', 'security-authorization',
                'syslog', 'line-printer', 'news', 'uucp', 'cron',
                'security-authorization-private', 'ftp', 'ntp', 'audit',
                'alert', 'clock', 'local0', 'local1', 'local2', 'local3',
                'local4', 'local5', 'local6', 'local7'
            ]
        },
        'severity': {
            'type':
            'str',
            'choices': [
                'emergency', 'alert', 'critical', 'error', 'warning', 'notice',
                'informational', 'debug'
            ]
        },
        'format': {
            'type': 'str',
            'choices': ['ascii', 'cef']
        },
        'service_group': {
            'type': 'str',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'source_address': {
            'type': 'dict',
            'ip': {
                'type': 'str',
            },
            'ipv6': {
                'type': 'str',
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
    url_base = "/axapi/v3/fw/template/logging/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/fw/template/logging/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["logging"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["logging"].get(k) != v:
            change_results["changed"] = True
            config_changes["logging"][k] = v

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
    payload = utils.build_json("logging", module.params, AVAILABLE_PROPERTIES)
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
                    "logging"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "logging-list"] if info != "NotFound" else info
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
