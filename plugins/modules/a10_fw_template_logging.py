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

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

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
    url_base = "/axapi/v3/fw/template/logging/{name}"

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
        for k, v in payload["logging"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["logging"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["logging"][k] = v
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
    payload = build_json("logging", module)
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
