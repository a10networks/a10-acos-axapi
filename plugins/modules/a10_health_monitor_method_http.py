#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_health_monitor_method_http
description:
    - HTTP type
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
    monitor_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    http:
        description:
        - "HTTP type"
        type: bool
        required: False
    http_port:
        description:
        - "Specify HTTP Port (Specify port number (default 80))"
        type: int
        required: False
    http_expect:
        description:
        - "Specify what you expect from the response message"
        type: bool
        required: False
    http_response_code:
        description:
        - "Specify response code range (e.g. 200,400-430) (Format is xx,xx-xx (xx between
          [100, 899]))"
        type: str
        required: False
    response_code_regex:
        description:
        - "Specify response code range with Regex (code with Regex, such as
          [2-5][0-9][0-9])"
        type: str
        required: False
    http_text:
        description:
        - "Specify text expected"
        type: str
        required: False
    text_regex:
        description:
        - "Specify text expected  with Regex"
        type: str
        required: False
    http_host:
        description:
        - "Specify 'Host=' header used in request (enclose IPv6 address in [])"
        type: str
        required: False
    http_maintenance_code:
        description:
        - "Specify response code for maintenance (Format is xx,xx-xx (xx between [100,
          899]))"
        type: str
        required: False
    http_url:
        description:
        - "Specify URL string, default is GET /"
        type: bool
        required: False
    url_type:
        description:
        - "'GET'= HTTP GET method; 'POST'= HTTP POST method; 'HEAD'= HTTP HEAD method;"
        type: str
        required: False
    url_path:
        description:
        - "Specify URL path, default is '/'"
        type: str
        required: False
    post_path:
        description:
        - "Specify URL path, default is '/'"
        type: str
        required: False
    post_type:
        description:
        - "'postdata'= Specify the HTTP post data; 'postfile'= Specify the HTTP post data;"
        type: str
        required: False
    http_postdata:
        description:
        - "Specify the HTTP post data (Input post data here)"
        type: str
        required: False
    http_postfile:
        description:
        - "Specify the HTTP post data (Input post data file name here)"
        type: str
        required: False
    http_username:
        description:
        - "Specify the username"
        type: str
        required: False
    http_password:
        description:
        - "Specify the user password"
        type: bool
        required: False
    http_password_string:
        description:
        - "Specify password, '' means empty password"
        type: str
        required: False
    http_encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED password string)"
        type: str
        required: False
    http_kerberos_auth:
        description:
        - "Http Kerberos Auth"
        type: bool
        required: False
    http_kerberos_realm:
        description:
        - "Specify realm of Kerberos server"
        type: str
        required: False
    http_kerberos_kdc:
        description:
        - "Field http_kerberos_kdc"
        type: dict
        required: False
        suboptions:
            http_kerberos_hostip:
                description:
                - "Kdc's hostname(length=1-31) or IP address"
                type: str
            http_kerberos_hostipv6:
                description:
                - "Server's IPV6 address"
                type: str
            http_kerberos_port:
                description:
                - "Specify the kdc port"
                type: int
            http_kerberos_portv6:
                description:
                - "Specify the kdc port"
                type: int
    uuid:
        description:
        - "uuid of the object"
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
    "http",
    "http_encrypted",
    "http_expect",
    "http_host",
    "http_kerberos_auth",
    "http_kerberos_kdc",
    "http_kerberos_realm",
    "http_maintenance_code",
    "http_password",
    "http_password_string",
    "http_port",
    "http_postdata",
    "http_postfile",
    "http_response_code",
    "http_text",
    "http_url",
    "http_username",
    "post_path",
    "post_type",
    "response_code_regex",
    "text_regex",
    "url_path",
    "url_type",
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
        'http': {
            'type': 'bool',
        },
        'http_port': {
            'type': 'int',
        },
        'http_expect': {
            'type': 'bool',
        },
        'http_response_code': {
            'type': 'str',
        },
        'response_code_regex': {
            'type': 'str',
        },
        'http_text': {
            'type': 'str',
        },
        'text_regex': {
            'type': 'str',
        },
        'http_host': {
            'type': 'str',
        },
        'http_maintenance_code': {
            'type': 'str',
        },
        'http_url': {
            'type': 'bool',
        },
        'url_type': {
            'type': 'str',
            'choices': ['GET', 'POST', 'HEAD']
        },
        'url_path': {
            'type': 'str',
        },
        'post_path': {
            'type': 'str',
        },
        'post_type': {
            'type': 'str',
            'choices': ['postdata', 'postfile']
        },
        'http_postdata': {
            'type': 'str',
        },
        'http_postfile': {
            'type': 'str',
        },
        'http_username': {
            'type': 'str',
        },
        'http_password': {
            'type': 'bool',
        },
        'http_password_string': {
            'type': 'str',
        },
        'http_encrypted': {
            'type': 'str',
        },
        'http_kerberos_auth': {
            'type': 'bool',
        },
        'http_kerberos_realm': {
            'type': 'str',
        },
        'http_kerberos_kdc': {
            'type': 'dict',
            'http_kerberos_hostip': {
                'type': 'str',
            },
            'http_kerberos_hostipv6': {
                'type': 'str',
            },
            'http_kerberos_port': {
                'type': 'int',
            },
            'http_kerberos_portv6': {
                'type': 'int',
            }
        },
        'uuid': {
            'type': 'str',
        }
    })
    # Parent keys
    rv.update(dict(monitor_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/health/monitor/{monitor_name}/method/http"

    f_dict = {}
    f_dict["monitor_name"] = module.params["monitor_name"]

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
    url_base = "/axapi/v3/health/monitor/{monitor_name}/method/http"

    f_dict = {}
    f_dict["monitor_name"] = module.params["monitor_name"]

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
        for k, v in payload["http"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["http"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["http"][k] = v
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
    payload = build_json("http", module)
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
