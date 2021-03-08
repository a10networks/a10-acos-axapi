#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_diameter
description:
    - diameter template
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
        - "diameter template Name"
        type: str
        required: True
    customize_cea:
        description:
        - "customizing cea response"
        type: bool
        required: False
    avp_code:
        description:
        - "avp code"
        type: int
        required: False
    avp_string:
        description:
        - "pattern to be matched in the avp string name, max length 127 bytes"
        type: str
        required: False
    service_group_name:
        description:
        - "service group name, this is the service group that the message needs to be
          copied to"
        type: str
        required: False
    dwr_time:
        description:
        - "dwr health-check timer interval (in 100 milli second unit, default is 100, 0
          means unset this option)"
        type: int
        required: False
    idle_timeout:
        description:
        - "user sesison idle timeout (in minutes, default is 5)"
        type: int
        required: False
    multiple_origin_host:
        description:
        - "allowing multiple origin-host to a single server"
        type: bool
        required: False
    origin_realm:
        description:
        - "origin-realm name avp"
        type: str
        required: False
    product_name:
        description:
        - "product name avp"
        type: str
        required: False
    vendor_id:
        description:
        - "vendor-id avp (Vendor Id)"
        type: int
        required: False
    session_age:
        description:
        - "user session age allowed (default 10), this is not idle-time (in minutes)"
        type: int
        required: False
    dwr_up_retry:
        description:
        - "number of successful dwr health-check before declaring target up"
        type: int
        required: False
    terminate_on_cca_t:
        description:
        - "remove diameter session when receiving CCA-T message"
        type: bool
        required: False
    forward_unknown_session_id:
        description:
        - "Forward server message even it has unknown session id"
        type: bool
        required: False
    forward_to_latest_server:
        description:
        - "Forward client message to the latest server that sends message with the same
          session id"
        type: bool
        required: False
    load_balance_on_session_id:
        description:
        - "Load balance based on the session id"
        type: bool
        required: False
    message_code_list:
        description:
        - "Field message_code_list"
        type: list
        required: False
        suboptions:
            message_code:
                description:
                - "Field message_code"
                type: int
    avp_list:
        description:
        - "Field avp_list"
        type: list
        required: False
        suboptions:
            avp:
                description:
                - "customize avps for cer to the server (avp number)"
                type: int
            int32:
                description:
                - "32 bits integer"
                type: int
            int64:
                description:
                - "64 bits integer"
                type: int
            string:
                description:
                - "String (string name, max length 127 bytes)"
                type: str
            mandatory:
                description:
                - "mandatory avp"
                type: bool
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
    origin_host:
        description:
        - "Field origin_host"
        type: dict
        required: False
        suboptions:
            origin_host_name:
                description:
                - "origin-host name avp"
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
    "avp_code",
    "avp_list",
    "avp_string",
    "customize_cea",
    "dwr_time",
    "dwr_up_retry",
    "forward_to_latest_server",
    "forward_unknown_session_id",
    "idle_timeout",
    "load_balance_on_session_id",
    "message_code_list",
    "multiple_origin_host",
    "name",
    "origin_host",
    "origin_realm",
    "product_name",
    "service_group_name",
    "session_age",
    "terminate_on_cca_t",
    "user_tag",
    "uuid",
    "vendor_id",
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
        'customize_cea': {
            'type': 'bool',
        },
        'avp_code': {
            'type': 'int',
        },
        'avp_string': {
            'type': 'str',
        },
        'service_group_name': {
            'type': 'str',
        },
        'dwr_time': {
            'type': 'int',
        },
        'idle_timeout': {
            'type': 'int',
        },
        'multiple_origin_host': {
            'type': 'bool',
        },
        'origin_realm': {
            'type': 'str',
        },
        'product_name': {
            'type': 'str',
        },
        'vendor_id': {
            'type': 'int',
        },
        'session_age': {
            'type': 'int',
        },
        'dwr_up_retry': {
            'type': 'int',
        },
        'terminate_on_cca_t': {
            'type': 'bool',
        },
        'forward_unknown_session_id': {
            'type': 'bool',
        },
        'forward_to_latest_server': {
            'type': 'bool',
        },
        'load_balance_on_session_id': {
            'type': 'bool',
        },
        'message_code_list': {
            'type': 'list',
            'message_code': {
                'type': 'int',
            }
        },
        'avp_list': {
            'type': 'list',
            'avp': {
                'type': 'int',
            },
            'int32': {
                'type': 'int',
            },
            'int64': {
                'type': 'int',
            },
            'string': {
                'type': 'str',
            },
            'mandatory': {
                'type': 'bool',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'origin_host': {
            'type': 'dict',
            'origin_host_name': {
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
    url_base = "/axapi/v3/slb/template/diameter/{name}"

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
    url_base = "/axapi/v3/slb/template/diameter/{name}"

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
        for k, v in payload["diameter"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["diameter"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["diameter"][k] = v
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
    payload = build_json("diameter", module)
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
