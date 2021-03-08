#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_dns
description:
    - DNS template
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
        - "DNS Template Name"
        type: str
        required: True
    default_policy:
        description:
        - "'nocache'= Cache disable; 'cache'= Cache enable;"
        type: str
        required: False
    disable_dns_template:
        description:
        - "Disable DNS template"
        type: bool
        required: False
    period:
        description:
        - "Period in minutes"
        type: int
        required: False
    drop:
        description:
        - "Drop the malformed query"
        type: bool
        required: False
    forward:
        description:
        - "Forward to service group (Service group name)"
        type: str
        required: False
    max_query_length:
        description:
        - "Define Maximum DNS Query Length, default is unlimited (Specify Maximum Length)"
        type: int
        required: False
    max_cache_entry_size:
        description:
        - "Define maximum cache entry size (Maximum cache entry size per VIP)"
        type: int
        required: False
    max_cache_size:
        description:
        - "Define maximum cache size (Maximum cache entry per VIP)"
        type: int
        required: False
    enable_cache_sharing:
        description:
        - "Enable DNS cache sharing"
        type: bool
        required: False
    redirect_to_tcp_port:
        description:
        - "Direct the client to retry with TCP for DNS UDP request"
        type: bool
        required: False
    query_id_switch:
        description:
        - "Use DNS query ID to create sesion"
        type: bool
        required: False
    dnssec_service_group:
        description:
        - "Use different service group if DNSSEC DO bit set (Service Group Name)"
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
    class_list:
        description:
        - "Field class_list"
        type: dict
        required: False
        suboptions:
            name:
                description:
                - "Specify a class list name"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            lid_list:
                description:
                - "Field lid_list"
                type: list
    response_rate_limiting:
        description:
        - "Field response_rate_limiting"
        type: dict
        required: False
        suboptions:
            response_rate:
                description:
                - "Responses exceeding this rate within the window will be dropped (default 5 per
          second)"
                type: int
            filter_response_rate:
                description:
                - "Maximum allowed request rate for the filter. This should match average traffic.
          (default 20 per two seconds)"
                type: int
            slip_rate:
                description:
                - "Every n'th response that would be rate-limited will be let through instead"
                type: int
            window:
                description:
                - "Rate-Limiting Interval in Seconds (default is one)"
                type: int
            enable_log:
                description:
                - "Enable logging"
                type: bool
            action:
                description:
                - "'log-only'= Only log rate-limiting, do not actually rate limit. Requires
          enable-log configuration; 'rate-limit'= Rate-Limit based on configuration
          (Default); 'whitelist'= Whitelist, disable rate-limiting;"
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
    "class_list",
    "default_policy",
    "disable_dns_template",
    "dnssec_service_group",
    "drop",
    "enable_cache_sharing",
    "forward",
    "max_cache_entry_size",
    "max_cache_size",
    "max_query_length",
    "name",
    "period",
    "query_id_switch",
    "redirect_to_tcp_port",
    "response_rate_limiting",
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
        'default_policy': {
            'type': 'str',
            'choices': ['nocache', 'cache']
        },
        'disable_dns_template': {
            'type': 'bool',
        },
        'period': {
            'type': 'int',
        },
        'drop': {
            'type': 'bool',
        },
        'forward': {
            'type': 'str',
        },
        'max_query_length': {
            'type': 'int',
        },
        'max_cache_entry_size': {
            'type': 'int',
        },
        'max_cache_size': {
            'type': 'int',
        },
        'enable_cache_sharing': {
            'type': 'bool',
        },
        'redirect_to_tcp_port': {
            'type': 'bool',
        },
        'query_id_switch': {
            'type': 'bool',
        },
        'dnssec_service_group': {
            'type': 'str',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'class_list': {
            'type': 'dict',
            'name': {
                'type': 'str',
            },
            'uuid': {
                'type': 'str',
            },
            'lid_list': {
                'type': 'list',
                'lidnum': {
                    'type': 'int',
                    'required': True,
                },
                'conn_rate_limit': {
                    'type': 'int',
                },
                'per': {
                    'type': 'int',
                },
                'over_limit_action': {
                    'type': 'bool',
                },
                'action_value': {
                    'type': 'str',
                    'choices':
                    ['dns-cache-disable', 'dns-cache-enable', 'forward']
                },
                'lockout': {
                    'type': 'int',
                },
                'log': {
                    'type': 'bool',
                },
                'log_interval': {
                    'type': 'int',
                },
                'dns': {
                    'type': 'dict',
                    'cache_action': {
                        'type': 'str',
                        'choices': ['cache-disable', 'cache-enable']
                    },
                    'ttl': {
                        'type': 'int',
                    },
                    'weight': {
                        'type': 'int',
                    },
                    'honor_server_response_ttl': {
                        'type': 'bool',
                    }
                },
                'uuid': {
                    'type': 'str',
                },
                'user_tag': {
                    'type': 'str',
                }
            }
        },
        'response_rate_limiting': {
            'type': 'dict',
            'response_rate': {
                'type': 'int',
            },
            'filter_response_rate': {
                'type': 'int',
            },
            'slip_rate': {
                'type': 'int',
            },
            'window': {
                'type': 'int',
            },
            'enable_log': {
                'type': 'bool',
            },
            'action': {
                'type': 'str',
                'choices': ['log-only', 'rate-limit', 'whitelist']
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
    url_base = "/axapi/v3/slb/template/dns/{name}"

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
    url_base = "/axapi/v3/slb/template/dns/{name}"

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
        for k, v in payload["dns"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["dns"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["dns"][k] = v
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
    payload = build_json("dns", module)
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
