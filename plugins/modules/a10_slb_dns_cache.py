#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_dns_cache
description:
    - DNS Cache Statistics
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
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'total_q'= Total query; 'total_r'= Total server response; 'hit'=
          Total cache hit; 'bad_q'= Query not passed; 'encode_q'= Query encoded;
          'multiple_q'= Query with multiple questions; 'oversize_q'= Query exceed cache
          size; 'bad_r'= Response not passed; 'oversize_r'= Response exceed cache size;
          'encode_r'= Response encoded; 'multiple_r'= Response with multiple questions;
          'answer_r'= Response with multiple answers; 'ttl_r'= Response with short TTL;
          'ageout'= Total aged out; 'bad_answer'= Bad Answer; 'ageout_weight'= Total aged
          for lower weight; 'total_log'= Total stats log sent; 'total_alloc'= Total
          allocated; 'total_freed'= Total freed; 'current_allocate'= Current allocate;
          'current_data_allocate'= Current data allocate;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            cache_client:
                description:
                - "Field cache_client"
                type: list
            cache_entry:
                description:
                - "Field cache_entry"
                type: list
            total:
                description:
                - "Field total"
                type: int
            client:
                description:
                - "Field client"
                type: bool
            entry:
                description:
                - "Field entry"
                type: bool
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            total_q:
                description:
                - "Total query"
                type: str
            total_r:
                description:
                - "Total server response"
                type: str
            hit:
                description:
                - "Total cache hit"
                type: str
            bad_q:
                description:
                - "Query not passed"
                type: str
            encode_q:
                description:
                - "Query encoded"
                type: str
            multiple_q:
                description:
                - "Query with multiple questions"
                type: str
            oversize_q:
                description:
                - "Query exceed cache size"
                type: str
            bad_r:
                description:
                - "Response not passed"
                type: str
            oversize_r:
                description:
                - "Response exceed cache size"
                type: str
            encode_r:
                description:
                - "Response encoded"
                type: str
            multiple_r:
                description:
                - "Response with multiple questions"
                type: str
            answer_r:
                description:
                - "Response with multiple answers"
                type: str
            ttl_r:
                description:
                - "Response with short TTL"
                type: str
            ageout:
                description:
                - "Total aged out"
                type: str
            bad_answer:
                description:
                - "Bad Answer"
                type: str
            ageout_weight:
                description:
                - "Total aged for lower weight"
                type: str
            total_log:
                description:
                - "Total stats log sent"
                type: str
            total_alloc:
                description:
                - "Total allocated"
                type: str
            total_freed:
                description:
                - "Total freed"
                type: str
            current_allocate:
                description:
                - "Current allocate"
                type: str
            current_data_allocate:
                description:
                - "Current data allocate"
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
    "oper",
    "sampling_enable",
    "stats",
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
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'total_q', 'total_r', 'hit', 'bad_q', 'encode_q',
                    'multiple_q', 'oversize_q', 'bad_r', 'oversize_r',
                    'encode_r', 'multiple_r', 'answer_r', 'ttl_r', 'ageout',
                    'bad_answer', 'ageout_weight', 'total_log', 'total_alloc',
                    'total_freed', 'current_allocate', 'current_data_allocate'
                ]
            }
        },
        'oper': {
            'type': 'dict',
            'cache_client': {
                'type': 'list',
                'domain': {
                    'type': 'str',
                },
                'address': {
                    'type': 'str',
                },
                'unit_type': {
                    'type': 'str',
                },
                'curr_rate': {
                    'type': 'int',
                },
                'over_rate_limit_times': {
                    'type': 'int',
                },
                'lockup': {
                    'type': 'int',
                },
                'lockup_time': {
                    'type': 'int',
                }
            },
            'cache_entry': {
                'type': 'list',
                'name': {
                    'type': 'str',
                },
                'domain': {
                    'type': 'str',
                },
                'dnssec': {
                    'type': 'int',
                },
                'cache_type': {
                    'type': 'int',
                },
                'cache_class': {
                    'type': 'int',
                },
                'q_length': {
                    'type': 'int',
                },
                'r_length': {
                    'type': 'int',
                },
                'ttl': {
                    'type': 'int',
                },
                'age': {
                    'type': 'int',
                },
                'weight': {
                    'type': 'int',
                },
                'hits': {
                    'type': 'int',
                }
            },
            'total': {
                'type': 'int',
            },
            'client': {
                'type': 'bool',
            },
            'entry': {
                'type': 'bool',
            }
        },
        'stats': {
            'type': 'dict',
            'total_q': {
                'type': 'str',
            },
            'total_r': {
                'type': 'str',
            },
            'hit': {
                'type': 'str',
            },
            'bad_q': {
                'type': 'str',
            },
            'encode_q': {
                'type': 'str',
            },
            'multiple_q': {
                'type': 'str',
            },
            'oversize_q': {
                'type': 'str',
            },
            'bad_r': {
                'type': 'str',
            },
            'oversize_r': {
                'type': 'str',
            },
            'encode_r': {
                'type': 'str',
            },
            'multiple_r': {
                'type': 'str',
            },
            'answer_r': {
                'type': 'str',
            },
            'ttl_r': {
                'type': 'str',
            },
            'ageout': {
                'type': 'str',
            },
            'bad_answer': {
                'type': 'str',
            },
            'ageout_weight': {
                'type': 'str',
            },
            'total_log': {
                'type': 'str',
            },
            'total_alloc': {
                'type': 'str',
            },
            'total_freed': {
                'type': 'str',
            },
            'current_allocate': {
                'type': 'str',
            },
            'current_data_allocate': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/dns-cache"

    f_dict = {}

    return url_base.format(**f_dict)


def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"


def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
    return module.client.get(oper_url(module))


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
    return module.client.get(stats_url(module))


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
    url_base = "/axapi/v3/slb/dns-cache"

    f_dict = {}

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
        for k, v in payload["dns-cache"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["dns-cache"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["dns-cache"][k] = v
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
    payload = build_json("dns-cache", module)
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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
