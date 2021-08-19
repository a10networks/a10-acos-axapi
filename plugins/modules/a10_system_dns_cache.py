#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_system_dns_cache
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
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "oper",
    "sampling_enable",
    "stats",
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
    url_base = "/axapi/v3/system/dns-cache"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/system/dns-cache"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["dns-cache"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["dns-cache"].get(k) != v:
            change_results["changed"] = True
            config_changes["dns-cache"][k] = v

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
    payload = utils.build_json("dns-cache", module.params,
                               AVAILABLE_PROPERTIES)
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
                  axapi_calls=[])

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
        if existing_config['response_body'] != 'Not Found':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                result["axapi_calls"].append(
                    api_client.get(module.client, existing_url(module)))
            elif module.params.get("get_type") == "list":
                result["axapi_calls"].append(
                    api_client.get_list(module.client, existing_url(module)))
            elif module.params.get("get_type") == "oper":
                result["axapi_calls"].append(
                    api_client.get_oper(module.client, existing_url(module)))
            elif module.params.get("get_type") == "stats":
                result["axapi_calls"].append(
                    api_client.get_stats(module.client, existing_url(module)))
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.session.session_id:
            module.client.session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
