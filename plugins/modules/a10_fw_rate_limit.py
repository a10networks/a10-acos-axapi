#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_fw_rate_limit
description:
    - View Rate Limit Entries
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
    interval:
        description:
        - "'100'= 100 ms; '250'= 250 ms; '500'= 500 ms; '1000'= 1000 ms;"
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
                - "'all'= all; 'ratelimit_used_total_mem'= Total Memory Used For Rate-limiting
          (bytes); 'ratelimit_used_spm_mem'= Total SPM Memory Used For Rate-limiting
          Infra in Bytes; 'ratelimit_used_heap_mem'= Total Heap Memory Used For Rate-
          limiting Infra in Bytes; 'ratelimit_entry_alloc_frm_spm_mem'= Total Number of
          Rate-limit Entries created using SPM Memory;
          'ratelimit_high_accurate_entry_alloc_fail'= Total Number of Failures to Create
          Highly Accurate Rate-limit Entries Due to Memory Allocation Failures;
          'ratelimit_high_perf_entry_alloc_fail'= Total Number of Failures to Create
          High-Perf Rate-limit Entries Due to Memory Allocation Failures;
          'ratelimit_high_perf_entry_secondary_alloc_fail'= Total Number of Failures to
          Allocate Additional Memory to Existing High-Perf Rate-limit Entries;
          'ratelimit_entry_alloc_fail_rate_too_high'= Total Number of Attempts to
          Configure Too High Rate Limits;
          'ratelimit_entry_alloc_fail_metric_count_gt_supported'= Total Number of
          Failures to Create High-Perf Rate-limit Entries Because of Too Many Metrics;
          'ratelimit_entry_count_t2_key'= Number of Total Rate-limit Entries;
          'ratelimit_entry_count_fw_rule_uid'= Number of Rate-limit Entries with Scope
          Aggregate; 'ratelimit_entry_count_ip_addr'= Number of Rate-limit Entries with
          Scope IPv4 Address; 'ratelimit_entry_count_ip6_addr'= Number of Rate-limit
          Entries with Scope IPv6 Address; 'ratelimit_entry_count_session_id'= Number of
          Rate-limit Entries with Scope Session ID;
          'ratelimit_entry_count_rule_ipv4_prefix'= Number of Rate-limit Entries with
          Scope IPv4 Prefix; 'ratelimit_entry_count_rule_ipv6_prefix'= Number of Rate-
          limit Entries with Scope IPv6 Prefix; 'ratelimit_entry_count_parent_uid'=
          Number of Parent Rate-limit Entries with Scope Aggregate;
          'ratelimit_entry_count_parent_ipv4_prefix'= Number of Parent Rate-limit Entries
          with Scope IPv4 Prefix; 'ratelimit_entry_count_parent_ipv6_prefix'= Number of
          Parent Rate-limit Entries with Scope IPv6 Prefix;
          'ratelimit_infra_generic_errors'= Current Number of Generic Errors Encountered
          in Ratelimit Infra; 'ratelimit_entry_count_rule_ip'= Number of Rate-limit
          Entries with Scope IP; 'ratelimit_entry_count_parent_ip'= Number of Parent
          Rate-limit Entries with Scope IP;"
                type: str
    summary:
        description:
        - "Field summary"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            rate_limit_list:
                description:
                - "Field rate_limit_list"
                type: list
            v4_address:
                description:
                - "Field v4_address"
                type: str
            v4_netmask:
                description:
                - "Field v4_netmask"
                type: str
            v6_prefix:
                description:
                - "Field v6_prefix"
                type: str
            template_id:
                description:
                - "Field template_id"
                type: int
            summary:
                description:
                - "Field summary"
                type: dict
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            ratelimit_used_total_mem:
                description:
                - "Total Memory Used For Rate-limiting (bytes)"
                type: str
            ratelimit_entry_count_t2_key:
                description:
                - "Number of Total Rate-limit Entries"
                type: str
            ratelimit_entry_count_fw_rule_uid:
                description:
                - "Number of Rate-limit Entries with Scope Aggregate"
                type: str
            ratelimit_entry_count_ip_addr:
                description:
                - "Number of Rate-limit Entries with Scope IPv4 Address"
                type: str
            ratelimit_entry_count_ip6_addr:
                description:
                - "Number of Rate-limit Entries with Scope IPv6 Address"
                type: str
            ratelimit_entry_count_session_id:
                description:
                - "Number of Rate-limit Entries with Scope Session ID"
                type: str
            ratelimit_entry_count_rule_ipv4_prefix:
                description:
                - "Number of Rate-limit Entries with Scope IPv4 Prefix"
                type: str
            ratelimit_entry_count_rule_ipv6_prefix:
                description:
                - "Number of Rate-limit Entries with Scope IPv6 Prefix"
                type: str
            ratelimit_entry_count_parent_uid:
                description:
                - "Number of Parent Rate-limit Entries with Scope Aggregate"
                type: str
            ratelimit_entry_count_parent_ipv4_prefix:
                description:
                - "Number of Parent Rate-limit Entries with Scope IPv4 Prefix"
                type: str
            ratelimit_entry_count_parent_ipv6_prefix:
                description:
                - "Number of Parent Rate-limit Entries with Scope IPv6 Prefix"
                type: str
            ratelimit_entry_count_rule_ip:
                description:
                - "Number of Rate-limit Entries with Scope IP"
                type: str
            ratelimit_entry_count_parent_ip:
                description:
                - "Number of Parent Rate-limit Entries with Scope IP"
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
AVAILABLE_PROPERTIES = ["interval", "oper", "sampling_enable", "stats", "summary", "uuid", ]


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
        'interval': {
            'type': 'str',
            'choices': ['100', '250', '500', '1000']
            },
        'uuid': {
            'type': 'str',
            },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'ratelimit_used_total_mem', 'ratelimit_used_spm_mem', 'ratelimit_used_heap_mem', 'ratelimit_entry_alloc_frm_spm_mem', 'ratelimit_high_accurate_entry_alloc_fail', 'ratelimit_high_perf_entry_alloc_fail', 'ratelimit_high_perf_entry_secondary_alloc_fail', 'ratelimit_entry_alloc_fail_rate_too_high',
                    'ratelimit_entry_alloc_fail_metric_count_gt_supported', 'ratelimit_entry_count_t2_key', 'ratelimit_entry_count_fw_rule_uid', 'ratelimit_entry_count_ip_addr', 'ratelimit_entry_count_ip6_addr', 'ratelimit_entry_count_session_id', 'ratelimit_entry_count_rule_ipv4_prefix', 'ratelimit_entry_count_rule_ipv6_prefix',
                    'ratelimit_entry_count_parent_uid', 'ratelimit_entry_count_parent_ipv4_prefix', 'ratelimit_entry_count_parent_ipv6_prefix', 'ratelimit_infra_generic_errors', 'ratelimit_entry_count_rule_ip', 'ratelimit_entry_count_parent_ip'
                    ]
                }
            },
        'summary': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'rate_limit_list': {
                'type': 'list',
                'address': {
                    'type': 'str',
                    },
                'prefix_len': {
                    'type': 'int',
                    },
                'rule_name': {
                    'type': 'str',
                    },
                'template_id': {
                    'type': 'int',
                    },
                'ntype': {
                    'type': 'str',
                    },
                'cps_received': {
                    'type': 'int',
                    },
                'cps_allowed': {
                    'type': 'int',
                    },
                'uplink_traffic_received': {
                    'type': 'int',
                    },
                'uplink_traffic_allowed': {
                    'type': 'int',
                    },
                'downlink_traffic_received': {
                    'type': 'int',
                    },
                'downlink_traffic_allowed': {
                    'type': 'int',
                    },
                'total_traffic_received': {
                    'type': 'int',
                    },
                'total_traffic_allowed': {
                    'type': 'int',
                    },
                'drop_count': {
                    'type': 'int',
                    }
                },
            'v4_address': {
                'type': 'str',
                },
            'v4_netmask': {
                'type': 'str',
                },
            'v6_prefix': {
                'type': 'str',
                },
            'template_id': {
                'type': 'int',
                },
            'summary': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'mem_reserved': {
                        'type': 'int',
                        },
                    'mem_used': {
                        'type': 'int',
                        },
                    'alloc_failures': {
                        'type': 'int',
                        },
                    'total_num_entries': {
                        'type': 'int',
                        },
                    'total_entries_scope_aggregate': {
                        'type': 'int',
                        },
                    'total_entries_scope_subscriber_ip': {
                        'type': 'int',
                        },
                    'total_entries_scope_subscriber_prefix': {
                        'type': 'int',
                        },
                    'total_entries_scope_parent': {
                        'type': 'int',
                        },
                    'total_entries_scope_parent_subscriber_ip': {
                        'type': 'int',
                        },
                    'total_entries_scope_parent_subscriber_prefix': {
                        'type': 'int',
                        }
                    }
                }
            },
        'stats': {
            'type': 'dict',
            'ratelimit_used_total_mem': {
                'type': 'str',
                },
            'ratelimit_entry_count_t2_key': {
                'type': 'str',
                },
            'ratelimit_entry_count_fw_rule_uid': {
                'type': 'str',
                },
            'ratelimit_entry_count_ip_addr': {
                'type': 'str',
                },
            'ratelimit_entry_count_ip6_addr': {
                'type': 'str',
                },
            'ratelimit_entry_count_session_id': {
                'type': 'str',
                },
            'ratelimit_entry_count_rule_ipv4_prefix': {
                'type': 'str',
                },
            'ratelimit_entry_count_rule_ipv6_prefix': {
                'type': 'str',
                },
            'ratelimit_entry_count_parent_uid': {
                'type': 'str',
                },
            'ratelimit_entry_count_parent_ipv4_prefix': {
                'type': 'str',
                },
            'ratelimit_entry_count_parent_ipv6_prefix': {
                'type': 'str',
                },
            'ratelimit_entry_count_rule_ip': {
                'type': 'str',
                },
            'ratelimit_entry_count_parent_ip': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/rate-limit"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/fw/rate-limit"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["rate-limit"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["rate-limit"].get(k) != v:
            change_results["changed"] = True
            config_changes["rate-limit"][k] = v

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
    payload = utils.build_json("rate-limit", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["rate-limit"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["rate-limit-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["rate-limit"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["rate-limit"]["stats"] if info != "NotFound" else info
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
