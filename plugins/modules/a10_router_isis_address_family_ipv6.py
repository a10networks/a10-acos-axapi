#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_router_isis_address_family_ipv6
description:
    - Address family
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
    isis_tag:
        description:
        - Key to identify parent object
        type: str
        required: True
    default_information:
        description:
        - "'originate'= Distribute a default route;"
        type: str
        required: False
    adjacency_check:
        description:
        - "Check ISIS neighbor protocol support"
        type: bool
        required: False
    distance:
        description:
        - "ISIS Administrative Distance (Distance value)"
        type: int
        required: False
    multi_topology_cfg:
        description:
        - "Field multi_topology_cfg"
        type: dict
        required: False
        suboptions:
            multi_topology:
                description:
                - "Enable multi-topology mode"
                type: bool
            level:
                description:
                - "'level-1'= Level-1 only; 'level-1-2'= Level-1-2; 'level-2'= Level-2 only;"
                type: str
            transition:
                description:
                - "Accept and generate both IS-IS IPv6 and Multi-topology IPV6 TLVs"
                type: bool
            level_transition:
                description:
                - "Accept and generate both IS-IS IPv6 and Multi-topology IPV6 TLVs"
                type: bool
    summary_prefix_list:
        description:
        - "Field summary_prefix_list"
        type: list
        required: False
        suboptions:
            prefix:
                description:
                - "IPv6 prefix"
                type: str
            level:
                description:
                - "'level-1'= Summarize into level-1 area; 'level-1-2'= Summarize into both area
          and sub-domain; 'level-2'= Summarize into level-2 sub-domain;"
                type: str
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    redistribute:
        description:
        - "Field redistribute"
        type: dict
        required: False
        suboptions:
            redist_list:
                description:
                - "Field redist_list"
                type: list
            vip_list:
                description:
                - "Field vip_list"
                type: list
            isis:
                description:
                - "Field isis"
                type: dict
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
    "adjacency_check",
    "default_information",
    "distance",
    "multi_topology_cfg",
    "redistribute",
    "summary_prefix_list",
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
        'default_information': {
            'type': 'str',
            'choices': ['originate']
        },
        'adjacency_check': {
            'type': 'bool',
        },
        'distance': {
            'type': 'int',
        },
        'multi_topology_cfg': {
            'type': 'dict',
            'multi_topology': {
                'type': 'bool',
            },
            'level': {
                'type': 'str',
                'choices': ['level-1', 'level-1-2', 'level-2']
            },
            'transition': {
                'type': 'bool',
            },
            'level_transition': {
                'type': 'bool',
            }
        },
        'summary_prefix_list': {
            'type': 'list',
            'prefix': {
                'type': 'str',
            },
            'level': {
                'type': 'str',
                'choices': ['level-1', 'level-1-2', 'level-2']
            }
        },
        'uuid': {
            'type': 'str',
        },
        'redistribute': {
            'type': 'dict',
            'redist_list': {
                'type': 'list',
                'ntype': {
                    'type':
                    'str',
                    'choices': [
                        'bgp', 'connected', 'floating-ip', 'ip-nat-list',
                        'ip-nat', 'lw4o6', 'nat-map', 'static-nat', 'nat64',
                        'ospf', 'rip', 'static'
                    ]
                },
                'metric': {
                    'type': 'int',
                },
                'metric_type': {
                    'type': 'str',
                    'choices': ['external', 'internal']
                },
                'route_map': {
                    'type': 'str',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-1-2', 'level-2']
                }
            },
            'vip_list': {
                'type': 'list',
                'vip_type': {
                    'type': 'str',
                    'choices': ['only-flagged', 'only-not-flagged']
                },
                'vip_metric': {
                    'type': 'int',
                },
                'vip_route_map': {
                    'type': 'str',
                },
                'vip_metric_type': {
                    'type': 'str',
                    'choices': ['external', 'internal']
                },
                'vip_level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-1-2', 'level-2']
                }
            },
            'isis': {
                'type': 'dict',
                'level_1_from': {
                    'type': 'dict',
                    'into_1': {
                        'type': 'dict',
                        'level_2': {
                            'type': 'bool',
                        },
                        'distribute_list': {
                            'type': 'str',
                        }
                    }
                },
                'level_2_from': {
                    'type': 'dict',
                    'into_2': {
                        'type': 'dict',
                        'level_1': {
                            'type': 'bool',
                        },
                        'distribute_list': {
                            'type': 'str',
                        }
                    }
                }
            },
            'uuid': {
                'type': 'str',
            }
        }
    })
    # Parent keys
    rv.update(dict(isis_tag=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/isis/{isis_tag}/address-family/ipv6"

    f_dict = {}
    f_dict["isis_tag"] = module.params["isis_tag"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/router/isis/{isis_tag}/address-family/ipv6"

    f_dict = {}
    f_dict["isis_tag"] = module.params["isis_tag"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["ipv6"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["ipv6"].get(k) != v:
            change_results["changed"] = True
            config_changes["ipv6"][k] = v

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
    payload = utils.build_json("ipv6", module.params, AVAILABLE_PROPERTIES)
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
                result[
                    "acos_info"] = info["ipv6"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "ipv6-list"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()
        raise gex
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
