#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_network_vlan
description:
    - Configure VLAN
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
    vlan_num:
        description:
        - "VLAN number"
        type: int
        required: True
    shared_vlan:
        description:
        - "Configure VLAN as a shared VLAN"
        type: bool
        required: False
    untagged_eth_list:
        description:
        - "Field untagged_eth_list"
        type: list
        required: False
        suboptions:
            untagged_ethernet_start:
                description:
                - "Ethernet port (Interface number)"
                type: str
            untagged_ethernet_end:
                description:
                - "Ethernet port"
                type: str
    untagged_trunk_list:
        description:
        - "Field untagged_trunk_list"
        type: list
        required: False
        suboptions:
            untagged_trunk_start:
                description:
                - "Trunk groups"
                type: int
            untagged_trunk_end:
                description:
                - "Trunk Group"
                type: int
    untagged_lif:
        description:
        - "Logical tunnel interface (Logical tunnel interface name)"
        type: str
        required: False
    tagged_eth_list:
        description:
        - "Field tagged_eth_list"
        type: list
        required: False
        suboptions:
            tagged_ethernet_start:
                description:
                - "Ethernet port (Interface number)"
                type: str
            tagged_ethernet_end:
                description:
                - "Ethernet port"
                type: str
    tagged_trunk_list:
        description:
        - "Field tagged_trunk_list"
        type: list
        required: False
        suboptions:
            tagged_trunk_start:
                description:
                - "Trunk groups"
                type: int
            tagged_trunk_end:
                description:
                - "Trunk Group"
                type: int
    ve:
        description:
        - "ve number"
        type: int
        required: False
    name:
        description:
        - "VLAN name"
        type: str
        required: False
    traffic_distribution_mode:
        description:
        - "'sip'= sip; 'dip'= dip; 'primary'= primary; 'blade'= blade; 'l4-src-port'=
          l4-src-port; 'l4-dst-port'= l4-dst-port;"
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'broadcast_count'= Broadcast counter; 'multicast_count'= Multicast
          counter; 'ip_multicast_count'= IP Multicast counter; 'unknown_unicast_count'=
          Unknown Unicast counter; 'mac_movement_count'= Mac Movement counter;
          'shared_vlan_partition_switched_counter'= SVLAN Partition switched counter;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            vlan_name:
                description:
                - "Field vlan_name"
                type: str
            ve_num:
                description:
                - "Field ve_num"
                type: int
            is_shared_vlan:
                description:
                - "Field is_shared_vlan"
                type: str
            un_tagg_eth_ports:
                description:
                - "Field un_tagg_eth_ports"
                type: dict
            tagg_eth_ports:
                description:
                - "Field tagg_eth_ports"
                type: dict
            un_tagg_logical_ports:
                description:
                - "Field un_tagg_logical_ports"
                type: dict
            tagg_logical_ports:
                description:
                - "Field tagg_logical_ports"
                type: dict
            span_tree:
                description:
                - "Field span_tree"
                type: str
            vlan_num:
                description:
                - "VLAN number"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            broadcast_count:
                description:
                - "Broadcast counter"
                type: str
            multicast_count:
                description:
                - "Multicast counter"
                type: str
            ip_multicast_count:
                description:
                - "IP Multicast counter"
                type: str
            unknown_unicast_count:
                description:
                - "Unknown Unicast counter"
                type: str
            mac_movement_count:
                description:
                - "Mac Movement counter"
                type: str
            shared_vlan_partition_switched_counter:
                description:
                - "SVLAN Partition switched counter"
                type: str
            vlan_num:
                description:
                - "VLAN number"
                type: int

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
    "name",
    "oper",
    "sampling_enable",
    "shared_vlan",
    "stats",
    "tagged_eth_list",
    "tagged_trunk_list",
    "traffic_distribution_mode",
    "untagged_eth_list",
    "untagged_lif",
    "untagged_trunk_list",
    "user_tag",
    "uuid",
    "ve",
    "vlan_num",
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
        'vlan_num': {
            'type': 'int',
            'required': True,
        },
        'shared_vlan': {
            'type': 'bool',
        },
        'untagged_eth_list': {
            'type': 'list',
            'untagged_ethernet_start': {
                'type': 'str',
            },
            'untagged_ethernet_end': {
                'type': 'str',
            }
        },
        'untagged_trunk_list': {
            'type': 'list',
            'untagged_trunk_start': {
                'type': 'int',
            },
            'untagged_trunk_end': {
                'type': 'int',
            }
        },
        'untagged_lif': {
            'type': 'str',
        },
        'tagged_eth_list': {
            'type': 'list',
            'tagged_ethernet_start': {
                'type': 'str',
            },
            'tagged_ethernet_end': {
                'type': 'str',
            }
        },
        'tagged_trunk_list': {
            'type': 'list',
            'tagged_trunk_start': {
                'type': 'int',
            },
            'tagged_trunk_end': {
                'type': 'int',
            }
        },
        've': {
            'type': 'int',
        },
        'name': {
            'type': 'str',
        },
        'traffic_distribution_mode': {
            'type':
            'str',
            'choices':
            ['sip', 'dip', 'primary', 'blade', 'l4-src-port', 'l4-dst-port']
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'broadcast_count', 'multicast_count',
                    'ip_multicast_count', 'unknown_unicast_count',
                    'mac_movement_count',
                    'shared_vlan_partition_switched_counter'
                ]
            }
        },
        'oper': {
            'type': 'dict',
            'vlan_name': {
                'type': 'str',
            },
            've_num': {
                'type': 'int',
            },
            'is_shared_vlan': {
                'type': 'str',
            },
            'un_tagg_eth_ports': {
                'type': 'dict',
                'ports': {
                    'type': 'int',
                }
            },
            'tagg_eth_ports': {
                'type': 'dict',
                'ports': {
                    'type': 'int',
                }
            },
            'un_tagg_logical_ports': {
                'type': 'dict',
                'ports': {
                    'type': 'int',
                }
            },
            'tagg_logical_ports': {
                'type': 'dict',
                'ports': {
                    'type': 'int',
                }
            },
            'span_tree': {
                'type': 'str',
            },
            'vlan_num': {
                'type': 'int',
                'required': True,
            }
        },
        'stats': {
            'type': 'dict',
            'broadcast_count': {
                'type': 'str',
            },
            'multicast_count': {
                'type': 'str',
            },
            'ip_multicast_count': {
                'type': 'str',
            },
            'unknown_unicast_count': {
                'type': 'str',
            },
            'mac_movement_count': {
                'type': 'str',
            },
            'shared_vlan_partition_switched_counter': {
                'type': 'str',
            },
            'vlan_num': {
                'type': 'int',
                'required': True,
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/network/vlan/{vlan-num}"

    f_dict = {}
    f_dict["vlan-num"] = module.params["vlan_num"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/network/vlan/{vlan-num}"

    f_dict = {}
    f_dict["vlan-num"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["vlan"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["vlan"].get(k) != v:
            change_results["changed"] = True
            config_changes["vlan"][k] = v

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
    payload = utils.build_json("vlan", module.params, AVAILABLE_PROPERTIES)
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
                    "acos_info"] = info["vlan"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "vlan-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client,
                                                      existing_url(module),
                                                      params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["vlan"][
                    "oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client,
                                                       existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["vlan"][
                    "stats"] if info != "NotFound" else info
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
