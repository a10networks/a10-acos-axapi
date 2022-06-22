#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_route_map_set
description:
    - Set values in destination routing protocol
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
    sequence:
        description:
        - Key to identify parent object
        type: str
        required: True
    action:
        description:
        - Key to identify parent object
        type: str
        required: True
    route_map_tag:
        description:
        - Key to identify parent object
        type: str
        required: True
    ip:
        description:
        - "Field ip"
        type: dict
        required: False
        suboptions:
            next_hop:
                description:
                - "Field next_hop"
                type: dict
    ddos:
        description:
        - "Field ddos"
        type: dict
        required: False
        suboptions:
            class_list_name:
                description:
                - "Class-List Name"
                type: str
            class_list_cid:
                description:
                - "Class-List Cid"
                type: int
            zone:
                description:
                - "Zone Name"
                type: str
    ipv6:
        description:
        - "Field ipv6"
        type: dict
        required: False
        suboptions:
            next_hop_1:
                description:
                - "Field next_hop_1"
                type: dict
    level:
        description:
        - "Field level"
        type: dict
        required: False
        suboptions:
            value:
                description:
                - "'level-1'= Export into a level-1 area; 'level-1-2'= Export into level-1 and
          level-2; 'level-2'= Export into level-2 sub-domain;"
                type: str
    metric:
        description:
        - "Field metric"
        type: dict
        required: False
        suboptions:
            value:
                description:
                - "Metric Value (from -4294967295 to 4294967295)"
                type: str
    metric_type:
        description:
        - "Field metric_type"
        type: dict
        required: False
        suboptions:
            value:
                description:
                - "'external'= IS-IS external metric type; 'internal'= IS-IS internal metric type;
          'type-1'= OSPF external type 1 metric; 'type-2'= OSPF external type 2 metric;"
                type: str
    tag:
        description:
        - "Field tag"
        type: dict
        required: False
        suboptions:
            value:
                description:
                - "Tag value"
                type: int
    aggregator:
        description:
        - "Field aggregator"
        type: dict
        required: False
        suboptions:
            aggregator_as:
                description:
                - "Field aggregator_as"
                type: dict
    as_path:
        description:
        - "Field as_path"
        type: dict
        required: False
        suboptions:
            prepend:
                description:
                - "Prepend to the as-path (AS number)"
                type: str
            num:
                description:
                - "AS number"
                type: int
            num2:
                description:
                - "AS number"
                type: int
    atomic_aggregate:
        description:
        - "BGP atomic aggregate attribute"
        type: bool
        required: False
    comm_list:
        description:
        - "Field comm_list"
        type: dict
        required: False
        suboptions:
            v_std:
                description:
                - "Community-list number (standard)"
                type: int
            delete:
                description:
                - "Delete matching communities"
                type: bool
            v_exp:
                description:
                - "Community-list number (expanded)"
                type: int
            v_exp_delete:
                description:
                - "Delete matching communities"
                type: bool
            name:
                description:
                - "Community-list name"
                type: str
            name_delete:
                description:
                - "Delete matching communities"
                type: bool
    community:
        description:
        - "BGP community attribute"
        type: str
        required: False
    dampening_cfg:
        description:
        - "Field dampening_cfg"
        type: dict
        required: False
        suboptions:
            dampening:
                description:
                - "Enable route-flap dampening"
                type: bool
            dampening_half_time:
                description:
                - "Reachability Half-life time for the penalty(minutes)"
                type: int
            dampening_reuse:
                description:
                - "Value to start reusing a route"
                type: int
            dampening_supress:
                description:
                - "Value to start suppressing a route"
                type: int
            dampening_max_supress:
                description:
                - "Maximum duration to suppress a stable route(minutes)"
                type: int
            dampening_penalty:
                description:
                - "Un-reachability Half-life time for the penalty(minutes)"
                type: int
    extcommunity:
        description:
        - "Field extcommunity"
        type: dict
        required: False
        suboptions:
            rt:
                description:
                - "Field rt"
                type: dict
            soo:
                description:
                - "Field soo"
                type: dict
    local_preference:
        description:
        - "Field local_preference"
        type: dict
        required: False
        suboptions:
            val:
                description:
                - "Preference value"
                type: int
    originator_id:
        description:
        - "Field originator_id"
        type: dict
        required: False
        suboptions:
            originator_ip:
                description:
                - "IP address of originator"
                type: str
    weight:
        description:
        - "Field weight"
        type: dict
        required: False
        suboptions:
            weight_val:
                description:
                - "Weight value"
                type: int
    origin:
        description:
        - "Field origin"
        type: dict
        required: False
        suboptions:
            egp:
                description:
                - "remote EGP"
                type: bool
            igp:
                description:
                - "local IGP"
                type: bool
            incomplete:
                description:
                - "unknown heritage"
                type: bool
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False

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
AVAILABLE_PROPERTIES = ["aggregator", "as_path", "atomic_aggregate", "comm_list", "community", "dampening_cfg", "ddos", "extcommunity", "ip", "ipv6", "level", "local_preference", "metric", "metric_type", "origin", "originator_id", "tag", "uuid", "weight", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({'ip': {'type': 'dict', 'next_hop': {'type': 'dict', 'address': {'type': 'str', }}},
        'ddos': {'type': 'dict', 'class_list_name': {'type': 'str', }, 'class_list_cid': {'type': 'int', }, 'zone': {'type': 'str', }},
        'ipv6': {'type': 'dict', 'next_hop_1': {'type': 'dict', 'address': {'type': 'str', }, 'local': {'type': 'dict', 'address': {'type': 'str', }}}},
        'level': {'type': 'dict', 'value': {'type': 'str', 'choices': ['level-1', 'level-1-2', 'level-2']}},
        'metric': {'type': 'dict', 'value': {'type': 'str', }},
        'metric_type': {'type': 'dict', 'value': {'type': 'str', 'choices': ['external', 'internal', 'type-1', 'type-2']}},
        'tag': {'type': 'dict', 'value': {'type': 'int', }},
        'aggregator': {'type': 'dict', 'aggregator_as': {'type': 'dict', 'asn': {'type': 'int', }, 'ip': {'type': 'str', }}},
        'as_path': {'type': 'dict', 'prepend': {'type': 'str', }, 'num': {'type': 'int', }, 'num2': {'type': 'int', }},
        'atomic_aggregate': {'type': 'bool', },
        'comm_list': {'type': 'dict', 'v_std': {'type': 'int', }, 'delete': {'type': 'bool', }, 'v_exp': {'type': 'int', }, 'v_exp_delete': {'type': 'bool', }, 'name': {'type': 'str', }, 'name_delete': {'type': 'bool', }},
        'community': {'type': 'str', },
        'dampening_cfg': {'type': 'dict', 'dampening': {'type': 'bool', }, 'dampening_half_time': {'type': 'int', }, 'dampening_reuse': {'type': 'int', }, 'dampening_supress': {'type': 'int', }, 'dampening_max_supress': {'type': 'int', }, 'dampening_penalty': {'type': 'int', }},
        'extcommunity': {'type': 'dict', 'rt': {'type': 'dict', 'value': {'type': 'str', }}, 'soo': {'type': 'dict', 'value': {'type': 'str', }}},
        'local_preference': {'type': 'dict', 'val': {'type': 'int', }},
        'originator_id': {'type': 'dict', 'originator_ip': {'type': 'str', }},
        'weight': {'type': 'dict', 'weight_val': {'type': 'int', }},
        'origin': {'type': 'dict', 'egp': {'type': 'bool', }, 'igp': {'type': 'bool', }, 'incomplete': {'type': 'bool', }},
        'uuid': {'type': 'str', }
    })
    # Parent keys
    rv.update(dict(
        sequence=dict(type='str', required=True),
        action=dict(type='str', required=True),
        route_map_tag=dict(type='str', required=True),
    ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/route-map/{route_map_tag}+{action}+{sequence}/set"

    f_dict = {}
    f_dict["sequence"] = module.params["sequence"]
    f_dict["action"] = module.params["action"]
    f_dict["route_map_tag"] = module.params["route_map_tag"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/route-map/{route_map_tag}+{action}+{sequence}/set"

    f_dict = {}
    f_dict["sequence"] = module.params["sequence"]
    f_dict["action"] = module.params["action"]
    f_dict["route_map_tag"] = module.params["route_map_tag"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["set"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["set"].get(k) != v:
            change_results["changed"] = True
            config_changes["set"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(
        **call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(
            **call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("set", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(
        changed=False,
        messages="",
        modified_values={},
        axapi_calls=[],
        ansible_facts={},
        acos_info={}
    )

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

    module.client = client_factory(ansible_host, ansible_port,
                                   protocol, ansible_username,
                                   ansible_password)

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
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
             result["axapi_calls"].append(
                api_client.switch_device_context(module.client, a10_device_context_id))

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
                result["acos_info"] = info["set"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["set-list"] if info != "NotFound" else info
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
