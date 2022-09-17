#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_router_ipv6_ospf
description:
    - Open Shortest Path First (OSPFv3)
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
    process_id:
        description:
        - "OSPFv3 process tag"
        type: str
        required: True
    abr_type_option:
        description:
        - "'cisco'= Alternative ABR, Cisco implementation (RFC3509); 'ibm'= Alternative
          ABR, IBM implementation (RFC3509); 'standard'= Standard behavior (RFC2328);"
        type: str
        required: False
    auto_cost_reference_bandwidth:
        description:
        - "Use reference bandwidth method to assign OSPF cost (The reference bandwidth in
          terms of Mbits per second)"
        type: int
        required: False
    bfd_all_interfaces:
        description:
        - "Enable BFD on all interfaces"
        type: bool
        required: False
    default_metric:
        description:
        - "Set metric of redistributed routes (Default metric)"
        type: int
        required: False
    distribute_internal_list:
        description:
        - "Field distribute_internal_list"
        type: list
        required: False
        suboptions:
            ntype:
                description:
                - "'lw4o6'= LW4O6 Prefix; 'nat64'= NAT64 Prefix; 'static-nat'= Static NAT;
          'floating-ip'= Floating IP; 'ip-nat'= IP NAT; 'ip-nat-list'= IP NAT list;
          'vip'= Only not flagged Virtual IP (VIP); 'vip-only-flagged'= Selected Virtual
          IP (VIP);"
                type: str
            area_ipv4:
                description:
                - "OSPF area ID in IP address format"
                type: str
            area_num:
                description:
                - "OSPF area ID as a decimal value"
                type: int
            cost:
                description:
                - "Cost"
                type: int
    distribute_list:
        description:
        - "Field distribute_list"
        type: dict
        required: False
        suboptions:
            prefix_list:
                description:
                - "Field prefix_list"
                type: dict
    log_adjacency_changes:
        description:
        - "'detail'= Log changes in adjacency state; 'disable'= Disable logging;"
        type: str
        required: False
    ha_standby_extra_cost:
        description:
        - "Field ha_standby_extra_cost"
        type: list
        required: False
        suboptions:
            extra_cost:
                description:
                - "The extra cost value"
                type: int
            group:
                description:
                - "Group (Group ID)"
                type: int
    max_concurrent_dd:
        description:
        - "Maximum number allowed to process DD concurrently (Number of DD process)"
        type: int
        required: False
    passive_interface:
        description:
        - "Field passive_interface"
        type: dict
        required: False
        suboptions:
            loopback_cfg:
                description:
                - "Field loopback_cfg"
                type: list
            trunk_cfg:
                description:
                - "Field trunk_cfg"
                type: list
            ve_cfg:
                description:
                - "Field ve_cfg"
                type: list
            tunnel_cfg:
                description:
                - "Field tunnel_cfg"
                type: list
            eth_cfg:
                description:
                - "Field eth_cfg"
                type: list
    router_id:
        description:
        - "router-id for the OSPF process (OSPFv3 router-id in IPv4 address format)"
        type: str
        required: False
    timers:
        description:
        - "Field timers"
        type: dict
        required: False
        suboptions:
            spf:
                description:
                - "Field spf"
                type: dict
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
    default_information:
        description:
        - "Field default_information"
        type: dict
        required: False
        suboptions:
            originate:
                description:
                - "Distribute a default route"
                type: bool
            always:
                description:
                - "Always advertise default route"
                type: bool
            metric:
                description:
                - "OSPF default metric (OSPF metric)"
                type: int
            metric_type:
                description:
                - "OSPF metric type for default routes"
                type: int
            route_map:
                description:
                - "Route map reference (Pointer to route-map entries)"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    area_list:
        description:
        - "Field area_list"
        type: list
        required: False
        suboptions:
            area_ipv4:
                description:
                - "OSPFv3 area ID in IP address format"
                type: str
            area_num:
                description:
                - "OSPFv3 area ID as a decimal value"
                type: int
            default_cost:
                description:
                - "Set the summary-default cost of a NSSA or stub area (Stub's advertised default
          summary cost)"
                type: int
            range_list:
                description:
                - "Field range_list"
                type: list
            stub:
                description:
                - "Configure OSPFv3 area as stub"
                type: bool
            no_summary:
                description:
                - "Do not inject inter-area routes into area"
                type: bool
            virtual_link_list:
                description:
                - "Field virtual_link_list"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
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
            ospf_list:
                description:
                - "Field ospf_list"
                type: list
            ip_nat:
                description:
                - "IP-NAT"
                type: bool
            metric_ip_nat:
                description:
                - "OSPFV3 default metric (OSPFV3 metric)"
                type: int
            metric_type_ip_nat:
                description:
                - "'1'= Set OSPFV3 External Type 1 metrics; '2'= Set OSPFV3 External Type 2
          metrics;"
                type: str
            route_map_ip_nat:
                description:
                - "Route map reference (Pointer to route-map entries)"
                type: str
            ip_nat_floating_list:
                description:
                - "Field ip_nat_floating_list"
                type: list
            vip_list:
                description:
                - "Field vip_list"
                type: list
            vip_floating_list:
                description:
                - "Field vip_floating_list"
                type: list
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
AVAILABLE_PROPERTIES = ["abr_type_option", "area_list", "auto_cost_reference_bandwidth", "bfd_all_interfaces", "default_information", "default_metric", "distribute_internal_list", "distribute_list", "ha_standby_extra_cost", "log_adjacency_changes", "max_concurrent_dd", "passive_interface", "process_id", "redistribute", "router_id", "timers", "user_tag", "uuid", ]


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
    rv.update({'process_id': {'type': 'str', 'required': True, },
        'abr_type_option': {'type': 'str', 'choices': ['cisco', 'ibm', 'standard']},
        'auto_cost_reference_bandwidth': {'type': 'int', },
        'bfd_all_interfaces': {'type': 'bool', },
        'default_metric': {'type': 'int', },
        'distribute_internal_list': {'type': 'list', 'ntype': {'type': 'str', 'choices': ['lw4o6', 'nat64', 'static-nat', 'floating-ip', 'ip-nat', 'ip-nat-list', 'vip', 'vip-only-flagged']}, 'area_ipv4': {'type': 'str', }, 'area_num': {'type': 'int', }, 'cost': {'type': 'int', }},
        'distribute_list': {'type': 'dict', 'prefix_list': {'type': 'dict', 'value': {'type': 'str', }, 'direction': {'type': 'str', 'choices': ['in']}}},
        'log_adjacency_changes': {'type': 'str', 'choices': ['detail', 'disable']},
        'ha_standby_extra_cost': {'type': 'list', 'extra_cost': {'type': 'int', }, 'group': {'type': 'int', }},
        'max_concurrent_dd': {'type': 'int', },
        'passive_interface': {'type': 'dict', 'loopback_cfg': {'type': 'list', 'loopback': {'type': 'str', }}, 'trunk_cfg': {'type': 'list', 'trunk': {'type': 'str', }}, 've_cfg': {'type': 'list', 've': {'type': 'str', }}, 'tunnel_cfg': {'type': 'list', 'tunnel': {'type': 'str', }}, 'eth_cfg': {'type': 'list', 'ethernet': {'type': 'str', }}},
        'router_id': {'type': 'str', },
        'timers': {'type': 'dict', 'spf': {'type': 'dict', 'exp': {'type': 'dict', 'min_delay': {'type': 'int', }, 'max_delay': {'type': 'int', }}}},
        'uuid': {'type': 'str', },
        'user_tag': {'type': 'str', },
        'default_information': {'type': 'dict', 'originate': {'type': 'bool', }, 'always': {'type': 'bool', }, 'metric': {'type': 'int', }, 'metric_type': {'type': 'int', }, 'route_map': {'type': 'str', }, 'uuid': {'type': 'str', }},
        'area_list': {'type': 'list', 'area_ipv4': {'type': 'str', 'required': True, }, 'area_num': {'type': 'int', 'required': True, }, 'default_cost': {'type': 'int', }, 'range_list': {'type': 'list', 'value': {'type': 'str', }, 'option': {'type': 'str', 'choices': ['advertise', 'not-advertise']}}, 'stub': {'type': 'bool', }, 'no_summary': {'type': 'bool', }, 'virtual_link_list': {'type': 'list', 'value': {'type': 'str', }, 'dead_interval': {'type': 'int', }, 'bfd': {'type': 'bool', }, 'hello_interval': {'type': 'int', }, 'retransmit_interval': {'type': 'int', }, 'transmit_delay': {'type': 'int', }, 'instance_id': {'type': 'int', }}, 'uuid': {'type': 'str', }},
        'redistribute': {'type': 'dict', 'redist_list': {'type': 'list', 'ntype': {'type': 'str', 'choices': ['bgp', 'connected', 'floating-ip', 'ip-nat-list', 'nat-map', 'static-nat', 'nat64', 'lw4o6', 'isis', 'rip', 'static']}, 'metric': {'type': 'int', }, 'metric_type': {'type': 'str', 'choices': ['1', '2']}, 'route_map': {'type': 'str', }}, 'ospf_list': {'type': 'list', 'ospf': {'type': 'bool', }, 'process_id': {'type': 'str', }, 'metric_ospf': {'type': 'int', }, 'metric_type_ospf': {'type': 'str', 'choices': ['1', '2']}, 'route_map_ospf': {'type': 'str', }}, 'ip_nat': {'type': 'bool', }, 'metric_ip_nat': {'type': 'int', }, 'metric_type_ip_nat': {'type': 'str', 'choices': ['1', '2']}, 'route_map_ip_nat': {'type': 'str', }, 'ip_nat_floating_list': {'type': 'list', 'ip_nat_prefix': {'type': 'str', }, 'ip_nat_floating_IP_forward': {'type': 'str', }}, 'vip_list': {'type': 'list', 'type_vip': {'type': 'str', 'choices': ['only-flagged', 'only-not-flagged']}, 'metric_vip': {'type': 'int', }, 'metric_type_vip': {'type': 'str', 'choices': ['1', '2']}, 'route_map_vip': {'type': 'str', }}, 'vip_floating_list': {'type': 'list', 'vip_address': {'type': 'str', }, 'vip_floating_IP_forward': {'type': 'str', }}, 'uuid': {'type': 'str', }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/ipv6/ospf/{process_id}"

    f_dict = {}
    if '/' in str(module.params["process_id"]):
        f_dict["process_id"] = module.params["process_id"].replace("/","%2F")
    else:
        f_dict["process_id"] = module.params["process_id"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/router/ipv6/ospf/{process_id}"

    f_dict = {}
    f_dict["process_id"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["ospf"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["ospf"].get(k) != v:
            change_results["changed"] = True
            config_changes["ospf"][k] = v

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
    payload = utils.build_json("ospf", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["ospf"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["ospf-list"] if info != "NotFound" else info
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
