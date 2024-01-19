#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_so_counters
description:
    - Show scaleout statistics
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
                - "'all'= all; 'so_pkts_rcvd'= Total data packets received;
          'so_redirect_pkts_sent'= Total packets redirected out of node;
          'so_pkts_dropped'= Total packets dropped; 'so_redirected_pkts_rcvd'= Total
          redirected packets received on node; 'so_fw_shadow_session_created'= FW Shadow
          Session created; 'so_pkts_traffic_map_not_found_drop'= Traffic MAP Not Found
          Drop; 'so_slb_pkts_redirect_conn_aged_out'= Total SLB redirect conns aged out;
          'so_pkts_scaleout_not_active_drop'= Scaleout Not Active Drop;
          'so_pkts_slb_nat_reserve_fail'= Total SLB NAT reserve failures;
          'so_pkts_slb_nat_release_fail'= Total SLB NAT release failures;
          'so_pkts_dest_mac_mismatch_drop'= Destination MAC Mistmatch Drop;
          'so_pkts_l2redirect_dest_mac_zero_drop'= Destination MAC Address zero Drop;
          'so_pkts_l2redirect_interface_not_up'= L2redirect Intf is not UP;
          'so_pkts_l2redirect_invalid_redirect_info_error'= Redirect Table Error due to
          invalid redirect info; 'so_pkts_l3_redirect_encap_error_drop'= L3 Redirect
          encap error drop during transmission;
          'so_pkts_l3_redirect_inner_mac_zero_drop'= L3 Redirect inner mac zero drop
          during transmission; 'so_pkts_l3_redirect_decap_vlan_sanity_drop'= L3 Redirect
          Decap VLAN Sanity Drop during receipt;
          'so_pkts_l3_redirect_decap_non_ipv4_vxlan_drop'= L3 Redirect received non ipv4
          VXLAN packet; 'so_pkts_l3_redirect_decap_rx_encap_params_drop'= L3 Redirect
          decap Rx encap params error Drop; 'so_pkts_l3_redirect_table_error'= L3
          Redirect Table error Drop; 'so_pkts_l3_redirect_rcvd_in_l2_mode_drop'= Recevied
          l3 redirect packets in L2 mode Drop; 'so_pkts_l3_redirect_fragmentation_error'=
          L3 redirect encap Fragmentation error;
          'so_pkts_l3_redirect_table_no_entry_found'= L3 redirect Table no redirect entry
          found error; 'so_pkts_l3_redirect_invalid_dev_dir'= L3 Redirect Invalid Device
          direction during transmission; 'so_pkts_l3_redirect_chassis_dest_mac_error'= L3
          Redirect RX multi-slot Destination MAC Error;
          'so_pkts_l3_redirect_encap_ipv4_jumbo_frag_drop'= L3 Redirect ipv4 packet after
          encap more than max jumbo size;
          'so_pkts_l3_redirect_encap_ipv6_jumbo_frag_drop'= L3 Redirect tx ipv6 packet
          after encap more than max jumbo size;
          'so_pkts_l3_redirect_too_large_pkts_in_drop'= Received L3 Redirected fragmented
          packets too large; 'so_pkts_l3_redirect_encap_mtu_error_drop'= Received L3
          Redirected MTU not enough to add encap; 'so_sync_fw_shadow_session_create'=
          Sent Sync message for FW Shadow session creation;
          'so_sync_fw_shadow_session_delete'= Sent Sync message for FW Shadow session
          deletion; 'so_sync_fw_shadow_ext'= Sync FW Shadow extension creation/updation;
          'so_sync_shadow_stats_to_active'= Sync Shadow session stats from shadow to
          active; 'so_fw_internal_rule_count'= FW internal rule count;
          'so_hc_registration_done'= Scaleout stats block registered with HC;
          'so_hc_deregistration_done'= Scaleout stats block de-registered with HC;
          'so_pkts_l2redirect_vlan_retrieval_error'= L2 redirect pkt vlan not retrieved;
          'so_pkts_l2redirect_port_retrieval_error'= L2 redirect pkt port not retrieved;
          'so_pkts_l2redirect_loop_detect_drop'= L2 redirect pkt loop detected and
          dropped; 'so_pkts_l2redirect_same_pkt_multiple_times'= L2 redirect same pkt
          multiple times; 'so_slb_shadow_session_created'= SLB Shadow Session created;
          'so_sync_slb_shadow_session_create'= Sent Sync message for SLB Shadow session
          creation; 'so_sync_slb_shadow_session_delete'= Sent Sync message for SLB Shadow
          session deletion;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            so_pkts_rcvd:
                description:
                - "Total data packets received"
                type: str
            so_redirect_pkts_sent:
                description:
                - "Total packets redirected out of node"
                type: str
            so_pkts_dropped:
                description:
                - "Total packets dropped"
                type: str
            so_redirected_pkts_rcvd:
                description:
                - "Total redirected packets received on node"
                type: str
            so_fw_shadow_session_created:
                description:
                - "FW Shadow Session created"
                type: str
            so_pkts_traffic_map_not_found_drop:
                description:
                - "Traffic MAP Not Found Drop"
                type: str
            so_slb_pkts_redirect_conn_aged_out:
                description:
                - "Total SLB redirect conns aged out"
                type: str
            so_pkts_scaleout_not_active_drop:
                description:
                - "Scaleout Not Active Drop"
                type: str
            so_pkts_slb_nat_reserve_fail:
                description:
                - "Total SLB NAT reserve failures"
                type: str
            so_pkts_slb_nat_release_fail:
                description:
                - "Total SLB NAT release failures"
                type: str
            so_pkts_dest_mac_mismatch_drop:
                description:
                - "Destination MAC Mistmatch Drop"
                type: str
            so_pkts_l2redirect_dest_mac_zero_drop:
                description:
                - "Destination MAC Address zero Drop"
                type: str
            so_pkts_l2redirect_interface_not_up:
                description:
                - "L2redirect Intf is not UP"
                type: str
            so_pkts_l2redirect_invalid_redirect_info_error:
                description:
                - "Redirect Table Error due to invalid redirect info"
                type: str
            so_pkts_l3_redirect_encap_error_drop:
                description:
                - "L3 Redirect encap error drop during transmission"
                type: str
            so_pkts_l3_redirect_inner_mac_zero_drop:
                description:
                - "L3 Redirect inner mac zero drop during transmission"
                type: str
            so_pkts_l3_redirect_decap_vlan_sanity_drop:
                description:
                - "L3 Redirect Decap VLAN Sanity Drop during receipt"
                type: str
            so_pkts_l3_redirect_decap_non_ipv4_vxlan_drop:
                description:
                - "L3 Redirect received non ipv4 VXLAN packet"
                type: str
            so_pkts_l3_redirect_decap_rx_encap_params_drop:
                description:
                - "L3 Redirect decap Rx encap params error Drop"
                type: str
            so_pkts_l3_redirect_table_error:
                description:
                - "L3 Redirect Table error Drop"
                type: str
            so_pkts_l3_redirect_rcvd_in_l2_mode_drop:
                description:
                - "Recevied l3 redirect packets in L2 mode Drop"
                type: str
            so_pkts_l3_redirect_fragmentation_error:
                description:
                - "L3 redirect encap Fragmentation error"
                type: str
            so_pkts_l3_redirect_table_no_entry_found:
                description:
                - "L3 redirect Table no redirect entry found error"
                type: str
            so_pkts_l3_redirect_invalid_dev_dir:
                description:
                - "L3 Redirect Invalid Device direction during transmission"
                type: str
            so_pkts_l3_redirect_chassis_dest_mac_error:
                description:
                - "L3 Redirect RX multi-slot Destination MAC Error"
                type: str
            so_pkts_l3_redirect_encap_ipv4_jumbo_frag_drop:
                description:
                - "L3 Redirect ipv4 packet after encap more than max jumbo size"
                type: str
            so_pkts_l3_redirect_encap_ipv6_jumbo_frag_drop:
                description:
                - "L3 Redirect tx ipv6 packet after encap more than max jumbo size"
                type: str
            so_pkts_l3_redirect_too_large_pkts_in_drop:
                description:
                - "Received L3 Redirected fragmented packets too large"
                type: str
            so_pkts_l3_redirect_encap_mtu_error_drop:
                description:
                - "Received L3 Redirected MTU not enough to add encap"
                type: str
            so_pkts_l2redirect_vlan_retrieval_error:
                description:
                - "L2 redirect pkt vlan not retrieved"
                type: str
            so_pkts_l2redirect_port_retrieval_error:
                description:
                - "L2 redirect pkt port not retrieved"
                type: str
            so_pkts_l2redirect_loop_detect_drop:
                description:
                - "L2 redirect pkt loop detected and dropped"
                type: str
            so_pkts_l2redirect_same_pkt_multiple_times:
                description:
                - "L2 redirect same pkt multiple times"
                type: str
            so_slb_shadow_session_created:
                description:
                - "SLB Shadow Session created"
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
AVAILABLE_PROPERTIES = ["sampling_enable", "stats", "uuid", ]


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
        'uuid': {
            'type': 'str',
            },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'so_pkts_rcvd', 'so_redirect_pkts_sent', 'so_pkts_dropped', 'so_redirected_pkts_rcvd', 'so_fw_shadow_session_created', 'so_pkts_traffic_map_not_found_drop', 'so_slb_pkts_redirect_conn_aged_out', 'so_pkts_scaleout_not_active_drop', 'so_pkts_slb_nat_reserve_fail', 'so_pkts_slb_nat_release_fail',
                    'so_pkts_dest_mac_mismatch_drop', 'so_pkts_l2redirect_dest_mac_zero_drop', 'so_pkts_l2redirect_interface_not_up', 'so_pkts_l2redirect_invalid_redirect_info_error', 'so_pkts_l3_redirect_encap_error_drop', 'so_pkts_l3_redirect_inner_mac_zero_drop', 'so_pkts_l3_redirect_decap_vlan_sanity_drop',
                    'so_pkts_l3_redirect_decap_non_ipv4_vxlan_drop', 'so_pkts_l3_redirect_decap_rx_encap_params_drop', 'so_pkts_l3_redirect_table_error', 'so_pkts_l3_redirect_rcvd_in_l2_mode_drop', 'so_pkts_l3_redirect_fragmentation_error', 'so_pkts_l3_redirect_table_no_entry_found', 'so_pkts_l3_redirect_invalid_dev_dir',
                    'so_pkts_l3_redirect_chassis_dest_mac_error', 'so_pkts_l3_redirect_encap_ipv4_jumbo_frag_drop', 'so_pkts_l3_redirect_encap_ipv6_jumbo_frag_drop', 'so_pkts_l3_redirect_too_large_pkts_in_drop', 'so_pkts_l3_redirect_encap_mtu_error_drop', 'so_sync_fw_shadow_session_create', 'so_sync_fw_shadow_session_delete',
                    'so_sync_fw_shadow_ext', 'so_sync_shadow_stats_to_active', 'so_fw_internal_rule_count', 'so_hc_registration_done', 'so_hc_deregistration_done', 'so_pkts_l2redirect_vlan_retrieval_error', 'so_pkts_l2redirect_port_retrieval_error', 'so_pkts_l2redirect_loop_detect_drop', 'so_pkts_l2redirect_same_pkt_multiple_times',
                    'so_slb_shadow_session_created', 'so_sync_slb_shadow_session_create', 'so_sync_slb_shadow_session_delete'
                    ]
                }
            },
        'stats': {
            'type': 'dict',
            'so_pkts_rcvd': {
                'type': 'str',
                },
            'so_redirect_pkts_sent': {
                'type': 'str',
                },
            'so_pkts_dropped': {
                'type': 'str',
                },
            'so_redirected_pkts_rcvd': {
                'type': 'str',
                },
            'so_fw_shadow_session_created': {
                'type': 'str',
                },
            'so_pkts_traffic_map_not_found_drop': {
                'type': 'str',
                },
            'so_slb_pkts_redirect_conn_aged_out': {
                'type': 'str',
                },
            'so_pkts_scaleout_not_active_drop': {
                'type': 'str',
                },
            'so_pkts_slb_nat_reserve_fail': {
                'type': 'str',
                },
            'so_pkts_slb_nat_release_fail': {
                'type': 'str',
                },
            'so_pkts_dest_mac_mismatch_drop': {
                'type': 'str',
                },
            'so_pkts_l2redirect_dest_mac_zero_drop': {
                'type': 'str',
                },
            'so_pkts_l2redirect_interface_not_up': {
                'type': 'str',
                },
            'so_pkts_l2redirect_invalid_redirect_info_error': {
                'type': 'str',
                },
            'so_pkts_l3_redirect_encap_error_drop': {
                'type': 'str',
                },
            'so_pkts_l3_redirect_inner_mac_zero_drop': {
                'type': 'str',
                },
            'so_pkts_l3_redirect_decap_vlan_sanity_drop': {
                'type': 'str',
                },
            'so_pkts_l3_redirect_decap_non_ipv4_vxlan_drop': {
                'type': 'str',
                },
            'so_pkts_l3_redirect_decap_rx_encap_params_drop': {
                'type': 'str',
                },
            'so_pkts_l3_redirect_table_error': {
                'type': 'str',
                },
            'so_pkts_l3_redirect_rcvd_in_l2_mode_drop': {
                'type': 'str',
                },
            'so_pkts_l3_redirect_fragmentation_error': {
                'type': 'str',
                },
            'so_pkts_l3_redirect_table_no_entry_found': {
                'type': 'str',
                },
            'so_pkts_l3_redirect_invalid_dev_dir': {
                'type': 'str',
                },
            'so_pkts_l3_redirect_chassis_dest_mac_error': {
                'type': 'str',
                },
            'so_pkts_l3_redirect_encap_ipv4_jumbo_frag_drop': {
                'type': 'str',
                },
            'so_pkts_l3_redirect_encap_ipv6_jumbo_frag_drop': {
                'type': 'str',
                },
            'so_pkts_l3_redirect_too_large_pkts_in_drop': {
                'type': 'str',
                },
            'so_pkts_l3_redirect_encap_mtu_error_drop': {
                'type': 'str',
                },
            'so_pkts_l2redirect_vlan_retrieval_error': {
                'type': 'str',
                },
            'so_pkts_l2redirect_port_retrieval_error': {
                'type': 'str',
                },
            'so_pkts_l2redirect_loop_detect_drop': {
                'type': 'str',
                },
            'so_pkts_l2redirect_same_pkt_multiple_times': {
                'type': 'str',
                },
            'so_slb_shadow_session_created': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/so-counters"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/so-counters"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["so-counters"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["so-counters"].get(k) != v:
            change_results["changed"] = True
            config_changes["so-counters"][k] = v

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
    payload = utils.build_json("so-counters", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["so-counters"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["so-counters-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["so-counters"]["stats"] if info != "NotFound" else info
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
