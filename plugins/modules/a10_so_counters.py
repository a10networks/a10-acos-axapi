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
                - "'all'= all; 'so_pkts_conn_in'= Total packets processed for an established
          connection; 'so_pkts_conn_redirect'= Total packets redirected for an
          established connection; 'so_pkts_dropped'= Total packets dropped;
          'so_pkts_errors'= Total packet errors; 'so_pkts_in'= Total packets in-coming;
          'so_pkts_new_conn_in'= Total packets processed for a new connection;
          'so_pkts_new_conn_redirect'= Total packets redirected for a new connection;
          'so_pkts_out'= Total packets sent out; 'so_pkts_redirect'= Total packets
          redirected; 'so_pkts_conn_sync_fail'= Total connection sync failures;
          'so_pkts_nat_reserve_fail'= Total NAT reserve failures;
          'so_pkts_nat_release_fail'= Total NAT release failures; 'so_pkts_conn_l7_sync'=
          Total L7 connection syncs; 'so_pkts_conn_l4_sync'= Total L4 connection syncs;
          'so_pkts_conn_nat_sync'= Total NAT connection syncs;
          'so_pkts_conn_xparent_fw_sync'= Total Xparent FW connection syncs;
          'so_pkts_redirect_conn_aged_out'= Total redirect conns aged out;
          'so_pkts_traffic_map_not_found_drop'= Traffic MAP Not Found Drop;
          'so_pkts_scaleout_not_active_drop'= Scaleout Not Active Drop;
          'so_pkts_dest_mac_mistmatch_drop'= Destination MAC Mistmatch Drop;
          'so_pkts_l2redirect_interface_not_up'= L2redirect Intf is not UP;
          'so_fw_internal_rule_count'= FW internal rule count;
          'so_pkts_redirect_table_error'= Redirect Table Error; 'so_pkts_mac_zero_drop'=
          MAC Address zero Drop;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            so_pkts_conn_in:
                description:
                - "Total packets processed for an established connection"
                type: str
            so_pkts_conn_redirect:
                description:
                - "Total packets redirected for an established connection"
                type: str
            so_pkts_dropped:
                description:
                - "Total packets dropped"
                type: str
            so_pkts_errors:
                description:
                - "Total packet errors"
                type: str
            so_pkts_in:
                description:
                - "Total packets in-coming"
                type: str
            so_pkts_new_conn_in:
                description:
                - "Total packets processed for a new connection"
                type: str
            so_pkts_new_conn_redirect:
                description:
                - "Total packets redirected for a new connection"
                type: str
            so_pkts_out:
                description:
                - "Total packets sent out"
                type: str
            so_pkts_redirect:
                description:
                - "Total packets redirected"
                type: str
            so_pkts_conn_sync_fail:
                description:
                - "Total connection sync failures"
                type: str
            so_pkts_nat_reserve_fail:
                description:
                - "Total NAT reserve failures"
                type: str
            so_pkts_nat_release_fail:
                description:
                - "Total NAT release failures"
                type: str
            so_pkts_conn_l7_sync:
                description:
                - "Total L7 connection syncs"
                type: str
            so_pkts_conn_l4_sync:
                description:
                - "Total L4 connection syncs"
                type: str
            so_pkts_conn_nat_sync:
                description:
                - "Total NAT connection syncs"
                type: str
            so_pkts_conn_xparent_fw_sync:
                description:
                - "Total Xparent FW connection syncs"
                type: str
            so_pkts_redirect_conn_aged_out:
                description:
                - "Total redirect conns aged out"
                type: str
            so_pkts_traffic_map_not_found_drop:
                description:
                - "Traffic MAP Not Found Drop"
                type: str
            so_pkts_scaleout_not_active_drop:
                description:
                - "Scaleout Not Active Drop"
                type: str
            so_pkts_dest_mac_mistmatch_drop:
                description:
                - "Destination MAC Mistmatch Drop"
                type: str
            so_pkts_l2redirect_interface_not_up:
                description:
                - "L2redirect Intf is not UP"
                type: str
            so_fw_internal_rule_count:
                description:
                - "FW internal rule count"
                type: str
            so_pkts_redirect_table_error:
                description:
                - "Redirect Table Error"
                type: str
            so_pkts_mac_zero_drop:
                description:
                - "MAC Address zero Drop"
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

# standard ansible module imports
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
AVAILABLE_PROPERTIES = ["sampling_enable", "stats", "uuid", ]


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
    rv.update({'uuid': {'type': 'str', },
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'so_pkts_conn_in', 'so_pkts_conn_redirect', 'so_pkts_dropped', 'so_pkts_errors', 'so_pkts_in', 'so_pkts_new_conn_in', 'so_pkts_new_conn_redirect', 'so_pkts_out', 'so_pkts_redirect', 'so_pkts_conn_sync_fail', 'so_pkts_nat_reserve_fail', 'so_pkts_nat_release_fail', 'so_pkts_conn_l7_sync', 'so_pkts_conn_l4_sync', 'so_pkts_conn_nat_sync', 'so_pkts_conn_xparent_fw_sync', 'so_pkts_redirect_conn_aged_out', 'so_pkts_traffic_map_not_found_drop', 'so_pkts_scaleout_not_active_drop', 'so_pkts_dest_mac_mistmatch_drop', 'so_pkts_l2redirect_interface_not_up', 'so_fw_internal_rule_count', 'so_pkts_redirect_table_error', 'so_pkts_mac_zero_drop']}},
        'stats': {'type': 'dict', 'so_pkts_conn_in': {'type': 'str', }, 'so_pkts_conn_redirect': {'type': 'str', }, 'so_pkts_dropped': {'type': 'str', }, 'so_pkts_errors': {'type': 'str', }, 'so_pkts_in': {'type': 'str', }, 'so_pkts_new_conn_in': {'type': 'str', }, 'so_pkts_new_conn_redirect': {'type': 'str', }, 'so_pkts_out': {'type': 'str', }, 'so_pkts_redirect': {'type': 'str', }, 'so_pkts_conn_sync_fail': {'type': 'str', }, 'so_pkts_nat_reserve_fail': {'type': 'str', }, 'so_pkts_nat_release_fail': {'type': 'str', }, 'so_pkts_conn_l7_sync': {'type': 'str', }, 'so_pkts_conn_l4_sync': {'type': 'str', }, 'so_pkts_conn_nat_sync': {'type': 'str', }, 'so_pkts_conn_xparent_fw_sync': {'type': 'str', }, 'so_pkts_redirect_conn_aged_out': {'type': 'str', }, 'so_pkts_traffic_map_not_found_drop': {'type': 'str', }, 'so_pkts_scaleout_not_active_drop': {'type': 'str', }, 'so_pkts_dest_mac_mistmatch_drop': {'type': 'str', }, 'so_pkts_l2redirect_interface_not_up': {'type': 'str', }, 'so_fw_internal_rule_count': {'type': 'str', }, 'so_pkts_redirect_table_error': {'type': 'str', }, 'so_pkts_mac_zero_drop': {'type': 'str', }}
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
    result = dict(
        changed=False,
        messages="",
        modified_values={},
        axapi_calls=[]
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
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
