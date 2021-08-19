#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_cgnv6_server_port
description:
    - Real Server Port
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
    server_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    port_number:
        description:
        - "Port Number"
        type: int
        required: True
    protocol:
        description:
        - "'tcp'= TCP Port; 'udp'= UDP Port;"
        type: str
        required: True
    action:
        description:
        - "'enable'= enable; 'disable'= disable;"
        type: str
        required: False
    health_check:
        description:
        - "Health Check (Monitor Name)"
        type: str
        required: False
    health_check_follow_port:
        description:
        - "Specify which port to follow for health status (Port Number)"
        type: int
        required: False
    follow_port_protocol:
        description:
        - "'tcp'= TCP Port; 'udp'= UDP Port;"
        type: str
        required: False
    health_check_disable:
        description:
        - "Disable health check"
        type: bool
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
                - "'all'= all; 'curr_conn'= Current connections; 'curr_req'= Current requests;
          'total_req'= Total requests; 'total_req_succ'= Total request success;
          'total_fwd_bytes'= Forward bytes; 'total_fwd_pkts'= Forward packets;
          'total_rev_bytes'= Reverse bytes; 'total_rev_pkts'= Reverse packets;
          'total_conn'= Total connections; 'last_total_conn'= Last total connections;
          'peak_conn'= Peak connections; 'es_resp_200'= Response status 200;
          'es_resp_300'= Response status 300; 'es_resp_400'= Response status 400;
          'es_resp_500'= Response status 500; 'es_resp_other'= Response status other;
          'es_req_count'= Total proxy request; 'es_resp_count'= Total proxy Response;
          'es_resp_invalid_http'= Total non-http response; 'total_rev_pkts_inspected'=
          Total reverse packets inspected; 'total_rev_pkts_inspected_good_status_code'=
          Total reverse packets with good status code inspected; 'response_time'=
          Response time; 'fastest_rsp_time'= Fastest response time; 'slowest_rsp_time'=
          Slowest response time;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            state:
                description:
                - "Field state"
                type: str
            curr_conn_rate:
                description:
                - "Field curr_conn_rate"
                type: int
            conn_rate_unit:
                description:
                - "Field conn_rate_unit"
                type: str
            slow_start_conn_limit:
                description:
                - "Field slow_start_conn_limit"
                type: int
            curr_observe_rate:
                description:
                - "Field curr_observe_rate"
                type: int
            down_grace_period_allowed:
                description:
                - "Field down_grace_period_allowed"
                type: int
            current_time:
                description:
                - "Field current_time"
                type: int
            down_time_grace_period:
                description:
                - "Field down_time_grace_period"
                type: int
            diameter_enabled:
                description:
                - "Field diameter_enabled"
                type: int
            es_resp_time:
                description:
                - "Field es_resp_time"
                type: int
            inband_hm_reassign_num:
                description:
                - "Field inband_hm_reassign_num"
                type: int
            disable:
                description:
                - "Field disable"
                type: int
            hm_key:
                description:
                - "Field hm_key"
                type: int
            hm_index:
                description:
                - "Field hm_index"
                type: int
            soft_down_time:
                description:
                - "Field soft_down_time"
                type: int
            aflow_conn_limit:
                description:
                - "Field aflow_conn_limit"
                type: int
            aflow_queue_size:
                description:
                - "Field aflow_queue_size"
                type: int
            resv_conn:
                description:
                - "Field resv_conn"
                type: int
            ip:
                description:
                - "Field ip"
                type: str
            ipv6:
                description:
                - "Field ipv6"
                type: str
            vrid:
                description:
                - "Field vrid"
                type: int
            ha_group_id:
                description:
                - "Field ha_group_id"
                type: int
            ports_consumed:
                description:
                - "Field ports_consumed"
                type: int
            ports_consumed_total:
                description:
                - "Field ports_consumed_total"
                type: int
            ports_freed_total:
                description:
                - "Field ports_freed_total"
                type: int
            alloc_failed:
                description:
                - "Field alloc_failed"
                type: int
            port_number:
                description:
                - "Port Number"
                type: int
            protocol:
                description:
                - "'tcp'= TCP Port; 'udp'= UDP Port;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            curr_conn:
                description:
                - "Current connections"
                type: str
            curr_req:
                description:
                - "Current requests"
                type: str
            total_req:
                description:
                - "Total requests"
                type: str
            total_req_succ:
                description:
                - "Total request success"
                type: str
            total_fwd_bytes:
                description:
                - "Forward bytes"
                type: str
            total_fwd_pkts:
                description:
                - "Forward packets"
                type: str
            total_rev_bytes:
                description:
                - "Reverse bytes"
                type: str
            total_rev_pkts:
                description:
                - "Reverse packets"
                type: str
            total_conn:
                description:
                - "Total connections"
                type: str
            last_total_conn:
                description:
                - "Last total connections"
                type: str
            peak_conn:
                description:
                - "Peak connections"
                type: str
            es_resp_200:
                description:
                - "Response status 200"
                type: str
            es_resp_300:
                description:
                - "Response status 300"
                type: str
            es_resp_400:
                description:
                - "Response status 400"
                type: str
            es_resp_500:
                description:
                - "Response status 500"
                type: str
            es_resp_other:
                description:
                - "Response status other"
                type: str
            es_req_count:
                description:
                - "Total proxy request"
                type: str
            es_resp_count:
                description:
                - "Total proxy Response"
                type: str
            es_resp_invalid_http:
                description:
                - "Total non-http response"
                type: str
            total_rev_pkts_inspected:
                description:
                - "Total reverse packets inspected"
                type: str
            total_rev_pkts_inspected_good_status_code:
                description:
                - "Total reverse packets with good status code inspected"
                type: str
            response_time:
                description:
                - "Response time"
                type: str
            fastest_rsp_time:
                description:
                - "Fastest response time"
                type: str
            slowest_rsp_time:
                description:
                - "Slowest response time"
                type: str
            port_number:
                description:
                - "Port Number"
                type: int
            protocol:
                description:
                - "'tcp'= TCP Port; 'udp'= UDP Port;"
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
AVAILABLE_PROPERTIES = ["action", "follow_port_protocol", "health_check", "health_check_disable", "health_check_follow_port", "oper", "port_number", "protocol", "sampling_enable", "stats", "user_tag", "uuid", ]


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
    rv.update({'port_number': {'type': 'int', 'required': True, },
        'protocol': {'type': 'str', 'required': True, 'choices': ['tcp', 'udp']},
        'action': {'type': 'str', 'choices': ['enable', 'disable']},
        'health_check': {'type': 'str', },
        'health_check_follow_port': {'type': 'int', },
        'follow_port_protocol': {'type': 'str', 'choices': ['tcp', 'udp']},
        'health_check_disable': {'type': 'bool', },
        'uuid': {'type': 'str', },
        'user_tag': {'type': 'str', },
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'curr_conn', 'curr_req', 'total_req', 'total_req_succ', 'total_fwd_bytes', 'total_fwd_pkts', 'total_rev_bytes', 'total_rev_pkts', 'total_conn', 'last_total_conn', 'peak_conn', 'es_resp_200', 'es_resp_300', 'es_resp_400', 'es_resp_500', 'es_resp_other', 'es_req_count', 'es_resp_count', 'es_resp_invalid_http', 'total_rev_pkts_inspected', 'total_rev_pkts_inspected_good_status_code', 'response_time', 'fastest_rsp_time', 'slowest_rsp_time']}},
        'oper': {'type': 'dict', 'state': {'type': 'str', 'choices': ['Up', 'Down', 'Disabled', 'Maintenance', 'Unknown', 'DIS-UP', 'DIS-DOWN', 'DIS-MAINTENANCE', 'DIS-EXCEED-RATE', 'DIS-DAMP']}, 'curr_conn_rate': {'type': 'int', }, 'conn_rate_unit': {'type': 'str', }, 'slow_start_conn_limit': {'type': 'int', }, 'curr_observe_rate': {'type': 'int', }, 'down_grace_period_allowed': {'type': 'int', }, 'current_time': {'type': 'int', }, 'down_time_grace_period': {'type': 'int', }, 'diameter_enabled': {'type': 'int', }, 'es_resp_time': {'type': 'int', }, 'inband_hm_reassign_num': {'type': 'int', }, 'disable': {'type': 'int', }, 'hm_key': {'type': 'int', }, 'hm_index': {'type': 'int', }, 'soft_down_time': {'type': 'int', }, 'aflow_conn_limit': {'type': 'int', }, 'aflow_queue_size': {'type': 'int', }, 'resv_conn': {'type': 'int', }, 'ip': {'type': 'str', }, 'ipv6': {'type': 'str', }, 'vrid': {'type': 'int', }, 'ha_group_id': {'type': 'int', }, 'ports_consumed': {'type': 'int', }, 'ports_consumed_total': {'type': 'int', }, 'ports_freed_total': {'type': 'int', }, 'alloc_failed': {'type': 'int', }, 'port_number': {'type': 'int', 'required': True, }, 'protocol': {'type': 'str', 'required': True, 'choices': ['tcp', 'udp']}},
        'stats': {'type': 'dict', 'curr_conn': {'type': 'str', }, 'curr_req': {'type': 'str', }, 'total_req': {'type': 'str', }, 'total_req_succ': {'type': 'str', }, 'total_fwd_bytes': {'type': 'str', }, 'total_fwd_pkts': {'type': 'str', }, 'total_rev_bytes': {'type': 'str', }, 'total_rev_pkts': {'type': 'str', }, 'total_conn': {'type': 'str', }, 'last_total_conn': {'type': 'str', }, 'peak_conn': {'type': 'str', }, 'es_resp_200': {'type': 'str', }, 'es_resp_300': {'type': 'str', }, 'es_resp_400': {'type': 'str', }, 'es_resp_500': {'type': 'str', }, 'es_resp_other': {'type': 'str', }, 'es_req_count': {'type': 'str', }, 'es_resp_count': {'type': 'str', }, 'es_resp_invalid_http': {'type': 'str', }, 'total_rev_pkts_inspected': {'type': 'str', }, 'total_rev_pkts_inspected_good_status_code': {'type': 'str', }, 'response_time': {'type': 'str', }, 'fastest_rsp_time': {'type': 'str', }, 'slowest_rsp_time': {'type': 'str', }, 'port_number': {'type': 'int', 'required': True, }, 'protocol': {'type': 'str', 'required': True, 'choices': ['tcp', 'udp']}}
    })
    # Parent keys
    rv.update(dict(
        server_name=dict(type='str', required=True),
    ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/server/{server_name}/port/{port-number}+{protocol}"

    f_dict = {}
    f_dict["port-number"] = module.params["port_number"]
    f_dict["protocol"] = module.params["protocol"]
    f_dict["server_name"] = module.params["server_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/server/{server_name}/port/{port-number}+{protocol}"

    f_dict = {}
    f_dict["port-number"] = ""
    f_dict["protocol"] = ""
    f_dict["server_name"] = module.params["server_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["port"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["port"].get(k) != v:
            change_results["changed"] = True
            config_changes["port"][k] = v

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
    payload = utils.build_json("port", module.params, AVAILABLE_PROPERTIES)
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
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
