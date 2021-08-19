#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_cgnv6_server
description:
    - CGNV6 logging Server
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
    name:
        description:
        - "Server Name"
        type: str
        required: True
    server_ipv6_addr:
        description:
        - "IPV6 address"
        type: str
        required: False
    host:
        description:
        - "IP Address"
        type: str
        required: False
    fqdn_name:
        description:
        - "Server hostname"
        type: str
        required: False
    resolve_as:
        description:
        - "'resolve-to-ipv4'= Use A Query only to resolve FQDN; 'resolve-to-ipv6'= Use
          AAAA Query only to resolve FQDN; 'resolve-to-ipv4-and-ipv6'= Use A as well as
          AAAA Query to resolve FQDN;"
        type: str
        required: False
    action:
        description:
        - "'enable'= Enable this Real Server; 'disable'= Disable this Real Server;"
        type: str
        required: False
    health_check:
        description:
        - "Health Check Monitor (Health monitor name)"
        type: str
        required: False
    health_check_disable:
        description:
        - "Disable configured health check configuration"
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
                - "'all'= all; 'curr-conn'= Current connections; 'total-conn'= Total connections;
          'fwd-pkt'= Forward packets; 'rev-pkt'= Reverse Packets; 'peak-conn'= Peak
          connections;"
                type: str
    port_list:
        description:
        - "Field port_list"
        type: list
        required: False
        suboptions:
            port_number:
                description:
                - "Port Number"
                type: int
            protocol:
                description:
                - "'tcp'= TCP Port; 'udp'= UDP Port;"
                type: str
            action:
                description:
                - "'enable'= enable; 'disable'= disable;"
                type: str
            health_check:
                description:
                - "Health Check (Monitor Name)"
                type: str
            health_check_follow_port:
                description:
                - "Specify which port to follow for health status (Port Number)"
                type: int
            follow_port_protocol:
                description:
                - "'tcp'= TCP Port; 'udp'= UDP Port;"
                type: str
            health_check_disable:
                description:
                - "Disable health check"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
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
            creation_type:
                description:
                - "Field creation_type"
                type: str
            dns_update_time:
                description:
                - "Field dns_update_time"
                type: str
            server_ttl:
                description:
                - "Field server_ttl"
                type: int
            srv_gateway_arp:
                description:
                - "Field srv_gateway_arp"
                type: str
            is_autocreate:
                description:
                - "Field is_autocreate"
                type: int
            slow_start_conn_limit:
                description:
                - "Field slow_start_conn_limit"
                type: int
            curr_conn_rate:
                description:
                - "Field curr_conn_rate"
                type: int
            conn_rate_unit:
                description:
                - "Field conn_rate_unit"
                type: str
            curr_observe_rate:
                description:
                - "Field curr_observe_rate"
                type: int
            disable:
                description:
                - "Field disable"
                type: int
            drs_list:
                description:
                - "Field drs_list"
                type: list
            name:
                description:
                - "Server Name"
                type: str
            port_list:
                description:
                - "Field port_list"
                type: list
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
            total_conn:
                description:
                - "Total connections"
                type: str
            fwd_pkt:
                description:
                - "Forward packets"
                type: str
            rev_pkt:
                description:
                - "Reverse Packets"
                type: str
            peak_conn:
                description:
                - "Peak connections"
                type: str
            name:
                description:
                - "Server Name"
                type: str
            port_list:
                description:
                - "Field port_list"
                type: list

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
AVAILABLE_PROPERTIES = ["action", "fqdn_name", "health_check", "health_check_disable", "host", "name", "oper", "port_list", "resolve_as", "sampling_enable", "server_ipv6_addr", "stats", "user_tag", "uuid", ]


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
    rv.update({'name': {'type': 'str', 'required': True, },
        'server_ipv6_addr': {'type': 'str', },
        'host': {'type': 'str', },
        'fqdn_name': {'type': 'str', },
        'resolve_as': {'type': 'str', 'choices': ['resolve-to-ipv4', 'resolve-to-ipv6', 'resolve-to-ipv4-and-ipv6']},
        'action': {'type': 'str', 'choices': ['enable', 'disable']},
        'health_check': {'type': 'str', },
        'health_check_disable': {'type': 'bool', },
        'uuid': {'type': 'str', },
        'user_tag': {'type': 'str', },
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'curr-conn', 'total-conn', 'fwd-pkt', 'rev-pkt', 'peak-conn']}},
        'port_list': {'type': 'list', 'port_number': {'type': 'int', 'required': True, }, 'protocol': {'type': 'str', 'required': True, 'choices': ['tcp', 'udp']}, 'action': {'type': 'str', 'choices': ['enable', 'disable']}, 'health_check': {'type': 'str', }, 'health_check_follow_port': {'type': 'int', }, 'follow_port_protocol': {'type': 'str', 'choices': ['tcp', 'udp']}, 'health_check_disable': {'type': 'bool', }, 'uuid': {'type': 'str', }, 'user_tag': {'type': 'str', }, 'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'curr_conn', 'curr_req', 'total_req', 'total_req_succ', 'total_fwd_bytes', 'total_fwd_pkts', 'total_rev_bytes', 'total_rev_pkts', 'total_conn', 'last_total_conn', 'peak_conn', 'es_resp_200', 'es_resp_300', 'es_resp_400', 'es_resp_500', 'es_resp_other', 'es_req_count', 'es_resp_count', 'es_resp_invalid_http', 'total_rev_pkts_inspected', 'total_rev_pkts_inspected_good_status_code', 'response_time', 'fastest_rsp_time', 'slowest_rsp_time']}}},
        'oper': {'type': 'dict', 'state': {'type': 'str', 'choices': ['UP', 'DOWN', 'DELETE', 'DISABLED', 'MAINTENANCE']}, 'creation_type': {'type': 'str', }, 'dns_update_time': {'type': 'str', }, 'server_ttl': {'type': 'int', }, 'srv_gateway_arp': {'type': 'str', }, 'is_autocreate': {'type': 'int', }, 'slow_start_conn_limit': {'type': 'int', }, 'curr_conn_rate': {'type': 'int', }, 'conn_rate_unit': {'type': 'str', }, 'curr_observe_rate': {'type': 'int', }, 'disable': {'type': 'int', }, 'drs_list': {'type': 'list', 'drs_name': {'type': 'str', }, 'drs_host': {'type': 'str', }, 'drs_server_ipv6_addr': {'type': 'str', }, 'drs_state': {'type': 'str', 'choices': ['Up', 'Down', 'Disabled', 'Maintenance', 'Unknown', 'Functional Up', 'DIS-UP', 'DIS-DOWN', 'DIS-MAINTENANCE', 'DIS-EXCEED-RATE', 'DIS-UNKNOWN']}, 'drs_creation_type': {'type': 'str', }, 'drs_dns_update_time': {'type': 'str', }, 'drs_server_ttl': {'type': 'int', }, 'drs_srv_gateway_arp': {'type': 'str', }, 'drs_is_autocreate': {'type': 'int', }, 'drs_slow_start_conn_limit': {'type': 'int', }, 'drs_curr_conn_rate': {'type': 'int', }, 'drs_conn_rate_unit': {'type': 'str', }, 'drs_curr_observe_rate': {'type': 'int', }, 'drs_disable': {'type': 'int', }, 'drs_curr_conn': {'type': 'int', }, 'drs_curr_req': {'type': 'int', }, 'drs_tot_conn': {'type': 'int', }, 'drs_tot_req': {'type': 'int', }, 'drs_tot_req_suc': {'type': 'int', }, 'drs_tot_fwd_bytes': {'type': 'int', }, 'drs_tot_fwd_pkts': {'type': 'int', }, 'drs_tot_rev_bytes': {'type': 'int', }, 'drs_tot_rev_pkts': {'type': 'int', }, 'drs_peak_conn': {'type': 'int', }}, 'name': {'type': 'str', 'required': True, }, 'port_list': {'type': 'list', 'port_number': {'type': 'int', 'required': True, }, 'protocol': {'type': 'str', 'required': True, 'choices': ['tcp', 'udp']}, 'oper': {'type': 'dict', 'state': {'type': 'str', 'choices': ['Up', 'Down', 'Disabled', 'Maintenance', 'Unknown', 'DIS-UP', 'DIS-DOWN', 'DIS-MAINTENANCE', 'DIS-EXCEED-RATE', 'DIS-DAMP']}, 'curr_conn_rate': {'type': 'int', }, 'conn_rate_unit': {'type': 'str', }, 'slow_start_conn_limit': {'type': 'int', }, 'curr_observe_rate': {'type': 'int', }, 'down_grace_period_allowed': {'type': 'int', }, 'current_time': {'type': 'int', }, 'down_time_grace_period': {'type': 'int', }, 'diameter_enabled': {'type': 'int', }, 'es_resp_time': {'type': 'int', }, 'inband_hm_reassign_num': {'type': 'int', }, 'disable': {'type': 'int', }, 'hm_key': {'type': 'int', }, 'hm_index': {'type': 'int', }, 'soft_down_time': {'type': 'int', }, 'aflow_conn_limit': {'type': 'int', }, 'aflow_queue_size': {'type': 'int', }, 'resv_conn': {'type': 'int', }, 'ip': {'type': 'str', }, 'ipv6': {'type': 'str', }, 'vrid': {'type': 'int', }, 'ha_group_id': {'type': 'int', }, 'ports_consumed': {'type': 'int', }, 'ports_consumed_total': {'type': 'int', }, 'ports_freed_total': {'type': 'int', }, 'alloc_failed': {'type': 'int', }}}},
        'stats': {'type': 'dict', 'curr_conn': {'type': 'str', }, 'total_conn': {'type': 'str', }, 'fwd_pkt': {'type': 'str', }, 'rev_pkt': {'type': 'str', }, 'peak_conn': {'type': 'str', }, 'name': {'type': 'str', 'required': True, }, 'port_list': {'type': 'list', 'port_number': {'type': 'int', 'required': True, }, 'protocol': {'type': 'str', 'required': True, 'choices': ['tcp', 'udp']}, 'stats': {'type': 'dict', 'curr_conn': {'type': 'str', }, 'curr_req': {'type': 'str', }, 'total_req': {'type': 'str', }, 'total_req_succ': {'type': 'str', }, 'total_fwd_bytes': {'type': 'str', }, 'total_fwd_pkts': {'type': 'str', }, 'total_rev_bytes': {'type': 'str', }, 'total_rev_pkts': {'type': 'str', }, 'total_conn': {'type': 'str', }, 'last_total_conn': {'type': 'str', }, 'peak_conn': {'type': 'str', }, 'es_resp_200': {'type': 'str', }, 'es_resp_300': {'type': 'str', }, 'es_resp_400': {'type': 'str', }, 'es_resp_500': {'type': 'str', }, 'es_resp_other': {'type': 'str', }, 'es_req_count': {'type': 'str', }, 'es_resp_count': {'type': 'str', }, 'es_resp_invalid_http': {'type': 'str', }, 'total_rev_pkts_inspected': {'type': 'str', }, 'total_rev_pkts_inspected_good_status_code': {'type': 'str', }, 'response_time': {'type': 'str', }, 'fastest_rsp_time': {'type': 'str', }, 'slowest_rsp_time': {'type': 'str', }}}}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/server/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/server/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["server"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["server"].get(k) != v:
            change_results["changed"] = True
            config_changes["server"][k] = v

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
    payload = utils.build_json("server", module.params, AVAILABLE_PROPERTIES)
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
