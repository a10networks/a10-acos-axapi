#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_system_dns
description:
    - DNS Packet Statistics
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
                - "'all'= all; 'slb_req'= No. of requests; 'slb_resp'= No. of responses;
          'slb_no_resp'= No. of requests with no response; 'slb_req_rexmit'= No. of
          requests retransmit; 'slb_resp_no_match'= No. of requests and responses with no
          match; 'slb_no_resource'= No. of resource failures; 'nat_req'= (NAT) No. of
          requests; 'nat_resp'= (NAT) No. of responses; 'nat_no_resp'= (NAT) No. of
          resource failures; 'nat_req_rexmit'= (NAT) No. of request retransmits;
          'nat_resp_no_match'= (NAT) No. of requests with no response; 'nat_no_resource'=
          (NAT) No. of resource failures; 'nat_xid_reused'= (NAT) No. of requests reusing
          a transaction id; 'filter_type_drop'= Total Query Type Drop;
          'filter_class_drop'= Total Query Class Drop; 'filter_type_any_drop'= Total
          Query ANY Type Drop; 'slb_dns_client_ssl_succ'= No. of client ssl success;
          'slb_dns_server_ssl_succ'= No. of server ssl success; 'slb_dns_udp_conn'= No.
          of backend udp connections; 'slb_dns_udp_conn_succ'= No. of backend udp conn
          established; 'slb_dns_padding_to_server_removed'= some help string;
          'slb_dns_padding_to_client_added'= some help string;
          'slb_dns_edns_subnet_to_server_removed'= some help string;
          'slb_dns_udp_retransmit'= some help string; 'slb_dns_udp_retransmit_fail'= some
          help string; 'rpz_action_drop'= RPZ Action Drop; 'rpz_action_pass_thru'= RPZ
          Action Pass Through; 'rpz_action_tcp_only'= RPZ Action TCP Only;
          'rpz_action_nxdomain'= RPZ Action NXDOMAIN; 'rpz_action_nodata'= RPZ Action
          NODATA; 'rpz_action_local_data'= RPZ Action Local Data; 'slb_drop'= DNS
          requests drop; 'nat_slb_drop'= (NAT)DNS requests drop; 'invalid_q_len_to_udp'=
          invalid query length to conver to UDP;"
                type: str
    recursive_nameserver:
        description:
        - "Field recursive_nameserver"
        type: dict
        required: False
        suboptions:
            follow_shared:
                description:
                - "Use the configured name servers of shared partition"
                type: bool
            server_list:
                description:
                - "Field server_list"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            slb_req:
                description:
                - "No. of requests"
                type: str
            slb_resp:
                description:
                - "No. of responses"
                type: str
            slb_no_resp:
                description:
                - "No. of requests with no response"
                type: str
            slb_req_rexmit:
                description:
                - "No. of requests retransmit"
                type: str
            slb_resp_no_match:
                description:
                - "No. of requests and responses with no match"
                type: str
            slb_no_resource:
                description:
                - "No. of resource failures"
                type: str
            nat_req:
                description:
                - "(NAT) No. of requests"
                type: str
            nat_resp:
                description:
                - "(NAT) No. of responses"
                type: str
            nat_no_resp:
                description:
                - "(NAT) No. of resource failures"
                type: str
            nat_req_rexmit:
                description:
                - "(NAT) No. of request retransmits"
                type: str
            nat_resp_no_match:
                description:
                - "(NAT) No. of requests with no response"
                type: str
            nat_no_resource:
                description:
                - "(NAT) No. of resource failures"
                type: str
            nat_xid_reused:
                description:
                - "(NAT) No. of requests reusing a transaction id"
                type: str
            filter_type_drop:
                description:
                - "Total Query Type Drop"
                type: str
            filter_class_drop:
                description:
                - "Total Query Class Drop"
                type: str
            filter_type_any_drop:
                description:
                - "Total Query ANY Type Drop"
                type: str
            slb_dns_client_ssl_succ:
                description:
                - "No. of client ssl success"
                type: str
            slb_dns_server_ssl_succ:
                description:
                - "No. of server ssl success"
                type: str
            slb_dns_udp_conn:
                description:
                - "No. of backend udp connections"
                type: str
            slb_dns_udp_conn_succ:
                description:
                - "No. of backend udp conn established"
                type: str
            slb_dns_padding_to_server_removed:
                description:
                - "some help string"
                type: str
            slb_dns_padding_to_client_added:
                description:
                - "some help string"
                type: str
            slb_dns_edns_subnet_to_server_removed:
                description:
                - "some help string"
                type: str
            slb_dns_udp_retransmit:
                description:
                - "some help string"
                type: str
            slb_dns_udp_retransmit_fail:
                description:
                - "some help string"
                type: str
            rpz_action_drop:
                description:
                - "RPZ Action Drop"
                type: str
            rpz_action_pass_thru:
                description:
                - "RPZ Action Pass Through"
                type: str
            rpz_action_tcp_only:
                description:
                - "RPZ Action TCP Only"
                type: str
            rpz_action_nxdomain:
                description:
                - "RPZ Action NXDOMAIN"
                type: str
            rpz_action_nodata:
                description:
                - "RPZ Action NODATA"
                type: str
            rpz_action_local_data:
                description:
                - "RPZ Action Local Data"
                type: str
            slb_drop:
                description:
                - "DNS requests drop"
                type: str
            nat_slb_drop:
                description:
                - "(NAT)DNS requests drop"
                type: str
            invalid_q_len_to_udp:
                description:
                - "invalid query length to conver to UDP"
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
AVAILABLE_PROPERTIES = ["recursive_nameserver", "sampling_enable", "stats", "uuid", ]


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
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'slb_req', 'slb_resp', 'slb_no_resp', 'slb_req_rexmit', 'slb_resp_no_match', 'slb_no_resource', 'nat_req', 'nat_resp', 'nat_no_resp', 'nat_req_rexmit', 'nat_resp_no_match', 'nat_no_resource', 'nat_xid_reused', 'filter_type_drop', 'filter_class_drop', 'filter_type_any_drop', 'slb_dns_client_ssl_succ', 'slb_dns_server_ssl_succ', 'slb_dns_udp_conn', 'slb_dns_udp_conn_succ', 'slb_dns_padding_to_server_removed', 'slb_dns_padding_to_client_added', 'slb_dns_edns_subnet_to_server_removed', 'slb_dns_udp_retransmit', 'slb_dns_udp_retransmit_fail', 'rpz_action_drop', 'rpz_action_pass_thru', 'rpz_action_tcp_only', 'rpz_action_nxdomain', 'rpz_action_nodata', 'rpz_action_local_data', 'slb_drop', 'nat_slb_drop', 'invalid_q_len_to_udp']}},
        'recursive_nameserver': {'type': 'dict', 'follow_shared': {'type': 'bool', }, 'server_list': {'type': 'list', 'ipv4_addr': {'type': 'str', }, 'v4_desc': {'type': 'str', }, 'ipv6_addr': {'type': 'str', }, 'v6_desc': {'type': 'str', }}, 'uuid': {'type': 'str', }},
        'stats': {'type': 'dict', 'slb_req': {'type': 'str', }, 'slb_resp': {'type': 'str', }, 'slb_no_resp': {'type': 'str', }, 'slb_req_rexmit': {'type': 'str', }, 'slb_resp_no_match': {'type': 'str', }, 'slb_no_resource': {'type': 'str', }, 'nat_req': {'type': 'str', }, 'nat_resp': {'type': 'str', }, 'nat_no_resp': {'type': 'str', }, 'nat_req_rexmit': {'type': 'str', }, 'nat_resp_no_match': {'type': 'str', }, 'nat_no_resource': {'type': 'str', }, 'nat_xid_reused': {'type': 'str', }, 'filter_type_drop': {'type': 'str', }, 'filter_class_drop': {'type': 'str', }, 'filter_type_any_drop': {'type': 'str', }, 'slb_dns_client_ssl_succ': {'type': 'str', }, 'slb_dns_server_ssl_succ': {'type': 'str', }, 'slb_dns_udp_conn': {'type': 'str', }, 'slb_dns_udp_conn_succ': {'type': 'str', }, 'slb_dns_padding_to_server_removed': {'type': 'str', }, 'slb_dns_padding_to_client_added': {'type': 'str', }, 'slb_dns_edns_subnet_to_server_removed': {'type': 'str', }, 'slb_dns_udp_retransmit': {'type': 'str', }, 'slb_dns_udp_retransmit_fail': {'type': 'str', }, 'rpz_action_drop': {'type': 'str', }, 'rpz_action_pass_thru': {'type': 'str', }, 'rpz_action_tcp_only': {'type': 'str', }, 'rpz_action_nxdomain': {'type': 'str', }, 'rpz_action_nodata': {'type': 'str', }, 'rpz_action_local_data': {'type': 'str', }, 'slb_drop': {'type': 'str', }, 'nat_slb_drop': {'type': 'str', }, 'invalid_q_len_to_udp': {'type': 'str', }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/dns"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/system/dns"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["dns"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["dns"].get(k) != v:
            change_results["changed"] = True
            config_changes["dns"][k] = v

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
    payload = utils.build_json("dns", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["dns"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["dns-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["dns"]["stats"] if info != "NotFound" else info
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
