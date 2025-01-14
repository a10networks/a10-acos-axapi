#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_detection_statistics
description:
    - DDoS Detection statistics
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
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            sflow_packets_received:
                description:
                - "sFlow Packets Received"
                type: str
            not_supported_sflow_ver:
                description:
                - "sFlow Packets Version Not Supported"
                type: str
            netflow_pkts_received:
                description:
                - "Netflow Packets Received"
                type: str
            not_supproted_nflow_ver:
                description:
                - "Netflow Packets Version Not Supported"
                type: str
            agent_not_found:
                description:
                - "Detection Agent Not Found"
                type: str
            pkt_drop:
                description:
                - "Flow Packets Dropped"
                type: str
            report_alloc_fail:
                description:
                - "Report Allocate Failure"
                type: str
            report_enqueue_fail:
                description:
                - "Report Enqueue Failure"
                type: str
            sample_procssed:
                description:
                - "Sample Processed"
                type: str
            ip_rcvd:
                description:
                - "IPv4 Received"
                type: str
            ipv6_rcvd:
                description:
                - "IPv6 Received"
                type: str
            frag_rcvd:
                description:
                - "Fragment Received"
                type: str
            dst_hit:
                description:
                - "Dst Entry Hit"
                type: str
            dst_miss:
                description:
                - "Dst Entry Missed"
                type: str
            dst_learn:
                description:
                - "Dst Entry Learned"
                type: str
            dst_age:
                description:
                - "Dst Entry Aged"
                type: str
            dst_service_hit:
                description:
                - "Dst Service Entry Hit"
                type: str
            dst_service_miss:
                description:
                - "Dst Service Entry Missed"
                type: str
            dst_service_learn:
                description:
                - "Dst Service Entry Learned"
                type: str
            dst_service_age:
                description:
                - "Dst Service Entry Aged"
                type: str
            src_hit:
                description:
                - "Src Entry Hit"
                type: str
            src_miss:
                description:
                - "Src Entry Missed"
                type: str
            src_learn:
                description:
                - "Src Entry Learned"
                type: str
            src_age:
                description:
                - "Src Entry Aged"
                type: str
            entry_alloc_fail:
                description:
                - "Entry Allocate Failure"
                type: str
            geo_learn:
                description:
                - "Geolocation Entry Learned"
                type: str
            geo_age:
                description:
                - "Geolocation Entry Aged"
                type: str
            unmatch_entry_port_zero:
                description:
                - "Unmatched Entry Port-zero Packet"
                type: str
            object_alloc_oom:
                description:
                - "Object Allocate Failure Out of Memory"
                type: str
            invalid_event:
                description:
                - "Invalid Event in Notification"
                type: str
            rtbh_start_sent:
                description:
                - "RTBH Start Notification Sent"
                type: str
            rtbh_stop_sent:
                description:
                - "RTBH Stop Notification Sent"
                type: str
            rtbh_start_fail:
                description:
                - "RTBH Start Notification Sent Failed"
                type: str
            rtbh_stop_fail:
                description:
                - "RTBH Stop Notification Sent Failed"
                type: str
            invalid_proto:
                description:
                - "Invalid Proto in Notification"
                type: str
            dst_ip_learn:
                description:
                - "Dst IP Entry Learned"
                type: str
            dst_ip_age:
                description:
                - "Dst IP Entry Aged"
                type: str
            n_subnet_learned:
                description:
                - "Subnet Entry of Network-object learned"
                type: str
            n_subnet_aged:
                description:
                - "Subnet Entry of Network-object Aged"
                type: str
            n_ip_learned:
                description:
                - "IP Entry of Network-object Learned"
                type: str
            n_ip_aged:
                description:
                - "IP Entry of Network-object Aged"
                type: str
            n_service_learned:
                description:
                - "Service Entry of Network-object Learned"
                type: str
            n_service_aged:
                description:
                - "Service Entry of Network-object Aged"
                type: str
            network_match_miss:
                description:
                - "Network-object Match Missed"
                type: str
            session_match_miss:
                description:
                - "Session Match Missed"
                type: str
            session_allocate_fail:
                description:
                - "Session Allocate Failed"
                type: str
            session_learned:
                description:
                - "Session Learned"
                type: str
            session_aged:
                description:
                - "Session Aged"
                type: str
            src_port_hit:
                description:
                - "Src Port Entry Hit"
                type: str
            src_port_miss:
                description:
                - "Src Port Entry Missed"
                type: str
            src_port_learn:
                description:
                - "Src Port Entry Learned"
                type: str
            src_port_age:
                description:
                - "Src Port Entry Aged"
                type: str
            n_service_not_found:
                description:
                - "Service Entry of Network-object Not Found"
                type: str
            n_subnet_create_fail:
                description:
                - "Subnet Entry of Network-object Create Failed"
                type: str
            n_ip_create_fail:
                description:
                - "IP Entry of Network-object Create Failed"
                type: str
            n_service_create_fail:
                description:
                - "Service Entry of Network-object Create Failed"
                type: str
            db_unexpected_error:
                description:
                - "Entry-Saving Unexpected Error"
                type: str
            db_oper_failure:
                description:
                - "Entry-Saving Storage Operation Failure"
                type: str
            db_open_failure:
                description:
                - "Entry-Saving Storage Open Failure"
                type: str
            db_n_subnet_table_create_failure:
                description:
                - "Entry-Saving Network Subnet Entry Storage Creation Failure"
                type: str
            db_n_ip_table_create_failure:
                description:
                - "Entry-Saving Network IP Entry Storage Creation Failure"
                type: str
            db_n_svc_table_create_failure:
                description:
                - "Entry-Saving Network Service Entry Storage Creation Failure"
                type: str
            db_n_subnet_save_attempt:
                description:
                - "Entry-Saving Network Subnet Entry Saving Attempt"
                type: str
            db_n_subnet_save_failure:
                description:
                - "Entry-Saving Network Subnet Entry Saving Failure"
                type: str
            db_n_subnet_restore_attempt:
                description:
                - "Entry-Saving Network Subnet Entry Restoring Attempt"
                type: str
            db_n_ip_save_attempt:
                description:
                - "Entry-Saving Network IP Entry Saving Attempt"
                type: str
            db_n_ip_save_failure:
                description:
                - "Entry-Saving Network IP Entry Saving Failure"
                type: str
            db_n_ip_restore_attempt:
                description:
                - "Entry-Saving Network IP Entry Restoring Attempt"
                type: str
            db_n_svc_save_attempt:
                description:
                - "Entry-Saving Network Service Entry Saving Attempt"
                type: str
            db_n_svc_save_failure:
                description:
                - "Entry-Saving Network Service Entry Saving Failure"
                type: str
            db_n_svc_restore_attempt:
                description:
                - "Entry-Saving Network Service Entry Restoring Attempt"
                type: str
            db_n_static_subnet_not_found:
                description:
                - "Entry-Saving Network Static Subnet Entry Not Found"
                type: str
            db_n_parent_entry_not_found:
                description:
                - "Entry-Saving Network Parent Entry Not Found"
                type: str
            db_worker_enq_failure:
                description:
                - "Entry-Saving Periodic Saving Routine Schedule Failure"
                type: str
            db_n_subnet_table_purge_failure:
                description:
                - "Entry-Saving Network Subnet Entry Storage Purge Failure"
                type: str
            db_n_ip_table_purge_failure:
                description:
                - "Entry-Saving Network IP Entry Storage Purge Failure"
                type: str
            db_n_svc_table_purge_failure:
                description:
                - "Entry-Saving Network Service Entry Storage Purge Failure"
                type: str
            n_sport_learned:
                description:
                - "Source Port Entry of Network-object Learned"
                type: str
            n_sport_aged:
                description:
                - "Source Port Entry of Network-object Aged"
                type: str
            n_sport_not_found:
                description:
                - "Source Port Entry of Network-object Not Found"
                type: str
            n_sport_create_fail:
                description:
                - "Source Port Entry of Network-object Create Failed"
                type: str
            trusted_sample_processed:
                description:
                - "Samples with Source IP in Trustlist Processed"
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
AVAILABLE_PROPERTIES = ["stats", "uuid", ]


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
        'stats': {
            'type': 'dict',
            'sflow_packets_received': {
                'type': 'str',
                },
            'not_supported_sflow_ver': {
                'type': 'str',
                },
            'netflow_pkts_received': {
                'type': 'str',
                },
            'not_supproted_nflow_ver': {
                'type': 'str',
                },
            'agent_not_found': {
                'type': 'str',
                },
            'pkt_drop': {
                'type': 'str',
                },
            'report_alloc_fail': {
                'type': 'str',
                },
            'report_enqueue_fail': {
                'type': 'str',
                },
            'sample_procssed': {
                'type': 'str',
                },
            'ip_rcvd': {
                'type': 'str',
                },
            'ipv6_rcvd': {
                'type': 'str',
                },
            'frag_rcvd': {
                'type': 'str',
                },
            'dst_hit': {
                'type': 'str',
                },
            'dst_miss': {
                'type': 'str',
                },
            'dst_learn': {
                'type': 'str',
                },
            'dst_age': {
                'type': 'str',
                },
            'dst_service_hit': {
                'type': 'str',
                },
            'dst_service_miss': {
                'type': 'str',
                },
            'dst_service_learn': {
                'type': 'str',
                },
            'dst_service_age': {
                'type': 'str',
                },
            'src_hit': {
                'type': 'str',
                },
            'src_miss': {
                'type': 'str',
                },
            'src_learn': {
                'type': 'str',
                },
            'src_age': {
                'type': 'str',
                },
            'entry_alloc_fail': {
                'type': 'str',
                },
            'geo_learn': {
                'type': 'str',
                },
            'geo_age': {
                'type': 'str',
                },
            'unmatch_entry_port_zero': {
                'type': 'str',
                },
            'object_alloc_oom': {
                'type': 'str',
                },
            'invalid_event': {
                'type': 'str',
                },
            'rtbh_start_sent': {
                'type': 'str',
                },
            'rtbh_stop_sent': {
                'type': 'str',
                },
            'rtbh_start_fail': {
                'type': 'str',
                },
            'rtbh_stop_fail': {
                'type': 'str',
                },
            'invalid_proto': {
                'type': 'str',
                },
            'dst_ip_learn': {
                'type': 'str',
                },
            'dst_ip_age': {
                'type': 'str',
                },
            'n_subnet_learned': {
                'type': 'str',
                },
            'n_subnet_aged': {
                'type': 'str',
                },
            'n_ip_learned': {
                'type': 'str',
                },
            'n_ip_aged': {
                'type': 'str',
                },
            'n_service_learned': {
                'type': 'str',
                },
            'n_service_aged': {
                'type': 'str',
                },
            'network_match_miss': {
                'type': 'str',
                },
            'session_match_miss': {
                'type': 'str',
                },
            'session_allocate_fail': {
                'type': 'str',
                },
            'session_learned': {
                'type': 'str',
                },
            'session_aged': {
                'type': 'str',
                },
            'src_port_hit': {
                'type': 'str',
                },
            'src_port_miss': {
                'type': 'str',
                },
            'src_port_learn': {
                'type': 'str',
                },
            'src_port_age': {
                'type': 'str',
                },
            'n_service_not_found': {
                'type': 'str',
                },
            'n_subnet_create_fail': {
                'type': 'str',
                },
            'n_ip_create_fail': {
                'type': 'str',
                },
            'n_service_create_fail': {
                'type': 'str',
                },
            'db_unexpected_error': {
                'type': 'str',
                },
            'db_oper_failure': {
                'type': 'str',
                },
            'db_open_failure': {
                'type': 'str',
                },
            'db_n_subnet_table_create_failure': {
                'type': 'str',
                },
            'db_n_ip_table_create_failure': {
                'type': 'str',
                },
            'db_n_svc_table_create_failure': {
                'type': 'str',
                },
            'db_n_subnet_save_attempt': {
                'type': 'str',
                },
            'db_n_subnet_save_failure': {
                'type': 'str',
                },
            'db_n_subnet_restore_attempt': {
                'type': 'str',
                },
            'db_n_ip_save_attempt': {
                'type': 'str',
                },
            'db_n_ip_save_failure': {
                'type': 'str',
                },
            'db_n_ip_restore_attempt': {
                'type': 'str',
                },
            'db_n_svc_save_attempt': {
                'type': 'str',
                },
            'db_n_svc_save_failure': {
                'type': 'str',
                },
            'db_n_svc_restore_attempt': {
                'type': 'str',
                },
            'db_n_static_subnet_not_found': {
                'type': 'str',
                },
            'db_n_parent_entry_not_found': {
                'type': 'str',
                },
            'db_worker_enq_failure': {
                'type': 'str',
                },
            'db_n_subnet_table_purge_failure': {
                'type': 'str',
                },
            'db_n_ip_table_purge_failure': {
                'type': 'str',
                },
            'db_n_svc_table_purge_failure': {
                'type': 'str',
                },
            'n_sport_learned': {
                'type': 'str',
                },
            'n_sport_aged': {
                'type': 'str',
                },
            'n_sport_not_found': {
                'type': 'str',
                },
            'n_sport_create_fail': {
                'type': 'str',
                },
            'trusted_sample_processed': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/detection/statistics"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/detection/statistics"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config):
    if existing_config:
        result["changed"] = True
    return result


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
    payload = utils.build_json("statistics", module.params, AVAILABLE_PROPERTIES)
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

        if state == 'present' or state == 'absent':
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
            if module.params.get("get_type") == "single" or module.params.get("get_type") is None:
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["statistics"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["statistics-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["statistics"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


"""
    Custom class which override the _check_required_arguments function to check check required arguments based on state and get_type.
"""


class AcosAnsibleModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        super(AcosAnsibleModule, self).__init__(*args, **kwargs)

    def _check_required_arguments(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        # skip validation if state is 'noop' and get_type is 'list'
        if not (param.get("state") == "noop" and param.get("get_type") == "list"):
            missing = []
            if spec is None:
                return missing
            # Check for missing required parameters in the provided argument spec
            for (k, v) in spec.items():
                required = v.get('required', False)
                if required and k not in param:
                    missing.append(k)
            if missing:
                self.fail_json(msg="Missing required parameters: {}".format(", ".join(missing)))


def main():
    module = AcosAnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
