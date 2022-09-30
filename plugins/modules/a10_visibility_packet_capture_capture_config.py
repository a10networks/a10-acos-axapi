#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_visibility_packet_capture_capture_config
description:
    - Packet Capture-Configuration
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
        - "Specify the name of the capture-config"
        type: str
        required: True
    disable:
        description:
        - "Disable packet capture (default enabled)"
        type: bool
        required: False
    concurrent_captures:
        description:
        - "Enable and specify maximum concurrent 3 tuple filter based captures in seperate
          pcaps."
        type: int
        required: False
    concurrent_conn_per_capture:
        description:
        - "Specify maximum number of concurrent connnections(5 tuple matches) to be
          captured within in a 3 tuple based capture. (default 1"
        type: int
        required: False
    concurrent_captures_age:
        description:
        - "Specify the time in minutes upto which a 3 tuple filter based capture will be
          kept active(default 1)"
        type: int
        required: False
    concurrent_conn_tag:
        description:
        - "Enable and specify maximum concurrent connnections(only 5 tuple based) to be
          captured in common pcaps."
        type: int
        required: False
    number_of_packets_per_conn:
        description:
        - "Specify maximum number of packets to be captured in a 5 tuple based connection
          (default 0 unlimited)."
        type: int
        required: False
    packet_length:
        description:
        - "Packet length in Bytes to capture (Default 128)"
        type: int
        required: False
    file_size:
        description:
        - "Specify pcapng filesize in MB, Will be distributed per CPU (default 1)"
        type: int
        required: False
    file_count:
        description:
        - "Specify the number of continuous pcapng files that can be created for capturing
          packets (default 10)"
        type: int
        required: False
    number_of_packets_per_capture:
        description:
        - "Specify Maximum number of packets per global or dynamic capture (default 0
          unlimited)"
        type: int
        required: False
    number_of_packets_total:
        description:
        - "Specify Maximum number of packets for all captures (default 0 unlimited)"
        type: int
        required: False
    enable_continuous_global_capture:
        description:
        - "Enable continuous capture of packets for the global capture(non 3 tuple based
          capture) overriding size limits"
        type: bool
        required: False
    create_pcap_files_now:
        description:
        - "Operational command to force create temporary pcapng files before completion
          (for global/non 3 tuple based captures)"
        type: bool
        required: False
    disable_auto_merge:
        description:
        - "Disable auto merging per CPU pcapng files(default enabled)"
        type: bool
        required: False
    keep_pcap_files_after_merge:
        description:
        - "Keep original per CPU pcapng files after auto merging pcapng files(default
          disabled)"
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
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            Concurrent_capture_created_by_ctr_increment:
                description:
                - "Dynamic 3 tuple based capture created (ctr increment based)"
                type: str
            Concurrent_capture_created_by_ctr_anomaly:
                description:
                - "Dynamic 3 tuple based capture created (ctr anomaly based)"
                type: str
            Concurrent_capture_create_failed_by_ctr_increment:
                description:
                - "Error, Dynamic Capture(ctr increment based) create failed"
                type: str
            Concurrent_capture_create_failed_by_ctr_anomaly:
                description:
                - "Error, Dynamic Capture(ctr anomaly based) create failed"
                type: str
            Concurrent_capture_create_failed_by_other_feature:
                description:
                - "Error, Dynamic Capture(Other feature based) create failed"
                type: str
            Concurrent_capture_create_failed_oom:
                description:
                - "Error, Dynamic Capture create failed, OOM"
                type: str
            Concurrent_capture_limit_reached:
                description:
                - "Dynamic Capture configured concurrent limit reached"
                type: str
            Concurrent_capture_by_ctr_increment_freed:
                description:
                - "Dynamic Capture(ctr increment based) freed"
                type: str
            Concurrent_capture_by_ctr_anomaly_freed:
                description:
                - "Dynamic Capture(ctr anomaly based) freed"
                type: str
            Concurrent_capture_by_ctr_other_feature_freed:
                description:
                - "Dynamic Capture(Other feature based) freed"
                type: str
            Global_capture_finished:
                description:
                - "Number of times global capture finished capturing"
                type: str
            Concurrent_capture_finished:
                description:
                - "Number of Dynamic captures(3 tuple based) finished capturing"
                type: str
            pktcapture_with_no_conn_success:
                description:
                - "Capture success, Packets without conn"
                type: str
            pktcapture_with_no_conn_failure:
                description:
                - "Capture fail, Packets without conn"
                type: str
            pktcapture_with_conn_but_not_tagged_success:
                description:
                - "Capture success, Packets with untagged conn"
                type: str
            pktcapture_with_conn_but_not_tagged_failure:
                description:
                - "Capture fail, Packets with untagged conn"
                type: str
            pktcapture_with_conn_success_global:
                description:
                - "Capture success, Packets with tagged conn (global capture)"
                type: str
            pktcapture_with_conn_success:
                description:
                - "Capture success, Packets with tagged conn (dynamic capture)"
                type: str
            pktcapture_with_conn_failure_global:
                description:
                - "Capture fail, Packets with tagged conn (global capture)"
                type: str
            pktcapture_with_conn_failure:
                description:
                - "Capture fail, Packets with tagged conn (dynamic capture)"
                type: str
            pktcapture_failure_wait_for_block:
                description:
                - "Capture fail, waiting to get free buffer"
                type: str
            pktcapture_failure_file_size_rchd:
                description:
                - "Capture fail, file size reached"
                type: str
            num_conns_tagged_global_increment:
                description:
                - "Conn tag success (based on ctr increment, Global)"
                type: str
            num_conns_tagged_global_anomaly:
                description:
                - "Conn tag success (based on ctr anomaly, Global)"
                type: str
            num_conns_tagged_global_other_feature:
                description:
                - "Conn tag success (based on Other feature, Global)"
                type: str
            num_conns_tagged_global_increment_fail:
                description:
                - "Conn tag fail (based on ctr increment, Global)"
                type: str
            num_conns_tagged_global_anomaly_fail:
                description:
                - "Conn tag fail (based on ctr anomaly, Global)"
                type: str
            num_conns_tagged_global_other_feature_fail:
                description:
                - "Conn tag fail (based on Other feature, Global)"
                type: str
            num_conns_tagged_global_increment_maxed:
                description:
                - "Conn tag fail, reached limit (based on ctr increment, Global)"
                type: str
            num_conns_tagged_global_anomaly_maxed:
                description:
                - "Conn tag fail, reached limit (based on ctr anomaly, Global)"
                type: str
            num_conns_tagged_global_other_feature_maxed:
                description:
                - "Conn tag fail, reached limit (based on Other feature, Global)"
                type: str
            num_conns_tagged_increment:
                description:
                - "Conn tag success (based on ctr increment, dynamic)"
                type: str
            num_conns_tagged_anomaly:
                description:
                - "Conn tag success (based on ctr anomaly, dynamic)"
                type: str
            num_conns_tagged_other_feature:
                description:
                - "Conn tag success (based on Other feature, dynamic)"
                type: str
            num_conns_tagged_increment_fail:
                description:
                - "Conn tag fail (based on ctr increment, dynamic)"
                type: str
            num_conns_tagged_anomaly_fail:
                description:
                - "Conn tag fail (based on ctr anomaly, dynamic)"
                type: str
            num_conns_tagged_other_feature_fail:
                description:
                - "Conn tag fail (based on Other feature, dynamic)"
                type: str
            num_conns_tagged_increment_maxed:
                description:
                - "Conn tag fail, reached limit (based on ctr increment, dynamic)"
                type: str
            num_conns_tagged_anomaly_maxed:
                description:
                - "Conn tag fail, reached limit (based on ctr anomaly, dynamic)"
                type: str
            num_conns_tagged_other_feature_maxed:
                description:
                - "Conn tag fail, reached limit (based on Other feature, dynamic)"
                type: str
            num_conns_untagged:
                description:
                - "Number of conns untagged (done with conn limit or capture)"
                type: str
            pktcapture_triggered_by_increment:
                description:
                - "Capture triggered by counter increment"
                type: str
            pktcapture_triggered_by_anomaly:
                description:
                - "Capture triggered by counter anomaly"
                type: str
            pktcapture_triggered_by_other_feature:
                description:
                - "Capture triggered by Other feature"
                type: str
            num_of_anomalies_detected:
                description:
                - "Number of times ctr Anomaly detected"
                type: str
            num_of_anomalies_cleared:
                description:
                - "Number of times ctr Anomaly cleared"
                type: str
            num_pcaps_created:
                description:
                - "Number of pcapng files created"
                type: str
            num_tmp_pcaps_created:
                description:
                - "Number of temporary pcapng files created"
                type: str
            num_pcaps_create_failed:
                description:
                - "Error, Number of pcapng files creation failed"
                type: str
            pktcap_oom:
                description:
                - "Error, Automated Packet capture infra OOM"
                type: str
            failed_disk_full:
                description:
                - "Error, Capture fail, Disk limit reached"
                type: str
            conn_ext_failed:
                description:
                - "Error, Conn extension creation fail"
                type: str
            skip_as_conn_already_recapture:
                description:
                - "Skip creating capture, conn was already captured"
                type: str
            skip_capture_as_conn_created_before_smp:
                description:
                - "Skip capturing, conn was created before the capture started"
                type: str
            failed_as_return_completed_set:
                description:
                - "Skip capturing, capture-config marked completed"
                type: str
            non_pkt_path:
                description:
                - "Skip capturing, not packet processing path"
                type: str
            pkt_already_captured:
                description:
                - "Skip capturing, packet already captured"
                type: str
            wrong_ctr_incremented:
                description:
                - "Counter increment issue"
                type: str
            auto_pcap_file_merged:
                description:
                - "Auto pcapng files merged"
                type: str
            auto_pcap_file_merged_failed:
                description:
                - "Auto pcapng files merged failed"
                type: str
            num_dynamic_capture_config_created:
                description:
                - "Number of dynamic capture-config created"
                type: str
            num_dynamic_capture_config_delete_q:
                description:
                - "Field num_dynamic_capture_config_delete_q"
                type: str
            num_dynamic_capture_config_deleted:
                description:
                - "Number of dynamic capture-config deleted"
                type: str
            num_global_counters_registered:
                description:
                - "Number of global objects registered"
                type: str
            num_global_counters_deregistered:
                description:
                - "Number of global objects deregistered"
                type: str
            num_per_object_counters_registered:
                description:
                - "Number of per instance objects registered"
                type: str
            num_per_object_counters_deregistered:
                description:
                - "Number of per instance objects deregistered"
                type: str
            name:
                description:
                - "Specify the name of the capture-config"
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
    "concurrent_captures",
    "concurrent_captures_age",
    "concurrent_conn_per_capture",
    "concurrent_conn_tag",
    "create_pcap_files_now",
    "disable",
    "disable_auto_merge",
    "enable_continuous_global_capture",
    "file_count",
    "file_size",
    "keep_pcap_files_after_merge",
    "name",
    "number_of_packets_per_capture",
    "number_of_packets_per_conn",
    "number_of_packets_total",
    "packet_length",
    "stats",
    "user_tag",
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
        'name': {
            'type': 'str',
            'required': True,
        },
        'disable': {
            'type': 'bool',
        },
        'concurrent_captures': {
            'type': 'int',
        },
        'concurrent_conn_per_capture': {
            'type': 'int',
        },
        'concurrent_captures_age': {
            'type': 'int',
        },
        'concurrent_conn_tag': {
            'type': 'int',
        },
        'number_of_packets_per_conn': {
            'type': 'int',
        },
        'packet_length': {
            'type': 'int',
        },
        'file_size': {
            'type': 'int',
        },
        'file_count': {
            'type': 'int',
        },
        'number_of_packets_per_capture': {
            'type': 'int',
        },
        'number_of_packets_total': {
            'type': 'int',
        },
        'enable_continuous_global_capture': {
            'type': 'bool',
        },
        'create_pcap_files_now': {
            'type': 'bool',
        },
        'disable_auto_merge': {
            'type': 'bool',
        },
        'keep_pcap_files_after_merge': {
            'type': 'bool',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'stats': {
            'type': 'dict',
            'Concurrent_capture_created_by_ctr_increment': {
                'type': 'str',
            },
            'Concurrent_capture_created_by_ctr_anomaly': {
                'type': 'str',
            },
            'Concurrent_capture_create_failed_by_ctr_increment': {
                'type': 'str',
            },
            'Concurrent_capture_create_failed_by_ctr_anomaly': {
                'type': 'str',
            },
            'Concurrent_capture_create_failed_by_other_feature': {
                'type': 'str',
            },
            'Concurrent_capture_create_failed_oom': {
                'type': 'str',
            },
            'Concurrent_capture_limit_reached': {
                'type': 'str',
            },
            'Concurrent_capture_by_ctr_increment_freed': {
                'type': 'str',
            },
            'Concurrent_capture_by_ctr_anomaly_freed': {
                'type': 'str',
            },
            'Concurrent_capture_by_ctr_other_feature_freed': {
                'type': 'str',
            },
            'Global_capture_finished': {
                'type': 'str',
            },
            'Concurrent_capture_finished': {
                'type': 'str',
            },
            'pktcapture_with_no_conn_success': {
                'type': 'str',
            },
            'pktcapture_with_no_conn_failure': {
                'type': 'str',
            },
            'pktcapture_with_conn_but_not_tagged_success': {
                'type': 'str',
            },
            'pktcapture_with_conn_but_not_tagged_failure': {
                'type': 'str',
            },
            'pktcapture_with_conn_success_global': {
                'type': 'str',
            },
            'pktcapture_with_conn_success': {
                'type': 'str',
            },
            'pktcapture_with_conn_failure_global': {
                'type': 'str',
            },
            'pktcapture_with_conn_failure': {
                'type': 'str',
            },
            'pktcapture_failure_wait_for_block': {
                'type': 'str',
            },
            'pktcapture_failure_file_size_rchd': {
                'type': 'str',
            },
            'num_conns_tagged_global_increment': {
                'type': 'str',
            },
            'num_conns_tagged_global_anomaly': {
                'type': 'str',
            },
            'num_conns_tagged_global_other_feature': {
                'type': 'str',
            },
            'num_conns_tagged_global_increment_fail': {
                'type': 'str',
            },
            'num_conns_tagged_global_anomaly_fail': {
                'type': 'str',
            },
            'num_conns_tagged_global_other_feature_fail': {
                'type': 'str',
            },
            'num_conns_tagged_global_increment_maxed': {
                'type': 'str',
            },
            'num_conns_tagged_global_anomaly_maxed': {
                'type': 'str',
            },
            'num_conns_tagged_global_other_feature_maxed': {
                'type': 'str',
            },
            'num_conns_tagged_increment': {
                'type': 'str',
            },
            'num_conns_tagged_anomaly': {
                'type': 'str',
            },
            'num_conns_tagged_other_feature': {
                'type': 'str',
            },
            'num_conns_tagged_increment_fail': {
                'type': 'str',
            },
            'num_conns_tagged_anomaly_fail': {
                'type': 'str',
            },
            'num_conns_tagged_other_feature_fail': {
                'type': 'str',
            },
            'num_conns_tagged_increment_maxed': {
                'type': 'str',
            },
            'num_conns_tagged_anomaly_maxed': {
                'type': 'str',
            },
            'num_conns_tagged_other_feature_maxed': {
                'type': 'str',
            },
            'num_conns_untagged': {
                'type': 'str',
            },
            'pktcapture_triggered_by_increment': {
                'type': 'str',
            },
            'pktcapture_triggered_by_anomaly': {
                'type': 'str',
            },
            'pktcapture_triggered_by_other_feature': {
                'type': 'str',
            },
            'num_of_anomalies_detected': {
                'type': 'str',
            },
            'num_of_anomalies_cleared': {
                'type': 'str',
            },
            'num_pcaps_created': {
                'type': 'str',
            },
            'num_tmp_pcaps_created': {
                'type': 'str',
            },
            'num_pcaps_create_failed': {
                'type': 'str',
            },
            'pktcap_oom': {
                'type': 'str',
            },
            'failed_disk_full': {
                'type': 'str',
            },
            'conn_ext_failed': {
                'type': 'str',
            },
            'skip_as_conn_already_recapture': {
                'type': 'str',
            },
            'skip_capture_as_conn_created_before_smp': {
                'type': 'str',
            },
            'failed_as_return_completed_set': {
                'type': 'str',
            },
            'non_pkt_path': {
                'type': 'str',
            },
            'pkt_already_captured': {
                'type': 'str',
            },
            'wrong_ctr_incremented': {
                'type': 'str',
            },
            'auto_pcap_file_merged': {
                'type': 'str',
            },
            'auto_pcap_file_merged_failed': {
                'type': 'str',
            },
            'num_dynamic_capture_config_created': {
                'type': 'str',
            },
            'num_dynamic_capture_config_delete_q': {
                'type': 'str',
            },
            'num_dynamic_capture_config_deleted': {
                'type': 'str',
            },
            'num_global_counters_registered': {
                'type': 'str',
            },
            'num_global_counters_deregistered': {
                'type': 'str',
            },
            'num_per_object_counters_registered': {
                'type': 'str',
            },
            'num_per_object_counters_deregistered': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/packet-capture/capture-config/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/packet-capture/capture-config/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["capture-config"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["capture-config"].get(k) != v:
            change_results["changed"] = True
            config_changes["capture-config"][k] = v

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
    payload = utils.build_json("capture-config", module.params,
                               AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info[
                    "capture-config"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "capture-config-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client,
                                                       existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["capture-config"][
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
