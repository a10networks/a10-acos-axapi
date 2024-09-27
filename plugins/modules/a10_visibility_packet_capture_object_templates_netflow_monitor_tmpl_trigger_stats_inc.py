#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_visibility_packet_capture_object_templates_netflow_monitor_tmpl_trigger_stats_inc
description:
    - Configure stats to triggers packet capture on increment
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
    netflow_monitor_tmpl_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    nat44_records_sent_failure:
        description:
        - "Enable automatic packet-capture for NAT44 Flow Records Failed"
        type: bool
        required: False
    nat64_records_sent_failure:
        description:
        - "Enable automatic packet-capture for NAT64 Flow Records Failed"
        type: bool
        required: False
    dslite_records_sent_failure:
        description:
        - "Enable automatic packet-capture for Dslite Flow Records Failed"
        type: bool
        required: False
    session_event_nat44_records_sent_failur:
        description:
        - "Enable automatic packet-capture for Nat44 Session Event Records Failed"
        type: bool
        required: False
    session_event_nat64_records_sent_failur:
        description:
        - "Enable automatic packet-capture for Nat64 Session Event Records Falied"
        type: bool
        required: False
    session_event_dslite_records_sent_failu:
        description:
        - "Enable automatic packet-capture for Dslite Session Event Records Failed"
        type: bool
        required: False
    session_event_fw4_records_sent_failure:
        description:
        - "Enable automatic packet-capture for FW4 Session Event Records Failed"
        type: bool
        required: False
    session_event_fw6_records_sent_failure:
        description:
        - "Enable automatic packet-capture for FW6 Session Event Records Failed"
        type: bool
        required: False
    port_mapping_nat44_records_sent_failure:
        description:
        - "Enable automatic packet-capture for Port Mapping Nat44 Event Records Failed"
        type: bool
        required: False
    port_mapping_nat64_records_sent_failure:
        description:
        - "Enable automatic packet-capture for Port Mapping Nat64 Event Records Failed"
        type: bool
        required: False
    port_mapping_dslite_records_sent_failur:
        description:
        - "Enable automatic packet-capture for Port Mapping Dslite Event Records failed"
        type: bool
        required: False
    netflow_v5_records_sent_failure:
        description:
        - "Enable automatic packet-capture for Netflow v5 Records Failed"
        type: bool
        required: False
    netflow_v5_ext_records_sent_failure:
        description:
        - "Enable automatic packet-capture for Netflow v5 Ext Records Failed"
        type: bool
        required: False
    port_batching_nat44_records_sent_failur:
        description:
        - "Enable automatic packet-capture for Port Batching Nat44 Records Failed"
        type: bool
        required: False
    port_batching_nat64_records_sent_failur:
        description:
        - "Enable automatic packet-capture for Port Batching Nat64 Records Failed"
        type: bool
        required: False
    port_batching_dslite_records_sent_failu:
        description:
        - "Enable automatic packet-capture for Port Batching Dslite Records Failed"
        type: bool
        required: False
    port_batching_v2_nat44_records_sent_fai:
        description:
        - "Enable automatic packet-capture for Port Batching V2 Nat44 Records Failed"
        type: bool
        required: False
    port_batching_v2_nat64_records_sent_fai:
        description:
        - "Enable automatic packet-capture for Port Batching V2 Nat64 Records Failed"
        type: bool
        required: False
    port_batching_v2_dslite_records_sent_fa:
        description:
        - "Enable automatic packet-capture for Port Batching V2 Dslite Records Falied"
        type: bool
        required: False
    custom_session_event_nat44_creation_rec:
        description:
        - "Enable automatic packet-capture for Custom Nat44 Session Creation Records
          Failed"
        type: bool
        required: False
    custom_session_event_nat64_creation_rec:
        description:
        - "Enable automatic packet-capture for Custom Nat64 Session Creation Records
          Failed"
        type: bool
        required: False
    custom_session_event_dslite_creation_re:
        description:
        - "Enable automatic packet-capture for Custom Dslite Session Creation Records
          Failed"
        type: bool
        required: False
    custom_session_event_nat44_deletion_rec:
        description:
        - "Enable automatic packet-capture for Custom Nat44 Session Deletion Records
          Failed"
        type: bool
        required: False
    custom_session_event_nat64_deletion_rec:
        description:
        - "Enable automatic packet-capture for Custom Nat64 Session Deletion Records
          Failed"
        type: bool
        required: False
    custom_session_event_dslite_deletion_re:
        description:
        - "Enable automatic packet-capture for Custom Dslite Session Deletion Records
          Failed"
        type: bool
        required: False
    custom_session_event_fw4_creation_recor:
        description:
        - "Enable automatic packet-capture for Custom FW4 Session Creation Records Failed"
        type: bool
        required: False
    custom_session_event_fw6_creation_recor:
        description:
        - "Enable automatic packet-capture for Custom FW6 Session Creation Records Failed"
        type: bool
        required: False
    custom_session_event_fw4_deletion_recor:
        description:
        - "Enable automatic packet-capture for Custom FW4 Session Deletion Records Failed"
        type: bool
        required: False
    custom_session_event_fw6_deletion_recor:
        description:
        - "Enable automatic packet-capture for Custom FW6 Session Deletion Records Failed"
        type: bool
        required: False
    custom_deny_reset_event_fw4_records_sen:
        description:
        - "Enable automatic packet-capture for Custom FW4 Deny/Reset Event Records Failed"
        type: bool
        required: False
    custom_deny_reset_event_fw6_records_sen:
        description:
        - "Enable automatic packet-capture for Custom FW6 Deny/Reset Event Records Failed"
        type: bool
        required: False
    custom_port_mapping_nat44_creation_reco:
        description:
        - "Enable automatic packet-capture for Custom Nat44 Port Map Creation Records
          Failed"
        type: bool
        required: False
    custom_port_mapping_nat64_creation_reco:
        description:
        - "Enable automatic packet-capture for Custom Nat64 Port Map Creation Records
          Failed"
        type: bool
        required: False
    custom_port_mapping_dslite_creation_rec:
        description:
        - "Enable automatic packet-capture for Custom Dslite Port Map Creation Records
          Failed"
        type: bool
        required: False
    custom_port_mapping_nat44_deletion_reco:
        description:
        - "Enable automatic packet-capture for Custom Nat44 Port Map Deletion Records
          Failed"
        type: bool
        required: False
    custom_port_mapping_nat64_deletion_reco:
        description:
        - "Enable automatic packet-capture for Custom Nat64 Port Map Deletion Records
          Failed"
        type: bool
        required: False
    custom_port_mapping_dslite_deletion_rec:
        description:
        - "Enable automatic packet-capture for Custom Dslite Port Map Deletion Records
          Failed"
        type: bool
        required: False
    custom_port_batching_nat44_creation_rec:
        description:
        - "Enable automatic packet-capture for Custom Nat44 Port Batch Creation Records
          Failed"
        type: bool
        required: False
    custom_port_batching_nat64_creation_rec:
        description:
        - "Enable automatic packet-capture for Custom Nat64 Port Batch Creation Records
          Failed"
        type: bool
        required: False
    custom_port_batching_dslite_creation_re:
        description:
        - "Enable automatic packet-capture for Custom Dslite Port Batch Creation Records
          Failed"
        type: bool
        required: False
    custom_port_batching_nat44_deletion_rec:
        description:
        - "Enable automatic packet-capture for Custom Nat44 Port Batch Deletion Records
          Failed"
        type: bool
        required: False
    custom_port_batching_nat64_deletion_rec:
        description:
        - "Enable automatic packet-capture for Custom Nat64 Port Batch Deletion Records
          Failed"
        type: bool
        required: False
    custom_port_batching_dslite_deletion_re:
        description:
        - "Enable automatic packet-capture for Custom Dslite Port Batch Deletion Records
          Failed"
        type: bool
        required: False
    custom_port_batching_v2_nat44_creation_:
        description:
        - "Enable automatic packet-capture for Custom Nat44 Port Batch V2 Creation Records
          Failed"
        type: bool
        required: False
    custom_port_batching_v2_nat64_creation_:
        description:
        - "Enable automatic packet-capture for Custom Nat64 Port Batch V2 Creation Records
          Failed"
        type: bool
        required: False
    custom_port_batching_v2_dslite_creation:
        description:
        - "Enable automatic packet-capture for Custom Dslite Port Batch V2 Creation
          Records Failed"
        type: bool
        required: False
    custom_port_batching_v2_nat44_deletion_:
        description:
        - "Enable automatic packet-capture for Custom Nat44 Port Batch V2 Deletion Records
          Failed"
        type: bool
        required: False
    custom_port_batching_v2_nat64_deletion_:
        description:
        - "Enable automatic packet-capture for Custom Nat64 Port Batch V2 Deletion Records
          Failed"
        type: bool
        required: False
    custom_port_batching_v2_dslite_deletion:
        description:
        - "Enable automatic packet-capture for Custom Dslite Port Batch V2 Deletion
          Records Failed"
        type: bool
        required: False
    custom_gtp_c_tunnel_event_records_sent_:
        description:
        - "Enable automatic packet-capture for Custom GTP C Tunnel Records Sent Failure"
        type: bool
        required: False
    custom_gtp_u_tunnel_event_records_sent_:
        description:
        - "Enable automatic packet-capture for Custom GTP U Tunnel Records Sent Failure"
        type: bool
        required: False
    custom_gtp_deny_event_records_sent_fail:
        description:
        - "Enable automatic packet-capture for Custom GTP Deny Records Sent Failure"
        type: bool
        required: False
    custom_gtp_info_event_records_sent_fail:
        description:
        - "Enable automatic packet-capture for Custom GTP Info Records Sent Failure"
        type: bool
        required: False
    custom_fw_iddos_entry_created_records_s:
        description:
        - "Enable automatic packet-capture for Custom FW iDDoS Entry Created Records Sent
          Failure"
        type: bool
        required: False
    custom_fw_iddos_entry_deleted_records_s:
        description:
        - "Enable automatic packet-capture for Custom FW iDDoS Entry Deleted Records Sent
          Failure"
        type: bool
        required: False
    custom_fw_sesn_limit_exceeded_records_s:
        description:
        - "Enable automatic packet-capture for Custom FW Session Limit Exceeded Records
          Sent Failure"
        type: bool
        required: False
    custom_nat_iddos_l3_entry_created_recor:
        description:
        - "Enable automatic packet-capture for Custom NAT iDDoS L3 Entry Created Records
          Sent Failure"
        type: bool
        required: False
    custom_nat_iddos_l3_entry_deleted_recor:
        description:
        - "Enable automatic packet-capture for Custom NAT iDDoS L3 Entry Deleted Records
          Sent Failure"
        type: bool
        required: False
    custom_nat_iddos_l4_entry_created_recor:
        description:
        - "Enable automatic packet-capture for Custom NAT iDDoS L4 Entry Created Records
          Sent Failure"
        type: bool
        required: False
    custom_nat_iddos_l4_entry_deleted_recor:
        description:
        - "Enable automatic packet-capture for Custom NAT iDDoS L4 Entry Deleted Records
          Sent Failure"
        type: bool
        required: False
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
AVAILABLE_PROPERTIES = [
    "custom_deny_reset_event_fw4_records_sen", "custom_deny_reset_event_fw6_records_sen", "custom_fw_iddos_entry_created_records_s", "custom_fw_iddos_entry_deleted_records_s", "custom_fw_sesn_limit_exceeded_records_s", "custom_gtp_c_tunnel_event_records_sent_", "custom_gtp_deny_event_records_sent_fail", "custom_gtp_info_event_records_sent_fail",
    "custom_gtp_u_tunnel_event_records_sent_", "custom_nat_iddos_l3_entry_created_recor", "custom_nat_iddos_l3_entry_deleted_recor", "custom_nat_iddos_l4_entry_created_recor", "custom_nat_iddos_l4_entry_deleted_recor", "custom_port_batching_dslite_creation_re", "custom_port_batching_dslite_deletion_re", "custom_port_batching_nat44_creation_rec",
    "custom_port_batching_nat44_deletion_rec", "custom_port_batching_nat64_creation_rec", "custom_port_batching_nat64_deletion_rec", "custom_port_batching_v2_dslite_creation", "custom_port_batching_v2_dslite_deletion", "custom_port_batching_v2_nat44_creation_", "custom_port_batching_v2_nat44_deletion_", "custom_port_batching_v2_nat64_creation_",
    "custom_port_batching_v2_nat64_deletion_", "custom_port_mapping_dslite_creation_rec", "custom_port_mapping_dslite_deletion_rec", "custom_port_mapping_nat44_creation_reco", "custom_port_mapping_nat44_deletion_reco", "custom_port_mapping_nat64_creation_reco", "custom_port_mapping_nat64_deletion_reco", "custom_session_event_dslite_creation_re",
    "custom_session_event_dslite_deletion_re", "custom_session_event_fw4_creation_recor", "custom_session_event_fw4_deletion_recor", "custom_session_event_fw6_creation_recor", "custom_session_event_fw6_deletion_recor", "custom_session_event_nat44_creation_rec", "custom_session_event_nat44_deletion_rec", "custom_session_event_nat64_creation_rec",
    "custom_session_event_nat64_deletion_rec", "dslite_records_sent_failure", "nat44_records_sent_failure", "nat64_records_sent_failure", "netflow_v5_ext_records_sent_failure", "netflow_v5_records_sent_failure", "port_batching_dslite_records_sent_failu", "port_batching_nat44_records_sent_failur", "port_batching_nat64_records_sent_failur",
    "port_batching_v2_dslite_records_sent_fa", "port_batching_v2_nat44_records_sent_fai", "port_batching_v2_nat64_records_sent_fai", "port_mapping_dslite_records_sent_failur", "port_mapping_nat44_records_sent_failure", "port_mapping_nat64_records_sent_failure", "session_event_dslite_records_sent_failu", "session_event_fw4_records_sent_failure",
    "session_event_fw6_records_sent_failure", "session_event_nat44_records_sent_failur", "session_event_nat64_records_sent_failur", "uuid",
    ]


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
        'nat44_records_sent_failure': {
            'type': 'bool',
            },
        'nat64_records_sent_failure': {
            'type': 'bool',
            },
        'dslite_records_sent_failure': {
            'type': 'bool',
            },
        'session_event_nat44_records_sent_failur': {
            'type': 'bool',
            },
        'session_event_nat64_records_sent_failur': {
            'type': 'bool',
            },
        'session_event_dslite_records_sent_failu': {
            'type': 'bool',
            },
        'session_event_fw4_records_sent_failure': {
            'type': 'bool',
            },
        'session_event_fw6_records_sent_failure': {
            'type': 'bool',
            },
        'port_mapping_nat44_records_sent_failure': {
            'type': 'bool',
            },
        'port_mapping_nat64_records_sent_failure': {
            'type': 'bool',
            },
        'port_mapping_dslite_records_sent_failur': {
            'type': 'bool',
            },
        'netflow_v5_records_sent_failure': {
            'type': 'bool',
            },
        'netflow_v5_ext_records_sent_failure': {
            'type': 'bool',
            },
        'port_batching_nat44_records_sent_failur': {
            'type': 'bool',
            },
        'port_batching_nat64_records_sent_failur': {
            'type': 'bool',
            },
        'port_batching_dslite_records_sent_failu': {
            'type': 'bool',
            },
        'port_batching_v2_nat44_records_sent_fai': {
            'type': 'bool',
            },
        'port_batching_v2_nat64_records_sent_fai': {
            'type': 'bool',
            },
        'port_batching_v2_dslite_records_sent_fa': {
            'type': 'bool',
            },
        'custom_session_event_nat44_creation_rec': {
            'type': 'bool',
            },
        'custom_session_event_nat64_creation_rec': {
            'type': 'bool',
            },
        'custom_session_event_dslite_creation_re': {
            'type': 'bool',
            },
        'custom_session_event_nat44_deletion_rec': {
            'type': 'bool',
            },
        'custom_session_event_nat64_deletion_rec': {
            'type': 'bool',
            },
        'custom_session_event_dslite_deletion_re': {
            'type': 'bool',
            },
        'custom_session_event_fw4_creation_recor': {
            'type': 'bool',
            },
        'custom_session_event_fw6_creation_recor': {
            'type': 'bool',
            },
        'custom_session_event_fw4_deletion_recor': {
            'type': 'bool',
            },
        'custom_session_event_fw6_deletion_recor': {
            'type': 'bool',
            },
        'custom_deny_reset_event_fw4_records_sen': {
            'type': 'bool',
            },
        'custom_deny_reset_event_fw6_records_sen': {
            'type': 'bool',
            },
        'custom_port_mapping_nat44_creation_reco': {
            'type': 'bool',
            },
        'custom_port_mapping_nat64_creation_reco': {
            'type': 'bool',
            },
        'custom_port_mapping_dslite_creation_rec': {
            'type': 'bool',
            },
        'custom_port_mapping_nat44_deletion_reco': {
            'type': 'bool',
            },
        'custom_port_mapping_nat64_deletion_reco': {
            'type': 'bool',
            },
        'custom_port_mapping_dslite_deletion_rec': {
            'type': 'bool',
            },
        'custom_port_batching_nat44_creation_rec': {
            'type': 'bool',
            },
        'custom_port_batching_nat64_creation_rec': {
            'type': 'bool',
            },
        'custom_port_batching_dslite_creation_re': {
            'type': 'bool',
            },
        'custom_port_batching_nat44_deletion_rec': {
            'type': 'bool',
            },
        'custom_port_batching_nat64_deletion_rec': {
            'type': 'bool',
            },
        'custom_port_batching_dslite_deletion_re': {
            'type': 'bool',
            },
        'custom_port_batching_v2_nat44_creation_': {
            'type': 'bool',
            },
        'custom_port_batching_v2_nat64_creation_': {
            'type': 'bool',
            },
        'custom_port_batching_v2_dslite_creation': {
            'type': 'bool',
            },
        'custom_port_batching_v2_nat44_deletion_': {
            'type': 'bool',
            },
        'custom_port_batching_v2_nat64_deletion_': {
            'type': 'bool',
            },
        'custom_port_batching_v2_dslite_deletion': {
            'type': 'bool',
            },
        'custom_gtp_c_tunnel_event_records_sent_': {
            'type': 'bool',
            },
        'custom_gtp_u_tunnel_event_records_sent_': {
            'type': 'bool',
            },
        'custom_gtp_deny_event_records_sent_fail': {
            'type': 'bool',
            },
        'custom_gtp_info_event_records_sent_fail': {
            'type': 'bool',
            },
        'custom_fw_iddos_entry_created_records_s': {
            'type': 'bool',
            },
        'custom_fw_iddos_entry_deleted_records_s': {
            'type': 'bool',
            },
        'custom_fw_sesn_limit_exceeded_records_s': {
            'type': 'bool',
            },
        'custom_nat_iddos_l3_entry_created_recor': {
            'type': 'bool',
            },
        'custom_nat_iddos_l3_entry_deleted_recor': {
            'type': 'bool',
            },
        'custom_nat_iddos_l4_entry_created_recor': {
            'type': 'bool',
            },
        'custom_nat_iddos_l4_entry_deleted_recor': {
            'type': 'bool',
            },
        'uuid': {
            'type': 'str',
            }
        })
    # Parent keys
    rv.update(dict(netflow_monitor_tmpl_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/packet-capture/object-templates/netflow-monitor-tmpl/{netflow_monitor_tmpl_name}/trigger-stats-inc"

    f_dict = {}
    if '/' in module.params["netflow_monitor_tmpl_name"]:
        f_dict["netflow_monitor_tmpl_name"] = module.params["netflow_monitor_tmpl_name"].replace("/", "%2F")
    else:
        f_dict["netflow_monitor_tmpl_name"] = module.params["netflow_monitor_tmpl_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/packet-capture/object-templates/netflow-monitor-tmpl/{netflow_monitor_tmpl_name}/trigger-stats-inc"

    f_dict = {}
    f_dict["netflow_monitor_tmpl_name"] = module.params["netflow_monitor_tmpl_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["trigger-stats-inc"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["trigger-stats-inc"].get(k) != v:
            change_results["changed"] = True
            config_changes["trigger-stats-inc"][k] = v

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
    payload = utils.build_json("trigger-stats-inc", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["trigger-stats-inc"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["trigger-stats-inc-list"] if info != "NotFound" else info
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
