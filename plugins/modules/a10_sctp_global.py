#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_sctp_global
description:
    - SCTP Statistics
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
                - "'all'= all; 'sctp-static-nat-session-created'= SCTP Static NAT Session Created;
          'sctp-static-nat-session-deleted'= SCTP Static NAT Session Deleted; 'sctp-fw-
          session-created'= SCTP Firewall Session Created; 'sctp-fw-session-deleted'=
          SCTP Firewall Session Deleted; 'pkt-err-drop'= Packet Error Drop; 'bad-csum'=
          Bad Checksum; 'bad-payload-drop'= Bad Payload Drop; 'bad-alignment-drop'= Bad
          Alignment Drop; 'oos-pkt-drop'= Out-of-state Packet Drop; 'max-multi-home-
          drop'= Maximum Multi-homing IP Addresses Drop; 'multi-home-remove-ip-skip'=
          Multi-homing Remove IP Parameter Skip; 'multi-home-addr-not-found-drop'= Multi-
          homing IP Address Not Found Drop; 'static-nat-cfg-not-found'= Static NAT Config
          Not Found Drop; 'cfg-err-drop'= Configuration Error Drop; 'vrrp-standby-drop'=
          NAT Resource VRRP-A Standby Drop; 'invalid-frag-chunk-drop'= Invalid Fragmented
          Chunks Drop; 'disallowed-chunk-filtered'= Disallowed Chunk Filtered;
          'disallowed-pkt-drop'= Disallowed Packet Drop; 'rate-limit-drop'= Rate-limit
          Drop; 'sby-session-created'= Standby Session Created; 'sby-session-create-
          fail'= Standby Session Create Failed; 'sby-session-updated'= Standby Session
          Updated; 'sby-session-update-fail'= Standby Session Update Failed; 'sby-static-
          nat-cfg-not-found'= Static NAT Config Not Found on Standby; 'sctp-out-of-
          system-memory'= Out of System Memory; 'conn_ext_size_max'= Max Conn Extension
          Size; 'bad-csum-shadow'= Bad Checksum Shadow; 'bad-payload-drop-shadow'= Bad
          Packet Payload Drop Shadow; 'bad-alignment-drop-shadow'= Bad Packet Alignment
          Drop Shadow; 'sctp-chunk-type-init'= SCTP Chunk Type INIT; 'sctp-chunk-type-
          init-ack'= SCTP Chunk Type INIT-ACK; 'sctp-chunk-type-cookie-echo'= SCTP Chunk
          Type COOKIE-ECHO; 'sctp-chunk-type-cookie-ack'= SCTP Chunk Type COOKIE-ACK;
          'sctp-chunk-type-sack'= SCTP Chunk Type SACK; 'sctp-chunk-type-asconf'= SCTP
          Chunk Type ASCONF; 'sctp-chunk-type-asconf-ack'= SCTP Chunk Type ASCONF-ACK;
          'sctp-chunk-type-data'= SCTP Chunk Type DATA; 'sctp-chunk-type-abort'= SCTP
          Chunk Type ABORT; 'sctp-chunk-type-shutdown'= SCTP Chunk Type SHUTDOWN; 'sctp-
          chunk-type-shutdown-ack'= SCTP Chunk Type SHUTDOWN-ACK; 'sctp-chunk-type-
          shutdown-complete'= SCTP Chunk Type SHUTDOWN-COMPLETE; 'sctp-chunk-type-error-
          op'= SCTP Chunk Type ERROR-OP; 'sctp-chunk-type-heartbeat'= SCTP Chunk Type
          HEARTBEAT; 'sctp-chunk-type-heartbeat-ack'= SCTP Chunk Type HEARTBEAT-ACK;
          'sctp-chunk-type-other'= SCTP Chunk Type OTHER; 'sctp-heartbeat-no-tuple'= SCTP
          HEARTBEAT/ACK no tuple found; 'sctp-data-no-tuple'= SCTP DATA chunk no tuple
          found; 'sctp-data-no-ext-match'= SCTP DATA no extended match found; 'sctp-
          chunk-type-init-drop'= SCTP Chunk Type INIT drop; 'sctp-chunk-type-init-ack-
          drop'= SCTP Chunk Type INIT-ACK drop; 'sctp-chunk-type-shutdown-complete-drop'=
          SCTP Chunk Type SHUTDOWN-COMPLETE drop; 'sctp-chunk-type-abort-data-drop'= SCTP
          Chunk Type with ABORT and DATA drop; 'sctp-chunk-heart-beat-clubbed'= SCTP
          HEARTBEAT chunk with other chunk; 'sctp-retx-init-ack-drop'= SCTP Chunk Type
          INIT_ACK with retx mismatched vtag drop; 'sctp-route-err-heartbeat-drop'= SCTP
          HEARTBEAT ROUTE lookup failed drop; 'sctp-reroute-failover'= SCTP REROUTE
          lookup for chunks other than HEARTBEAT; 'sctp-route-err-drop'= SCTP ROUTE
          lookup failed for chunks other than HEARTBEAT drop; 'sctp-no-ext-match'= SCTP
          no extended match found; 'sctp-retx-init-ack'= SCTP Chunk Type INIT_ACK
          retransmitted; 'sctp-retx-init-drop'= SCTP Retransmitted INIT drop; 'sctp-retx-
          init'= SCTP Retransmitted INIT; 'sctp-asconf-process-drop'= SCTP ASCONF process
          drop; 'sctp-init-vtag-zero-drop'= SCTP INIT VTAG ZERO drop; 'pkt-len-err-drop'=
          Invalid Packet Length Drop; 'pkt-chunk-len-err-drop'= Invalid Chunk Length
          Drop; 'pkt-asconf-param-len-err-drop'= Invalid Parameter Length Drop;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            sctp_static_nat_session_created:
                description:
                - "SCTP Static NAT Session Created"
                type: str
            sctp_static_nat_session_deleted:
                description:
                - "SCTP Static NAT Session Deleted"
                type: str
            sctp_fw_session_created:
                description:
                - "SCTP Firewall Session Created"
                type: str
            sctp_fw_session_deleted:
                description:
                - "SCTP Firewall Session Deleted"
                type: str
            pkt_err_drop:
                description:
                - "Packet Error Drop"
                type: str
            bad_csum:
                description:
                - "Bad Checksum"
                type: str
            bad_payload_drop:
                description:
                - "Bad Payload Drop"
                type: str
            bad_alignment_drop:
                description:
                - "Bad Alignment Drop"
                type: str
            oos_pkt_drop:
                description:
                - "Out-of-state Packet Drop"
                type: str
            max_multi_home_drop:
                description:
                - "Maximum Multi-homing IP Addresses Drop"
                type: str
            multi_home_remove_ip_skip:
                description:
                - "Multi-homing Remove IP Parameter Skip"
                type: str
            multi_home_addr_not_found_drop:
                description:
                - "Multi-homing IP Address Not Found Drop"
                type: str
            static_nat_cfg_not_found:
                description:
                - "Static NAT Config Not Found Drop"
                type: str
            cfg_err_drop:
                description:
                - "Configuration Error Drop"
                type: str
            vrrp_standby_drop:
                description:
                - "NAT Resource VRRP-A Standby Drop"
                type: str
            invalid_frag_chunk_drop:
                description:
                - "Invalid Fragmented Chunks Drop"
                type: str
            disallowed_chunk_filtered:
                description:
                - "Disallowed Chunk Filtered"
                type: str
            disallowed_pkt_drop:
                description:
                - "Disallowed Packet Drop"
                type: str
            rate_limit_drop:
                description:
                - "Rate-limit Drop"
                type: str
            sby_session_created:
                description:
                - "Standby Session Created"
                type: str
            sby_session_create_fail:
                description:
                - "Standby Session Create Failed"
                type: str
            sby_session_updated:
                description:
                - "Standby Session Updated"
                type: str
            sby_session_update_fail:
                description:
                - "Standby Session Update Failed"
                type: str
            sby_static_nat_cfg_not_found:
                description:
                - "Static NAT Config Not Found on Standby"
                type: str
            sctp_chunk_type_init:
                description:
                - "SCTP Chunk Type INIT"
                type: str
            sctp_chunk_type_init_ack:
                description:
                - "SCTP Chunk Type INIT-ACK"
                type: str
            sctp_chunk_type_cookie_echo:
                description:
                - "SCTP Chunk Type COOKIE-ECHO"
                type: str
            sctp_chunk_type_cookie_ack:
                description:
                - "SCTP Chunk Type COOKIE-ACK"
                type: str
            sctp_chunk_type_sack:
                description:
                - "SCTP Chunk Type SACK"
                type: str
            sctp_chunk_type_asconf:
                description:
                - "SCTP Chunk Type ASCONF"
                type: str
            sctp_chunk_type_asconf_ack:
                description:
                - "SCTP Chunk Type ASCONF-ACK"
                type: str
            sctp_chunk_type_data:
                description:
                - "SCTP Chunk Type DATA"
                type: str
            sctp_chunk_type_abort:
                description:
                - "SCTP Chunk Type ABORT"
                type: str
            sctp_chunk_type_shutdown:
                description:
                - "SCTP Chunk Type SHUTDOWN"
                type: str
            sctp_chunk_type_shutdown_ack:
                description:
                - "SCTP Chunk Type SHUTDOWN-ACK"
                type: str
            sctp_chunk_type_shutdown_complete:
                description:
                - "SCTP Chunk Type SHUTDOWN-COMPLETE"
                type: str
            sctp_chunk_type_error_op:
                description:
                - "SCTP Chunk Type ERROR-OP"
                type: str
            sctp_chunk_type_heartbeat:
                description:
                - "SCTP Chunk Type HEARTBEAT"
                type: str
            sctp_chunk_type_heartbeat_ack:
                description:
                - "SCTP Chunk Type HEARTBEAT-ACK"
                type: str
            sctp_chunk_type_other:
                description:
                - "SCTP Chunk Type OTHER"
                type: str
            sctp_heartbeat_no_tuple:
                description:
                - "SCTP HEARTBEAT/ACK no tuple found"
                type: str
            sctp_data_no_tuple:
                description:
                - "SCTP DATA chunk no tuple found"
                type: str
            sctp_data_no_ext_match:
                description:
                - "SCTP DATA no extended match found"
                type: str
            sctp_chunk_type_init_drop:
                description:
                - "SCTP Chunk Type INIT drop"
                type: str
            sctp_chunk_type_init_ack_drop:
                description:
                - "SCTP Chunk Type INIT-ACK drop"
                type: str
            sctp_chunk_type_shutdown_complete_drop:
                description:
                - "SCTP Chunk Type SHUTDOWN-COMPLETE drop"
                type: str
            sctp_chunk_type_abort_data_drop:
                description:
                - "SCTP Chunk Type with ABORT and DATA drop"
                type: str
            sctp_chunk_heart_beat_clubbed:
                description:
                - "SCTP HEARTBEAT chunk with other chunk"
                type: str
            sctp_retx_init_ack_drop:
                description:
                - "SCTP Chunk Type INIT_ACK with retx mismatched vtag drop"
                type: str
            sctp_route_err_heartbeat_drop:
                description:
                - "SCTP HEARTBEAT ROUTE lookup failed drop"
                type: str
            sctp_reroute_failover:
                description:
                - "SCTP REROUTE lookup for chunks other than HEARTBEAT"
                type: str
            sctp_route_err_drop:
                description:
                - "SCTP ROUTE lookup failed for chunks other than HEARTBEAT drop"
                type: str
            sctp_no_ext_match:
                description:
                - "SCTP no extended match found"
                type: str
            sctp_retx_init_ack:
                description:
                - "SCTP Chunk Type INIT_ACK retransmitted"
                type: str
            sctp_retx_init_drop:
                description:
                - "SCTP Retransmitted INIT drop"
                type: str
            sctp_retx_init:
                description:
                - "SCTP Retransmitted INIT"
                type: str
            sctp_asconf_process_drop:
                description:
                - "SCTP ASCONF process drop"
                type: str
            sctp_init_vtag_zero_drop:
                description:
                - "SCTP INIT VTAG ZERO drop"
                type: str
            pkt_len_err_drop:
                description:
                - "Invalid Packet Length Drop"
                type: str
            pkt_chunk_len_err_drop:
                description:
                - "Invalid Chunk Length Drop"
                type: str
            pkt_asconf_param_len_err_drop:
                description:
                - "Invalid Parameter Length Drop"
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
                    'all', 'sctp-static-nat-session-created', 'sctp-static-nat-session-deleted', 'sctp-fw-session-created', 'sctp-fw-session-deleted', 'pkt-err-drop', 'bad-csum', 'bad-payload-drop', 'bad-alignment-drop', 'oos-pkt-drop', 'max-multi-home-drop', 'multi-home-remove-ip-skip',
                    'multi-home-addr-not-found-drop', 'static-nat-cfg-not-found', 'cfg-err-drop', 'vrrp-standby-drop', 'invalid-frag-chunk-drop', 'disallowed-chunk-filtered', 'disallowed-pkt-drop', 'rate-limit-drop', 'sby-session-created', 'sby-session-create-fail', 'sby-session-updated',
                    'sby-session-update-fail', 'sby-static-nat-cfg-not-found', 'sctp-out-of-system-memory', 'conn_ext_size_max', 'bad-csum-shadow', 'bad-payload-drop-shadow', 'bad-alignment-drop-shadow', 'sctp-chunk-type-init', 'sctp-chunk-type-init-ack', 'sctp-chunk-type-cookie-echo',
                    'sctp-chunk-type-cookie-ack', 'sctp-chunk-type-sack', 'sctp-chunk-type-asconf', 'sctp-chunk-type-asconf-ack', 'sctp-chunk-type-data', 'sctp-chunk-type-abort', 'sctp-chunk-type-shutdown', 'sctp-chunk-type-shutdown-ack', 'sctp-chunk-type-shutdown-complete',
                    'sctp-chunk-type-error-op', 'sctp-chunk-type-heartbeat', 'sctp-chunk-type-heartbeat-ack', 'sctp-chunk-type-other', 'sctp-heartbeat-no-tuple', 'sctp-data-no-tuple', 'sctp-data-no-ext-match', 'sctp-chunk-type-init-drop', 'sctp-chunk-type-init-ack-drop',
                    'sctp-chunk-type-shutdown-complete-drop', 'sctp-chunk-type-abort-data-drop', 'sctp-chunk-heart-beat-clubbed', 'sctp-retx-init-ack-drop', 'sctp-route-err-heartbeat-drop', 'sctp-reroute-failover', 'sctp-route-err-drop', 'sctp-no-ext-match', 'sctp-retx-init-ack',
                    'sctp-retx-init-drop', 'sctp-retx-init', 'sctp-asconf-process-drop', 'sctp-init-vtag-zero-drop', 'pkt-len-err-drop', 'pkt-chunk-len-err-drop', 'pkt-asconf-param-len-err-drop'
                    ]
                }
            },
        'stats': {
            'type': 'dict',
            'sctp_static_nat_session_created': {
                'type': 'str',
                },
            'sctp_static_nat_session_deleted': {
                'type': 'str',
                },
            'sctp_fw_session_created': {
                'type': 'str',
                },
            'sctp_fw_session_deleted': {
                'type': 'str',
                },
            'pkt_err_drop': {
                'type': 'str',
                },
            'bad_csum': {
                'type': 'str',
                },
            'bad_payload_drop': {
                'type': 'str',
                },
            'bad_alignment_drop': {
                'type': 'str',
                },
            'oos_pkt_drop': {
                'type': 'str',
                },
            'max_multi_home_drop': {
                'type': 'str',
                },
            'multi_home_remove_ip_skip': {
                'type': 'str',
                },
            'multi_home_addr_not_found_drop': {
                'type': 'str',
                },
            'static_nat_cfg_not_found': {
                'type': 'str',
                },
            'cfg_err_drop': {
                'type': 'str',
                },
            'vrrp_standby_drop': {
                'type': 'str',
                },
            'invalid_frag_chunk_drop': {
                'type': 'str',
                },
            'disallowed_chunk_filtered': {
                'type': 'str',
                },
            'disallowed_pkt_drop': {
                'type': 'str',
                },
            'rate_limit_drop': {
                'type': 'str',
                },
            'sby_session_created': {
                'type': 'str',
                },
            'sby_session_create_fail': {
                'type': 'str',
                },
            'sby_session_updated': {
                'type': 'str',
                },
            'sby_session_update_fail': {
                'type': 'str',
                },
            'sby_static_nat_cfg_not_found': {
                'type': 'str',
                },
            'sctp_chunk_type_init': {
                'type': 'str',
                },
            'sctp_chunk_type_init_ack': {
                'type': 'str',
                },
            'sctp_chunk_type_cookie_echo': {
                'type': 'str',
                },
            'sctp_chunk_type_cookie_ack': {
                'type': 'str',
                },
            'sctp_chunk_type_sack': {
                'type': 'str',
                },
            'sctp_chunk_type_asconf': {
                'type': 'str',
                },
            'sctp_chunk_type_asconf_ack': {
                'type': 'str',
                },
            'sctp_chunk_type_data': {
                'type': 'str',
                },
            'sctp_chunk_type_abort': {
                'type': 'str',
                },
            'sctp_chunk_type_shutdown': {
                'type': 'str',
                },
            'sctp_chunk_type_shutdown_ack': {
                'type': 'str',
                },
            'sctp_chunk_type_shutdown_complete': {
                'type': 'str',
                },
            'sctp_chunk_type_error_op': {
                'type': 'str',
                },
            'sctp_chunk_type_heartbeat': {
                'type': 'str',
                },
            'sctp_chunk_type_heartbeat_ack': {
                'type': 'str',
                },
            'sctp_chunk_type_other': {
                'type': 'str',
                },
            'sctp_heartbeat_no_tuple': {
                'type': 'str',
                },
            'sctp_data_no_tuple': {
                'type': 'str',
                },
            'sctp_data_no_ext_match': {
                'type': 'str',
                },
            'sctp_chunk_type_init_drop': {
                'type': 'str',
                },
            'sctp_chunk_type_init_ack_drop': {
                'type': 'str',
                },
            'sctp_chunk_type_shutdown_complete_drop': {
                'type': 'str',
                },
            'sctp_chunk_type_abort_data_drop': {
                'type': 'str',
                },
            'sctp_chunk_heart_beat_clubbed': {
                'type': 'str',
                },
            'sctp_retx_init_ack_drop': {
                'type': 'str',
                },
            'sctp_route_err_heartbeat_drop': {
                'type': 'str',
                },
            'sctp_reroute_failover': {
                'type': 'str',
                },
            'sctp_route_err_drop': {
                'type': 'str',
                },
            'sctp_no_ext_match': {
                'type': 'str',
                },
            'sctp_retx_init_ack': {
                'type': 'str',
                },
            'sctp_retx_init_drop': {
                'type': 'str',
                },
            'sctp_retx_init': {
                'type': 'str',
                },
            'sctp_asconf_process_drop': {
                'type': 'str',
                },
            'sctp_init_vtag_zero_drop': {
                'type': 'str',
                },
            'pkt_len_err_drop': {
                'type': 'str',
                },
            'pkt_chunk_len_err_drop': {
                'type': 'str',
                },
            'pkt_asconf_param_len_err_drop': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/sctp/global"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/sctp/global"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["global"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["global"].get(k) != v:
            change_results["changed"] = True
            config_changes["global"][k] = v

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
    payload = utils.build_json("global", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["global"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["global-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["global"]["stats"] if info != "NotFound" else info
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
