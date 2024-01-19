#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_fw_gtp_apn_prefix
description:
    - Dynamic GTP APN Prefix counters
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
            key_name:
                description:
                - "Field key_name"
                type: str
            uplink_bytes:
                description:
                - "Uplink Bytes"
                type: str
            downlink_bytes:
                description:
                - "Downlink Bytes"
                type: str
            uplink_pkts:
                description:
                - "Uplink Packets"
                type: str
            downlink_pkts:
                description:
                - "Downlink Packets"
                type: str
            u_uplink_bytes:
                description:
                - "Uplink Bytes"
                type: str
            u_downlink_bytes:
                description:
                - "Downlink Bytes"
                type: str
            u_uplink_pkts:
                description:
                - "Uplink Packets"
                type: str
            u_downlink_pkts:
                description:
                - "GTP-U Downlink Packets"
                type: str
            gtp_v0_c_tunnel_created:
                description:
                - "GTPv0-C Tunnel Created"
                type: str
            gtp_v0_c_tunnel_half_open:
                description:
                - "GTPv0-C Half open tunnel created"
                type: str
            gtp_v0_c_tunnel_half_closed:
                description:
                - "GTPv0-C Tunnel Delete Request"
                type: str
            gtp_v0_c_tunnel_closed:
                description:
                - "GTPv0-C Tunnel Marked Deleted"
                type: str
            gtp_v0_c_tunnel_deleted:
                description:
                - "GTPv0-C Tunnel Deleted"
                type: str
            gtp_v0_c_half_open_tunnel_closed:
                description:
                - "GTPv0-C Half open tunnel closed"
                type: str
            gtp_v1_c_tunnel_created:
                description:
                - "GTPv1-C Tunnel Created"
                type: str
            gtp_v1_c_tunnel_half_open:
                description:
                - "GTPv1-C Half open tunnel created"
                type: str
            gtp_v1_c_tunnel_half_closed:
                description:
                - "GTPv1-C Tunnel Delete Request"
                type: str
            gtp_v1_c_tunnel_closed:
                description:
                - "GTPv1-C Tunnel Marked Deleted"
                type: str
            gtp_v1_c_tunnel_deleted:
                description:
                - "GTPv1-C Tunnel Deleted"
                type: str
            gtp_v1_c_half_open_tunnel_closed:
                description:
                - "GTPv1-C Half open tunnel closed"
                type: str
            gtp_v2_c_tunnel_created:
                description:
                - "GTPv2-C Tunnel Created"
                type: str
            gtp_v2_c_tunnel_half_open:
                description:
                - "GTPv2-C Half open tunnel created"
                type: str
            gtp_v2_c_tunnel_half_closed:
                description:
                - "GTPv2-C Tunnel Delete Request"
                type: str
            gtp_v2_c_tunnel_closed:
                description:
                - "GTPv2-C Tunnel Marked Deleted"
                type: str
            gtp_v2_c_tunnel_deleted:
                description:
                - "GTPv2-C Tunnel Deleted"
                type: str
            gtp_v2_c_half_open_tunnel_closed:
                description:
                - "GTPv2-C Half open tunnel closed"
                type: str
            gtp_u_tunnel_created:
                description:
                - "GTP-U Tunnel Created"
                type: str
            gtp_u_tunnel_deleted:
                description:
                - "GTP-U Tunnel Deleted"
                type: str
            gtp_v0_c_update_pdp_resp_unsuccess:
                description:
                - "GTPV0-C Update PDP Context Response Unsuccessful"
                type: str
            gtp_v1_c_update_pdp_resp_unsuccess:
                description:
                - "GTPV1-C Update PDP Context response Unsuccessful"
                type: str
            gtp_v2_c_mod_bearer_resp_unsuccess:
                description:
                - "GTPV2-C Modify Bearer Response Unsuccessful"
                type: str
            gtp_v0_c_create_pdp_resp_unsuccess:
                description:
                - "GTPV0-C Create PDP Context Response Unsuccessful"
                type: str
            gtp_v1_c_create_pdp_resp_unsuccess:
                description:
                - "GTPV1-C Create PDP Context Response Unsuccessful"
                type: str
            gtp_v2_c_create_sess_resp_unsuccess:
                description:
                - "GTPV2-C Create Session Response Unsuccessful"
                type: str
            gtp_v2_c_piggyback_message:
                description:
                - "GTPv2-C Piggyback Messages seen"
                type: str
            gtp_path_management_message:
                description:
                - "GTP Path Management Messages Received"
                type: str
            gtp_v0_c_tunnel_deleted_restart:
                description:
                - "GTPv0-C Tunnel Deleted with Restart/failure"
                type: str
            gtp_v1_c_tunnel_deleted_restart:
                description:
                - "GTPv1-C Tunnel Deleted with Restart/failure"
                type: str
            gtp_v2_c_tunnel_deleted_restart:
                description:
                - "GTPv2-C Tunnel Deleted with Restart/failure"
                type: str
            gtp_v0_c_reserved_message_allow:
                description:
                - "GTPv0-C Reserved Message Allow"
                type: str
            gtp_v1_c_reserved_message_allow:
                description:
                - "GTPv1-C Reserved Message Allow"
                type: str
            gtp_v2_c_reserved_message_allow:
                description:
                - "GTPv2-C Reserved Message Allow"
                type: str
            gtp_v1_c_pdu_notification_request_forward:
                description:
                - "GTPv1-C PDU Notification Request Forward"
                type: str
            gtp_v1_c_pdu_notification_reject_request_forward:
                description:
                - "GTPv1-C PDU Notification Reject Request Forward"
                type: str
            gtp_v0_c_pdu_notification_request_forward:
                description:
                - "GTPv0-C PDU Notification Request Forward"
                type: str
            gtp_v0_c_pdu_notification_reject_request_forward:
                description:
                - "GTPv0-C PDU Notification Reject Request Forward"
                type: str
            gtp_v0_c_message_skipped_apn_filtering_no_imsi:
                description:
                - "GTPv0-C APN/IMSI Filtering Skipped (No IMSI)"
                type: str
            gtp_v1_c_message_skipped_apn_filtering_no_imsi:
                description:
                - "GTPv1-C APN/IMSI Filtering Skipped (No IMSI)"
                type: str
            gtp_v2_c_message_skipped_apn_filtering_no_imsi:
                description:
                - "GTPv2-C APN/IMSI Filtering Skipped (No IMSI)"
                type: str
            gtp_v0_c_message_skipped_msisdn_filtering_no_msisdn:
                description:
                - "GTPv0-C MSISDN Filtering Skipped (No MSISDN)"
                type: str
            gtp_v1_c_message_skipped_msisdn_filtering_no_msisdn:
                description:
                - "GTPv1-C MSISDN Filtering Skipped (No MSISDN)"
                type: str
            gtp_v2_c_message_skipped_msisdn_filtering_no_msisdn:
                description:
                - "GTPv2-C MSISDN Filtering Skipped (No MSISDN)"
                type: str
            gtp_v0_c_packet_dummy_msisdn:
                description:
                - "GTPv0-C Packet With Dummy MSISDN Forwarded"
                type: str
            gtp_v1_c_packet_dummy_msisdn:
                description:
                - "GTPv1-C Packet With Dummy MSISDN Forwarded"
                type: str
            gtp_v2_c_packet_dummy_msisdn:
                description:
                - "GTPv2-C Packet With Dummy MSISDN Forwarded"
                type: str
            drop_vld_gtp_v2_c_message_with_teid_zero_expected:
                description:
                - "Validation Drop= GTPv2-C Create Session Request with TEID"
                type: str
            drop_vld_gtp_v1_c_message_with_teid_zero_expected:
                description:
                - "Validation Drop= GTPv1-C PDU Notification Request with TEID"
                type: str
            drop_vld_gtp_v0_c_message_with_teid_zero_expected:
                description:
                - "Validation Drop= GTPv0-C PDU Notification Request with TEID"
                type: str
            drop_vld_reserved_field_set:
                description:
                - "Validation Drop= Reserved Header Field Set"
                type: str
            drop_vld_tunnel_id_flag:
                description:
                - "Validation Drop= Tunnel Header Flag Not Set"
                type: str
            drop_vld_invalid_flow_label_v0:
                description:
                - "Validation Drop= Invalid Flow Label in GTPv0-C Header"
                type: str
            drop_vld_invalid_teid:
                description:
                - "Validation Drop= Invalid TEID Value"
                type: str
            drop_vld_unsupported_message_type:
                description:
                - "Validation Drop= Message type not supported by GTP Version"
                type: str
            drop_vld_out_of_state:
                description:
                - "Validation Drop= Out Of State GTP Message"
                type: str
            drop_vld_mandatory_information_element:
                description:
                - "Validation Drop= Mandatory IE Not Present"
                type: str
            drop_vld_out_of_order_ie:
                description:
                - "Validation Drop= GTPv1-C Message Out of Order IE"
                type: str
            drop_vld_out_of_state_ie:
                description:
                - "Validation Drop= Unexpected IE Present in Message"
                type: str
            drop_vld_reserved_information_element:
                description:
                - "Validation Drop= Reserved IE Field Present"
                type: str
            drop_vld_version_not_supported:
                description:
                - "Validation Drop= Invalid GTP version"
                type: str
            drop_vld_message_length:
                description:
                - "Validation Drop= Message Length Exceeded"
                type: str
            drop_vld_cross_layer_correlation:
                description:
                - "Validation Drop= Cross Layer IP Address Mismatch"
                type: str
            drop_vld_country_code_mismatch:
                description:
                - "Validation Drop= Country Code Mismatch in IMSI and MSISDN"
                type: str
            drop_vld_gtp_u_spoofed_source_address:
                description:
                - "Validation Drop= GTP-U IP Address Spoofed"
                type: str
            drop_vld_gtp_bearer_count_exceed:
                description:
                - "Validation Drop= GTP Bearer count exceeded max (11)"
                type: str
            drop_vld_gtp_v2_wrong_lbi_create_bearer_req:
                description:
                - "Validation Drop= GTPV2-C Wrong LBI in Create Bearer Request"
                type: str
            gtp_c_handover_in_progress_with_conn:
                description:
                - "GTP-C matching a conn with Handover In Progress"
                type: str
            drop_vld_v0_reserved_message_drop:
                description:
                - "Validation Drop= GTPv0-C Reserved Message Drop"
                type: str
            drop_vld_v1_reserved_message_drop:
                description:
                - "Validation Drop= GTPv1-C Reserved Message Drop"
                type: str
            drop_vld_v2_reserved_message_drop:
                description:
                - "Validation Drop= GTPv2-C Reserved Message Drop"
                type: str
            drop_vld_invalid_pkt_len_piggyback:
                description:
                - "Validation Drop= Piggyback message invalid packet length"
                type: str
            drop_vld_sanity_failed_piggyback:
                description:
                - "Validation Drop= piggyback message anomaly failed"
                type: str
            drop_vld_sequence_num_correlation:
                description:
                - "Validation Drop= GTP-C Sequence number Mismatch"
                type: str
            drop_vld_gtpv0_seqnum_buffer_full:
                description:
                - "Validation Drop= GTPV0-C conn Sequence number Buffer Full"
                type: str
            drop_vld_gtpv1_seqnum_buffer_full:
                description:
                - "Validation Drop= GTPV1-C conn Sequence number Buffer Full"
                type: str
            drop_vld_gtpv2_seqnum_buffer_full:
                description:
                - "Validation Drop= GTPV2-C conn Sequence number Buffer Full"
                type: str
            drop_vld_gtp_invalid_imsi_len_drop:
                description:
                - "Validation Drop= GTP-C Invalid IMSI Length Drop"
                type: str
            drop_vld_gtp_invalid_apn_len_drop:
                description:
                - "Validation Drop= GTP-C Invalid APN Length Drop"
                type: str
            drop_vld_protocol_flag_unset:
                description:
                - "Validation Drop= Protocol flag in Header Field not Set"
                type: str
            drop_vld_gtpv0_subscriber_attr_miss:
                description:
                - "Validation Drop= GTPV0-c Subscriber Attributes Missing"
                type: str
            drop_vld_gtpv1_subscriber_attr_miss:
                description:
                - "Validation Drop= GTPV1-c Subscriber Attributes Missing"
                type: str
            drop_vld_gtpv2_subscriber_attr_miss:
                description:
                - "Validation Drop= GTPV2-c Subscriber Attributes Missing"
                type: str
            drop_vld_gtp_v0_c_ie_len_exceed_msg_len:
                description:
                - "Validation Drop= GTPv0-C IE Length Exceeds Message Length"
                type: str
            drop_vld_gtp_v1_c_ie_len_exceed_msg_len:
                description:
                - "Validation Drop= GTPv1-C IE Length Exceeds Message Length"
                type: str
            drop_vld_gtp_v2_c_ie_len_exceed_msg_len:
                description:
                - "Validation Drop= GTPv2-C IE Length Exceeds Message Length"
                type: str
            drop_vld_gtp_v0_c_message_length_mismatch:
                description:
                - "Validation Drop= GTPv0-C Message Length Mismatch Across Layers"
                type: str
            drop_vld_gtp_v1_c_message_length_mismatch:
                description:
                - "Validation Drop= GTPv1-C Message Length Mismatch Across Layers"
                type: str
            drop_vld_gtp_v2_c_message_length_mismatch:
                description:
                - "Validation Drop= GTPv2-C Message Length Mismatch Across Layers"
                type: str
            drop_vld_gtp_v0_c_message_dropped_apn_filtering_no_apn:
                description:
                - "GTPv0-C APN/IMSI Filtering dropped (No APN)"
                type: str
            drop_vld_gtp_v1_c_message_dropped_apn_filtering_no_apn:
                description:
                - "GTPv1-C APN/IMSI Filtering dropped (No APN)"
                type: str
            drop_vld_gtp_v2_c_message_dropped_apn_filtering_no_apn:
                description:
                - "GTPv2-C APN/IMSI Filtering dropped (No APN)"
                type: str
            drop_flt_message_filtering:
                description:
                - "Filtering Drop= Message Type Not Permitted on Interface"
                type: str
            drop_flt_apn_filtering:
                description:
                - "Filtering Drop= APN IMSI Filtering"
                type: str
            drop_flt_msisdn_filtering:
                description:
                - "Filtering Drop= MSISDN Filtering"
                type: str
            drop_flt_rat_type_filtering:
                description:
                - "Filtering Drop= RAT Type Filtering"
                type: str
            drop_flt_gtp_in_gtp:
                description:
                - "Filtering Drop= GTP in GTP Tunnel Present"
                type: str
            drop_rl_gtp_v0_c_agg:
                description:
                - "Rate-limit Drop= Maximum GTPv0-C messages rate"
                type: str
            drop_rl_gtp_v1_c_agg:
                description:
                - "Rate-limit Drop= Maximum GTPv1-C messages rate"
                type: str
            drop_rl_gtp_v2_c_agg:
                description:
                - "Rate-limit Drop= Maximum GTPv2-C messages rate"
                type: str
            drop_rl_gtp_v1_c_create_pdp_request:
                description:
                - "Rate-limit Drop= GTPv1-C Create PDP Req rate"
                type: str
            drop_rl_gtp_v2_c_create_session_request:
                description:
                - "Rate-limit Drop= GTPv2-C Create Session Req rate"
                type: str
            drop_rl_gtp_v1_c_update_pdp_request:
                description:
                - "Rate-limit Drop= GTPv1-C Update PDP Req rate"
                type: str
            drop_rl_gtp_v2_c_modify_bearer_request:
                description:
                - "Rate-limit Drop= GTPv2-C Modify Bearer Req rate"
                type: str
            drop_rl_gtp_u_tunnel_create:
                description:
                - "Rate-limit Drop= GTP-U Tunnel Creation rate"
                type: str
            drop_rl_gtp_u_uplink_byte:
                description:
                - "Rate-limit Drop= GTP-U Uplink byte rate"
                type: str
            drop_rl_gtp_u_uplink_packet:
                description:
                - "Rate-limit Drop= GTP-U Uplink packet rate"
                type: str
            drop_rl_gtp_u_downlink_byte:
                description:
                - "Rate-limit Drop= GTP-U Downlink byte rate"
                type: str
            drop_rl_gtp_u_downlink_packet:
                description:
                - "Rate-limit Drop= GTP-U Downlink packet rate"
                type: str
            drop_rl_gtp_u_total_byte:
                description:
                - "Rate-limit Drop= GTP-U Total byte rate"
                type: str
            drop_rl_gtp_u_total_packet:
                description:
                - "Rate-limit Drop= GTP-U Total packet rate"
                type: str
            drop_rl_gtp_u_max_concurrent_tunnels:
                description:
                - "Rate-limit Drop= GTP-U Concurrent Tunnels"
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
            'key_name': {
                'type': 'str',
                },
            'uplink_bytes': {
                'type': 'str',
                },
            'downlink_bytes': {
                'type': 'str',
                },
            'uplink_pkts': {
                'type': 'str',
                },
            'downlink_pkts': {
                'type': 'str',
                },
            'u_uplink_bytes': {
                'type': 'str',
                },
            'u_downlink_bytes': {
                'type': 'str',
                },
            'u_uplink_pkts': {
                'type': 'str',
                },
            'u_downlink_pkts': {
                'type': 'str',
                },
            'gtp_v0_c_tunnel_created': {
                'type': 'str',
                },
            'gtp_v0_c_tunnel_half_open': {
                'type': 'str',
                },
            'gtp_v0_c_tunnel_half_closed': {
                'type': 'str',
                },
            'gtp_v0_c_tunnel_closed': {
                'type': 'str',
                },
            'gtp_v0_c_tunnel_deleted': {
                'type': 'str',
                },
            'gtp_v0_c_half_open_tunnel_closed': {
                'type': 'str',
                },
            'gtp_v1_c_tunnel_created': {
                'type': 'str',
                },
            'gtp_v1_c_tunnel_half_open': {
                'type': 'str',
                },
            'gtp_v1_c_tunnel_half_closed': {
                'type': 'str',
                },
            'gtp_v1_c_tunnel_closed': {
                'type': 'str',
                },
            'gtp_v1_c_tunnel_deleted': {
                'type': 'str',
                },
            'gtp_v1_c_half_open_tunnel_closed': {
                'type': 'str',
                },
            'gtp_v2_c_tunnel_created': {
                'type': 'str',
                },
            'gtp_v2_c_tunnel_half_open': {
                'type': 'str',
                },
            'gtp_v2_c_tunnel_half_closed': {
                'type': 'str',
                },
            'gtp_v2_c_tunnel_closed': {
                'type': 'str',
                },
            'gtp_v2_c_tunnel_deleted': {
                'type': 'str',
                },
            'gtp_v2_c_half_open_tunnel_closed': {
                'type': 'str',
                },
            'gtp_u_tunnel_created': {
                'type': 'str',
                },
            'gtp_u_tunnel_deleted': {
                'type': 'str',
                },
            'gtp_v0_c_update_pdp_resp_unsuccess': {
                'type': 'str',
                },
            'gtp_v1_c_update_pdp_resp_unsuccess': {
                'type': 'str',
                },
            'gtp_v2_c_mod_bearer_resp_unsuccess': {
                'type': 'str',
                },
            'gtp_v0_c_create_pdp_resp_unsuccess': {
                'type': 'str',
                },
            'gtp_v1_c_create_pdp_resp_unsuccess': {
                'type': 'str',
                },
            'gtp_v2_c_create_sess_resp_unsuccess': {
                'type': 'str',
                },
            'gtp_v2_c_piggyback_message': {
                'type': 'str',
                },
            'gtp_path_management_message': {
                'type': 'str',
                },
            'gtp_v0_c_tunnel_deleted_restart': {
                'type': 'str',
                },
            'gtp_v1_c_tunnel_deleted_restart': {
                'type': 'str',
                },
            'gtp_v2_c_tunnel_deleted_restart': {
                'type': 'str',
                },
            'gtp_v0_c_reserved_message_allow': {
                'type': 'str',
                },
            'gtp_v1_c_reserved_message_allow': {
                'type': 'str',
                },
            'gtp_v2_c_reserved_message_allow': {
                'type': 'str',
                },
            'gtp_v1_c_pdu_notification_request_forward': {
                'type': 'str',
                },
            'gtp_v1_c_pdu_notification_reject_request_forward': {
                'type': 'str',
                },
            'gtp_v0_c_pdu_notification_request_forward': {
                'type': 'str',
                },
            'gtp_v0_c_pdu_notification_reject_request_forward': {
                'type': 'str',
                },
            'gtp_v0_c_message_skipped_apn_filtering_no_imsi': {
                'type': 'str',
                },
            'gtp_v1_c_message_skipped_apn_filtering_no_imsi': {
                'type': 'str',
                },
            'gtp_v2_c_message_skipped_apn_filtering_no_imsi': {
                'type': 'str',
                },
            'gtp_v0_c_message_skipped_msisdn_filtering_no_msisdn': {
                'type': 'str',
                },
            'gtp_v1_c_message_skipped_msisdn_filtering_no_msisdn': {
                'type': 'str',
                },
            'gtp_v2_c_message_skipped_msisdn_filtering_no_msisdn': {
                'type': 'str',
                },
            'gtp_v0_c_packet_dummy_msisdn': {
                'type': 'str',
                },
            'gtp_v1_c_packet_dummy_msisdn': {
                'type': 'str',
                },
            'gtp_v2_c_packet_dummy_msisdn': {
                'type': 'str',
                },
            'drop_vld_gtp_v2_c_message_with_teid_zero_expected': {
                'type': 'str',
                },
            'drop_vld_gtp_v1_c_message_with_teid_zero_expected': {
                'type': 'str',
                },
            'drop_vld_gtp_v0_c_message_with_teid_zero_expected': {
                'type': 'str',
                },
            'drop_vld_reserved_field_set': {
                'type': 'str',
                },
            'drop_vld_tunnel_id_flag': {
                'type': 'str',
                },
            'drop_vld_invalid_flow_label_v0': {
                'type': 'str',
                },
            'drop_vld_invalid_teid': {
                'type': 'str',
                },
            'drop_vld_unsupported_message_type': {
                'type': 'str',
                },
            'drop_vld_out_of_state': {
                'type': 'str',
                },
            'drop_vld_mandatory_information_element': {
                'type': 'str',
                },
            'drop_vld_out_of_order_ie': {
                'type': 'str',
                },
            'drop_vld_out_of_state_ie': {
                'type': 'str',
                },
            'drop_vld_reserved_information_element': {
                'type': 'str',
                },
            'drop_vld_version_not_supported': {
                'type': 'str',
                },
            'drop_vld_message_length': {
                'type': 'str',
                },
            'drop_vld_cross_layer_correlation': {
                'type': 'str',
                },
            'drop_vld_country_code_mismatch': {
                'type': 'str',
                },
            'drop_vld_gtp_u_spoofed_source_address': {
                'type': 'str',
                },
            'drop_vld_gtp_bearer_count_exceed': {
                'type': 'str',
                },
            'drop_vld_gtp_v2_wrong_lbi_create_bearer_req': {
                'type': 'str',
                },
            'gtp_c_handover_in_progress_with_conn': {
                'type': 'str',
                },
            'drop_vld_v0_reserved_message_drop': {
                'type': 'str',
                },
            'drop_vld_v1_reserved_message_drop': {
                'type': 'str',
                },
            'drop_vld_v2_reserved_message_drop': {
                'type': 'str',
                },
            'drop_vld_invalid_pkt_len_piggyback': {
                'type': 'str',
                },
            'drop_vld_sanity_failed_piggyback': {
                'type': 'str',
                },
            'drop_vld_sequence_num_correlation': {
                'type': 'str',
                },
            'drop_vld_gtpv0_seqnum_buffer_full': {
                'type': 'str',
                },
            'drop_vld_gtpv1_seqnum_buffer_full': {
                'type': 'str',
                },
            'drop_vld_gtpv2_seqnum_buffer_full': {
                'type': 'str',
                },
            'drop_vld_gtp_invalid_imsi_len_drop': {
                'type': 'str',
                },
            'drop_vld_gtp_invalid_apn_len_drop': {
                'type': 'str',
                },
            'drop_vld_protocol_flag_unset': {
                'type': 'str',
                },
            'drop_vld_gtpv0_subscriber_attr_miss': {
                'type': 'str',
                },
            'drop_vld_gtpv1_subscriber_attr_miss': {
                'type': 'str',
                },
            'drop_vld_gtpv2_subscriber_attr_miss': {
                'type': 'str',
                },
            'drop_vld_gtp_v0_c_ie_len_exceed_msg_len': {
                'type': 'str',
                },
            'drop_vld_gtp_v1_c_ie_len_exceed_msg_len': {
                'type': 'str',
                },
            'drop_vld_gtp_v2_c_ie_len_exceed_msg_len': {
                'type': 'str',
                },
            'drop_vld_gtp_v0_c_message_length_mismatch': {
                'type': 'str',
                },
            'drop_vld_gtp_v1_c_message_length_mismatch': {
                'type': 'str',
                },
            'drop_vld_gtp_v2_c_message_length_mismatch': {
                'type': 'str',
                },
            'drop_vld_gtp_v0_c_message_dropped_apn_filtering_no_apn': {
                'type': 'str',
                },
            'drop_vld_gtp_v1_c_message_dropped_apn_filtering_no_apn': {
                'type': 'str',
                },
            'drop_vld_gtp_v2_c_message_dropped_apn_filtering_no_apn': {
                'type': 'str',
                },
            'drop_flt_message_filtering': {
                'type': 'str',
                },
            'drop_flt_apn_filtering': {
                'type': 'str',
                },
            'drop_flt_msisdn_filtering': {
                'type': 'str',
                },
            'drop_flt_rat_type_filtering': {
                'type': 'str',
                },
            'drop_flt_gtp_in_gtp': {
                'type': 'str',
                },
            'drop_rl_gtp_v0_c_agg': {
                'type': 'str',
                },
            'drop_rl_gtp_v1_c_agg': {
                'type': 'str',
                },
            'drop_rl_gtp_v2_c_agg': {
                'type': 'str',
                },
            'drop_rl_gtp_v1_c_create_pdp_request': {
                'type': 'str',
                },
            'drop_rl_gtp_v2_c_create_session_request': {
                'type': 'str',
                },
            'drop_rl_gtp_v1_c_update_pdp_request': {
                'type': 'str',
                },
            'drop_rl_gtp_v2_c_modify_bearer_request': {
                'type': 'str',
                },
            'drop_rl_gtp_u_tunnel_create': {
                'type': 'str',
                },
            'drop_rl_gtp_u_uplink_byte': {
                'type': 'str',
                },
            'drop_rl_gtp_u_uplink_packet': {
                'type': 'str',
                },
            'drop_rl_gtp_u_downlink_byte': {
                'type': 'str',
                },
            'drop_rl_gtp_u_downlink_packet': {
                'type': 'str',
                },
            'drop_rl_gtp_u_total_byte': {
                'type': 'str',
                },
            'drop_rl_gtp_u_total_packet': {
                'type': 'str',
                },
            'drop_rl_gtp_u_max_concurrent_tunnels': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/gtp/apn-prefix"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/fw/gtp/apn-prefix"

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
    payload = utils.build_json("apn-prefix", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["apn-prefix"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["apn-prefix-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["apn-prefix"]["stats"] if info != "NotFound" else info
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
