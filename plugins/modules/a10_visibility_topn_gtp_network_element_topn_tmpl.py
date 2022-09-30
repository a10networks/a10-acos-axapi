#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_visibility_topn_gtp_network_element_topn_tmpl
description:
    - Configure template for fw.gtp.network-element
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
        - "Template Name"
        type: str
        required: True
    topn_size:
        description:
        - "Congure value of N for topn"
        type: int
        required: False
    interval:
        description:
        - "'5'= 5 minutes; '15'= 15 minutes; '30'= 30 minutes; '60'= 60 minutes; 'all-
          time'= Since template is activated;"
        type: str
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
    metrics:
        description:
        - "Field metrics"
        type: dict
        required: False
        suboptions:
            uplink_bytes:
                description:
                - "Track Top-N entities for Uplink Bytes"
                type: bool
            downlink_bytes:
                description:
                - "Track Top-N entities for Downlink Bytes"
                type: bool
            uplink_pkts:
                description:
                - "Track Top-N entities for Uplink Packets"
                type: bool
            downlink_pkts:
                description:
                - "Track Top-N entities for Downlink Packets"
                type: bool
            gtp_v0_c_tunnel_created:
                description:
                - "Track Top-N entities for GTPv0-C Tunnel Created"
                type: bool
            gtp_v0_c_tunnel_half_open:
                description:
                - "Track Top-N entities for GTPv0-C Half open tunnel created"
                type: bool
            gtp_v0_c_tunnel_half_closed:
                description:
                - "Track Top-N entities for GTPv0-C Tunnel Delete Request"
                type: bool
            gtp_v0_c_tunnel_closed:
                description:
                - "Track Top-N entities for GTPv0-C Tunnel Marked Deleted"
                type: bool
            gtp_v0_c_tunnel_deleted:
                description:
                - "Track Top-N entities for GTPv0-C Tunnel Deleted"
                type: bool
            gtp_v0_c_half_open_tunnel_closed:
                description:
                - "Track Top-N entities for GTPv0-C Half open tunnel closed"
                type: bool
            gtp_v1_c_tunnel_created:
                description:
                - "Track Top-N entities for GTPv1-C Tunnel Created"
                type: bool
            gtp_v1_c_tunnel_half_open:
                description:
                - "Track Top-N entities for GTPv1-C Half open tunnel created"
                type: bool
            gtp_v1_c_tunnel_half_closed:
                description:
                - "Track Top-N entities for GTPv1-C Tunnel Delete Request"
                type: bool
            gtp_v1_c_tunnel_closed:
                description:
                - "Track Top-N entities for GTPv1-C Tunnel Marked Deleted"
                type: bool
            gtp_v1_c_tunnel_deleted:
                description:
                - "Track Top-N entities for GTPv1-C Tunnel Deleted"
                type: bool
            gtp_v1_c_half_open_tunnel_closed:
                description:
                - "Track Top-N entities for GTPv1-C Half open tunnel closed"
                type: bool
            gtp_v2_c_tunnel_created:
                description:
                - "Track Top-N entities for GTPv2-C Tunnel Created"
                type: bool
            gtp_v2_c_tunnel_half_open:
                description:
                - "Track Top-N entities for GTPv2-C Half open tunnel created"
                type: bool
            gtp_v2_c_tunnel_half_closed:
                description:
                - "Track Top-N entities for GTPv2-C Tunnel Delete Request"
                type: bool
            gtp_v2_c_tunnel_closed:
                description:
                - "Track Top-N entities for GTPv2-C Tunnel Marked Deleted"
                type: bool
            gtp_v2_c_tunnel_deleted:
                description:
                - "Track Top-N entities for GTPv2-C Tunnel Deleted"
                type: bool
            gtp_v2_c_half_open_tunnel_closed:
                description:
                - "Track Top-N entities for GTPv2-C Half open tunnel closed"
                type: bool
            gtp_u_tunnel_created:
                description:
                - "Track Top-N entities for GTP-U Tunnel Created"
                type: bool
            gtp_u_tunnel_deleted:
                description:
                - "Track Top-N entities for GTP-U Tunnel Deleted"
                type: bool
            gtp_v0_c_update_pdp_resp_unsuccess:
                description:
                - "Track Top-N entities for GTPv0-C Update PDP Context Response Unsuccessful"
                type: bool
            gtp_v1_c_update_pdp_resp_unsuccess:
                description:
                - "Track Top-N entities for GTPv1-C Update PDP Context Response Unsuccessful"
                type: bool
            gtp_v2_c_mod_bearer_resp_unsuccess:
                description:
                - "Track Top-N entities for GTPv2-C Modify Bearer Response Unsuccessful"
                type: bool
            gtp_v0_c_create_pdp_resp_unsuccess:
                description:
                - "Track Top-N entities for GTPv0-C Create PDP Context Response Unsuccessful"
                type: bool
            gtp_v1_c_create_pdp_resp_unsuccess:
                description:
                - "Track Top-N entities for GTPv1-C Create PDP Context Response Unsuccessful"
                type: bool
            gtp_v2_c_create_sess_resp_unsuccess:
                description:
                - "Track Top-N entities for GTPv2-C Create Session Response Unsuccessful"
                type: bool
            gtp_v2_c_piggyback_message:
                description:
                - "Track Top-N entities for GTPv2-C Piggyback Messages"
                type: bool
            gtp_path_management_message:
                description:
                - "Track Top-N entities for GTP Path Management Messages Received"
                type: bool
            gtp_v0_c_tunnel_deleted_restart:
                description:
                - "Track Top-N entities for GTPv0-C Tunnel Deleted with Restart/failure"
                type: bool
            gtp_v1_c_tunnel_deleted_restart:
                description:
                - "Track Top-N entities for GTPv1-C Tunnel Deleted with Restart/failure"
                type: bool
            gtp_v2_c_tunnel_deleted_restart:
                description:
                - "Track Top-N entities for GTPv2-C Tunnel Deleted with Restart/failure"
                type: bool
            gtp_v0_c_reserved_message_allow:
                description:
                - "Track Top-N entities for GTPv0-C Reserved Message Allow"
                type: bool
            gtp_v1_c_reserved_message_allow:
                description:
                - "Track Top-N entities for GTPv1-C Reserved Message Allow"
                type: bool
            gtp_v2_c_reserved_message_allow:
                description:
                - "Track Top-N entities for GTPv2-C Reserved Message Allow"
                type: bool
            drop_vld_reserved_field_set:
                description:
                - "Track Top-N entities for Validation Drop= Reserved Header Field Set"
                type: bool
            drop_vld_tunnel_id_flag:
                description:
                - "Track Top-N entities for Validation Drop= Tunnel Header Flag Not Set"
                type: bool
            drop_vld_invalid_flow_label_v0:
                description:
                - "Track Top-N entities for Validation Drop= Invalid Flow Label in GTPv0-C Header"
                type: bool
            drop_vld_invalid_teid:
                description:
                - "Track Top-N entities for Validation Drop= Invalid TEID Value"
                type: bool
            drop_vld_unsupported_message_type:
                description:
                - "Track Top-N entities for Validation Drop= Message type not supported by GTP
          Version"
                type: bool
            drop_vld_out_of_state:
                description:
                - "Track Top-N entities for Validation Drop= Out Of State GTP Message"
                type: bool
            drop_vld_mandatory_information_element:
                description:
                - "Track Top-N entities for Validation Drop= Mandatory IE Not Present"
                type: bool
            drop_vld_out_of_order_ie:
                description:
                - "Track Top-N entities for Validation Drop= GTPv1-C Message Out of Order IE"
                type: bool
            drop_vld_out_of_state_ie:
                description:
                - "Track Top-N entities for Validation Drop= Unexpected IE Present in Message"
                type: bool
            drop_vld_reserved_information_element:
                description:
                - "Track Top-N entities for Validation Drop= Reserved IE Field Present"
                type: bool
            drop_vld_version_not_supported:
                description:
                - "Track Top-N entities for Validation Drop= Invalid GTP version"
                type: bool
            drop_vld_message_length:
                description:
                - "Track Top-N entities for Validation Drop= Message Length Exceeded"
                type: bool
            drop_vld_cross_layer_correlation:
                description:
                - "Track Top-N entities for Validation Drop= Cross Layer IP Address Mismatch"
                type: bool
            drop_vld_country_code_mismatch:
                description:
                - "Track Top-N entities for Validation Drop= Country Code Mismatch in IMSI and
          MSISDN"
                type: bool
            drop_vld_gtp_u_spoofed_source_address:
                description:
                - "Track Top-N entities for Validation Drop= GTP-U IP Address Spoofed"
                type: bool
            drop_vld_gtp_bearer_count_exceed:
                description:
                - "Track Top-N entities for Validation Drop= GTP Bearer count exceeded max (11)"
                type: bool
            drop_vld_gtp_v2_wrong_lbi_create_bearer:
                description:
                - "Track Top-N entities for Validation Drop= GTPV2-C Wrong LBI in Create Bearer
          Request"
                type: bool
            gtp_c_handover_in_progress_with_conn:
                description:
                - "Track Top-N entities for GTP-C matching a conn with Handover In Progress"
                type: bool
            drop_vld_invalid_pkt_len_piggyback:
                description:
                - "Track Top-N entities for Validation Drop= Piggyback message invalid packet
          length"
                type: bool
            drop_vld_sanity_failed_piggyback:
                description:
                - "Track Top-N entities for Validation Drop= piggyback message anomaly failed"
                type: bool
            drop_vld_sequence_num_correlation:
                description:
                - "Track Top-N entities for Validation Drop= GTP-C Sequence number Mismatch"
                type: bool
            drop_vld_gtpv0_seqnum_buffer_full:
                description:
                - "Track Top-N entities for Validation Drop= GTPV0-C conn Sequence number Buffer
          Full"
                type: bool
            drop_vld_gtpv1_seqnum_buffer_full:
                description:
                - "Track Top-N entities for Validation Drop= GTPV1-C conn Sequence number Buffer
          Full"
                type: bool
            drop_vld_gtpv2_seqnum_buffer_full:
                description:
                - "Track Top-N entities for Validation Drop= GTPV2-C conn Sequence number Buffer
          Full"
                type: bool
            drop_vld_gtp_invalid_imsi_len_drop:
                description:
                - "Track Top-N entities for Validation Drop= GTP-C Invalid IMSI Length Drop"
                type: bool
            drop_vld_gtp_invalid_apn_len_drop:
                description:
                - "Track Top-N entities for Validation Drop= GTP-C Invalid APN Length Drop"
                type: bool
            drop_vld_protocol_flag_unset:
                description:
                - "Track Top-N entities for Validation Drop= Protocol flag in Header Field not Set"
                type: bool
            drop_flt_message_filtering:
                description:
                - "Track Top-N entities for Filtering Drop= Message Type Not Permitted on
          Interface"
                type: bool
            drop_flt_apn_filtering:
                description:
                - "Track Top-N entities for Filtering Drop= APN IMSI Filtering"
                type: bool
            drop_flt_msisdn_filtering:
                description:
                - "Track Top-N entities for Filtering Drop= MSISDN Filtering"
                type: bool
            drop_flt_rat_type_filtering:
                description:
                - "Track Top-N entities for Filtering Drop= RAT Type Filtering"
                type: bool
            drop_flt_gtp_in_gtp:
                description:
                - "Track Top-N entities for Filtering Drop= GTP in GTP Tunnel Present"
                type: bool
            drop_rl_gtp_v0_c_agg:
                description:
                - "Track Top-N entities for Rate-limit Drop= Maximum GTPv0-C messages rate"
                type: bool
            drop_rl_gtp_v1_c_agg:
                description:
                - "Track Top-N entities for Rate-limit Drop= Maximum GTPv1-C messages rate"
                type: bool
            drop_rl_gtp_v2_c_agg:
                description:
                - "Track Top-N entities for Rate-limit Drop= Maximum GTPv2-C messages rate"
                type: bool
            drop_rl_gtp_v1_c_create_pdp_request:
                description:
                - "Track Top-N entities for Rate-limit Drop= GTPv1-C Create PDP Req rate"
                type: bool
            drop_rl_gtp_v2_c_create_session_request:
                description:
                - "Track Top-N entities for Rate-limit Drop= GTPv2-C Create Session Req rate"
                type: bool
            drop_rl_gtp_v1_c_update_pdp_request:
                description:
                - "Track Top-N entities for Rate-limit Drop= GTPv1-C Update PDP Req rate"
                type: bool
            drop_rl_gtp_v2_c_modify_bearer_request:
                description:
                - "Track Top-N entities for Rate-limit Drop= GTPv2-C Modify Bearer Req rate"
                type: bool
            drop_rl_gtp_u_tunnel_create:
                description:
                - "Track Top-N entities for Rate-limit Drop= GTP-U Tunnel Creation rate"
                type: bool
            drop_rl_gtp_u_uplink_byte:
                description:
                - "Track Top-N entities for Rate-limit Drop= GTP-U Uplink byte rate"
                type: bool
            drop_rl_gtp_u_uplink_packet:
                description:
                - "Track Top-N entities for Rate-limit Drop= GTP-U Uplink packet rate"
                type: bool
            drop_rl_gtp_u_downlink_byte:
                description:
                - "Track Top-N entities for Rate-limit Drop= GTP-U Downlink byte rate"
                type: bool
            drop_rl_gtp_u_downlink_packet:
                description:
                - "Track Top-N entities for Rate-limit Drop= GTP-U Downlink packet rate"
                type: bool
            drop_rl_gtp_u_total_byte:
                description:
                - "Track Top-N entities for Rate-limit Drop= GTP-U Total byte rate"
                type: bool
            drop_rl_gtp_u_total_packet:
                description:
                - "Track Top-N entities for Rate-limit Drop= GTP-U Total packet rate"
                type: bool
            drop_rl_gtp_u_max_concurrent_tunnels:
                description:
                - "Track Top-N entities for Rate-limit Drop= GTP-U Concurrent Tunnels"
                type: bool
            uuid:
                description:
                - "uuid of the object"
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
    "interval",
    "metrics",
    "name",
    "topn_size",
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
        'topn_size': {
            'type': 'int',
        },
        'interval': {
            'type': 'str',
            'choices': ['5', '15', '30', '60', 'all-time']
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'metrics': {
            'type': 'dict',
            'uplink_bytes': {
                'type': 'bool',
            },
            'downlink_bytes': {
                'type': 'bool',
            },
            'uplink_pkts': {
                'type': 'bool',
            },
            'downlink_pkts': {
                'type': 'bool',
            },
            'gtp_v0_c_tunnel_created': {
                'type': 'bool',
            },
            'gtp_v0_c_tunnel_half_open': {
                'type': 'bool',
            },
            'gtp_v0_c_tunnel_half_closed': {
                'type': 'bool',
            },
            'gtp_v0_c_tunnel_closed': {
                'type': 'bool',
            },
            'gtp_v0_c_tunnel_deleted': {
                'type': 'bool',
            },
            'gtp_v0_c_half_open_tunnel_closed': {
                'type': 'bool',
            },
            'gtp_v1_c_tunnel_created': {
                'type': 'bool',
            },
            'gtp_v1_c_tunnel_half_open': {
                'type': 'bool',
            },
            'gtp_v1_c_tunnel_half_closed': {
                'type': 'bool',
            },
            'gtp_v1_c_tunnel_closed': {
                'type': 'bool',
            },
            'gtp_v1_c_tunnel_deleted': {
                'type': 'bool',
            },
            'gtp_v1_c_half_open_tunnel_closed': {
                'type': 'bool',
            },
            'gtp_v2_c_tunnel_created': {
                'type': 'bool',
            },
            'gtp_v2_c_tunnel_half_open': {
                'type': 'bool',
            },
            'gtp_v2_c_tunnel_half_closed': {
                'type': 'bool',
            },
            'gtp_v2_c_tunnel_closed': {
                'type': 'bool',
            },
            'gtp_v2_c_tunnel_deleted': {
                'type': 'bool',
            },
            'gtp_v2_c_half_open_tunnel_closed': {
                'type': 'bool',
            },
            'gtp_u_tunnel_created': {
                'type': 'bool',
            },
            'gtp_u_tunnel_deleted': {
                'type': 'bool',
            },
            'gtp_v0_c_update_pdp_resp_unsuccess': {
                'type': 'bool',
            },
            'gtp_v1_c_update_pdp_resp_unsuccess': {
                'type': 'bool',
            },
            'gtp_v2_c_mod_bearer_resp_unsuccess': {
                'type': 'bool',
            },
            'gtp_v0_c_create_pdp_resp_unsuccess': {
                'type': 'bool',
            },
            'gtp_v1_c_create_pdp_resp_unsuccess': {
                'type': 'bool',
            },
            'gtp_v2_c_create_sess_resp_unsuccess': {
                'type': 'bool',
            },
            'gtp_v2_c_piggyback_message': {
                'type': 'bool',
            },
            'gtp_path_management_message': {
                'type': 'bool',
            },
            'gtp_v0_c_tunnel_deleted_restart': {
                'type': 'bool',
            },
            'gtp_v1_c_tunnel_deleted_restart': {
                'type': 'bool',
            },
            'gtp_v2_c_tunnel_deleted_restart': {
                'type': 'bool',
            },
            'gtp_v0_c_reserved_message_allow': {
                'type': 'bool',
            },
            'gtp_v1_c_reserved_message_allow': {
                'type': 'bool',
            },
            'gtp_v2_c_reserved_message_allow': {
                'type': 'bool',
            },
            'drop_vld_reserved_field_set': {
                'type': 'bool',
            },
            'drop_vld_tunnel_id_flag': {
                'type': 'bool',
            },
            'drop_vld_invalid_flow_label_v0': {
                'type': 'bool',
            },
            'drop_vld_invalid_teid': {
                'type': 'bool',
            },
            'drop_vld_unsupported_message_type': {
                'type': 'bool',
            },
            'drop_vld_out_of_state': {
                'type': 'bool',
            },
            'drop_vld_mandatory_information_element': {
                'type': 'bool',
            },
            'drop_vld_out_of_order_ie': {
                'type': 'bool',
            },
            'drop_vld_out_of_state_ie': {
                'type': 'bool',
            },
            'drop_vld_reserved_information_element': {
                'type': 'bool',
            },
            'drop_vld_version_not_supported': {
                'type': 'bool',
            },
            'drop_vld_message_length': {
                'type': 'bool',
            },
            'drop_vld_cross_layer_correlation': {
                'type': 'bool',
            },
            'drop_vld_country_code_mismatch': {
                'type': 'bool',
            },
            'drop_vld_gtp_u_spoofed_source_address': {
                'type': 'bool',
            },
            'drop_vld_gtp_bearer_count_exceed': {
                'type': 'bool',
            },
            'drop_vld_gtp_v2_wrong_lbi_create_bearer': {
                'type': 'bool',
            },
            'gtp_c_handover_in_progress_with_conn': {
                'type': 'bool',
            },
            'drop_vld_invalid_pkt_len_piggyback': {
                'type': 'bool',
            },
            'drop_vld_sanity_failed_piggyback': {
                'type': 'bool',
            },
            'drop_vld_sequence_num_correlation': {
                'type': 'bool',
            },
            'drop_vld_gtpv0_seqnum_buffer_full': {
                'type': 'bool',
            },
            'drop_vld_gtpv1_seqnum_buffer_full': {
                'type': 'bool',
            },
            'drop_vld_gtpv2_seqnum_buffer_full': {
                'type': 'bool',
            },
            'drop_vld_gtp_invalid_imsi_len_drop': {
                'type': 'bool',
            },
            'drop_vld_gtp_invalid_apn_len_drop': {
                'type': 'bool',
            },
            'drop_vld_protocol_flag_unset': {
                'type': 'bool',
            },
            'drop_flt_message_filtering': {
                'type': 'bool',
            },
            'drop_flt_apn_filtering': {
                'type': 'bool',
            },
            'drop_flt_msisdn_filtering': {
                'type': 'bool',
            },
            'drop_flt_rat_type_filtering': {
                'type': 'bool',
            },
            'drop_flt_gtp_in_gtp': {
                'type': 'bool',
            },
            'drop_rl_gtp_v0_c_agg': {
                'type': 'bool',
            },
            'drop_rl_gtp_v1_c_agg': {
                'type': 'bool',
            },
            'drop_rl_gtp_v2_c_agg': {
                'type': 'bool',
            },
            'drop_rl_gtp_v1_c_create_pdp_request': {
                'type': 'bool',
            },
            'drop_rl_gtp_v2_c_create_session_request': {
                'type': 'bool',
            },
            'drop_rl_gtp_v1_c_update_pdp_request': {
                'type': 'bool',
            },
            'drop_rl_gtp_v2_c_modify_bearer_request': {
                'type': 'bool',
            },
            'drop_rl_gtp_u_tunnel_create': {
                'type': 'bool',
            },
            'drop_rl_gtp_u_uplink_byte': {
                'type': 'bool',
            },
            'drop_rl_gtp_u_uplink_packet': {
                'type': 'bool',
            },
            'drop_rl_gtp_u_downlink_byte': {
                'type': 'bool',
            },
            'drop_rl_gtp_u_downlink_packet': {
                'type': 'bool',
            },
            'drop_rl_gtp_u_total_byte': {
                'type': 'bool',
            },
            'drop_rl_gtp_u_total_packet': {
                'type': 'bool',
            },
            'drop_rl_gtp_u_max_concurrent_tunnels': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/topn/gtp-network-element-topn-tmpl/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/topn/gtp-network-element-topn-tmpl/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["gtp-network-element-topn-tmpl"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["gtp-network-element-topn-tmpl"].get(k) != v:
            change_results["changed"] = True
            config_changes["gtp-network-element-topn-tmpl"][k] = v

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
    payload = utils.build_json("gtp-network-element-topn-tmpl", module.params,
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
                    "gtp-network-element-topn-tmpl"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "gtp-network-element-topn-tmpl-list"] if info != "NotFound" else info
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
