#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_vrrp_a_state
description:
    - HA VRRP-A Global Commands
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
                - "'all'= all; 'sync_pkt_tx_counter'= Conn Sync Sent counter;
          'sync_pkt_rcv_counter'= Conn Sync Received counter; 'sync_rx_create_counter'=
          Conn Sync Create Session Received counter; 'sync_rx_del_counter'= Conn Sync Del
          Session Received counter; 'sync_rx_update_age_counter'= Conn Sync Update Age
          Received counter; 'sync_tx_create_counter'= Conn Sync Create Session Sent
          counter; 'sync_tx_del_counter'= Conn Sync Del Session Sent counter;
          'sync_tx_update_age_counter'= Conn Sync Update Age Sent counter;
          'sync_rx_persist_create_counter'= Conn Sync Create Persist Session Pkts
          Received counter; 'sync_rx_persist_del_counter'= Conn Sync Delete Persist
          Session Pkts Received counter; 'sync_rx_persist_update_age_counter'= Conn Sync
          Update Persist Age Pkts Received counter; 'sync_tx_persist_create_counter'=
          Conn Sync Create Persist Session Pkts Sent counter;
          'sync_tx_persist_del_counter'= Conn Sync Delete Persist Session Pkts Sent
          counter; 'sync_tx_persist_update_age_counter'= Conn Sync Update Persist Age
          Pkts Sent counter; 'query_pkt_tx_counter'= Conn Query sent counter;
          'query_pkt_rcv_counter'= Conn Query Received counter;
          'sync_tx_smp_radius_table_counter'= Conn Sync Update LSN RADIUS Sent counter;
          'sync_rx_smp_radius_table_counter'= Conn Sync Update LSN RADIUS Received
          counter; 'query_tx_max_packed'= Max Query Msg Per Packet;
          'query_tx_min_packed'= Min Query Msg Per Packet;
          'query_pkt_invalid_idx_counter'= Conn Query Invalid Interface;
          'query_tx_get_buff_failed'= Conn Query Get Buff Failure;
          'query_rx_zero_info_counter'= Conn Query Packet Empty;
          'query_rx_full_info_counter'= Conn Query Packet Full; 'query_rx_unk_counter'=
          Conn Query Unknown Type; 'sync_pkt_invalid_idx_counter'= Conn Sync Invalid
          Interface; 'sync_tx_get_buff_failed'= Conn Sync Get Buff Failure;
          'sync_tx_total_info_counter'= Conn Sync Total Info Pkts Sent counter;
          'sync_tx_create_ext_bit_counter'= Conn Sync Create with Ext Sent counter;
          'sync_tx_update_seqnos_counter'= Conn Sync Update Seq Num Sent counter;
          'sync_tx_min_packed'= Max Sync Msg Per Packet; 'sync_tx_max_packed'= Min Sync
          Msg Per Packet; 'sync_rx_len_invalid'= Conn Sync Length Invalid;
          'sync_persist_rx_len_invalid'= Persist Conn Sync Length Invalid;
          'sync_persist_rx_proto_not_supported'= Persist Conn Sync Protocol Invalid;
          'sync_persist_rx_type_invalid'= Persist Conn Sync Type Invalid;
          'sync_persist_rx_cannot_process_mandatory'= Persist Conn Sync Process Mandatory
          Invalid; 'sync_persist_rx_ext_bit_process_error'= Persist Conn Sync Proc Ext
          Bit Failure; 'sync_persist_rx_no_such_vport'= Persist Conn Sync Virt Port Not
          Found; 'sync_persist_rx_vporttype_not_supported'= Persist Conn Sync Virt Port
          Type Invalid; 'sync_persist_rx_no_such_rport'= Persist Conn Sync Real Port Not
          Found; 'sync_persist_rx_no_such_sg_group'= Persist Conn Sync No Service Group
          Found; 'sync_persist_rx_no_sg_group_info'= Persist Conn Sync No Service Group
          Info Found; 'sync_persist_rx_conn_get_failed'= Persist Conn Sync Get Conn
          Failure; 'sync_rx_no_such_vport'= Conn Sync Virt Port Not Found;
          'sync_rx_no_such_rport'= Conn Sync Real Port Not Found;
          'sync_rx_cannot_process_mandatory'= Conn Sync Process Mandatory Invalid;
          'sync_rx_ext_bit_process_error'= Conn Sync Proc Ext Bit Failure;
          'sync_rx_create_ext_bit_counter'= Conn Sync Create with Ext Received counter;
          'sync_rx_conn_exists'= Conn Sync Create Conn Exists; 'sync_rx_conn_get_failed'=
          Conn Sync Get Conn Failure; 'sync_rx_proto_not_supported'= Conn Sync Protocol
          Invalid; 'sync_rx_no_dst_for_vport_inline'= Conn Sync 'dst' not found for vport
          inline; 'sync_rx_no_such_nat_pool'= Conn Sync NAT Pool Error;
          'sync_rx_no_such_sg_node'= Conn Sync no SG node found;
          'sync_rx_del_no_such_session'= Conn Sync Del Conn not Found;
          'sync_rx_type_invalid'= Conn Sync Type Invalid; 'sync_rx_zero_info_counter'=
          Conn Sync Packet Empty; 'sync_rx_dcmsg_counter'= Conn Sync forward CPU;
          'sync_rx_total_info_counter'= Conn Sync Total Info Pkts Received counter;
          'sync_rx_update_seqnos_counter'= Conn Sync Update Seq Num Received counter;
          'sync_rx_unk_counter'= Conn Sync Unknown Type; 'sync_rx_apptype_not_supported'=
          Conn Sync App Type Invalid; 'sync_query_dcmsg_counter'= Conn Sync query forward
          CPU; 'sync_get_buff_failed_rt'= Conn Sync Get Buff Failure No Route;
          'sync_get_buff_failed_port'= Conn Sync Get Buff Failure Wrong Port;
          'sync_rx_lsn_create_sby'= Conn Sync LSN Create Standby;
          'sync_rx_nat_create_sby'= Conn Sync NAT Create Standby;
          'sync_rx_nat_alloc_sby'= Conn Sync NAT Alloc Standby; 'sync_rx_insert_tuple'=
          Conn Sync Insert Tuple; 'sync_rx_sfw'= Conn Sync SFW;
          'sync_rx_create_static_sby'= Conn Sync Create Static Standby;
          'sync_rx_ext_pptp'= Conn Sync Ext PPTP; 'sync_rx_ext_rtsp'= Conn Sync Ext RTSP;
          'sync_rx_reserve_ha'= Conn Sync Reserve HA Conn; 'sync_rx_seq_deltas'= Conn
          Sync Seq Deltas Failure; 'sync_rx_ftp_control'= Conn Sync FTP Control Failure;
          'sync_rx_ext_lsn_acl'= Conn Sync LSN ACL Failure;
          'sync_rx_ext_lsn_ac_idle_timeout'= Conn Sync LSN ACL Idle Timeout Failure;
          'sync_rx_ext_sip_alg'= Conn Sync SIP TCP ALG Failure; 'sync_rx_ext_h323_alg'=
          Conn Sync H323 TCP ALG Failure; 'sync_rx_ext_nat_mac'= Conn Sync NAT MAC
          Failure; 'sync_tx_lsn_fullcone'= Conn Sync Update LSN Fullcone Sent counter;
          'sync_rx_lsn_fullcone'= Conn Sync Update LSN Fullcone Received counter;
          'sync_err_lsn_fullcone'= Conn Sync LSN Fullcone Failure;
          'sync_tx_update_sctp_conn_addr'= Update SCTP Addresses Sent;
          'sync_rx_update_sctp_conn_addr'= Update SCTP Addresses Received;
          'sync_rx_ext_nat_alg_tcp_info'= Conn Sync NAT ALG TCP Information;
          'sync_rx_ext_dcfw_rule_id'= Conn Sync FIREWALL session rule ID information
          Failure; 'sync_rx_ext_dcfw_log'= Conn Sync FIREWALL session logging information
          Failure; 'sync_rx_estab_counter'= Conn Sync rcv established state;
          'sync_tx_estab_counter'= Conn Sync send established state;
          'sync_rx_zone_failure_counter'= Conn Sync Zone Failure;
          'sync_rx_ext_fw_http_logging'= FW HTTP Logging Sync Failures;
          'sync_rx_ext_dcfw_rule_idle_timeout'= Conn Sync FIREWALL session rule idle
          timeout information Failure; 'sync_rx_ext_fw_gtp_info'= FW GTP Info Received;
          'sync_rx_not_expect_sync_pkt'= unexpected session sync packets;
          'sync_rx_ext_fw_apps'= Conn Sync FIREWALL application information Failure;
          'sync_tx_mon_entity'= Acos Monitoring Entities Sync Messages Sent;
          'sync_rx_mon_entity'= Acos monitoring Entities Sync Messages Received;
          'sync_rx_ext_fw_gtp_log_info'= FW GTP Log Info Received;
          'sync_rx_ddos_drop_counter'= Conn Sync receive ddos protect packet;
          'sync_rx_invalid_sync_packet_counter'= Conn Sync receive invalid packet;
          'sync_rx_bad_protocol_counter'= Conn Sync receive packet with bad protocol;
          'sync_rx_no_vgrp_counter'= Conn Sync receive packet with non-existing group;
          'sync_rx_by_inactive_peer_counter'= Conn Sync receive packet by inactive peer;
          'sync_rx_smp_create_counter'= Sync Create SMP Session Pkts Received counter;
          'sync_rx_smp_delete_counter'= Sync Delete SMP Session Pkts Received counter;
          'sync_rx_smp_update_counter'= Sync Update SMP Session Pkts Received counter;
          'sync_tx_smp_create_counter'= Sync Create SMP Session Pkts Sent counter;
          'sync_tx_smp_delete_counter'= Sync Delete SMP Session Pkts Sent counter;
          'sync_tx_smp_update_counter'= Sync Update SMP Session Pkts Sent counter;
          'sync_rx_smp_clear_counter'= Sync Clear SMP Session Pkts Received counter;
          'sync_tx_smp_clear_counter'= Sync Clear SMP Session Pkts Sent counter;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            sync_pkt_tx_counter:
                description:
                - "Conn Sync Sent counter"
                type: str
            sync_pkt_rcv_counter:
                description:
                - "Conn Sync Received counter"
                type: str
            sync_rx_create_counter:
                description:
                - "Conn Sync Create Session Received counter"
                type: str
            sync_rx_del_counter:
                description:
                - "Conn Sync Del Session Received counter"
                type: str
            sync_rx_update_age_counter:
                description:
                - "Conn Sync Update Age Received counter"
                type: str
            sync_tx_create_counter:
                description:
                - "Conn Sync Create Session Sent counter"
                type: str
            sync_tx_del_counter:
                description:
                - "Conn Sync Del Session Sent counter"
                type: str
            sync_tx_update_age_counter:
                description:
                - "Conn Sync Update Age Sent counter"
                type: str
            sync_rx_persist_create_counter:
                description:
                - "Conn Sync Create Persist Session Pkts Received counter"
                type: str
            sync_rx_persist_del_counter:
                description:
                - "Conn Sync Delete Persist Session Pkts Received counter"
                type: str
            sync_rx_persist_update_age_counter:
                description:
                - "Conn Sync Update Persist Age Pkts Received counter"
                type: str
            sync_tx_persist_create_counter:
                description:
                - "Conn Sync Create Persist Session Pkts Sent counter"
                type: str
            sync_tx_persist_del_counter:
                description:
                - "Conn Sync Delete Persist Session Pkts Sent counter"
                type: str
            sync_tx_persist_update_age_counter:
                description:
                - "Conn Sync Update Persist Age Pkts Sent counter"
                type: str
            query_pkt_tx_counter:
                description:
                - "Conn Query sent counter"
                type: str
            query_pkt_rcv_counter:
                description:
                - "Conn Query Received counter"
                type: str
            sync_tx_smp_radius_table_counter:
                description:
                - "Conn Sync Update LSN RADIUS Sent counter"
                type: str
            sync_rx_smp_radius_table_counter:
                description:
                - "Conn Sync Update LSN RADIUS Received counter"
                type: str
            query_tx_max_packed:
                description:
                - "Max Query Msg Per Packet"
                type: str
            query_tx_min_packed:
                description:
                - "Min Query Msg Per Packet"
                type: str
            query_pkt_invalid_idx_counter:
                description:
                - "Conn Query Invalid Interface"
                type: str
            query_tx_get_buff_failed:
                description:
                - "Conn Query Get Buff Failure"
                type: str
            query_rx_zero_info_counter:
                description:
                - "Conn Query Packet Empty"
                type: str
            query_rx_full_info_counter:
                description:
                - "Conn Query Packet Full"
                type: str
            query_rx_unk_counter:
                description:
                - "Conn Query Unknown Type"
                type: str
            sync_pkt_invalid_idx_counter:
                description:
                - "Conn Sync Invalid Interface"
                type: str
            sync_tx_get_buff_failed:
                description:
                - "Conn Sync Get Buff Failure"
                type: str
            sync_tx_total_info_counter:
                description:
                - "Conn Sync Total Info Pkts Sent counter"
                type: str
            sync_tx_create_ext_bit_counter:
                description:
                - "Conn Sync Create with Ext Sent counter"
                type: str
            sync_tx_update_seqnos_counter:
                description:
                - "Conn Sync Update Seq Num Sent counter"
                type: str
            sync_tx_min_packed:
                description:
                - "Max Sync Msg Per Packet"
                type: str
            sync_tx_max_packed:
                description:
                - "Min Sync Msg Per Packet"
                type: str
            sync_rx_len_invalid:
                description:
                - "Conn Sync Length Invalid"
                type: str
            sync_persist_rx_len_invalid:
                description:
                - "Persist Conn Sync Length Invalid"
                type: str
            sync_persist_rx_proto_not_supported:
                description:
                - "Persist Conn Sync Protocol Invalid"
                type: str
            sync_persist_rx_type_invalid:
                description:
                - "Persist Conn Sync Type Invalid"
                type: str
            sync_persist_rx_cannot_process_mandatory:
                description:
                - "Persist Conn Sync Process Mandatory Invalid"
                type: str
            sync_persist_rx_ext_bit_process_error:
                description:
                - "Persist Conn Sync Proc Ext Bit Failure"
                type: str
            sync_persist_rx_no_such_vport:
                description:
                - "Persist Conn Sync Virt Port Not Found"
                type: str
            sync_persist_rx_vporttype_not_supported:
                description:
                - "Persist Conn Sync Virt Port Type Invalid"
                type: str
            sync_persist_rx_no_such_rport:
                description:
                - "Persist Conn Sync Real Port Not Found"
                type: str
            sync_persist_rx_no_such_sg_group:
                description:
                - "Persist Conn Sync No Service Group Found"
                type: str
            sync_persist_rx_no_sg_group_info:
                description:
                - "Persist Conn Sync No Service Group Info Found"
                type: str
            sync_persist_rx_conn_get_failed:
                description:
                - "Persist Conn Sync Get Conn Failure"
                type: str
            sync_rx_no_such_vport:
                description:
                - "Conn Sync Virt Port Not Found"
                type: str
            sync_rx_no_such_rport:
                description:
                - "Conn Sync Real Port Not Found"
                type: str
            sync_rx_cannot_process_mandatory:
                description:
                - "Conn Sync Process Mandatory Invalid"
                type: str
            sync_rx_ext_bit_process_error:
                description:
                - "Conn Sync Proc Ext Bit Failure"
                type: str
            sync_rx_create_ext_bit_counter:
                description:
                - "Conn Sync Create with Ext Received counter"
                type: str
            sync_rx_conn_exists:
                description:
                - "Conn Sync Create Conn Exists"
                type: str
            sync_rx_conn_get_failed:
                description:
                - "Conn Sync Get Conn Failure"
                type: str
            sync_rx_proto_not_supported:
                description:
                - "Conn Sync Protocol Invalid"
                type: str
            sync_rx_no_dst_for_vport_inline:
                description:
                - "Conn Sync 'dst' not found for vport inline"
                type: str
            sync_rx_no_such_nat_pool:
                description:
                - "Conn Sync NAT Pool Error"
                type: str
            sync_rx_no_such_sg_node:
                description:
                - "Conn Sync no SG node found"
                type: str
            sync_rx_del_no_such_session:
                description:
                - "Conn Sync Del Conn not Found"
                type: str
            sync_rx_type_invalid:
                description:
                - "Conn Sync Type Invalid"
                type: str
            sync_rx_zero_info_counter:
                description:
                - "Conn Sync Packet Empty"
                type: str
            sync_rx_dcmsg_counter:
                description:
                - "Conn Sync forward CPU"
                type: str
            sync_rx_total_info_counter:
                description:
                - "Conn Sync Total Info Pkts Received counter"
                type: str
            sync_rx_update_seqnos_counter:
                description:
                - "Conn Sync Update Seq Num Received counter"
                type: str
            sync_rx_unk_counter:
                description:
                - "Conn Sync Unknown Type"
                type: str
            sync_rx_apptype_not_supported:
                description:
                - "Conn Sync App Type Invalid"
                type: str
            sync_query_dcmsg_counter:
                description:
                - "Conn Sync query forward CPU"
                type: str
            sync_get_buff_failed_rt:
                description:
                - "Conn Sync Get Buff Failure No Route"
                type: str
            sync_get_buff_failed_port:
                description:
                - "Conn Sync Get Buff Failure Wrong Port"
                type: str
            sync_rx_lsn_create_sby:
                description:
                - "Conn Sync LSN Create Standby"
                type: str
            sync_rx_nat_create_sby:
                description:
                - "Conn Sync NAT Create Standby"
                type: str
            sync_rx_nat_alloc_sby:
                description:
                - "Conn Sync NAT Alloc Standby"
                type: str
            sync_rx_insert_tuple:
                description:
                - "Conn Sync Insert Tuple"
                type: str
            sync_rx_sfw:
                description:
                - "Conn Sync SFW"
                type: str
            sync_rx_create_static_sby:
                description:
                - "Conn Sync Create Static Standby"
                type: str
            sync_rx_ext_pptp:
                description:
                - "Conn Sync Ext PPTP"
                type: str
            sync_rx_ext_rtsp:
                description:
                - "Conn Sync Ext RTSP"
                type: str
            sync_rx_reserve_ha:
                description:
                - "Conn Sync Reserve HA Conn"
                type: str
            sync_rx_seq_deltas:
                description:
                - "Conn Sync Seq Deltas Failure"
                type: str
            sync_rx_ftp_control:
                description:
                - "Conn Sync FTP Control Failure"
                type: str
            sync_rx_ext_lsn_acl:
                description:
                - "Conn Sync LSN ACL Failure"
                type: str
            sync_rx_ext_lsn_ac_idle_timeout:
                description:
                - "Conn Sync LSN ACL Idle Timeout Failure"
                type: str
            sync_rx_ext_sip_alg:
                description:
                - "Conn Sync SIP TCP ALG Failure"
                type: str
            sync_rx_ext_h323_alg:
                description:
                - "Conn Sync H323 TCP ALG Failure"
                type: str
            sync_rx_ext_nat_mac:
                description:
                - "Conn Sync NAT MAC Failure"
                type: str
            sync_tx_lsn_fullcone:
                description:
                - "Conn Sync Update LSN Fullcone Sent counter"
                type: str
            sync_rx_lsn_fullcone:
                description:
                - "Conn Sync Update LSN Fullcone Received counter"
                type: str
            sync_err_lsn_fullcone:
                description:
                - "Conn Sync LSN Fullcone Failure"
                type: str
            sync_tx_update_sctp_conn_addr:
                description:
                - "Update SCTP Addresses Sent"
                type: str
            sync_rx_update_sctp_conn_addr:
                description:
                - "Update SCTP Addresses Received"
                type: str
            sync_rx_ext_nat_alg_tcp_info:
                description:
                - "Conn Sync NAT ALG TCP Information"
                type: str
            sync_rx_ext_dcfw_rule_id:
                description:
                - "Conn Sync FIREWALL session rule ID information Failure"
                type: str
            sync_rx_ext_dcfw_log:
                description:
                - "Conn Sync FIREWALL session logging information Failure"
                type: str
            sync_rx_estab_counter:
                description:
                - "Conn Sync rcv established state"
                type: str
            sync_tx_estab_counter:
                description:
                - "Conn Sync send established state"
                type: str
            sync_rx_zone_failure_counter:
                description:
                - "Conn Sync Zone Failure"
                type: str
            sync_rx_ext_fw_http_logging:
                description:
                - "FW HTTP Logging Sync Failures"
                type: str
            sync_rx_ext_dcfw_rule_idle_timeout:
                description:
                - "Conn Sync FIREWALL session rule idle timeout information Failure"
                type: str
            sync_rx_ext_fw_gtp_info:
                description:
                - "FW GTP Info Received"
                type: str
            sync_rx_not_expect_sync_pkt:
                description:
                - "unexpected session sync packets"
                type: str
            sync_rx_ext_fw_apps:
                description:
                - "Conn Sync FIREWALL application information Failure"
                type: str
            sync_tx_mon_entity:
                description:
                - "Acos Monitoring Entities Sync Messages Sent"
                type: str
            sync_rx_mon_entity:
                description:
                - "Acos monitoring Entities Sync Messages Received"
                type: str
            sync_rx_ext_fw_gtp_log_info:
                description:
                - "FW GTP Log Info Received"
                type: str
            sync_rx_ddos_drop_counter:
                description:
                - "Conn Sync receive ddos protect packet"
                type: str
            sync_rx_invalid_sync_packet_counter:
                description:
                - "Conn Sync receive invalid packet"
                type: str
            sync_rx_bad_protocol_counter:
                description:
                - "Conn Sync receive packet with bad protocol"
                type: str
            sync_rx_no_vgrp_counter:
                description:
                - "Conn Sync receive packet with non-existing group"
                type: str
            sync_rx_by_inactive_peer_counter:
                description:
                - "Conn Sync receive packet by inactive peer"
                type: str
            sync_rx_smp_create_counter:
                description:
                - "Sync Create SMP Session Pkts Received counter"
                type: str
            sync_rx_smp_delete_counter:
                description:
                - "Sync Delete SMP Session Pkts Received counter"
                type: str
            sync_rx_smp_update_counter:
                description:
                - "Sync Update SMP Session Pkts Received counter"
                type: str
            sync_tx_smp_create_counter:
                description:
                - "Sync Create SMP Session Pkts Sent counter"
                type: str
            sync_tx_smp_delete_counter:
                description:
                - "Sync Delete SMP Session Pkts Sent counter"
                type: str
            sync_tx_smp_update_counter:
                description:
                - "Sync Update SMP Session Pkts Sent counter"
                type: str
            sync_rx_smp_clear_counter:
                description:
                - "Sync Clear SMP Session Pkts Received counter"
                type: str
            sync_tx_smp_clear_counter:
                description:
                - "Sync Clear SMP Session Pkts Sent counter"
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
    "sampling_enable",
    "stats",
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
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'sync_pkt_tx_counter', 'sync_pkt_rcv_counter',
                    'sync_rx_create_counter', 'sync_rx_del_counter',
                    'sync_rx_update_age_counter', 'sync_tx_create_counter',
                    'sync_tx_del_counter', 'sync_tx_update_age_counter',
                    'sync_rx_persist_create_counter',
                    'sync_rx_persist_del_counter',
                    'sync_rx_persist_update_age_counter',
                    'sync_tx_persist_create_counter',
                    'sync_tx_persist_del_counter',
                    'sync_tx_persist_update_age_counter',
                    'query_pkt_tx_counter', 'query_pkt_rcv_counter',
                    'sync_tx_smp_radius_table_counter',
                    'sync_rx_smp_radius_table_counter', 'query_tx_max_packed',
                    'query_tx_min_packed', 'query_pkt_invalid_idx_counter',
                    'query_tx_get_buff_failed', 'query_rx_zero_info_counter',
                    'query_rx_full_info_counter', 'query_rx_unk_counter',
                    'sync_pkt_invalid_idx_counter', 'sync_tx_get_buff_failed',
                    'sync_tx_total_info_counter',
                    'sync_tx_create_ext_bit_counter',
                    'sync_tx_update_seqnos_counter', 'sync_tx_min_packed',
                    'sync_tx_max_packed', 'sync_rx_len_invalid',
                    'sync_persist_rx_len_invalid',
                    'sync_persist_rx_proto_not_supported',
                    'sync_persist_rx_type_invalid',
                    'sync_persist_rx_cannot_process_mandatory',
                    'sync_persist_rx_ext_bit_process_error',
                    'sync_persist_rx_no_such_vport',
                    'sync_persist_rx_vporttype_not_supported',
                    'sync_persist_rx_no_such_rport',
                    'sync_persist_rx_no_such_sg_group',
                    'sync_persist_rx_no_sg_group_info',
                    'sync_persist_rx_conn_get_failed', 'sync_rx_no_such_vport',
                    'sync_rx_no_such_rport',
                    'sync_rx_cannot_process_mandatory',
                    'sync_rx_ext_bit_process_error',
                    'sync_rx_create_ext_bit_counter', 'sync_rx_conn_exists',
                    'sync_rx_conn_get_failed', 'sync_rx_proto_not_supported',
                    'sync_rx_no_dst_for_vport_inline',
                    'sync_rx_no_such_nat_pool', 'sync_rx_no_such_sg_node',
                    'sync_rx_del_no_such_session', 'sync_rx_type_invalid',
                    'sync_rx_zero_info_counter', 'sync_rx_dcmsg_counter',
                    'sync_rx_total_info_counter',
                    'sync_rx_update_seqnos_counter', 'sync_rx_unk_counter',
                    'sync_rx_apptype_not_supported',
                    'sync_query_dcmsg_counter', 'sync_get_buff_failed_rt',
                    'sync_get_buff_failed_port', 'sync_rx_lsn_create_sby',
                    'sync_rx_nat_create_sby', 'sync_rx_nat_alloc_sby',
                    'sync_rx_insert_tuple', 'sync_rx_sfw',
                    'sync_rx_create_static_sby', 'sync_rx_ext_pptp',
                    'sync_rx_ext_rtsp', 'sync_rx_reserve_ha',
                    'sync_rx_seq_deltas', 'sync_rx_ftp_control',
                    'sync_rx_ext_lsn_acl', 'sync_rx_ext_lsn_ac_idle_timeout',
                    'sync_rx_ext_sip_alg', 'sync_rx_ext_h323_alg',
                    'sync_rx_ext_nat_mac', 'sync_tx_lsn_fullcone',
                    'sync_rx_lsn_fullcone', 'sync_err_lsn_fullcone',
                    'sync_tx_update_sctp_conn_addr',
                    'sync_rx_update_sctp_conn_addr',
                    'sync_rx_ext_nat_alg_tcp_info', 'sync_rx_ext_dcfw_rule_id',
                    'sync_rx_ext_dcfw_log', 'sync_rx_estab_counter',
                    'sync_tx_estab_counter', 'sync_rx_zone_failure_counter',
                    'sync_rx_ext_fw_http_logging',
                    'sync_rx_ext_dcfw_rule_idle_timeout',
                    'sync_rx_ext_fw_gtp_info', 'sync_rx_not_expect_sync_pkt',
                    'sync_rx_ext_fw_apps', 'sync_tx_mon_entity',
                    'sync_rx_mon_entity', 'sync_rx_ext_fw_gtp_log_info',
                    'sync_rx_ddos_drop_counter',
                    'sync_rx_invalid_sync_packet_counter',
                    'sync_rx_bad_protocol_counter', 'sync_rx_no_vgrp_counter',
                    'sync_rx_by_inactive_peer_counter',
                    'sync_rx_smp_create_counter', 'sync_rx_smp_delete_counter',
                    'sync_rx_smp_update_counter', 'sync_tx_smp_create_counter',
                    'sync_tx_smp_delete_counter', 'sync_tx_smp_update_counter',
                    'sync_rx_smp_clear_counter', 'sync_tx_smp_clear_counter'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'sync_pkt_tx_counter': {
                'type': 'str',
            },
            'sync_pkt_rcv_counter': {
                'type': 'str',
            },
            'sync_rx_create_counter': {
                'type': 'str',
            },
            'sync_rx_del_counter': {
                'type': 'str',
            },
            'sync_rx_update_age_counter': {
                'type': 'str',
            },
            'sync_tx_create_counter': {
                'type': 'str',
            },
            'sync_tx_del_counter': {
                'type': 'str',
            },
            'sync_tx_update_age_counter': {
                'type': 'str',
            },
            'sync_rx_persist_create_counter': {
                'type': 'str',
            },
            'sync_rx_persist_del_counter': {
                'type': 'str',
            },
            'sync_rx_persist_update_age_counter': {
                'type': 'str',
            },
            'sync_tx_persist_create_counter': {
                'type': 'str',
            },
            'sync_tx_persist_del_counter': {
                'type': 'str',
            },
            'sync_tx_persist_update_age_counter': {
                'type': 'str',
            },
            'query_pkt_tx_counter': {
                'type': 'str',
            },
            'query_pkt_rcv_counter': {
                'type': 'str',
            },
            'sync_tx_smp_radius_table_counter': {
                'type': 'str',
            },
            'sync_rx_smp_radius_table_counter': {
                'type': 'str',
            },
            'query_tx_max_packed': {
                'type': 'str',
            },
            'query_tx_min_packed': {
                'type': 'str',
            },
            'query_pkt_invalid_idx_counter': {
                'type': 'str',
            },
            'query_tx_get_buff_failed': {
                'type': 'str',
            },
            'query_rx_zero_info_counter': {
                'type': 'str',
            },
            'query_rx_full_info_counter': {
                'type': 'str',
            },
            'query_rx_unk_counter': {
                'type': 'str',
            },
            'sync_pkt_invalid_idx_counter': {
                'type': 'str',
            },
            'sync_tx_get_buff_failed': {
                'type': 'str',
            },
            'sync_tx_total_info_counter': {
                'type': 'str',
            },
            'sync_tx_create_ext_bit_counter': {
                'type': 'str',
            },
            'sync_tx_update_seqnos_counter': {
                'type': 'str',
            },
            'sync_tx_min_packed': {
                'type': 'str',
            },
            'sync_tx_max_packed': {
                'type': 'str',
            },
            'sync_rx_len_invalid': {
                'type': 'str',
            },
            'sync_persist_rx_len_invalid': {
                'type': 'str',
            },
            'sync_persist_rx_proto_not_supported': {
                'type': 'str',
            },
            'sync_persist_rx_type_invalid': {
                'type': 'str',
            },
            'sync_persist_rx_cannot_process_mandatory': {
                'type': 'str',
            },
            'sync_persist_rx_ext_bit_process_error': {
                'type': 'str',
            },
            'sync_persist_rx_no_such_vport': {
                'type': 'str',
            },
            'sync_persist_rx_vporttype_not_supported': {
                'type': 'str',
            },
            'sync_persist_rx_no_such_rport': {
                'type': 'str',
            },
            'sync_persist_rx_no_such_sg_group': {
                'type': 'str',
            },
            'sync_persist_rx_no_sg_group_info': {
                'type': 'str',
            },
            'sync_persist_rx_conn_get_failed': {
                'type': 'str',
            },
            'sync_rx_no_such_vport': {
                'type': 'str',
            },
            'sync_rx_no_such_rport': {
                'type': 'str',
            },
            'sync_rx_cannot_process_mandatory': {
                'type': 'str',
            },
            'sync_rx_ext_bit_process_error': {
                'type': 'str',
            },
            'sync_rx_create_ext_bit_counter': {
                'type': 'str',
            },
            'sync_rx_conn_exists': {
                'type': 'str',
            },
            'sync_rx_conn_get_failed': {
                'type': 'str',
            },
            'sync_rx_proto_not_supported': {
                'type': 'str',
            },
            'sync_rx_no_dst_for_vport_inline': {
                'type': 'str',
            },
            'sync_rx_no_such_nat_pool': {
                'type': 'str',
            },
            'sync_rx_no_such_sg_node': {
                'type': 'str',
            },
            'sync_rx_del_no_such_session': {
                'type': 'str',
            },
            'sync_rx_type_invalid': {
                'type': 'str',
            },
            'sync_rx_zero_info_counter': {
                'type': 'str',
            },
            'sync_rx_dcmsg_counter': {
                'type': 'str',
            },
            'sync_rx_total_info_counter': {
                'type': 'str',
            },
            'sync_rx_update_seqnos_counter': {
                'type': 'str',
            },
            'sync_rx_unk_counter': {
                'type': 'str',
            },
            'sync_rx_apptype_not_supported': {
                'type': 'str',
            },
            'sync_query_dcmsg_counter': {
                'type': 'str',
            },
            'sync_get_buff_failed_rt': {
                'type': 'str',
            },
            'sync_get_buff_failed_port': {
                'type': 'str',
            },
            'sync_rx_lsn_create_sby': {
                'type': 'str',
            },
            'sync_rx_nat_create_sby': {
                'type': 'str',
            },
            'sync_rx_nat_alloc_sby': {
                'type': 'str',
            },
            'sync_rx_insert_tuple': {
                'type': 'str',
            },
            'sync_rx_sfw': {
                'type': 'str',
            },
            'sync_rx_create_static_sby': {
                'type': 'str',
            },
            'sync_rx_ext_pptp': {
                'type': 'str',
            },
            'sync_rx_ext_rtsp': {
                'type': 'str',
            },
            'sync_rx_reserve_ha': {
                'type': 'str',
            },
            'sync_rx_seq_deltas': {
                'type': 'str',
            },
            'sync_rx_ftp_control': {
                'type': 'str',
            },
            'sync_rx_ext_lsn_acl': {
                'type': 'str',
            },
            'sync_rx_ext_lsn_ac_idle_timeout': {
                'type': 'str',
            },
            'sync_rx_ext_sip_alg': {
                'type': 'str',
            },
            'sync_rx_ext_h323_alg': {
                'type': 'str',
            },
            'sync_rx_ext_nat_mac': {
                'type': 'str',
            },
            'sync_tx_lsn_fullcone': {
                'type': 'str',
            },
            'sync_rx_lsn_fullcone': {
                'type': 'str',
            },
            'sync_err_lsn_fullcone': {
                'type': 'str',
            },
            'sync_tx_update_sctp_conn_addr': {
                'type': 'str',
            },
            'sync_rx_update_sctp_conn_addr': {
                'type': 'str',
            },
            'sync_rx_ext_nat_alg_tcp_info': {
                'type': 'str',
            },
            'sync_rx_ext_dcfw_rule_id': {
                'type': 'str',
            },
            'sync_rx_ext_dcfw_log': {
                'type': 'str',
            },
            'sync_rx_estab_counter': {
                'type': 'str',
            },
            'sync_tx_estab_counter': {
                'type': 'str',
            },
            'sync_rx_zone_failure_counter': {
                'type': 'str',
            },
            'sync_rx_ext_fw_http_logging': {
                'type': 'str',
            },
            'sync_rx_ext_dcfw_rule_idle_timeout': {
                'type': 'str',
            },
            'sync_rx_ext_fw_gtp_info': {
                'type': 'str',
            },
            'sync_rx_not_expect_sync_pkt': {
                'type': 'str',
            },
            'sync_rx_ext_fw_apps': {
                'type': 'str',
            },
            'sync_tx_mon_entity': {
                'type': 'str',
            },
            'sync_rx_mon_entity': {
                'type': 'str',
            },
            'sync_rx_ext_fw_gtp_log_info': {
                'type': 'str',
            },
            'sync_rx_ddos_drop_counter': {
                'type': 'str',
            },
            'sync_rx_invalid_sync_packet_counter': {
                'type': 'str',
            },
            'sync_rx_bad_protocol_counter': {
                'type': 'str',
            },
            'sync_rx_no_vgrp_counter': {
                'type': 'str',
            },
            'sync_rx_by_inactive_peer_counter': {
                'type': 'str',
            },
            'sync_rx_smp_create_counter': {
                'type': 'str',
            },
            'sync_rx_smp_delete_counter': {
                'type': 'str',
            },
            'sync_rx_smp_update_counter': {
                'type': 'str',
            },
            'sync_tx_smp_create_counter': {
                'type': 'str',
            },
            'sync_tx_smp_delete_counter': {
                'type': 'str',
            },
            'sync_tx_smp_update_counter': {
                'type': 'str',
            },
            'sync_rx_smp_clear_counter': {
                'type': 'str',
            },
            'sync_tx_smp_clear_counter': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vrrp-a/state"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vrrp-a/state"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["state"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["state"].get(k) != v:
            change_results["changed"] = True
            config_changes["state"][k] = v

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
    payload = utils.build_json("state", module.params, AVAILABLE_PROPERTIES)
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
                  axapi_calls=[])

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
                    api_client.get_stats(module.client,
                                         existing_url(module),
                                         params=module.params))
    except a10_ex.ACOSException as ex:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()
        raise gex
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
