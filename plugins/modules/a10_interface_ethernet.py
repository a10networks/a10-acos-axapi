#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_interface_ethernet
description:
    - Ethernet interface
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
    ifnum:
        description:
        - "Ethernet interface number"
        type: str
        required: True
    name:
        description:
        - "Name for the interface"
        type: str
        required: False
    l3_vlan_fwd_disable:
        description:
        - "Field l3_vlan_fwd_disable"
        type: bool
        required: False
    load_interval:
        description:
        - "Configure Load Interval (Seconds (5-300, Multiple of 5), default 300)"
        type: int
        required: False
    media_type_copper:
        description:
        - "Set the media type to copper"
        type: bool
        required: False
    auto_neg_enable:
        description:
        - "enable auto-negotiation"
        type: bool
        required: False
    fec_forced_on:
        description:
        - "turn on the FEC"
        type: bool
        required: False
    fec_forced_off:
        description:
        - "turn off the FEC"
        type: bool
        required: False
    speed_forced_40g:
        description:
        - "force the speed to be 40G on 100G link"
        type: bool
        required: False
    remove_vlan_tag:
        description:
        - "Remove the vlan tag for egressing packets"
        type: bool
        required: False
    mtu:
        description:
        - "Interface mtu (Interface MTU, default 1 (min MTU is 1280 for IPv6))"
        type: int
        required: False
    trap_source:
        description:
        - "The trap source"
        type: bool
        required: False
    duplexity:
        description:
        - "'Full'= Full; 'Half'= Half; 'auto'= auto;"
        type: str
        required: False
    speed:
        description:
        - "'10'= 10; '100'= 100; '1000'= 1000; 'auto'= auto;"
        type: str
        required: False
    flow_control:
        description:
        - "Enable 802.3x flow control on full duplex port"
        type: bool
        required: False
    action:
        description:
        - "'enable'= Enable; 'disable'= Disable;"
        type: str
        required: False
    icmp_rate_limit:
        description:
        - "Field icmp_rate_limit"
        type: dict
        required: False
        suboptions:
            normal:
                description:
                - "Normal rate limit. If exceeds this limit, drop the ICMP packet that goes over
          the limit"
                type: int
            lockup:
                description:
                - "Enter lockup state when ICMP rate exceeds lockup rate limit (Maximum rate
          limit. If exceeds this limit, drop all ICMP packet for a time period)"
                type: int
            lockup_period:
                description:
                - "Lockup period (second)"
                type: int
    icmpv6_rate_limit:
        description:
        - "Field icmpv6_rate_limit"
        type: dict
        required: False
        suboptions:
            normal_v6:
                description:
                - "Normal rate limit. If exceeds this limit, drop the ICMP packet that goes over
          the limit"
                type: int
            lockup_v6:
                description:
                - "Enter lockup state when ICMP rate exceeds lockup rate limit (Maximum rate
          limit. If exceeds this limit, drop all ICMP packet for a time period)"
                type: int
            lockup_period_v6:
                description:
                - "Lockup period (second)"
                type: int
    monitor_list:
        description:
        - "Field monitor_list"
        type: list
        required: False
        suboptions:
            monitor:
                description:
                - "'input'= Incoming packets; 'output'= Outgoing packets; 'both'= Both incoming
          and outgoing packets;"
                type: str
            mirror_index:
                description:
                - "Mirror index"
                type: int
            monitor_vlan:
                description:
                - "VLAN number"
                type: int
    cpu_process:
        description:
        - "All Packets to this port are processed by CPU"
        type: bool
        required: False
    cpu_process_dir:
        description:
        - "'primary'= Primary board; 'blade'= blade board; 'hash-dip'= Hash based on the
          Destination IP; 'hash-sip'= Hash based on the Source IP; 'hash-dmac'= Hash
          based on the Destination MAC; 'hash-smac'= Hash based on the Source MAC;"
        type: str
        required: False
    traffic_distribution_mode:
        description:
        - "'sip'= sip; 'dip'= dip; 'primary'= primary; 'blade'= blade; 'l4-src-port'=
          l4-src-port; 'l4-dst-port'= l4-dst-port;"
        type: str
        required: False
    access_list:
        description:
        - "Field access_list"
        type: dict
        required: False
        suboptions:
            acl_id:
                description:
                - "ACL id"
                type: int
            acl_name:
                description:
                - "Apply an access list (Named Access List)"
                type: str
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
                - "'all'= all; 'packets_input'= Input packets; 'bytes_input'= Input bytes;
          'received_broadcasts'= Received broadcasts; 'received_multicasts'= Received
          multicasts; 'received_unicasts'= Received unicasts; 'input_errors'= Input
          errors; 'crc'= CRC; 'frame'= Frames; 'runts'= Runts; 'giants'= Giants;
          'packets_output'= Output packets; 'bytes_output'= Output bytes;
          'transmitted_broadcasts'= Transmitted broadcasts; 'transmitted_multicasts'=
          Transmitted multicasts; 'transmitted_unicasts'= Transmitted unicasts;
          'output_errors'= Output errors; 'collisions'= Collisions; 'giants_output'=
          Output Giants; 'rate_pkt_sent'= Packet sent rate packets/sec; 'rate_byte_sent'=
          Byte sent rate bits/sec; 'rate_pkt_rcvd'= Packet received rate packets/sec;
          'rate_byte_rcvd'= Byte received rate bits/sec; 'load_interval'= Load Interval;"
                type: str
    lldp:
        description:
        - "Field lldp"
        type: dict
        required: False
        suboptions:
            enable_cfg:
                description:
                - "Field enable_cfg"
                type: dict
            notification_cfg:
                description:
                - "Field notification_cfg"
                type: dict
            tx_dot1_cfg:
                description:
                - "Field tx_dot1_cfg"
                type: dict
            tx_tlvs_cfg:
                description:
                - "Field tx_tlvs_cfg"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
    ddos:
        description:
        - "Field ddos"
        type: dict
        required: False
        suboptions:
            outside:
                description:
                - "DDoS outside (untrusted) interface"
                type: bool
            inside:
                description:
                - "DDoS inside (trusted) interface"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    ip:
        description:
        - "Field ip"
        type: dict
        required: False
        suboptions:
            dhcp:
                description:
                - "Use DHCP to configure IP address"
                type: bool
            address_list:
                description:
                - "Field address_list"
                type: list
            allow_promiscuous_vip:
                description:
                - "Allow traffic to be associated with promiscuous VIP"
                type: bool
            cache_spoofing_port:
                description:
                - "This interface connects to spoofing cache"
                type: bool
            helper_address_list:
                description:
                - "Field helper_address_list"
                type: list
            inside:
                description:
                - "Configure interface as inside"
                type: bool
            outside:
                description:
                - "Configure interface as outside"
                type: bool
            ttl_ignore:
                description:
                - "Ignore TTL decrement for a received packet before sending out"
                type: bool
            slb_partition_redirect:
                description:
                - "Redirect SLB traffic across partition"
                type: bool
            generate_membership_query:
                description:
                - "Enable Membership Query"
                type: bool
            query_interval:
                description:
                - "1 - 255 (Default is 125)"
                type: int
            max_resp_time:
                description:
                - "Maximum Response Time (Max Response Time (Default is 100))"
                type: int
            client:
                description:
                - "Client facing interface for IPv4/v6 traffic"
                type: bool
            server:
                description:
                - "Server facing interface for IPv4/v6 traffic"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            stateful_firewall:
                description:
                - "Field stateful_firewall"
                type: dict
            router:
                description:
                - "Field router"
                type: dict
            rip:
                description:
                - "Field rip"
                type: dict
            ospf:
                description:
                - "Field ospf"
                type: dict
    ipv6:
        description:
        - "Field ipv6"
        type: dict
        required: False
        suboptions:
            address_list:
                description:
                - "Field address_list"
                type: list
            inside:
                description:
                - "Configure interface as inside"
                type: bool
            outside:
                description:
                - "Configure interface as outside"
                type: bool
            ipv6_enable:
                description:
                - "Enable IPv6 processing"
                type: bool
            ttl_ignore:
                description:
                - "Ignore TTL decrement for a received packet before sending out"
                type: bool
            access_list_cfg:
                description:
                - "Field access_list_cfg"
                type: dict
            router_adver:
                description:
                - "Field router_adver"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
            stateful_firewall:
                description:
                - "Field stateful_firewall"
                type: dict
            router:
                description:
                - "Field router"
                type: dict
            rip:
                description:
                - "Field rip"
                type: dict
            ospf:
                description:
                - "Field ospf"
                type: dict
    nptv6:
        description:
        - "Field nptv6"
        type: dict
        required: False
        suboptions:
            domain_list:
                description:
                - "Field domain_list"
                type: list
    map:
        description:
        - "Field map"
        type: dict
        required: False
        suboptions:
            inside:
                description:
                - "Configure MAP inside interface (connected to MAP domains)"
                type: bool
            outside:
                description:
                - "Configure MAP outside interface"
                type: bool
            map_t_inside:
                description:
                - "Configure MAP inside interface (connected to MAP domains)"
                type: bool
            map_t_outside:
                description:
                - "Configure MAP outside interface"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    lw_4o6:
        description:
        - "Field lw_4o6"
        type: dict
        required: False
        suboptions:
            outside:
                description:
                - "Configure LW-4over6 inside interface"
                type: bool
            inside:
                description:
                - "Configure LW-4over6 outside interface"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    trunk_group_list:
        description:
        - "Field trunk_group_list"
        type: list
        required: False
        suboptions:
            trunk_number:
                description:
                - "Trunk Number"
                type: int
            ntype:
                description:
                - "'static'= Static (default); 'lacp'= lacp; 'lacp-udld'= lacp-udld;"
                type: str
            admin_key:
                description:
                - "LACP admin key (Admin key value)"
                type: int
            port_priority:
                description:
                - "Set LACP priority for a port (LACP port priority)"
                type: int
            udld_timeout_cfg:
                description:
                - "Field udld_timeout_cfg"
                type: dict
            mode:
                description:
                - "'active'= enable initiation of LACP negotiation on a port(default); 'passive'=
          disable initiation of LACP negotiation on a port;"
                type: str
            timeout:
                description:
                - "'long'= Set LACP long timeout (default); 'short'= Set LACP short timeout;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    bfd:
        description:
        - "Field bfd"
        type: dict
        required: False
        suboptions:
            authentication:
                description:
                - "Field authentication"
                type: dict
            echo:
                description:
                - "Enable BFD Echo"
                type: bool
            demand:
                description:
                - "Demand mode"
                type: bool
            interval_cfg:
                description:
                - "Field interval_cfg"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
    isis:
        description:
        - "Field isis"
        type: dict
        required: False
        suboptions:
            authentication:
                description:
                - "Field authentication"
                type: dict
            bfd_cfg:
                description:
                - "Field bfd_cfg"
                type: dict
            circuit_type:
                description:
                - "'level-1'= Level-1 only adjacencies are formed; 'level-1-2'= Level-1-2
          adjacencies are formed; 'level-2-only'= Level-2 only adjacencies are formed;"
                type: str
            csnp_interval_list:
                description:
                - "Field csnp_interval_list"
                type: list
            padding:
                description:
                - "Add padding to IS-IS hello packets"
                type: bool
            hello_interval_list:
                description:
                - "Field hello_interval_list"
                type: list
            hello_interval_minimal_list:
                description:
                - "Field hello_interval_minimal_list"
                type: list
            hello_multiplier_list:
                description:
                - "Field hello_multiplier_list"
                type: list
            lsp_interval:
                description:
                - "Set LSP transmission interval (LSP transmission interval (milliseconds))"
                type: int
            mesh_group:
                description:
                - "Field mesh_group"
                type: dict
            metric_list:
                description:
                - "Field metric_list"
                type: list
            network:
                description:
                - "'broadcast'= Specify IS-IS broadcast multi-access network; 'point-to-point'=
          Specify IS-IS point-to-point network;"
                type: str
            password_list:
                description:
                - "Field password_list"
                type: list
            priority_list:
                description:
                - "Field priority_list"
                type: list
            retransmit_interval:
                description:
                - "Set per-LSP retransmission interval (Interval between retransmissions of the
          same LSP (seconds))"
                type: int
            wide_metric_list:
                description:
                - "Field wide_metric_list"
                type: list
            uuid:
                description:
                - "uuid of the object"
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
            line_protocol:
                description:
                - "Field line_protocol"
                type: str
            link_type:
                description:
                - "Field link_type"
                type: str
            mac:
                description:
                - "Field mac"
                type: str
            config_speed:
                description:
                - "Field config_speed"
                type: str
            actual_speed:
                description:
                - "Field actual_speed"
                type: str
            config_duplexity:
                description:
                - "Field config_duplexity"
                type: str
            actual_duplexity:
                description:
                - "Field actual_duplexity"
                type: str
            media_type:
                description:
                - "Field media_type"
                type: str
            ipv4_address:
                description:
                - "IP address"
                type: str
            ipv4_netmask:
                description:
                - "IP subnet mask"
                type: str
            ipv4_addr_count:
                description:
                - "Field ipv4_addr_count"
                type: int
            ipv4_list:
                description:
                - "Field ipv4_list"
                type: list
            ipv6_addr_count:
                description:
                - "Field ipv6_addr_count"
                type: int
            ipv6_list:
                description:
                - "Field ipv6_list"
                type: list
            ipv6_link_local:
                description:
                - "Field ipv6_link_local"
                type: str
            ipv6_link_local_prefix:
                description:
                - "Field ipv6_link_local_prefix"
                type: str
            ipv6_link_local_type:
                description:
                - "Field ipv6_link_local_type"
                type: str
            ipv6_link_local_scope:
                description:
                - "Field ipv6_link_local_scope"
                type: str
            igmp_query_sent:
                description:
                - "Field igmp_query_sent"
                type: int
            icmp_rate_limit_current:
                description:
                - "Field icmp_rate_limit_current"
                type: int
            icmp_rate_over_limit_drop:
                description:
                - "Field icmp_rate_over_limit_drop"
                type: int
            icmp6_rate_limit_current:
                description:
                - "Field icmp6_rate_limit_current"
                type: int
            icmp6_rate_over_limit_drop:
                description:
                - "Field icmp6_rate_over_limit_drop"
                type: int
            is_tagged:
                description:
                - "Field is_tagged"
                type: int
            vlan_id:
                description:
                - "Field vlan_id"
                type: int
            tagged_vlan_list:
                description:
                - "Field tagged_vlan_list"
                type: str
            is_lead_member:
                description:
                - "Field is_lead_member"
                type: int
            current_vnp_id:
                description:
                - "Field current_vnp_id"
                type: int
            port_vnp_id:
                description:
                - "Field port_vnp_id"
                type: int
            is_pristine:
                description:
                - "Field is_pristine"
                type: int
            rate_byte_rcvd:
                description:
                - "Field rate_byte_rcvd"
                type: int
            rate_byte_sent:
                description:
                - "Field rate_byte_sent"
                type: int
            rate_pkt_rcvd:
                description:
                - "Field rate_pkt_rcvd"
                type: int
            rate_pkt_sent:
                description:
                - "Field rate_pkt_sent"
                type: int
            input_utilization:
                description:
                - "Field input_utilization"
                type: int
            output_utilization:
                description:
                - "Field output_utilization"
                type: int
            is_device_transparent:
                description:
                - "Field is_device_transparent"
                type: int
            incoming_pkts_mirrored:
                description:
                - "Field incoming_pkts_mirrored"
                type: int
            outgoing_pkts_mirrored:
                description:
                - "Field outgoing_pkts_mirrored"
                type: int
            incoming_pkts_monitored:
                description:
                - "Field incoming_pkts_monitored"
                type: int
            outgoing_pkts_monitored:
                description:
                - "Field outgoing_pkts_monitored"
                type: int
            ifnum:
                description:
                - "Ethernet interface number"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            packets_input:
                description:
                - "Input packets"
                type: str
            bytes_input:
                description:
                - "Input bytes"
                type: str
            received_broadcasts:
                description:
                - "Received broadcasts"
                type: str
            received_multicasts:
                description:
                - "Received multicasts"
                type: str
            received_unicasts:
                description:
                - "Received unicasts"
                type: str
            input_errors:
                description:
                - "Input errors"
                type: str
            crc:
                description:
                - "CRC"
                type: str
            frame:
                description:
                - "Frames"
                type: str
            runts:
                description:
                - "Runts"
                type: str
            giants:
                description:
                - "Giants"
                type: str
            packets_output:
                description:
                - "Output packets"
                type: str
            bytes_output:
                description:
                - "Output bytes"
                type: str
            transmitted_broadcasts:
                description:
                - "Transmitted broadcasts"
                type: str
            transmitted_multicasts:
                description:
                - "Transmitted multicasts"
                type: str
            transmitted_unicasts:
                description:
                - "Transmitted unicasts"
                type: str
            output_errors:
                description:
                - "Output errors"
                type: str
            collisions:
                description:
                - "Collisions"
                type: str
            giants_output:
                description:
                - "Output Giants"
                type: str
            rate_pkt_sent:
                description:
                - "Packet sent rate packets/sec"
                type: str
            rate_byte_sent:
                description:
                - "Byte sent rate bits/sec"
                type: str
            rate_pkt_rcvd:
                description:
                - "Packet received rate packets/sec"
                type: str
            rate_byte_rcvd:
                description:
                - "Byte received rate bits/sec"
                type: str
            load_interval:
                description:
                - "Load Interval"
                type: str
            ifnum:
                description:
                - "Ethernet interface number"
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
    "access_list",
    "action",
    "auto_neg_enable",
    "bfd",
    "cpu_process",
    "cpu_process_dir",
    "ddos",
    "duplexity",
    "fec_forced_off",
    "fec_forced_on",
    "flow_control",
    "icmp_rate_limit",
    "icmpv6_rate_limit",
    "ifnum",
    "ip",
    "ipv6",
    "isis",
    "l3_vlan_fwd_disable",
    "lldp",
    "load_interval",
    "lw_4o6",
    "map",
    "media_type_copper",
    "monitor_list",
    "mtu",
    "name",
    "nptv6",
    "oper",
    "remove_vlan_tag",
    "sampling_enable",
    "speed",
    "speed_forced_40g",
    "stats",
    "traffic_distribution_mode",
    "trap_source",
    "trunk_group_list",
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
        'ifnum': {
            'type': 'str',
            'required': True,
        },
        'name': {
            'type': 'str',
        },
        'l3_vlan_fwd_disable': {
            'type': 'bool',
        },
        'load_interval': {
            'type': 'int',
        },
        'media_type_copper': {
            'type': 'bool',
        },
        'auto_neg_enable': {
            'type': 'bool',
        },
        'fec_forced_on': {
            'type': 'bool',
        },
        'fec_forced_off': {
            'type': 'bool',
        },
        'speed_forced_40g': {
            'type': 'bool',
        },
        'remove_vlan_tag': {
            'type': 'bool',
        },
        'mtu': {
            'type': 'int',
        },
        'trap_source': {
            'type': 'bool',
        },
        'duplexity': {
            'type': 'str',
            'choices': ['Full', 'Half', 'auto']
        },
        'speed': {
            'type': 'str',
            'choices': ['10', '100', '1000', 'auto']
        },
        'flow_control': {
            'type': 'bool',
        },
        'action': {
            'type': 'str',
            'choices': ['enable', 'disable']
        },
        'icmp_rate_limit': {
            'type': 'dict',
            'normal': {
                'type': 'int',
            },
            'lockup': {
                'type': 'int',
            },
            'lockup_period': {
                'type': 'int',
            }
        },
        'icmpv6_rate_limit': {
            'type': 'dict',
            'normal_v6': {
                'type': 'int',
            },
            'lockup_v6': {
                'type': 'int',
            },
            'lockup_period_v6': {
                'type': 'int',
            }
        },
        'monitor_list': {
            'type': 'list',
            'monitor': {
                'type': 'str',
                'choices': ['input', 'output', 'both']
            },
            'mirror_index': {
                'type': 'int',
            },
            'monitor_vlan': {
                'type': 'int',
            }
        },
        'cpu_process': {
            'type': 'bool',
        },
        'cpu_process_dir': {
            'type':
            'str',
            'choices': [
                'primary', 'blade', 'hash-dip', 'hash-sip', 'hash-dmac',
                'hash-smac'
            ]
        },
        'traffic_distribution_mode': {
            'type':
            'str',
            'choices':
            ['sip', 'dip', 'primary', 'blade', 'l4-src-port', 'l4-dst-port']
        },
        'access_list': {
            'type': 'dict',
            'acl_id': {
                'type': 'int',
            },
            'acl_name': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'packets_input', 'bytes_input',
                    'received_broadcasts', 'received_multicasts',
                    'received_unicasts', 'input_errors', 'crc', 'frame',
                    'runts', 'giants', 'packets_output', 'bytes_output',
                    'transmitted_broadcasts', 'transmitted_multicasts',
                    'transmitted_unicasts', 'output_errors', 'collisions',
                    'giants_output', 'rate_pkt_sent', 'rate_byte_sent',
                    'rate_pkt_rcvd', 'rate_byte_rcvd', 'load_interval'
                ]
            }
        },
        'lldp': {
            'type': 'dict',
            'enable_cfg': {
                'type': 'dict',
                'rt_enable': {
                    'type': 'bool',
                },
                'rx': {
                    'type': 'bool',
                },
                'tx': {
                    'type': 'bool',
                }
            },
            'notification_cfg': {
                'type': 'dict',
                'notification': {
                    'type': 'bool',
                },
                'notif_enable': {
                    'type': 'bool',
                }
            },
            'tx_dot1_cfg': {
                'type': 'dict',
                'tx_dot1_tlvs': {
                    'type': 'bool',
                },
                'link_aggregation': {
                    'type': 'bool',
                },
                'vlan': {
                    'type': 'bool',
                }
            },
            'tx_tlvs_cfg': {
                'type': 'dict',
                'tx_tlvs': {
                    'type': 'bool',
                },
                'exclude': {
                    'type': 'bool',
                },
                'management_address': {
                    'type': 'bool',
                },
                'port_description': {
                    'type': 'bool',
                },
                'system_capabilities': {
                    'type': 'bool',
                },
                'system_description': {
                    'type': 'bool',
                },
                'system_name': {
                    'type': 'bool',
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'ddos': {
            'type': 'dict',
            'outside': {
                'type': 'bool',
            },
            'inside': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'ip': {
            'type': 'dict',
            'dhcp': {
                'type': 'bool',
            },
            'address_list': {
                'type': 'list',
                'ipv4_address': {
                    'type': 'str',
                },
                'ipv4_netmask': {
                    'type': 'str',
                }
            },
            'allow_promiscuous_vip': {
                'type': 'bool',
            },
            'cache_spoofing_port': {
                'type': 'bool',
            },
            'helper_address_list': {
                'type': 'list',
                'helper_address': {
                    'type': 'str',
                }
            },
            'inside': {
                'type': 'bool',
            },
            'outside': {
                'type': 'bool',
            },
            'ttl_ignore': {
                'type': 'bool',
            },
            'slb_partition_redirect': {
                'type': 'bool',
            },
            'generate_membership_query': {
                'type': 'bool',
            },
            'query_interval': {
                'type': 'int',
            },
            'max_resp_time': {
                'type': 'int',
            },
            'client': {
                'type': 'bool',
            },
            'server': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            },
            'stateful_firewall': {
                'type': 'dict',
                'inside': {
                    'type': 'bool',
                },
                'class_list': {
                    'type': 'str',
                },
                'outside': {
                    'type': 'bool',
                },
                'access_list': {
                    'type': 'bool',
                },
                'acl_id': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'router': {
                'type': 'dict',
                'isis': {
                    'type': 'dict',
                    'tag': {
                        'type': 'str',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                }
            },
            'rip': {
                'type': 'dict',
                'authentication': {
                    'type': 'dict',
                    'str': {
                        'type': 'dict',
                        'string': {
                            'type': 'str',
                        }
                    },
                    'mode': {
                        'type': 'dict',
                        'mode': {
                            'type': 'str',
                            'choices': ['md5', 'text']
                        }
                    },
                    'key_chain': {
                        'type': 'dict',
                        'key_chain': {
                            'type': 'str',
                        }
                    }
                },
                'send_packet': {
                    'type': 'bool',
                },
                'receive_packet': {
                    'type': 'bool',
                },
                'send_cfg': {
                    'type': 'dict',
                    'send': {
                        'type': 'bool',
                    },
                    'version': {
                        'type': 'str',
                        'choices': ['1', '2', '1-compatible', '1-2']
                    }
                },
                'receive_cfg': {
                    'type': 'dict',
                    'receive': {
                        'type': 'bool',
                    },
                    'version': {
                        'type': 'str',
                        'choices': ['1', '2', '1-2']
                    }
                },
                'split_horizon_cfg': {
                    'type': 'dict',
                    'state': {
                        'type': 'str',
                        'choices': ['poisoned', 'disable', 'enable']
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'ospf': {
                'type': 'dict',
                'ospf_global': {
                    'type': 'dict',
                    'authentication_cfg': {
                        'type': 'dict',
                        'authentication': {
                            'type': 'bool',
                        },
                        'value': {
                            'type': 'str',
                            'choices': ['message-digest', 'null']
                        }
                    },
                    'authentication_key': {
                        'type': 'str',
                    },
                    'bfd_cfg': {
                        'type': 'dict',
                        'bfd': {
                            'type': 'bool',
                        },
                        'disable': {
                            'type': 'bool',
                        }
                    },
                    'cost': {
                        'type': 'int',
                    },
                    'database_filter_cfg': {
                        'type': 'dict',
                        'database_filter': {
                            'type': 'str',
                            'choices': ['all']
                        },
                        'out': {
                            'type': 'bool',
                        }
                    },
                    'dead_interval': {
                        'type': 'int',
                    },
                    'disable': {
                        'type': 'str',
                        'choices': ['all']
                    },
                    'hello_interval': {
                        'type': 'int',
                    },
                    'message_digest_cfg': {
                        'type': 'list',
                        'message_digest_key': {
                            'type': 'int',
                        },
                        'md5': {
                            'type': 'dict',
                            'md5_value': {
                                'type': 'str',
                            },
                            'encrypted': {
                                'type': 'str',
                            }
                        }
                    },
                    'mtu': {
                        'type': 'int',
                    },
                    'mtu_ignore': {
                        'type': 'bool',
                    },
                    'network': {
                        'type': 'dict',
                        'broadcast': {
                            'type': 'bool',
                        },
                        'non_broadcast': {
                            'type': 'bool',
                        },
                        'point_to_point': {
                            'type': 'bool',
                        },
                        'point_to_multipoint': {
                            'type': 'bool',
                        },
                        'p2mp_nbma': {
                            'type': 'bool',
                        }
                    },
                    'priority': {
                        'type': 'int',
                    },
                    'retransmit_interval': {
                        'type': 'int',
                    },
                    'transmit_delay': {
                        'type': 'int',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                },
                'ospf_ip_list': {
                    'type': 'list',
                    'ip_addr': {
                        'type': 'str',
                        'required': True,
                    },
                    'authentication': {
                        'type': 'bool',
                    },
                    'value': {
                        'type': 'str',
                        'choices': ['message-digest', 'null']
                    },
                    'authentication_key': {
                        'type': 'str',
                    },
                    'cost': {
                        'type': 'int',
                    },
                    'database_filter': {
                        'type': 'str',
                        'choices': ['all']
                    },
                    'out': {
                        'type': 'bool',
                    },
                    'dead_interval': {
                        'type': 'int',
                    },
                    'hello_interval': {
                        'type': 'int',
                    },
                    'message_digest_cfg': {
                        'type': 'list',
                        'message_digest_key': {
                            'type': 'int',
                        },
                        'md5_value': {
                            'type': 'str',
                        },
                        'encrypted': {
                            'type': 'str',
                        }
                    },
                    'mtu_ignore': {
                        'type': 'bool',
                    },
                    'priority': {
                        'type': 'int',
                    },
                    'retransmit_interval': {
                        'type': 'int',
                    },
                    'transmit_delay': {
                        'type': 'int',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                }
            }
        },
        'ipv6': {
            'type': 'dict',
            'address_list': {
                'type': 'list',
                'ipv6_addr': {
                    'type': 'str',
                },
                'address_type': {
                    'type': 'str',
                    'choices': ['anycast', 'link-local']
                }
            },
            'inside': {
                'type': 'bool',
            },
            'outside': {
                'type': 'bool',
            },
            'ipv6_enable': {
                'type': 'bool',
            },
            'ttl_ignore': {
                'type': 'bool',
            },
            'access_list_cfg': {
                'type': 'dict',
                'v6_acl_name': {
                    'type': 'str',
                },
                'inbound': {
                    'type': 'bool',
                }
            },
            'router_adver': {
                'type': 'dict',
                'action': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                },
                'hop_limit': {
                    'type': 'int',
                },
                'max_interval': {
                    'type': 'int',
                },
                'min_interval': {
                    'type': 'int',
                },
                'default_lifetime': {
                    'type': 'int',
                },
                'rate_limit': {
                    'type': 'int',
                },
                'reachable_time': {
                    'type': 'int',
                },
                'retransmit_timer': {
                    'type': 'int',
                },
                'adver_mtu_disable': {
                    'type': 'bool',
                },
                'adver_mtu': {
                    'type': 'int',
                },
                'prefix_list': {
                    'type': 'list',
                    'prefix': {
                        'type': 'str',
                    },
                    'not_autonomous': {
                        'type': 'bool',
                    },
                    'not_on_link': {
                        'type': 'bool',
                    },
                    'preferred_lifetime': {
                        'type': 'int',
                    },
                    'valid_lifetime': {
                        'type': 'int',
                    }
                },
                'managed_config_action': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                },
                'other_config_action': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                },
                'adver_vrid': {
                    'type': 'int',
                },
                'use_floating_ip': {
                    'type': 'bool',
                },
                'floating_ip': {
                    'type': 'str',
                },
                'adver_vrid_default': {
                    'type': 'bool',
                },
                'use_floating_ip_default_vrid': {
                    'type': 'bool',
                },
                'floating_ip_default_vrid': {
                    'type': 'str',
                }
            },
            'uuid': {
                'type': 'str',
            },
            'stateful_firewall': {
                'type': 'dict',
                'inside': {
                    'type': 'bool',
                },
                'class_list': {
                    'type': 'str',
                },
                'outside': {
                    'type': 'bool',
                },
                'access_list': {
                    'type': 'bool',
                },
                'acl_name': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'router': {
                'type': 'dict',
                'ripng': {
                    'type': 'dict',
                    'rip': {
                        'type': 'bool',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                },
                'ospf': {
                    'type': 'dict',
                    'area_list': {
                        'type': 'list',
                        'area_id_num': {
                            'type': 'int',
                        },
                        'area_id_addr': {
                            'type': 'str',
                        },
                        'tag': {
                            'type': 'str',
                        },
                        'instance_id': {
                            'type': 'int',
                        }
                    },
                    'uuid': {
                        'type': 'str',
                    }
                },
                'isis': {
                    'type': 'dict',
                    'tag': {
                        'type': 'str',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                }
            },
            'rip': {
                'type': 'dict',
                'split_horizon_cfg': {
                    'type': 'dict',
                    'state': {
                        'type': 'str',
                        'choices': ['poisoned', 'disable', 'enable']
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'ospf': {
                'type': 'dict',
                'network_list': {
                    'type': 'list',
                    'broadcast_type': {
                        'type':
                        'str',
                        'choices': [
                            'broadcast', 'non-broadcast', 'point-to-point',
                            'point-to-multipoint'
                        ]
                    },
                    'p2mp_nbma': {
                        'type': 'bool',
                    },
                    'network_instance_id': {
                        'type': 'int',
                    }
                },
                'bfd': {
                    'type': 'bool',
                },
                'disable': {
                    'type': 'bool',
                },
                'cost_cfg': {
                    'type': 'list',
                    'cost': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'dead_interval_cfg': {
                    'type': 'list',
                    'dead_interval': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'hello_interval_cfg': {
                    'type': 'list',
                    'hello_interval': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'mtu_ignore_cfg': {
                    'type': 'list',
                    'mtu_ignore': {
                        'type': 'bool',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'neighbor_cfg': {
                    'type': 'list',
                    'neighbor': {
                        'type': 'str',
                    },
                    'neig_inst': {
                        'type': 'int',
                    },
                    'neighbor_cost': {
                        'type': 'int',
                    },
                    'neighbor_poll_interval': {
                        'type': 'int',
                    },
                    'neighbor_priority': {
                        'type': 'int',
                    }
                },
                'priority_cfg': {
                    'type': 'list',
                    'priority': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'retransmit_interval_cfg': {
                    'type': 'list',
                    'retransmit_interval': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'transmit_delay_cfg': {
                    'type': 'list',
                    'transmit_delay': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            }
        },
        'nptv6': {
            'type': 'dict',
            'domain_list': {
                'type': 'list',
                'domain_name': {
                    'type': 'str',
                    'required': True,
                },
                'bind_type': {
                    'type': 'str',
                    'required': True,
                    'choices': ['inside', 'outside']
                },
                'uuid': {
                    'type': 'str',
                }
            }
        },
        'map': {
            'type': 'dict',
            'inside': {
                'type': 'bool',
            },
            'outside': {
                'type': 'bool',
            },
            'map_t_inside': {
                'type': 'bool',
            },
            'map_t_outside': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'lw_4o6': {
            'type': 'dict',
            'outside': {
                'type': 'bool',
            },
            'inside': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'trunk_group_list': {
            'type': 'list',
            'trunk_number': {
                'type': 'int',
                'required': True,
            },
            'ntype': {
                'type': 'str',
                'choices': ['static', 'lacp', 'lacp-udld']
            },
            'admin_key': {
                'type': 'int',
            },
            'port_priority': {
                'type': 'int',
            },
            'udld_timeout_cfg': {
                'type': 'dict',
                'fast': {
                    'type': 'int',
                },
                'slow': {
                    'type': 'int',
                }
            },
            'mode': {
                'type': 'str',
                'choices': ['active', 'passive']
            },
            'timeout': {
                'type': 'str',
                'choices': ['long', 'short']
            },
            'uuid': {
                'type': 'str',
            },
            'user_tag': {
                'type': 'str',
            }
        },
        'bfd': {
            'type': 'dict',
            'authentication': {
                'type': 'dict',
                'key_id': {
                    'type': 'int',
                },
                'method': {
                    'type':
                    'str',
                    'choices': [
                        'md5', 'meticulous-md5', 'meticulous-sha1', 'sha1',
                        'simple'
                    ]
                },
                'password': {
                    'type': 'str',
                },
                'encrypted': {
                    'type': 'str',
                }
            },
            'echo': {
                'type': 'bool',
            },
            'demand': {
                'type': 'bool',
            },
            'interval_cfg': {
                'type': 'dict',
                'interval': {
                    'type': 'int',
                },
                'min_rx': {
                    'type': 'int',
                },
                'multiplier': {
                    'type': 'int',
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'isis': {
            'type': 'dict',
            'authentication': {
                'type': 'dict',
                'send_only_list': {
                    'type': 'list',
                    'send_only': {
                        'type': 'bool',
                    },
                    'level': {
                        'type': 'str',
                        'choices': ['level-1', 'level-2']
                    }
                },
                'mode_list': {
                    'type': 'list',
                    'mode': {
                        'type': 'str',
                        'choices': ['md5']
                    },
                    'level': {
                        'type': 'str',
                        'choices': ['level-1', 'level-2']
                    }
                },
                'key_chain_list': {
                    'type': 'list',
                    'key_chain': {
                        'type': 'str',
                    },
                    'level': {
                        'type': 'str',
                        'choices': ['level-1', 'level-2']
                    }
                }
            },
            'bfd_cfg': {
                'type': 'dict',
                'bfd': {
                    'type': 'bool',
                },
                'disable': {
                    'type': 'bool',
                }
            },
            'circuit_type': {
                'type': 'str',
                'choices': ['level-1', 'level-1-2', 'level-2-only']
            },
            'csnp_interval_list': {
                'type': 'list',
                'csnp_interval': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'padding': {
                'type': 'bool',
            },
            'hello_interval_list': {
                'type': 'list',
                'hello_interval': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'hello_interval_minimal_list': {
                'type': 'list',
                'hello_interval_minimal': {
                    'type': 'bool',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'hello_multiplier_list': {
                'type': 'list',
                'hello_multiplier': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'lsp_interval': {
                'type': 'int',
            },
            'mesh_group': {
                'type': 'dict',
                'value': {
                    'type': 'int',
                },
                'blocked': {
                    'type': 'bool',
                }
            },
            'metric_list': {
                'type': 'list',
                'metric': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'network': {
                'type': 'str',
                'choices': ['broadcast', 'point-to-point']
            },
            'password_list': {
                'type': 'list',
                'password': {
                    'type': 'str',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'priority_list': {
                'type': 'list',
                'priority': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'retransmit_interval': {
                'type': 'int',
            },
            'wide_metric_list': {
                'type': 'list',
                'wide_metric': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'oper': {
            'type': 'dict',
            'state': {
                'type': 'str',
                'choices': ['up', 'disabled', 'down']
            },
            'line_protocol': {
                'type': 'str',
                'choices': ['up', 'down']
            },
            'link_type': {
                'type': 'str',
                'choices': ['GigabitEthernet', '10Gig', '40Gig']
            },
            'mac': {
                'type': 'str',
            },
            'config_speed': {
                'type':
                'str',
                'choices':
                ['10Mbit', '100Mbit', '1Gbit', '10Gbit', '40Gbit', 'auto']
            },
            'actual_speed': {
                'type':
                'str',
                'choices':
                ['10Mbit', '100Mbit', '1Gbit', '10Gbit', '40Gbit', 'unknown']
            },
            'config_duplexity': {
                'type': 'str',
                'choices': ['Full', 'fdx', 'Half', 'hdx', 'auto']
            },
            'actual_duplexity': {
                'type': 'str',
                'choices': ['Full', 'fdx', 'Half', 'hdx', 'auto']
            },
            'media_type': {
                'type': 'str',
                'choices': ['Copper', 'Fiber']
            },
            'ipv4_address': {
                'type': 'str',
            },
            'ipv4_netmask': {
                'type': 'str',
            },
            'ipv4_addr_count': {
                'type': 'int',
            },
            'ipv4_list': {
                'type': 'list',
                'addr': {
                    'type': 'str',
                },
                'mask': {
                    'type': 'str',
                }
            },
            'ipv6_addr_count': {
                'type': 'int',
            },
            'ipv6_list': {
                'type': 'list',
                'addr': {
                    'type': 'str',
                },
                'prefix': {
                    'type': 'str',
                },
                'is_anycast': {
                    'type': 'int',
                }
            },
            'ipv6_link_local': {
                'type': 'str',
            },
            'ipv6_link_local_prefix': {
                'type': 'str',
            },
            'ipv6_link_local_type': {
                'type': 'str',
            },
            'ipv6_link_local_scope': {
                'type': 'str',
            },
            'igmp_query_sent': {
                'type': 'int',
            },
            'icmp_rate_limit_current': {
                'type': 'int',
            },
            'icmp_rate_over_limit_drop': {
                'type': 'int',
            },
            'icmp6_rate_limit_current': {
                'type': 'int',
            },
            'icmp6_rate_over_limit_drop': {
                'type': 'int',
            },
            'is_tagged': {
                'type': 'int',
            },
            'vlan_id': {
                'type': 'int',
            },
            'tagged_vlan_list': {
                'type': 'str',
            },
            'is_lead_member': {
                'type': 'int',
            },
            'current_vnp_id': {
                'type': 'int',
            },
            'port_vnp_id': {
                'type': 'int',
            },
            'is_pristine': {
                'type': 'int',
            },
            'rate_byte_rcvd': {
                'type': 'int',
            },
            'rate_byte_sent': {
                'type': 'int',
            },
            'rate_pkt_rcvd': {
                'type': 'int',
            },
            'rate_pkt_sent': {
                'type': 'int',
            },
            'input_utilization': {
                'type': 'int',
            },
            'output_utilization': {
                'type': 'int',
            },
            'is_device_transparent': {
                'type': 'int',
            },
            'incoming_pkts_mirrored': {
                'type': 'int',
            },
            'outgoing_pkts_mirrored': {
                'type': 'int',
            },
            'incoming_pkts_monitored': {
                'type': 'int',
            },
            'outgoing_pkts_monitored': {
                'type': 'int',
            },
            'ifnum': {
                'type': 'str',
                'required': True,
            }
        },
        'stats': {
            'type': 'dict',
            'packets_input': {
                'type': 'str',
            },
            'bytes_input': {
                'type': 'str',
            },
            'received_broadcasts': {
                'type': 'str',
            },
            'received_multicasts': {
                'type': 'str',
            },
            'received_unicasts': {
                'type': 'str',
            },
            'input_errors': {
                'type': 'str',
            },
            'crc': {
                'type': 'str',
            },
            'frame': {
                'type': 'str',
            },
            'runts': {
                'type': 'str',
            },
            'giants': {
                'type': 'str',
            },
            'packets_output': {
                'type': 'str',
            },
            'bytes_output': {
                'type': 'str',
            },
            'transmitted_broadcasts': {
                'type': 'str',
            },
            'transmitted_multicasts': {
                'type': 'str',
            },
            'transmitted_unicasts': {
                'type': 'str',
            },
            'output_errors': {
                'type': 'str',
            },
            'collisions': {
                'type': 'str',
            },
            'giants_output': {
                'type': 'str',
            },
            'rate_pkt_sent': {
                'type': 'str',
            },
            'rate_byte_sent': {
                'type': 'str',
            },
            'rate_pkt_rcvd': {
                'type': 'str',
            },
            'rate_byte_rcvd': {
                'type': 'str',
            },
            'load_interval': {
                'type': 'str',
            },
            'ifnum': {
                'type': 'str',
                'required': True,
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/ethernet/{ifnum}"

    f_dict = {}
    f_dict["ifnum"] = module.params["ifnum"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/interface/ethernet/{ifnum}"

    f_dict = {}
    f_dict["ifnum"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["ethernet"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["ethernet"].get(k) != v:
            change_results["changed"] = True
            config_changes["ethernet"][k] = v

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
    payload = utils.build_json("ethernet", module.params, AVAILABLE_PROPERTIES)
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
                    "ethernet"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "ethernet-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client,
                                                      existing_url(module),
                                                      params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["ethernet"][
                    "oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client,
                                                       existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["ethernet"][
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
