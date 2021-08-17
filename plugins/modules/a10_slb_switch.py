#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_switch
description:
    - Configure slb switch
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
                - "'all'= all; 'fwlb'= FWLB; 'licexpire_drop'= License Expire Drop; 'bwl_drop'= BW
          Limit Drop; 'rx_kernel'= Received kernel; 'rx_arp_req'= ARP REQ Rcvd;
          'rx_arp_resp'= ARP RESP Rcvd; 'vlan_flood'= VLAN Flood; 'l2_def_vlan_drop'= L2
          Default Vlan FWD Drop; 'ipv4_noroute_drop'= IPv4 No Route Drop;
          'ipv6_noroute_drop'= IPv6 No Route Drop; 'prot_down_drop'= Prot Down Drop;
          'l2_forward'= L2 Forward; 'l3_forward_ip'= L3 IP Forward; 'l3_forward_ipv6'= L3
          IPv6 Forward; 'l4_process'= L4 Process; 'unknown_prot_drop'= Unknown Prot Drop;
          'ttl_exceeded_drop'= TTL Exceeded Drop; 'linkdown_drop'= Link Down Drop;
          'sport_drop'= SPORT Drop; 'incorrect_len_drop'= Incorrect Length Drop;
          'ip_defrag'= IP Defrag; 'acl_deny'= ACL Denys; 'ipfrag_tcp'= IP(TCP) Fragment
          Rcvd; 'ipfrag_overlap'= IP Fragment Overlap; 'ipfrag_timeout'= IP Fragment
          Timeout; 'ipfrag_overload'= IP Frag Overload Drops; 'ipfrag_reasmoks'= IP
          Fragment Reasm OKs; 'ipfrag_reasmfails'= IP Fragment Reasm Fails; 'land_drop'=
          Anomaly Land Attack Drop; 'ipoptions_drop'= Anomaly IP OPT Drops;
          'badpkt_drop'= Bad Pkt Drop; 'pingofdeath_drop'= Anomaly PingDeath Drop;
          'allfrag_drop'= Anomaly All Frag Drop; 'tcpnoflag_drop'= Anomaly TCP noFlag
          Drop; 'tcpsynfrag_drop'= Anomaly SYN Frag Drop; 'tcpsynfin_drop'= Anomaly TCP
          SYNFIN Drop; 'ipsec_drop'= IPSec Drop; 'bpdu_rcvd'= BPDUs Received;
          'bpdu_sent'= BPDUs Sent; 'ctrl_syn_rate_drop'= SYN rate exceeded Drop;
          'ip_defrag_invalid_len'= IP Invalid Length Frag; 'ipv4_frag_6rd_ok'= IPv4 Frag
          6RD OK; 'ipv4_frag_6rd_drop'= IPv4 Frag 6RD Dropped; 'no_ip_drop'= No IP Drop;
          'ipv6frag_udp'= IPv6 Frag UDP; 'ipv6frag_udp_dropped'= IPv6 Frag UDP Dropped;
          'ipv6frag_tcp_dropped'= IPv6 Frag TCP Dropped; 'ipv6frag_ipip_ok'= IPv6 Frag
          IPIP OKs; 'ipv6frag_ipip_dropped'= IPv6 Frag IPIP Drop; 'ip_frag_oversize'= IP
          Fragment oversize; 'ip_frag_too_many'= IP Fragment too many;
          'ipv4_novlanfwd_drop'= IPv4 No L3 VLAN FWD Drop; 'ipv6_novlanfwd_drop'= IPv6 No
          L3 VLAN FWD Drop; 'fpga_error_pkt1'= FPGA Error PKT1; 'fpga_error_pkt2'= FPGA
          Error PKT2; 'max_arp_drop'= Max ARP Drop; 'ipv6frag_tcp'= IPv6 Frag TCP;
          'ipv6frag_icmp'= IPv6 Frag ICMP; 'ipv6frag_ospf'= IPv6 Frag OSPF;
          'ipv6frag_esp'= IPv6 Frag ESP; 'l4_in_ctrl_cpu'= L4 In Ctrl CPU;
          'mgmt_svc_drop'= Management Service Drop; 'jumbo_frag_drop'= Jumbo Frag Drop;
          'ipv6_jumbo_frag_drop'= IPv6 Jumbo Frag Drop; 'ipipv6_jumbo_frag_drop'= IPIPv6
          Jumbo Frag Drop; 'ipv6_ndisc_dad_solicits'= IPv6 DAD on Solicits;
          'ipv6_ndisc_dad_adverts'= IPv6 DAD on Adverts; 'ipv6_ndisc_mac_changes'= IPv6
          DAD MAC Changed; 'ipv6_ndisc_out_of_memory'= IPv6 DAD Out-of-memory;
          'sp_non_ctrl_pkt_drop'= Shared IP mode non ctrl packet to linux drop;
          'urpf_pkt_drop'= URPF check packet drop; 'fw_smp_zone_mismatch'= FW SMP Zone
          Mismatch; 'ipfrag_udp'= IP(UDP) Fragment Rcvd; 'ipfrag_icmp'= IP(ICMP) Fragment
          Rcvd; 'ipfrag_ospf'= IP(OSPF) Fragment Rcvd; 'ipfrag_esp'= IP(ESP) Fragment
          Rcvd; 'ipfrag_tcp_dropped'= IP Frag TCP Dropped; 'ipfrag_udp_dropped'= IP Frag
          UDP Dropped; 'ipfrag_ipip_dropped'= IP Frag IPIP Drop; 'redirect_fwd_fail'=
          Redirect failed in the fwd direction; 'redirect_fwd_sent'= Redirect succeeded
          in the fwd direction; 'redirect_rev_fail'= Redirect failed in the rev
          direction; 'redirect_rev_sent'= Redirect succeeded in the rev direction;
          'redirect_setup_fail'= Redirect connection setup failed; 'ip_frag_sent'= IP
          frag sent; 'invalid_rx_arp_pkt'= Invalid ARP PKT Rcvd;
          'invalid_sender_mac_arp_drop'= ARP PKT dropped due to invalid sender MAC;
          'dev_based_arp_drop'= ARP PKT dropped due to interface state checks;
          'scaleout_arp_drop'= ARP PKT dropped due to scaleout checks;
          'virtual_ip_not_found_arp_drop'= ARP PKT dropped due to virtual IP not found;
          'inactive_static_nat_pool_arp_drop'= ARP PKT dropped due to inactive static nat
          pool; 'inactive_nat_pool_arp_drop'= ARP PKT dropped due to inactive nat pool;
          'scaleout_hairpin_arp_drop'= ARP PKT dropped due to scaleout hairpin checks;
          'self_grat_arp_drop'= Self generated grat ARP PKT dropped;
          'self_grat_nat_ip_arp_drop'= Self generated grat ARP PKT dropped for NAT IP;
          'ip_not_found_arp_drop'= ARP PKT dropped due to IP not found;
          'dev_link_down_arp_drop'= ARP PKT dropped due to interface is down;
          'lacp_tx_intf_err_drop'= LACP interface error corrected;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            fwlb:
                description:
                - "FWLB"
                type: str
            licexpire_drop:
                description:
                - "License Expire Drop"
                type: str
            bwl_drop:
                description:
                - "BW Limit Drop"
                type: str
            rx_kernel:
                description:
                - "Received kernel"
                type: str
            rx_arp_req:
                description:
                - "ARP REQ Rcvd"
                type: str
            rx_arp_resp:
                description:
                - "ARP RESP Rcvd"
                type: str
            vlan_flood:
                description:
                - "VLAN Flood"
                type: str
            l2_def_vlan_drop:
                description:
                - "L2 Default Vlan FWD Drop"
                type: str
            ipv4_noroute_drop:
                description:
                - "IPv4 No Route Drop"
                type: str
            ipv6_noroute_drop:
                description:
                - "IPv6 No Route Drop"
                type: str
            prot_down_drop:
                description:
                - "Prot Down Drop"
                type: str
            l2_forward:
                description:
                - "L2 Forward"
                type: str
            l3_forward_ip:
                description:
                - "L3 IP Forward"
                type: str
            l3_forward_ipv6:
                description:
                - "L3 IPv6 Forward"
                type: str
            l4_process:
                description:
                - "L4 Process"
                type: str
            unknown_prot_drop:
                description:
                - "Unknown Prot Drop"
                type: str
            ttl_exceeded_drop:
                description:
                - "TTL Exceeded Drop"
                type: str
            linkdown_drop:
                description:
                - "Link Down Drop"
                type: str
            sport_drop:
                description:
                - "SPORT Drop"
                type: str
            incorrect_len_drop:
                description:
                - "Incorrect Length Drop"
                type: str
            ip_defrag:
                description:
                - "IP Defrag"
                type: str
            acl_deny:
                description:
                - "ACL Denys"
                type: str
            ipfrag_tcp:
                description:
                - "IP(TCP) Fragment Rcvd"
                type: str
            ipfrag_overlap:
                description:
                - "IP Fragment Overlap"
                type: str
            ipfrag_timeout:
                description:
                - "IP Fragment Timeout"
                type: str
            ipfrag_overload:
                description:
                - "IP Frag Overload Drops"
                type: str
            ipfrag_reasmoks:
                description:
                - "IP Fragment Reasm OKs"
                type: str
            ipfrag_reasmfails:
                description:
                - "IP Fragment Reasm Fails"
                type: str
            badpkt_drop:
                description:
                - "Bad Pkt Drop"
                type: str
            ipsec_drop:
                description:
                - "IPSec Drop"
                type: str
            bpdu_rcvd:
                description:
                - "BPDUs Received"
                type: str
            bpdu_sent:
                description:
                - "BPDUs Sent"
                type: str
            ctrl_syn_rate_drop:
                description:
                - "SYN rate exceeded Drop"
                type: str
            ip_defrag_invalid_len:
                description:
                - "IP Invalid Length Frag"
                type: str
            ipv4_frag_6rd_ok:
                description:
                - "IPv4 Frag 6RD OK"
                type: str
            ipv4_frag_6rd_drop:
                description:
                - "IPv4 Frag 6RD Dropped"
                type: str
            no_ip_drop:
                description:
                - "No IP Drop"
                type: str
            ipv6frag_udp:
                description:
                - "IPv6 Frag UDP"
                type: str
            ipv6frag_udp_dropped:
                description:
                - "IPv6 Frag UDP Dropped"
                type: str
            ipv6frag_tcp_dropped:
                description:
                - "IPv6 Frag TCP Dropped"
                type: str
            ipv6frag_ipip_ok:
                description:
                - "IPv6 Frag IPIP OKs"
                type: str
            ipv6frag_ipip_dropped:
                description:
                - "IPv6 Frag IPIP Drop"
                type: str
            ip_frag_oversize:
                description:
                - "IP Fragment oversize"
                type: str
            ip_frag_too_many:
                description:
                - "IP Fragment too many"
                type: str
            ipv4_novlanfwd_drop:
                description:
                - "IPv4 No L3 VLAN FWD Drop"
                type: str
            ipv6_novlanfwd_drop:
                description:
                - "IPv6 No L3 VLAN FWD Drop"
                type: str
            fpga_error_pkt1:
                description:
                - "FPGA Error PKT1"
                type: str
            fpga_error_pkt2:
                description:
                - "FPGA Error PKT2"
                type: str
            max_arp_drop:
                description:
                - "Max ARP Drop"
                type: str
            ipv6frag_tcp:
                description:
                - "IPv6 Frag TCP"
                type: str
            ipv6frag_icmp:
                description:
                - "IPv6 Frag ICMP"
                type: str
            ipv6frag_ospf:
                description:
                - "IPv6 Frag OSPF"
                type: str
            ipv6frag_esp:
                description:
                - "IPv6 Frag ESP"
                type: str
            l4_in_ctrl_cpu:
                description:
                - "L4 In Ctrl CPU"
                type: str
            mgmt_svc_drop:
                description:
                - "Management Service Drop"
                type: str
            jumbo_frag_drop:
                description:
                - "Jumbo Frag Drop"
                type: str
            ipv6_jumbo_frag_drop:
                description:
                - "IPv6 Jumbo Frag Drop"
                type: str
            ipipv6_jumbo_frag_drop:
                description:
                - "IPIPv6 Jumbo Frag Drop"
                type: str
            ipv6_ndisc_dad_solicits:
                description:
                - "IPv6 DAD on Solicits"
                type: str
            ipv6_ndisc_dad_adverts:
                description:
                - "IPv6 DAD on Adverts"
                type: str
            ipv6_ndisc_mac_changes:
                description:
                - "IPv6 DAD MAC Changed"
                type: str
            ipv6_ndisc_out_of_memory:
                description:
                - "IPv6 DAD Out-of-memory"
                type: str
            sp_non_ctrl_pkt_drop:
                description:
                - "Shared IP mode non ctrl packet to linux drop"
                type: str
            urpf_pkt_drop:
                description:
                - "URPF check packet drop"
                type: str
            fw_smp_zone_mismatch:
                description:
                - "FW SMP Zone Mismatch"
                type: str
            ipfrag_udp:
                description:
                - "IP(UDP) Fragment Rcvd"
                type: str
            ipfrag_icmp:
                description:
                - "IP(ICMP) Fragment Rcvd"
                type: str
            ipfrag_ospf:
                description:
                - "IP(OSPF) Fragment Rcvd"
                type: str
            ipfrag_esp:
                description:
                - "IP(ESP) Fragment Rcvd"
                type: str
            ipfrag_tcp_dropped:
                description:
                - "IP Frag TCP Dropped"
                type: str
            ipfrag_udp_dropped:
                description:
                - "IP Frag UDP Dropped"
                type: str
            ipfrag_ipip_dropped:
                description:
                - "IP Frag IPIP Drop"
                type: str
            redirect_fwd_fail:
                description:
                - "Redirect failed in the fwd direction"
                type: str
            redirect_fwd_sent:
                description:
                - "Redirect succeeded in the fwd direction"
                type: str
            redirect_rev_fail:
                description:
                - "Redirect failed in the rev direction"
                type: str
            redirect_rev_sent:
                description:
                - "Redirect succeeded in the rev direction"
                type: str
            redirect_setup_fail:
                description:
                - "Redirect connection setup failed"
                type: str
            ip_frag_sent:
                description:
                - "IP frag sent"
                type: str
            invalid_rx_arp_pkt:
                description:
                - "Invalid ARP PKT Rcvd"
                type: str
            invalid_sender_mac_arp_drop:
                description:
                - "ARP PKT dropped due to invalid sender MAC"
                type: str
            dev_based_arp_drop:
                description:
                - "ARP PKT dropped due to interface state checks"
                type: str
            scaleout_arp_drop:
                description:
                - "ARP PKT dropped due to scaleout checks"
                type: str
            virtual_ip_not_found_arp_drop:
                description:
                - "ARP PKT dropped due to virtual IP not found"
                type: str
            inactive_static_nat_pool_arp_drop:
                description:
                - "ARP PKT dropped due to inactive static nat pool"
                type: str
            inactive_nat_pool_arp_drop:
                description:
                - "ARP PKT dropped due to inactive nat pool"
                type: str
            scaleout_hairpin_arp_drop:
                description:
                - "ARP PKT dropped due to scaleout hairpin checks"
                type: str
            self_grat_arp_drop:
                description:
                - "Self generated grat ARP PKT dropped"
                type: str
            self_grat_nat_ip_arp_drop:
                description:
                - "Self generated grat ARP PKT dropped for NAT IP"
                type: str
            ip_not_found_arp_drop:
                description:
                - "ARP PKT dropped due to IP not found"
                type: str
            dev_link_down_arp_drop:
                description:
                - "ARP PKT dropped due to interface is down"
                type: str
            lacp_tx_intf_err_drop:
                description:
                - "LACP interface error corrected"
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

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
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
                    'all', 'fwlb', 'licexpire_drop', 'bwl_drop', 'rx_kernel',
                    'rx_arp_req', 'rx_arp_resp', 'vlan_flood',
                    'l2_def_vlan_drop', 'ipv4_noroute_drop',
                    'ipv6_noroute_drop', 'prot_down_drop', 'l2_forward',
                    'l3_forward_ip', 'l3_forward_ipv6', 'l4_process',
                    'unknown_prot_drop', 'ttl_exceeded_drop', 'linkdown_drop',
                    'sport_drop', 'incorrect_len_drop', 'ip_defrag',
                    'acl_deny', 'ipfrag_tcp', 'ipfrag_overlap',
                    'ipfrag_timeout', 'ipfrag_overload', 'ipfrag_reasmoks',
                    'ipfrag_reasmfails', 'land_drop', 'ipoptions_drop',
                    'badpkt_drop', 'pingofdeath_drop', 'allfrag_drop',
                    'tcpnoflag_drop', 'tcpsynfrag_drop', 'tcpsynfin_drop',
                    'ipsec_drop', 'bpdu_rcvd', 'bpdu_sent',
                    'ctrl_syn_rate_drop', 'ip_defrag_invalid_len',
                    'ipv4_frag_6rd_ok', 'ipv4_frag_6rd_drop', 'no_ip_drop',
                    'ipv6frag_udp', 'ipv6frag_udp_dropped',
                    'ipv6frag_tcp_dropped', 'ipv6frag_ipip_ok',
                    'ipv6frag_ipip_dropped', 'ip_frag_oversize',
                    'ip_frag_too_many', 'ipv4_novlanfwd_drop',
                    'ipv6_novlanfwd_drop', 'fpga_error_pkt1',
                    'fpga_error_pkt2', 'max_arp_drop', 'ipv6frag_tcp',
                    'ipv6frag_icmp', 'ipv6frag_ospf', 'ipv6frag_esp',
                    'l4_in_ctrl_cpu', 'mgmt_svc_drop', 'jumbo_frag_drop',
                    'ipv6_jumbo_frag_drop', 'ipipv6_jumbo_frag_drop',
                    'ipv6_ndisc_dad_solicits', 'ipv6_ndisc_dad_adverts',
                    'ipv6_ndisc_mac_changes', 'ipv6_ndisc_out_of_memory',
                    'sp_non_ctrl_pkt_drop', 'urpf_pkt_drop',
                    'fw_smp_zone_mismatch', 'ipfrag_udp', 'ipfrag_icmp',
                    'ipfrag_ospf', 'ipfrag_esp', 'ipfrag_tcp_dropped',
                    'ipfrag_udp_dropped', 'ipfrag_ipip_dropped',
                    'redirect_fwd_fail', 'redirect_fwd_sent',
                    'redirect_rev_fail', 'redirect_rev_sent',
                    'redirect_setup_fail', 'ip_frag_sent',
                    'invalid_rx_arp_pkt', 'invalid_sender_mac_arp_drop',
                    'dev_based_arp_drop', 'scaleout_arp_drop',
                    'virtual_ip_not_found_arp_drop',
                    'inactive_static_nat_pool_arp_drop',
                    'inactive_nat_pool_arp_drop', 'scaleout_hairpin_arp_drop',
                    'self_grat_arp_drop', 'self_grat_nat_ip_arp_drop',
                    'ip_not_found_arp_drop', 'dev_link_down_arp_drop',
                    'lacp_tx_intf_err_drop'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'fwlb': {
                'type': 'str',
            },
            'licexpire_drop': {
                'type': 'str',
            },
            'bwl_drop': {
                'type': 'str',
            },
            'rx_kernel': {
                'type': 'str',
            },
            'rx_arp_req': {
                'type': 'str',
            },
            'rx_arp_resp': {
                'type': 'str',
            },
            'vlan_flood': {
                'type': 'str',
            },
            'l2_def_vlan_drop': {
                'type': 'str',
            },
            'ipv4_noroute_drop': {
                'type': 'str',
            },
            'ipv6_noroute_drop': {
                'type': 'str',
            },
            'prot_down_drop': {
                'type': 'str',
            },
            'l2_forward': {
                'type': 'str',
            },
            'l3_forward_ip': {
                'type': 'str',
            },
            'l3_forward_ipv6': {
                'type': 'str',
            },
            'l4_process': {
                'type': 'str',
            },
            'unknown_prot_drop': {
                'type': 'str',
            },
            'ttl_exceeded_drop': {
                'type': 'str',
            },
            'linkdown_drop': {
                'type': 'str',
            },
            'sport_drop': {
                'type': 'str',
            },
            'incorrect_len_drop': {
                'type': 'str',
            },
            'ip_defrag': {
                'type': 'str',
            },
            'acl_deny': {
                'type': 'str',
            },
            'ipfrag_tcp': {
                'type': 'str',
            },
            'ipfrag_overlap': {
                'type': 'str',
            },
            'ipfrag_timeout': {
                'type': 'str',
            },
            'ipfrag_overload': {
                'type': 'str',
            },
            'ipfrag_reasmoks': {
                'type': 'str',
            },
            'ipfrag_reasmfails': {
                'type': 'str',
            },
            'badpkt_drop': {
                'type': 'str',
            },
            'ipsec_drop': {
                'type': 'str',
            },
            'bpdu_rcvd': {
                'type': 'str',
            },
            'bpdu_sent': {
                'type': 'str',
            },
            'ctrl_syn_rate_drop': {
                'type': 'str',
            },
            'ip_defrag_invalid_len': {
                'type': 'str',
            },
            'ipv4_frag_6rd_ok': {
                'type': 'str',
            },
            'ipv4_frag_6rd_drop': {
                'type': 'str',
            },
            'no_ip_drop': {
                'type': 'str',
            },
            'ipv6frag_udp': {
                'type': 'str',
            },
            'ipv6frag_udp_dropped': {
                'type': 'str',
            },
            'ipv6frag_tcp_dropped': {
                'type': 'str',
            },
            'ipv6frag_ipip_ok': {
                'type': 'str',
            },
            'ipv6frag_ipip_dropped': {
                'type': 'str',
            },
            'ip_frag_oversize': {
                'type': 'str',
            },
            'ip_frag_too_many': {
                'type': 'str',
            },
            'ipv4_novlanfwd_drop': {
                'type': 'str',
            },
            'ipv6_novlanfwd_drop': {
                'type': 'str',
            },
            'fpga_error_pkt1': {
                'type': 'str',
            },
            'fpga_error_pkt2': {
                'type': 'str',
            },
            'max_arp_drop': {
                'type': 'str',
            },
            'ipv6frag_tcp': {
                'type': 'str',
            },
            'ipv6frag_icmp': {
                'type': 'str',
            },
            'ipv6frag_ospf': {
                'type': 'str',
            },
            'ipv6frag_esp': {
                'type': 'str',
            },
            'l4_in_ctrl_cpu': {
                'type': 'str',
            },
            'mgmt_svc_drop': {
                'type': 'str',
            },
            'jumbo_frag_drop': {
                'type': 'str',
            },
            'ipv6_jumbo_frag_drop': {
                'type': 'str',
            },
            'ipipv6_jumbo_frag_drop': {
                'type': 'str',
            },
            'ipv6_ndisc_dad_solicits': {
                'type': 'str',
            },
            'ipv6_ndisc_dad_adverts': {
                'type': 'str',
            },
            'ipv6_ndisc_mac_changes': {
                'type': 'str',
            },
            'ipv6_ndisc_out_of_memory': {
                'type': 'str',
            },
            'sp_non_ctrl_pkt_drop': {
                'type': 'str',
            },
            'urpf_pkt_drop': {
                'type': 'str',
            },
            'fw_smp_zone_mismatch': {
                'type': 'str',
            },
            'ipfrag_udp': {
                'type': 'str',
            },
            'ipfrag_icmp': {
                'type': 'str',
            },
            'ipfrag_ospf': {
                'type': 'str',
            },
            'ipfrag_esp': {
                'type': 'str',
            },
            'ipfrag_tcp_dropped': {
                'type': 'str',
            },
            'ipfrag_udp_dropped': {
                'type': 'str',
            },
            'ipfrag_ipip_dropped': {
                'type': 'str',
            },
            'redirect_fwd_fail': {
                'type': 'str',
            },
            'redirect_fwd_sent': {
                'type': 'str',
            },
            'redirect_rev_fail': {
                'type': 'str',
            },
            'redirect_rev_sent': {
                'type': 'str',
            },
            'redirect_setup_fail': {
                'type': 'str',
            },
            'ip_frag_sent': {
                'type': 'str',
            },
            'invalid_rx_arp_pkt': {
                'type': 'str',
            },
            'invalid_sender_mac_arp_drop': {
                'type': 'str',
            },
            'dev_based_arp_drop': {
                'type': 'str',
            },
            'scaleout_arp_drop': {
                'type': 'str',
            },
            'virtual_ip_not_found_arp_drop': {
                'type': 'str',
            },
            'inactive_static_nat_pool_arp_drop': {
                'type': 'str',
            },
            'inactive_nat_pool_arp_drop': {
                'type': 'str',
            },
            'scaleout_hairpin_arp_drop': {
                'type': 'str',
            },
            'self_grat_arp_drop': {
                'type': 'str',
            },
            'self_grat_nat_ip_arp_drop': {
                'type': 'str',
            },
            'ip_not_found_arp_drop': {
                'type': 'str',
            },
            'dev_link_down_arp_drop': {
                'type': 'str',
            },
            'lacp_tx_intf_err_drop': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/switch"

    f_dict = {}

    return url_base.format(**f_dict)


def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def _get(module, url, params={}):

    resp = None
    try:
        resp = module.client.get(url, params=params)
    except a10_ex.NotFound:
        resp = "Not Found"

    call_result = {
        "endpoint": url,
        "http_method": "GET",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _post(module, url, params={}, file_content=None, file_name=None):
    resp = module.client.post(url, params=params)
    resp = resp if resp else {}
    call_result = {
        "endpoint": url,
        "http_method": "POST",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _delete(module, url):
    call_result = {
        "endpoint": url,
        "http_method": "DELETE",
        "request_body": {},
        "response_body": module.client.delete(url),
    }
    return call_result


def _switch_device_context(module, device_id):
    call_result = {
        "endpoint": "/axapi/v3/device-context",
        "http_method": "POST",
        "request_body": {
            "device-id": device_id
        },
        "response_body": module.client.change_context(device_id)
    }
    return call_result


def _active_partition(module, a10_partition):
    call_result = {
        "endpoint": "/axapi/v3/active-partition",
        "http_method": "POST",
        "request_body": {
            "curr_part_name": a10_partition
        },
        "response_body": module.client.activate_partition(a10_partition)
    }
    return call_result


def get(module):
    return _get(module, existing_url(module))


def get_list(module):
    return _get(module, list_url(module))


def get_stats(module):
    query_params = {}
    if module.params.get("stats"):
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, stats_url(module), params=query_params)


def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")


def _build_dict_from_param(param):
    rv = {}

    for k, v in param.items():
        hk = _to_axapi(k)
        if isinstance(v, dict):
            v_dict = _build_dict_from_param(v)
            rv[hk] = v_dict
        elif isinstance(v, list):
            nv = [_build_dict_from_param(x) for x in v]
            rv[hk] = nv
        else:
            rv[hk] = v

    return rv


def build_envelope(title, data):
    return {title: data}


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/switch"

    f_dict = {}

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v is not None:
            rx = _to_axapi(x)

            if isinstance(v, dict):
                nv = _build_dict_from_param(v)
                rv[rx] = nv
            elif isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["switch"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["switch"].get(k) != v:
            change_results["changed"] = True
            config_changes["switch"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload):
    try:
        call_result = _post(module, new_url(module), payload)
        result["axapi_calls"].append(call_result)
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        module.client.session.close()
    return result


def update(module, result, existing_config, payload):
    try:
        call_result = _post(module, existing_url(module), payload)
        result["axapi_calls"].append(call_result)
        if call_result["response_body"] == existing_config:
            result["changed"] = False
        else:
            result["modified_values"].update(**call_result["response_body"])
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        module.client.session.close()
    return result


def present(module, result, existing_config):
    payload = build_json("switch", module)
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
        call_result = _delete(module, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        module.client.session.close()
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

    return delete(module, result)


def replace(module, result, existing_config, payload):
    try:
        post_result = module.client.put(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        module.client.session.close()
    return result


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

    valid = True

    run_errors = []
    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        result["axapi_calls"].append(_active_partition(module, a10_partition))

    if a10_device_context_id:
        result["axapi_calls"].append(
            _switch_device_context(module, a10_device_context_id))

    existing_config = get(module)
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
            result["axapi_calls"].append(get(module))
        elif module.params.get("get_type") == "list":
            result["axapi_calls"].append(get_list(module))
        elif module.params.get("get_type") == "stats":
            result["axapi_calls"].append(get_stats(module))

    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
