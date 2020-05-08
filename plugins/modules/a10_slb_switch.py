#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_slb_switch
description:
    - Configure slb switch
short_description: Configures A10 slb.switch
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        required: True
    a10_host:
        description:
        - Host for AXAPI authentication
        required: True
    a10_username:
        description:
        - Username for AXAPI authentication
        required: True
    a10_password:
        description:
        - Password for AXAPI authentication
        required: True
    a10_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_protocol:
        description:
        - Protocol for AXAPI authentication
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'fwlb'= FWLB; 'licexpire_drop'= License Expire Drop; 'bwl_drop'= BW Limit Drop; 'rx_kernel'= Received kernel; 'rx_arp_req'= ARP REQ Rcvd; 'rx_arp_resp'= ARP RESP Rcvd; 'vlan_flood'= VLAN Flood; 'l2_def_vlan_drop'= L2 Default Vlan FWD Drop; 'ipv4_noroute_drop'= IPv4 No Route Drop; 'ipv6_noroute_drop'= IPv6 No Route Drop; 'prot_down_drop'= Prot Down Drop; 'l2_forward'= L2 Forward; 'l3_forward_ip'= L3 IP Forward; 'l3_forward_ipv6'= L3 IPv6 Forward; 'l4_process'= L4 Process; 'unknown_prot_drop'= Unknown Prot Drop; 'ttl_exceeded_drop'= TTL Exceeded Drop; 'linkdown_drop'= Link Down Drop; 'sport_drop'= SPORT Drop; 'incorrect_len_drop'= Incorrect Length Drop; 'ip_defrag'= IP Defrag; 'acl_deny'= ACL Denys; 'ipfrag_tcp'= IP(TCP) Fragment Rcvd; 'ipfrag_overlap'= IP Fragment Overlap; 'ipfrag_timeout'= IP Fragment Timeout; 'ipfrag_overload'= IP Frag Overload Drops; 'ipfrag_reasmoks'= IP Fragment Reasm OKs; 'ipfrag_reasmfails'= IP Fragment Reasm Fails; 'land_drop'= Anomaly Land Attack Drop; 'ipoptions_drop'= Anomaly IP OPT Drops; 'badpkt_drop'= Bad Pkt Drop; 'pingofdeath_drop'= Anomaly PingDeath Drop; 'allfrag_drop'= Anomaly All Frag Drop; 'tcpnoflag_drop'= Anomaly TCP noFlag Drop; 'tcpsynfrag_drop'= Anomaly SYN Frag Drop; 'tcpsynfin_drop'= Anomaly TCP SYNFIN Drop; 'ipsec_drop'= IPSec Drop; 'bpdu_rcvd'= BPDUs Received; 'bpdu_sent'= BPDUs Sent; 'ctrl_syn_rate_drop'= SYN rate exceeded Drop; 'ip_defrag_invalid_len'= IP Invalid Length Frag; 'ipv4_frag_6rd_ok'= IPv4 Frag 6RD OK; 'ipv4_frag_6rd_drop'= IPv4 Frag 6RD Dropped; 'no_ip_drop'= No IP Drop; 'ipv6frag_udp'= IPv6 Frag UDP; 'ipv6frag_udp_dropped'= IPv6 Frag UDP Dropped; 'ipv6frag_tcp_dropped'= IPv6 Frag TCP Dropped; 'ipv6frag_ipip_ok'= IPv6 Frag IPIP OKs; 'ipv6frag_ipip_dropped'= IPv6 Frag IPIP Drop; 'ip_frag_oversize'= IP Fragment oversize; 'ip_frag_too_many'= IP Fragment too many; 'ipv4_novlanfwd_drop'= IPv4 No L3 VLAN FWD Drop; 'ipv6_novlanfwd_drop'= IPv6 No L3 VLAN FWD Drop; 'fpga_error_pkt1'= FPGA Error PKT1; 'fpga_error_pkt2'= FPGA Error PKT2; 'max_arp_drop'= Max ARP Drop; 'ipv6frag_tcp'= IPv6 Frag TCP; 'ipv6frag_icmp'= IPv6 Frag ICMP; 'ipv6frag_ospf'= IPv6 Frag OSPF; 'ipv6frag_esp'= IPv6 Frag ESP; 'l4_in_ctrl_cpu'= L4 In Ctrl CPU; 'mgmt_svc_drop'= Management Service Drop; 'jumbo_frag_drop'= Jumbo Frag Drop; 'ipv6_jumbo_frag_drop'= IPv6 Jumbo Frag Drop; 'ipipv6_jumbo_frag_drop'= IPIPv6 Jumbo Frag Drop; 'ipv6_ndisc_dad_solicits'= IPv6 DAD on Solicits; 'ipv6_ndisc_dad_adverts'= IPv6 DAD on Adverts; 'ipv6_ndisc_mac_changes'= IPv6 DAD MAC Changed; 'ipv6_ndisc_out_of_memory'= IPv6 DAD Out-of-memory; 'sp_non_ctrl_pkt_drop'= Shared IP mode non ctrl packet to linux drop; 'urpf_pkt_drop'= URPF check packet drop; 'fw_smp_zone_mismatch'= FW SMP Zone Mismatch; 'ipfrag_udp'= IP(UDP) Fragment Rcvd; 'ipfrag_icmp'= IP(ICMP) Fragment Rcvd; 'ipfrag_ospf'= IP(OSPF) Fragment Rcvd; 'ipfrag_esp'= IP(ESP) Fragment Rcvd; 'ipfrag_tcp_dropped'= IP Frag TCP Dropped; 'ipfrag_udp_dropped'= IP Frag UDP Dropped; 'ipfrag_ipip_dropped'= IP Frag IPIP Drop; 'redirect_fwd_fail'= Redirect failed in the fwd direction; 'redirect_fwd_sent'= Redirect succeeded in the fwd direction; 'redirect_rev_fail'= Redirect failed in the rev direction; 'redirect_rev_sent'= Redirect succeeded in the rev direction; 'redirect_setup_fail'= Redirect connection setup failed; 'ip_frag_sent'= IP frag sent; 'invalid_rx_arp_pkt'= Invalid ARP PKT Rcvd; 'invalid_sender_mac_arp_drop'= ARP PKT dropped due to invalid sender MAC; 'dev_based_arp_drop'= ARP PKT dropped due to interface state checks; 'scaleout_arp_drop'= ARP PKT dropped due to scaleout checks; 'virtual_ip_not_found_arp_drop'= ARP PKT dropped due to virtual IP not found; 'inactive_static_nat_pool_arp_drop'= ARP PKT dropped due to inactive static nat pool; 'inactive_nat_pool_arp_drop'= ARP PKT dropped due to inactive nat pool; 'scaleout_hairpin_arp_drop'= ARP PKT dropped due to scaleout hairpin checks; 'self_grat_arp_drop'= Self generated grat ARP PKT dropped; 'self_grat_nat_ip_arp_drop'= Self generated grat ARP PKT dropped for NAT IP; 'ip_not_found_arp_drop'= ARP PKT dropped due to IP not found; 'dev_link_down_arp_drop'= ARP PKT dropped due to interface is down; 'lacp_tx_intf_err_drop'= LACP interface error corrected; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            bwl_drop:
                description:
                - "BW Limit Drop"
            ipfrag_tcp:
                description:
                - "IP(TCP) Fragment Rcvd"
            ipipv6_jumbo_frag_drop:
                description:
                - "IPIPv6 Jumbo Frag Drop"
            ipfrag_ospf:
                description:
                - "IP(OSPF) Fragment Rcvd"
            dev_based_arp_drop:
                description:
                - "ARP PKT dropped due to interface state checks"
            rx_arp_resp:
                description:
                - "ARP RESP Rcvd"
            l4_process:
                description:
                - "L4 Process"
            ipv6frag_tcp:
                description:
                - "IPv6 Frag TCP"
            redirect_fwd_sent:
                description:
                - "Redirect succeeded in the fwd direction"
            ipv4_frag_6rd_drop:
                description:
                - "IPv4 Frag 6RD Dropped"
            sport_drop:
                description:
                - "SPORT Drop"
            ipfrag_overlap:
                description:
                - "IP Fragment Overlap"
            bpdu_sent:
                description:
                - "BPDUs Sent"
            invalid_rx_arp_pkt:
                description:
                - "Invalid ARP PKT Rcvd"
            ipfrag_ipip_dropped:
                description:
                - "IP Frag IPIP Drop"
            linkdown_drop:
                description:
                - "Link Down Drop"
            ipfrag_reasmoks:
                description:
                - "IP Fragment Reasm OKs"
            ipv6_novlanfwd_drop:
                description:
                - "IPv6 No L3 VLAN FWD Drop"
            badpkt_drop:
                description:
                - "Bad Pkt Drop"
            l2_forward:
                description:
                - "L2 Forward"
            rx_arp_req:
                description:
                - "ARP REQ Rcvd"
            ipv4_frag_6rd_ok:
                description:
                - "IPv4 Frag 6RD OK"
            no_ip_drop:
                description:
                - "No IP Drop"
            l2_def_vlan_drop:
                description:
                - "L2 Default Vlan FWD Drop"
            ip_frag_sent:
                description:
                - "IP frag sent"
            ipv6frag_tcp_dropped:
                description:
                - "IPv6 Frag TCP Dropped"
            bpdu_rcvd:
                description:
                - "BPDUs Received"
            licexpire_drop:
                description:
                - "License Expire Drop"
            prot_down_drop:
                description:
                - "Prot Down Drop"
            unknown_prot_drop:
                description:
                - "Unknown Prot Drop"
            fpga_error_pkt1:
                description:
                - "FPGA Error PKT1"
            fpga_error_pkt2:
                description:
                - "FPGA Error PKT2"
            ipfrag_udp:
                description:
                - "IP(UDP) Fragment Rcvd"
            mgmt_svc_drop:
                description:
                - "Management Service Drop"
            ipfrag_reasmfails:
                description:
                - "IP Fragment Reasm Fails"
            ip_not_found_arp_drop:
                description:
                - "ARP PKT dropped due to IP not found"
            l3_forward_ip:
                description:
                - "L3 IP Forward"
            l3_forward_ipv6:
                description:
                - "L3 IPv6 Forward"
            ipfrag_overload:
                description:
                - "IP Frag Overload Drops"
            ip_frag_oversize:
                description:
                - "IP Fragment oversize"
            ipfrag_udp_dropped:
                description:
                - "IP Frag UDP Dropped"
            ipv6frag_udp:
                description:
                - "IPv6 Frag UDP"
            jumbo_frag_drop:
                description:
                - "Jumbo Frag Drop"
            ipv6_ndisc_dad_solicits:
                description:
                - "IPv6 DAD on Solicits"
            lacp_tx_intf_err_drop:
                description:
                - "LACP interface error corrected"
            fwlb:
                description:
                - "FWLB"
            redirect_fwd_fail:
                description:
                - "Redirect failed in the fwd direction"
            ipv6frag_ipip_ok:
                description:
                - "IPv6 Frag IPIP OKs"
            ipfrag_esp:
                description:
                - "IP(ESP) Fragment Rcvd"
            redirect_rev_fail:
                description:
                - "Redirect failed in the rev direction"
            rx_kernel:
                description:
                - "Received kernel"
            fw_smp_zone_mismatch:
                description:
                - "FW SMP Zone Mismatch"
            ctrl_syn_rate_drop:
                description:
                - "SYN rate exceeded Drop"
            self_grat_nat_ip_arp_drop:
                description:
                - "Self generated grat ARP PKT dropped for NAT IP"
            ipv6frag_udp_dropped:
                description:
                - "IPv6 Frag UDP Dropped"
            ip_frag_too_many:
                description:
                - "IP Fragment too many"
            ipfrag_tcp_dropped:
                description:
                - "IP Frag TCP Dropped"
            ipv6_jumbo_frag_drop:
                description:
                - "IPv6 Jumbo Frag Drop"
            invalid_sender_mac_arp_drop:
                description:
                - "ARP PKT dropped due to invalid sender MAC"
            inactive_static_nat_pool_arp_drop:
                description:
                - "ARP PKT dropped due to inactive static nat pool"
            ipsec_drop:
                description:
                - "IPSec Drop"
            self_grat_arp_drop:
                description:
                - "Self generated grat ARP PKT dropped"
            inactive_nat_pool_arp_drop:
                description:
                - "ARP PKT dropped due to inactive nat pool"
            scaleout_hairpin_arp_drop:
                description:
                - "ARP PKT dropped due to scaleout hairpin checks"
            urpf_pkt_drop:
                description:
                - "URPF check packet drop"
            l4_in_ctrl_cpu:
                description:
                - "L4 In Ctrl CPU"
            ipfrag_icmp:
                description:
                - "IP(ICMP) Fragment Rcvd"
            redirect_setup_fail:
                description:
                - "Redirect connection setup failed"
            ipfrag_timeout:
                description:
                - "IP Fragment Timeout"
            vlan_flood:
                description:
                - "VLAN Flood"
            scaleout_arp_drop:
                description:
                - "ARP PKT dropped due to scaleout checks"
            ttl_exceeded_drop:
                description:
                - "TTL Exceeded Drop"
            acl_deny:
                description:
                - "ACL Denys"
            ip_defrag:
                description:
                - "IP Defrag"
            incorrect_len_drop:
                description:
                - "Incorrect Length Drop"
            ip_defrag_invalid_len:
                description:
                - "IP Invalid Length Frag"
            ipv6_ndisc_out_of_memory:
                description:
                - "IPv6 DAD Out-of-memory"
            sp_non_ctrl_pkt_drop:
                description:
                - "Shared IP mode non ctrl packet to linux drop"
            virtual_ip_not_found_arp_drop:
                description:
                - "ARP PKT dropped due to virtual IP not found"
            ipv6frag_ipip_dropped:
                description:
                - "IPv6 Frag IPIP Drop"
            ipv6_ndisc_mac_changes:
                description:
                - "IPv6 DAD MAC Changed"
            ipv6_noroute_drop:
                description:
                - "IPv6 No Route Drop"
            ipv6frag_icmp:
                description:
                - "IPv6 Frag ICMP"
            ipv4_noroute_drop:
                description:
                - "IPv4 No Route Drop"
            max_arp_drop:
                description:
                - "Max ARP Drop"
            ipv6_ndisc_dad_adverts:
                description:
                - "IPv6 DAD on Adverts"
            redirect_rev_sent:
                description:
                - "Redirect succeeded in the rev direction"
            ipv6frag_esp:
                description:
                - "IPv6 Frag ESP"
            ipv6frag_ospf:
                description:
                - "IPv6 Frag OSPF"
            dev_link_down_arp_drop:
                description:
                - "ARP PKT dropped due to interface is down"
            ipv4_novlanfwd_drop:
                description:
                - "IPv4 No L3 VLAN FWD Drop"
    uuid:
        description:
        - "uuid of the object"
        required: False


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["sampling_enable","stats","uuid",]

# our imports go at the top so we fail fast.
try:
    from ansible_collections.a10.acos_axapi.plugins.module_utils import errors as a10_ex
    from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import client_factory, session_factory
    from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'fwlb', 'licexpire_drop', 'bwl_drop', 'rx_kernel', 'rx_arp_req', 'rx_arp_resp', 'vlan_flood', 'l2_def_vlan_drop', 'ipv4_noroute_drop', 'ipv6_noroute_drop', 'prot_down_drop', 'l2_forward', 'l3_forward_ip', 'l3_forward_ipv6', 'l4_process', 'unknown_prot_drop', 'ttl_exceeded_drop', 'linkdown_drop', 'sport_drop', 'incorrect_len_drop', 'ip_defrag', 'acl_deny', 'ipfrag_tcp', 'ipfrag_overlap', 'ipfrag_timeout', 'ipfrag_overload', 'ipfrag_reasmoks', 'ipfrag_reasmfails', 'land_drop', 'ipoptions_drop', 'badpkt_drop', 'pingofdeath_drop', 'allfrag_drop', 'tcpnoflag_drop', 'tcpsynfrag_drop', 'tcpsynfin_drop', 'ipsec_drop', 'bpdu_rcvd', 'bpdu_sent', 'ctrl_syn_rate_drop', 'ip_defrag_invalid_len', 'ipv4_frag_6rd_ok', 'ipv4_frag_6rd_drop', 'no_ip_drop', 'ipv6frag_udp', 'ipv6frag_udp_dropped', 'ipv6frag_tcp_dropped', 'ipv6frag_ipip_ok', 'ipv6frag_ipip_dropped', 'ip_frag_oversize', 'ip_frag_too_many', 'ipv4_novlanfwd_drop', 'ipv6_novlanfwd_drop', 'fpga_error_pkt1', 'fpga_error_pkt2', 'max_arp_drop', 'ipv6frag_tcp', 'ipv6frag_icmp', 'ipv6frag_ospf', 'ipv6frag_esp', 'l4_in_ctrl_cpu', 'mgmt_svc_drop', 'jumbo_frag_drop', 'ipv6_jumbo_frag_drop', 'ipipv6_jumbo_frag_drop', 'ipv6_ndisc_dad_solicits', 'ipv6_ndisc_dad_adverts', 'ipv6_ndisc_mac_changes', 'ipv6_ndisc_out_of_memory', 'sp_non_ctrl_pkt_drop', 'urpf_pkt_drop', 'fw_smp_zone_mismatch', 'ipfrag_udp', 'ipfrag_icmp', 'ipfrag_ospf', 'ipfrag_esp', 'ipfrag_tcp_dropped', 'ipfrag_udp_dropped', 'ipfrag_ipip_dropped', 'redirect_fwd_fail', 'redirect_fwd_sent', 'redirect_rev_fail', 'redirect_rev_sent', 'redirect_setup_fail', 'ip_frag_sent', 'invalid_rx_arp_pkt', 'invalid_sender_mac_arp_drop', 'dev_based_arp_drop', 'scaleout_arp_drop', 'virtual_ip_not_found_arp_drop', 'inactive_static_nat_pool_arp_drop', 'inactive_nat_pool_arp_drop', 'scaleout_hairpin_arp_drop', 'self_grat_arp_drop', 'self_grat_nat_ip_arp_drop', 'ip_not_found_arp_drop', 'dev_link_down_arp_drop', 'lacp_tx_intf_err_drop'])),
        stats=dict(type='dict', bwl_drop=dict(type='str', ), ipfrag_tcp=dict(type='str', ), ipipv6_jumbo_frag_drop=dict(type='str', ), ipfrag_ospf=dict(type='str', ), dev_based_arp_drop=dict(type='str', ), rx_arp_resp=dict(type='str', ), l4_process=dict(type='str', ), ipv6frag_tcp=dict(type='str', ), redirect_fwd_sent=dict(type='str', ), ipv4_frag_6rd_drop=dict(type='str', ), sport_drop=dict(type='str', ), ipfrag_overlap=dict(type='str', ), bpdu_sent=dict(type='str', ), invalid_rx_arp_pkt=dict(type='str', ), ipfrag_ipip_dropped=dict(type='str', ), linkdown_drop=dict(type='str', ), ipfrag_reasmoks=dict(type='str', ), ipv6_novlanfwd_drop=dict(type='str', ), badpkt_drop=dict(type='str', ), l2_forward=dict(type='str', ), rx_arp_req=dict(type='str', ), ipv4_frag_6rd_ok=dict(type='str', ), no_ip_drop=dict(type='str', ), l2_def_vlan_drop=dict(type='str', ), ip_frag_sent=dict(type='str', ), ipv6frag_tcp_dropped=dict(type='str', ), bpdu_rcvd=dict(type='str', ), licexpire_drop=dict(type='str', ), prot_down_drop=dict(type='str', ), unknown_prot_drop=dict(type='str', ), fpga_error_pkt1=dict(type='str', ), fpga_error_pkt2=dict(type='str', ), ipfrag_udp=dict(type='str', ), mgmt_svc_drop=dict(type='str', ), ipfrag_reasmfails=dict(type='str', ), ip_not_found_arp_drop=dict(type='str', ), l3_forward_ip=dict(type='str', ), l3_forward_ipv6=dict(type='str', ), ipfrag_overload=dict(type='str', ), ip_frag_oversize=dict(type='str', ), ipfrag_udp_dropped=dict(type='str', ), ipv6frag_udp=dict(type='str', ), jumbo_frag_drop=dict(type='str', ), ipv6_ndisc_dad_solicits=dict(type='str', ), lacp_tx_intf_err_drop=dict(type='str', ), fwlb=dict(type='str', ), redirect_fwd_fail=dict(type='str', ), ipv6frag_ipip_ok=dict(type='str', ), ipfrag_esp=dict(type='str', ), redirect_rev_fail=dict(type='str', ), rx_kernel=dict(type='str', ), fw_smp_zone_mismatch=dict(type='str', ), ctrl_syn_rate_drop=dict(type='str', ), self_grat_nat_ip_arp_drop=dict(type='str', ), ipv6frag_udp_dropped=dict(type='str', ), ip_frag_too_many=dict(type='str', ), ipfrag_tcp_dropped=dict(type='str', ), ipv6_jumbo_frag_drop=dict(type='str', ), invalid_sender_mac_arp_drop=dict(type='str', ), inactive_static_nat_pool_arp_drop=dict(type='str', ), ipsec_drop=dict(type='str', ), self_grat_arp_drop=dict(type='str', ), inactive_nat_pool_arp_drop=dict(type='str', ), scaleout_hairpin_arp_drop=dict(type='str', ), urpf_pkt_drop=dict(type='str', ), l4_in_ctrl_cpu=dict(type='str', ), ipfrag_icmp=dict(type='str', ), redirect_setup_fail=dict(type='str', ), ipfrag_timeout=dict(type='str', ), vlan_flood=dict(type='str', ), scaleout_arp_drop=dict(type='str', ), ttl_exceeded_drop=dict(type='str', ), acl_deny=dict(type='str', ), ip_defrag=dict(type='str', ), incorrect_len_drop=dict(type='str', ), ip_defrag_invalid_len=dict(type='str', ), ipv6_ndisc_out_of_memory=dict(type='str', ), sp_non_ctrl_pkt_drop=dict(type='str', ), virtual_ip_not_found_arp_drop=dict(type='str', ), ipv6frag_ipip_dropped=dict(type='str', ), ipv6_ndisc_mac_changes=dict(type='str', ), ipv6_noroute_drop=dict(type='str', ), ipv6frag_icmp=dict(type='str', ), ipv4_noroute_drop=dict(type='str', ), max_arp_drop=dict(type='str', ), ipv6_ndisc_dad_adverts=dict(type='str', ), redirect_rev_sent=dict(type='str', ), ipv6frag_esp=dict(type='str', ), ipv6frag_ospf=dict(type='str', ), dev_link_down_arp_drop=dict(type='str', ), ipv4_novlanfwd_drop=dict(type='str', )),
        uuid=dict(type='str', )
    ))
   

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

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k,v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module),
                                 params=query_params)
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")

def _build_dict_from_param(param):
    rv = {}

    for k,v in param.items():
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
    return {
        title: data
    }

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/switch"

    f_dict = {}

    return url_base.format(**f_dict)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params and params.get(x) is not None])
    
    errors = []
    marg = []
    
    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc,msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc,msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc,msg = REQUIRED_VALID
    
    if not rc:
        errors.append(msg.format(", ".join(marg)))
    
    return rc,errors

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
    if existing_config:
        for k, v in payload["switch"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["switch"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["switch"][k] = v
            result.update(**existing_config)
    else:
        result.update(**payload)
    return result

def create(module, result, payload):
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def update(module, result, existing_config, payload):
    try:
        post_result = module.client.post(existing_url(module), payload)
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
    return result

def present(module, result, existing_config):
    payload = build_json("switch", module)
    changed_config = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return changed_config
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and not changed_config.get('changed'):
        return update(module, result, existing_config, payload)
    else:
        result["changed"] = True
        return result

def delete(module, result):
    try:
        module.client.delete(existing_url(module))
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def absent(module, result, existing_config):
    if module.check_mode:
        if existing_config:
            result["changed"] = True
            return result
        else:
            result["changed"] = False
            return result
    else:
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
    return result

def run_command(module):
    run_errors = []

    result = dict(
        changed=False,
        original_message="",
        message="",
        result={}
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    
    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)
    
    if state == 'present':
        result = present(module, result, existing_config)

    elif state == 'absent':
        result = absent(module, result, existing_config)
    
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()