#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_interface_ethernet
description:
    - Ethernet interface
short_description: Configures A10 interface.ethernet
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
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
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            line_protocol:
                description:
                - "Field line_protocol"
            config_speed:
                description:
                - "Field config_speed"
            ipv4_netmask:
                description:
                - "IP subnet mask"
            ipv6_link_local:
                description:
                - "Field ipv6_link_local"
            ifnum:
                description:
                - "Ethernet interface number"
            state:
                description:
                - "Field state"
            actual_speed:
                description:
                - "Field actual_speed"
            config_duplexity:
                description:
                - "Field config_duplexity"
            mac:
                description:
                - "Field mac"
            ipv6_link_local_type:
                description:
                - "Field ipv6_link_local_type"
            actual_duplexity:
                description:
                - "Field actual_duplexity"
            media_type:
                description:
                - "Field media_type"
            ipv4_address:
                description:
                - "IP address"
            ipv6_link_local_prefix:
                description:
                - "Field ipv6_link_local_prefix"
            link_type:
                description:
                - "Field link_type"
    trap_source:
        description:
        - "The trap source"
        required: False
    ip:
        description:
        - "Field ip"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            address_list:
                description:
                - "Field address_list"
            generate_membership_query:
                description:
                - "Enable Membership Query"
            cache_spoofing_port:
                description:
                - "This interface connects to spoofing cache"
            inside:
                description:
                - "Configure interface as inside"
            allow_promiscuous_vip:
                description:
                - "Allow traffic to be associated with promiscuous VIP"
            dhcp:
                description:
                - "Use DHCP to configure IP address"
            max_resp_time:
                description:
                - "Maximum Response Time (Max Response Time (Default is 100))"
            query_interval:
                description:
                - "1 - 255 (Default is 125)"
            outside:
                description:
                - "Configure interface as outside"
            helper_address_list:
                description:
                - "Field helper_address_list"
            stateful_firewall:
                description:
                - "Field stateful_firewall"
            rip:
                description:
                - "Field rip"
            ttl_ignore:
                description:
                - "Ignore TTL decrement for a received packet before sending out"
            router:
                description:
                - "Field router"
            ospf:
                description:
                - "Field ospf"
            slb_partition_redirect:
                description:
                - "Redirect SLB traffic across partition"
    ddos:
        description:
        - "Field ddos"
        required: False
        suboptions:
            outside:
                description:
                - "DDoS outside (untrusted) interface"
            inside:
                description:
                - "DDoS inside (trusted) interface"
            uuid:
                description:
                - "uuid of the object"
    access_list:
        description:
        - "Field access_list"
        required: False
        suboptions:
            acl_name:
                description:
                - "Apply an access list (Named Access List)"
            acl_id:
                description:
                - "ACL id"
    speed:
        description:
        - "'10'= 10; '100'= 100; '1000'= 1000; 'auto'= auto; "
        required: False
    lldp:
        description:
        - "Field lldp"
        required: False
        suboptions:
            tx_dot1_cfg:
                description:
                - "Field tx_dot1_cfg"
            notification_cfg:
                description:
                - "Field notification_cfg"
            enable_cfg:
                description:
                - "Field enable_cfg"
            tx_tlvs_cfg:
                description:
                - "Field tx_tlvs_cfg"
            uuid:
                description:
                - "uuid of the object"
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            giants:
                description:
                - "Giants"
            transmitted_multicasts:
                description:
                - "Transmitted multicasts"
            packets_input:
                description:
                - "Input packets"
            received_multicasts:
                description:
                - "Received multicasts"
            received_broadcasts:
                description:
                - "Received broadcasts"
            transmitted_unicasts:
                description:
                - "Transmitted unicasts"
            ifnum:
                description:
                - "Ethernet interface number"
            crc:
                description:
                - "CRC"
            packets_output:
                description:
                - "Output packets"
            received_unicasts:
                description:
                - "Received unicasts"
            runts:
                description:
                - "Runts"
            bytes_output:
                description:
                - "Output bytes"
            collisions:
                description:
                - "Collisions"
            input_errors:
                description:
                - "Input errors"
            bytes_input:
                description:
                - "Input bytes"
            transmitted_broadcasts:
                description:
                - "Transmitted braodcasts"
            frame:
                description:
                - "Frames"
            output_errors:
                description:
                - "Output errors"
    uuid:
        description:
        - "uuid of the object"
        required: False
    bfd:
        description:
        - "Field bfd"
        required: False
        suboptions:
            interval_cfg:
                description:
                - "Field interval_cfg"
            authentication:
                description:
                - "Field authentication"
            echo:
                description:
                - "Enable BFD Echo"
            uuid:
                description:
                - "uuid of the object"
            demand:
                description:
                - "Demand mode"
    media_type_copper:
        description:
        - "Set the media type to copper"
        required: False
    ifnum:
        description:
        - "Ethernet interface number"
        required: True
    remove_vlan_tag:
        description:
        - "Remove the vlan tag for egressing packets"
        required: False
    monitor_list:
        description:
        - "Field monitor_list"
        required: False
        suboptions:
            monitor_vlan:
                description:
                - "VLAN number"
            monitor:
                description:
                - "'input'= Incoming packets; 'output'= Outgoing packets; 'both'= Both incoming and outgoing packets; "
            mirror_index:
                description:
                - "Mirror index"
    cpu_process:
        description:
        - "All Packets to this port are processed by CPU"
        required: False
    ipv6:
        description:
        - "Field ipv6"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            address_list:
                description:
                - "Field address_list"
            inside:
                description:
                - "Configure interface as inside"
            ipv6_enable:
                description:
                - "Enable IPv6 processing"
            rip:
                description:
                - "Field rip"
            outside:
                description:
                - "Configure interface as outside"
            stateful_firewall:
                description:
                - "Field stateful_firewall"
            ttl_ignore:
                description:
                - "Ignore TTL decrement for a received packet before sending out"
            router:
                description:
                - "Field router"
            access_list_cfg:
                description:
                - "Field access_list_cfg"
            ospf:
                description:
                - "Field ospf"
            router_adver:
                description:
                - "Field router_adver"
    map:
        description:
        - "Field map"
        required: False
        suboptions:
            translation:
                description:
                - "Field translation"
    trunk_group_list:
        description:
        - "Field trunk_group_list"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            trunk_number:
                description:
                - "Trunk Number"
            user_tag:
                description:
                - "Customized tag"
            udld_timeout_cfg:
                description:
                - "Field udld_timeout_cfg"
            mode:
                description:
                - "'active'= enable initiation of LACP negotiation on a port(default); 'passive'= disable initiation of LACP negotiation on a port; "
            timeout:
                description:
                - "'long'= Set LACP long timeout (default); 'short'= Set LACP short timeout; "
            ntype:
                description:
                - "'static'= Static (default); 'lacp'= lacp; 'lacp-udld'= lacp-udld; "
            admin_key:
                description:
                - "LACP admin key (Admin key value)"
            port_priority:
                description:
                - "Set LACP priority for a port (LACP port priority)"
    nptv6:
        description:
        - "Field nptv6"
        required: False
        suboptions:
            domain_list:
                description:
                - "Field domain_list"
    icmp_rate_limit:
        description:
        - "Field icmp_rate_limit"
        required: False
        suboptions:
            lockup:
                description:
                - "Enter lockup state when ICMP rate exceeds lockup rate limit (Maximum rate limit. If exceeds this limit, drop all ICMP packet for a time period)"
            lockup_period:
                description:
                - "Lockup period (second)"
            normal:
                description:
                - "Normal rate limit. If exceeds this limit, drop the ICMP packet that goes over the limit"
    isis:
        description:
        - "Field isis"
        required: False
        suboptions:
            priority_list:
                description:
                - "Field priority_list"
            padding:
                description:
                - "Add padding to IS-IS hello packets"
            hello_interval_minimal_list:
                description:
                - "Field hello_interval_minimal_list"
            mesh_group:
                description:
                - "Field mesh_group"
            network:
                description:
                - "'broadcast'= Specify IS-IS broadcast multi-access network; 'point-to-point'= Specify IS-IS point-to-point network; "
            authentication:
                description:
                - "Field authentication"
            csnp_interval_list:
                description:
                - "Field csnp_interval_list"
            retransmit_interval:
                description:
                - "Set per-LSP retransmission interval (Interval between retransmissions of the same LSP (seconds))"
            password_list:
                description:
                - "Field password_list"
            bfd_cfg:
                description:
                - "Field bfd_cfg"
            wide_metric_list:
                description:
                - "Field wide_metric_list"
            hello_interval_list:
                description:
                - "Field hello_interval_list"
            circuit_type:
                description:
                - "'level-1'= Level-1 only adjacencies are formed; 'level-1-2'= Level-1-2 adjacencies are formed; 'level-2-only'= Level-2 only adjacencies are formed; "
            hello_multiplier_list:
                description:
                - "Field hello_multiplier_list"
            metric_list:
                description:
                - "Field metric_list"
            lsp_interval:
                description:
                - "Set LSP transmission interval (LSP transmission interval (milliseconds))"
            uuid:
                description:
                - "uuid of the object"
    name:
        description:
        - "Name for the interface"
        required: False
    duplexity:
        description:
        - "'Full'= Full; 'Half'= Half; 'auto'= auto; "
        required: False
    icmpv6_rate_limit:
        description:
        - "Field icmpv6_rate_limit"
        required: False
        suboptions:
            lockup_period_v6:
                description:
                - "Lockup period (second)"
            normal_v6:
                description:
                - "Normal rate limit. If exceeds this limit, drop the ICMP packet that goes over the limit"
            lockup_v6:
                description:
                - "Enter lockup state when ICMP rate exceeds lockup rate limit (Maximum rate limit. If exceeds this limit, drop all ICMP packet for a time period)"
    user_tag:
        description:
        - "Customized tag"
        required: False
    mtu:
        description:
        - "Interface mtu (Interface MTU, default 1 (min MTU is 1280 for IPv6))"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'packets_input'= Input packets; 'bytes_input'= Input bytes; 'received_broadcasts'= Received broadcasts; 'received_multicasts'= Received multicasts; 'received_unicasts'= Received unicasts; 'input_errors'= Input errors; 'crc'= CRC; 'frame'= Frames; 'runts'= Runts; 'giants'= Giants; 'packets_output'= Output packets; 'bytes_output'= Output bytes; 'transmitted_broadcasts'= Transmitted braodcasts; 'transmitted_multicasts'= Transmitted multicasts; 'transmitted_unicasts'= Transmitted unicasts; 'output_errors'= Output errors; 'collisions'= Collisions; "
    load_interval:
        description:
        - "Configure Load Interval (Seconds (5-300, Multiple of 5), default 300)"
        required: False
    lw_4o6:
        description:
        - "Field lw_4o6"
        required: False
        suboptions:
            outside:
                description:
                - "Configure LW-4over6 inside interface"
            inside:
                description:
                - "Configure LW-4over6 outside interface"
            uuid:
                description:
                - "uuid of the object"
    action:
        description:
        - "'enable'= Enable; 'disable'= Disable; "
        required: False
    l3_vlan_fwd_disable:
        description:
        - "Field l3_vlan_fwd_disable"
        required: False
    flow_control:
        description:
        - "Enable 802.3x flow control on full duplex port"
        required: False


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["access_list","action","bfd","cpu_process","ddos","duplexity","flow_control","icmp_rate_limit","icmpv6_rate_limit","ifnum","ip","ipv6","isis","l3_vlan_fwd_disable","lldp","load_interval","lw_4o6","map","media_type_copper","monitor_list","mtu","name","nptv6","oper","remove_vlan_tag","sampling_enable","speed","stats","trap_source","trunk_group_list","user_tag","uuid",]

# our imports go at the top so we fail fast.
try:
    from a10_ansible import errors as a10_ex
    from a10_ansible.axapi_http import client_factory, session_factory
    from a10_ansible.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=["present", "absent", "noop"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict',line_protocol=dict(type='str',choices=['UP','DOWN']),config_speed=dict(type='str',choices=['10Mbit','100Mbit','1Gbit','10Gbit','40Gbit','auto']),ipv4_netmask=dict(type='str',),ipv6_link_local=dict(type='str',),ifnum=dict(type='str',required=True,),state=dict(type='str',choices=['UP','DISABLED','DOWN']),actual_speed=dict(type='str',choices=['10Mbit','100Mbit','1Gbit','10Gbit','40Gbit','unknown']),config_duplexity=dict(type='str',choices=['Full','fdx','Half','hdx','auto']),mac=dict(type='str',),ipv6_link_local_type=dict(type='str',),actual_duplexity=dict(type='str',choices=['Full','fdx','Half','hdx','auto']),media_type=dict(type='str',choices=['Copper','Fiber']),ipv4_address=dict(type='str',),ipv6_link_local_prefix=dict(type='str',),link_type=dict(type='str',choices=['GigabitEthernet','10Gig','40Gig'])),
        trap_source=dict(type='bool',),
        ip=dict(type='dict',uuid=dict(type='str',),address_list=dict(type='list',ipv4_address=dict(type='str',),ipv4_netmask=dict(type='str',)),generate_membership_query=dict(type='bool',),cache_spoofing_port=dict(type='bool',),inside=dict(type='bool',),allow_promiscuous_vip=dict(type='bool',),dhcp=dict(type='bool',),max_resp_time=dict(type='int',),query_interval=dict(type='int',),outside=dict(type='bool',),helper_address_list=dict(type='list',helper_address=dict(type='str',)),stateful_firewall=dict(type='dict',uuid=dict(type='str',),class_list=dict(type='str',),inside=dict(type='bool',),outside=dict(type='bool',),acl_id=dict(type='int',),access_list=dict(type='bool',)),rip=dict(type='dict',receive_cfg=dict(type='dict',receive=dict(type='bool',),version=dict(type='str',choices=['1','2','1-2'])),uuid=dict(type='str',),receive_packet=dict(type='bool',),split_horizon_cfg=dict(type='dict',state=dict(type='str',choices=['poisoned','disable','enable'])),authentication=dict(type='dict',key_chain=dict(type='dict',key_chain=dict(type='str',)),mode=dict(type='dict',mode=dict(type='str',choices=['md5','text'])),str=dict(type='dict',string=dict(type='str',))),send_cfg=dict(type='dict',version=dict(type='str',choices=['1','2','1-compatible','1-2']),send=dict(type='bool',)),send_packet=dict(type='bool',)),ttl_ignore=dict(type='bool',),router=dict(type='dict',isis=dict(type='dict',tag=dict(type='str',),uuid=dict(type='str',))),ospf=dict(type='dict',ospf_ip_list=dict(type='list',dead_interval=dict(type='int',),authentication_key=dict(type='str',),uuid=dict(type='str',),mtu_ignore=dict(type='bool',),transmit_delay=dict(type='int',),value=dict(type='str',choices=['message-digest','null']),priority=dict(type='int',),authentication=dict(type='bool',),cost=dict(type='int',),database_filter=dict(type='str',choices=['all']),hello_interval=dict(type='int',),ip_addr=dict(type='str',required=True,),retransmit_interval=dict(type='int',),message_digest_cfg=dict(type='list',md5_value=dict(type='str',),message_digest_key=dict(type='int',),encrypted=dict(type='str',)),out=dict(type='bool',)),ospf_global=dict(type='dict',cost=dict(type='int',),dead_interval=dict(type='int',),authentication_key=dict(type='str',),network=dict(type='dict',broadcast=dict(type='bool',),point_to_multipoint=dict(type='bool',),non_broadcast=dict(type='bool',),point_to_point=dict(type='bool',),p2mp_nbma=dict(type='bool',)),mtu_ignore=dict(type='bool',),transmit_delay=dict(type='int',),authentication_cfg=dict(type='dict',authentication=dict(type='bool',),value=dict(type='str',choices=['message-digest','null'])),retransmit_interval=dict(type='int',),bfd_cfg=dict(type='dict',disable=dict(type='bool',),bfd=dict(type='bool',)),disable=dict(type='str',choices=['all']),hello_interval=dict(type='int',),database_filter_cfg=dict(type='dict',database_filter=dict(type='str',choices=['all']),out=dict(type='bool',)),priority=dict(type='int',),mtu=dict(type='int',),message_digest_cfg=dict(type='list',message_digest_key=dict(type='int',),md5=dict(type='dict',md5_value=dict(type='str',),encrypted=dict(type='str',))),uuid=dict(type='str',))),slb_partition_redirect=dict(type='bool',)),
        ddos=dict(type='dict',outside=dict(type='bool',),inside=dict(type='bool',),uuid=dict(type='str',)),
        access_list=dict(type='dict',acl_name=dict(type='str',),acl_id=dict(type='int',)),
        speed=dict(type='str',choices=['10','100','1000','auto']),
        lldp=dict(type='dict',tx_dot1_cfg=dict(type='dict',link_aggregation=dict(type='bool',),vlan=dict(type='bool',),tx_dot1_tlvs=dict(type='bool',)),notification_cfg=dict(type='dict',notification=dict(type='bool',),notif_enable=dict(type='bool',)),enable_cfg=dict(type='dict',rx=dict(type='bool',),tx=dict(type='bool',),rt_enable=dict(type='bool',)),tx_tlvs_cfg=dict(type='dict',system_capabilities=dict(type='bool',),system_description=dict(type='bool',),management_address=dict(type='bool',),tx_tlvs=dict(type='bool',),exclude=dict(type='bool',),port_description=dict(type='bool',),system_name=dict(type='bool',)),uuid=dict(type='str',)),
        stats=dict(type='dict',giants=dict(type='str',),transmitted_multicasts=dict(type='str',),packets_input=dict(type='str',),received_multicasts=dict(type='str',),received_broadcasts=dict(type='str',),transmitted_unicasts=dict(type='str',),ifnum=dict(type='str',required=True,),crc=dict(type='str',),packets_output=dict(type='str',),received_unicasts=dict(type='str',),runts=dict(type='str',),bytes_output=dict(type='str',),collisions=dict(type='str',),input_errors=dict(type='str',),bytes_input=dict(type='str',),transmitted_broadcasts=dict(type='str',),frame=dict(type='str',),output_errors=dict(type='str',)),
        uuid=dict(type='str',),
        bfd=dict(type='dict',interval_cfg=dict(type='dict',interval=dict(type='int',),min_rx=dict(type='int',),multiplier=dict(type='int',)),authentication=dict(type='dict',encrypted=dict(type='str',),password=dict(type='str',),method=dict(type='str',choices=['md5','meticulous-md5','meticulous-sha1','sha1','simple']),key_id=dict(type='int',)),echo=dict(type='bool',),uuid=dict(type='str',),demand=dict(type='bool',)),
        media_type_copper=dict(type='bool',),
        ifnum=dict(type='str',required=True,),
        remove_vlan_tag=dict(type='bool',),
        monitor_list=dict(type='list',monitor_vlan=dict(type='int',),monitor=dict(type='str',choices=['input','output','both']),mirror_index=dict(type='int',)),
        cpu_process=dict(type='bool',),
        ipv6=dict(type='dict',uuid=dict(type='str',),address_list=dict(type='list',address_type=dict(type='str',choices=['anycast','link-local']),ipv6_addr=dict(type='str',)),inside=dict(type='bool',),ipv6_enable=dict(type='bool',),rip=dict(type='dict',split_horizon_cfg=dict(type='dict',state=dict(type='str',choices=['poisoned','disable','enable'])),uuid=dict(type='str',)),outside=dict(type='bool',),stateful_firewall=dict(type='dict',uuid=dict(type='str',),class_list=dict(type='str',),acl_name=dict(type='str',),inside=dict(type='bool',),outside=dict(type='bool',),access_list=dict(type='bool',)),ttl_ignore=dict(type='bool',),router=dict(type='dict',ripng=dict(type='dict',uuid=dict(type='str',),rip=dict(type='bool',)),ospf=dict(type='dict',area_list=dict(type='list',area_id_addr=dict(type='str',),tag=dict(type='str',),instance_id=dict(type='int',),area_id_num=dict(type='int',)),uuid=dict(type='str',)),isis=dict(type='dict',tag=dict(type='str',),uuid=dict(type='str',))),access_list_cfg=dict(type='dict',inbound=dict(type='bool',),v6_acl_name=dict(type='str',)),ospf=dict(type='dict',uuid=dict(type='str',),bfd=dict(type='bool',),cost_cfg=dict(type='list',cost=dict(type='int',),instance_id=dict(type='int',)),priority_cfg=dict(type='list',priority=dict(type='int',),instance_id=dict(type='int',)),hello_interval_cfg=dict(type='list',hello_interval=dict(type='int',),instance_id=dict(type='int',)),mtu_ignore_cfg=dict(type='list',mtu_ignore=dict(type='bool',),instance_id=dict(type='int',)),retransmit_interval_cfg=dict(type='list',retransmit_interval=dict(type='int',),instance_id=dict(type='int',)),disable=dict(type='bool',),transmit_delay_cfg=dict(type='list',transmit_delay=dict(type='int',),instance_id=dict(type='int',)),neighbor_cfg=dict(type='list',neighbor_priority=dict(type='int',),neighbor_poll_interval=dict(type='int',),neig_inst=dict(type='int',),neighbor=dict(type='str',),neighbor_cost=dict(type='int',)),network_list=dict(type='list',broadcast_type=dict(type='str',choices=['broadcast','non-broadcast','point-to-point','point-to-multipoint']),p2mp_nbma=dict(type='bool',),network_instance_id=dict(type='int',)),dead_interval_cfg=dict(type='list',dead_interval=dict(type='int',),instance_id=dict(type='int',))),router_adver=dict(type='dict',max_interval=dict(type='int',),default_lifetime=dict(type='int',),reachable_time=dict(type='int',),other_config_action=dict(type='str',choices=['enable','disable']),floating_ip_default_vrid=dict(type='str',),managed_config_action=dict(type='str',choices=['enable','disable']),min_interval=dict(type='int',),rate_limit=dict(type='int',),adver_mtu_disable=dict(type='bool',),prefix_list=dict(type='list',not_autonomous=dict(type='bool',),not_on_link=dict(type='bool',),valid_lifetime=dict(type='int',),prefix=dict(type='str',),preferred_lifetime=dict(type='int',)),floating_ip=dict(type='str',),adver_vrid=dict(type='int',),use_floating_ip_default_vrid=dict(type='bool',),action=dict(type='str',choices=['enable','disable']),adver_vrid_default=dict(type='bool',),adver_mtu=dict(type='int',),retransmit_timer=dict(type='int',),hop_limit=dict(type='int',),use_floating_ip=dict(type='bool',))),
        map=dict(type='dict',translation=dict(type='dict',inside=dict(type='bool',),outside=dict(type='bool',),uuid=dict(type='str',))),
        trunk_group_list=dict(type='list',uuid=dict(type='str',),trunk_number=dict(type='int',required=True,),user_tag=dict(type='str',),udld_timeout_cfg=dict(type='dict',slow=dict(type='int',),fast=dict(type='int',)),mode=dict(type='str',choices=['active','passive']),timeout=dict(type='str',choices=['long','short']),ntype=dict(type='str',choices=['static','lacp','lacp-udld']),admin_key=dict(type='int',),port_priority=dict(type='int',)),
        nptv6=dict(type='dict',domain_list=dict(type='list',domain_name=dict(type='str',required=True,),bind_type=dict(type='str',required=True,choices=['inside','outside']),uuid=dict(type='str',))),
        icmp_rate_limit=dict(type='dict',lockup=dict(type='int',),lockup_period=dict(type='int',),normal=dict(type='int',)),
        isis=dict(type='dict',priority_list=dict(type='list',priority=dict(type='int',),level=dict(type='str',choices=['level-1','level-2'])),padding=dict(type='bool',),hello_interval_minimal_list=dict(type='list',hello_interval_minimal=dict(type='bool',),level=dict(type='str',choices=['level-1','level-2'])),mesh_group=dict(type='dict',value=dict(type='int',),blocked=dict(type='bool',)),network=dict(type='str',choices=['broadcast','point-to-point']),authentication=dict(type='dict',send_only_list=dict(type='list',send_only=dict(type='bool',),level=dict(type='str',choices=['level-1','level-2'])),mode_list=dict(type='list',mode=dict(type='str',choices=['md5']),level=dict(type='str',choices=['level-1','level-2'])),key_chain_list=dict(type='list',key_chain=dict(type='str',),level=dict(type='str',choices=['level-1','level-2']))),csnp_interval_list=dict(type='list',csnp_interval=dict(type='int',),level=dict(type='str',choices=['level-1','level-2'])),retransmit_interval=dict(type='int',),password_list=dict(type='list',password=dict(type='str',),level=dict(type='str',choices=['level-1','level-2'])),bfd_cfg=dict(type='dict',disable=dict(type='bool',),bfd=dict(type='bool',)),wide_metric_list=dict(type='list',wide_metric=dict(type='int',),level=dict(type='str',choices=['level-1','level-2'])),hello_interval_list=dict(type='list',hello_interval=dict(type='int',),level=dict(type='str',choices=['level-1','level-2'])),circuit_type=dict(type='str',choices=['level-1','level-1-2','level-2-only']),hello_multiplier_list=dict(type='list',hello_multiplier=dict(type='int',),level=dict(type='str',choices=['level-1','level-2'])),metric_list=dict(type='list',metric=dict(type='int',),level=dict(type='str',choices=['level-1','level-2'])),lsp_interval=dict(type='int',),uuid=dict(type='str',)),
        name=dict(type='str',),
        duplexity=dict(type='str',choices=['Full','Half','auto']),
        icmpv6_rate_limit=dict(type='dict',lockup_period_v6=dict(type='int',),normal_v6=dict(type='int',),lockup_v6=dict(type='int',)),
        user_tag=dict(type='str',),
        mtu=dict(type='int',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','packets_input','bytes_input','received_broadcasts','received_multicasts','received_unicasts','input_errors','crc','frame','runts','giants','packets_output','bytes_output','transmitted_broadcasts','transmitted_multicasts','transmitted_unicasts','output_errors','collisions'])),
        load_interval=dict(type='int',),
        lw_4o6=dict(type='dict',outside=dict(type='bool',),inside=dict(type='bool',),uuid=dict(type='str',)),
        action=dict(type='str',choices=['enable','disable']),
        l3_vlan_fwd_disable=dict(type='bool',),
        flow_control=dict(type='bool',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/interface/ethernet/{ifnum}"

    f_dict = {}
    f_dict["ifnum"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/ethernet/{ifnum}"

    f_dict = {}
    f_dict["ifnum"] = module.params["ifnum"]

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

def build_envelope(title, data):
    return {
        title: data
    }

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

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k,v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v 
        return module.client.get(oper_url(module),
                                 params=query_params)
    return module.client.get(oper_url(module))

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

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["ethernet"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["ethernet"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["ethernet"][k] = v
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
    payload = build_json("ethernet", module)
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
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