#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_virtual_server
description:
    - Create a Virtual Server
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
        - "SLB Virtual Server Name"
        type: str
        required: True
    ipv6_address:
        description:
        - "IPV6 address"
        type: str
        required: False
    ip_address:
        description:
        - "IP Address"
        type: str
        required: False
    netmask:
        description:
        - "IP subnet mask"
        type: str
        required: False
    ipv6_acl:
        description:
        - "ipv6 acl name"
        type: str
        required: False
    ipv6_acl_shared:
        description:
        - "ipv6 acl name"
        type: str
        required: False
    acl_id:
        description:
        - "acl id"
        type: int
        required: False
    acl_name:
        description:
        - "Access List name (IPv4 Access List Name)"
        type: str
        required: False
    acl_id_shared:
        description:
        - "acl id"
        type: int
        required: False
    acl_name_shared:
        description:
        - "Access List name (IPv4 Access List Name)"
        type: str
        required: False
    use_if_ip:
        description:
        - "Use Interface IP"
        type: bool
        required: False
    ethernet:
        description:
        - "Ethernet interface"
        type: str
        required: False
    description:
        description:
        - "Create a description for VIP"
        type: str
        required: False
    enable_disable_action:
        description:
        - "'enable'= Enable Virtual Server (default); 'disable'= Disable Virtual Server;
          'disable-when-all-ports-down'= Disable Virtual Server when all member ports are
          down; 'disable-when-any-port-down'= Disable Virtual Server when any member port
          is down;"
        type: str
        required: False
    redistribution_flagged:
        description:
        - "Flag VIP for special redistribution handling"
        type: bool
        required: False
    vport_disable_action:
        description:
        - "'drop-packet'= Drop packet for disabled virtual-port;"
        type: str
        required: False
    arp_disable:
        description:
        - "Disable Respond to Virtual Server ARP request"
        type: bool
        required: False
    template_policy:
        description:
        - "Policy template (Policy template name)"
        type: str
        required: False
    shared_partition_policy_template:
        description:
        - "Reference a policy template from shared partition"
        type: bool
        required: False
    template_policy_shared:
        description:
        - "Policy Template Name"
        type: str
        required: False
    template_virtual_server:
        description:
        - "Virtual server template (Virtual server template name)"
        type: str
        required: False
    template_logging:
        description:
        - "NAT Logging template (NAT Logging template name)"
        type: str
        required: False
    template_scaleout:
        description:
        - "Scaleout template (Scaleout template name)"
        type: str
        required: False
    stats_data_action:
        description:
        - "'stats-data-enable'= Enable statistical data collection for virtual server;
          'stats-data-disable'= Disable statistical data collection for virtual server;"
        type: str
        required: False
    extended_stats:
        description:
        - "Enable extended statistics on virtual server"
        type: bool
        required: False
    vrid:
        description:
        - "Join a vrrp group (Specify ha VRRP-A vrid)"
        type: int
        required: False
    disable_vip_adv:
        description:
        - "Disable virtual server GARP"
        type: bool
        required: False
    ha_dynamic:
        description:
        - "Dynamic failover based on vip status"
        type: int
        required: False
    redistribute_route_map:
        description:
        - "Route map reference (Name of route-map)"
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
    migrate_vip:
        description:
        - "Field migrate_vip"
        type: dict
        required: False
        suboptions:
            target_data_cpu:
                description:
                - "Number of CPUs on the target platform"
                type: int
            target_floating_ipv4:
                description:
                - "Specify IP address"
                type: str
            cancel_migration:
                description:
                - "Cancel migration"
                type: bool
            finish_migration:
                description:
                - "Complete the migration"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    port_list:
        description:
        - "Field port_list"
        type: list
        required: False
        suboptions:
            port_number:
                description:
                - "Port"
                type: int
            protocol:
                description:
                - "'tcp'= TCP LB service; 'udp'= UDP Port; 'others'= for no tcp/udp protocol, do
          IP load balancing; 'diameter'= diameter port; 'dns-tcp'= DNS service over TCP;
          'dns-udp'= DNS service over UDP; 'fast-http'= Fast HTTP Port; 'fix'= FIX Port;
          'ftp'= File Transfer Protocol Port; 'ftp-proxy'= ftp proxy port; 'http'= HTTP
          Port; 'https'= HTTPS port; 'http2'= [Deprecated] HTTP2 Port; 'http2s'=
          [Deprecated] HTTP2 SSL port; 'imap'= imap proxy port; 'mlb'= Message based load
          balancing; 'mms'= Microsoft Multimedia Service Port; 'mysql'= mssql port;
          'mssql'= mssql; 'pop3'= pop3 proxy port; 'radius'= RADIUS Port; 'rtsp'= Real
          Time Streaming Protocol Port; 'sip'= Session initiation protocol over UDP;
          'sip-tcp'= Session initiation protocol over TCP; 'sips'= Session initiation
          protocol over TLS; 'smpp-tcp'= SMPP service over TCP; 'spdy'= spdy port;
          'spdys'= spdys port; 'smtp'= SMTP Port; 'ssl-proxy'= Generic SSL proxy; 'ssli'=
          SSL insight; 'ssh'= SSH Port; 'tcp-proxy'= Generic TCP proxy; 'tftp'= TFTP
          Port; 'fast-fix'= Fast FIX port;"
                type: str
            range:
                description:
                - "Virtual Port range (Virtual Port range value)"
                type: int
            alternate_port:
                description:
                - "Alternate Virtual Port"
                type: bool
            optimization_level:
                description:
                - "'0'= No optimization; '1'= Optimization level 1 (Experimental);"
                type: str
            support_http2:
                description:
                - "Support HTTP2"
                type: bool
            ip_only_lb:
                description:
                - "Enable IP-Only LB mode"
                type: bool
            name:
                description:
                - "SLB Virtual Service Name"
                type: str
            conn_limit:
                description:
                - "Connection Limit"
                type: int
            reset:
                description:
                - "Send client reset when connection number over limit"
                type: bool
            no_logging:
                description:
                - "Do not log connection over limit event"
                type: bool
            use_alternate_port:
                description:
                - "Use alternate virtual port"
                type: bool
            alternate_port_number:
                description:
                - "Virtual Port"
                type: int
            alt_protocol1:
                description:
                - "'http'= HTTP Port;"
                type: str
            serv_sel_fail:
                description:
                - "Use alternate virtual port when server selection failure"
                type: bool
            when_down:
                description:
                - "Use alternate virtual port when down"
                type: bool
            alt_protocol2:
                description:
                - "'tcp'= TCP LB service;"
                type: str
            req_fail:
                description:
                - "Use alternate virtual port when L7 request fail"
                type: bool
            when_down_protocol2:
                description:
                - "Use alternate virtual port when down"
                type: bool
            action:
                description:
                - "'enable'= Enable; 'disable'= Disable;"
                type: str
            def_selection_if_pref_failed:
                description:
                - "'def-selection-if-pref-failed'= Use default server selection method if prefer
          method failed; 'def-selection-if-pref-failed-disable'= Stop using default
          server selection method if prefer method failed;"
                type: str
            ha_conn_mirror:
                description:
                - "Enable for HA Conn sync"
                type: bool
            on_syn:
                description:
                - "Enable for HA Conn sync for l4 tcp sessions on SYN"
                type: bool
            skip_rev_hash:
                description:
                - "Skip rev tuple hash insertion"
                type: bool
            message_switching:
                description:
                - "Message switching"
                type: bool
            force_routing_mode:
                description:
                - "Force routing mode"
                type: bool
            rate:
                description:
                - "Specify the log message rate"
                type: int
            secs:
                description:
                - "Specify the interval in seconds"
                type: int
            reset_on_server_selection_fail:
                description:
                - "Send client reset when server selection fails"
                type: bool
            clientip_sticky_nat:
                description:
                - "Prefer to use same source NAT address for a client"
                type: bool
            extended_stats:
                description:
                - "Enable extended statistics on virtual port"
                type: bool
            gslb_enable:
                description:
                - "Enable Global Server Load Balancing"
                type: bool
            view:
                description:
                - "Specify a GSLB View (ID)"
                type: int
            snat_on_vip:
                description:
                - "Enable source NAT traffic against VIP"
                type: bool
            stats_data_action:
                description:
                - "'stats-data-enable'= Enable statistical data collection for virtual port;
          'stats-data-disable'= Disable statistical data collection for virtual port;"
                type: str
            syn_cookie:
                description:
                - "Enable syn-cookie"
                type: bool
            expand:
                description:
                - "expand syn-cookie with timestamp and wscale"
                type: bool
            acl_id_list:
                description:
                - "Field acl_id_list"
                type: list
            acl_name_list:
                description:
                - "Field acl_name_list"
                type: list
            template_policy:
                description:
                - "Policy Template (Policy template name)"
                type: str
            shared_partition_policy_template:
                description:
                - "Reference a policy template from shared partition"
                type: bool
            template_policy_shared:
                description:
                - "Policy Template Name"
                type: str
            aflex_scripts:
                description:
                - "Field aflex_scripts"
                type: list
            no_auto_up_on_aflex:
                description:
                - "Don't automatically mark vport up when aFleX is bound"
                type: bool
            scaleout_bucket_count:
                description:
                - "Number of traffic buckets"
                type: int
            scaleout_device_group:
                description:
                - "Device group id"
                type: int
            pool:
                description:
                - "Specify NAT pool or pool group"
                type: str
            shared_partition_pool:
                description:
                - "Specify NAT pool or pool group from shared partition"
                type: bool
            pool_shared:
                description:
                - "Specify NAT pool or pool group"
                type: str
            auto:
                description:
                - "Configure auto NAT for the vport"
                type: bool
            precedence:
                description:
                - "Set auto NAT pool as higher precedence for source NAT"
                type: bool
            use_cgnv6:
                description:
                - "Follow CGNv6 source NAT configuration"
                type: bool
            enable_playerid_check:
                description:
                - "Enable playerid checks on UDP packets once the AX is in active mode"
                type: bool
            service_group:
                description:
                - "Bind a Service Group to this Virtual Server (Service Group Name)"
                type: str
            ipinip:
                description:
                - "Enable IP in IP"
                type: bool
            ip_map_list:
                description:
                - "Enter name of IP Map List to be bound (IP Map List Name)"
                type: str
            rtp_sip_call_id_match:
                description:
                - "rtp traffic try to match the real server of sip smp call-id session"
                type: bool
            use_rcv_hop_for_resp:
                description:
                - "Use receive hop for response to client(For packets on default-vlan, also config
          'vlan-global enable-def-vlan-l2-forwarding'.)"
                type: bool
            persist_type:
                description:
                - "'src-dst-ip-swap-persist'= Create persist session after source IP and
          destination IP swap; 'use-src-ip-for-dst-persist'= Use the source IP to create
          a destination persist session; 'use-dst-ip-for-src-persist'= Use the
          destination IP to create source IP persist session;"
                type: str
            use_rcv_hop_group:
                description:
                - "Set use-rcv-hop group"
                type: bool
            server_group:
                description:
                - "Bind a use-rcv-hop-for-resp Server Group to this Virtual Server (Server Group
          Name)"
                type: str
            eth_fwd:
                description:
                - "Ethernet interface number"
                type: str
            trunk_fwd:
                description:
                - "Trunk interface number"
                type: str
            eth_rev:
                description:
                - "Ethernet interface number"
                type: str
            trunk_rev:
                description:
                - "Trunk interface number"
                type: str
            template_sip:
                description:
                - "SIP template"
                type: str
            template_smpp:
                description:
                - "SMPP template"
                type: str
            template_dblb:
                description:
                - "DBLB Template (DBLB template name)"
                type: str
            template_connection_reuse:
                description:
                - "Connection Reuse Template (Connection Reuse Template Name)"
                type: str
            shared_partition_connection_reuse_template:
                description:
                - "Reference a connection reuse template from shared partition"
                type: bool
            template_connection_reuse_shared:
                description:
                - "Connection Reuse Template Name"
                type: str
            template_dns:
                description:
                - "DNS template (DNS template name)"
                type: str
            shared_partition_dns_template:
                description:
                - "Reference a dns template from shared partition"
                type: bool
            template_dns_shared:
                description:
                - "DNS Template Name"
                type: str
            template_dynamic_service:
                description:
                - "Dynamic Service Template (dynamic-service template name)"
                type: str
            shared_partition_dynamic_service_template:
                description:
                - "Reference a dynamic service template from shared partition"
                type: bool
            template_dynamic_service_shared:
                description:
                - "Dynamic Service Template Name"
                type: str
            template_persist_source_ip:
                description:
                - "Source IP persistence (Source IP persistence template name)"
                type: str
            shared_partition_persist_source_ip_template:
                description:
                - "Reference a persist source ip template from shared partition"
                type: bool
            template_persist_source_ip_shared:
                description:
                - "Source IP Persistence Template Name"
                type: str
            template_persist_destination_ip:
                description:
                - "Destination IP persistence (Destination IP persistence template name)"
                type: str
            shared_partition_persist_destination_ip_template:
                description:
                - "Reference a persist destination ip template from shared partition"
                type: bool
            template_persist_destination_ip_shared:
                description:
                - "Destination IP Persistence Template Name"
                type: str
            template_persist_ssl_sid:
                description:
                - "SSL SID persistence (SSL SID persistence template name)"
                type: str
            shared_partition_persist_ssl_sid_template:
                description:
                - "Reference a persist SSL SID template from shared partition"
                type: bool
            template_persist_ssl_sid_shared:
                description:
                - "SSL SID Persistence Template Name"
                type: str
            template_persist_cookie:
                description:
                - "Cookie persistence (Cookie persistence template name)"
                type: str
            shared_partition_persist_cookie_template:
                description:
                - "Reference a persist cookie template from shared partition"
                type: bool
            template_persist_cookie_shared:
                description:
                - "Cookie Persistence Template Name"
                type: str
            template_imap_pop3:
                description:
                - "IMAP/POP3 Template (IMAP/POP3 Config Name)"
                type: str
            template_smtp:
                description:
                - "SMTP Template (SMTP Config Name)"
                type: str
            template_http:
                description:
                - "HTTP Template Name"
                type: str
            shared_partition_http_template:
                description:
                - "Reference a HTTP template from shared partition"
                type: bool
            template_http_shared:
                description:
                - "HTTP Template Name"
                type: str
            template_http_policy:
                description:
                - "http-policy template (http-policy template name)"
                type: str
            shared_partition_http_policy_template:
                description:
                - "Reference a http policy template from shared partition"
                type: bool
            template_http_policy_shared:
                description:
                - "Http Policy Template Name"
                type: str
            redirect_to_https:
                description:
                - "Redirect HTTP to HTTPS"
                type: bool
            template_external_service:
                description:
                - "External service template (external-service template name)"
                type: str
            shared_partition_external_service_template:
                description:
                - "Reference a external service template from shared partition"
                type: bool
            template_external_service_shared:
                description:
                - "External Service Template Name"
                type: str
            template_reqmod_icap:
                description:
                - "ICAP reqmod template (reqmod-icap template name)"
                type: str
            template_respmod_icap:
                description:
                - "ICAP respmod service template (respmod-icap template name)"
                type: str
            template_file_inspection:
                description:
                - "File Inspection service template (file-inspection template name)"
                type: str
            template_server_ssl:
                description:
                - "Server Side SSL Template Name"
                type: str
            shared_partition_server_ssl_template:
                description:
                - "Reference a SSL Server template from shared partition"
                type: bool
            template_server_ssl_shared:
                description:
                - "Server SSL Template Name"
                type: str
            template_client_ssl:
                description:
                - "Client SSL Template Name"
                type: str
            shared_partition_client_ssl_template:
                description:
                - "Reference a Client SSL template from shared partition"
                type: bool
            template_client_ssl_shared:
                description:
                - "Client SSL Template Name"
                type: str
            template_server_ssh:
                description:
                - "Server SSH Template (Server SSH Config Name)"
                type: str
            template_client_ssh:
                description:
                - "Client SSH Template (Client SSH Config Name)"
                type: str
            template_udp:
                description:
                - "L4 UDP Template"
                type: str
            shared_partition_udp:
                description:
                - "Reference a UDP template from shared partition"
                type: bool
            template_udp_shared:
                description:
                - "UDP Template Name"
                type: str
            template_tcp:
                description:
                - "TCP Template Name"
                type: str
            shared_partition_tcp:
                description:
                - "Reference a tcp template from shared partition"
                type: bool
            template_tcp_shared:
                description:
                - "TCP Template Name"
                type: str
            template_virtual_port:
                description:
                - "Virtual port template (Virtual port template name)"
                type: str
            shared_partition_virtual_port_template:
                description:
                - "Reference a Virtual Port template from shared partition"
                type: bool
            template_virtual_port_shared:
                description:
                - "Virtual Port Template Name"
                type: str
            template_ftp:
                description:
                - "FTP port template (Ftp template name)"
                type: str
            template_diameter:
                description:
                - "Diameter Template (diameter template name)"
                type: str
            shared_partition_diameter_template:
                description:
                - "Reference a Diameter template from shared partition"
                type: bool
            template_diameter_shared:
                description:
                - "Diameter Template Name"
                type: str
            template_cache:
                description:
                - "RAM caching template (Cache Template Name)"
                type: str
            shared_partition_cache_template:
                description:
                - "Reference a Cache template from shared partition"
                type: bool
            template_cache_shared:
                description:
                - "Cache Template Name"
                type: str
            template_fix:
                description:
                - "FIX template (FIX Template Name)"
                type: str
            waf_template:
                description:
                - "WAF template (WAF Template Name)"
                type: str
            template_ssli:
                description:
                - "SSLi template (SSLi Template Name)"
                type: str
            template_tcp_proxy_client:
                description:
                - "TCP Proxy Config Client (TCP Proxy Config name)"
                type: str
            template_tcp_proxy_server:
                description:
                - "TCP Proxy Config Server (TCP Proxy Config name)"
                type: str
            template_tcp_proxy:
                description:
                - "TCP Proxy Template Name"
                type: str
            shared_partition_tcp_proxy_template:
                description:
                - "Reference a TCP Proxy template from shared partition"
                type: bool
            template_tcp_proxy_shared:
                description:
                - "TCP Proxy Template name"
                type: str
            use_default_if_no_server:
                description:
                - "Use default forwarding if server selection failed"
                type: bool
            template_scaleout:
                description:
                - "Scaleout template (Scaleout template name)"
                type: str
            no_dest_nat:
                description:
                - "Disable destination NAT, this option only supports in wildcard VIP or when a
          connection is operated in SSLi + EP mode"
                type: bool
            port_translation:
                description:
                - "Enable port translation under no-dest-nat"
                type: bool
            l7_hardware_assist:
                description:
                - "FPGA assist L7 packet parsing"
                type: bool
            auth_cfg:
                description:
                - "Field auth_cfg"
                type: dict
            cpu_compute:
                description:
                - "enable cpu compute on virtual port"
                type: bool
            memory_compute:
                description:
                - "enable dynamic memory compute on virtual port"
                type: bool
            resolve_web_cat_list:
                description:
                - "Web Category List name"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            mac:
                description:
                - "Field mac"
                type: str
            state:
                description:
                - "Field state"
                type: str
            curr_conn_rate:
                description:
                - "Field curr_conn_rate"
                type: int
            conn_rate_unit:
                description:
                - "Field conn_rate_unit"
                type: str
            curr_icmp_rate:
                description:
                - "Field curr_icmp_rate"
                type: int
            icmp_lockup_time_left:
                description:
                - "Field icmp_lockup_time_left"
                type: int
            icmp_rate_over_limit_drop:
                description:
                - "Field icmp_rate_over_limit_drop"
                type: int
            curr_icmpv6_rate:
                description:
                - "Field curr_icmpv6_rate"
                type: int
            icmpv6_lockup_time_left:
                description:
                - "Field icmpv6_lockup_time_left"
                type: int
            icmpv6_rate_over_limit_drop:
                description:
                - "Field icmpv6_rate_over_limit_drop"
                type: int
            migration_status:
                description:
                - "Field migration_status"
                type: str
            peak_conn:
                description:
                - "Field peak_conn"
                type: int
            ip_address:
                description:
                - "Field ip_address"
                type: str
            curr_conn_overflow:
                description:
                - "Field curr_conn_overflow"
                type: int
            ip_only_lb_fwd_bytes:
                description:
                - "Field ip_only_lb_fwd_bytes"
                type: int
            ip_only_lb_rev_bytes:
                description:
                - "Field ip_only_lb_rev_bytes"
                type: int
            ip_only_lb_fwd_pkts:
                description:
                - "Field ip_only_lb_fwd_pkts"
                type: int
            ip_only_lb_rev_pkts:
                description:
                - "Field ip_only_lb_rev_pkts"
                type: int
            name:
                description:
                - "SLB Virtual Server Name"
                type: str
            migrate_vip:
                description:
                - "Field migrate_vip"
                type: dict
            port_list:
                description:
                - "Field port_list"
                type: list

'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "acl_id",
    "acl_id_shared",
    "acl_name",
    "acl_name_shared",
    "arp_disable",
    "description",
    "disable_vip_adv",
    "enable_disable_action",
    "ethernet",
    "extended_stats",
    "ha_dynamic",
    "ip_address",
    "ipv6_acl",
    "ipv6_acl_shared",
    "ipv6_address",
    "migrate_vip",
    "name",
    "netmask",
    "oper",
    "port_list",
    "redistribute_route_map",
    "redistribution_flagged",
    "shared_partition_policy_template",
    "stats_data_action",
    "template_logging",
    "template_policy",
    "template_policy_shared",
    "template_scaleout",
    "template_virtual_server",
    "use_if_ip",
    "user_tag",
    "uuid",
    "vport_disable_action",
    "vrid",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


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
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
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
        'ipv6_address': {
            'type': 'str',
        },
        'ip_address': {
            'type': 'str',
        },
        'netmask': {
            'type': 'str',
        },
        'ipv6_acl': {
            'type': 'str',
        },
        'ipv6_acl_shared': {
            'type': 'str',
        },
        'acl_id': {
            'type': 'int',
        },
        'acl_name': {
            'type': 'str',
        },
        'acl_id_shared': {
            'type': 'int',
        },
        'acl_name_shared': {
            'type': 'str',
        },
        'use_if_ip': {
            'type': 'bool',
        },
        'ethernet': {
            'type': 'str',
        },
        'description': {
            'type': 'str',
        },
        'enable_disable_action': {
            'type':
            'str',
            'choices': [
                'enable', 'disable', 'disable-when-all-ports-down',
                'disable-when-any-port-down'
            ]
        },
        'redistribution_flagged': {
            'type': 'bool',
        },
        'vport_disable_action': {
            'type': 'str',
            'choices': ['drop-packet']
        },
        'arp_disable': {
            'type': 'bool',
        },
        'template_policy': {
            'type': 'str',
        },
        'shared_partition_policy_template': {
            'type': 'bool',
        },
        'template_policy_shared': {
            'type': 'str',
        },
        'template_virtual_server': {
            'type': 'str',
        },
        'template_logging': {
            'type': 'str',
        },
        'template_scaleout': {
            'type': 'str',
        },
        'stats_data_action': {
            'type': 'str',
            'choices': ['stats-data-enable', 'stats-data-disable']
        },
        'extended_stats': {
            'type': 'bool',
        },
        'vrid': {
            'type': 'int',
        },
        'disable_vip_adv': {
            'type': 'bool',
        },
        'ha_dynamic': {
            'type': 'int',
        },
        'redistribute_route_map': {
            'type': 'str',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'migrate_vip': {
            'type': 'dict',
            'target_data_cpu': {
                'type': 'int',
            },
            'target_floating_ipv4': {
                'type': 'str',
            },
            'cancel_migration': {
                'type': 'bool',
            },
            'finish_migration': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'port_list': {
            'type': 'list',
            'port_number': {
                'type': 'int',
                'required': True,
            },
            'protocol': {
                'type':
                'str',
                'required':
                True,
                'choices': [
                    'tcp', 'udp', 'others', 'diameter', 'dns-tcp', 'dns-udp',
                    'fast-http', 'fix', 'ftp', 'ftp-proxy', 'http', 'https',
                    'http2', 'http2s', 'imap', 'mlb', 'mms', 'mysql', 'mssql',
                    'pop3', 'radius', 'rtsp', 'sip', 'sip-tcp', 'sips',
                    'smpp-tcp', 'spdy', 'spdys', 'smtp', 'ssl-proxy', 'ssli',
                    'ssh', 'tcp-proxy', 'tftp', 'fast-fix'
                ]
            },
            'range': {
                'type': 'int',
            },
            'alternate_port': {
                'type': 'bool',
            },
            'optimization_level': {
                'type': 'str',
                'choices': ['0', '1']
            },
            'support_http2': {
                'type': 'bool',
            },
            'ip_only_lb': {
                'type': 'bool',
            },
            'name': {
                'type': 'str',
            },
            'conn_limit': {
                'type': 'int',
            },
            'reset': {
                'type': 'bool',
            },
            'no_logging': {
                'type': 'bool',
            },
            'use_alternate_port': {
                'type': 'bool',
            },
            'alternate_port_number': {
                'type': 'int',
            },
            'alt_protocol1': {
                'type': 'str',
                'choices': ['http']
            },
            'serv_sel_fail': {
                'type': 'bool',
            },
            'when_down': {
                'type': 'bool',
            },
            'alt_protocol2': {
                'type': 'str',
                'choices': ['tcp']
            },
            'req_fail': {
                'type': 'bool',
            },
            'when_down_protocol2': {
                'type': 'bool',
            },
            'action': {
                'type': 'str',
                'choices': ['enable', 'disable']
            },
            'def_selection_if_pref_failed': {
                'type':
                'str',
                'choices': [
                    'def-selection-if-pref-failed',
                    'def-selection-if-pref-failed-disable'
                ]
            },
            'ha_conn_mirror': {
                'type': 'bool',
            },
            'on_syn': {
                'type': 'bool',
            },
            'skip_rev_hash': {
                'type': 'bool',
            },
            'message_switching': {
                'type': 'bool',
            },
            'force_routing_mode': {
                'type': 'bool',
            },
            'rate': {
                'type': 'int',
            },
            'secs': {
                'type': 'int',
            },
            'reset_on_server_selection_fail': {
                'type': 'bool',
            },
            'clientip_sticky_nat': {
                'type': 'bool',
            },
            'extended_stats': {
                'type': 'bool',
            },
            'gslb_enable': {
                'type': 'bool',
            },
            'view': {
                'type': 'int',
            },
            'snat_on_vip': {
                'type': 'bool',
            },
            'stats_data_action': {
                'type': 'str',
                'choices': ['stats-data-enable', 'stats-data-disable']
            },
            'syn_cookie': {
                'type': 'bool',
            },
            'expand': {
                'type': 'bool',
            },
            'acl_id_list': {
                'type': 'list',
                'acl_id': {
                    'type': 'int',
                },
                'acl_id_src_nat_pool': {
                    'type': 'str',
                },
                'acl_id_seq_num': {
                    'type': 'int',
                },
                'shared_partition_pool_id': {
                    'type': 'bool',
                },
                'acl_id_src_nat_pool_shared': {
                    'type': 'str',
                },
                'acl_id_seq_num_shared': {
                    'type': 'int',
                },
                'acl_id_shared': {
                    'type': 'int',
                },
                'v_acl_id_src_nat_pool': {
                    'type': 'str',
                },
                'v_acl_id_seq_num': {
                    'type': 'int',
                },
                'v_shared_partition_pool_id': {
                    'type': 'bool',
                },
                'v_acl_id_src_nat_pool_shared': {
                    'type': 'str',
                },
                'v_acl_id_seq_num_shared': {
                    'type': 'int',
                }
            },
            'acl_name_list': {
                'type': 'list',
                'acl_name': {
                    'type': 'str',
                },
                'acl_name_src_nat_pool': {
                    'type': 'str',
                },
                'acl_name_seq_num': {
                    'type': 'int',
                },
                'shared_partition_pool_name': {
                    'type': 'bool',
                },
                'acl_name_src_nat_pool_shared': {
                    'type': 'str',
                },
                'acl_name_seq_num_shared': {
                    'type': 'int',
                },
                'acl_name_shared': {
                    'type': 'str',
                },
                'v_acl_name_src_nat_pool': {
                    'type': 'str',
                },
                'v_acl_name_seq_num': {
                    'type': 'int',
                },
                'v_shared_partition_pool_name': {
                    'type': 'bool',
                },
                'v_acl_name_src_nat_pool_shared': {
                    'type': 'str',
                },
                'v_acl_name_seq_num_shared': {
                    'type': 'int',
                }
            },
            'template_policy': {
                'type': 'str',
            },
            'shared_partition_policy_template': {
                'type': 'bool',
            },
            'template_policy_shared': {
                'type': 'str',
            },
            'aflex_scripts': {
                'type': 'list',
                'aflex': {
                    'type': 'str',
                },
                'aflex_shared': {
                    'type': 'str',
                }
            },
            'no_auto_up_on_aflex': {
                'type': 'bool',
            },
            'scaleout_bucket_count': {
                'type': 'int',
            },
            'scaleout_device_group': {
                'type': 'int',
            },
            'pool': {
                'type': 'str',
            },
            'shared_partition_pool': {
                'type': 'bool',
            },
            'pool_shared': {
                'type': 'str',
            },
            'auto': {
                'type': 'bool',
            },
            'precedence': {
                'type': 'bool',
            },
            'use_cgnv6': {
                'type': 'bool',
            },
            'enable_playerid_check': {
                'type': 'bool',
            },
            'service_group': {
                'type': 'str',
            },
            'ipinip': {
                'type': 'bool',
            },
            'ip_map_list': {
                'type': 'str',
            },
            'rtp_sip_call_id_match': {
                'type': 'bool',
            },
            'use_rcv_hop_for_resp': {
                'type': 'bool',
            },
            'persist_type': {
                'type':
                'str',
                'choices': [
                    'src-dst-ip-swap-persist', 'use-src-ip-for-dst-persist',
                    'use-dst-ip-for-src-persist'
                ]
            },
            'use_rcv_hop_group': {
                'type': 'bool',
            },
            'server_group': {
                'type': 'str',
            },
            'eth_fwd': {
                'type': 'str',
            },
            'trunk_fwd': {
                'type': 'str',
            },
            'eth_rev': {
                'type': 'str',
            },
            'trunk_rev': {
                'type': 'str',
            },
            'template_sip': {
                'type': 'str',
            },
            'template_smpp': {
                'type': 'str',
            },
            'template_dblb': {
                'type': 'str',
            },
            'template_connection_reuse': {
                'type': 'str',
            },
            'shared_partition_connection_reuse_template': {
                'type': 'bool',
            },
            'template_connection_reuse_shared': {
                'type': 'str',
            },
            'template_dns': {
                'type': 'str',
            },
            'shared_partition_dns_template': {
                'type': 'bool',
            },
            'template_dns_shared': {
                'type': 'str',
            },
            'template_dynamic_service': {
                'type': 'str',
            },
            'shared_partition_dynamic_service_template': {
                'type': 'bool',
            },
            'template_dynamic_service_shared': {
                'type': 'str',
            },
            'template_persist_source_ip': {
                'type': 'str',
            },
            'shared_partition_persist_source_ip_template': {
                'type': 'bool',
            },
            'template_persist_source_ip_shared': {
                'type': 'str',
            },
            'template_persist_destination_ip': {
                'type': 'str',
            },
            'shared_partition_persist_destination_ip_template': {
                'type': 'bool',
            },
            'template_persist_destination_ip_shared': {
                'type': 'str',
            },
            'template_persist_ssl_sid': {
                'type': 'str',
            },
            'shared_partition_persist_ssl_sid_template': {
                'type': 'bool',
            },
            'template_persist_ssl_sid_shared': {
                'type': 'str',
            },
            'template_persist_cookie': {
                'type': 'str',
            },
            'shared_partition_persist_cookie_template': {
                'type': 'bool',
            },
            'template_persist_cookie_shared': {
                'type': 'str',
            },
            'template_imap_pop3': {
                'type': 'str',
            },
            'template_smtp': {
                'type': 'str',
            },
            'template_http': {
                'type': 'str',
            },
            'shared_partition_http_template': {
                'type': 'bool',
            },
            'template_http_shared': {
                'type': 'str',
            },
            'template_http_policy': {
                'type': 'str',
            },
            'shared_partition_http_policy_template': {
                'type': 'bool',
            },
            'template_http_policy_shared': {
                'type': 'str',
            },
            'redirect_to_https': {
                'type': 'bool',
            },
            'template_external_service': {
                'type': 'str',
            },
            'shared_partition_external_service_template': {
                'type': 'bool',
            },
            'template_external_service_shared': {
                'type': 'str',
            },
            'template_reqmod_icap': {
                'type': 'str',
            },
            'template_respmod_icap': {
                'type': 'str',
            },
            'template_file_inspection': {
                'type': 'str',
            },
            'template_server_ssl': {
                'type': 'str',
            },
            'shared_partition_server_ssl_template': {
                'type': 'bool',
            },
            'template_server_ssl_shared': {
                'type': 'str',
            },
            'template_client_ssl': {
                'type': 'str',
            },
            'shared_partition_client_ssl_template': {
                'type': 'bool',
            },
            'template_client_ssl_shared': {
                'type': 'str',
            },
            'template_server_ssh': {
                'type': 'str',
            },
            'template_client_ssh': {
                'type': 'str',
            },
            'template_udp': {
                'type': 'str',
            },
            'shared_partition_udp': {
                'type': 'bool',
            },
            'template_udp_shared': {
                'type': 'str',
            },
            'template_tcp': {
                'type': 'str',
            },
            'shared_partition_tcp': {
                'type': 'bool',
            },
            'template_tcp_shared': {
                'type': 'str',
            },
            'template_virtual_port': {
                'type': 'str',
            },
            'shared_partition_virtual_port_template': {
                'type': 'bool',
            },
            'template_virtual_port_shared': {
                'type': 'str',
            },
            'template_ftp': {
                'type': 'str',
            },
            'template_diameter': {
                'type': 'str',
            },
            'shared_partition_diameter_template': {
                'type': 'bool',
            },
            'template_diameter_shared': {
                'type': 'str',
            },
            'template_cache': {
                'type': 'str',
            },
            'shared_partition_cache_template': {
                'type': 'bool',
            },
            'template_cache_shared': {
                'type': 'str',
            },
            'template_fix': {
                'type': 'str',
            },
            'waf_template': {
                'type': 'str',
            },
            'template_ssli': {
                'type': 'str',
            },
            'template_tcp_proxy_client': {
                'type': 'str',
            },
            'template_tcp_proxy_server': {
                'type': 'str',
            },
            'template_tcp_proxy': {
                'type': 'str',
            },
            'shared_partition_tcp_proxy_template': {
                'type': 'bool',
            },
            'template_tcp_proxy_shared': {
                'type': 'str',
            },
            'use_default_if_no_server': {
                'type': 'bool',
            },
            'template_scaleout': {
                'type': 'str',
            },
            'no_dest_nat': {
                'type': 'bool',
            },
            'port_translation': {
                'type': 'bool',
            },
            'l7_hardware_assist': {
                'type': 'bool',
            },
            'auth_cfg': {
                'type': 'dict',
                'aaa_policy': {
                    'type': 'str',
                }
            },
            'cpu_compute': {
                'type': 'bool',
            },
            'memory_compute': {
                'type': 'bool',
            },
            'resolve_web_cat_list': {
                'type': 'str',
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
                        'all', 'curr_conn', 'total_l4_conn', 'total_l7_conn',
                        'total_tcp_conn', 'total_conn', 'total_fwd_bytes',
                        'total_fwd_pkts', 'total_rev_bytes', 'total_rev_pkts',
                        'total_dns_pkts', 'total_mf_dns_pkts',
                        'es_total_failure_actions', 'compression_bytes_before',
                        'compression_bytes_after', 'compression_hit',
                        'compression_miss', 'compression_miss_no_client',
                        'compression_miss_template_exclusion', 'curr_req',
                        'total_req', 'total_req_succ', 'peak_conn',
                        'curr_conn_rate', 'last_rsp_time', 'fastest_rsp_time',
                        'slowest_rsp_time', 'loc_permit', 'loc_deny',
                        'loc_conn', 'curr_ssl_conn', 'total_ssl_conn',
                        'backend-time-to-first-byte',
                        'backend-time-to-last-byte', 'in-latency',
                        'out-latency', 'total_fwd_bytes_out',
                        'total_fwd_pkts_out', 'total_rev_bytes_out',
                        'total_rev_pkts_out', 'curr_req_rate', 'curr_resp',
                        'total_resp', 'total_resp_succ', 'curr_resp_rate',
                        'curr_conn_overflow', 'dnsrrl_total_allowed',
                        'dnsrrl_total_dropped', 'dnsrrl_total_slipped',
                        'dnsrrl_bad_fqdn', 'throughput-bits-per-sec',
                        'dynamic-memory-alloc', 'dynamic-memory-free',
                        'dynamic-memory', 'ip_only_lb_fwd_bytes',
                        'ip_only_lb_rev_bytes', 'ip_only_lb_fwd_pkts',
                        'ip_only_lb_rev_pkts'
                    ]
                }
            }
        },
        'oper': {
            'type': 'dict',
            'mac': {
                'type': 'str',
            },
            'state': {
                'type':
                'str',
                'choices': [
                    'All Up', 'Functional Up', 'Partial Up', 'Down', 'Disb',
                    'Unkn'
                ]
            },
            'curr_conn_rate': {
                'type': 'int',
            },
            'conn_rate_unit': {
                'type': 'str',
                'choices': ['100ms', 'second']
            },
            'curr_icmp_rate': {
                'type': 'int',
            },
            'icmp_lockup_time_left': {
                'type': 'int',
            },
            'icmp_rate_over_limit_drop': {
                'type': 'int',
            },
            'curr_icmpv6_rate': {
                'type': 'int',
            },
            'icmpv6_lockup_time_left': {
                'type': 'int',
            },
            'icmpv6_rate_over_limit_drop': {
                'type': 'int',
            },
            'migration_status': {
                'type': 'str',
            },
            'peak_conn': {
                'type': 'int',
            },
            'ip_address': {
                'type': 'str',
            },
            'curr_conn_overflow': {
                'type': 'int',
            },
            'ip_only_lb_fwd_bytes': {
                'type': 'int',
            },
            'ip_only_lb_rev_bytes': {
                'type': 'int',
            },
            'ip_only_lb_fwd_pkts': {
                'type': 'int',
            },
            'ip_only_lb_rev_pkts': {
                'type': 'int',
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'migrate_vip': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'state': {
                        'type':
                        'str',
                        'choices': [
                            'Sync started', 'Sync complete', 'Quiet mode',
                            'Not in migration'
                        ]
                    }
                }
            },
            'port_list': {
                'type': 'list',
                'port_number': {
                    'type': 'int',
                    'required': True,
                },
                'protocol': {
                    'type':
                    'str',
                    'required':
                    True,
                    'choices': [
                        'tcp', 'udp', 'others', 'diameter', 'dns-tcp',
                        'dns-udp', 'fast-http', 'fix', 'ftp', 'ftp-proxy',
                        'http', 'https', 'http2', 'http2s', 'imap', 'mlb',
                        'mms', 'mysql', 'mssql', 'pop3', 'radius', 'rtsp',
                        'sip', 'sip-tcp', 'sips', 'smpp-tcp', 'spdy', 'spdys',
                        'smtp', 'ssl-proxy', 'ssli', 'ssh', 'tcp-proxy',
                        'tftp', 'fast-fix'
                    ]
                },
                'oper': {
                    'type': 'dict',
                    'state': {
                        'type':
                        'str',
                        'choices':
                        ['All Up', 'Functional Up', 'Down', 'Disb', 'Unkn']
                    },
                    'loc_list': {
                        'type': 'str',
                    },
                    'geo_location': {
                        'type': 'str',
                    },
                    'level_str': {
                        'type': 'str',
                    },
                    'group_id': {
                        'type': 'int',
                    },
                    'loc_max_depth': {
                        'type': 'int',
                    },
                    'loc_success': {
                        'type': 'int',
                    },
                    'loc_error': {
                        'type': 'int',
                    },
                    'loc_override': {
                        'type': 'int',
                    },
                    'loc_last': {
                        'type': 'str',
                    },
                    'http_hits_list': {
                        'type': 'list',
                        'name': {
                            'type': 'str',
                        },
                        'hits_count': {
                            'type': 'int',
                        }
                    },
                    'http_vport_cpu_list': {
                        'type': 'list',
                        'status_200': {
                            'type': 'int',
                        },
                        'status_201': {
                            'type': 'int',
                        },
                        'status_202': {
                            'type': 'int',
                        },
                        'status_203': {
                            'type': 'int',
                        },
                        'status_204': {
                            'type': 'int',
                        },
                        'status_205': {
                            'type': 'int',
                        },
                        'status_206': {
                            'type': 'int',
                        },
                        'status_207': {
                            'type': 'int',
                        },
                        'status_100': {
                            'type': 'int',
                        },
                        'status_101': {
                            'type': 'int',
                        },
                        'status_102': {
                            'type': 'int',
                        },
                        'status_300': {
                            'type': 'int',
                        },
                        'status_301': {
                            'type': 'int',
                        },
                        'status_302': {
                            'type': 'int',
                        },
                        'status_303': {
                            'type': 'int',
                        },
                        'status_304': {
                            'type': 'int',
                        },
                        'status_305': {
                            'type': 'int',
                        },
                        'status_306': {
                            'type': 'int',
                        },
                        'status_307': {
                            'type': 'int',
                        },
                        'status_400': {
                            'type': 'int',
                        },
                        'status_401': {
                            'type': 'int',
                        },
                        'status_402': {
                            'type': 'int',
                        },
                        'status_403': {
                            'type': 'int',
                        },
                        'status_404': {
                            'type': 'int',
                        },
                        'status_405': {
                            'type': 'int',
                        },
                        'status_406': {
                            'type': 'int',
                        },
                        'status_407': {
                            'type': 'int',
                        },
                        'status_408': {
                            'type': 'int',
                        },
                        'status_409': {
                            'type': 'int',
                        },
                        'status_410': {
                            'type': 'int',
                        },
                        'status_411': {
                            'type': 'int',
                        },
                        'status_412': {
                            'type': 'int',
                        },
                        'status_413': {
                            'type': 'int',
                        },
                        'status_414': {
                            'type': 'int',
                        },
                        'status_415': {
                            'type': 'int',
                        },
                        'status_416': {
                            'type': 'int',
                        },
                        'status_417': {
                            'type': 'int',
                        },
                        'status_418': {
                            'type': 'int',
                        },
                        'status_422': {
                            'type': 'int',
                        },
                        'status_423': {
                            'type': 'int',
                        },
                        'status_424': {
                            'type': 'int',
                        },
                        'status_425': {
                            'type': 'int',
                        },
                        'status_426': {
                            'type': 'int',
                        },
                        'status_449': {
                            'type': 'int',
                        },
                        'status_450': {
                            'type': 'int',
                        },
                        'status_500': {
                            'type': 'int',
                        },
                        'status_501': {
                            'type': 'int',
                        },
                        'status_502': {
                            'type': 'int',
                        },
                        'status_503': {
                            'type': 'int',
                        },
                        'status_504': {
                            'type': 'int',
                        },
                        'status_504_ax': {
                            'type': 'int',
                        },
                        'status_505': {
                            'type': 'int',
                        },
                        'status_506': {
                            'type': 'int',
                        },
                        'status_507': {
                            'type': 'int',
                        },
                        'status_508': {
                            'type': 'int',
                        },
                        'status_509': {
                            'type': 'int',
                        },
                        'status_510': {
                            'type': 'int',
                        },
                        'status_1xx': {
                            'type': 'int',
                        },
                        'status_2xx': {
                            'type': 'int',
                        },
                        'status_3xx': {
                            'type': 'int',
                        },
                        'status_4xx': {
                            'type': 'int',
                        },
                        'status_5xx': {
                            'type': 'int',
                        },
                        'status_6xx': {
                            'type': 'int',
                        },
                        'status_unknown': {
                            'type': 'int',
                        },
                        'ws_handshake_request': {
                            'type': 'int',
                        },
                        'ws_handshake_success': {
                            'type': 'int',
                        },
                        'ws_client_switch': {
                            'type': 'int',
                        },
                        'ws_server_switch': {
                            'type': 'int',
                        },
                        'REQ_10u': {
                            'type': 'int',
                        },
                        'REQ_20u': {
                            'type': 'int',
                        },
                        'REQ_50u': {
                            'type': 'int',
                        },
                        'REQ_100u': {
                            'type': 'int',
                        },
                        'REQ_200u': {
                            'type': 'int',
                        },
                        'REQ_500u': {
                            'type': 'int',
                        },
                        'REQ_1m': {
                            'type': 'int',
                        },
                        'REQ_2m': {
                            'type': 'int',
                        },
                        'REQ_5m': {
                            'type': 'int',
                        },
                        'REQ_10m': {
                            'type': 'int',
                        },
                        'REQ_20m': {
                            'type': 'int',
                        },
                        'REQ_50m': {
                            'type': 'int',
                        },
                        'REQ_100m': {
                            'type': 'int',
                        },
                        'REQ_200m': {
                            'type': 'int',
                        },
                        'REQ_500m': {
                            'type': 'int',
                        },
                        'REQ_1s': {
                            'type': 'int',
                        },
                        'REQ_2s': {
                            'type': 'int',
                        },
                        'REQ_5s': {
                            'type': 'int',
                        },
                        'REQ_OVER_5s': {
                            'type': 'int',
                        },
                        'curr_http2_conn': {
                            'type': 'int',
                        },
                        'total_http2_conn': {
                            'type': 'int',
                        },
                        'peak_http2_conn': {
                            'type': 'int',
                        },
                        'total_http2_bytes': {
                            'type': 'int',
                        },
                        'http2_control_bytes': {
                            'type': 'int',
                        },
                        'http2_header_bytes': {
                            'type': 'int',
                        },
                        'http2_data_bytes': {
                            'type': 'int',
                        },
                        'http2_reset_received': {
                            'type': 'int',
                        },
                        'http2_reset_sent': {
                            'type': 'int',
                        },
                        'http2_goaway_received': {
                            'type': 'int',
                        },
                        'http2_goaway_sent': {
                            'type': 'int',
                        },
                        'stream_closed': {
                            'type': 'int',
                        },
                        'header_length_long': {
                            'type': 'int',
                        }
                    },
                    'cpu_count': {
                        'type': 'int',
                    },
                    'http_host_hits': {
                        'type': 'bool',
                    },
                    'http_url_hits': {
                        'type': 'bool',
                    },
                    'http_vport': {
                        'type': 'bool',
                    },
                    'real_curr_conn': {
                        'type': 'int',
                    }
                }
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/virtual-server/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
    return module.client.get(oper_url(module))


def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None


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
    url_base = "/axapi/v3/slb/virtual-server/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
    if existing_config:
        for k, v in payload["virtual-server"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["virtual-server"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["virtual-server"][k] = v
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
    payload = build_json("virtual-server", module)
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

    result = dict(changed=False, original_message="", message="", result={})

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
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
