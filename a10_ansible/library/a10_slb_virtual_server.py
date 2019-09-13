#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_virtual_server
description:
    - Create a Virtual Server
short_description: Configures A10 slb.virtual-server
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
    partition:
        description:
        - Destination/target partition for object/command
    port_list:
        description:
        - "Field port_list"
        required: False
        suboptions:
            ha_conn_mirror:
                description:
                - "Enable for HA Conn sync"
            protocol:
                description:
                - "'tcp'= TCP LB service; 'udp'= UDP Port; 'others'= for no tcp/udp protocol, do IP load balancing; 'diameter'= diameter port; 'dns-tcp'= DNS service over TCP; 'dns-udp'= DNS service over UDP; 'fast-http'= Fast HTTP Port; 'fix'= FIX Port; 'ftp'= File Transfer Protocol Port; 'ftp-proxy'= ftp proxy port; 'http'= HTTP Port; 'https'= HTTPS port; 'http2'= [Deprecated] HTTP2 Port; 'http2s'= [Deprecated] HTTP2 SSL port; 'imap'= imap proxy port; 'mlb'= Message based load balancing; 'mms'= Microsoft Multimedia Service Port; 'mysql'= mssql port; 'mssql'= mssql; 'pop3'= pop3 proxy port; 'radius'= RADIUS Port; 'rtsp'= Real Time Streaming Protocol Port; 'sip'= Session initiation protocol over UDP; 'sip-tcp'= Session initiation protocol over TCP; 'sips'= Session initiation protocol over TLS; 'smpp-tcp'= SMPP service over TCP; 'spdy'= spdy port; 'spdys'= spdys port; 'smtp'= SMTP Port; 'ssl-proxy'= Generic SSL proxy; 'ssli'= SSL insight; 'ssh'= SSH Port; 'tcp-proxy'= Generic TCP proxy; 'tftp'= TFTP Port; 'fast-fix'= Fast FIX port; "
            cpu_compute:
                description:
                - "enable cpu compute on virtual port"
            precedence:
                description:
                - "Set auto NAT pool as higher precedence for source NAT"
            port_translation:
                description:
                - "Enable port translation under no-dest-nat"
            ip_map_list:
                description:
                - "Enter name of IP Map List to be bound (IP Map List Name)"
            template_reqmod_icap:
                description:
                - "ICAP reqmod template (reqmod-icap template name)"
            acl_name_list:
                description:
                - "Field acl_name_list"
            stats_data_action:
                description:
                - "'stats-data-enable'= Enable statistical data collection for virtual port; 'stats-data-disable'= Disable statistical data collection for virtual port; "
            use_default_if_no_server:
                description:
                - "Use default forwarding if server selection failed"
            template_connection_reuse:
                description:
                - "Connection Reuse Template (Connection Reuse Template Name)"
            uuid:
                description:
                - "uuid of the object"
            template_tcp_shared:
                description:
                - "TCP Template Name"
            template_tcp:
                description:
                - "TCP Template Name"
            template_persist_cookie:
                description:
                - "Cookie persistence (Cookie persistence template name)"
            shared_partition_dynamic_service_template:
                description:
                - "Reference a dynamic service template from shared partition"
            shared_partition_connection_reuse_template:
                description:
                - "Reference a connection reuse template from shared partition"
            when_down:
                description:
                - "Use alternate virtual port when down"
            template_client_ssl_shared:
                description:
                - "Client SSL Template Name"
            shared_partition_persist_destination_ip_template:
                description:
                - "Reference a persist destination ip template from shared partition"
            shared_partition_external_service_template:
                description:
                - "Reference a external service template from shared partition"
            persist_type:
                description:
                - "'src-dst-ip-swap-persist'= Create persist session after source IP and destination IP swap; 'use-src-ip-for-dst-persist'= Use the source IP to create a destination persist session; 'use-dst-ip-for-src-persist'= Use the destination IP to create source IP persist session; "
            shared_partition_http_policy_template:
                description:
                - "Reference a http policy template from shared partition"
            use_rcv_hop_for_resp:
                description:
                - "Use receive hop for response to client(For packets on default-vlan, also config 'vlan-global enable-def-vlan-l2-forwarding'.)"
            scaleout_bucket_count:
                description:
                - "Number of traffic buckets"
            optimization_level:
                description:
                - "'0'= No optimization; '1'= Optimization level 1 (Experimental); "
            req_fail:
                description:
                - "Use alternate virtual port when L7 request fail"
            no_dest_nat:
                description:
                - "Disable destination NAT, this option only supports in wildcard VIP or when a connection is operated in SSLi + EP mode"
            name:
                description:
                - "SLB Virtual Service Name"
            template_smpp:
                description:
                - "SMPP template"
            user_tag:
                description:
                - "Customized tag"
            template_diameter:
                description:
                - "Diameter Template (diameter template name)"
            sampling_enable:
                description:
                - "Field sampling_enable"
            template_ssli:
                description:
                - "SSLi template (SSLi Template Name)"
            memory_compute:
                description:
                - "enable dynamic memory compute on virtual port"
            shared_partition_policy_template:
                description:
                - "Reference a policy template from shared partition"
            template_policy:
                description:
                - "Policy Template (Policy template name)"
            no_logging:
                description:
                - "Do not log connection over limit event"
            reset_on_server_selection_fail:
                description:
                - "Send client reset when server selection fails"
            waf_template:
                description:
                - "WAF template (WAF Template Name)"
            ipinip:
                description:
                - "Enable IP in IP"
            no_auto_up_on_aflex:
                description:
                - "Don't automatically mark vport up when aFleX is bound"
            rate:
                description:
                - "Specify the log message rate"
            gslb_enable:
                description:
                - "Enable Global Server Load Balancing"
            template_dns_shared:
                description:
                - "DNS Template Name"
            template_persist_ssl_sid:
                description:
                - "SSL SID persistence (SSL SID persistence template name)"
            template_dns:
                description:
                - "DNS template (DNS template name)"
            shared_partition_dns_template:
                description:
                - "Reference a dns template from shared partition"
            template_sip:
                description:
                - "SIP template"
            template_dblb:
                description:
                - "DBLB Template (DBLB template name)"
            shared_partition_server_ssl_template:
                description:
                - "Reference a SSL Server template from shared partition"
            template_client_ssl:
                description:
                - "Client SSL Template Name"
            support_http2:
                description:
                - "Support HTTP2"
            template_client_ssh:
                description:
                - "Client SSH Template (Client SSH Config Name)"
            shared_partition_tcp_proxy_template:
                description:
                - "Reference a TCP Proxy template from shared partition"
            enable_playerid_check:
                description:
                - "Enable playerid checks on UDP packets once the AX is in active mode"
            service_group:
                description:
                - "Bind a Service Group to this Virtual Server (Service Group Name)"
            shared_partition_persist_ssl_sid_template:
                description:
                - "Reference a persist SSL SID template from shared partition"
            def_selection_if_pref_failed:
                description:
                - "'def-selection-if-pref-failed'= Use default server selection method if prefer method failed; 'def-selection-if-pref-failed-disable'= Stop using default server selection method if prefer method failed; "
            shared_partition_udp:
                description:
                - "Reference a UDP template from shared partition"
            syn_cookie:
                description:
                - "Enable syn-cookie"
            alternate_port:
                description:
                - "Alternate Virtual Port"
            alternate_port_number:
                description:
                - "Virtual Port"
            template_persist_source_ip_shared:
                description:
                - "Source IP Persistence Template Name"
            template_cache:
                description:
                - "RAM caching template (Cache Template Name)"
            template_persist_cookie_shared:
                description:
                - "Cookie Persistence Template Name"
            rtp_sip_call_id_match:
                description:
                - "rtp traffic try to match the real server of sip smp call-id session"
            shared_partition_persist_cookie_template:
                description:
                - "Reference a persist cookie template from shared partition"
            template_file_inspection:
                description:
                - "File Inspection service template (file-inspection template name)"
            template_ftp:
                description:
                - "FTP port template (Ftp template name)"
            serv_sel_fail:
                description:
                - "Use alternate virtual port when server selection failure"
            template_udp:
                description:
                - "L4 UDP Template"
            template_virtual_port_shared:
                description:
                - "Virtual Port Template Name"
            action:
                description:
                - "'enable'= Enable; 'disable'= Disable; "
            template_http:
                description:
                - "HTTP Template Name"
            view:
                description:
                - "Specify a GSLB View (ID)"
            template_persist_source_ip:
                description:
                - "Source IP persistence (Source IP persistence template name)"
            template_dynamic_service:
                description:
                - "Dynamic Service Template (dynamic-service template name)"
            shared_partition_virtual_port_template:
                description:
                - "Reference a Virtual Port template from shared partition"
            use_cgnv6:
                description:
                - "Follow CGNv6 source NAT configuration"
            template_persist_destination_ip:
                description:
                - "Destination IP persistence (Destination IP persistence template name)"
            template_virtual_port:
                description:
                - "Virtual port template (Virtual port template name)"
            conn_limit:
                description:
                - "Connection Limit"
            trunk_fwd:
                description:
                - "Trunk interface number"
            template_udp_shared:
                description:
                - "UDP Template Name"
            template_http_policy_shared:
                description:
                - "Http Policy Template Name"
            pool:
                description:
                - "Specify NAT pool or pool group"
            snat_on_vip:
                description:
                - "Enable source NAT traffic against VIP"
            template_connection_reuse_shared:
                description:
                - "Connection Reuse Template Name"
            shared_partition_tcp:
                description:
                - "Reference a tcp template from shared partition"
            acl_id_list:
                description:
                - "Field acl_id_list"
            shared_partition_http_template:
                description:
                - "Reference a HTTP template from shared partition"
            template_external_service:
                description:
                - "External service template (external-service template name)"
            on_syn:
                description:
                - "Enable for HA Conn sync for l4 tcp sessions on SYN"
            template_persist_ssl_sid_shared:
                description:
                - "SSL SID Persistence Template Name"
            force_routing_mode:
                description:
                - "Force routing mode"
            template_http_policy:
                description:
                - "http-policy template (http-policy template name)"
            template_policy_shared:
                description:
                - "Policy Template Name"
            template_scaleout:
                description:
                - "Scaleout template (Scaleout template name)"
            when_down_protocol2:
                description:
                - "Use alternate virtual port when down"
            template_fix:
                description:
                - "FIX template (FIX Template Name)"
            template_smtp:
                description:
                - "SMTP Template (SMTP Config Name)"
            redirect_to_https:
                description:
                - "Redirect HTTP to HTTPS"
            alt_protocol2:
                description:
                - "'tcp'= TCP LB service; "
            alt_protocol1:
                description:
                - "'http'= HTTP Port; "
            message_switching:
                description:
                - "Message switching"
            template_imap_pop3:
                description:
                - "IMAP/POP3 Template (IMAP/POP3 Config Name)"
            scaleout_device_group:
                description:
                - "Device group id"
            shared_partition_persist_source_ip_template:
                description:
                - "Reference a persist source ip template from shared partition"
            l7_hardware_assist:
                description:
                - "FPGA assist L7 packet parsing"
            template_tcp_proxy_shared:
                description:
                - "TCP Proxy Template name"
            shared_partition_cache_template:
                description:
                - "Reference a Cache template from shared partition"
            use_alternate_port:
                description:
                - "Use alternate virtual port"
            template_tcp_proxy_server:
                description:
                - "TCP Proxy Config Server (TCP Proxy Config name)"
            trunk_rev:
                description:
                - "Trunk interface number"
            eth_fwd:
                description:
                - "Ethernet interface number"
            pool_shared:
                description:
                - "Specify NAT pool or pool group"
            template_respmod_icap:
                description:
                - "ICAP respmod service template (respmod-icap template name)"
            range:
                description:
                - "Virtual Port range (Virtual Port range value)"
            reset:
                description:
                - "Send client reset when connection number over limit"
            template_external_service_shared:
                description:
                - "External Service Template Name"
            auto:
                description:
                - "Configure auto NAT for the vport"
            template_dynamic_service_shared:
                description:
                - "Dynamic Service Template Name"
            template_server_ssh:
                description:
                - "Server SSH Template (Server SSH Config Name)"
            aflex_scripts:
                description:
                - "Field aflex_scripts"
            template_http_shared:
                description:
                - "HTTP Template Name"
            template_server_ssl:
                description:
                - "Server Side SSL Template Name"
            shared_partition_diameter_template:
                description:
                - "Reference a Diameter template from shared partition"
            template_server_ssl_shared:
                description:
                - "Server SSL Template Name"
            template_persist_destination_ip_shared:
                description:
                - "Destination IP Persistence Template Name"
            template_cache_shared:
                description:
                - "Cache Template Name"
            port_number:
                description:
                - "Port"
            template_tcp_proxy_client:
                description:
                - "TCP Proxy Config Client (TCP Proxy Config name)"
            shared_partition_pool:
                description:
                - "Specify NAT pool or pool group from shared partition"
            template_tcp_proxy:
                description:
                - "TCP Proxy Template Name"
            extended_stats:
                description:
                - "Enable extended statistics on virtual port"
            shared_partition_client_ssl_template:
                description:
                - "Reference a Client SSL template from shared partition"
            expand:
                description:
                - "expand syn-cookie with timestamp and wscale"
            skip_rev_hash:
                description:
                - "Skip rev tuple hash insertion"
            template_diameter_shared:
                description:
                - "Diameter Template Name"
            clientip_sticky_nat:
                description:
                - "Prefer to use same source NAT address for a client"
            secs:
                description:
                - "Specify the interval in seconds"
            auth_cfg:
                description:
                - "Field auth_cfg"
            eth_rev:
                description:
                - "Ethernet interface number"
    stats_data_action:
        description:
        - "'stats-data-enable'= Enable statistical data collection for virtual server; 'stats-data-disable'= Disable statistical data collection for virtual server; "
        required: False
    ipv6_acl_shared:
        description:
        - "ipv6 acl name"
        required: False
    acl_name:
        description:
        - "Access List name (IPv4 Access List Name)"
        required: False
    enable_disable_action:
        description:
        - "'enable'= Enable Virtual Server (default); 'disable'= Disable Virtual Server; 'disable-when-all-ports-down'= Disable Virtual Server when all member ports are down; 'disable-when-any-port-down'= Disable Virtual Server when any member port is down; "
        required: False
    ha_dynamic:
        description:
        - "Dynamic failover based on vip status"
        required: False
    redistribute_route_map:
        description:
        - "Route map reference (Name of route-map)"
        required: False
    acl_name_shared:
        description:
        - "Access List name (IPv4 Access List Name)"
        required: False
    ip_address:
        description:
        - "IP Address"
        required: False
    vport_disable_action:
        description:
        - "'drop-packet'= Drop packet for disabled virtual-port; "
        required: False
    template_logging:
        description:
        - "NAT Logging template (NAT Logging template name)"
        required: False
    use_if_ip:
        description:
        - "Use Interface IP"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    vrid:
        description:
        - "Join a vrrp group (Specify ha VRRP-A vrid)"
        required: False
    disable_vip_adv:
        description:
        - "Disable virtual server GARP"
        required: False
    template_virtual_server:
        description:
        - "Virtual server template (Virtual server template name)"
        required: False
    arp_disable:
        description:
        - "Disable Respond to Virtual Server ARP request"
        required: False
    description:
        description:
        - "Create a description for VIP"
        required: False
    redistribution_flagged:
        description:
        - "Flag VIP for special redistribution handling"
        required: False
    netmask:
        description:
        - "IP subnet mask"
        required: False
    acl_id:
        description:
        - "acl id"
        required: False
    ipv6_acl:
        description:
        - "ipv6 acl name"
        required: False
    migrate_vip:
        description:
        - "Field migrate_vip"
        required: False
        suboptions:
            target_data_cpu:
                description:
                - "Number of CPUs on the target platform"
            uuid:
                description:
                - "uuid of the object"
            finish_migration:
                description:
                - "Complete the migration"
            target_floating_ipv6:
                description:
                - "Specify IPv6 address"
            target_floating_ipv4:
                description:
                - "Specify IP address"
            cancel_migration:
                description:
                - "Cancel migration"
    extended_stats:
        description:
        - "Enable extended statistics on virtual server"
        required: False
    name:
        description:
        - "SLB Virtual Server Name"
        required: True
    template_scaleout:
        description:
        - "Scaleout template (Scaleout template name)"
        required: False
    template_policy:
        description:
        - "Policy template (Policy template name)"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    template_policy_shared:
        description:
        - "Policy Template Name"
        required: False
    ipv6_address:
        description:
        - "IPV6 address"
        required: False
    ethernet:
        description:
        - "Ethernet interface"
        required: False
    shared_partition_policy_template:
        description:
        - "Reference a policy template from shared partition"
        required: False
    acl_id_shared:
        description:
        - "acl id"
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
AVAILABLE_PROPERTIES = ["acl_id","acl_id_shared","acl_name","acl_name_shared","arp_disable","description","disable_vip_adv","enable_disable_action","ethernet","extended_stats","ha_dynamic","ip_address","ipv6_acl","ipv6_acl_shared","ipv6_address","migrate_vip","name","netmask","port_list","redistribute_route_map","redistribution_flagged","shared_partition_policy_template","stats_data_action","template_logging","template_policy","template_policy_shared","template_scaleout","template_virtual_server","use_if_ip","user_tag","uuid","vport_disable_action","vrid",]

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
        partition=dict(type='str', required=False),
        get_type=dict(type='str', choices=["single", "list"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        port_list=dict(type='list',ha_conn_mirror=dict(type='bool',),protocol=dict(type='str',required=True,choices=['tcp','udp','others','diameter','dns-tcp','dns-udp','fast-http','fix','ftp','ftp-proxy','http','https','http2','http2s','imap','mlb','mms','mysql','mssql','pop3','radius','rtsp','sip','sip-tcp','sips','smpp-tcp','spdy','spdys','smtp','ssl-proxy','ssli','ssh','tcp-proxy','tftp','fast-fix']),cpu_compute=dict(type='bool',),precedence=dict(type='bool',),port_translation=dict(type='bool',),ip_map_list=dict(type='str',),template_reqmod_icap=dict(type='str',),acl_name_list=dict(type='list',acl_name_src_nat_pool_shared=dict(type='str',),v_acl_name_src_nat_pool_shared=dict(type='str',),shared_partition_pool_name=dict(type='bool',),acl_name_seq_num_shared=dict(type='int',),acl_name=dict(type='str',),v_shared_partition_pool_name=dict(type='bool',),acl_name_src_nat_pool=dict(type='str',),v_acl_name_seq_num=dict(type='int',),acl_name_shared=dict(type='str',),acl_name_seq_num=dict(type='int',),v_acl_name_src_nat_pool=dict(type='str',),v_acl_name_seq_num_shared=dict(type='int',)),stats_data_action=dict(type='str',choices=['stats-data-enable','stats-data-disable']),use_default_if_no_server=dict(type='bool',),template_connection_reuse=dict(type='str',),uuid=dict(type='str',),template_tcp_shared=dict(type='str',),template_tcp=dict(type='str',),template_persist_cookie=dict(type='str',),shared_partition_dynamic_service_template=dict(type='bool',),shared_partition_connection_reuse_template=dict(type='bool',),when_down=dict(type='bool',),template_client_ssl_shared=dict(type='str',),shared_partition_persist_destination_ip_template=dict(type='bool',),shared_partition_external_service_template=dict(type='bool',),persist_type=dict(type='str',choices=['src-dst-ip-swap-persist','use-src-ip-for-dst-persist','use-dst-ip-for-src-persist']),shared_partition_http_policy_template=dict(type='bool',),use_rcv_hop_for_resp=dict(type='bool',),scaleout_bucket_count=dict(type='int',),optimization_level=dict(type='str',choices=['0','1']),req_fail=dict(type='bool',),no_dest_nat=dict(type='bool',),name=dict(type='str',),template_smpp=dict(type='str',),user_tag=dict(type='str',),template_diameter=dict(type='str',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','curr_conn','total_l4_conn','total_l7_conn','total_tcp_conn','total_conn','total_fwd_bytes','total_fwd_pkts','total_rev_bytes','total_rev_pkts','total_dns_pkts','total_mf_dns_pkts','es_total_failure_actions','compression_bytes_before','compression_bytes_after','compression_hit','compression_miss','compression_miss_no_client','compression_miss_template_exclusion','curr_req','total_req','total_req_succ','peak_conn','curr_conn_rate','last_rsp_time','fastest_rsp_time','slowest_rsp_time','loc_permit','loc_deny','loc_conn','curr_ssl_conn','total_ssl_conn','backend-time-to-first-byte','backend-time-to-last-byte','in-latency','out-latency','total_fwd_bytes_out','total_fwd_pkts_out','total_rev_bytes_out','total_rev_pkts_out','curr_req_rate','curr_resp','total_resp','total_resp_succ','curr_resp_rate','curr_conn_overflow','dnsrrl_total_allowed','dnsrrl_total_dropped','dnsrrl_total_slipped','dnsrrl_bad_fqdn','throughput-bits-per-sec','dynamic-memory-alloc','dynamic-memory-free','dynamic-memory'])),template_ssli=dict(type='str',),memory_compute=dict(type='bool',),shared_partition_policy_template=dict(type='bool',),template_policy=dict(type='str',),no_logging=dict(type='bool',),reset_on_server_selection_fail=dict(type='bool',),waf_template=dict(type='str',),ipinip=dict(type='bool',),no_auto_up_on_aflex=dict(type='bool',),rate=dict(type='int',),gslb_enable=dict(type='bool',),template_dns_shared=dict(type='str',),template_persist_ssl_sid=dict(type='str',),template_dns=dict(type='str',),shared_partition_dns_template=dict(type='bool',),template_sip=dict(type='str',),template_dblb=dict(type='str',),shared_partition_server_ssl_template=dict(type='bool',),template_client_ssl=dict(type='str',),support_http2=dict(type='bool',),template_client_ssh=dict(type='str',),shared_partition_tcp_proxy_template=dict(type='bool',),enable_playerid_check=dict(type='bool',),service_group=dict(type='str',),shared_partition_persist_ssl_sid_template=dict(type='bool',),def_selection_if_pref_failed=dict(type='str',choices=['def-selection-if-pref-failed','def-selection-if-pref-failed-disable']),shared_partition_udp=dict(type='bool',),syn_cookie=dict(type='bool',),alternate_port=dict(type='bool',),alternate_port_number=dict(type='int',),template_persist_source_ip_shared=dict(type='str',),template_cache=dict(type='str',),template_persist_cookie_shared=dict(type='str',),rtp_sip_call_id_match=dict(type='bool',),shared_partition_persist_cookie_template=dict(type='bool',),template_file_inspection=dict(type='str',),template_ftp=dict(type='str',),serv_sel_fail=dict(type='bool',),template_udp=dict(type='str',),template_virtual_port_shared=dict(type='str',),action=dict(type='str',choices=['enable','disable']),template_http=dict(type='str',),view=dict(type='int',),template_persist_source_ip=dict(type='str',),template_dynamic_service=dict(type='str',),shared_partition_virtual_port_template=dict(type='bool',),use_cgnv6=dict(type='bool',),template_persist_destination_ip=dict(type='str',),template_virtual_port=dict(type='str',),conn_limit=dict(type='int',),trunk_fwd=dict(type='str',),template_udp_shared=dict(type='str',),template_http_policy_shared=dict(type='str',),pool=dict(type='str',),snat_on_vip=dict(type='bool',),template_connection_reuse_shared=dict(type='str',),shared_partition_tcp=dict(type='bool',),acl_id_list=dict(type='list',v_acl_id_seq_num=dict(type='int',),acl_id_seq_num=dict(type='int',),acl_id_src_nat_pool=dict(type='str',),acl_id_seq_num_shared=dict(type='int',),v_acl_id_src_nat_pool=dict(type='str',),acl_id_shared=dict(type='int',),v_acl_id_src_nat_pool_shared=dict(type='str',),acl_id=dict(type='int',),acl_id_src_nat_pool_shared=dict(type='str',),v_shared_partition_pool_id=dict(type='bool',),shared_partition_pool_id=dict(type='bool',),v_acl_id_seq_num_shared=dict(type='int',)),shared_partition_http_template=dict(type='bool',),template_external_service=dict(type='str',),on_syn=dict(type='bool',),template_persist_ssl_sid_shared=dict(type='str',),force_routing_mode=dict(type='bool',),template_http_policy=dict(type='str',),template_policy_shared=dict(type='str',),template_scaleout=dict(type='str',),when_down_protocol2=dict(type='bool',),template_fix=dict(type='str',),template_smtp=dict(type='str',),redirect_to_https=dict(type='bool',),alt_protocol2=dict(type='str',choices=['tcp']),alt_protocol1=dict(type='str',choices=['http']),message_switching=dict(type='bool',),template_imap_pop3=dict(type='str',),scaleout_device_group=dict(type='int',),shared_partition_persist_source_ip_template=dict(type='bool',),l7_hardware_assist=dict(type='bool',),template_tcp_proxy_shared=dict(type='str',),shared_partition_cache_template=dict(type='bool',),use_alternate_port=dict(type='bool',),template_tcp_proxy_server=dict(type='str',),trunk_rev=dict(type='str',),eth_fwd=dict(type='str',),pool_shared=dict(type='str',),template_respmod_icap=dict(type='str',),range=dict(type='int',),reset=dict(type='bool',),template_external_service_shared=dict(type='str',),auto=dict(type='bool',),template_dynamic_service_shared=dict(type='str',),template_server_ssh=dict(type='str',),aflex_scripts=dict(type='list',aflex=dict(type='str',),aflex_shared=dict(type='str',)),template_http_shared=dict(type='str',),template_server_ssl=dict(type='str',),shared_partition_diameter_template=dict(type='bool',),template_server_ssl_shared=dict(type='str',),template_persist_destination_ip_shared=dict(type='str',),template_cache_shared=dict(type='str',),port_number=dict(type='int',required=True,),template_tcp_proxy_client=dict(type='str',),shared_partition_pool=dict(type='bool',),template_tcp_proxy=dict(type='str',),extended_stats=dict(type='bool',),shared_partition_client_ssl_template=dict(type='bool',),expand=dict(type='bool',),skip_rev_hash=dict(type='bool',),template_diameter_shared=dict(type='str',),clientip_sticky_nat=dict(type='bool',),secs=dict(type='int',),auth_cfg=dict(type='dict',aaa_policy=dict(type='str',)),eth_rev=dict(type='str',)),
        stats_data_action=dict(type='str',choices=['stats-data-enable','stats-data-disable']),
        ipv6_acl_shared=dict(type='str',),
        acl_name=dict(type='str',),
        enable_disable_action=dict(type='str',choices=['enable','disable','disable-when-all-ports-down','disable-when-any-port-down']),
        ha_dynamic=dict(type='int',),
        redistribute_route_map=dict(type='str',),
        acl_name_shared=dict(type='str',),
        ip_address=dict(type='str',),
        vport_disable_action=dict(type='str',choices=['drop-packet']),
        template_logging=dict(type='str',),
        use_if_ip=dict(type='bool',),
        uuid=dict(type='str',),
        vrid=dict(type='int',),
        disable_vip_adv=dict(type='bool',),
        template_virtual_server=dict(type='str',),
        arp_disable=dict(type='bool',),
        description=dict(type='str',),
        redistribution_flagged=dict(type='bool',),
        netmask=dict(type='str',),
        acl_id=dict(type='int',),
        ipv6_acl=dict(type='str',),
        migrate_vip=dict(type='dict',target_data_cpu=dict(type='int',),uuid=dict(type='str',),finish_migration=dict(type='bool',),target_floating_ipv6=dict(type='str',),target_floating_ipv4=dict(type='str',),cancel_migration=dict(type='bool',)),
        extended_stats=dict(type='bool',),
        name=dict(type='str',required=True,),
        template_scaleout=dict(type='str',),
        template_policy=dict(type='str',),
        user_tag=dict(type='str',),
        template_policy_shared=dict(type='str',),
        ipv6_address=dict(type='str',),
        ethernet=dict(type='str',),
        shared_partition_policy_template=dict(type='bool',),
        acl_id_shared=dict(type='int',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/virtual-server/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/virtual-server/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)

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
        if v:
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
    requires_one_of = sorted(['ip_address','ipv6_address'])
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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["virtual-server"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["virtual-server"][k] != v:
                if result["changed"] != True:
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
    except a10_ex.Exists:
        result["changed"] = False
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
    payload = build_json("virtual-server", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    if module.check_mode:
        result["changed"] = True
        return result
    else:
        return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("virtual-server", module)
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
    partition = module.params["partition"]

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
    if partition:
        module.client.activate_partition(partition)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
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