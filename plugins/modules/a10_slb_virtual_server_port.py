#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_virtual_server_port
description:
    - Virtual Port
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
    virtual_server_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    port_number:
        description:
        - "Port"
        type: int
        required: True
    protocol:
        description:
        - "'tcp'= TCP LB service; 'udp'= UDP Port; 'others'= for no tcp/udp protocol, do
          IP load balancing; 'diameter'= diameter port; 'dns-tcp'= DNS service over TCP;
          'dns-udp'= DNS service over UDP; 'fast-http'= Fast HTTP Port; 'fix'= FIX Port;
          'ftp'= File Transfer Protocol Port; 'ftp-proxy'= ftp proxy port; 'http'= HTTP
          Port; 'https'= HTTPS port; 'imap'= imap proxy port; 'mlb'= Message based load
          balancing; 'mms'= Microsoft Multimedia Service Port; 'mysql'= mssql port;
          'mssql'= mssql; 'pop3'= pop3 proxy port; 'radius'= RADIUS Port; 'rtsp'= Real
          Time Streaming Protocol Port; 'sip'= Session initiation protocol over UDP;
          'sip-tcp'= Session initiation protocol over TCP; 'sips'= Session initiation
          protocol over TLS; 'smpp-tcp'= SMPP service over TCP; 'spdy'= spdy port;
          'spdys'= spdys port; 'smtp'= SMTP Port; 'mqtt'= MQTT Port; 'mqtts'= MQTTS Port;
          'ssl-proxy'= Generic SSL proxy; 'ssli'= SSL insight; 'ssh'= SSH Port; 'tcp-
          proxy'= Generic TCP proxy; 'tftp'= TFTP Port; 'fast-fix'= Fast FIX port; 'http-
          over-quic'= HTTP3-over-quic port;"
        type: str
        required: True
    range:
        description:
        - "Virtual Port range (Virtual Port range value)"
        type: int
        required: False
    alternate_port:
        description:
        - "Alternate Virtual Port"
        type: bool
        required: False
    proxy_layer:
        description:
        - "'v1'= Force using old proxy; 'v2'= Force using new proxy;"
        type: str
        required: False
    optimization_level:
        description:
        - "'0'= No optimization; '1'= Optimization level 1 (Experimental);"
        type: str
        required: False
    support_http2:
        description:
        - "Support HTTP2"
        type: bool
        required: False
    when_server_selection_failed:
        description:
        - "'send-504'= Stay functional up and response with HTTP 504;"
        type: str
        required: False
    ip_only_lb:
        description:
        - "Enable IP-Only LB mode"
        type: bool
        required: False
    name:
        description:
        - "SLB Virtual Service Name"
        type: str
        required: False
    conn_limit:
        description:
        - "Connection Limit"
        type: int
        required: False
    reset:
        description:
        - "Send client reset when connection number over limit"
        type: bool
        required: False
    no_logging:
        description:
        - "Do not log connection over limit event"
        type: bool
        required: False
    use_alternate_port:
        description:
        - "Use alternate virtual port"
        type: bool
        required: False
    alternate_port_number:
        description:
        - "Virtual Port"
        type: int
        required: False
    alt_protocol1:
        description:
        - "'http'= HTTP Port;"
        type: str
        required: False
    serv_sel_fail:
        description:
        - "Use alternate virtual port when server selection failure"
        type: bool
        required: False
    when_down:
        description:
        - "Use alternate virtual port when down"
        type: bool
        required: False
    alt_protocol2:
        description:
        - "'tcp'= TCP LB service;"
        type: str
        required: False
    req_fail:
        description:
        - "Use alternate virtual port when L7 request fail"
        type: bool
        required: False
    when_down_protocol2:
        description:
        - "Use alternate virtual port when down"
        type: bool
        required: False
    action:
        description:
        - "'enable'= Enable; 'disable'= Disable;"
        type: str
        required: False
    l7_service_chain:
        description:
        - "Field l7_service_chain"
        type: bool
        required: False
    def_selection_if_pref_failed:
        description:
        - "'def-selection-if-pref-failed'= Use default server selection method if prefer
          method failed; 'def-selection-if-pref-failed-disable'= Stop using default
          server selection method if prefer method failed;"
        type: str
        required: False
    ha_conn_mirror:
        description:
        - "Enable for HA Conn sync"
        type: bool
        required: False
    on_syn:
        description:
        - "Enable for HA Conn sync for l4 tcp sessions on SYN"
        type: bool
        required: False
    skip_rev_hash:
        description:
        - "Skip rev tuple hash insertion"
        type: bool
        required: False
    message_switching:
        description:
        - "Message switching"
        type: bool
        required: False
    force_routing_mode:
        description:
        - "Force routing mode"
        type: bool
        required: False
    one_server_conn:
        description:
        - "Support server that allow only one connection"
        type: bool
        required: False
    rate:
        description:
        - "Specify the log message rate"
        type: int
        required: False
    secs:
        description:
        - "Specify the interval in seconds"
        type: int
        required: False
    reset_on_server_selection_fail:
        description:
        - "Send client reset when server selection fails"
        type: bool
        required: False
    clientip_sticky_nat:
        description:
        - "Prefer to use same source NAT address for a client"
        type: bool
        required: False
    extended_stats:
        description:
        - "Enable extended statistics on virtual port"
        type: bool
        required: False
    gslb_enable:
        description:
        - "Enable Global Server Load Balancing"
        type: bool
        required: False
    view:
        description:
        - "Specify a GSLB View (ID)"
        type: int
        required: False
    snat_on_vip:
        description:
        - "Enable source NAT traffic against VIP"
        type: bool
        required: False
    stats_data_action:
        description:
        - "'stats-data-enable'= Enable statistical data collection for virtual port;
          'stats-data-disable'= Disable statistical data collection for virtual port;"
        type: str
        required: False
    syn_cookie:
        description:
        - "Enable syn-cookie"
        type: bool
        required: False
    showtech_print_extended_stats:
        description:
        - "Enable print extended stats in showtech"
        type: bool
        required: False
    expand:
        description:
        - "expand syn-cookie with timestamp and wscale"
        type: bool
        required: False
    attack_detection:
        description:
        - "Enable analytics"
        type: bool
        required: False
    acl_list:
        description:
        - "Field acl_list"
        type: list
        required: False
        suboptions:
            acl_id:
                description:
                - "ACL id VPORT"
                type: int
            acl_name:
                description:
                - "Apply an access list name (Named Access List)"
                type: str
            acl_id_shared:
                description:
                - "acl id"
                type: int
            acl_name_shared:
                description:
                - "Apply an access list name (Named Access List)"
                type: str
            acl_id_src_nat_pool:
                description:
                - "Policy based Source NAT (NAT Pool or Pool Group)"
                type: str
            acl_id_seq_num:
                description:
                - "Specify ACL precedence (sequence-number)"
                type: int
            shared_partition_pool_id:
                description:
                - "Policy based Source NAT from shared partition"
                type: bool
            acl_id_src_nat_pool_shared:
                description:
                - "Policy based Source NAT (NAT Pool or Pool Group)"
                type: str
            acl_id_seq_num_shared:
                description:
                - "Specify ACL precedence (sequence-number)"
                type: int
            v_acl_id_src_nat_pool:
                description:
                - "Policy based Source NAT (NAT Pool or Pool Group)"
                type: str
            v_acl_id_seq_num:
                description:
                - "Specify ACL precedence (sequence-number)"
                type: int
            v_shared_partition_pool_id:
                description:
                - "Policy based Source NAT from shared partition"
                type: bool
            v_acl_id_src_nat_pool_shared:
                description:
                - "Policy based Source NAT (NAT Pool or Pool Group)"
                type: str
            v_acl_id_seq_num_shared:
                description:
                - "Specify ACL precedence (sequence-number)"
                type: int
            acl_name_src_nat_pool:
                description:
                - "Policy based Source NAT (NAT Pool or Pool Group)"
                type: str
            acl_name_seq_num:
                description:
                - "Specify ACL precedence (sequence-number)"
                type: int
            shared_partition_pool_name:
                description:
                - "Policy based Source NAT from shared partition"
                type: bool
            acl_name_src_nat_pool_shared:
                description:
                - "Policy based Source NAT (NAT Pool or Pool Group)"
                type: str
            acl_name_seq_num_shared:
                description:
                - "Specify ACL precedence (sequence-number)"
                type: int
            v_acl_name_src_nat_pool:
                description:
                - "Policy based Source NAT (NAT Pool or Pool Group)"
                type: str
            v_acl_name_seq_num:
                description:
                - "Specify ACL precedence (sequence-number)"
                type: int
            v_shared_partition_pool_name:
                description:
                - "Policy based Source NAT from shared partition"
                type: bool
            v_acl_name_src_nat_pool_shared:
                description:
                - "Policy based Source NAT (NAT Pool or Pool Group)"
                type: str
            v_acl_name_seq_num_shared:
                description:
                - "Specify ACL precedence (sequence-number)"
                type: int
    template_policy:
        description:
        - "Policy Template (Policy template name)"
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
    aflex_scripts:
        description:
        - "Field aflex_scripts"
        type: list
        required: False
        suboptions:
            aflex:
                description:
                - "aFleX Script Name"
                type: str
            aflex_shared:
                description:
                - "aFleX Script Name"
                type: str
    no_auto_up_on_aflex:
        description:
        - "Don't automatically mark vport up when aFleX is bound"
        type: bool
        required: False
    enable_scaleout:
        description:
        - "Field enable_scaleout"
        type: bool
        required: False
    pool:
        description:
        - "Specify NAT pool or pool group"
        type: str
        required: False
    shared_partition_pool:
        description:
        - "Specify NAT pool or pool group from shared partition"
        type: bool
        required: False
    pool_shared:
        description:
        - "Specify NAT pool or pool group"
        type: str
        required: False
    auto:
        description:
        - "Configure auto NAT for the vport"
        type: bool
        required: False
    precedence:
        description:
        - "Set auto NAT pool as higher precedence for source NAT"
        type: bool
        required: False
    ip_smart_rr:
        description:
        - "Use IP address round-robin behavior"
        type: bool
        required: False
    use_cgnv6:
        description:
        - "Follow CGNv6 source NAT configuration"
        type: bool
        required: False
    enable_playerid_check:
        description:
        - "Enable playerid checks on UDP packets once the AX is in active mode"
        type: bool
        required: False
    service_group:
        description:
        - "Bind a Service Group to this Virtual Server (Service Group Name)"
        type: str
        required: False
    ipinip:
        description:
        - "Enable IP in IP"
        type: bool
        required: False
    ip_map_list:
        description:
        - "Enter name of IP Map List to be bound (IP Map List Name)"
        type: str
        required: False
    rtp_sip_call_id_match:
        description:
        - "rtp traffic try to match the real server of sip smp call-id session"
        type: bool
        required: False
    use_rcv_hop_for_resp:
        description:
        - "Use receive hop for response to client(For packets on default-vlan, also config
          'vlan-global enable-def-vlan-l2-forwarding'.)"
        type: bool
        required: False
    persist_type:
        description:
        - "'src-dst-ip-swap-persist'= Create persist session after source IP and
          destination IP swap; 'use-src-ip-for-dst-persist'= Use the source IP to create
          a destination persist session; 'use-dst-ip-for-src-persist'= Use the
          destination IP to create source IP persist session;"
        type: str
        required: False
    use_rcv_hop_group:
        description:
        - "Set use-rcv-hop group"
        type: bool
        required: False
    server_group:
        description:
        - "Bind a use-rcv-hop-for-resp Server Group to this Virtual Server (Server Group
          Name)"
        type: str
        required: False
    reselection:
        description:
        - "'disable'= disable;"
        type: str
        required: False
    eth_fwd:
        description:
        - "Ethernet interface number"
        type: str
        required: False
    trunk_fwd:
        description:
        - "Trunk interface number"
        type: str
        required: False
    eth_rev:
        description:
        - "Ethernet interface number"
        type: str
        required: False
    trunk_rev:
        description:
        - "Trunk interface number"
        type: str
        required: False
    template_sip:
        description:
        - "SIP Template Name"
        type: str
        required: False
    p_template_sip_shared:
        description:
        - "SIP Template Name"
        type: bool
        required: False
    template_sip_shared:
        description:
        - "SIP template"
        type: str
        required: False
    template_smpp:
        description:
        - "SMPP template"
        type: str
        required: False
    shared_partition_smpp_template:
        description:
        - "Reference a smpp template from shared partition"
        type: bool
        required: False
    template_smpp_shared:
        description:
        - "SMPP Template Name"
        type: str
        required: False
    template_dblb:
        description:
        - "DBLB Template (DBLB template name)"
        type: str
        required: False
    shared_partition_dblb_template:
        description:
        - "Reference a dblb template from shared partition"
        type: bool
        required: False
    template_dblb_shared:
        description:
        - "DBLB Template Name"
        type: str
        required: False
    template_connection_reuse:
        description:
        - "Connection Reuse Template (Connection Reuse Template Name)"
        type: str
        required: False
    shared_partition_connection_reuse_template:
        description:
        - "Reference a connection reuse template from shared partition"
        type: bool
        required: False
    template_connection_reuse_shared:
        description:
        - "Connection Reuse Template Name"
        type: str
        required: False
    template_dns:
        description:
        - "DNS template (DNS template name)"
        type: str
        required: False
    shared_partition_dns_template:
        description:
        - "Reference a dns template from shared partition"
        type: bool
        required: False
    template_dns_shared:
        description:
        - "DNS Template Name"
        type: str
        required: False
    template_dynamic_service:
        description:
        - "Dynamic Service Template (dynamic-service template name)"
        type: str
        required: False
    shared_partition_dynamic_service_template:
        description:
        - "Reference a dynamic service template from shared partition"
        type: bool
        required: False
    template_dynamic_service_shared:
        description:
        - "Dynamic Service Template Name"
        type: str
        required: False
    template_persist_source_ip:
        description:
        - "Source IP persistence (Source IP persistence template name)"
        type: str
        required: False
    shared_partition_persist_source_ip_template:
        description:
        - "Reference a persist source ip template from shared partition"
        type: bool
        required: False
    template_persist_source_ip_shared:
        description:
        - "Source IP Persistence Template Name"
        type: str
        required: False
    template_persist_destination_ip:
        description:
        - "Destination IP persistence (Destination IP persistence template name)"
        type: str
        required: False
    shared_partition_persist_destination_ip_template:
        description:
        - "Reference a persist destination ip template from shared partition"
        type: bool
        required: False
    template_persist_destination_ip_shared:
        description:
        - "Destination IP Persistence Template Name"
        type: str
        required: False
    template_persist_ssl_sid:
        description:
        - "SSL SID persistence (SSL SID persistence template name)"
        type: str
        required: False
    shared_partition_persist_ssl_sid_template:
        description:
        - "Reference a persist SSL SID template from shared partition"
        type: bool
        required: False
    template_persist_ssl_sid_shared:
        description:
        - "SSL SID Persistence Template Name"
        type: str
        required: False
    template_persist_cookie:
        description:
        - "Cookie persistence (Cookie persistence template name)"
        type: str
        required: False
    shared_partition_persist_cookie_template:
        description:
        - "Reference a persist cookie template from shared partition"
        type: bool
        required: False
    template_persist_cookie_shared:
        description:
        - "Cookie Persistence Template Name"
        type: str
        required: False
    template_imap_pop3:
        description:
        - "IMAP/POP3 Template (IMAP/POP3 Config Name)"
        type: str
        required: False
    shared_partition_imap_pop3_template:
        description:
        - "Reference a IMAP/POP3 template from shared partition"
        type: bool
        required: False
    template_imap_pop3_shared:
        description:
        - "IMAP/POP3 Template Name"
        type: str
        required: False
    template_smtp:
        description:
        - "SMTP Template (SMTP Config Name)"
        type: str
        required: False
    shared_partition_smtp_template:
        description:
        - "Reference a SMTP template from shared partition"
        type: bool
        required: False
    template_smtp_shared:
        description:
        - "SMTP Template Name"
        type: str
        required: False
    template_mqtt:
        description:
        - "MQTT Template (MQTT Config Name)"
        type: str
        required: False
    template_http:
        description:
        - "HTTP Template Name"
        type: str
        required: False
    shared_partition_http_template:
        description:
        - "Reference a HTTP template from shared partition"
        type: bool
        required: False
    template_http_shared:
        description:
        - "HTTP Template Name"
        type: str
        required: False
    template_http_policy:
        description:
        - "http-policy template (http-policy template name)"
        type: str
        required: False
    shared_partition_http_policy_template:
        description:
        - "Reference a http policy template from shared partition"
        type: bool
        required: False
    template_http_policy_shared:
        description:
        - "Http Policy Template Name"
        type: str
        required: False
    redirect_to_https:
        description:
        - "Redirect HTTP to HTTPS"
        type: bool
        required: False
    template_external_service:
        description:
        - "External service template (external-service template name)"
        type: str
        required: False
    shared_partition_external_service_template:
        description:
        - "Reference a external service template from shared partition"
        type: bool
        required: False
    template_external_service_shared:
        description:
        - "External Service Template Name"
        type: str
        required: False
    template_reqmod_icap:
        description:
        - "ICAP reqmod template (reqmod-icap template name)"
        type: str
        required: False
    template_respmod_icap:
        description:
        - "ICAP respmod service template (respmod-icap template name)"
        type: str
        required: False
    template_doh:
        description:
        - "DNS over HTTP(s) Template Name"
        type: str
        required: False
    shared_partition_doh_template:
        description:
        - "Reference a DNS over HTTP(s) template from shared partition"
        type: bool
        required: False
    template_doh_shared:
        description:
        - "DNS over HTTP(s) Template Name"
        type: str
        required: False
    template_server_ssl:
        description:
        - "Server Side SSL Template Name"
        type: str
        required: False
    shared_partition_server_ssl_template:
        description:
        - "Reference a SSL Server template from shared partition"
        type: bool
        required: False
    template_server_ssl_shared:
        description:
        - "Server SSL Template Name"
        type: str
        required: False
    template_client_ssl:
        description:
        - "Client SSL Template Name"
        type: str
        required: False
    shared_partition_client_ssl_template:
        description:
        - "Reference a Client SSL template from shared partition"
        type: bool
        required: False
    template_client_ssl_shared:
        description:
        - "Client SSL Template Name"
        type: str
        required: False
    template_server_ssh:
        description:
        - "Server SSH Template (Server SSH Config Name)"
        type: str
        required: False
    template_client_ssh:
        description:
        - "Client SSH Template (Client SSH Config Name)"
        type: str
        required: False
    template_udp:
        description:
        - "L4 UDP Template"
        type: str
        required: False
    shared_partition_udp:
        description:
        - "Reference a UDP template from shared partition"
        type: bool
        required: False
    template_udp_shared:
        description:
        - "UDP Template Name"
        type: str
        required: False
    template_tcp:
        description:
        - "TCP Template Name"
        type: str
        required: False
    shared_partition_tcp:
        description:
        - "Reference a tcp template from shared partition"
        type: bool
        required: False
    template_tcp_shared:
        description:
        - "TCP Template Name"
        type: str
        required: False
    template_virtual_port:
        description:
        - "Virtual port template (Virtual port template name)"
        type: str
        required: False
    shared_partition_virtual_port_template:
        description:
        - "Reference a Virtual Port template from shared partition"
        type: bool
        required: False
    template_virtual_port_shared:
        description:
        - "Virtual Port Template Name"
        type: str
        required: False
    template_ftp:
        description:
        - "FTP port template (Ftp template name)"
        type: str
        required: False
    template_diameter:
        description:
        - "Diameter Template (diameter template name)"
        type: str
        required: False
    shared_partition_diameter_template:
        description:
        - "Reference a Diameter template from shared partition"
        type: bool
        required: False
    template_diameter_shared:
        description:
        - "Diameter Template Name"
        type: str
        required: False
    template_cache:
        description:
        - "RAM caching template (Cache Template Name)"
        type: str
        required: False
    shared_partition_cache_template:
        description:
        - "Reference a Cache template from shared partition"
        type: bool
        required: False
    template_cache_shared:
        description:
        - "Cache Template Name"
        type: str
        required: False
    template_ram_cache:
        description:
        - "RAM caching template (Cache Template Name)"
        type: str
        required: False
    template_fix:
        description:
        - "FIX template (FIX Template Name)"
        type: str
        required: False
    shared_partition_fix_template:
        description:
        - "Reference a FIX template from shared partition"
        type: bool
        required: False
    template_fix_shared:
        description:
        - "FIX Template Name"
        type: str
        required: False
    template_ssli:
        description:
        - "SSLi template (SSLi Template Name)"
        type: str
        required: False
    template_tcp_proxy_client:
        description:
        - "TCP Proxy Config Client (TCP Proxy Config name)"
        type: str
        required: False
    template_tcp_proxy_server:
        description:
        - "TCP Proxy Config Server (TCP Proxy Config name)"
        type: str
        required: False
    template_tcp_proxy:
        description:
        - "TCP Proxy Template Name"
        type: str
        required: False
    shared_partition_tcp_proxy_template:
        description:
        - "Reference a TCP Proxy template from shared partition"
        type: bool
        required: False
    template_tcp_proxy_shared:
        description:
        - "TCP Proxy Template name"
        type: str
        required: False
    template_quic_client:
        description:
        - "QUIC Config Client (QUIC Config name)"
        type: str
        required: False
    template_quic_server:
        description:
        - "QUIC Config Server (QUIC Config name)"
        type: str
        required: False
    template_quic:
        description:
        - "QUIC Template Name"
        type: str
        required: False
    shared_partition_quic_template:
        description:
        - "Reference a QUIC template from shared partition"
        type: bool
        required: False
    template_quic_shared:
        description:
        - "QUIC Template name"
        type: str
        required: False
    use_default_if_no_server:
        description:
        - "Use default forwarding if server selection failed"
        type: bool
        required: False
    template_scaleout:
        description:
        - "Scaleout template (Scaleout template name)"
        type: str
        required: False
    no_dest_nat:
        description:
        - "Disable destination NAT, this option only supports in wildcard VIP or when a
          connection is operated in SSLi + EP mode"
        type: bool
        required: False
    port_translation:
        description:
        - "Enable port translation under no-dest-nat"
        type: bool
        required: False
    l7_hardware_assist:
        description:
        - "FPGA assist L7 packet parsing"
        type: bool
        required: False
    auth_cfg:
        description:
        - "Field auth_cfg"
        type: dict
        required: False
        suboptions:
            aaa_policy:
                description:
                - "Specify AAA policy name to bind to the virtual port"
                type: str
    cpu_compute:
        description:
        - "enable cpu compute on virtual port"
        type: bool
        required: False
    memory_compute:
        description:
        - "enable dynamic memory compute on virtual port"
        type: bool
        required: False
    substitute_source_mac:
        description:
        - "Substitute Source MAC Address to that of the outgoing interface"
        type: bool
        required: False
    ignore_global:
        description:
        - "Ignore global substitute-source-mac"
        type: bool
        required: False
    aflex_table_entry_syn_disable:
        description:
        - "Disable aFlex entry sync for this port"
        type: bool
        required: False
    aflex_table_entry_syn_enable:
        description:
        - "Enable aFlex entry sync for this port"
        type: bool
        required: False
    gtp_session_lb:
        description:
        - "Enable GTP Session Load Balancing"
        type: bool
        required: False
    reply_acme_challenge:
        description:
        - "Reply ACME http-01 challenge. This option only takes effect in HTTP port 80"
        type: bool
        required: False
    resolve_web_cat_list:
        description:
        - "Web Category List name"
        type: str
        required: False
    ng_waf:
        description:
        - "Next-gen WAF"
        type: bool
        required: False
    fast_dns_cache:
        description:
        - "'force-enable'= Always enable; 'force-disable'= Always disable; 'depends-on-
          config'= Depends on configurations;"
        type: str
        required: False
    fast_path:
        description:
        - "'force'= Force fast path in SLB processing; 'disable'= Disable fast path in SLB
          processing;"
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'curr_conn'= Current established connections; 'total_l4_conn'=
          Total L4 connections established; 'total_l7_conn'= Total L7 connections
          established; 'total_tcp_conn'= Total TCP connections established; 'total_conn'=
          Total connections established; 'total_fwd_bytes'= Bytes processed in forward
          direction; 'total_fwd_pkts'= Packets processed in forward direction;
          'total_rev_bytes'= Bytes processed in reverse direction; 'total_rev_pkts'=
          Packets processed in reverse direction; 'total_dns_pkts'= Total DNS packets
          processed; 'total_mf_dns_pkts'= Total MF DNS packets;
          'es_total_failure_actions'= Total failure actions; 'compression_bytes_before'=
          Data into gzip compression engine; 'compression_bytes_after'= Data out of gzip
          compression engine; 'compression_hit'= Number of requests compressed;
          'compression_miss'= Number of requests NOT compressed;
          'compression_miss_no_client'= Compression miss no client;
          'compression_miss_template_exclusion'= Compression miss template exclusion;
          'curr_req'= Current requests; 'total_req'= Total requests; 'total_req_succ'=
          Total successful requests; 'peak_conn'= Peak connections; 'curr_conn_rate'=
          Current connection rate; 'last_rsp_time'= Last response time;
          'fastest_rsp_time'= Fastest response time; 'slowest_rsp_time'= Slowest response
          time; 'loc_permit'= Geo-location Permit count; 'loc_deny'= Geo-location Deny
          count; 'loc_conn'= Geo-location Connection count; 'curr_ssl_conn'= Current SSL
          connections; 'total_ssl_conn'= Total SSL connections; 'backend-time-to-first-
          byte'= Backend Time from Request to Response First Byte; 'backend-time-to-last-
          byte'= Backend Time from Request to Response Last Byte; 'in-latency'= Request
          Latency at Thunder; 'out-latency'= Response Latency at Thunder;
          'total_fwd_bytes_out'= Bytes processed in forward direction (outbound);
          'total_fwd_pkts_out'= Packets processed in forward direction (outbound);
          'total_rev_bytes_out'= Bytes processed in reverse direction (outbound);
          'total_rev_pkts_out'= Packets processed in reverse direction (outbound);
          'curr_req_rate'= Current request rate; 'curr_resp'= Current response;
          'total_resp'= Total response; 'total_resp_succ'= Total successful responses;
          'curr_resp_rate'= Current response rate; 'dnsrrl_total_allowed'= DNS Response-
          Rate-Limiting Total Responses Allowed; 'dnsrrl_total_dropped'= DNS Response-
          Rate-Limiting Total Responses Dropped; 'dnsrrl_total_slipped'= DNS Response-
          Rate-Limiting Total Responses Slipped; 'dnsrrl_bad_fqdn'= DNS Response-Rate-
          Limiting Bad FQDN; 'throughput-bits-per-sec'= Throughput in bits/sec; 'dynamic-
          memory-alloc'= dynamic memory (bytes) allocated by the vport; 'dynamic-memory-
          free'= dynamic memory (bytes) allocated by the vport; 'dynamic-memory'= dynamic
          memory (bytes) used by the vport(alloc-free); 'ip_only_lb_fwd_bytes'= IP-Only-
          LB Bytes processed in forward direction; 'ip_only_lb_rev_bytes'= IP-Only-LB
          Bytes processed in reverse direction; 'ip_only_lb_fwd_pkts'= IP-Only-LB Packets
          processed in forward direction; 'ip_only_lb_rev_pkts'= IP-Only-LB Packets
          processed in reverse direction; 'total_dns_filter_type_drop'= Total DNS Filter
          Type Drop; 'total_dns_filter_class_drop'= Total DNS Filter Class Drop;
          'dns_filter_type_a_drop'= DNS Filter Type A Drop; 'dns_filter_type_aaaa_drop'=
          DNS Filter Type AAAA Drop; 'dns_filter_type_cname_drop'= DNS Filter Type CNAME
          Drop; 'dns_filter_type_mx_drop'= DNS Filter Type MX Drop;
          'dns_filter_type_ns_drop'= DNS Filter Type NS Drop; 'dns_filter_type_srv_drop'=
          DNS Filter Type SRV Drop; 'dns_filter_type_ptr_drop'= DNS Filter Type PTR Drop;
          'dns_filter_type_soa_drop'= DNS Filter Type SOA Drop;
          'dns_filter_type_txt_drop'= DNS Filter Type TXT Drop;
          'dns_filter_type_any_drop'= DNS Filter Type Any Drop;
          'dns_filter_type_others_drop'= DNS Filter Type OTHERS Drop;
          'dns_filter_class_internet_drop'= DNS Filter Class INTERNET Drop;
          'dns_filter_class_chaos_drop'= DNS Filter Class CHAOS Drop;
          'dns_filter_class_hesiod_drop'= DNS Filter Class HESIOD Drop;
          'dns_filter_class_none_drop'= DNS Filter Class NONE Drop;
          'dns_filter_class_any_drop'= DNS Filter Class ANY Drop;
          'dns_filter_class_others_drop'= DNS Filter Class OTHERS Drop;
          'dns_rpz_action_drop'= DNS RPZ Action Drop; 'dns_rpz_action_pass_thru'= DNS RPZ
          Action Pass Through; 'dns_rpz_action_tcp_only'= DNS RPZ Action TCP Only;
          'dns_rpz_action_nxdomain'= DNS RPZ Action NXDOMAIN; 'dns_rpz_action_nodata'=
          DNS RPZ Action NODATA; 'dns_rpz_action_local_data'= DNS RPZ Action Local Data;
          'dns_rpz_trigger_client_ip'= DNS RPZ Trigger Client IP;
          'dns_rpz_trigger_resp_ip'= DNS RPZ Trigger Response IP;
          'dns_rpz_trigger_ns_ip'= DNS RPZ Trigger NS IP; 'dns_rpz_trigger_qname'= DNS
          RPZ Trigger Qname IP; 'dns_rpz_trigger_ns_name'= DNS RPZ Trigger NS Name;
          'compression_bytes_before_br'= Data into brotli compression engine;
          'compression_bytes_after_br'= Data out of brotli compression engine;
          'compression_bytes_before_total'= Data into compression engine;
          'compression_bytes_after_total'= Data out of compression engine;
          'compression_hit_br'= Number of requests compressed with brotli;
          'compression_miss_br'= Number of requests NOT compressed with brotli;
          'compression_hit_total'= Number of requests compressed;
          'compression_miss_total'= Number of requests NOT compressed; 'dnsrrl_total_tc'=
          DNS Response-Rate-Limiting Total Responses Replied With Truncated;
          'http1_client_idle_timeout'= HTTP1 Client Idle Timeout;
          'http2_client_idle_timeout'= HTTP2 Client Idle Timeout; 'dnsrrl_nx_exceed'= DNS
          Response-Rate-Limiting NX Responses Exceed Limit;"
                type: str
    packet_capture_template:
        description:
        - "Name of the packet capture template to be bind with this object"
        type: str
        required: False
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
            real_curr_conn:
                description:
                - "Field real_curr_conn"
                type: int
            int_curr_conn:
                description:
                - "Field int_curr_conn"
                type: int
            curr_conn_overflow:
                description:
                - "Field curr_conn_overflow"
                type: int
            print_extended_stats:
                description:
                - "Field print_extended_stats"
                type: int
            loc_list:
                description:
                - "Field loc_list"
                type: str
            geo_location:
                description:
                - "Field geo_location"
                type: str
            level_str:
                description:
                - "Field level_str"
                type: str
            group_id:
                description:
                - "Field group_id"
                type: int
            loc_max_depth:
                description:
                - "Field loc_max_depth"
                type: int
            loc_success:
                description:
                - "Field loc_success"
                type: int
            loc_error:
                description:
                - "Field loc_error"
                type: int
            loc_override:
                description:
                - "Field loc_override"
                type: int
            loc_last:
                description:
                - "Field loc_last"
                type: str
            http_hits_list:
                description:
                - "Field http_hits_list"
                type: list
            http_vport_cpu_list:
                description:
                - "Field http_vport_cpu_list"
                type: list
            cpu_count:
                description:
                - "Field cpu_count"
                type: int
            http_host_hits:
                description:
                - "Field http_host_hits"
                type: bool
            http_url_hits:
                description:
                - "Field http_url_hits"
                type: bool
            http_vport:
                description:
                - "Field http_vport"
                type: bool
            clear_curr_conn:
                description:
                - "Field clear_curr_conn"
                type: bool
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
          Port; 'https'= HTTPS port; 'imap'= imap proxy port; 'mlb'= Message based load
          balancing; 'mms'= Microsoft Multimedia Service Port; 'mysql'= mssql port;
          'mssql'= mssql; 'pop3'= pop3 proxy port; 'radius'= RADIUS Port; 'rtsp'= Real
          Time Streaming Protocol Port; 'sip'= Session initiation protocol over UDP;
          'sip-tcp'= Session initiation protocol over TCP; 'sips'= Session initiation
          protocol over TLS; 'smpp-tcp'= SMPP service over TCP; 'spdy'= spdy port;
          'spdys'= spdys port; 'smtp'= SMTP Port; 'mqtt'= MQTT Port; 'mqtts'= MQTTS Port;
          'ssl-proxy'= Generic SSL proxy; 'ssli'= SSL insight; 'ssh'= SSH Port; 'tcp-
          proxy'= Generic TCP proxy; 'tftp'= TFTP Port; 'fast-fix'= Fast FIX port; 'http-
          over-quic'= HTTP3-over-quic port;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            curr_conn:
                description:
                - "Current established connections"
                type: str
            total_l4_conn:
                description:
                - "Total L4 connections established"
                type: str
            total_l7_conn:
                description:
                - "Total L7 connections established"
                type: str
            total_tcp_conn:
                description:
                - "Total TCP connections established"
                type: str
            total_conn:
                description:
                - "Total connections established"
                type: str
            total_fwd_bytes:
                description:
                - "Bytes processed in forward direction"
                type: str
            total_fwd_pkts:
                description:
                - "Packets processed in forward direction"
                type: str
            total_rev_bytes:
                description:
                - "Bytes processed in reverse direction"
                type: str
            total_rev_pkts:
                description:
                - "Packets processed in reverse direction"
                type: str
            total_dns_pkts:
                description:
                - "Total DNS packets processed"
                type: str
            total_mf_dns_pkts:
                description:
                - "Total MF DNS packets"
                type: str
            es_total_failure_actions:
                description:
                - "Total failure actions"
                type: str
            compression_bytes_before:
                description:
                - "Data into gzip compression engine"
                type: str
            compression_bytes_after:
                description:
                - "Data out of gzip compression engine"
                type: str
            compression_hit:
                description:
                - "Number of requests compressed"
                type: str
            compression_miss:
                description:
                - "Number of requests NOT compressed"
                type: str
            compression_miss_no_client:
                description:
                - "Compression miss no client"
                type: str
            compression_miss_template_exclusion:
                description:
                - "Compression miss template exclusion"
                type: str
            curr_req:
                description:
                - "Current requests"
                type: str
            total_req:
                description:
                - "Total requests"
                type: str
            total_req_succ:
                description:
                - "Total successful requests"
                type: str
            peak_conn:
                description:
                - "Peak connections"
                type: str
            curr_conn_rate:
                description:
                - "Current connection rate"
                type: str
            last_rsp_time:
                description:
                - "Last response time"
                type: str
            fastest_rsp_time:
                description:
                - "Fastest response time"
                type: str
            slowest_rsp_time:
                description:
                - "Slowest response time"
                type: str
            loc_permit:
                description:
                - "Geo-location Permit count"
                type: str
            loc_deny:
                description:
                - "Geo-location Deny count"
                type: str
            loc_conn:
                description:
                - "Geo-location Connection count"
                type: str
            curr_ssl_conn:
                description:
                - "Current SSL connections"
                type: str
            total_ssl_conn:
                description:
                - "Total SSL connections"
                type: str
            backend_time_to_first_byte:
                description:
                - "Backend Time from Request to Response First Byte"
                type: str
            backend_time_to_last_byte:
                description:
                - "Backend Time from Request to Response Last Byte"
                type: str
            in_latency:
                description:
                - "Request Latency at Thunder"
                type: str
            out_latency:
                description:
                - "Response Latency at Thunder"
                type: str
            total_fwd_bytes_out:
                description:
                - "Bytes processed in forward direction (outbound)"
                type: str
            total_fwd_pkts_out:
                description:
                - "Packets processed in forward direction (outbound)"
                type: str
            total_rev_bytes_out:
                description:
                - "Bytes processed in reverse direction (outbound)"
                type: str
            total_rev_pkts_out:
                description:
                - "Packets processed in reverse direction (outbound)"
                type: str
            curr_req_rate:
                description:
                - "Current request rate"
                type: str
            curr_resp:
                description:
                - "Current response"
                type: str
            total_resp:
                description:
                - "Total response"
                type: str
            total_resp_succ:
                description:
                - "Total successful responses"
                type: str
            curr_resp_rate:
                description:
                - "Current response rate"
                type: str
            dnsrrl_total_allowed:
                description:
                - "DNS Response-Rate-Limiting Total Responses Allowed"
                type: str
            dnsrrl_total_dropped:
                description:
                - "DNS Response-Rate-Limiting Total Responses Dropped"
                type: str
            dnsrrl_total_slipped:
                description:
                - "DNS Response-Rate-Limiting Total Responses Slipped"
                type: str
            dnsrrl_bad_fqdn:
                description:
                - "DNS Response-Rate-Limiting Bad FQDN"
                type: str
            throughput_bits_per_sec:
                description:
                - "Throughput in bits/sec"
                type: str
            dynamic_memory:
                description:
                - "dynamic memory (bytes) used by the vport(alloc-free)"
                type: str
            ip_only_lb_fwd_bytes:
                description:
                - "IP-Only-LB Bytes processed in forward direction"
                type: str
            ip_only_lb_rev_bytes:
                description:
                - "IP-Only-LB Bytes processed in reverse direction"
                type: str
            ip_only_lb_fwd_pkts:
                description:
                - "IP-Only-LB Packets processed in forward direction"
                type: str
            ip_only_lb_rev_pkts:
                description:
                - "IP-Only-LB Packets processed in reverse direction"
                type: str
            total_dns_filter_type_drop:
                description:
                - "Total DNS Filter Type Drop"
                type: str
            total_dns_filter_class_drop:
                description:
                - "Total DNS Filter Class Drop"
                type: str
            dns_filter_type_a_drop:
                description:
                - "DNS Filter Type A Drop"
                type: str
            dns_filter_type_aaaa_drop:
                description:
                - "DNS Filter Type AAAA Drop"
                type: str
            dns_filter_type_cname_drop:
                description:
                - "DNS Filter Type CNAME Drop"
                type: str
            dns_filter_type_mx_drop:
                description:
                - "DNS Filter Type MX Drop"
                type: str
            dns_filter_type_ns_drop:
                description:
                - "DNS Filter Type NS Drop"
                type: str
            dns_filter_type_srv_drop:
                description:
                - "DNS Filter Type SRV Drop"
                type: str
            dns_filter_type_ptr_drop:
                description:
                - "DNS Filter Type PTR Drop"
                type: str
            dns_filter_type_soa_drop:
                description:
                - "DNS Filter Type SOA Drop"
                type: str
            dns_filter_type_txt_drop:
                description:
                - "DNS Filter Type TXT Drop"
                type: str
            dns_filter_type_any_drop:
                description:
                - "DNS Filter Type Any Drop"
                type: str
            dns_filter_type_others_drop:
                description:
                - "DNS Filter Type OTHERS Drop"
                type: str
            dns_filter_class_internet_drop:
                description:
                - "DNS Filter Class INTERNET Drop"
                type: str
            dns_filter_class_chaos_drop:
                description:
                - "DNS Filter Class CHAOS Drop"
                type: str
            dns_filter_class_hesiod_drop:
                description:
                - "DNS Filter Class HESIOD Drop"
                type: str
            dns_filter_class_none_drop:
                description:
                - "DNS Filter Class NONE Drop"
                type: str
            dns_filter_class_any_drop:
                description:
                - "DNS Filter Class ANY Drop"
                type: str
            dns_filter_class_others_drop:
                description:
                - "DNS Filter Class OTHERS Drop"
                type: str
            dns_rpz_action_drop:
                description:
                - "DNS RPZ Action Drop"
                type: str
            dns_rpz_action_pass_thru:
                description:
                - "DNS RPZ Action Pass Through"
                type: str
            dns_rpz_action_tcp_only:
                description:
                - "DNS RPZ Action TCP Only"
                type: str
            dns_rpz_action_nxdomain:
                description:
                - "DNS RPZ Action NXDOMAIN"
                type: str
            dns_rpz_action_nodata:
                description:
                - "DNS RPZ Action NODATA"
                type: str
            dns_rpz_action_local_data:
                description:
                - "DNS RPZ Action Local Data"
                type: str
            dns_rpz_trigger_client_ip:
                description:
                - "DNS RPZ Trigger Client IP"
                type: str
            dns_rpz_trigger_resp_ip:
                description:
                - "DNS RPZ Trigger Response IP"
                type: str
            dns_rpz_trigger_ns_ip:
                description:
                - "DNS RPZ Trigger NS IP"
                type: str
            dns_rpz_trigger_qname:
                description:
                - "DNS RPZ Trigger Qname IP"
                type: str
            dns_rpz_trigger_ns_name:
                description:
                - "DNS RPZ Trigger NS Name"
                type: str
            compression_bytes_before_br:
                description:
                - "Data into brotli compression engine"
                type: str
            compression_bytes_after_br:
                description:
                - "Data out of brotli compression engine"
                type: str
            compression_bytes_before_total:
                description:
                - "Data into compression engine"
                type: str
            compression_bytes_after_total:
                description:
                - "Data out of compression engine"
                type: str
            compression_hit_br:
                description:
                - "Number of requests compressed with brotli"
                type: str
            compression_miss_br:
                description:
                - "Number of requests NOT compressed with brotli"
                type: str
            compression_hit_total:
                description:
                - "Number of requests compressed"
                type: str
            compression_miss_total:
                description:
                - "Number of requests NOT compressed"
                type: str
            dnsrrl_total_tc:
                description:
                - "DNS Response-Rate-Limiting Total Responses Replied With Truncated"
                type: str
            http1_client_idle_timeout:
                description:
                - "HTTP1 Client Idle Timeout"
                type: str
            http2_client_idle_timeout:
                description:
                - "HTTP2 Client Idle Timeout"
                type: str
            dnsrrl_nx_exceed:
                description:
                - "DNS Response-Rate-Limiting NX Responses Exceed Limit"
                type: str
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
          Port; 'https'= HTTPS port; 'imap'= imap proxy port; 'mlb'= Message based load
          balancing; 'mms'= Microsoft Multimedia Service Port; 'mysql'= mssql port;
          'mssql'= mssql; 'pop3'= pop3 proxy port; 'radius'= RADIUS Port; 'rtsp'= Real
          Time Streaming Protocol Port; 'sip'= Session initiation protocol over UDP;
          'sip-tcp'= Session initiation protocol over TCP; 'sips'= Session initiation
          protocol over TLS; 'smpp-tcp'= SMPP service over TCP; 'spdy'= spdy port;
          'spdys'= spdys port; 'smtp'= SMTP Port; 'mqtt'= MQTT Port; 'mqtts'= MQTTS Port;
          'ssl-proxy'= Generic SSL proxy; 'ssli'= SSL insight; 'ssh'= SSH Port; 'tcp-
          proxy'= Generic TCP proxy; 'tftp'= TFTP Port; 'fast-fix'= Fast FIX port; 'http-
          over-quic'= HTTP3-over-quic port;"
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
    "acl_list", "action", "aflex_scripts", "aflex_table_entry_syn_disable", "aflex_table_entry_syn_enable", "alt_protocol1", "alt_protocol2", "alternate_port", "alternate_port_number", "attack_detection", "auth_cfg", "auto", "clientip_sticky_nat", "conn_limit", "cpu_compute", "def_selection_if_pref_failed", "enable_playerid_check",
    "enable_scaleout", "eth_fwd", "eth_rev", "expand", "extended_stats", "fast_dns_cache", "fast_path", "force_routing_mode", "gslb_enable", "gtp_session_lb", "ha_conn_mirror", "ignore_global", "ip_map_list", "ip_only_lb", "ip_smart_rr", "ipinip", "l7_hardware_assist", "l7_service_chain", "memory_compute", "message_switching", "name", "ng_waf",
    "no_auto_up_on_aflex", "no_dest_nat", "no_logging", "on_syn", "one_server_conn", "oper", "optimization_level", "p_template_sip_shared", "packet_capture_template", "persist_type", "pool", "pool_shared", "port_number", "port_translation", "precedence", "protocol", "proxy_layer", "range", "rate", "redirect_to_https", "reply_acme_challenge",
    "req_fail", "reselection", "reset", "reset_on_server_selection_fail", "resolve_web_cat_list", "rtp_sip_call_id_match", "sampling_enable", "secs", "serv_sel_fail", "server_group", "service_group", "shared_partition_cache_template", "shared_partition_client_ssl_template", "shared_partition_connection_reuse_template",
    "shared_partition_dblb_template", "shared_partition_diameter_template", "shared_partition_dns_template", "shared_partition_doh_template", "shared_partition_dynamic_service_template", "shared_partition_external_service_template", "shared_partition_fix_template", "shared_partition_http_policy_template", "shared_partition_http_template",
    "shared_partition_imap_pop3_template", "shared_partition_persist_cookie_template", "shared_partition_persist_destination_ip_template", "shared_partition_persist_source_ip_template", "shared_partition_persist_ssl_sid_template", "shared_partition_policy_template", "shared_partition_pool", "shared_partition_quic_template",
    "shared_partition_server_ssl_template", "shared_partition_smpp_template", "shared_partition_smtp_template", "shared_partition_tcp", "shared_partition_tcp_proxy_template", "shared_partition_udp", "shared_partition_virtual_port_template", "showtech_print_extended_stats", "skip_rev_hash", "snat_on_vip", "stats", "stats_data_action",
    "substitute_source_mac", "support_http2", "syn_cookie", "template_cache", "template_cache_shared", "template_client_ssh", "template_client_ssl", "template_client_ssl_shared", "template_connection_reuse", "template_connection_reuse_shared", "template_dblb", "template_dblb_shared", "template_diameter", "template_diameter_shared", "template_dns",
    "template_dns_shared", "template_doh", "template_doh_shared", "template_dynamic_service", "template_dynamic_service_shared", "template_external_service", "template_external_service_shared", "template_fix", "template_fix_shared", "template_ftp", "template_http", "template_http_policy", "template_http_policy_shared", "template_http_shared",
    "template_imap_pop3", "template_imap_pop3_shared", "template_mqtt", "template_persist_cookie", "template_persist_cookie_shared", "template_persist_destination_ip", "template_persist_destination_ip_shared", "template_persist_source_ip", "template_persist_source_ip_shared", "template_persist_ssl_sid", "template_persist_ssl_sid_shared",
    "template_policy", "template_policy_shared", "template_quic", "template_quic_client", "template_quic_server", "template_quic_shared", "template_ram_cache", "template_reqmod_icap", "template_respmod_icap", "template_scaleout", "template_server_ssh", "template_server_ssl", "template_server_ssl_shared", "template_sip", "template_sip_shared",
    "template_smpp", "template_smpp_shared", "template_smtp", "template_smtp_shared", "template_ssli", "template_tcp", "template_tcp_proxy", "template_tcp_proxy_client", "template_tcp_proxy_server", "template_tcp_proxy_shared", "template_tcp_shared", "template_udp", "template_udp_shared", "template_virtual_port", "template_virtual_port_shared",
    "trunk_fwd", "trunk_rev", "use_alternate_port", "use_cgnv6", "use_default_if_no_server", "use_rcv_hop_for_resp", "use_rcv_hop_group", "user_tag", "uuid", "view", "when_down", "when_down_protocol2", "when_server_selection_failed",
    ]


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
                'tcp', 'udp', 'others', 'diameter', 'dns-tcp', 'dns-udp', 'fast-http', 'fix', 'ftp', 'ftp-proxy', 'http', 'https', 'imap', 'mlb', 'mms', 'mysql', 'mssql', 'pop3', 'radius', 'rtsp', 'sip', 'sip-tcp', 'sips', 'smpp-tcp', 'spdy', 'spdys', 'smtp', 'mqtt', 'mqtts', 'ssl-proxy', 'ssli', 'ssh', 'tcp-proxy', 'tftp', 'fast-fix',
                'http-over-quic'
                ]
            },
        'range': {
            'type': 'int',
            },
        'alternate_port': {
            'type': 'bool',
            },
        'proxy_layer': {
            'type': 'str',
            'choices': ['v1', 'v2']
            },
        'optimization_level': {
            'type': 'str',
            'choices': ['0', '1']
            },
        'support_http2': {
            'type': 'bool',
            },
        'when_server_selection_failed': {
            'type': 'str',
            'choices': ['send-504']
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
        'l7_service_chain': {
            'type': 'bool',
            },
        'def_selection_if_pref_failed': {
            'type': 'str',
            'choices': ['def-selection-if-pref-failed', 'def-selection-if-pref-failed-disable']
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
        'one_server_conn': {
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
        'showtech_print_extended_stats': {
            'type': 'bool',
            },
        'expand': {
            'type': 'bool',
            },
        'attack_detection': {
            'type': 'bool',
            },
        'acl_list': {
            'type': 'list',
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
        'enable_scaleout': {
            'type': 'bool',
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
        'ip_smart_rr': {
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
            'type': 'str',
            'choices': ['src-dst-ip-swap-persist', 'use-src-ip-for-dst-persist', 'use-dst-ip-for-src-persist']
            },
        'use_rcv_hop_group': {
            'type': 'bool',
            },
        'server_group': {
            'type': 'str',
            },
        'reselection': {
            'type': 'str',
            'choices': ['disable']
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
        'p_template_sip_shared': {
            'type': 'bool',
            },
        'template_sip_shared': {
            'type': 'str',
            },
        'template_smpp': {
            'type': 'str',
            },
        'shared_partition_smpp_template': {
            'type': 'bool',
            },
        'template_smpp_shared': {
            'type': 'str',
            },
        'template_dblb': {
            'type': 'str',
            },
        'shared_partition_dblb_template': {
            'type': 'bool',
            },
        'template_dblb_shared': {
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
        'shared_partition_imap_pop3_template': {
            'type': 'bool',
            },
        'template_imap_pop3_shared': {
            'type': 'str',
            },
        'template_smtp': {
            'type': 'str',
            },
        'shared_partition_smtp_template': {
            'type': 'bool',
            },
        'template_smtp_shared': {
            'type': 'str',
            },
        'template_mqtt': {
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
        'template_doh': {
            'type': 'str',
            },
        'shared_partition_doh_template': {
            'type': 'bool',
            },
        'template_doh_shared': {
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
        'template_ram_cache': {
            'type': 'str',
            },
        'template_fix': {
            'type': 'str',
            },
        'shared_partition_fix_template': {
            'type': 'bool',
            },
        'template_fix_shared': {
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
        'template_quic_client': {
            'type': 'str',
            },
        'template_quic_server': {
            'type': 'str',
            },
        'template_quic': {
            'type': 'str',
            },
        'shared_partition_quic_template': {
            'type': 'bool',
            },
        'template_quic_shared': {
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
        'substitute_source_mac': {
            'type': 'bool',
            },
        'ignore_global': {
            'type': 'bool',
            },
        'aflex_table_entry_syn_disable': {
            'type': 'bool',
            },
        'aflex_table_entry_syn_enable': {
            'type': 'bool',
            },
        'gtp_session_lb': {
            'type': 'bool',
            },
        'reply_acme_challenge': {
            'type': 'bool',
            },
        'resolve_web_cat_list': {
            'type': 'str',
            },
        'ng_waf': {
            'type': 'bool',
            },
        'fast_dns_cache': {
            'type': 'str',
            'choices': ['force-enable', 'force-disable', 'depends-on-config']
            },
        'fast_path': {
            'type': 'str',
            'choices': ['force', 'disable']
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
                    'all', 'curr_conn', 'total_l4_conn', 'total_l7_conn', 'total_tcp_conn', 'total_conn', 'total_fwd_bytes', 'total_fwd_pkts', 'total_rev_bytes', 'total_rev_pkts', 'total_dns_pkts', 'total_mf_dns_pkts', 'es_total_failure_actions', 'compression_bytes_before', 'compression_bytes_after', 'compression_hit', 'compression_miss',
                    'compression_miss_no_client', 'compression_miss_template_exclusion', 'curr_req', 'total_req', 'total_req_succ', 'peak_conn', 'curr_conn_rate', 'last_rsp_time', 'fastest_rsp_time', 'slowest_rsp_time', 'loc_permit', 'loc_deny', 'loc_conn', 'curr_ssl_conn', 'total_ssl_conn', 'backend-time-to-first-byte',
                    'backend-time-to-last-byte', 'in-latency', 'out-latency', 'total_fwd_bytes_out', 'total_fwd_pkts_out', 'total_rev_bytes_out', 'total_rev_pkts_out', 'curr_req_rate', 'curr_resp', 'total_resp', 'total_resp_succ', 'curr_resp_rate', 'dnsrrl_total_allowed', 'dnsrrl_total_dropped', 'dnsrrl_total_slipped', 'dnsrrl_bad_fqdn',
                    'throughput-bits-per-sec', 'dynamic-memory-alloc', 'dynamic-memory-free', 'dynamic-memory', 'ip_only_lb_fwd_bytes', 'ip_only_lb_rev_bytes', 'ip_only_lb_fwd_pkts', 'ip_only_lb_rev_pkts', 'total_dns_filter_type_drop', 'total_dns_filter_class_drop', 'dns_filter_type_a_drop', 'dns_filter_type_aaaa_drop',
                    'dns_filter_type_cname_drop', 'dns_filter_type_mx_drop', 'dns_filter_type_ns_drop', 'dns_filter_type_srv_drop', 'dns_filter_type_ptr_drop', 'dns_filter_type_soa_drop', 'dns_filter_type_txt_drop', 'dns_filter_type_any_drop', 'dns_filter_type_others_drop', 'dns_filter_class_internet_drop', 'dns_filter_class_chaos_drop',
                    'dns_filter_class_hesiod_drop', 'dns_filter_class_none_drop', 'dns_filter_class_any_drop', 'dns_filter_class_others_drop', 'dns_rpz_action_drop', 'dns_rpz_action_pass_thru', 'dns_rpz_action_tcp_only', 'dns_rpz_action_nxdomain', 'dns_rpz_action_nodata', 'dns_rpz_action_local_data', 'dns_rpz_trigger_client_ip',
                    'dns_rpz_trigger_resp_ip', 'dns_rpz_trigger_ns_ip', 'dns_rpz_trigger_qname', 'dns_rpz_trigger_ns_name', 'compression_bytes_before_br', 'compression_bytes_after_br', 'compression_bytes_before_total', 'compression_bytes_after_total', 'compression_hit_br', 'compression_miss_br', 'compression_hit_total', 'compression_miss_total',
                    'dnsrrl_total_tc', 'http1_client_idle_timeout', 'http2_client_idle_timeout', 'dnsrrl_nx_exceed'
                    ]
                }
            },
        'packet_capture_template': {
            'type': 'str',
            },
        'oper': {
            'type': 'dict',
            'state': {
                'type': 'str',
                'choices': ['All Up', 'Functional Up', 'Down', 'Disb', 'Unkn']
                },
            'real_curr_conn': {
                'type': 'int',
                },
            'int_curr_conn': {
                'type': 'int',
                },
            'curr_conn_overflow': {
                'type': 'int',
                },
            'print_extended_stats': {
                'type': 'int',
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
                'transaction_limited': {
                    'type': 'int',
                    },
                'jsi_requests': {
                    'type': 'int',
                    },
                'jsi_responses': {
                    'type': 'int',
                    },
                'jsi_pri_requests': {
                    'type': 'int',
                    },
                'jsi_api_requests': {
                    'type': 'int',
                    },
                'jsi_api_responses': {
                    'type': 'int',
                    },
                'jsi_api_no_auth_hdr': {
                    'type': 'int',
                    },
                'jsi_api_no_token': {
                    'type': 'int',
                    },
                'jsi_skip_no_fi': {
                    'type': 'int',
                    },
                'jsi_skip_no_ua': {
                    'type': 'int',
                    },
                'jsi_skip_not_browser': {
                    'type': 'int',
                    },
                'jsi_hash_add_fails': {
                    'type': 'int',
                    },
                'jsi_hash_lookup_fails': {
                    'type': 'int',
                    },
                'header_length_long': {
                    'type': 'int',
                    },
                'req_get': {
                    'type': 'int',
                    },
                'req_head': {
                    'type': 'int',
                    },
                'req_put': {
                    'type': 'int',
                    },
                'req_post': {
                    'type': 'int',
                    },
                'req_trace': {
                    'type': 'int',
                    },
                'req_options': {
                    'type': 'int',
                    },
                'req_connect': {
                    'type': 'int',
                    },
                'req_delete': {
                    'type': 'int',
                    },
                'req_unknown': {
                    'type': 'int',
                    },
                'req_track': {
                    'type': 'int',
                    },
                'rsp_sz_1k': {
                    'type': 'int',
                    },
                'rsp_sz_2k': {
                    'type': 'int',
                    },
                'rsp_sz_4k': {
                    'type': 'int',
                    },
                'rsp_sz_8k': {
                    'type': 'int',
                    },
                'rsp_sz_16k': {
                    'type': 'int',
                    },
                'rsp_sz_32k': {
                    'type': 'int',
                    },
                'rsp_sz_64k': {
                    'type': 'int',
                    },
                'rsp_sz_256k': {
                    'type': 'int',
                    },
                'rsp_sz_gt_256k': {
                    'type': 'int',
                    },
                'chunk_sz_512': {
                    'type': 'int',
                    },
                'chunk_sz_1k': {
                    'type': 'int',
                    },
                'chunk_sz_2k': {
                    'type': 'int',
                    },
                'chunk_sz_4k': {
                    'type': 'int',
                    },
                'chunk_sz_gt_4k': {
                    'type': 'int',
                    },
                'req_sz_1k': {
                    'type': 'int',
                    },
                'req_sz_2k': {
                    'type': 'int',
                    },
                'req_sz_4k': {
                    'type': 'int',
                    },
                'req_sz_8k': {
                    'type': 'int',
                    },
                'req_sz_16k': {
                    'type': 'int',
                    },
                'req_sz_32k': {
                    'type': 'int',
                    },
                'req_sz_64k': {
                    'type': 'int',
                    },
                'req_sz_256k': {
                    'type': 'int',
                    },
                'req_sz_gt_256k': {
                    'type': 'int',
                    },
                'req_content_len': {
                    'type': 'int',
                    },
                'rsp_chunk': {
                    'type': 'int',
                    },
                'doh_req': {
                    'type': 'int',
                    },
                'doh_req_get': {
                    'type': 'int',
                    },
                'doh_req_post': {
                    'type': 'int',
                    },
                'doh_non_doh_req': {
                    'type': 'int',
                    },
                'doh_non_doh_req_get': {
                    'type': 'int',
                    },
                'doh_non_doh_req_post': {
                    'type': 'int',
                    },
                'doh_resp': {
                    'type': 'int',
                    },
                'doh_tc_resp': {
                    'type': 'int',
                    },
                'doh_udp_dns_req': {
                    'type': 'int',
                    },
                'doh_udp_dns_resp': {
                    'type': 'int',
                    },
                'doh_tcp_dns_req': {
                    'type': 'int',
                    },
                'doh_tcp_dns_resp': {
                    'type': 'int',
                    },
                'doh_req_send_failed': {
                    'type': 'int',
                    },
                'doh_resp_send_failed': {
                    'type': 'int',
                    },
                'doh_malloc_fail': {
                    'type': 'int',
                    },
                'doh_req_udp_retry': {
                    'type': 'int',
                    },
                'doh_req_udp_retry_fail': {
                    'type': 'int',
                    },
                'doh_req_tcp_retry': {
                    'type': 'int',
                    },
                'doh_req_tcp_retry_fail': {
                    'type': 'int',
                    },
                'doh_snat_failed': {
                    'type': 'int',
                    },
                'doh_path_not_found': {
                    'type': 'int',
                    },
                'doh_get_dns_arg_failed': {
                    'type': 'int',
                    },
                'doh_get_base64_decode_failed': {
                    'type': 'int',
                    },
                'doh_post_content_type_mismatch': {
                    'type': 'int',
                    },
                'doh_post_payload_not_found': {
                    'type': 'int',
                    },
                'doh_post_payload_extract_failed': {
                    'type': 'int',
                    },
                'doh_non_doh_method': {
                    'type': 'int',
                    },
                'doh_tcp_send_failed': {
                    'type': 'int',
                    },
                'doh_udp_send_failed': {
                    'type': 'int',
                    },
                'doh_query_time_out': {
                    'type': 'int',
                    },
                'doh_dns_query_type_a': {
                    'type': 'int',
                    },
                'doh_dns_query_type_aaaa': {
                    'type': 'int',
                    },
                'doh_dns_query_type_ns': {
                    'type': 'int',
                    },
                'doh_dns_query_type_cname': {
                    'type': 'int',
                    },
                'doh_dns_query_type_any': {
                    'type': 'int',
                    },
                'doh_dns_query_type_srv': {
                    'type': 'int',
                    },
                'doh_dns_query_type_mx': {
                    'type': 'int',
                    },
                'doh_dns_query_type_soa': {
                    'type': 'int',
                    },
                'doh_dns_query_type_others': {
                    'type': 'int',
                    },
                'doh_resp_setup_failed': {
                    'type': 'int',
                    },
                'doh_resp_header_alloc_failed': {
                    'type': 'int',
                    },
                'doh_resp_que_failed': {
                    'type': 'int',
                    },
                'doh_resp_udp_frags': {
                    'type': 'int',
                    },
                'doh_resp_tcp_frags': {
                    'type': 'int',
                    },
                'doh_serv_sel_failed': {
                    'type': 'int',
                    },
                'doh_retry_w_tcp': {
                    'type': 'int',
                    },
                'doh_get_uri_too_long': {
                    'type': 'int',
                    },
                'doh_post_payload_too_large': {
                    'type': 'int',
                    },
                'doh_dns_malformed_query': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_err_format': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_err_server': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_err_name': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_err_type': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_refuse': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_yxdomain': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_yxrrset': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_nxrrset': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_notauth': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_notzone': {
                    'type': 'int',
                    },
                'doh_dns_resp_rcode_other': {
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
            'clear_curr_conn': {
                'type': 'bool',
                },
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
                    'tcp', 'udp', 'others', 'diameter', 'dns-tcp', 'dns-udp', 'fast-http', 'fix', 'ftp', 'ftp-proxy', 'http', 'https', 'imap', 'mlb', 'mms', 'mysql', 'mssql', 'pop3', 'radius', 'rtsp', 'sip', 'sip-tcp', 'sips', 'smpp-tcp', 'spdy', 'spdys', 'smtp', 'mqtt', 'mqtts', 'ssl-proxy', 'ssli', 'ssh', 'tcp-proxy', 'tftp', 'fast-fix',
                    'http-over-quic'
                    ]
                }
            },
        'stats': {
            'type': 'dict',
            'curr_conn': {
                'type': 'str',
                },
            'total_l4_conn': {
                'type': 'str',
                },
            'total_l7_conn': {
                'type': 'str',
                },
            'total_tcp_conn': {
                'type': 'str',
                },
            'total_conn': {
                'type': 'str',
                },
            'total_fwd_bytes': {
                'type': 'str',
                },
            'total_fwd_pkts': {
                'type': 'str',
                },
            'total_rev_bytes': {
                'type': 'str',
                },
            'total_rev_pkts': {
                'type': 'str',
                },
            'total_dns_pkts': {
                'type': 'str',
                },
            'total_mf_dns_pkts': {
                'type': 'str',
                },
            'es_total_failure_actions': {
                'type': 'str',
                },
            'compression_bytes_before': {
                'type': 'str',
                },
            'compression_bytes_after': {
                'type': 'str',
                },
            'compression_hit': {
                'type': 'str',
                },
            'compression_miss': {
                'type': 'str',
                },
            'compression_miss_no_client': {
                'type': 'str',
                },
            'compression_miss_template_exclusion': {
                'type': 'str',
                },
            'curr_req': {
                'type': 'str',
                },
            'total_req': {
                'type': 'str',
                },
            'total_req_succ': {
                'type': 'str',
                },
            'peak_conn': {
                'type': 'str',
                },
            'curr_conn_rate': {
                'type': 'str',
                },
            'last_rsp_time': {
                'type': 'str',
                },
            'fastest_rsp_time': {
                'type': 'str',
                },
            'slowest_rsp_time': {
                'type': 'str',
                },
            'loc_permit': {
                'type': 'str',
                },
            'loc_deny': {
                'type': 'str',
                },
            'loc_conn': {
                'type': 'str',
                },
            'curr_ssl_conn': {
                'type': 'str',
                },
            'total_ssl_conn': {
                'type': 'str',
                },
            'backend_time_to_first_byte': {
                'type': 'str',
                },
            'backend_time_to_last_byte': {
                'type': 'str',
                },
            'in_latency': {
                'type': 'str',
                },
            'out_latency': {
                'type': 'str',
                },
            'total_fwd_bytes_out': {
                'type': 'str',
                },
            'total_fwd_pkts_out': {
                'type': 'str',
                },
            'total_rev_bytes_out': {
                'type': 'str',
                },
            'total_rev_pkts_out': {
                'type': 'str',
                },
            'curr_req_rate': {
                'type': 'str',
                },
            'curr_resp': {
                'type': 'str',
                },
            'total_resp': {
                'type': 'str',
                },
            'total_resp_succ': {
                'type': 'str',
                },
            'curr_resp_rate': {
                'type': 'str',
                },
            'dnsrrl_total_allowed': {
                'type': 'str',
                },
            'dnsrrl_total_dropped': {
                'type': 'str',
                },
            'dnsrrl_total_slipped': {
                'type': 'str',
                },
            'dnsrrl_bad_fqdn': {
                'type': 'str',
                },
            'throughput_bits_per_sec': {
                'type': 'str',
                },
            'dynamic_memory': {
                'type': 'str',
                },
            'ip_only_lb_fwd_bytes': {
                'type': 'str',
                },
            'ip_only_lb_rev_bytes': {
                'type': 'str',
                },
            'ip_only_lb_fwd_pkts': {
                'type': 'str',
                },
            'ip_only_lb_rev_pkts': {
                'type': 'str',
                },
            'total_dns_filter_type_drop': {
                'type': 'str',
                },
            'total_dns_filter_class_drop': {
                'type': 'str',
                },
            'dns_filter_type_a_drop': {
                'type': 'str',
                },
            'dns_filter_type_aaaa_drop': {
                'type': 'str',
                },
            'dns_filter_type_cname_drop': {
                'type': 'str',
                },
            'dns_filter_type_mx_drop': {
                'type': 'str',
                },
            'dns_filter_type_ns_drop': {
                'type': 'str',
                },
            'dns_filter_type_srv_drop': {
                'type': 'str',
                },
            'dns_filter_type_ptr_drop': {
                'type': 'str',
                },
            'dns_filter_type_soa_drop': {
                'type': 'str',
                },
            'dns_filter_type_txt_drop': {
                'type': 'str',
                },
            'dns_filter_type_any_drop': {
                'type': 'str',
                },
            'dns_filter_type_others_drop': {
                'type': 'str',
                },
            'dns_filter_class_internet_drop': {
                'type': 'str',
                },
            'dns_filter_class_chaos_drop': {
                'type': 'str',
                },
            'dns_filter_class_hesiod_drop': {
                'type': 'str',
                },
            'dns_filter_class_none_drop': {
                'type': 'str',
                },
            'dns_filter_class_any_drop': {
                'type': 'str',
                },
            'dns_filter_class_others_drop': {
                'type': 'str',
                },
            'dns_rpz_action_drop': {
                'type': 'str',
                },
            'dns_rpz_action_pass_thru': {
                'type': 'str',
                },
            'dns_rpz_action_tcp_only': {
                'type': 'str',
                },
            'dns_rpz_action_nxdomain': {
                'type': 'str',
                },
            'dns_rpz_action_nodata': {
                'type': 'str',
                },
            'dns_rpz_action_local_data': {
                'type': 'str',
                },
            'dns_rpz_trigger_client_ip': {
                'type': 'str',
                },
            'dns_rpz_trigger_resp_ip': {
                'type': 'str',
                },
            'dns_rpz_trigger_ns_ip': {
                'type': 'str',
                },
            'dns_rpz_trigger_qname': {
                'type': 'str',
                },
            'dns_rpz_trigger_ns_name': {
                'type': 'str',
                },
            'compression_bytes_before_br': {
                'type': 'str',
                },
            'compression_bytes_after_br': {
                'type': 'str',
                },
            'compression_bytes_before_total': {
                'type': 'str',
                },
            'compression_bytes_after_total': {
                'type': 'str',
                },
            'compression_hit_br': {
                'type': 'str',
                },
            'compression_miss_br': {
                'type': 'str',
                },
            'compression_hit_total': {
                'type': 'str',
                },
            'compression_miss_total': {
                'type': 'str',
                },
            'dnsrrl_total_tc': {
                'type': 'str',
                },
            'http1_client_idle_timeout': {
                'type': 'str',
                },
            'http2_client_idle_timeout': {
                'type': 'str',
                },
            'dnsrrl_nx_exceed': {
                'type': 'str',
                },
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
                    'tcp', 'udp', 'others', 'diameter', 'dns-tcp', 'dns-udp', 'fast-http', 'fix', 'ftp', 'ftp-proxy', 'http', 'https', 'imap', 'mlb', 'mms', 'mysql', 'mssql', 'pop3', 'radius', 'rtsp', 'sip', 'sip-tcp', 'sips', 'smpp-tcp', 'spdy', 'spdys', 'smtp', 'mqtt', 'mqtts', 'ssl-proxy', 'ssli', 'ssh', 'tcp-proxy', 'tftp', 'fast-fix',
                    'http-over-quic'
                    ]
                }
            }
        })
    # Parent keys
    rv.update(dict(virtual_server_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/virtual-server/{virtual_server_name}/port/{port_number}+{protocol}"

    f_dict = {}
    if '/' in str(module.params["port_number"]):
        f_dict["port_number"] = module.params["port_number"].replace("/", "%2F")
    else:
        f_dict["port_number"] = module.params["port_number"]
    if '/' in str(module.params["protocol"]):
        f_dict["protocol"] = module.params["protocol"].replace("/", "%2F")
    else:
        f_dict["protocol"] = module.params["protocol"]
    if '/' in module.params["virtual_server_name"]:
        f_dict["virtual_server_name"] = module.params["virtual_server_name"].replace("/", "%2F")
    else:
        f_dict["virtual_server_name"] = module.params["virtual_server_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/virtual-server/{virtual_server_name}/port/"

    f_dict = {}
    f_dict["port_number"] = ""
    f_dict["protocol"] = ""
    f_dict["virtual_server_name"] = module.params["virtual_server_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["port"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["port"].get(k) != v:
            change_results["changed"] = True
            config_changes["port"][k] = v

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
    payload = utils.build_json("port", module.params, AVAILABLE_PROPERTIES)
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

        if state == 'present' or state == 'absent':
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
            if module.params.get("get_type") == "single" or module.params.get("get_type") is None:
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["port"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["port-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["port"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["port"]["stats"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


"""
    Custom class which override the _check_required_arguments function to check check required arguments based on state and get_type.
"""


class AcosAnsibleModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        super(AcosAnsibleModule, self).__init__(*args, **kwargs)

    def _check_required_arguments(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        # skip validation if state is 'noop' and get_type is 'list'
        if not (param.get("state") == "noop" and param.get("get_type") == "list"):
            missing = []
            if spec is None:
                return missing
            # Check for missing required parameters in the provided argument spec
            for (k, v) in spec.items():
                required = v.get('required', False)
                if required and k not in param:
                    missing.append(k)
            if missing:
                self.fail_json(msg="Missing required parameters: {}".format(", ".join(missing)))


def main():
    module = AcosAnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
