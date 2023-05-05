#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_dst_entry
description:
    - Configure IP/IPv6 static entry
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
    dst_entry_name:
        description:
        - "Field dst_entry_name"
        type: str
        required: True
    ipv6_addr:
        description:
        - "Field ipv6_addr"
        type: str
        required: False
    ip_addr:
        description:
        - "Field ip_addr"
        type: str
        required: False
    subnet_ip_addr:
        description:
        - "IP Subnet"
        type: str
        required: False
    subnet_ipv6_addr:
        description:
        - "IPV6 Subnet"
        type: str
        required: False
    description:
        description:
        - "Description for this Destination Entry"
        type: str
        required: False
    exceed_log_dep_cfg:
        description:
        - "Field exceed_log_dep_cfg"
        type: dict
        required: False
        suboptions:
            exceed_log_enable:
                description:
                - "(Deprecated)Enable logging of limit exceed drop's"
                type: bool
            log_with_sflow_dep:
                description:
                - "Turn on sflow sample with log"
                type: bool
    exceed_log_cfg:
        description:
        - "Field exceed_log_cfg"
        type: dict
        required: False
        suboptions:
            log_enable:
                description:
                - "Enable logging of limit exceed drop's"
                type: bool
            log_with_sflow:
                description:
                - "Turn on sflow sample with log"
                type: bool
            log_high_frequency:
                description:
                - "Enable High frequency logging for non-event logs per entry"
                type: bool
            rate_limit:
                description:
                - "Rate limit per second per entry(Default = 1 per second)"
                type: int
    log_periodic:
        description:
        - "Enable periodic log while event is continuing"
        type: bool
        required: False
    drop_frag_pkt:
        description:
        - "Drop fragmented packets"
        type: bool
        required: False
    sflow:
        description:
        - "Field sflow"
        type: dict
        required: False
        suboptions:
            polling:
                description:
                - "Field polling"
                type: dict
    drop_on_no_src_dst_default:
        description:
        - "Drop if no match with src-based-policy class-list, and default is not
          configured"
        type: bool
        required: False
    blackhole_on_glid_exceed:
        description:
        - "Blackhole destination entry for X minutes upon glid limit exceeded"
        type: int
        required: False
    source_nat_pool:
        description:
        - "Configure source NAT"
        type: str
        required: False
    dest_nat_ip:
        description:
        - "Destination NAT IP address"
        type: str
        required: False
    dest_nat_ipv6:
        description:
        - "Destination NAT IPv6 address"
        type: str
        required: False
    drop_disable:
        description:
        - "Disable certain drops during packet processing"
        type: bool
        required: False
    drop_disable_fwd_immediate:
        description:
        - "Immediately forward L4 drops"
        type: bool
        required: False
    template:
        description:
        - "Field template"
        type: dict
        required: False
        suboptions:
            logging:
                description:
                - "DDOS logging template"
                type: str
    operational_mode:
        description:
        - "'protection'= Protection mode; 'bypass'= Bypass mode;"
        type: str
        required: False
    reporting_disabled:
        description:
        - "Disable Reporting"
        type: bool
        required: False
    glid:
        description:
        - "Global limit ID"
        type: str
        required: False
    glid_exceed_action:
        description:
        - "Field glid_exceed_action"
        type: dict
        required: False
        suboptions:
            stateless_encap_action_cfg:
                description:
                - "Field stateless_encap_action_cfg"
                type: dict
    advertised_enable:
        description:
        - "BGP advertised"
        type: bool
        required: False
    set_counter_base_val:
        description:
        - "Set T2 counter value of current context to specified value"
        type: int
        required: False
    inbound_forward_dscp:
        description:
        - "To set dscp value for inbound packets (DSCP Value for the clear traffic
          marking)"
        type: int
        required: False
    outbound_forward_dscp:
        description:
        - "To set dscp value for outbound"
        type: int
        required: False
    pattern_recognition_sensitivity:
        description:
        - "'high'= High sensitive pattern recognition; 'medium'= Medium sensitive pattern
          recognition; 'low'= Low sensitive pattern recognition;"
        type: str
        required: False
    pattern_recognition_hw_filter_enable:
        description:
        - "to enable pattern recognition hardware filter"
        type: bool
        required: False
    enable_top_k:
        description:
        - "Field enable_top_k"
        type: list
        required: False
        suboptions:
            topk_type:
                description:
                - "'destination'= Topk destination IP;"
                type: str
            topk_num_records:
                description:
                - "Maximum number of records to show in topk"
                type: int
    traffic_distribution_mode:
        description:
        - "'default'= Distribute traffic to one slot using default distribution mechanism;
          'source-ip-based'= Distribute traffic between slots, based on source ip;"
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
                - "'all'= all; 'dst_tcp_any_exceed'= TCP Dst L4-Type Rate= Total Exceeded;
          'dst_tcp_pkt_rate_exceed'= TCP Dst L4-Type Rate= Packet Exceeded;
          'dst_tcp_conn_rate_exceed'= TCP Dst L4-Type Rate= Conn Exceeded;
          'dst_udp_any_exceed'= UDP Dst L4-Type Rate= Total Exceeded;
          'dst_udp_pkt_rate_exceed'= UDP Dst L4-Type Rate= Packet Exceeded;
          'dst_udp_conn_limit_exceed'= UDP Dst L4-Type Limit= Conn Exceeded;
          'dst_udp_conn_rate_exceed'= UDP Dst L4-Type Rate= Conn Exceeded;
          'dst_icmp_pkt_rate_exceed'= ICMP Dst Rate= Packet Exceeded;
          'dst_other_pkt_rate_exceed'= OTHER Dst L4-Type Rate= Packet Exceeded;
          'dst_other_frag_pkt_rate_exceed'= OTHER Dst L4-Type Rate= Frag Exceeded;
          'dst_port_pkt_rate_exceed'= Port Rate= Packet Exceeded;
          'dst_port_conn_limit_exceed'= Port Limit= Conn Exceeded;
          'dst_port_conn_rate_exceed'= Port Rate= Conn Exceeded; 'dst_pkt_sent'= Inbound=
          Packets Forwarded; 'dst_udp_pkt_sent'= UDP Total Packets Forwarded;
          'dst_tcp_pkt_sent'= TCP Total Packets Forwarded; 'dst_icmp_pkt_sent'= ICMP
          Total Packets Forwarded; 'dst_other_pkt_sent'= OTHER Total Packets Forwarded;
          'dst_tcp_conn_limit_exceed'= TCP Dst L4-Type Limit= Conn Exceeded;
          'dst_tcp_pkt_rcvd'= TCP Total Packets Received; 'dst_udp_pkt_rcvd'= UDP Total
          Packets Received; 'dst_icmp_pkt_rcvd'= ICMP Total Packets Received;
          'dst_other_pkt_rcvd'= OTHER Total Packets Received; 'dst_udp_filter_match'= UDP
          Filter Match; 'dst_udp_filter_not_match'= UDP Filter Not Matched on Pkt;
          'dst_udp_filter_action_blacklist'= UDP Filter Action Blacklist;
          'dst_udp_filter_action_drop'= UDP Filter Action Drop; 'dst_tcp_syn'= TCP Total
          SYN Received; 'dst_tcp_syn_drop'= TCP SYN Packets Dropped;
          'dst_tcp_src_rate_drop'= TCP Src Rate= Total Exceeded; 'dst_udp_src_rate_drop'=
          UDP Src Rate= Total Exceeded; 'dst_icmp_src_rate_drop'= ICMP Src Rate= Total
          Exceeded; 'dst_other_frag_src_rate_drop'= OTHER Src Rate= Frag Exceeded;
          'dst_other_src_rate_drop'= OTHER Src Rate= Total Exceeded; 'dst_tcp_drop'= TCP
          Total Packets Dropped; 'dst_udp_drop'= UDP Total Packets Dropped;
          'dst_icmp_drop'= ICMP Total Packets Dropped; 'dst_frag_drop'= Fragmented
          Packets Dropped; 'dst_other_drop'= OTHER Total Packets Dropped; 'dst_tcp_auth'=
          TCP Auth= SYN Cookie Sent; 'dst_udp_filter_action_default_pass'= UDP Filter
          Action Default Pass; 'dst_tcp_filter_match'= TCP Filter Match;
          'dst_tcp_filter_not_match'= TCP Filter Not Matched on Pkt;
          'dst_tcp_filter_action_blacklist'= TCP Filter Action Blacklist;
          'dst_tcp_filter_action_drop'= TCP Filter Action Drop;
          'dst_tcp_filter_action_default_pass'= TCP Filter Action Default Pass;
          'dst_udp_filter_action_whitelist'= UDP Filter Action WL; 'dst_over_limit_on'=
          DST overlimit Trigger ON; 'dst_over_limit_off'= DST overlimit Trigger OFF;
          'dst_port_over_limit_on'= DST port overlimit Trigger ON;
          'dst_port_over_limit_off'= DST port overlimit Trigger OFF;
          'dst_over_limit_action'= DST overlimit action; 'dst_port_over_limit_action'=
          DST port overlimit action; 'scanning_detected_drop'= Scanning Detected drop
          (deprecated); 'scanning_detected_blacklist'= Scanning Detected blacklist
          (deprecated); 'dst_udp_kibit_rate_drop'= UDP Dst L4-Type Rate= KiBit Exceeded;
          'dst_tcp_kibit_rate_drop'= TCP Dst L4-Type Rate= KiBit Exceeded;
          'dst_icmp_kibit_rate_drop'= ICMP Dst Rate= KiBit Exceeded;
          'dst_other_kibit_rate_drop'= OTHER Dst L4-Type Rate= KiBit Exceeded;
          'dst_port_undef_drop'= Dst Port Undefined Dropped; 'dst_port_bl'= Dst Port
          Blacklist Packets Dropped; 'dst_src_port_bl'= Dst SrcPort Blacklist Packets
          Dropped; 'dst_port_kbit_rate_exceed'= Port Rate= KiBit Exceeded;
          'dst_tcp_src_drop'= TCP Src Packets Dropped; 'dst_udp_src_drop'= UDP Src
          Packets Dropped; 'dst_icmp_src_drop'= ICMP Src Packets Dropped;
          'dst_other_src_drop'= OTHER Src Packets Dropped; 'tcp_syn_rcvd'= TCP Inbound
          SYN Received; 'tcp_syn_ack_rcvd'= TCP SYN ACK Received; 'tcp_ack_rcvd'= TCP ACK
          Received; 'tcp_fin_rcvd'= TCP FIN Received; 'tcp_rst_rcvd'= TCP RST Received;
          'ingress_bytes'= Inbound= Bytes Received; 'egress_bytes'= Outbound= Bytes
          Received; 'ingress_packets'= Inbound= Packets Received; 'egress_packets'=
          Outbound= Packets Received; 'tcp_fwd_recv'= TCP Inbound Packets Received;
          'udp_fwd_recv'= UDP Inbound Packets Received; 'icmp_fwd_recv'= ICMP Inbound
          Packets Received; 'tcp_syn_cookie_fail'= TCP Auth= SYN Cookie Failed;
          'dst_tcp_session_created'= TCP Sessions Created; 'dst_udp_session_created'= UDP
          Sessions Created; 'dst_tcp_filter_action_whitelist'= TCP Filter Action WL;
          'dst_other_filter_match'= OTHER Filter Match; 'dst_other_filter_not_match'=
          OTHER Filter Not Matched on Pkt; 'dst_other_filter_action_blacklist'= OTHER
          Filter Action Blacklist; 'dst_other_filter_action_drop'= OTHER Filter Action
          Drop; 'dst_other_filter_action_whitelist'= OTHER Filter Action WL;
          'dst_other_filter_action_default_pass'= OTHER Filter Action Default Pass;
          'dst_blackhole_inject'= Dst Blackhole Inject; 'dst_blackhole_withdraw'= Dst
          Blackhole Withdraw; 'dst_tcp_out_of_seq_excd'= TCP Out-Of-Seq Exceeded;
          'dst_tcp_retransmit_excd'= TCP Retransmit Exceeded; 'dst_tcp_zero_window_excd'=
          TCP Zero-Window Exceeded; 'dst_tcp_conn_prate_excd'= TCP Rate= Conn Pkt
          Exceeded; 'dst_tcp_action_on_ack_init'= TCP Auth= ACK Retry Init;
          'dst_tcp_action_on_ack_gap_drop'= TCP Auth= ACK Retry Retry-Gap Dropped;
          'dst_tcp_action_on_ack_fail'= TCP Auth= ACK Retry Dropped;
          'dst_tcp_action_on_ack_pass'= TCP Auth= ACK Retry Passed;
          'dst_tcp_action_on_syn_init'= TCP Auth= SYN Retry Init;
          'dst_tcp_action_on_syn_gap_drop'= TCP Auth= SYN Retry-Gap Dropped;
          'dst_tcp_action_on_syn_fail'= TCP Auth= SYN Retry Dropped;
          'dst_tcp_action_on_syn_pass'= TCP Auth= SYN Retry Passed;
          'udp_payload_too_small'= UDP Payload Too Small; 'udp_payload_too_big'= UDP
          Payload Too Large; 'dst_udp_conn_prate_excd'= UDP Rate= Conn Pkt Exceeded;
          'dst_udp_ntp_monlist_req'= UDP NTP Monlist Request; 'dst_udp_ntp_monlist_resp'=
          UDP NTP Monlist Response; 'dst_udp_wellknown_sport_drop'= UDP SrcPort
          Wellknown; 'dst_udp_retry_init'= UDP Auth= Retry Init; 'dst_udp_retry_pass'=
          UDP Auth= Retry Passed; 'dst_tcp_bytes_drop'= TCP Total Bytes Dropped;
          'dst_udp_bytes_drop'= UDP Total Bytes Dropped; 'dst_icmp_bytes_drop'= ICMP
          Total Bytes Dropped; 'dst_other_bytes_drop'= OTHER Total Bytes Dropped;
          'dst_out_no_route'= Dst IPv4/v6 Out No Route; 'outbound_bytes_sent'= Outbound=
          Bytes Forwarded; 'outbound_pkt_drop'= Outbound= Packets Dropped;
          'outbound_bytes_drop'= Outbound= Bytes Dropped; 'outbound_pkt_sent'= Outbound=
          Packets Forwarded; 'inbound_bytes_sent'= Inbound= Bytes Forwarded;
          'inbound_bytes_drop'= Inbound= Bytes Dropped; 'dst_src_port_pkt_rate_exceed'=
          SrcPort Rate= Packet Exceeded; 'dst_src_port_kbit_rate_exceed'= SrcPort Rate=
          KiBit Exceeded; 'dst_src_port_conn_limit_exceed'= SrcPort Limit= Conn Exceeded;
          'dst_src_port_conn_rate_exceed'= SrcPort Rate= Conn Exceeded;
          'dst_ip_proto_pkt_rate_exceed'= IP-Proto Rate= Packet Exceeded;
          'dst_ip_proto_kbit_rate_exceed'= IP-Proto Rate= KiBit Exceeded;
          'dst_tcp_port_any_exceed'= TCP Port Rate= Total Exceed;
          'dst_udp_port_any_exceed'= UDP Port Rate= Total Exceed; 'dst_tcp_auth_pass'=
          TCP Auth= SYN Auth Passed; 'dst_tcp_rst_cookie_fail'= TCP Auth= RST Cookie
          Failed; 'dst_tcp_unauth_drop'= TCP Auth= Unauth Dropped;
          'src_tcp_syn_auth_fail'= Src TCP Auth= SYN Auth Failed;
          'src_tcp_syn_cookie_sent'= Src TCP Auth= SYN Cookie Sent;
          'src_tcp_syn_cookie_fail'= Src TCP Auth= SYN Cookie Failed;
          'src_tcp_rst_cookie_fail'= Src TCP Auth= RST Cookie Failed;
          'src_tcp_unauth_drop'= Src TCP Auth= Unauth Dropped;
          'src_tcp_action_on_syn_init'= Src TCP Auth= SYN Retry Init;"
                type: str
            counters2:
                description:
                - "'src_tcp_action_on_syn_gap_drop'= Src TCP Auth= SYN Retry-Gap Dropped;
          'src_tcp_action_on_syn_fail'= Src TCP Auth= SYN Retry Dropped;
          'src_tcp_action_on_ack_init'= Src TCP Auth= ACK Retry Init;
          'src_tcp_action_on_ack_gap_drop'= Src TCP Auth= ACK Retry Retry-Gap Dropped;
          'src_tcp_action_on_ack_fail'= Src TCP Auth= ACK Retry Dropped;
          'src_tcp_out_of_seq_excd'= Src TCP Out-Of-Seq Exceeded;
          'src_tcp_retransmit_excd'= Src TCP Retransmit Exceeded;
          'src_tcp_zero_window_excd'= Src TCP Zero-Window Exceeded;
          'src_tcp_conn_prate_excd'= Src TCP Rate= Conn Pkt Exceeded;
          'src_udp_min_payload'= Src UDP Payload Too Small; 'src_udp_max_payload'= Src
          UDP Payload Too Large; 'src_udp_conn_prate_excd'= Src UDP Rate= Conn Pkt
          Exceeded; 'src_udp_ntp_monlist_req'= Src UDP NTP Monlist Request;
          'src_udp_ntp_monlist_resp'= Src UDP NTP Monlist Response;
          'src_udp_wellknown_sport_drop'= Src UDP SrcPort Wellknown;
          'src_udp_retry_init'= Src UDP Auth= Retry Init; 'dst_udp_retry_gap_drop'= UDP
          Auth= Retry-Gap Dropped; 'dst_udp_retry_fail'= UDP Auth= Retry Timeout;
          'dst_tcp_session_aged'= TCP Sessions Aged; 'dst_udp_session_aged'= UDP Sessions
          Aged; 'dst_tcp_conn_close'= TCP Connections Closed;
          'dst_tcp_conn_close_half_open'= TCP Half Open Connections Closed;
          'dst_l4_tcp_auth'= TCP Dst L4-Type Auth= SYN Cookie Sent;
          'tcp_l4_syn_cookie_fail'= TCP Dst L4-Type Auth= SYN Cookie Failed;
          'tcp_l4_rst_cookie_fail'= TCP Dst L4-Type Auth= RST Cookie Failed;
          'tcp_l4_unauth_drop'= TCP Dst L4-Type Auth= Unauth Dropped;
          'dst_drop_frag_pkt'= Dst Fragmented Packets Dropped;
          'src_tcp_filter_action_blacklist'= Src TCP Filter Action Blacklist;
          'src_tcp_filter_action_whitelist'= Src TCP Filter Action WL;
          'src_tcp_filter_action_drop'= Src TCP Filter Action Drop;
          'src_tcp_filter_action_default_pass'= Src TCP Filter Action Default Pass;
          'src_udp_filter_action_blacklist'= Src UDP Filter Action Blacklist;
          'src_udp_filter_action_whitelist'= Src UDP Filter Action WL;
          'src_udp_filter_action_drop'= Src UDP Filter Action Drop;
          'src_udp_filter_action_default_pass'= Src UDP Filter Action Default Pass;
          'src_other_filter_action_blacklist'= Src OTHER Filter Action Blacklist;
          'src_other_filter_action_whitelist'= Src OTHER Filter Action WL;
          'src_other_filter_action_drop'= Src OTHER Filter Action Drop;
          'src_other_filter_action_default_pass'= Src OTHER Filter Action Default Pass;
          'tcp_invalid_syn'= TCP Invalid SYN Received; 'dst_tcp_conn_close_w_rst'= TCP
          RST Connections Closed; 'dst_tcp_conn_close_w_fin'= TCP FIN Connections Closed;
          'dst_tcp_conn_close_w_idle'= TCP Idle Connections Closed;
          'dst_tcp_conn_create_from_syn'= TCP Connections Created From SYN;
          'dst_tcp_conn_create_from_ack'= TCP Connections Created From ACK;
          'src_frag_drop'= Src Fragmented Packets Dropped; 'dst_l4_tcp_blacklist_drop'=
          Dst L4-type TCP Blacklist Dropped; 'dst_l4_udp_blacklist_drop'= Dst L4-type UDP
          Blacklist Dropped; 'dst_l4_icmp_blacklist_drop'= Dst L4-type ICMP Blacklist
          Dropped; 'dst_l4_other_blacklist_drop'= Dst L4-type OTHER Blacklist Dropped;
          'src_l4_tcp_blacklist_drop'= Src L4-type TCP Blacklist Dropped;
          'src_l4_udp_blacklist_drop'= Src L4-type UDP Blacklist Dropped;
          'src_l4_icmp_blacklist_drop'= Src L4-type ICMP Blacklist Dropped;
          'src_l4_other_blacklist_drop'= Src L4-type OTHER Blacklist Dropped;
          'drop_frag_timeout_drop'= Fragment Reassemble Timeout Drop;
          'dst_port_kbit_rate_exceed_pkt'= Port Rate= KiBit Pkt Exceeded;
          'dst_tcp_bytes_rcv'= TCP Total Bytes Received; 'dst_udp_bytes_rcv'= UDP Total
          Bytes Received; 'dst_icmp_bytes_rcv'= ICMP Total Bytes Received;
          'dst_other_bytes_rcv'= OTHER Total Bytes Received; 'dst_tcp_bytes_sent'= TCP
          Total Bytes Forwarded; 'dst_udp_bytes_sent'= UDP Total Bytes Forwarded;
          'dst_icmp_bytes_sent'= ICMP Total Bytes Forwarded; 'dst_other_bytes_sent'=
          OTHER Total Bytes Forwarded; 'dst_udp_auth_drop'= UDP Auth= Dropped;
          'dst_tcp_auth_drop'= TCP Auth= Dropped; 'dst_tcp_auth_resp'= TCP Auth=
          Responded; 'inbound_pkt_drop'= Inbound= Packets Dropped;
          'dst_entry_pkt_rate_exceed'= Entry Rate= Packet Exceeded;
          'dst_entry_kbit_rate_exceed'= Entry Rate= KiBit Exceeded;
          'dst_entry_conn_limit_exceed'= Entry Limit= Conn Exceeded;
          'dst_entry_conn_rate_exceed'= Entry Rate= Conn Exceeded;
          'dst_entry_frag_pkt_rate_exceed'= Entry Rate= Frag Packet Exceeded;
          'dst_icmp_any_exceed'= ICMP Rate= Total Exceed; 'dst_other_any_exceed'= OTHER
          Rate= Total Exceed; 'src_dst_pair_entry_total'= Src-Dst Pair Entry Total Count;
          'src_dst_pair_entry_udp'= Src-Dst Pair Entry UDP Count;
          'src_dst_pair_entry_tcp'= Src-Dst Pair Entry TCP Count;
          'src_dst_pair_entry_icmp'= Src-Dst Pair Entry ICMP Count;
          'src_dst_pair_entry_other'= Src-Dst Pair Entry OTHER Count;
          'dst_clist_overflow_policy_at_learning'= Dst Src-Based Overflow Policy Hit;
          'tcp_rexmit_syn_limit_drop'= TCP SYN Retransmit Exceeded Drop;
          'tcp_rexmit_syn_limit_bl'= TCP SYN Retransmit Exceeded Blacklist;
          'dst_tcp_wellknown_sport_drop'= TCP SrcPort Wellknown;
          'src_tcp_wellknown_sport_drop'= Src TCP SrcPort Wellknown; 'dst_frag_rcvd'=
          Fragmented Packets Received; 'no_policy_class_list_match'= No Policy Class-list
          Match; 'src_udp_retry_gap_drop'= Src UDP Auth= Retry-Gap Dropped;
          'dst_entry_kbit_rate_exceed_count'= Entry Rate= KiBit Exceeded Count;
          'dst_port_undef_hit'= Dst Port Undefined Hit; 'dst_tcp_action_on_ack_timeout'=
          TCP Auth= ACK Retry Timeout; 'dst_tcp_action_on_ack_reset'= TCP Auth= ACK Retry
          Timeout Reset; 'dst_tcp_action_on_ack_blacklist'= TCP Auth= ACK Retry Timeout
          Blacklisted; 'src_tcp_action_on_ack_timeout'= Src TCP Auth= ACK Retry Timeout;
          'src_tcp_action_on_ack_reset'= Src TCP Auth= ACK Retry Timeout Reset;
          'src_tcp_action_on_ack_blacklist'= Src TCP Auth= ACK Retry Timeout Blacklisted;
          'dst_tcp_action_on_syn_timeout'= TCP Auth= SYN Retry Timeout;
          'dst_tcp_action_on_syn_reset'= TCP Auth= SYN Retry Timeout Reset;
          'dst_tcp_action_on_syn_blacklist'= TCP Auth= SYN Retry Timeout Blacklisted;
          'src_tcp_action_on_syn_timeout'= Src TCP Auth= SYN Retry Timeout;
          'src_tcp_action_on_syn_reset'= Src TCP Auth= SYN Retry Timeout Reset;
          'src_tcp_action_on_syn_blacklist'= Src TCP Auth= SYN Retry Timeout Blacklisted;
          'dst_udp_frag_pkt_rate_exceed'= UDP Dst L4-Type Rate= Frag Exceeded;
          'dst_udp_frag_src_rate_drop'= UDP Src Rate= Frag Exceeded;
          'dst_tcp_frag_pkt_rate_exceed'= TCP Dst L4-Type Rate= Frag Exceeded;
          'dst_tcp_frag_src_rate_drop'= TCP Src Rate= Frag Exceeded;
          'dst_icmp_frag_pkt_rate_exceed'= ICMP Dst L4-Type Rate= Frag Exceeded;
          'dst_icmp_frag_src_rate_drop'= ICMP Src Rate= Frag Exceeded;
          'sflow_internal_samples_packed'= Sflow Internal Samples Packed;
          'sflow_external_samples_packed'= Sflow External Samples Packed;
          'sflow_internal_packets_sent'= Sflow Internal Packets Sent;
          'sflow_external_packets_sent'= Sflow External Packets Sent;
          'dns_outbound_total_query'= DNS Outbound Total Query;
          'dns_outbound_query_malformed'= DNS Outbound Query Malformed;
          'dns_outbound_query_resp_chk_failed'= DNS Outbound Query Resp Check Failed;
          'dns_outbound_query_resp_chk_blacklisted'= DNS Outbound Query Resp Check
          Blacklisted; 'dns_outbound_query_resp_chk_refused_sent'= DNS Outbound Query
          Resp Check REFUSED Sent; 'dns_outbound_query_resp_chk_reset_sent'= DNS Outbound
          Query Resp Check RESET Sent; 'dns_outbound_query_resp_chk_no_resp_sent'= DNS
          Outbound Query Resp Check No Response Sent;
          'dns_outbound_query_resp_size_exceed'= DNS Outbound Query Response Size Exceed;
          'dns_outbound_query_sess_timed_out'= DNS Outbound Query Session Timed Out;
          'dst_exceed_action_tunnel'= Entry Exceed Action= Tunnel;
          'src_udp_auth_timeout'= Src UDP Auth= Retry Timeout; 'src_udp_retry_pass'= Src
          UDP Retry Passed;"
                type: str
            counters3:
                description:
                - "'dst_hw_drop_rule_insert'= Dst Hardware Drop Rules Inserted;
          'dst_hw_drop_rule_remove'= Dst Hardware Drop Rules Removed;
          'src_hw_drop_rule_insert'= Src Hardware Drop Rules Inserted;
          'src_hw_drop_rule_remove'= Src Hardware Drop Rules Removed;
          'prog_first_req_time_exceed'= Req-Resp= First Request Time Exceed;
          'prog_req_resp_time_exceed'= Req-Resp= Request to Response Time Exceed;
          'prog_request_len_exceed'= Req-Resp= Request Length Exceed;
          'prog_response_len_exceed'= Req-Resp= Response Length Exceed;
          'prog_resp_req_ratio_exceed'= Req-Resp= Response to Request Ratio Exceed;
          'prog_resp_req_time_exceed'= Req-Resp= Response to Request Time Exceed;
          'entry_sync_message_received'= Entry Sync Message Received;
          'entry_sync_message_sent'= Entry Sync Message Sent; 'prog_conn_sent_exceed'=
          Connection= Sent Exceed; 'prog_conn_rcvd_exceed'= Connection= Received Exceed;
          'prog_conn_time_exceed'= Connection= Time Exceed;
          'prog_conn_rcvd_sent_ratio_exceed'= Connection= Received to Sent Ratio Exceed;
          'prog_win_sent_exceed'= Time Window= Sent Exceed; 'prog_win_rcvd_exceed'= Time
          Window= Received Exceed; 'prog_win_rcvd_sent_ratio_exceed'= Time Window=
          Received to Sent Exceed; 'prog_exceed_drop'= Req-Resp= Violation Exceed
          Dropped; 'prog_exceed_bl'= Req-Resp= Violation Exceed Blacklisted;
          'prog_conn_exceed_drop'= Connection= Violation Exceed Dropped;
          'prog_conn_exceed_bl'= Connection= Violation Exceed Blacklisted;
          'prog_win_exceed_drop'= Time Window= Violation Exceed Dropped;
          'prog_win_exceed_bl'= Time Window= Violation Exceed Blacklisted;
          'dst_exceed_action_drop'= Entry Exceed Action= Dropped; 'prog_conn_samples'=
          Sample Collected= Connection; 'prog_req_samples'= Sample Collected= Req-Resp;
          'prog_win_samples'= Sample Collected= Time Window;"
                type: str
    capture_config_list:
        description:
        - "Field capture_config_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Capture-config name"
                type: str
            mode:
                description:
                - "'drop'= Apply capture-config to dropped packets; 'forward'= Apply capture-
          config to forwarded packets; 'all'= Apply capture-config to both dropped and
          forwarded packets;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    hw_blacklist_blocking:
        description:
        - "Field hw_blacklist_blocking"
        type: dict
        required: False
        suboptions:
            dst_enable:
                description:
                - "Enable Dst side hardware blocking"
                type: bool
            src_enable:
                description:
                - "Enable Src side hardware blocking"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    topk_destinations:
        description:
        - "Field topk_destinations"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    l4_type_list:
        description:
        - "Field l4_type_list"
        type: list
        required: False
        suboptions:
            protocol:
                description:
                - "'tcp'= L4-Type TCP; 'udp'= L4-Type UDP; 'icmp'= L4-Type ICMP; 'other'= L4-Type
          OTHER;"
                type: str
            glid:
                description:
                - "Global limit ID"
                type: str
            glid_exceed_action:
                description:
                - "Field glid_exceed_action"
                type: dict
            deny:
                description:
                - "Blacklist and Drop all incoming packets for protocol"
                type: bool
            max_rexmit_syn_per_flow:
                description:
                - "Maximum number of re-transmit SYN per flow"
                type: int
            max_rexmit_syn_per_flow_exceed_action:
                description:
                - "'drop'= Drop the packet; 'black-list'= Add the source IP into black list;"
                type: str
            disable_syn_auth:
                description:
                - "Disable TCP SYN Authentication"
                type: bool
            syn_auth:
                description:
                - "'send-rst'= Send RST to client upon client ACK; 'force-rst-by-ack'= Force
          client RST via the use of ACK; 'force-rst-by-synack'= Force client RST via the
          use of bad SYN|ACK; 'disable'= Disable TCP SYN Authentication;"
                type: str
            syn_cookie:
                description:
                - "Enable SYN Cookie"
                type: bool
            tcp_reset_client:
                description:
                - "Send reset to client when rate exceeds or session ages out"
                type: bool
            tcp_reset_server:
                description:
                - "Send reset to server when rate exceeds or session ages out"
                type: bool
            drop_on_no_port_match:
                description:
                - "'disable'= disable; 'enable'= enable;"
                type: str
            stateful:
                description:
                - "Enable stateful tracking of sessions (Default is stateless)"
                type: bool
            tunnel_decap:
                description:
                - "Field tunnel_decap"
                type: dict
            tunnel_rate_limit:
                description:
                - "Field tunnel_rate_limit"
                type: dict
            drop_frag_pkt:
                description:
                - "Drop fragmented packets"
                type: bool
            undefined_port_hit_statistics:
                description:
                - "Field undefined_port_hit_statistics"
                type: dict
            template:
                description:
                - "Field template"
                type: dict
            detection_enable:
                description:
                - "Enable ddos detection"
                type: bool
            enable_top_k:
                description:
                - "Enable ddos top-k entries"
                type: bool
            topk_num_records:
                description:
                - "Maximum number of records to show in topk"
                type: int
            set_counter_base_val:
                description:
                - "Set T2 counter value of current context to specified value"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            port_ind:
                description:
                - "Field port_ind"
                type: dict
            topk_sources:
                description:
                - "Field topk_sources"
                type: dict
            progression_tracking:
                description:
                - "Field progression_tracking"
                type: dict
    port_list:
        description:
        - "Field port_list"
        type: list
        required: False
        suboptions:
            port_num:
                description:
                - "Port Number"
                type: int
            protocol:
                description:
                - "'dns-tcp'= DNS-TCP Port; 'dns-udp'= DNS-UDP Port; 'http'= HTTP Port; 'tcp'= TCP
          Port; 'udp'= UDP Port; 'ssl-l4'= SSL-L4 Port; 'sip-udp'= SIP-UDP Port; 'sip-
          tcp'= SIP-TCP Port;"
                type: str
            detection_enable:
                description:
                - "Enable ddos detection"
                type: bool
            enable_top_k:
                description:
                - "Enable ddos top-k entries"
                type: bool
            topk_num_records:
                description:
                - "Maximum number of records to show in topk"
                type: int
            deny:
                description:
                - "Blacklist and Drop all incoming packets for protocol"
                type: bool
            glid:
                description:
                - "Global limit ID"
                type: str
            glid_exceed_action:
                description:
                - "Field glid_exceed_action"
                type: dict
            dns_cache:
                description:
                - "DNS Cache Instance"
                type: str
            template:
                description:
                - "Field template"
                type: dict
            sflow:
                description:
                - "Field sflow"
                type: dict
            capture_config:
                description:
                - "Field capture_config"
                type: dict
            set_counter_base_val:
                description:
                - "Set T2 counter value of current context to specified value"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            port_ind:
                description:
                - "Field port_ind"
                type: dict
            topk_sources:
                description:
                - "Field topk_sources"
                type: dict
            progression_tracking:
                description:
                - "Field progression_tracking"
                type: dict
            signature_extraction:
                description:
                - "Field signature_extraction"
                type: dict
            pattern_recognition:
                description:
                - "Field pattern_recognition"
                type: dict
            pattern_recognition_pu_details:
                description:
                - "Field pattern_recognition_pu_details"
                type: dict
    port_range_list:
        description:
        - "Field port_range_list"
        type: list
        required: False
        suboptions:
            port_range_start:
                description:
                - "Port-Range Start Port Number"
                type: int
            port_range_end:
                description:
                - "Port-Range End Port Number"
                type: int
            protocol:
                description:
                - "'dns-tcp'= DNS-TCP Port; 'dns-udp'= DNS-UDP Port; 'http'= HTTP Port; 'tcp'= TCP
          Port; 'udp'= UDP Port; 'ssl-l4'= SSL-L4 Port; 'sip-udp'= SIP-UDP Port; 'sip-
          tcp'= SIP-TCP Port;"
                type: str
            deny:
                description:
                - "Blacklist and Drop all incoming packets for protocol"
                type: bool
            detection_enable:
                description:
                - "Enable ddos detection"
                type: bool
            enable_top_k:
                description:
                - "Enable ddos top-k entries"
                type: bool
            topk_num_records:
                description:
                - "Maximum number of records to show in topk"
                type: int
            glid:
                description:
                - "Global limit ID"
                type: str
            glid_exceed_action:
                description:
                - "Field glid_exceed_action"
                type: dict
            template:
                description:
                - "Field template"
                type: dict
            sflow:
                description:
                - "Field sflow"
                type: dict
            capture_config:
                description:
                - "Field capture_config"
                type: dict
            set_counter_base_val:
                description:
                - "Set T2 counter value of current context to specified value"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            port_ind:
                description:
                - "Field port_ind"
                type: dict
            topk_sources:
                description:
                - "Field topk_sources"
                type: dict
            progression_tracking:
                description:
                - "Field progression_tracking"
                type: dict
            pattern_recognition:
                description:
                - "Field pattern_recognition"
                type: dict
            pattern_recognition_pu_details:
                description:
                - "Field pattern_recognition_pu_details"
                type: dict
    src_port_list:
        description:
        - "Field src_port_list"
        type: list
        required: False
        suboptions:
            port_num:
                description:
                - "Port Number"
                type: int
            protocol:
                description:
                - "'dns-udp'= DNS-UDP Port; 'dns-tcp'= DNS-TCP Port; 'udp'= UDP Port; 'tcp'= TCP
          Port;"
                type: str
            deny:
                description:
                - "Blacklist and Drop all incoming packets for protocol"
                type: bool
            glid:
                description:
                - "Global limit ID"
                type: str
            outbound_src_tracking:
                description:
                - "'enable'= enable; 'disable'= disable;"
                type: str
            template:
                description:
                - "Field template"
                type: dict
            set_counter_base_val:
                description:
                - "Set T2 counter value of current context to specified value"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    src_port_range_list:
        description:
        - "Field src_port_range_list"
        type: list
        required: False
        suboptions:
            src_port_range_start:
                description:
                - "Src Port-Range Start Port Number"
                type: int
            src_port_range_end:
                description:
                - "Src Port-Range End Port Number"
                type: int
            protocol:
                description:
                - "'udp'= UDP Port; 'tcp'= TCP Port;"
                type: str
            deny:
                description:
                - "Blacklist and Drop all incoming packets for protocol"
                type: bool
            glid:
                description:
                - "Global limit ID"
                type: str
            template:
                description:
                - "Field template"
                type: dict
            set_counter_base_val:
                description:
                - "Set T2 counter value of current context to specified value"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    ip_proto_list:
        description:
        - "Field ip_proto_list"
        type: list
        required: False
        suboptions:
            port_num:
                description:
                - "Protocol Number"
                type: int
            deny:
                description:
                - "Blacklist and Drop all incoming packets for protocol"
                type: bool
            esp_inspect:
                description:
                - "Field esp_inspect"
                type: dict
            glid:
                description:
                - "Global limit ID"
                type: str
            glid_exceed_action:
                description:
                - "Field glid_exceed_action"
                type: dict
            template:
                description:
                - "Field template"
                type: dict
            set_counter_base_val:
                description:
                - "Set T2 counter value of current context to specified value"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    src_dst_pair:
        description:
        - "Field src_dst_pair"
        type: dict
        required: False
        suboptions:
            default:
                description:
                - "Configure default"
                type: bool
            bypass:
                description:
                - "Always permit for the Source to bypass all feature & limit checks"
                type: bool
            exceed_log_cfg:
                description:
                - "Field exceed_log_cfg"
                type: dict
            log_periodic:
                description:
                - "Enable periodic log while event is continuing"
                type: bool
            template:
                description:
                - "Field template"
                type: dict
            glid:
                description:
                - "Global limit ID"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            l4_type_src_dst_list:
                description:
                - "Field l4_type_src_dst_list"
                type: list
            app_type_src_dst_list:
                description:
                - "Field app_type_src_dst_list"
                type: list
    src_dst_pair_policy_list:
        description:
        - "Field src_dst_pair_policy_list"
        type: list
        required: False
        suboptions:
            src_based_policy_name:
                description:
                - "Src-based-policy name"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            policy_class_list_list:
                description:
                - "Field policy_class_list_list"
                type: list
    src_dst_pair_settings_list:
        description:
        - "Field src_dst_pair_settings_list"
        type: list
        required: False
        suboptions:
            all_types:
                description:
                - "'all-types'= Settings for all types (default or class-list);"
                type: str
            age:
                description:
                - "Idle age for ip entry"
                type: int
            max_dynamic_entry_count:
                description:
                - "Maximum count for dynamic src-dst entry"
                type: int
            apply_policy_on_overflow:
                description:
                - "Enable this flag to apply overflow policy when dynamic entry count overflows"
                type: bool
            unlimited_dynamic_entry_count:
                description:
                - "No limit for maximum dynamic src entry count"
                type: bool
            enable_class_list_overflow:
                description:
                - "Apply class-list overflow policy upon exceeding dynamic entry count specified
          for DST entry or each class-list"
                type: bool
            src_prefix_len:
                description:
                - "Specify src prefix length for IPv6 (default= not set)"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            l4_type_src_dst_list:
                description:
                - "Field l4_type_src_dst_list"
                type: list
    src_dst_pair_class_list_list:
        description:
        - "Field src_dst_pair_class_list_list"
        type: list
        required: False
        suboptions:
            class_list_name:
                description:
                - "Class-list name"
                type: str
            exceed_log_cfg:
                description:
                - "Field exceed_log_cfg"
                type: dict
            log_periodic:
                description:
                - "Enable periodic log while event is continuing"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            l4_type_src_dst_list:
                description:
                - "Field l4_type_src_dst_list"
                type: list
            app_type_src_dst_list:
                description:
                - "Field app_type_src_dst_list"
                type: list
            cid_list:
                description:
                - "Field cid_list"
                type: list
    dynamic_entry_overflow_policy_list:
        description:
        - "Field dynamic_entry_overflow_policy_list"
        type: list
        required: False
        suboptions:
            dummy_name:
                description:
                - "'configuration'= Configure src dst dynamic entry count overflow policy;"
                type: str
            bypass:
                description:
                - "Always permit for the Source to bypass all feature & limit checks"
                type: bool
            exceed_log_cfg:
                description:
                - "Field exceed_log_cfg"
                type: dict
            log_periodic:
                description:
                - "Enable periodic log while event is continuing"
                type: bool
            template:
                description:
                - "Field template"
                type: dict
            glid:
                description:
                - "Global limit ID"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            l4_type_src_dst_list:
                description:
                - "Field l4_type_src_dst_list"
                type: list
            app_type_src_dst_list:
                description:
                - "Field app_type_src_dst_list"
                type: list
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            ddos_entry_list:
                description:
                - "Field ddos_entry_list"
                type: list
            entry_address_str:
                description:
                - "Field entry_address_str"
                type: str
            total_dynamic_entry_count:
                description:
                - "Field total_dynamic_entry_count"
                type: str
            total_dynamic_entry_limit:
                description:
                - "Field total_dynamic_entry_limit"
                type: str
            udp_dynamic_entry_count:
                description:
                - "Field udp_dynamic_entry_count"
                type: str
            udp_dynamic_entry_limit:
                description:
                - "Field udp_dynamic_entry_limit"
                type: str
            tcp_dynamic_entry_count:
                description:
                - "Field tcp_dynamic_entry_count"
                type: str
            tcp_dynamic_entry_limit:
                description:
                - "Field tcp_dynamic_entry_limit"
                type: str
            icmp_dynamic_entry_count:
                description:
                - "Field icmp_dynamic_entry_count"
                type: str
            icmp_dynamic_entry_limit:
                description:
                - "Field icmp_dynamic_entry_limit"
                type: str
            other_dynamic_entry_count:
                description:
                - "Field other_dynamic_entry_count"
                type: str
            other_dynamic_entry_limit:
                description:
                - "Field other_dynamic_entry_limit"
                type: str
            operational_mode:
                description:
                - "Field operational_mode"
                type: str
            traffic_distribution_status:
                description:
                - "Field traffic_distribution_status"
                type: list
            dst_entry_name:
                description:
                - "Field dst_entry_name"
                type: str
            source_entry_limit:
                description:
                - "Field source_entry_limit"
                type: str
            source_entry_alloc:
                description:
                - "Field source_entry_alloc"
                type: str
            source_entry_remain:
                description:
                - "Field source_entry_remain"
                type: str
            dst_service_limit:
                description:
                - "Field dst_service_limit"
                type: str
            dst_service_alloc:
                description:
                - "Field dst_service_alloc"
                type: str
            dst_service_remain:
                description:
                - "Field dst_service_remain"
                type: str
            entry_displayed_count:
                description:
                - "Field entry_displayed_count"
                type: int
            service_displayed_count:
                description:
                - "Field service_displayed_count"
                type: int
            no_t2_idx_port_count:
                description:
                - "Field no_t2_idx_port_count"
                type: int
            dst_all_entries:
                description:
                - "Field dst_all_entries"
                type: bool
            sources:
                description:
                - "Field sources"
                type: bool
            sources_all_entries:
                description:
                - "Field sources_all_entries"
                type: bool
            overflow_policy:
                description:
                - "Field overflow_policy"
                type: bool
            entry_count:
                description:
                - "Field entry_count"
                type: bool
            sflow_source_id:
                description:
                - "Field sflow_source_id"
                type: bool
            ipv6:
                description:
                - "Field ipv6"
                type: str
            subnet_ip_addr:
                description:
                - "Field subnet_ip_addr"
                type: str
            subnet_ipv6_addr:
                description:
                - "Field subnet_ipv6_addr"
                type: str
            l4_type_str:
                description:
                - "Field l4_type_str"
                type: str
            app_type:
                description:
                - "Field app_type"
                type: str
            exceeded:
                description:
                - "Field exceeded"
                type: bool
            black_listed:
                description:
                - "Field black_listed"
                type: bool
            white_listed:
                description:
                - "Field white_listed"
                type: bool
            authenticated:
                description:
                - "Field authenticated"
                type: bool
            class_list:
                description:
                - "Field class_list"
                type: str
            ip_proto_num:
                description:
                - "Field ip_proto_num"
                type: int
            port_num:
                description:
                - "Field port_num"
                type: int
            port_range_start:
                description:
                - "Field port_range_start"
                type: int
            port_range_end:
                description:
                - "Field port_range_end"
                type: int
            src_port_num:
                description:
                - "Field src_port_num"
                type: int
            src_port_range_start:
                description:
                - "Field src_port_range_start"
                type: int
            src_port_range_end:
                description:
                - "Field src_port_range_end"
                type: int
            protocol:
                description:
                - "Field protocol"
                type: str
            opt_protocol:
                description:
                - "Field opt_protocol"
                type: str
            sport_protocol:
                description:
                - "Field sport_protocol"
                type: str
            opt_sport_protocol:
                description:
                - "Field opt_sport_protocol"
                type: str
            app_stat:
                description:
                - "Field app_stat"
                type: bool
            port_app_stat:
                description:
                - "Field port_app_stat"
                type: bool
            all_ip_protos:
                description:
                - "Field all_ip_protos"
                type: bool
            all_l4_types:
                description:
                - "Field all_l4_types"
                type: bool
            all_ports:
                description:
                - "Field all_ports"
                type: bool
            all_src_ports:
                description:
                - "Field all_src_ports"
                type: bool
            black_holed:
                description:
                - "Field black_holed"
                type: bool
            resource_usage:
                description:
                - "Field resource_usage"
                type: bool
            display_traffic_distribution_status:
                description:
                - "Field display_traffic_distribution_status"
                type: bool
            entry_status:
                description:
                - "Field entry_status"
                type: bool
            l4_ext_rate:
                description:
                - "Field l4_ext_rate"
                type: bool
            hw_blacklisted:
                description:
                - "Field hw_blacklisted"
                type: str
            topk_destinations:
                description:
                - "Field topk_destinations"
                type: dict
            l4_type_list:
                description:
                - "Field l4_type_list"
                type: list
            port_list:
                description:
                - "Field port_list"
                type: list
            port_range_list:
                description:
                - "Field port_range_list"
                type: list
            src_port_list:
                description:
                - "Field src_port_list"
                type: list
            src_port_range_list:
                description:
                - "Field src_port_range_list"
                type: list
            ip_proto_list:
                description:
                - "Field ip_proto_list"
                type: list
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            dst_tcp_any_exceed:
                description:
                - "TCP Dst L4-Type Rate= Total Exceeded"
                type: str
            dst_tcp_pkt_rate_exceed:
                description:
                - "TCP Dst L4-Type Rate= Packet Exceeded"
                type: str
            dst_tcp_conn_rate_exceed:
                description:
                - "TCP Dst L4-Type Rate= Conn Exceeded"
                type: str
            dst_udp_any_exceed:
                description:
                - "UDP Dst L4-Type Rate= Total Exceeded"
                type: str
            dst_udp_pkt_rate_exceed:
                description:
                - "UDP Dst L4-Type Rate= Packet Exceeded"
                type: str
            dst_udp_conn_limit_exceed:
                description:
                - "UDP Dst L4-Type Limit= Conn Exceeded"
                type: str
            dst_udp_conn_rate_exceed:
                description:
                - "UDP Dst L4-Type Rate= Conn Exceeded"
                type: str
            dst_icmp_pkt_rate_exceed:
                description:
                - "ICMP Dst Rate= Packet Exceeded"
                type: str
            dst_other_pkt_rate_exceed:
                description:
                - "OTHER Dst L4-Type Rate= Packet Exceeded"
                type: str
            dst_other_frag_pkt_rate_exceed:
                description:
                - "OTHER Dst L4-Type Rate= Frag Exceeded"
                type: str
            dst_port_pkt_rate_exceed:
                description:
                - "Port Rate= Packet Exceeded"
                type: str
            dst_port_conn_limit_exceed:
                description:
                - "Port Limit= Conn Exceeded"
                type: str
            dst_port_conn_rate_exceed:
                description:
                - "Port Rate= Conn Exceeded"
                type: str
            dst_pkt_sent:
                description:
                - "Inbound= Packets Forwarded"
                type: str
            dst_udp_pkt_sent:
                description:
                - "UDP Total Packets Forwarded"
                type: str
            dst_tcp_pkt_sent:
                description:
                - "TCP Total Packets Forwarded"
                type: str
            dst_icmp_pkt_sent:
                description:
                - "ICMP Total Packets Forwarded"
                type: str
            dst_other_pkt_sent:
                description:
                - "OTHER Total Packets Forwarded"
                type: str
            dst_tcp_conn_limit_exceed:
                description:
                - "TCP Dst L4-Type Limit= Conn Exceeded"
                type: str
            dst_tcp_pkt_rcvd:
                description:
                - "TCP Total Packets Received"
                type: str
            dst_udp_pkt_rcvd:
                description:
                - "UDP Total Packets Received"
                type: str
            dst_icmp_pkt_rcvd:
                description:
                - "ICMP Total Packets Received"
                type: str
            dst_other_pkt_rcvd:
                description:
                - "OTHER Total Packets Received"
                type: str
            dst_udp_filter_match:
                description:
                - "UDP Filter Match"
                type: str
            dst_udp_filter_not_match:
                description:
                - "UDP Filter Not Matched on Pkt"
                type: str
            dst_udp_filter_action_blacklist:
                description:
                - "UDP Filter Action Blacklist"
                type: str
            dst_udp_filter_action_drop:
                description:
                - "UDP Filter Action Drop"
                type: str
            dst_tcp_syn:
                description:
                - "TCP Total SYN Received"
                type: str
            dst_tcp_syn_drop:
                description:
                - "TCP SYN Packets Dropped"
                type: str
            dst_tcp_src_rate_drop:
                description:
                - "TCP Src Rate= Total Exceeded"
                type: str
            dst_udp_src_rate_drop:
                description:
                - "UDP Src Rate= Total Exceeded"
                type: str
            dst_icmp_src_rate_drop:
                description:
                - "ICMP Src Rate= Total Exceeded"
                type: str
            dst_other_frag_src_rate_drop:
                description:
                - "OTHER Src Rate= Frag Exceeded"
                type: str
            dst_other_src_rate_drop:
                description:
                - "OTHER Src Rate= Total Exceeded"
                type: str
            dst_tcp_drop:
                description:
                - "TCP Total Packets Dropped"
                type: str
            dst_udp_drop:
                description:
                - "UDP Total Packets Dropped"
                type: str
            dst_icmp_drop:
                description:
                - "ICMP Total Packets Dropped"
                type: str
            dst_frag_drop:
                description:
                - "Fragmented Packets Dropped"
                type: str
            dst_other_drop:
                description:
                - "OTHER Total Packets Dropped"
                type: str
            dst_tcp_auth:
                description:
                - "TCP Auth= SYN Cookie Sent"
                type: str
            dst_udp_filter_action_default_pass:
                description:
                - "UDP Filter Action Default Pass"
                type: str
            dst_tcp_filter_match:
                description:
                - "TCP Filter Match"
                type: str
            dst_tcp_filter_not_match:
                description:
                - "TCP Filter Not Matched on Pkt"
                type: str
            dst_tcp_filter_action_blacklist:
                description:
                - "TCP Filter Action Blacklist"
                type: str
            dst_tcp_filter_action_drop:
                description:
                - "TCP Filter Action Drop"
                type: str
            dst_tcp_filter_action_default_pass:
                description:
                - "TCP Filter Action Default Pass"
                type: str
            dst_udp_filter_action_whitelist:
                description:
                - "UDP Filter Action WL"
                type: str
            dst_udp_kibit_rate_drop:
                description:
                - "UDP Dst L4-Type Rate= KiBit Exceeded"
                type: str
            dst_tcp_kibit_rate_drop:
                description:
                - "TCP Dst L4-Type Rate= KiBit Exceeded"
                type: str
            dst_icmp_kibit_rate_drop:
                description:
                - "ICMP Dst Rate= KiBit Exceeded"
                type: str
            dst_other_kibit_rate_drop:
                description:
                - "OTHER Dst L4-Type Rate= KiBit Exceeded"
                type: str
            dst_port_undef_drop:
                description:
                - "Dst Port Undefined Dropped"
                type: str
            dst_port_bl:
                description:
                - "Dst Port Blacklist Packets Dropped"
                type: str
            dst_src_port_bl:
                description:
                - "Dst SrcPort Blacklist Packets Dropped"
                type: str
            dst_port_kbit_rate_exceed:
                description:
                - "Port Rate= KiBit Exceeded"
                type: str
            dst_tcp_src_drop:
                description:
                - "TCP Src Packets Dropped"
                type: str
            dst_udp_src_drop:
                description:
                - "UDP Src Packets Dropped"
                type: str
            dst_icmp_src_drop:
                description:
                - "ICMP Src Packets Dropped"
                type: str
            dst_other_src_drop:
                description:
                - "OTHER Src Packets Dropped"
                type: str
            tcp_syn_rcvd:
                description:
                - "TCP Inbound SYN Received"
                type: str
            tcp_syn_ack_rcvd:
                description:
                - "TCP SYN ACK Received"
                type: str
            tcp_ack_rcvd:
                description:
                - "TCP ACK Received"
                type: str
            tcp_fin_rcvd:
                description:
                - "TCP FIN Received"
                type: str
            tcp_rst_rcvd:
                description:
                - "TCP RST Received"
                type: str
            ingress_bytes:
                description:
                - "Inbound= Bytes Received"
                type: str
            egress_bytes:
                description:
                - "Outbound= Bytes Received"
                type: str
            ingress_packets:
                description:
                - "Inbound= Packets Received"
                type: str
            egress_packets:
                description:
                - "Outbound= Packets Received"
                type: str
            tcp_fwd_recv:
                description:
                - "TCP Inbound Packets Received"
                type: str
            udp_fwd_recv:
                description:
                - "UDP Inbound Packets Received"
                type: str
            icmp_fwd_recv:
                description:
                - "ICMP Inbound Packets Received"
                type: str
            tcp_syn_cookie_fail:
                description:
                - "TCP Auth= SYN Cookie Failed"
                type: str
            dst_tcp_session_created:
                description:
                - "TCP Sessions Created"
                type: str
            dst_udp_session_created:
                description:
                - "UDP Sessions Created"
                type: str
            dst_tcp_filter_action_whitelist:
                description:
                - "TCP Filter Action WL"
                type: str
            dst_other_filter_match:
                description:
                - "OTHER Filter Match"
                type: str
            dst_other_filter_not_match:
                description:
                - "OTHER Filter Not Matched on Pkt"
                type: str
            dst_other_filter_action_blacklist:
                description:
                - "OTHER Filter Action Blacklist"
                type: str
            dst_other_filter_action_drop:
                description:
                - "OTHER Filter Action Drop"
                type: str
            dst_other_filter_action_whitelist:
                description:
                - "OTHER Filter Action WL"
                type: str
            dst_other_filter_action_default_pass:
                description:
                - "OTHER Filter Action Default Pass"
                type: str
            dst_blackhole_inject:
                description:
                - "Dst Blackhole Inject"
                type: str
            dst_blackhole_withdraw:
                description:
                - "Dst Blackhole Withdraw"
                type: str
            dst_tcp_out_of_seq_excd:
                description:
                - "TCP Out-Of-Seq Exceeded"
                type: str
            dst_tcp_retransmit_excd:
                description:
                - "TCP Retransmit Exceeded"
                type: str
            dst_tcp_zero_window_excd:
                description:
                - "TCP Zero-Window Exceeded"
                type: str
            dst_tcp_conn_prate_excd:
                description:
                - "TCP Rate= Conn Pkt Exceeded"
                type: str
            dst_tcp_action_on_ack_init:
                description:
                - "TCP Auth= ACK Retry Init"
                type: str
            dst_tcp_action_on_ack_gap_drop:
                description:
                - "TCP Auth= ACK Retry Retry-Gap Dropped"
                type: str
            dst_tcp_action_on_ack_fail:
                description:
                - "TCP Auth= ACK Retry Dropped"
                type: str
            dst_tcp_action_on_ack_pass:
                description:
                - "TCP Auth= ACK Retry Passed"
                type: str
            dst_tcp_action_on_syn_init:
                description:
                - "TCP Auth= SYN Retry Init"
                type: str
            dst_tcp_action_on_syn_gap_drop:
                description:
                - "TCP Auth= SYN Retry-Gap Dropped"
                type: str
            dst_tcp_action_on_syn_fail:
                description:
                - "TCP Auth= SYN Retry Dropped"
                type: str
            dst_tcp_action_on_syn_pass:
                description:
                - "TCP Auth= SYN Retry Passed"
                type: str
            udp_payload_too_small:
                description:
                - "UDP Payload Too Small"
                type: str
            udp_payload_too_big:
                description:
                - "UDP Payload Too Large"
                type: str
            dst_udp_conn_prate_excd:
                description:
                - "UDP Rate= Conn Pkt Exceeded"
                type: str
            dst_udp_ntp_monlist_req:
                description:
                - "UDP NTP Monlist Request"
                type: str
            dst_udp_ntp_monlist_resp:
                description:
                - "UDP NTP Monlist Response"
                type: str
            dst_udp_wellknown_sport_drop:
                description:
                - "UDP SrcPort Wellknown"
                type: str
            dst_udp_retry_init:
                description:
                - "UDP Auth= Retry Init"
                type: str
            dst_udp_retry_pass:
                description:
                - "UDP Auth= Retry Passed"
                type: str
            dst_tcp_bytes_drop:
                description:
                - "TCP Total Bytes Dropped"
                type: str
            dst_udp_bytes_drop:
                description:
                - "UDP Total Bytes Dropped"
                type: str
            dst_icmp_bytes_drop:
                description:
                - "ICMP Total Bytes Dropped"
                type: str
            dst_other_bytes_drop:
                description:
                - "OTHER Total Bytes Dropped"
                type: str
            dst_out_no_route:
                description:
                - "Dst IPv4/v6 Out No Route"
                type: str
            outbound_bytes_sent:
                description:
                - "Outbound= Bytes Forwarded"
                type: str
            outbound_pkt_drop:
                description:
                - "Outbound= Packets Dropped"
                type: str
            outbound_bytes_drop:
                description:
                - "Outbound= Bytes Dropped"
                type: str
            outbound_pkt_sent:
                description:
                - "Outbound= Packets Forwarded"
                type: str
            inbound_bytes_sent:
                description:
                - "Inbound= Bytes Forwarded"
                type: str
            inbound_bytes_drop:
                description:
                - "Inbound= Bytes Dropped"
                type: str
            dst_src_port_pkt_rate_exceed:
                description:
                - "SrcPort Rate= Packet Exceeded"
                type: str
            dst_src_port_kbit_rate_exceed:
                description:
                - "SrcPort Rate= KiBit Exceeded"
                type: str
            dst_src_port_conn_limit_exceed:
                description:
                - "SrcPort Limit= Conn Exceeded"
                type: str
            dst_src_port_conn_rate_exceed:
                description:
                - "SrcPort Rate= Conn Exceeded"
                type: str
            dst_ip_proto_pkt_rate_exceed:
                description:
                - "IP-Proto Rate= Packet Exceeded"
                type: str
            dst_ip_proto_kbit_rate_exceed:
                description:
                - "IP-Proto Rate= KiBit Exceeded"
                type: str
            dst_tcp_port_any_exceed:
                description:
                - "TCP Port Rate= Total Exceed"
                type: str
            dst_udp_port_any_exceed:
                description:
                - "UDP Port Rate= Total Exceed"
                type: str
            dst_tcp_auth_pass:
                description:
                - "TCP Auth= SYN Auth Passed"
                type: str
            dst_tcp_rst_cookie_fail:
                description:
                - "TCP Auth= RST Cookie Failed"
                type: str
            dst_tcp_unauth_drop:
                description:
                - "TCP Auth= Unauth Dropped"
                type: str
            src_tcp_syn_auth_fail:
                description:
                - "Src TCP Auth= SYN Auth Failed"
                type: str
            src_tcp_syn_cookie_sent:
                description:
                - "Src TCP Auth= SYN Cookie Sent"
                type: str
            src_tcp_syn_cookie_fail:
                description:
                - "Src TCP Auth= SYN Cookie Failed"
                type: str
            src_tcp_rst_cookie_fail:
                description:
                - "Src TCP Auth= RST Cookie Failed"
                type: str
            src_tcp_unauth_drop:
                description:
                - "Src TCP Auth= Unauth Dropped"
                type: str
            src_tcp_action_on_syn_init:
                description:
                - "Src TCP Auth= SYN Retry Init"
                type: str
            src_tcp_action_on_syn_gap_drop:
                description:
                - "Src TCP Auth= SYN Retry-Gap Dropped"
                type: str
            src_tcp_action_on_syn_fail:
                description:
                - "Src TCP Auth= SYN Retry Dropped"
                type: str
            src_tcp_action_on_ack_init:
                description:
                - "Src TCP Auth= ACK Retry Init"
                type: str
            src_tcp_action_on_ack_gap_drop:
                description:
                - "Src TCP Auth= ACK Retry Retry-Gap Dropped"
                type: str
            src_tcp_action_on_ack_fail:
                description:
                - "Src TCP Auth= ACK Retry Dropped"
                type: str
            src_tcp_out_of_seq_excd:
                description:
                - "Src TCP Out-Of-Seq Exceeded"
                type: str
            src_tcp_retransmit_excd:
                description:
                - "Src TCP Retransmit Exceeded"
                type: str
            src_tcp_zero_window_excd:
                description:
                - "Src TCP Zero-Window Exceeded"
                type: str
            src_tcp_conn_prate_excd:
                description:
                - "Src TCP Rate= Conn Pkt Exceeded"
                type: str
            src_udp_min_payload:
                description:
                - "Src UDP Payload Too Small"
                type: str
            src_udp_max_payload:
                description:
                - "Src UDP Payload Too Large"
                type: str
            src_udp_conn_prate_excd:
                description:
                - "Src UDP Rate= Conn Pkt Exceeded"
                type: str
            src_udp_ntp_monlist_req:
                description:
                - "Src UDP NTP Monlist Request"
                type: str
            src_udp_ntp_monlist_resp:
                description:
                - "Src UDP NTP Monlist Response"
                type: str
            src_udp_wellknown_sport_drop:
                description:
                - "Src UDP SrcPort Wellknown"
                type: str
            src_udp_retry_init:
                description:
                - "Src UDP Auth= Retry Init"
                type: str
            dst_udp_retry_gap_drop:
                description:
                - "UDP Auth= Retry-Gap Dropped"
                type: str
            dst_udp_retry_fail:
                description:
                - "UDP Auth= Retry Timeout"
                type: str
            dst_tcp_session_aged:
                description:
                - "TCP Sessions Aged"
                type: str
            dst_udp_session_aged:
                description:
                - "UDP Sessions Aged"
                type: str
            dst_tcp_conn_close:
                description:
                - "TCP Connections Closed"
                type: str
            dst_tcp_conn_close_half_open:
                description:
                - "TCP Half Open Connections Closed"
                type: str
            dst_l4_tcp_auth:
                description:
                - "TCP Dst L4-Type Auth= SYN Cookie Sent"
                type: str
            tcp_l4_syn_cookie_fail:
                description:
                - "TCP Dst L4-Type Auth= SYN Cookie Failed"
                type: str
            tcp_l4_rst_cookie_fail:
                description:
                - "TCP Dst L4-Type Auth= RST Cookie Failed"
                type: str
            tcp_l4_unauth_drop:
                description:
                - "TCP Dst L4-Type Auth= Unauth Dropped"
                type: str
            src_tcp_filter_action_blacklist:
                description:
                - "Src TCP Filter Action Blacklist"
                type: str
            src_tcp_filter_action_whitelist:
                description:
                - "Src TCP Filter Action WL"
                type: str
            src_tcp_filter_action_drop:
                description:
                - "Src TCP Filter Action Drop"
                type: str
            src_tcp_filter_action_default_pass:
                description:
                - "Src TCP Filter Action Default Pass"
                type: str
            src_udp_filter_action_blacklist:
                description:
                - "Src UDP Filter Action Blacklist"
                type: str
            src_udp_filter_action_whitelist:
                description:
                - "Src UDP Filter Action WL"
                type: str
            src_udp_filter_action_drop:
                description:
                - "Src UDP Filter Action Drop"
                type: str
            src_udp_filter_action_default_pass:
                description:
                - "Src UDP Filter Action Default Pass"
                type: str
            src_other_filter_action_blacklist:
                description:
                - "Src OTHER Filter Action Blacklist"
                type: str
            src_other_filter_action_whitelist:
                description:
                - "Src OTHER Filter Action WL"
                type: str
            src_other_filter_action_drop:
                description:
                - "Src OTHER Filter Action Drop"
                type: str
            src_other_filter_action_default_pass:
                description:
                - "Src OTHER Filter Action Default Pass"
                type: str
            tcp_invalid_syn:
                description:
                - "TCP Invalid SYN Received"
                type: str
            dst_tcp_conn_close_w_rst:
                description:
                - "TCP RST Connections Closed"
                type: str
            dst_tcp_conn_close_w_fin:
                description:
                - "TCP FIN Connections Closed"
                type: str
            dst_tcp_conn_close_w_idle:
                description:
                - "TCP Idle Connections Closed"
                type: str
            dst_tcp_conn_create_from_syn:
                description:
                - "TCP Connections Created From SYN"
                type: str
            dst_tcp_conn_create_from_ack:
                description:
                - "TCP Connections Created From ACK"
                type: str
            src_frag_drop:
                description:
                - "Src Fragmented Packets Dropped"
                type: str
            dst_l4_tcp_blacklist_drop:
                description:
                - "Dst L4-type TCP Blacklist Dropped"
                type: str
            dst_l4_udp_blacklist_drop:
                description:
                - "Dst L4-type UDP Blacklist Dropped"
                type: str
            dst_l4_icmp_blacklist_drop:
                description:
                - "Dst L4-type ICMP Blacklist Dropped"
                type: str
            dst_l4_other_blacklist_drop:
                description:
                - "Dst L4-type OTHER Blacklist Dropped"
                type: str
            src_l4_tcp_blacklist_drop:
                description:
                - "Src L4-type TCP Blacklist Dropped"
                type: str
            src_l4_udp_blacklist_drop:
                description:
                - "Src L4-type UDP Blacklist Dropped"
                type: str
            src_l4_icmp_blacklist_drop:
                description:
                - "Src L4-type ICMP Blacklist Dropped"
                type: str
            src_l4_other_blacklist_drop:
                description:
                - "Src L4-type OTHER Blacklist Dropped"
                type: str
            dst_port_kbit_rate_exceed_pkt:
                description:
                - "Port Rate= KiBit Pkt Exceeded"
                type: str
            dst_tcp_bytes_rcv:
                description:
                - "TCP Total Bytes Received"
                type: str
            dst_udp_bytes_rcv:
                description:
                - "UDP Total Bytes Received"
                type: str
            dst_icmp_bytes_rcv:
                description:
                - "ICMP Total Bytes Received"
                type: str
            dst_other_bytes_rcv:
                description:
                - "OTHER Total Bytes Received"
                type: str
            dst_tcp_bytes_sent:
                description:
                - "TCP Total Bytes Forwarded"
                type: str
            dst_udp_bytes_sent:
                description:
                - "UDP Total Bytes Forwarded"
                type: str
            dst_icmp_bytes_sent:
                description:
                - "ICMP Total Bytes Forwarded"
                type: str
            dst_other_bytes_sent:
                description:
                - "OTHER Total Bytes Forwarded"
                type: str
            dst_udp_auth_drop:
                description:
                - "UDP Auth= Dropped"
                type: str
            dst_tcp_auth_drop:
                description:
                - "TCP Auth= Dropped"
                type: str
            dst_tcp_auth_resp:
                description:
                - "TCP Auth= Responded"
                type: str
            inbound_pkt_drop:
                description:
                - "Inbound= Packets Dropped"
                type: str
            dst_entry_pkt_rate_exceed:
                description:
                - "Entry Rate= Packet Exceeded"
                type: str
            dst_entry_kbit_rate_exceed:
                description:
                - "Entry Rate= KiBit Exceeded"
                type: str
            dst_entry_conn_limit_exceed:
                description:
                - "Entry Limit= Conn Exceeded"
                type: str
            dst_entry_conn_rate_exceed:
                description:
                - "Entry Rate= Conn Exceeded"
                type: str
            dst_entry_frag_pkt_rate_exceed:
                description:
                - "Entry Rate= Frag Packet Exceeded"
                type: str
            dst_icmp_any_exceed:
                description:
                - "ICMP Rate= Total Exceed"
                type: str
            dst_other_any_exceed:
                description:
                - "OTHER Rate= Total Exceed"
                type: str
            src_dst_pair_entry_total:
                description:
                - "Src-Dst Pair Entry Total Count"
                type: str
            src_dst_pair_entry_udp:
                description:
                - "Src-Dst Pair Entry UDP Count"
                type: str
            src_dst_pair_entry_tcp:
                description:
                - "Src-Dst Pair Entry TCP Count"
                type: str
            src_dst_pair_entry_icmp:
                description:
                - "Src-Dst Pair Entry ICMP Count"
                type: str
            src_dst_pair_entry_other:
                description:
                - "Src-Dst Pair Entry OTHER Count"
                type: str
            dst_clist_overflow_policy_at_learning:
                description:
                - "Dst Src-Based Overflow Policy Hit"
                type: str
            tcp_rexmit_syn_limit_drop:
                description:
                - "TCP SYN Retransmit Exceeded Drop"
                type: str
            tcp_rexmit_syn_limit_bl:
                description:
                - "TCP SYN Retransmit Exceeded Blacklist"
                type: str
            dst_tcp_wellknown_sport_drop:
                description:
                - "TCP SrcPort Wellknown"
                type: str
            src_tcp_wellknown_sport_drop:
                description:
                - "Src TCP SrcPort Wellknown"
                type: str
            dst_frag_rcvd:
                description:
                - "Fragmented Packets Received"
                type: str
            no_policy_class_list_match:
                description:
                - "No Policy Class-list Match"
                type: str
            src_udp_retry_gap_drop:
                description:
                - "Src UDP Auth= Retry-Gap Dropped"
                type: str
            dst_entry_kbit_rate_exceed_count:
                description:
                - "Entry Rate= KiBit Exceeded Count"
                type: str
            dst_port_undef_hit:
                description:
                - "Dst Port Undefined Hit"
                type: str
            dst_tcp_action_on_ack_timeout:
                description:
                - "TCP Auth= ACK Retry Timeout"
                type: str
            dst_tcp_action_on_ack_reset:
                description:
                - "TCP Auth= ACK Retry Timeout Reset"
                type: str
            dst_tcp_action_on_ack_blacklist:
                description:
                - "TCP Auth= ACK Retry Timeout Blacklisted"
                type: str
            src_tcp_action_on_ack_timeout:
                description:
                - "Src TCP Auth= ACK Retry Timeout"
                type: str
            src_tcp_action_on_ack_reset:
                description:
                - "Src TCP Auth= ACK Retry Timeout Reset"
                type: str
            src_tcp_action_on_ack_blacklist:
                description:
                - "Src TCP Auth= ACK Retry Timeout Blacklisted"
                type: str
            dst_tcp_action_on_syn_timeout:
                description:
                - "TCP Auth= SYN Retry Timeout"
                type: str
            dst_tcp_action_on_syn_reset:
                description:
                - "TCP Auth= SYN Retry Timeout Reset"
                type: str
            dst_tcp_action_on_syn_blacklist:
                description:
                - "TCP Auth= SYN Retry Timeout Blacklisted"
                type: str
            src_tcp_action_on_syn_timeout:
                description:
                - "Src TCP Auth= SYN Retry Timeout"
                type: str
            src_tcp_action_on_syn_reset:
                description:
                - "Src TCP Auth= SYN Retry Timeout Reset"
                type: str
            src_tcp_action_on_syn_blacklist:
                description:
                - "Src TCP Auth= SYN Retry Timeout Blacklisted"
                type: str
            dst_udp_frag_pkt_rate_exceed:
                description:
                - "UDP Dst L4-Type Rate= Frag Exceeded"
                type: str
            dst_udp_frag_src_rate_drop:
                description:
                - "UDP Src Rate= Frag Exceeded"
                type: str
            dst_tcp_frag_pkt_rate_exceed:
                description:
                - "TCP Dst L4-Type Rate= Frag Exceeded"
                type: str
            dst_tcp_frag_src_rate_drop:
                description:
                - "TCP Src Rate= Frag Exceeded"
                type: str
            dst_icmp_frag_pkt_rate_exceed:
                description:
                - "ICMP Dst L4-Type Rate= Frag Exceeded"
                type: str
            dst_icmp_frag_src_rate_drop:
                description:
                - "ICMP Src Rate= Frag Exceeded"
                type: str
            sflow_internal_samples_packed:
                description:
                - "Sflow Internal Samples Packed"
                type: str
            sflow_external_samples_packed:
                description:
                - "Sflow External Samples Packed"
                type: str
            sflow_internal_packets_sent:
                description:
                - "Sflow Internal Packets Sent"
                type: str
            sflow_external_packets_sent:
                description:
                - "Sflow External Packets Sent"
                type: str
            dns_outbound_total_query:
                description:
                - "DNS Outbound Total Query"
                type: str
            dns_outbound_query_malformed:
                description:
                - "DNS Outbound Query Malformed"
                type: str
            dns_outbound_query_resp_chk_failed:
                description:
                - "DNS Outbound Query Resp Check Failed"
                type: str
            dns_outbound_query_resp_chk_blacklisted:
                description:
                - "DNS Outbound Query Resp Check Blacklisted"
                type: str
            dns_outbound_query_resp_chk_refused_sent:
                description:
                - "DNS Outbound Query Resp Check REFUSED Sent"
                type: str
            dns_outbound_query_resp_chk_reset_sent:
                description:
                - "DNS Outbound Query Resp Check RESET Sent"
                type: str
            dns_outbound_query_resp_chk_no_resp_sent:
                description:
                - "DNS Outbound Query Resp Check No Response Sent"
                type: str
            dns_outbound_query_resp_size_exceed:
                description:
                - "DNS Outbound Query Response Size Exceed"
                type: str
            dns_outbound_query_sess_timed_out:
                description:
                - "DNS Outbound Query Session Timed Out"
                type: str
            dst_exceed_action_tunnel:
                description:
                - "Entry Exceed Action= Tunnel"
                type: str
            src_udp_auth_timeout:
                description:
                - "Src UDP Auth= Retry Timeout"
                type: str
            src_udp_retry_pass:
                description:
                - "Src UDP Retry Passed"
                type: str
            dst_hw_drop_rule_insert:
                description:
                - "Dst Hardware Drop Rules Inserted"
                type: str
            dst_hw_drop_rule_remove:
                description:
                - "Dst Hardware Drop Rules Removed"
                type: str
            src_hw_drop_rule_insert:
                description:
                - "Src Hardware Drop Rules Inserted"
                type: str
            src_hw_drop_rule_remove:
                description:
                - "Src Hardware Drop Rules Removed"
                type: str
            prog_first_req_time_exceed:
                description:
                - "Req-Resp= First Request Time Exceed"
                type: str
            prog_req_resp_time_exceed:
                description:
                - "Req-Resp= Request to Response Time Exceed"
                type: str
            prog_request_len_exceed:
                description:
                - "Req-Resp= Request Length Exceed"
                type: str
            prog_response_len_exceed:
                description:
                - "Req-Resp= Response Length Exceed"
                type: str
            prog_resp_req_ratio_exceed:
                description:
                - "Req-Resp= Response to Request Ratio Exceed"
                type: str
            prog_resp_req_time_exceed:
                description:
                - "Req-Resp= Response to Request Time Exceed"
                type: str
            entry_sync_message_received:
                description:
                - "Entry Sync Message Received"
                type: str
            entry_sync_message_sent:
                description:
                - "Entry Sync Message Sent"
                type: str
            prog_conn_sent_exceed:
                description:
                - "Connection= Sent Exceed"
                type: str
            prog_conn_rcvd_exceed:
                description:
                - "Connection= Received Exceed"
                type: str
            prog_conn_time_exceed:
                description:
                - "Connection= Time Exceed"
                type: str
            prog_conn_rcvd_sent_ratio_exceed:
                description:
                - "Connection= Received to Sent Ratio Exceed"
                type: str
            prog_win_sent_exceed:
                description:
                - "Time Window= Sent Exceed"
                type: str
            prog_win_rcvd_exceed:
                description:
                - "Time Window= Received Exceed"
                type: str
            prog_win_rcvd_sent_ratio_exceed:
                description:
                - "Time Window= Received to Sent Exceed"
                type: str
            prog_exceed_drop:
                description:
                - "Req-Resp= Violation Exceed Dropped"
                type: str
            prog_exceed_bl:
                description:
                - "Req-Resp= Violation Exceed Blacklisted"
                type: str
            prog_conn_exceed_drop:
                description:
                - "Connection= Violation Exceed Dropped"
                type: str
            prog_conn_exceed_bl:
                description:
                - "Connection= Violation Exceed Blacklisted"
                type: str
            prog_win_exceed_drop:
                description:
                - "Time Window= Violation Exceed Dropped"
                type: str
            prog_win_exceed_bl:
                description:
                - "Time Window= Violation Exceed Blacklisted"
                type: str
            dst_exceed_action_drop:
                description:
                - "Entry Exceed Action= Dropped"
                type: str
            prog_conn_samples:
                description:
                - "Sample Collected= Connection"
                type: str
            prog_req_samples:
                description:
                - "Sample Collected= Req-Resp"
                type: str
            prog_win_samples:
                description:
                - "Sample Collected= Time Window"
                type: str
            dst_entry_name:
                description:
                - "Field dst_entry_name"
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
    "advertised_enable", "blackhole_on_glid_exceed", "capture_config_list", "description", "dest_nat_ip", "dest_nat_ipv6", "drop_disable", "drop_disable_fwd_immediate", "drop_frag_pkt", "drop_on_no_src_dst_default", "dst_entry_name", "dynamic_entry_overflow_policy_list", "enable_top_k", "exceed_log_cfg", "exceed_log_dep_cfg", "glid",
    "glid_exceed_action", "hw_blacklist_blocking", "inbound_forward_dscp", "ip_addr", "ip_proto_list", "ipv6_addr", "l4_type_list", "log_periodic", "oper", "operational_mode", "outbound_forward_dscp", "pattern_recognition_hw_filter_enable", "pattern_recognition_sensitivity", "port_list", "port_range_list", "reporting_disabled", "sampling_enable",
    "set_counter_base_val", "sflow", "source_nat_pool", "src_dst_pair", "src_dst_pair_class_list_list", "src_dst_pair_policy_list", "src_dst_pair_settings_list", "src_port_list", "src_port_range_list", "stats", "subnet_ip_addr", "subnet_ipv6_addr", "template", "topk_destinations", "traffic_distribution_mode", "user_tag", "uuid",
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
        'dst_entry_name': {
            'type': 'str',
            'required': True,
            },
        'ipv6_addr': {
            'type': 'str',
            },
        'ip_addr': {
            'type': 'str',
            },
        'subnet_ip_addr': {
            'type': 'str',
            },
        'subnet_ipv6_addr': {
            'type': 'str',
            },
        'description': {
            'type': 'str',
            },
        'exceed_log_dep_cfg': {
            'type': 'dict',
            'exceed_log_enable': {
                'type': 'bool',
                },
            'log_with_sflow_dep': {
                'type': 'bool',
                }
            },
        'exceed_log_cfg': {
            'type': 'dict',
            'log_enable': {
                'type': 'bool',
                },
            'log_with_sflow': {
                'type': 'bool',
                },
            'log_high_frequency': {
                'type': 'bool',
                },
            'rate_limit': {
                'type': 'int',
                }
            },
        'log_periodic': {
            'type': 'bool',
            },
        'drop_frag_pkt': {
            'type': 'bool',
            },
        'sflow': {
            'type': 'dict',
            'polling': {
                'type': 'dict',
                'sflow_packets': {
                    'type': 'bool',
                    },
                'sflow_layer_4': {
                    'type': 'bool',
                    },
                'sflow_tcp': {
                    'type': 'dict',
                    'sflow_tcp_basic': {
                        'type': 'bool',
                        },
                    'sflow_tcp_stateful': {
                        'type': 'bool',
                        }
                    },
                'sflow_http': {
                    'type': 'bool',
                    },
                'sflow_undef_port_hit_stats': {
                    'type': 'bool',
                    },
                'sflow_undef_port_hit_stats_brief': {
                    'type': 'bool',
                    }
                }
            },
        'drop_on_no_src_dst_default': {
            'type': 'bool',
            },
        'blackhole_on_glid_exceed': {
            'type': 'int',
            },
        'source_nat_pool': {
            'type': 'str',
            },
        'dest_nat_ip': {
            'type': 'str',
            },
        'dest_nat_ipv6': {
            'type': 'str',
            },
        'drop_disable': {
            'type': 'bool',
            },
        'drop_disable_fwd_immediate': {
            'type': 'bool',
            },
        'template': {
            'type': 'dict',
            'logging': {
                'type': 'str',
                }
            },
        'operational_mode': {
            'type': 'str',
            'choices': ['protection', 'bypass']
            },
        'reporting_disabled': {
            'type': 'bool',
            },
        'glid': {
            'type': 'str',
            },
        'glid_exceed_action': {
            'type': 'dict',
            'stateless_encap_action_cfg': {
                'type': 'dict',
                'stateless_encap_action': {
                    'type': 'str',
                    'choices': ['stateless-tunnel-encap', 'stateless-tunnel-encap-scrubbed']
                    },
                'encap_template': {
                    'type': 'str',
                    }
                }
            },
        'advertised_enable': {
            'type': 'bool',
            },
        'set_counter_base_val': {
            'type': 'int',
            },
        'inbound_forward_dscp': {
            'type': 'int',
            },
        'outbound_forward_dscp': {
            'type': 'int',
            },
        'pattern_recognition_sensitivity': {
            'type': 'str',
            'choices': ['high', 'medium', 'low']
            },
        'pattern_recognition_hw_filter_enable': {
            'type': 'bool',
            },
        'enable_top_k': {
            'type': 'list',
            'topk_type': {
                'type': 'str',
                'choices': ['destination']
                },
            'topk_num_records': {
                'type': 'int',
                }
            },
        'traffic_distribution_mode': {
            'type': 'str',
            'choices': ['default', 'source-ip-based']
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
                    'all', 'dst_tcp_any_exceed', 'dst_tcp_pkt_rate_exceed', 'dst_tcp_conn_rate_exceed', 'dst_udp_any_exceed', 'dst_udp_pkt_rate_exceed', 'dst_udp_conn_limit_exceed', 'dst_udp_conn_rate_exceed', 'dst_icmp_pkt_rate_exceed', 'dst_other_pkt_rate_exceed', 'dst_other_frag_pkt_rate_exceed', 'dst_port_pkt_rate_exceed',
                    'dst_port_conn_limit_exceed', 'dst_port_conn_rate_exceed', 'dst_pkt_sent', 'dst_udp_pkt_sent', 'dst_tcp_pkt_sent', 'dst_icmp_pkt_sent', 'dst_other_pkt_sent', 'dst_tcp_conn_limit_exceed', 'dst_tcp_pkt_rcvd', 'dst_udp_pkt_rcvd', 'dst_icmp_pkt_rcvd', 'dst_other_pkt_rcvd', 'dst_udp_filter_match', 'dst_udp_filter_not_match',
                    'dst_udp_filter_action_blacklist', 'dst_udp_filter_action_drop', 'dst_tcp_syn', 'dst_tcp_syn_drop', 'dst_tcp_src_rate_drop', 'dst_udp_src_rate_drop', 'dst_icmp_src_rate_drop', 'dst_other_frag_src_rate_drop', 'dst_other_src_rate_drop', 'dst_tcp_drop', 'dst_udp_drop', 'dst_icmp_drop', 'dst_frag_drop', 'dst_other_drop',
                    'dst_tcp_auth', 'dst_udp_filter_action_default_pass', 'dst_tcp_filter_match', 'dst_tcp_filter_not_match', 'dst_tcp_filter_action_blacklist', 'dst_tcp_filter_action_drop', 'dst_tcp_filter_action_default_pass', 'dst_udp_filter_action_whitelist', 'dst_over_limit_on', 'dst_over_limit_off', 'dst_port_over_limit_on',
                    'dst_port_over_limit_off', 'dst_over_limit_action', 'dst_port_over_limit_action', 'scanning_detected_drop', 'scanning_detected_blacklist', 'dst_udp_kibit_rate_drop', 'dst_tcp_kibit_rate_drop', 'dst_icmp_kibit_rate_drop', 'dst_other_kibit_rate_drop', 'dst_port_undef_drop', 'dst_port_bl', 'dst_src_port_bl',
                    'dst_port_kbit_rate_exceed', 'dst_tcp_src_drop', 'dst_udp_src_drop', 'dst_icmp_src_drop', 'dst_other_src_drop', 'tcp_syn_rcvd', 'tcp_syn_ack_rcvd', 'tcp_ack_rcvd', 'tcp_fin_rcvd', 'tcp_rst_rcvd', 'ingress_bytes', 'egress_bytes', 'ingress_packets', 'egress_packets', 'tcp_fwd_recv', 'udp_fwd_recv', 'icmp_fwd_recv',
                    'tcp_syn_cookie_fail', 'dst_tcp_session_created', 'dst_udp_session_created', 'dst_tcp_filter_action_whitelist', 'dst_other_filter_match', 'dst_other_filter_not_match', 'dst_other_filter_action_blacklist', 'dst_other_filter_action_drop', 'dst_other_filter_action_whitelist', 'dst_other_filter_action_default_pass',
                    'dst_blackhole_inject', 'dst_blackhole_withdraw', 'dst_tcp_out_of_seq_excd', 'dst_tcp_retransmit_excd', 'dst_tcp_zero_window_excd', 'dst_tcp_conn_prate_excd', 'dst_tcp_action_on_ack_init', 'dst_tcp_action_on_ack_gap_drop', 'dst_tcp_action_on_ack_fail', 'dst_tcp_action_on_ack_pass', 'dst_tcp_action_on_syn_init',
                    'dst_tcp_action_on_syn_gap_drop', 'dst_tcp_action_on_syn_fail', 'dst_tcp_action_on_syn_pass', 'udp_payload_too_small', 'udp_payload_too_big', 'dst_udp_conn_prate_excd', 'dst_udp_ntp_monlist_req', 'dst_udp_ntp_monlist_resp', 'dst_udp_wellknown_sport_drop', 'dst_udp_retry_init', 'dst_udp_retry_pass', 'dst_tcp_bytes_drop',
                    'dst_udp_bytes_drop', 'dst_icmp_bytes_drop', 'dst_other_bytes_drop', 'dst_out_no_route', 'outbound_bytes_sent', 'outbound_pkt_drop', 'outbound_bytes_drop', 'outbound_pkt_sent', 'inbound_bytes_sent', 'inbound_bytes_drop', 'dst_src_port_pkt_rate_exceed', 'dst_src_port_kbit_rate_exceed', 'dst_src_port_conn_limit_exceed',
                    'dst_src_port_conn_rate_exceed', 'dst_ip_proto_pkt_rate_exceed', 'dst_ip_proto_kbit_rate_exceed', 'dst_tcp_port_any_exceed', 'dst_udp_port_any_exceed', 'dst_tcp_auth_pass', 'dst_tcp_rst_cookie_fail', 'dst_tcp_unauth_drop', 'src_tcp_syn_auth_fail', 'src_tcp_syn_cookie_sent', 'src_tcp_syn_cookie_fail', 'src_tcp_rst_cookie_fail',
                    'src_tcp_unauth_drop', 'src_tcp_action_on_syn_init'
                    ]
                },
            'counters2': {
                'type':
                'str',
                'choices': [
                    'src_tcp_action_on_syn_gap_drop', 'src_tcp_action_on_syn_fail', 'src_tcp_action_on_ack_init', 'src_tcp_action_on_ack_gap_drop', 'src_tcp_action_on_ack_fail', 'src_tcp_out_of_seq_excd', 'src_tcp_retransmit_excd', 'src_tcp_zero_window_excd', 'src_tcp_conn_prate_excd', 'src_udp_min_payload', 'src_udp_max_payload',
                    'src_udp_conn_prate_excd', 'src_udp_ntp_monlist_req', 'src_udp_ntp_monlist_resp', 'src_udp_wellknown_sport_drop', 'src_udp_retry_init', 'dst_udp_retry_gap_drop', 'dst_udp_retry_fail', 'dst_tcp_session_aged', 'dst_udp_session_aged', 'dst_tcp_conn_close', 'dst_tcp_conn_close_half_open', 'dst_l4_tcp_auth', 'tcp_l4_syn_cookie_fail',
                    'tcp_l4_rst_cookie_fail', 'tcp_l4_unauth_drop', 'dst_drop_frag_pkt', 'src_tcp_filter_action_blacklist', 'src_tcp_filter_action_whitelist', 'src_tcp_filter_action_drop', 'src_tcp_filter_action_default_pass', 'src_udp_filter_action_blacklist', 'src_udp_filter_action_whitelist', 'src_udp_filter_action_drop',
                    'src_udp_filter_action_default_pass', 'src_other_filter_action_blacklist', 'src_other_filter_action_whitelist', 'src_other_filter_action_drop', 'src_other_filter_action_default_pass', 'tcp_invalid_syn', 'dst_tcp_conn_close_w_rst', 'dst_tcp_conn_close_w_fin', 'dst_tcp_conn_close_w_idle', 'dst_tcp_conn_create_from_syn',
                    'dst_tcp_conn_create_from_ack', 'src_frag_drop', 'dst_l4_tcp_blacklist_drop', 'dst_l4_udp_blacklist_drop', 'dst_l4_icmp_blacklist_drop', 'dst_l4_other_blacklist_drop', 'src_l4_tcp_blacklist_drop', 'src_l4_udp_blacklist_drop', 'src_l4_icmp_blacklist_drop', 'src_l4_other_blacklist_drop', 'drop_frag_timeout_drop',
                    'dst_port_kbit_rate_exceed_pkt', 'dst_tcp_bytes_rcv', 'dst_udp_bytes_rcv', 'dst_icmp_bytes_rcv', 'dst_other_bytes_rcv', 'dst_tcp_bytes_sent', 'dst_udp_bytes_sent', 'dst_icmp_bytes_sent', 'dst_other_bytes_sent', 'dst_udp_auth_drop', 'dst_tcp_auth_drop', 'dst_tcp_auth_resp', 'inbound_pkt_drop', 'dst_entry_pkt_rate_exceed',
                    'dst_entry_kbit_rate_exceed', 'dst_entry_conn_limit_exceed', 'dst_entry_conn_rate_exceed', 'dst_entry_frag_pkt_rate_exceed', 'dst_icmp_any_exceed', 'dst_other_any_exceed', 'src_dst_pair_entry_total', 'src_dst_pair_entry_udp', 'src_dst_pair_entry_tcp', 'src_dst_pair_entry_icmp', 'src_dst_pair_entry_other',
                    'dst_clist_overflow_policy_at_learning', 'tcp_rexmit_syn_limit_drop', 'tcp_rexmit_syn_limit_bl', 'dst_tcp_wellknown_sport_drop', 'src_tcp_wellknown_sport_drop', 'dst_frag_rcvd', 'no_policy_class_list_match', 'src_udp_retry_gap_drop', 'dst_entry_kbit_rate_exceed_count', 'dst_port_undef_hit', 'dst_tcp_action_on_ack_timeout',
                    'dst_tcp_action_on_ack_reset', 'dst_tcp_action_on_ack_blacklist', 'src_tcp_action_on_ack_timeout', 'src_tcp_action_on_ack_reset', 'src_tcp_action_on_ack_blacklist', 'dst_tcp_action_on_syn_timeout', 'dst_tcp_action_on_syn_reset', 'dst_tcp_action_on_syn_blacklist', 'src_tcp_action_on_syn_timeout', 'src_tcp_action_on_syn_reset',
                    'src_tcp_action_on_syn_blacklist', 'dst_udp_frag_pkt_rate_exceed', 'dst_udp_frag_src_rate_drop', 'dst_tcp_frag_pkt_rate_exceed', 'dst_tcp_frag_src_rate_drop', 'dst_icmp_frag_pkt_rate_exceed', 'dst_icmp_frag_src_rate_drop', 'sflow_internal_samples_packed', 'sflow_external_samples_packed', 'sflow_internal_packets_sent',
                    'sflow_external_packets_sent', 'dns_outbound_total_query', 'dns_outbound_query_malformed', 'dns_outbound_query_resp_chk_failed', 'dns_outbound_query_resp_chk_blacklisted', 'dns_outbound_query_resp_chk_refused_sent', 'dns_outbound_query_resp_chk_reset_sent', 'dns_outbound_query_resp_chk_no_resp_sent',
                    'dns_outbound_query_resp_size_exceed', 'dns_outbound_query_sess_timed_out', 'dst_exceed_action_tunnel', 'src_udp_auth_timeout', 'src_udp_retry_pass'
                    ]
                },
            'counters3': {
                'type':
                'str',
                'choices': [
                    'dst_hw_drop_rule_insert', 'dst_hw_drop_rule_remove', 'src_hw_drop_rule_insert', 'src_hw_drop_rule_remove', 'prog_first_req_time_exceed', 'prog_req_resp_time_exceed', 'prog_request_len_exceed', 'prog_response_len_exceed', 'prog_resp_req_ratio_exceed', 'prog_resp_req_time_exceed', 'entry_sync_message_received',
                    'entry_sync_message_sent', 'prog_conn_sent_exceed', 'prog_conn_rcvd_exceed', 'prog_conn_time_exceed', 'prog_conn_rcvd_sent_ratio_exceed', 'prog_win_sent_exceed', 'prog_win_rcvd_exceed', 'prog_win_rcvd_sent_ratio_exceed', 'prog_exceed_drop', 'prog_exceed_bl', 'prog_conn_exceed_drop', 'prog_conn_exceed_bl', 'prog_win_exceed_drop',
                    'prog_win_exceed_bl', 'dst_exceed_action_drop', 'prog_conn_samples', 'prog_req_samples', 'prog_win_samples'
                    ]
                }
            },
        'capture_config_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'mode': {
                'type': 'str',
                'choices': ['drop', 'forward', 'all']
                },
            'uuid': {
                'type': 'str',
                }
            },
        'hw_blacklist_blocking': {
            'type': 'dict',
            'dst_enable': {
                'type': 'bool',
                },
            'src_enable': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'topk_destinations': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'l4_type_list': {
            'type': 'list',
            'protocol': {
                'type': 'str',
                'required': True,
                'choices': ['tcp', 'udp', 'icmp', 'other']
                },
            'glid': {
                'type': 'str',
                },
            'glid_exceed_action': {
                'type': 'dict',
                'stateless_encap_action_cfg': {
                    'type': 'dict',
                    'stateless_encap_action': {
                        'type': 'str',
                        'choices': ['stateless-tunnel-encap', 'stateless-tunnel-encap-scrubbed']
                        },
                    'encap_template': {
                        'type': 'str',
                        }
                    }
                },
            'deny': {
                'type': 'bool',
                },
            'max_rexmit_syn_per_flow': {
                'type': 'int',
                },
            'max_rexmit_syn_per_flow_exceed_action': {
                'type': 'str',
                'choices': ['drop', 'black-list']
                },
            'disable_syn_auth': {
                'type': 'bool',
                },
            'syn_auth': {
                'type': 'str',
                'choices': ['send-rst', 'force-rst-by-ack', 'force-rst-by-synack', 'disable']
                },
            'syn_cookie': {
                'type': 'bool',
                },
            'tcp_reset_client': {
                'type': 'bool',
                },
            'tcp_reset_server': {
                'type': 'bool',
                },
            'drop_on_no_port_match': {
                'type': 'str',
                'choices': ['disable', 'enable']
                },
            'stateful': {
                'type': 'bool',
                },
            'tunnel_decap': {
                'type': 'dict',
                'ip_decap': {
                    'type': 'bool',
                    },
                'gre_decap': {
                    'type': 'bool',
                    },
                'key_cfg': {
                    'type': 'list',
                    'key': {
                        'type': 'str',
                        }
                    }
                },
            'tunnel_rate_limit': {
                'type': 'dict',
                'ip_rate_limit': {
                    'type': 'bool',
                    },
                'gre_rate_limit': {
                    'type': 'bool',
                    }
                },
            'drop_frag_pkt': {
                'type': 'bool',
                },
            'undefined_port_hit_statistics': {
                'type': 'dict',
                'undefined_port_hit_statistics': {
                    'type': 'bool',
                    },
                'reset_interval': {
                    'type': 'int',
                    }
                },
            'template': {
                'type': 'dict',
                'template_icmp_v4': {
                    'type': 'str',
                    },
                'template_icmp_v6': {
                    'type': 'str',
                    }
                },
            'detection_enable': {
                'type': 'bool',
                },
            'enable_top_k': {
                'type': 'bool',
                },
            'topk_num_records': {
                'type': 'int',
                },
            'set_counter_base_val': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'port_ind': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                    },
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type':
                        'str',
                        'choices': [
                            'all', 'ip-proto-type', 'ddet_ind_pkt_rate_current', 'ddet_ind_pkt_rate_min', 'ddet_ind_pkt_rate_max', 'ddet_ind_pkt_drop_rate_current', 'ddet_ind_pkt_drop_rate_min', 'ddet_ind_pkt_drop_rate_max', 'ddet_ind_syn_rate_current', 'ddet_ind_syn_rate_min', 'ddet_ind_syn_rate_max', 'ddet_ind_fin_rate_current',
                            'ddet_ind_fin_rate_min', 'ddet_ind_fin_rate_max', 'ddet_ind_rst_rate_current', 'ddet_ind_rst_rate_min', 'ddet_ind_rst_rate_max', 'ddet_ind_small_window_ack_rate_current', 'ddet_ind_small_window_ack_rate_min', 'ddet_ind_small_window_ack_rate_max', 'ddet_ind_empty_ack_rate_current', 'ddet_ind_empty_ack_rate_min',
                            'ddet_ind_empty_ack_rate_max', 'ddet_ind_small_payload_rate_current', 'ddet_ind_small_payload_rate_min', 'ddet_ind_small_payload_rate_max', 'ddet_ind_pkt_drop_ratio_current', 'ddet_ind_pkt_drop_ratio_min', 'ddet_ind_pkt_drop_ratio_max', 'ddet_ind_inb_per_outb_current', 'ddet_ind_inb_per_outb_min',
                            'ddet_ind_inb_per_outb_max', 'ddet_ind_syn_per_fin_rate_current', 'ddet_ind_syn_per_fin_rate_min', 'ddet_ind_syn_per_fin_rate_max', 'ddet_ind_conn_miss_rate_current', 'ddet_ind_conn_miss_rate_min', 'ddet_ind_conn_miss_rate_max', 'ddet_ind_concurrent_conns_current', 'ddet_ind_concurrent_conns_min',
                            'ddet_ind_concurrent_conns_max', 'ddet_ind_data_cpu_util_current', 'ddet_ind_data_cpu_util_min', 'ddet_ind_data_cpu_util_max', 'ddet_ind_outside_intf_util_current', 'ddet_ind_outside_intf_util_min', 'ddet_ind_outside_intf_util_max', 'ddet_ind_frag_rate_current', 'ddet_ind_frag_rate_min', 'ddet_ind_frag_rate_max',
                            'ddet_ind_bit_rate_current', 'ddet_ind_bit_rate_min', 'ddet_ind_bit_rate_max'
                            ]
                        }
                    }
                },
            'topk_sources': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                    }
                },
            'progression_tracking': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'port_list': {
            'type': 'list',
            'port_num': {
                'type': 'int',
                'required': True,
                },
            'protocol': {
                'type': 'str',
                'required': True,
                'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4', 'sip-udp', 'sip-tcp']
                },
            'detection_enable': {
                'type': 'bool',
                },
            'enable_top_k': {
                'type': 'bool',
                },
            'topk_num_records': {
                'type': 'int',
                },
            'deny': {
                'type': 'bool',
                },
            'glid': {
                'type': 'str',
                },
            'glid_exceed_action': {
                'type': 'dict',
                'stateless_encap_action_cfg': {
                    'type': 'dict',
                    'stateless_encap_action': {
                        'type': 'str',
                        'choices': ['stateless-tunnel-encap', 'stateless-tunnel-encap-scrubbed']
                        },
                    'encap_template': {
                        'type': 'str',
                        }
                    }
                },
            'dns_cache': {
                'type': 'str',
                },
            'template': {
                'type': 'dict',
                'dns': {
                    'type': 'str',
                    },
                'http': {
                    'type': 'str',
                    },
                'ssl_l4': {
                    'type': 'str',
                    },
                'sip': {
                    'type': 'str',
                    },
                'tcp': {
                    'type': 'str',
                    },
                'udp': {
                    'type': 'str',
                    }
                },
            'sflow': {
                'type': 'dict',
                'polling': {
                    'type': 'dict',
                    'sflow_packets': {
                        'type': 'bool',
                        },
                    'sflow_tcp': {
                        'type': 'dict',
                        'sflow_tcp_basic': {
                            'type': 'bool',
                            },
                        'sflow_tcp_stateful': {
                            'type': 'bool',
                            }
                        },
                    'sflow_http': {
                        'type': 'bool',
                        }
                    }
                },
            'capture_config': {
                'type': 'dict',
                'capture_config_name': {
                    'type': 'str',
                    },
                'capture_config_mode': {
                    'type': 'str',
                    'choices': ['drop', 'forward', 'all']
                    }
                },
            'set_counter_base_val': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'port_ind': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                    },
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type':
                        'str',
                        'choices': [
                            'all', 'ip-proto-type', 'ddet_ind_pkt_rate_current', 'ddet_ind_pkt_rate_min', 'ddet_ind_pkt_rate_max', 'ddet_ind_pkt_drop_rate_current', 'ddet_ind_pkt_drop_rate_min', 'ddet_ind_pkt_drop_rate_max', 'ddet_ind_syn_rate_current', 'ddet_ind_syn_rate_min', 'ddet_ind_syn_rate_max', 'ddet_ind_fin_rate_current',
                            'ddet_ind_fin_rate_min', 'ddet_ind_fin_rate_max', 'ddet_ind_rst_rate_current', 'ddet_ind_rst_rate_min', 'ddet_ind_rst_rate_max', 'ddet_ind_small_window_ack_rate_current', 'ddet_ind_small_window_ack_rate_min', 'ddet_ind_small_window_ack_rate_max', 'ddet_ind_empty_ack_rate_current', 'ddet_ind_empty_ack_rate_min',
                            'ddet_ind_empty_ack_rate_max', 'ddet_ind_small_payload_rate_current', 'ddet_ind_small_payload_rate_min', 'ddet_ind_small_payload_rate_max', 'ddet_ind_pkt_drop_ratio_current', 'ddet_ind_pkt_drop_ratio_min', 'ddet_ind_pkt_drop_ratio_max', 'ddet_ind_inb_per_outb_current', 'ddet_ind_inb_per_outb_min',
                            'ddet_ind_inb_per_outb_max', 'ddet_ind_syn_per_fin_rate_current', 'ddet_ind_syn_per_fin_rate_min', 'ddet_ind_syn_per_fin_rate_max', 'ddet_ind_conn_miss_rate_current', 'ddet_ind_conn_miss_rate_min', 'ddet_ind_conn_miss_rate_max', 'ddet_ind_concurrent_conns_current', 'ddet_ind_concurrent_conns_min',
                            'ddet_ind_concurrent_conns_max', 'ddet_ind_data_cpu_util_current', 'ddet_ind_data_cpu_util_min', 'ddet_ind_data_cpu_util_max', 'ddet_ind_outside_intf_util_current', 'ddet_ind_outside_intf_util_min', 'ddet_ind_outside_intf_util_max', 'ddet_ind_frag_rate_current', 'ddet_ind_frag_rate_min', 'ddet_ind_frag_rate_max',
                            'ddet_ind_bit_rate_current', 'ddet_ind_bit_rate_min', 'ddet_ind_bit_rate_max'
                            ]
                        }
                    }
                },
            'topk_sources': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                    }
                },
            'progression_tracking': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                    }
                },
            'signature_extraction': {
                'type': 'dict',
                'algorithm': {
                    'type': 'str',
                    'choices': ['heuristic']
                    },
                'manual_mode': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'pattern_recognition': {
                'type': 'dict',
                'algorithm': {
                    'type': 'str',
                    'choices': ['heuristic']
                    },
                'mode': {
                    'type': 'str',
                    'choices': ['capture-never-expire', 'manual']
                    },
                'sensitivity': {
                    'type': 'str',
                    'choices': ['high', 'medium', 'low']
                    },
                'filter_threshold': {
                    'type': 'int',
                    },
                'filter_inactive_threshold': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'pattern_recognition_pu_details': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'port_range_list': {
            'type': 'list',
            'port_range_start': {
                'type': 'int',
                'required': True,
                },
            'port_range_end': {
                'type': 'int',
                'required': True,
                },
            'protocol': {
                'type': 'str',
                'required': True,
                'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4', 'sip-udp', 'sip-tcp']
                },
            'deny': {
                'type': 'bool',
                },
            'detection_enable': {
                'type': 'bool',
                },
            'enable_top_k': {
                'type': 'bool',
                },
            'topk_num_records': {
                'type': 'int',
                },
            'glid': {
                'type': 'str',
                },
            'glid_exceed_action': {
                'type': 'dict',
                'stateless_encap_action_cfg': {
                    'type': 'dict',
                    'stateless_encap_action': {
                        'type': 'str',
                        'choices': ['stateless-tunnel-encap', 'stateless-tunnel-encap-scrubbed']
                        },
                    'encap_template': {
                        'type': 'str',
                        }
                    }
                },
            'template': {
                'type': 'dict',
                'dns': {
                    'type': 'str',
                    },
                'http': {
                    'type': 'str',
                    },
                'ssl_l4': {
                    'type': 'str',
                    },
                'sip': {
                    'type': 'str',
                    },
                'tcp': {
                    'type': 'str',
                    },
                'udp': {
                    'type': 'str',
                    }
                },
            'sflow': {
                'type': 'dict',
                'polling': {
                    'type': 'dict',
                    'sflow_packets': {
                        'type': 'bool',
                        },
                    'sflow_tcp': {
                        'type': 'dict',
                        'sflow_tcp_basic': {
                            'type': 'bool',
                            },
                        'sflow_tcp_stateful': {
                            'type': 'bool',
                            }
                        },
                    'sflow_http': {
                        'type': 'bool',
                        }
                    }
                },
            'capture_config': {
                'type': 'dict',
                'capture_config_name': {
                    'type': 'str',
                    },
                'capture_config_mode': {
                    'type': 'str',
                    'choices': ['drop', 'forward', 'all']
                    }
                },
            'set_counter_base_val': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'port_ind': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                    },
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type':
                        'str',
                        'choices': [
                            'all', 'ip-proto-type', 'ddet_ind_pkt_rate_current', 'ddet_ind_pkt_rate_min', 'ddet_ind_pkt_rate_max', 'ddet_ind_pkt_drop_rate_current', 'ddet_ind_pkt_drop_rate_min', 'ddet_ind_pkt_drop_rate_max', 'ddet_ind_syn_rate_current', 'ddet_ind_syn_rate_min', 'ddet_ind_syn_rate_max', 'ddet_ind_fin_rate_current',
                            'ddet_ind_fin_rate_min', 'ddet_ind_fin_rate_max', 'ddet_ind_rst_rate_current', 'ddet_ind_rst_rate_min', 'ddet_ind_rst_rate_max', 'ddet_ind_small_window_ack_rate_current', 'ddet_ind_small_window_ack_rate_min', 'ddet_ind_small_window_ack_rate_max', 'ddet_ind_empty_ack_rate_current', 'ddet_ind_empty_ack_rate_min',
                            'ddet_ind_empty_ack_rate_max', 'ddet_ind_small_payload_rate_current', 'ddet_ind_small_payload_rate_min', 'ddet_ind_small_payload_rate_max', 'ddet_ind_pkt_drop_ratio_current', 'ddet_ind_pkt_drop_ratio_min', 'ddet_ind_pkt_drop_ratio_max', 'ddet_ind_inb_per_outb_current', 'ddet_ind_inb_per_outb_min',
                            'ddet_ind_inb_per_outb_max', 'ddet_ind_syn_per_fin_rate_current', 'ddet_ind_syn_per_fin_rate_min', 'ddet_ind_syn_per_fin_rate_max', 'ddet_ind_conn_miss_rate_current', 'ddet_ind_conn_miss_rate_min', 'ddet_ind_conn_miss_rate_max', 'ddet_ind_concurrent_conns_current', 'ddet_ind_concurrent_conns_min',
                            'ddet_ind_concurrent_conns_max', 'ddet_ind_data_cpu_util_current', 'ddet_ind_data_cpu_util_min', 'ddet_ind_data_cpu_util_max', 'ddet_ind_outside_intf_util_current', 'ddet_ind_outside_intf_util_min', 'ddet_ind_outside_intf_util_max', 'ddet_ind_frag_rate_current', 'ddet_ind_frag_rate_min', 'ddet_ind_frag_rate_max',
                            'ddet_ind_bit_rate_current', 'ddet_ind_bit_rate_min', 'ddet_ind_bit_rate_max'
                            ]
                        }
                    }
                },
            'topk_sources': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                    }
                },
            'progression_tracking': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                    }
                },
            'pattern_recognition': {
                'type': 'dict',
                'algorithm': {
                    'type': 'str',
                    'choices': ['heuristic']
                    },
                'mode': {
                    'type': 'str',
                    'choices': ['capture-never-expire', 'manual']
                    },
                'sensitivity': {
                    'type': 'str',
                    'choices': ['high', 'medium', 'low']
                    },
                'filter_threshold': {
                    'type': 'int',
                    },
                'filter_inactive_threshold': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'pattern_recognition_pu_details': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'src_port_list': {
            'type': 'list',
            'port_num': {
                'type': 'int',
                'required': True,
                },
            'protocol': {
                'type': 'str',
                'required': True,
                'choices': ['dns-udp', 'dns-tcp', 'udp', 'tcp']
                },
            'deny': {
                'type': 'bool',
                },
            'glid': {
                'type': 'str',
                },
            'outbound_src_tracking': {
                'type': 'str',
                'choices': ['enable', 'disable']
                },
            'template': {
                'type': 'dict',
                'src_udp': {
                    'type': 'str',
                    },
                'src_tcp': {
                    'type': 'str',
                    },
                'src_dns': {
                    'type': 'str',
                    }
                },
            'set_counter_base_val': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            },
        'src_port_range_list': {
            'type': 'list',
            'src_port_range_start': {
                'type': 'int',
                'required': True,
                },
            'src_port_range_end': {
                'type': 'int',
                'required': True,
                },
            'protocol': {
                'type': 'str',
                'required': True,
                'choices': ['udp', 'tcp']
                },
            'deny': {
                'type': 'bool',
                },
            'glid': {
                'type': 'str',
                },
            'template': {
                'type': 'dict',
                'src_udp': {
                    'type': 'str',
                    },
                'src_tcp': {
                    'type': 'str',
                    }
                },
            'set_counter_base_val': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            },
        'ip_proto_list': {
            'type': 'list',
            'port_num': {
                'type': 'int',
                'required': True,
                },
            'deny': {
                'type': 'bool',
                },
            'esp_inspect': {
                'type': 'dict',
                'auth_algorithm': {
                    'type': 'str',
                    'choices': ['AUTH_NULL', 'HMAC-SHA-1-96', 'HMAC-SHA-256-96', 'HMAC-SHA-256-128', 'HMAC-SHA-384-192', 'HMAC-SHA-512-256', 'HMAC-MD5-96', 'MAC-RIPEMD-160-96']
                    },
                'encrypt_algorithm': {
                    'type': 'str',
                    'choices': ['NULL']
                    },
                'mode': {
                    'type': 'str',
                    'choices': ['transport']
                    }
                },
            'glid': {
                'type': 'str',
                },
            'glid_exceed_action': {
                'type': 'dict',
                'stateless_encap_action_cfg': {
                    'type': 'dict',
                    'stateless_encap_action': {
                        'type': 'str',
                        'choices': ['stateless-tunnel-encap', 'stateless-tunnel-encap-scrubbed']
                        },
                    'encap_template': {
                        'type': 'str',
                        }
                    }
                },
            'template': {
                'type': 'dict',
                'other': {
                    'type': 'str',
                    }
                },
            'set_counter_base_val': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            },
        'src_dst_pair': {
            'type': 'dict',
            'default': {
                'type': 'bool',
                },
            'bypass': {
                'type': 'bool',
                },
            'exceed_log_cfg': {
                'type': 'dict',
                'log_enable': {
                    'type': 'bool',
                    }
                },
            'log_periodic': {
                'type': 'bool',
                },
            'template': {
                'type': 'dict',
                'logging': {
                    'type': 'str',
                    }
                },
            'glid': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'l4_type_src_dst_list': {
                'type': 'list',
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['tcp', 'udp', 'icmp', 'other']
                    },
                'deny': {
                    'type': 'bool',
                    },
                'glid': {
                    'type': 'str',
                    },
                'template': {
                    'type': 'dict',
                    'tcp': {
                        'type': 'str',
                        },
                    'udp': {
                        'type': 'str',
                        },
                    'other': {
                        'type': 'str',
                        },
                    'template_icmp_v4': {
                        'type': 'str',
                        },
                    'template_icmp_v6': {
                        'type': 'str',
                        }
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    }
                },
            'app_type_src_dst_list': {
                'type': 'list',
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['dns', 'http', 'ssl-l4', 'sip']
                    },
                'template': {
                    'type': 'dict',
                    'ssl_l4': {
                        'type': 'str',
                        },
                    'dns': {
                        'type': 'str',
                        },
                    'http': {
                        'type': 'str',
                        },
                    'sip': {
                        'type': 'str',
                        }
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    }
                }
            },
        'src_dst_pair_policy_list': {
            'type': 'list',
            'src_based_policy_name': {
                'type': 'str',
                'required': True,
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'policy_class_list_list': {
                'type': 'list',
                'class_list_name': {
                    'type': 'str',
                    'required': True,
                    },
                'bypass': {
                    'type': 'bool',
                    },
                'exceed_log_cfg': {
                    'type': 'dict',
                    'log_enable': {
                        'type': 'bool',
                        }
                    },
                'log_periodic': {
                    'type': 'bool',
                    },
                'template': {
                    'type': 'dict',
                    'logging': {
                        'type': 'str',
                        }
                    },
                'glid': {
                    'type': 'str',
                    },
                'max_dynamic_entry_count': {
                    'type': 'int',
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
                        'type': 'str',
                        'choices': ['all', 'packet_received', 'packet_dropped', 'entry_learned', 'entry_count_overflow']
                        }
                    },
                'l4_type_src_dst_list': {
                    'type': 'list',
                    'protocol': {
                        'type': 'str',
                        'required': True,
                        'choices': ['tcp', 'udp', 'icmp', 'other']
                        },
                    'deny': {
                        'type': 'bool',
                        },
                    'glid': {
                        'type': 'str',
                        },
                    'template': {
                        'type': 'dict',
                        'tcp': {
                            'type': 'str',
                            },
                        'udp': {
                            'type': 'str',
                            },
                        'other': {
                            'type': 'str',
                            },
                        'template_icmp_v4': {
                            'type': 'str',
                            },
                        'template_icmp_v6': {
                            'type': 'str',
                            }
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        }
                    },
                'app_type_src_dst_list': {
                    'type': 'list',
                    'protocol': {
                        'type': 'str',
                        'required': True,
                        'choices': ['dns', 'http', 'ssl-l4', 'sip']
                        },
                    'template': {
                        'type': 'dict',
                        'ssl_l4': {
                            'type': 'str',
                            },
                        'dns': {
                            'type': 'str',
                            },
                        'http': {
                            'type': 'str',
                            },
                        'sip': {
                            'type': 'str',
                            }
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        }
                    },
                'class_list_overflow_policy_list': {
                    'type': 'list',
                    'dummy_name': {
                        'type': 'str',
                        'required': True,
                        'choices': ['configuration']
                        },
                    'bypass': {
                        'type': 'bool',
                        },
                    'exceed_log_cfg': {
                        'type': 'dict',
                        'log_enable': {
                            'type': 'bool',
                            }
                        },
                    'log_periodic': {
                        'type': 'bool',
                        },
                    'template': {
                        'type': 'dict',
                        'logging': {
                            'type': 'str',
                            }
                        },
                    'glid': {
                        'type': 'str',
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        },
                    'l4_type_src_dst_overflow_list': {
                        'type': 'list',
                        'protocol': {
                            'type': 'str',
                            'required': True,
                            'choices': ['tcp', 'udp', 'icmp', 'other']
                            },
                        'deny': {
                            'type': 'bool',
                            },
                        'glid': {
                            'type': 'str',
                            },
                        'template': {
                            'type': 'dict',
                            'tcp': {
                                'type': 'str',
                                },
                            'udp': {
                                'type': 'str',
                                },
                            'other': {
                                'type': 'str',
                                },
                            'template_icmp_v4': {
                                'type': 'str',
                                },
                            'template_icmp_v6': {
                                'type': 'str',
                                }
                            },
                        'uuid': {
                            'type': 'str',
                            },
                        'user_tag': {
                            'type': 'str',
                            }
                        },
                    'app_type_src_dst_overflow_list': {
                        'type': 'list',
                        'protocol': {
                            'type': 'str',
                            'required': True,
                            'choices': ['dns', 'http', 'ssl-l4', 'sip']
                            },
                        'template': {
                            'type': 'dict',
                            'ssl_l4': {
                                'type': 'str',
                                },
                            'dns': {
                                'type': 'str',
                                },
                            'http': {
                                'type': 'str',
                                },
                            'sip': {
                                'type': 'str',
                                }
                            },
                        'uuid': {
                            'type': 'str',
                            },
                        'user_tag': {
                            'type': 'str',
                            }
                        }
                    }
                }
            },
        'src_dst_pair_settings_list': {
            'type': 'list',
            'all_types': {
                'type': 'str',
                'required': True,
                'choices': ['all-types']
                },
            'age': {
                'type': 'int',
                },
            'max_dynamic_entry_count': {
                'type': 'int',
                },
            'apply_policy_on_overflow': {
                'type': 'bool',
                },
            'unlimited_dynamic_entry_count': {
                'type': 'bool',
                },
            'enable_class_list_overflow': {
                'type': 'bool',
                },
            'src_prefix_len': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'l4_type_src_dst_list': {
                'type': 'list',
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['tcp', 'udp', 'icmp', 'other']
                    },
                'max_dynamic_entry_count': {
                    'type': 'int',
                    },
                'apply_policy_on_overflow': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    }
                }
            },
        'src_dst_pair_class_list_list': {
            'type': 'list',
            'class_list_name': {
                'type': 'str',
                'required': True,
                },
            'exceed_log_cfg': {
                'type': 'dict',
                'log_enable': {
                    'type': 'bool',
                    }
                },
            'log_periodic': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'l4_type_src_dst_list': {
                'type': 'list',
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['tcp', 'udp', 'icmp', 'other']
                    },
                'deny': {
                    'type': 'bool',
                    },
                'glid': {
                    'type': 'str',
                    },
                'template': {
                    'type': 'dict',
                    'tcp': {
                        'type': 'str',
                        },
                    'udp': {
                        'type': 'str',
                        },
                    'other': {
                        'type': 'str',
                        },
                    'template_icmp_v4': {
                        'type': 'str',
                        },
                    'template_icmp_v6': {
                        'type': 'str',
                        }
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    }
                },
            'app_type_src_dst_list': {
                'type': 'list',
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['dns', 'http', 'ssl-l4', 'sip']
                    },
                'template': {
                    'type': 'dict',
                    'ssl_l4': {
                        'type': 'str',
                        },
                    'dns': {
                        'type': 'str',
                        },
                    'http': {
                        'type': 'str',
                        },
                    'sip': {
                        'type': 'str',
                        }
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    }
                },
            'cid_list': {
                'type': 'list',
                'cid_num': {
                    'type': 'int',
                    'required': True,
                    },
                'exceed_log_cfg': {
                    'type': 'dict',
                    'log_enable': {
                        'type': 'bool',
                        }
                    },
                'log_periodic': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'l4_type_src_dst_cid_list': {
                    'type': 'list',
                    'protocol': {
                        'type': 'str',
                        'required': True,
                        'choices': ['tcp', 'udp', 'icmp', 'other']
                        },
                    'deny': {
                        'type': 'bool',
                        },
                    'glid': {
                        'type': 'str',
                        },
                    'template': {
                        'type': 'dict',
                        'tcp': {
                            'type': 'str',
                            },
                        'udp': {
                            'type': 'str',
                            },
                        'other': {
                            'type': 'str',
                            },
                        'template_icmp_v4': {
                            'type': 'str',
                            },
                        'template_icmp_v6': {
                            'type': 'str',
                            }
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        }
                    },
                'app_type_src_dst_cid_list': {
                    'type': 'list',
                    'protocol': {
                        'type': 'str',
                        'required': True,
                        'choices': ['dns', 'http', 'ssl-l4', 'sip']
                        },
                    'template': {
                        'type': 'dict',
                        'ssl_l4': {
                            'type': 'str',
                            },
                        'dns': {
                            'type': 'str',
                            },
                        'http': {
                            'type': 'str',
                            },
                        'sip': {
                            'type': 'str',
                            }
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        }
                    }
                }
            },
        'dynamic_entry_overflow_policy_list': {
            'type': 'list',
            'dummy_name': {
                'type': 'str',
                'required': True,
                'choices': ['configuration']
                },
            'bypass': {
                'type': 'bool',
                },
            'exceed_log_cfg': {
                'type': 'dict',
                'log_enable': {
                    'type': 'bool',
                    }
                },
            'log_periodic': {
                'type': 'bool',
                },
            'template': {
                'type': 'dict',
                'logging': {
                    'type': 'str',
                    }
                },
            'glid': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'l4_type_src_dst_list': {
                'type': 'list',
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['tcp', 'udp', 'icmp', 'other']
                    },
                'deny': {
                    'type': 'bool',
                    },
                'glid': {
                    'type': 'str',
                    },
                'template': {
                    'type': 'dict',
                    'tcp': {
                        'type': 'str',
                        },
                    'udp': {
                        'type': 'str',
                        },
                    'other': {
                        'type': 'str',
                        },
                    'template_icmp_v4': {
                        'type': 'str',
                        },
                    'template_icmp_v6': {
                        'type': 'str',
                        }
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    }
                },
            'app_type_src_dst_list': {
                'type': 'list',
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['dns', 'http', 'ssl-l4', 'sip']
                    },
                'template': {
                    'type': 'dict',
                    'ssl_l4': {
                        'type': 'str',
                        },
                    'dns': {
                        'type': 'str',
                        },
                    'http': {
                        'type': 'str',
                        },
                    'sip': {
                        'type': 'str',
                        }
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    }
                }
            },
        'oper': {
            'type': 'dict',
            'ddos_entry_list': {
                'type': 'list',
                'dst_address_str': {
                    'type': 'str',
                    },
                'src_address_str': {
                    'type': 'str',
                    },
                'port_str': {
                    'type': 'str',
                    },
                'state_str': {
                    'type': 'str',
                    },
                'level_str': {
                    'type': 'str',
                    },
                'current_connections': {
                    'type': 'str',
                    },
                'connection_limit': {
                    'type': 'str',
                    },
                'current_connection_rate': {
                    'type': 'str',
                    },
                'connection_rate_limit': {
                    'type': 'str',
                    },
                'current_packet_rate': {
                    'type': 'str',
                    },
                'packet_rate_limit': {
                    'type': 'str',
                    },
                'current_kBit_rate': {
                    'type': 'str',
                    },
                'kBit_rate_limit': {
                    'type': 'str',
                    },
                'current_frag_packet_rate': {
                    'type': 'str',
                    },
                'frag_packet_rate_limit': {
                    'type': 'str',
                    },
                'current_app_stat1': {
                    'type': 'str',
                    },
                'app_stat1_limit': {
                    'type': 'str',
                    },
                'current_app_stat2': {
                    'type': 'str',
                    },
                'app_stat2_limit': {
                    'type': 'str',
                    },
                'current_app_stat3': {
                    'type': 'str',
                    },
                'app_stat3_limit': {
                    'type': 'str',
                    },
                'current_app_stat4': {
                    'type': 'str',
                    },
                'app_stat4_limit': {
                    'type': 'str',
                    },
                'current_app_stat5': {
                    'type': 'str',
                    },
                'app_stat5_limit': {
                    'type': 'str',
                    },
                'current_app_stat6': {
                    'type': 'str',
                    },
                'app_stat6_limit': {
                    'type': 'str',
                    },
                'current_app_stat7': {
                    'type': 'str',
                    },
                'app_stat7_limit': {
                    'type': 'str',
                    },
                'current_app_stat8': {
                    'type': 'str',
                    },
                'app_stat8_limit': {
                    'type': 'str',
                    },
                'age_str': {
                    'type': 'str',
                    },
                'lockup_time_str': {
                    'type': 'str',
                    },
                'dynamic_entry_count': {
                    'type': 'str',
                    },
                'dynamic_entry_limit': {
                    'type': 'str',
                    },
                'sflow_source_id': {
                    'type': 'str',
                    },
                'debug_str': {
                    'type': 'str',
                    }
                },
            'entry_address_str': {
                'type': 'str',
                },
            'total_dynamic_entry_count': {
                'type': 'str',
                },
            'total_dynamic_entry_limit': {
                'type': 'str',
                },
            'udp_dynamic_entry_count': {
                'type': 'str',
                },
            'udp_dynamic_entry_limit': {
                'type': 'str',
                },
            'tcp_dynamic_entry_count': {
                'type': 'str',
                },
            'tcp_dynamic_entry_limit': {
                'type': 'str',
                },
            'icmp_dynamic_entry_count': {
                'type': 'str',
                },
            'icmp_dynamic_entry_limit': {
                'type': 'str',
                },
            'other_dynamic_entry_count': {
                'type': 'str',
                },
            'other_dynamic_entry_limit': {
                'type': 'str',
                },
            'operational_mode': {
                'type': 'str',
                },
            'traffic_distribution_status': {
                'type': 'list',
                'master_pu': {
                    'type': 'str',
                    },
                'active_pu': {
                    'type': 'list',
                    'pu_id': {
                        'type': 'str',
                        }
                    }
                },
            'dst_entry_name': {
                'type': 'str',
                'required': True,
                },
            'source_entry_limit': {
                'type': 'str',
                },
            'source_entry_alloc': {
                'type': 'str',
                },
            'source_entry_remain': {
                'type': 'str',
                },
            'dst_service_limit': {
                'type': 'str',
                },
            'dst_service_alloc': {
                'type': 'str',
                },
            'dst_service_remain': {
                'type': 'str',
                },
            'entry_displayed_count': {
                'type': 'int',
                },
            'service_displayed_count': {
                'type': 'int',
                },
            'no_t2_idx_port_count': {
                'type': 'int',
                },
            'dst_all_entries': {
                'type': 'bool',
                },
            'sources': {
                'type': 'bool',
                },
            'sources_all_entries': {
                'type': 'bool',
                },
            'overflow_policy': {
                'type': 'bool',
                },
            'entry_count': {
                'type': 'bool',
                },
            'sflow_source_id': {
                'type': 'bool',
                },
            'ipv6': {
                'type': 'str',
                },
            'subnet_ip_addr': {
                'type': 'str',
                },
            'subnet_ipv6_addr': {
                'type': 'str',
                },
            'l4_type_str': {
                'type': 'str',
                },
            'app_type': {
                'type': 'str',
                },
            'exceeded': {
                'type': 'bool',
                },
            'black_listed': {
                'type': 'bool',
                },
            'white_listed': {
                'type': 'bool',
                },
            'authenticated': {
                'type': 'bool',
                },
            'class_list': {
                'type': 'str',
                },
            'ip_proto_num': {
                'type': 'int',
                },
            'port_num': {
                'type': 'int',
                },
            'port_range_start': {
                'type': 'int',
                },
            'port_range_end': {
                'type': 'int',
                },
            'src_port_num': {
                'type': 'int',
                },
            'src_port_range_start': {
                'type': 'int',
                },
            'src_port_range_end': {
                'type': 'int',
                },
            'protocol': {
                'type': 'str',
                },
            'opt_protocol': {
                'type': 'str',
                },
            'sport_protocol': {
                'type': 'str',
                },
            'opt_sport_protocol': {
                'type': 'str',
                },
            'app_stat': {
                'type': 'bool',
                },
            'port_app_stat': {
                'type': 'bool',
                },
            'all_ip_protos': {
                'type': 'bool',
                },
            'all_l4_types': {
                'type': 'bool',
                },
            'all_ports': {
                'type': 'bool',
                },
            'all_src_ports': {
                'type': 'bool',
                },
            'black_holed': {
                'type': 'bool',
                },
            'resource_usage': {
                'type': 'bool',
                },
            'display_traffic_distribution_status': {
                'type': 'bool',
                },
            'entry_status': {
                'type': 'bool',
                },
            'l4_ext_rate': {
                'type': 'bool',
                },
            'hw_blacklisted': {
                'type': 'str',
                },
            'topk_destinations': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'indicators': {
                        'type': 'list',
                        'indicator_name': {
                            'type': 'str',
                            },
                        'indicator_index': {
                            'type': 'int',
                            },
                        'destinations': {
                            'type': 'list',
                            'address': {
                                'type': 'str',
                                },
                            'rate': {
                                'type': 'str',
                                }
                            }
                        },
                    'next_indicator': {
                        'type': 'int',
                        },
                    'finished': {
                        'type': 'int',
                        },
                    'entry_list': {
                        'type': 'list',
                        'address_str': {
                            'type': 'str',
                            },
                        'indicators': {
                            'type': 'list',
                            'indicator_name': {
                                'type': 'str',
                                },
                            'indicator_index': {
                                'type': 'int',
                                },
                            'rate': {
                                'type': 'str',
                                },
                            'max_peak': {
                                'type': 'str',
                                },
                            'psd_wdw_cnt': {
                                'type': 'int',
                                }
                            }
                        },
                    'details': {
                        'type': 'bool',
                        },
                    'top_k_key': {
                        'type': 'str',
                        }
                    }
                },
            'l4_type_list': {
                'type': 'list',
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['tcp', 'udp', 'icmp', 'other']
                    },
                'oper': {
                    'type': 'dict',
                    'ddos_entry_list': {
                        'type': 'list',
                        'dst_address_str': {
                            'type': 'str',
                            },
                        'src_address_str': {
                            'type': 'str',
                            },
                        'port_str': {
                            'type': 'str',
                            },
                        'state_str': {
                            'type': 'str',
                            },
                        'level_str': {
                            'type': 'str',
                            },
                        'current_connections': {
                            'type': 'str',
                            },
                        'connection_limit': {
                            'type': 'str',
                            },
                        'current_connection_rate': {
                            'type': 'str',
                            },
                        'connection_rate_limit': {
                            'type': 'str',
                            },
                        'current_packet_rate': {
                            'type': 'str',
                            },
                        'packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_kBit_rate': {
                            'type': 'str',
                            },
                        'kBit_rate_limit': {
                            'type': 'str',
                            },
                        'current_frag_packet_rate': {
                            'type': 'str',
                            },
                        'frag_packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_app_stat1': {
                            'type': 'str',
                            },
                        'app_stat1_limit': {
                            'type': 'str',
                            },
                        'current_app_stat2': {
                            'type': 'str',
                            },
                        'app_stat2_limit': {
                            'type': 'str',
                            },
                        'current_app_stat3': {
                            'type': 'str',
                            },
                        'app_stat3_limit': {
                            'type': 'str',
                            },
                        'current_app_stat4': {
                            'type': 'str',
                            },
                        'app_stat4_limit': {
                            'type': 'str',
                            },
                        'current_app_stat5': {
                            'type': 'str',
                            },
                        'app_stat5_limit': {
                            'type': 'str',
                            },
                        'current_app_stat6': {
                            'type': 'str',
                            },
                        'app_stat6_limit': {
                            'type': 'str',
                            },
                        'current_app_stat7': {
                            'type': 'str',
                            },
                        'app_stat7_limit': {
                            'type': 'str',
                            },
                        'current_app_stat8': {
                            'type': 'str',
                            },
                        'app_stat8_limit': {
                            'type': 'str',
                            },
                        'age_str': {
                            'type': 'str',
                            },
                        'lockup_time_str': {
                            'type': 'str',
                            },
                        'dynamic_entry_count': {
                            'type': 'str',
                            },
                        'dynamic_entry_limit': {
                            'type': 'str',
                            },
                        'sflow_source_id': {
                            'type': 'str',
                            },
                        'debug_str': {
                            'type': 'str',
                            }
                        },
                    'undefined_port_hit_stats_wellknown': {
                        'type': 'list',
                        'port': {
                            'type': 'str',
                            },
                        'counter': {
                            'type': 'str',
                            }
                        },
                    'undefined_port_hit_stats_non_wellknown': {
                        'type': 'list',
                        'port_start': {
                            'type': 'str',
                            },
                        'port_end': {
                            'type': 'str',
                            },
                        'status': {
                            'type': 'str',
                            }
                        },
                    'entry_displayed_count': {
                        'type': 'int',
                        },
                    'service_displayed_count': {
                        'type': 'int',
                        },
                    'reporting_status': {
                        'type': 'int',
                        },
                    'undefined_port_hit_statistics': {
                        'type': 'bool',
                        },
                    'undefined_stats_port_num': {
                        'type': 'int',
                        },
                    'all_l4_types': {
                        'type': 'bool',
                        },
                    'hw_blacklisted': {
                        'type': 'str',
                        }
                    },
                'port_ind': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'indicators': {
                            'type': 'list',
                            'indicator_name': {
                                'type': 'str',
                                },
                            'indicator_index': {
                                'type': 'int',
                                },
                            'rate': {
                                'type': 'str',
                                },
                            'entry_maximum': {
                                'type': 'str',
                                },
                            'entry_minimum': {
                                'type': 'str',
                                },
                            'entry_non_zero_minimum': {
                                'type': 'str',
                                },
                            'entry_average': {
                                'type': 'str',
                                },
                            'src_maximum': {
                                'type': 'str',
                                }
                            },
                        'detection_data_source': {
                            'type': 'str',
                            }
                        }
                    },
                'topk_sources': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'indicators': {
                            'type': 'list',
                            'indicator_name': {
                                'type': 'str',
                                },
                            'indicator_index': {
                                'type': 'int',
                                },
                            'sources': {
                                'type': 'list',
                                'address': {
                                    'type': 'str',
                                    },
                                'rate': {
                                    'type': 'str',
                                    }
                                }
                            },
                        'next_indicator': {
                            'type': 'int',
                            },
                        'finished': {
                            'type': 'int',
                            },
                        'entry_list': {
                            'type': 'list',
                            'address_str': {
                                'type': 'str',
                                },
                            'indicators': {
                                'type': 'list',
                                'indicator_name': {
                                    'type': 'str',
                                    },
                                'indicator_index': {
                                    'type': 'int',
                                    },
                                'rate': {
                                    'type': 'str',
                                    },
                                'max_peak': {
                                    'type': 'str',
                                    },
                                'psd_wdw_cnt': {
                                    'type': 'int',
                                    }
                                }
                            },
                        'details': {
                            'type': 'bool',
                            },
                        'top_k_key': {
                            'type': 'str',
                            }
                        }
                    },
                'progression_tracking': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'indicators': {
                            'type': 'list',
                            'indicator_name': {
                                'type': 'str',
                                },
                            'indicator_index': {
                                'type': 'int',
                                },
                            'num_sample': {
                                'type': 'int',
                                },
                            'average': {
                                'type': 'str',
                                },
                            'maximum': {
                                'type': 'str',
                                },
                            'minimum': {
                                'type': 'str',
                                },
                            'standard_deviation': {
                                'type': 'str',
                                }
                            }
                        }
                    }
                },
            'port_list': {
                'type': 'list',
                'port_num': {
                    'type': 'int',
                    'required': True,
                    },
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4', 'sip-udp', 'sip-tcp']
                    },
                'oper': {
                    'type': 'dict',
                    'ddos_entry_list': {
                        'type': 'list',
                        'dst_address_str': {
                            'type': 'str',
                            },
                        'src_address_str': {
                            'type': 'str',
                            },
                        'port_str': {
                            'type': 'str',
                            },
                        'state_str': {
                            'type': 'str',
                            },
                        'level_str': {
                            'type': 'str',
                            },
                        'current_connections': {
                            'type': 'str',
                            },
                        'connection_limit': {
                            'type': 'str',
                            },
                        'current_connection_rate': {
                            'type': 'str',
                            },
                        'connection_rate_limit': {
                            'type': 'str',
                            },
                        'current_packet_rate': {
                            'type': 'str',
                            },
                        'packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_kBit_rate': {
                            'type': 'str',
                            },
                        'kBit_rate_limit': {
                            'type': 'str',
                            },
                        'current_frag_packet_rate': {
                            'type': 'str',
                            },
                        'frag_packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_app_stat1': {
                            'type': 'str',
                            },
                        'app_stat1_limit': {
                            'type': 'str',
                            },
                        'current_app_stat2': {
                            'type': 'str',
                            },
                        'app_stat2_limit': {
                            'type': 'str',
                            },
                        'current_app_stat3': {
                            'type': 'str',
                            },
                        'app_stat3_limit': {
                            'type': 'str',
                            },
                        'current_app_stat4': {
                            'type': 'str',
                            },
                        'app_stat4_limit': {
                            'type': 'str',
                            },
                        'current_app_stat5': {
                            'type': 'str',
                            },
                        'app_stat5_limit': {
                            'type': 'str',
                            },
                        'current_app_stat6': {
                            'type': 'str',
                            },
                        'app_stat6_limit': {
                            'type': 'str',
                            },
                        'current_app_stat7': {
                            'type': 'str',
                            },
                        'app_stat7_limit': {
                            'type': 'str',
                            },
                        'current_app_stat8': {
                            'type': 'str',
                            },
                        'app_stat8_limit': {
                            'type': 'str',
                            },
                        'age_str': {
                            'type': 'str',
                            },
                        'lockup_time_str': {
                            'type': 'str',
                            },
                        'dynamic_entry_count': {
                            'type': 'str',
                            },
                        'dynamic_entry_limit': {
                            'type': 'str',
                            },
                        'sflow_source_id': {
                            'type': 'str',
                            },
                        'debug_str': {
                            'type': 'str',
                            }
                        },
                    'resource_limit_config': {
                        'type': 'str',
                        },
                    'reource_limit_alloc': {
                        'type': 'str',
                        },
                    'resource_limit_remain': {
                        'type': 'str',
                        },
                    'entry_displayed_count': {
                        'type': 'int',
                        },
                    'service_displayed_count': {
                        'type': 'int',
                        },
                    'reporting_status': {
                        'type': 'int',
                        },
                    'all_ports': {
                        'type': 'bool',
                        },
                    'all_src_ports': {
                        'type': 'bool',
                        },
                    'all_ip_protos': {
                        'type': 'bool',
                        },
                    'port_protocol': {
                        'type': 'str',
                        },
                    'app_stat': {
                        'type': 'bool',
                        },
                    'sflow_source_id': {
                        'type': 'bool',
                        },
                    'resource_usage': {
                        'type': 'bool',
                        },
                    'l4_ext_rate': {
                        'type': 'bool',
                        },
                    'hw_blacklisted': {
                        'type': 'str',
                        },
                    'suffix_request_rate': {
                        'type': 'bool',
                        },
                    'domain_name': {
                        'type': 'str',
                        }
                    },
                'port_ind': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'indicators': {
                            'type': 'list',
                            'indicator_name': {
                                'type': 'str',
                                },
                            'indicator_index': {
                                'type': 'int',
                                },
                            'rate': {
                                'type': 'str',
                                },
                            'entry_maximum': {
                                'type': 'str',
                                },
                            'entry_minimum': {
                                'type': 'str',
                                },
                            'entry_non_zero_minimum': {
                                'type': 'str',
                                },
                            'entry_average': {
                                'type': 'str',
                                },
                            'src_maximum': {
                                'type': 'str',
                                }
                            },
                        'detection_data_source': {
                            'type': 'str',
                            }
                        }
                    },
                'topk_sources': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'indicators': {
                            'type': 'list',
                            'indicator_name': {
                                'type': 'str',
                                },
                            'indicator_index': {
                                'type': 'int',
                                },
                            'sources': {
                                'type': 'list',
                                'address': {
                                    'type': 'str',
                                    },
                                'rate': {
                                    'type': 'str',
                                    }
                                }
                            },
                        'next_indicator': {
                            'type': 'int',
                            },
                        'finished': {
                            'type': 'int',
                            },
                        'entry_list': {
                            'type': 'list',
                            'address_str': {
                                'type': 'str',
                                },
                            'indicators': {
                                'type': 'list',
                                'indicator_name': {
                                    'type': 'str',
                                    },
                                'indicator_index': {
                                    'type': 'int',
                                    },
                                'rate': {
                                    'type': 'str',
                                    },
                                'max_peak': {
                                    'type': 'str',
                                    },
                                'psd_wdw_cnt': {
                                    'type': 'int',
                                    }
                                }
                            },
                        'details': {
                            'type': 'bool',
                            },
                        'top_k_key': {
                            'type': 'str',
                            }
                        }
                    },
                'progression_tracking': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'indicators': {
                            'type': 'list',
                            'indicator_name': {
                                'type': 'str',
                                },
                            'indicator_index': {
                                'type': 'int',
                                },
                            'num_sample': {
                                'type': 'int',
                                },
                            'average': {
                                'type': 'str',
                                },
                            'maximum': {
                                'type': 'str',
                                },
                            'minimum': {
                                'type': 'str',
                                },
                            'standard_deviation': {
                                'type': 'str',
                                }
                            }
                        }
                    },
                'pattern_recognition': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'state': {
                            'type': 'str',
                            },
                        'timestamp': {
                            'type': 'str',
                            },
                        'peace_pkt_count': {
                            'type': 'int',
                            },
                        'war_pkt_count': {
                            'type': 'int',
                            },
                        'war_pkt_percentage': {
                            'type': 'int',
                            },
                        'filter_threshold': {
                            'type': 'int',
                            },
                        'filter_count': {
                            'type': 'int',
                            },
                        'filter_list': {
                            'type': 'list',
                            'processing_unit': {
                                'type': 'str',
                                },
                            'filter_enabled': {
                                'type': 'int',
                                },
                            'hardware_filter': {
                                'type': 'int',
                                },
                            'filter_expr': {
                                'type': 'str',
                                },
                            'filter_desc': {
                                'type': 'str',
                                },
                            'sample_ratio': {
                                'type': 'int',
                                }
                            }
                        }
                    },
                'pattern_recognition_pu_details': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'all_filters': {
                            'type': 'list',
                            'processing_unit': {
                                'type': 'str',
                                },
                            'state': {
                                'type': 'str',
                                },
                            'timestamp': {
                                'type': 'str',
                                },
                            'peace_pkt_count': {
                                'type': 'int',
                                },
                            'war_pkt_count': {
                                'type': 'int',
                                },
                            'war_pkt_percentage': {
                                'type': 'int',
                                },
                            'filter_threshold': {
                                'type': 'int',
                                },
                            'filter_count': {
                                'type': 'int',
                                },
                            'filter_list': {
                                'type': 'list',
                                'filter_enabled': {
                                    'type': 'int',
                                    },
                                'hardware_filter': {
                                    'type': 'int',
                                    },
                                'filter_expr': {
                                    'type': 'str',
                                    },
                                'filter_desc': {
                                    'type': 'str',
                                    },
                                'sample_ratio': {
                                    'type': 'int',
                                    }
                                }
                            }
                        }
                    }
                },
            'port_range_list': {
                'type': 'list',
                'port_range_start': {
                    'type': 'int',
                    'required': True,
                    },
                'port_range_end': {
                    'type': 'int',
                    'required': True,
                    },
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4', 'sip-udp', 'sip-tcp']
                    },
                'oper': {
                    'type': 'dict',
                    'ddos_entry_list': {
                        'type': 'list',
                        'dst_address_str': {
                            'type': 'str',
                            },
                        'src_address_str': {
                            'type': 'str',
                            },
                        'port_str': {
                            'type': 'str',
                            },
                        'state_str': {
                            'type': 'str',
                            },
                        'level_str': {
                            'type': 'str',
                            },
                        'current_connections': {
                            'type': 'str',
                            },
                        'connection_limit': {
                            'type': 'str',
                            },
                        'current_connection_rate': {
                            'type': 'str',
                            },
                        'connection_rate_limit': {
                            'type': 'str',
                            },
                        'current_packet_rate': {
                            'type': 'str',
                            },
                        'packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_kBit_rate': {
                            'type': 'str',
                            },
                        'kBit_rate_limit': {
                            'type': 'str',
                            },
                        'current_frag_packet_rate': {
                            'type': 'str',
                            },
                        'frag_packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_app_stat1': {
                            'type': 'str',
                            },
                        'app_stat1_limit': {
                            'type': 'str',
                            },
                        'current_app_stat2': {
                            'type': 'str',
                            },
                        'app_stat2_limit': {
                            'type': 'str',
                            },
                        'current_app_stat3': {
                            'type': 'str',
                            },
                        'app_stat3_limit': {
                            'type': 'str',
                            },
                        'current_app_stat4': {
                            'type': 'str',
                            },
                        'app_stat4_limit': {
                            'type': 'str',
                            },
                        'current_app_stat5': {
                            'type': 'str',
                            },
                        'app_stat5_limit': {
                            'type': 'str',
                            },
                        'current_app_stat6': {
                            'type': 'str',
                            },
                        'app_stat6_limit': {
                            'type': 'str',
                            },
                        'current_app_stat7': {
                            'type': 'str',
                            },
                        'app_stat7_limit': {
                            'type': 'str',
                            },
                        'current_app_stat8': {
                            'type': 'str',
                            },
                        'app_stat8_limit': {
                            'type': 'str',
                            },
                        'age_str': {
                            'type': 'str',
                            },
                        'lockup_time_str': {
                            'type': 'str',
                            },
                        'dynamic_entry_count': {
                            'type': 'str',
                            },
                        'dynamic_entry_limit': {
                            'type': 'str',
                            },
                        'sflow_source_id': {
                            'type': 'str',
                            },
                        'debug_str': {
                            'type': 'str',
                            }
                        },
                    'resource_limit_config': {
                        'type': 'str',
                        },
                    'reource_limit_alloc': {
                        'type': 'str',
                        },
                    'resource_limit_remain': {
                        'type': 'str',
                        },
                    'entry_displayed_count': {
                        'type': 'int',
                        },
                    'service_displayed_count': {
                        'type': 'int',
                        },
                    'reporting_status': {
                        'type': 'int',
                        },
                    'all_ports': {
                        'type': 'bool',
                        },
                    'all_src_ports': {
                        'type': 'bool',
                        },
                    'all_ip_protos': {
                        'type': 'bool',
                        },
                    'port_protocol': {
                        'type': 'str',
                        },
                    'app_stat': {
                        'type': 'bool',
                        },
                    'sflow_source_id': {
                        'type': 'bool',
                        },
                    'resource_usage': {
                        'type': 'bool',
                        },
                    'l4_ext_rate': {
                        'type': 'bool',
                        },
                    'hw_blacklisted': {
                        'type': 'str',
                        },
                    'suffix_request_rate': {
                        'type': 'bool',
                        },
                    'domain_name': {
                        'type': 'str',
                        }
                    },
                'port_ind': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'indicators': {
                            'type': 'list',
                            'indicator_name': {
                                'type': 'str',
                                },
                            'indicator_index': {
                                'type': 'int',
                                },
                            'rate': {
                                'type': 'str',
                                },
                            'entry_maximum': {
                                'type': 'str',
                                },
                            'entry_minimum': {
                                'type': 'str',
                                },
                            'entry_non_zero_minimum': {
                                'type': 'str',
                                },
                            'entry_average': {
                                'type': 'str',
                                },
                            'src_maximum': {
                                'type': 'str',
                                }
                            },
                        'detection_data_source': {
                            'type': 'str',
                            }
                        }
                    },
                'topk_sources': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'indicators': {
                            'type': 'list',
                            'indicator_name': {
                                'type': 'str',
                                },
                            'indicator_index': {
                                'type': 'int',
                                },
                            'sources': {
                                'type': 'list',
                                'address': {
                                    'type': 'str',
                                    },
                                'rate': {
                                    'type': 'str',
                                    }
                                }
                            },
                        'next_indicator': {
                            'type': 'int',
                            },
                        'finished': {
                            'type': 'int',
                            },
                        'entry_list': {
                            'type': 'list',
                            'address_str': {
                                'type': 'str',
                                },
                            'indicators': {
                                'type': 'list',
                                'indicator_name': {
                                    'type': 'str',
                                    },
                                'indicator_index': {
                                    'type': 'int',
                                    },
                                'rate': {
                                    'type': 'str',
                                    },
                                'max_peak': {
                                    'type': 'str',
                                    },
                                'psd_wdw_cnt': {
                                    'type': 'int',
                                    }
                                }
                            },
                        'details': {
                            'type': 'bool',
                            },
                        'top_k_key': {
                            'type': 'str',
                            }
                        }
                    },
                'progression_tracking': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'indicators': {
                            'type': 'list',
                            'indicator_name': {
                                'type': 'str',
                                },
                            'indicator_index': {
                                'type': 'int',
                                },
                            'num_sample': {
                                'type': 'int',
                                },
                            'average': {
                                'type': 'str',
                                },
                            'maximum': {
                                'type': 'str',
                                },
                            'minimum': {
                                'type': 'str',
                                },
                            'standard_deviation': {
                                'type': 'str',
                                }
                            }
                        }
                    },
                'pattern_recognition': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'state': {
                            'type': 'str',
                            },
                        'timestamp': {
                            'type': 'str',
                            },
                        'peace_pkt_count': {
                            'type': 'int',
                            },
                        'war_pkt_count': {
                            'type': 'int',
                            },
                        'war_pkt_percentage': {
                            'type': 'int',
                            },
                        'filter_threshold': {
                            'type': 'int',
                            },
                        'filter_count': {
                            'type': 'int',
                            },
                        'filter_list': {
                            'type': 'list',
                            'processing_unit': {
                                'type': 'str',
                                },
                            'filter_enabled': {
                                'type': 'int',
                                },
                            'hardware_filter': {
                                'type': 'int',
                                },
                            'filter_expr': {
                                'type': 'str',
                                },
                            'filter_desc': {
                                'type': 'str',
                                },
                            'sample_ratio': {
                                'type': 'int',
                                }
                            }
                        }
                    },
                'pattern_recognition_pu_details': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'all_filters': {
                            'type': 'list',
                            'processing_unit': {
                                'type': 'str',
                                },
                            'state': {
                                'type': 'str',
                                },
                            'timestamp': {
                                'type': 'str',
                                },
                            'peace_pkt_count': {
                                'type': 'int',
                                },
                            'war_pkt_count': {
                                'type': 'int',
                                },
                            'war_pkt_percentage': {
                                'type': 'int',
                                },
                            'filter_threshold': {
                                'type': 'int',
                                },
                            'filter_count': {
                                'type': 'int',
                                },
                            'filter_list': {
                                'type': 'list',
                                'filter_enabled': {
                                    'type': 'int',
                                    },
                                'hardware_filter': {
                                    'type': 'int',
                                    },
                                'filter_expr': {
                                    'type': 'str',
                                    },
                                'filter_desc': {
                                    'type': 'str',
                                    },
                                'sample_ratio': {
                                    'type': 'int',
                                    }
                                }
                            }
                        }
                    }
                },
            'src_port_list': {
                'type': 'list',
                'port_num': {
                    'type': 'int',
                    'required': True,
                    },
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['dns-udp', 'dns-tcp', 'udp', 'tcp']
                    },
                'oper': {
                    'type': 'dict',
                    'ddos_entry_list': {
                        'type': 'list',
                        'dst_address_str': {
                            'type': 'str',
                            },
                        'src_address_str': {
                            'type': 'str',
                            },
                        'port_str': {
                            'type': 'str',
                            },
                        'state_str': {
                            'type': 'str',
                            },
                        'level_str': {
                            'type': 'str',
                            },
                        'current_connections': {
                            'type': 'str',
                            },
                        'connection_limit': {
                            'type': 'str',
                            },
                        'current_connection_rate': {
                            'type': 'str',
                            },
                        'connection_rate_limit': {
                            'type': 'str',
                            },
                        'current_packet_rate': {
                            'type': 'str',
                            },
                        'packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_kBit_rate': {
                            'type': 'str',
                            },
                        'kBit_rate_limit': {
                            'type': 'str',
                            },
                        'current_frag_packet_rate': {
                            'type': 'str',
                            },
                        'frag_packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_app_stat1': {
                            'type': 'str',
                            },
                        'app_stat1_limit': {
                            'type': 'str',
                            },
                        'current_app_stat2': {
                            'type': 'str',
                            },
                        'app_stat2_limit': {
                            'type': 'str',
                            },
                        'current_app_stat3': {
                            'type': 'str',
                            },
                        'app_stat3_limit': {
                            'type': 'str',
                            },
                        'current_app_stat4': {
                            'type': 'str',
                            },
                        'app_stat4_limit': {
                            'type': 'str',
                            },
                        'current_app_stat5': {
                            'type': 'str',
                            },
                        'app_stat5_limit': {
                            'type': 'str',
                            },
                        'current_app_stat6': {
                            'type': 'str',
                            },
                        'app_stat6_limit': {
                            'type': 'str',
                            },
                        'current_app_stat7': {
                            'type': 'str',
                            },
                        'app_stat7_limit': {
                            'type': 'str',
                            },
                        'current_app_stat8': {
                            'type': 'str',
                            },
                        'app_stat8_limit': {
                            'type': 'str',
                            },
                        'age_str': {
                            'type': 'str',
                            },
                        'lockup_time_str': {
                            'type': 'str',
                            },
                        'dynamic_entry_count': {
                            'type': 'str',
                            },
                        'dynamic_entry_limit': {
                            'type': 'str',
                            },
                        'sflow_source_id': {
                            'type': 'str',
                            },
                        'debug_str': {
                            'type': 'str',
                            }
                        },
                    'entry_displayed_count': {
                        'type': 'int',
                        },
                    'service_displayed_count': {
                        'type': 'int',
                        },
                    'reporting_status': {
                        'type': 'int',
                        },
                    'all_ports': {
                        'type': 'bool',
                        },
                    'all_src_ports': {
                        'type': 'bool',
                        },
                    'all_ip_protos': {
                        'type': 'bool',
                        },
                    'port_protocol': {
                        'type': 'str',
                        },
                    'app_stat': {
                        'type': 'bool',
                        },
                    'sflow_source_id': {
                        'type': 'bool',
                        },
                    'hw_blacklisted': {
                        'type': 'str',
                        },
                    'suffix_request_rate': {
                        'type': 'bool',
                        },
                    'domain_name': {
                        'type': 'str',
                        }
                    }
                },
            'src_port_range_list': {
                'type': 'list',
                'src_port_range_start': {
                    'type': 'int',
                    'required': True,
                    },
                'src_port_range_end': {
                    'type': 'int',
                    'required': True,
                    },
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['udp', 'tcp']
                    },
                'oper': {
                    'type': 'dict',
                    'ddos_entry_list': {
                        'type': 'list',
                        'dst_address_str': {
                            'type': 'str',
                            },
                        'src_address_str': {
                            'type': 'str',
                            },
                        'port_str': {
                            'type': 'str',
                            },
                        'state_str': {
                            'type': 'str',
                            },
                        'level_str': {
                            'type': 'str',
                            },
                        'current_connections': {
                            'type': 'str',
                            },
                        'connection_limit': {
                            'type': 'str',
                            },
                        'current_connection_rate': {
                            'type': 'str',
                            },
                        'connection_rate_limit': {
                            'type': 'str',
                            },
                        'current_packet_rate': {
                            'type': 'str',
                            },
                        'packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_kBit_rate': {
                            'type': 'str',
                            },
                        'kBit_rate_limit': {
                            'type': 'str',
                            },
                        'current_frag_packet_rate': {
                            'type': 'str',
                            },
                        'frag_packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_app_stat1': {
                            'type': 'str',
                            },
                        'app_stat1_limit': {
                            'type': 'str',
                            },
                        'current_app_stat2': {
                            'type': 'str',
                            },
                        'app_stat2_limit': {
                            'type': 'str',
                            },
                        'current_app_stat3': {
                            'type': 'str',
                            },
                        'app_stat3_limit': {
                            'type': 'str',
                            },
                        'current_app_stat4': {
                            'type': 'str',
                            },
                        'app_stat4_limit': {
                            'type': 'str',
                            },
                        'current_app_stat5': {
                            'type': 'str',
                            },
                        'app_stat5_limit': {
                            'type': 'str',
                            },
                        'current_app_stat6': {
                            'type': 'str',
                            },
                        'app_stat6_limit': {
                            'type': 'str',
                            },
                        'current_app_stat7': {
                            'type': 'str',
                            },
                        'app_stat7_limit': {
                            'type': 'str',
                            },
                        'current_app_stat8': {
                            'type': 'str',
                            },
                        'app_stat8_limit': {
                            'type': 'str',
                            },
                        'age_str': {
                            'type': 'str',
                            },
                        'lockup_time_str': {
                            'type': 'str',
                            },
                        'dynamic_entry_count': {
                            'type': 'str',
                            },
                        'dynamic_entry_limit': {
                            'type': 'str',
                            },
                        'sflow_source_id': {
                            'type': 'str',
                            },
                        'debug_str': {
                            'type': 'str',
                            }
                        },
                    'entry_displayed_count': {
                        'type': 'int',
                        },
                    'service_displayed_count': {
                        'type': 'int',
                        },
                    'reporting_status': {
                        'type': 'int',
                        },
                    'all_ports': {
                        'type': 'bool',
                        },
                    'all_src_ports': {
                        'type': 'bool',
                        },
                    'all_ip_protos': {
                        'type': 'bool',
                        },
                    'port_protocol': {
                        'type': 'str',
                        },
                    'app_stat': {
                        'type': 'bool',
                        },
                    'sflow_source_id': {
                        'type': 'bool',
                        },
                    'hw_blacklisted': {
                        'type': 'str',
                        },
                    'suffix_request_rate': {
                        'type': 'bool',
                        },
                    'domain_name': {
                        'type': 'str',
                        }
                    }
                },
            'ip_proto_list': {
                'type': 'list',
                'port_num': {
                    'type': 'int',
                    'required': True,
                    },
                'oper': {
                    'type': 'dict',
                    'ddos_entry_list': {
                        'type': 'list',
                        'dst_address_str': {
                            'type': 'str',
                            },
                        'src_address_str': {
                            'type': 'str',
                            },
                        'port_str': {
                            'type': 'str',
                            },
                        'state_str': {
                            'type': 'str',
                            },
                        'level_str': {
                            'type': 'str',
                            },
                        'current_connections': {
                            'type': 'str',
                            },
                        'connection_limit': {
                            'type': 'str',
                            },
                        'current_connection_rate': {
                            'type': 'str',
                            },
                        'connection_rate_limit': {
                            'type': 'str',
                            },
                        'current_packet_rate': {
                            'type': 'str',
                            },
                        'packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_kBit_rate': {
                            'type': 'str',
                            },
                        'kBit_rate_limit': {
                            'type': 'str',
                            },
                        'current_frag_packet_rate': {
                            'type': 'str',
                            },
                        'frag_packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_app_stat1': {
                            'type': 'str',
                            },
                        'app_stat1_limit': {
                            'type': 'str',
                            },
                        'current_app_stat2': {
                            'type': 'str',
                            },
                        'app_stat2_limit': {
                            'type': 'str',
                            },
                        'current_app_stat3': {
                            'type': 'str',
                            },
                        'app_stat3_limit': {
                            'type': 'str',
                            },
                        'current_app_stat4': {
                            'type': 'str',
                            },
                        'app_stat4_limit': {
                            'type': 'str',
                            },
                        'current_app_stat5': {
                            'type': 'str',
                            },
                        'app_stat5_limit': {
                            'type': 'str',
                            },
                        'current_app_stat6': {
                            'type': 'str',
                            },
                        'app_stat6_limit': {
                            'type': 'str',
                            },
                        'current_app_stat7': {
                            'type': 'str',
                            },
                        'app_stat7_limit': {
                            'type': 'str',
                            },
                        'current_app_stat8': {
                            'type': 'str',
                            },
                        'app_stat8_limit': {
                            'type': 'str',
                            },
                        'age_str': {
                            'type': 'str',
                            },
                        'lockup_time_str': {
                            'type': 'str',
                            },
                        'dynamic_entry_count': {
                            'type': 'str',
                            },
                        'dynamic_entry_limit': {
                            'type': 'str',
                            },
                        'sflow_source_id': {
                            'type': 'str',
                            },
                        'debug_str': {
                            'type': 'str',
                            }
                        },
                    'entry_displayed_count': {
                        'type': 'int',
                        },
                    'service_displayed_count': {
                        'type': 'int',
                        },
                    'reporting_status': {
                        'type': 'int',
                        },
                    'all_ports': {
                        'type': 'bool',
                        },
                    'all_src_ports': {
                        'type': 'bool',
                        },
                    'all_ip_protos': {
                        'type': 'bool',
                        },
                    'port_protocol': {
                        'type': 'str',
                        },
                    'app_stat': {
                        'type': 'bool',
                        },
                    'sflow_source_id': {
                        'type': 'bool',
                        },
                    'hw_blacklisted': {
                        'type': 'str',
                        },
                    'suffix_request_rate': {
                        'type': 'bool',
                        },
                    'domain_name': {
                        'type': 'str',
                        }
                    }
                }
            },
        'stats': {
            'type': 'dict',
            'dst_tcp_any_exceed': {
                'type': 'str',
                },
            'dst_tcp_pkt_rate_exceed': {
                'type': 'str',
                },
            'dst_tcp_conn_rate_exceed': {
                'type': 'str',
                },
            'dst_udp_any_exceed': {
                'type': 'str',
                },
            'dst_udp_pkt_rate_exceed': {
                'type': 'str',
                },
            'dst_udp_conn_limit_exceed': {
                'type': 'str',
                },
            'dst_udp_conn_rate_exceed': {
                'type': 'str',
                },
            'dst_icmp_pkt_rate_exceed': {
                'type': 'str',
                },
            'dst_other_pkt_rate_exceed': {
                'type': 'str',
                },
            'dst_other_frag_pkt_rate_exceed': {
                'type': 'str',
                },
            'dst_port_pkt_rate_exceed': {
                'type': 'str',
                },
            'dst_port_conn_limit_exceed': {
                'type': 'str',
                },
            'dst_port_conn_rate_exceed': {
                'type': 'str',
                },
            'dst_pkt_sent': {
                'type': 'str',
                },
            'dst_udp_pkt_sent': {
                'type': 'str',
                },
            'dst_tcp_pkt_sent': {
                'type': 'str',
                },
            'dst_icmp_pkt_sent': {
                'type': 'str',
                },
            'dst_other_pkt_sent': {
                'type': 'str',
                },
            'dst_tcp_conn_limit_exceed': {
                'type': 'str',
                },
            'dst_tcp_pkt_rcvd': {
                'type': 'str',
                },
            'dst_udp_pkt_rcvd': {
                'type': 'str',
                },
            'dst_icmp_pkt_rcvd': {
                'type': 'str',
                },
            'dst_other_pkt_rcvd': {
                'type': 'str',
                },
            'dst_udp_filter_match': {
                'type': 'str',
                },
            'dst_udp_filter_not_match': {
                'type': 'str',
                },
            'dst_udp_filter_action_blacklist': {
                'type': 'str',
                },
            'dst_udp_filter_action_drop': {
                'type': 'str',
                },
            'dst_tcp_syn': {
                'type': 'str',
                },
            'dst_tcp_syn_drop': {
                'type': 'str',
                },
            'dst_tcp_src_rate_drop': {
                'type': 'str',
                },
            'dst_udp_src_rate_drop': {
                'type': 'str',
                },
            'dst_icmp_src_rate_drop': {
                'type': 'str',
                },
            'dst_other_frag_src_rate_drop': {
                'type': 'str',
                },
            'dst_other_src_rate_drop': {
                'type': 'str',
                },
            'dst_tcp_drop': {
                'type': 'str',
                },
            'dst_udp_drop': {
                'type': 'str',
                },
            'dst_icmp_drop': {
                'type': 'str',
                },
            'dst_frag_drop': {
                'type': 'str',
                },
            'dst_other_drop': {
                'type': 'str',
                },
            'dst_tcp_auth': {
                'type': 'str',
                },
            'dst_udp_filter_action_default_pass': {
                'type': 'str',
                },
            'dst_tcp_filter_match': {
                'type': 'str',
                },
            'dst_tcp_filter_not_match': {
                'type': 'str',
                },
            'dst_tcp_filter_action_blacklist': {
                'type': 'str',
                },
            'dst_tcp_filter_action_drop': {
                'type': 'str',
                },
            'dst_tcp_filter_action_default_pass': {
                'type': 'str',
                },
            'dst_udp_filter_action_whitelist': {
                'type': 'str',
                },
            'dst_udp_kibit_rate_drop': {
                'type': 'str',
                },
            'dst_tcp_kibit_rate_drop': {
                'type': 'str',
                },
            'dst_icmp_kibit_rate_drop': {
                'type': 'str',
                },
            'dst_other_kibit_rate_drop': {
                'type': 'str',
                },
            'dst_port_undef_drop': {
                'type': 'str',
                },
            'dst_port_bl': {
                'type': 'str',
                },
            'dst_src_port_bl': {
                'type': 'str',
                },
            'dst_port_kbit_rate_exceed': {
                'type': 'str',
                },
            'dst_tcp_src_drop': {
                'type': 'str',
                },
            'dst_udp_src_drop': {
                'type': 'str',
                },
            'dst_icmp_src_drop': {
                'type': 'str',
                },
            'dst_other_src_drop': {
                'type': 'str',
                },
            'tcp_syn_rcvd': {
                'type': 'str',
                },
            'tcp_syn_ack_rcvd': {
                'type': 'str',
                },
            'tcp_ack_rcvd': {
                'type': 'str',
                },
            'tcp_fin_rcvd': {
                'type': 'str',
                },
            'tcp_rst_rcvd': {
                'type': 'str',
                },
            'ingress_bytes': {
                'type': 'str',
                },
            'egress_bytes': {
                'type': 'str',
                },
            'ingress_packets': {
                'type': 'str',
                },
            'egress_packets': {
                'type': 'str',
                },
            'tcp_fwd_recv': {
                'type': 'str',
                },
            'udp_fwd_recv': {
                'type': 'str',
                },
            'icmp_fwd_recv': {
                'type': 'str',
                },
            'tcp_syn_cookie_fail': {
                'type': 'str',
                },
            'dst_tcp_session_created': {
                'type': 'str',
                },
            'dst_udp_session_created': {
                'type': 'str',
                },
            'dst_tcp_filter_action_whitelist': {
                'type': 'str',
                },
            'dst_other_filter_match': {
                'type': 'str',
                },
            'dst_other_filter_not_match': {
                'type': 'str',
                },
            'dst_other_filter_action_blacklist': {
                'type': 'str',
                },
            'dst_other_filter_action_drop': {
                'type': 'str',
                },
            'dst_other_filter_action_whitelist': {
                'type': 'str',
                },
            'dst_other_filter_action_default_pass': {
                'type': 'str',
                },
            'dst_blackhole_inject': {
                'type': 'str',
                },
            'dst_blackhole_withdraw': {
                'type': 'str',
                },
            'dst_tcp_out_of_seq_excd': {
                'type': 'str',
                },
            'dst_tcp_retransmit_excd': {
                'type': 'str',
                },
            'dst_tcp_zero_window_excd': {
                'type': 'str',
                },
            'dst_tcp_conn_prate_excd': {
                'type': 'str',
                },
            'dst_tcp_action_on_ack_init': {
                'type': 'str',
                },
            'dst_tcp_action_on_ack_gap_drop': {
                'type': 'str',
                },
            'dst_tcp_action_on_ack_fail': {
                'type': 'str',
                },
            'dst_tcp_action_on_ack_pass': {
                'type': 'str',
                },
            'dst_tcp_action_on_syn_init': {
                'type': 'str',
                },
            'dst_tcp_action_on_syn_gap_drop': {
                'type': 'str',
                },
            'dst_tcp_action_on_syn_fail': {
                'type': 'str',
                },
            'dst_tcp_action_on_syn_pass': {
                'type': 'str',
                },
            'udp_payload_too_small': {
                'type': 'str',
                },
            'udp_payload_too_big': {
                'type': 'str',
                },
            'dst_udp_conn_prate_excd': {
                'type': 'str',
                },
            'dst_udp_ntp_monlist_req': {
                'type': 'str',
                },
            'dst_udp_ntp_monlist_resp': {
                'type': 'str',
                },
            'dst_udp_wellknown_sport_drop': {
                'type': 'str',
                },
            'dst_udp_retry_init': {
                'type': 'str',
                },
            'dst_udp_retry_pass': {
                'type': 'str',
                },
            'dst_tcp_bytes_drop': {
                'type': 'str',
                },
            'dst_udp_bytes_drop': {
                'type': 'str',
                },
            'dst_icmp_bytes_drop': {
                'type': 'str',
                },
            'dst_other_bytes_drop': {
                'type': 'str',
                },
            'dst_out_no_route': {
                'type': 'str',
                },
            'outbound_bytes_sent': {
                'type': 'str',
                },
            'outbound_pkt_drop': {
                'type': 'str',
                },
            'outbound_bytes_drop': {
                'type': 'str',
                },
            'outbound_pkt_sent': {
                'type': 'str',
                },
            'inbound_bytes_sent': {
                'type': 'str',
                },
            'inbound_bytes_drop': {
                'type': 'str',
                },
            'dst_src_port_pkt_rate_exceed': {
                'type': 'str',
                },
            'dst_src_port_kbit_rate_exceed': {
                'type': 'str',
                },
            'dst_src_port_conn_limit_exceed': {
                'type': 'str',
                },
            'dst_src_port_conn_rate_exceed': {
                'type': 'str',
                },
            'dst_ip_proto_pkt_rate_exceed': {
                'type': 'str',
                },
            'dst_ip_proto_kbit_rate_exceed': {
                'type': 'str',
                },
            'dst_tcp_port_any_exceed': {
                'type': 'str',
                },
            'dst_udp_port_any_exceed': {
                'type': 'str',
                },
            'dst_tcp_auth_pass': {
                'type': 'str',
                },
            'dst_tcp_rst_cookie_fail': {
                'type': 'str',
                },
            'dst_tcp_unauth_drop': {
                'type': 'str',
                },
            'src_tcp_syn_auth_fail': {
                'type': 'str',
                },
            'src_tcp_syn_cookie_sent': {
                'type': 'str',
                },
            'src_tcp_syn_cookie_fail': {
                'type': 'str',
                },
            'src_tcp_rst_cookie_fail': {
                'type': 'str',
                },
            'src_tcp_unauth_drop': {
                'type': 'str',
                },
            'src_tcp_action_on_syn_init': {
                'type': 'str',
                },
            'src_tcp_action_on_syn_gap_drop': {
                'type': 'str',
                },
            'src_tcp_action_on_syn_fail': {
                'type': 'str',
                },
            'src_tcp_action_on_ack_init': {
                'type': 'str',
                },
            'src_tcp_action_on_ack_gap_drop': {
                'type': 'str',
                },
            'src_tcp_action_on_ack_fail': {
                'type': 'str',
                },
            'src_tcp_out_of_seq_excd': {
                'type': 'str',
                },
            'src_tcp_retransmit_excd': {
                'type': 'str',
                },
            'src_tcp_zero_window_excd': {
                'type': 'str',
                },
            'src_tcp_conn_prate_excd': {
                'type': 'str',
                },
            'src_udp_min_payload': {
                'type': 'str',
                },
            'src_udp_max_payload': {
                'type': 'str',
                },
            'src_udp_conn_prate_excd': {
                'type': 'str',
                },
            'src_udp_ntp_monlist_req': {
                'type': 'str',
                },
            'src_udp_ntp_monlist_resp': {
                'type': 'str',
                },
            'src_udp_wellknown_sport_drop': {
                'type': 'str',
                },
            'src_udp_retry_init': {
                'type': 'str',
                },
            'dst_udp_retry_gap_drop': {
                'type': 'str',
                },
            'dst_udp_retry_fail': {
                'type': 'str',
                },
            'dst_tcp_session_aged': {
                'type': 'str',
                },
            'dst_udp_session_aged': {
                'type': 'str',
                },
            'dst_tcp_conn_close': {
                'type': 'str',
                },
            'dst_tcp_conn_close_half_open': {
                'type': 'str',
                },
            'dst_l4_tcp_auth': {
                'type': 'str',
                },
            'tcp_l4_syn_cookie_fail': {
                'type': 'str',
                },
            'tcp_l4_rst_cookie_fail': {
                'type': 'str',
                },
            'tcp_l4_unauth_drop': {
                'type': 'str',
                },
            'src_tcp_filter_action_blacklist': {
                'type': 'str',
                },
            'src_tcp_filter_action_whitelist': {
                'type': 'str',
                },
            'src_tcp_filter_action_drop': {
                'type': 'str',
                },
            'src_tcp_filter_action_default_pass': {
                'type': 'str',
                },
            'src_udp_filter_action_blacklist': {
                'type': 'str',
                },
            'src_udp_filter_action_whitelist': {
                'type': 'str',
                },
            'src_udp_filter_action_drop': {
                'type': 'str',
                },
            'src_udp_filter_action_default_pass': {
                'type': 'str',
                },
            'src_other_filter_action_blacklist': {
                'type': 'str',
                },
            'src_other_filter_action_whitelist': {
                'type': 'str',
                },
            'src_other_filter_action_drop': {
                'type': 'str',
                },
            'src_other_filter_action_default_pass': {
                'type': 'str',
                },
            'tcp_invalid_syn': {
                'type': 'str',
                },
            'dst_tcp_conn_close_w_rst': {
                'type': 'str',
                },
            'dst_tcp_conn_close_w_fin': {
                'type': 'str',
                },
            'dst_tcp_conn_close_w_idle': {
                'type': 'str',
                },
            'dst_tcp_conn_create_from_syn': {
                'type': 'str',
                },
            'dst_tcp_conn_create_from_ack': {
                'type': 'str',
                },
            'src_frag_drop': {
                'type': 'str',
                },
            'dst_l4_tcp_blacklist_drop': {
                'type': 'str',
                },
            'dst_l4_udp_blacklist_drop': {
                'type': 'str',
                },
            'dst_l4_icmp_blacklist_drop': {
                'type': 'str',
                },
            'dst_l4_other_blacklist_drop': {
                'type': 'str',
                },
            'src_l4_tcp_blacklist_drop': {
                'type': 'str',
                },
            'src_l4_udp_blacklist_drop': {
                'type': 'str',
                },
            'src_l4_icmp_blacklist_drop': {
                'type': 'str',
                },
            'src_l4_other_blacklist_drop': {
                'type': 'str',
                },
            'dst_port_kbit_rate_exceed_pkt': {
                'type': 'str',
                },
            'dst_tcp_bytes_rcv': {
                'type': 'str',
                },
            'dst_udp_bytes_rcv': {
                'type': 'str',
                },
            'dst_icmp_bytes_rcv': {
                'type': 'str',
                },
            'dst_other_bytes_rcv': {
                'type': 'str',
                },
            'dst_tcp_bytes_sent': {
                'type': 'str',
                },
            'dst_udp_bytes_sent': {
                'type': 'str',
                },
            'dst_icmp_bytes_sent': {
                'type': 'str',
                },
            'dst_other_bytes_sent': {
                'type': 'str',
                },
            'dst_udp_auth_drop': {
                'type': 'str',
                },
            'dst_tcp_auth_drop': {
                'type': 'str',
                },
            'dst_tcp_auth_resp': {
                'type': 'str',
                },
            'inbound_pkt_drop': {
                'type': 'str',
                },
            'dst_entry_pkt_rate_exceed': {
                'type': 'str',
                },
            'dst_entry_kbit_rate_exceed': {
                'type': 'str',
                },
            'dst_entry_conn_limit_exceed': {
                'type': 'str',
                },
            'dst_entry_conn_rate_exceed': {
                'type': 'str',
                },
            'dst_entry_frag_pkt_rate_exceed': {
                'type': 'str',
                },
            'dst_icmp_any_exceed': {
                'type': 'str',
                },
            'dst_other_any_exceed': {
                'type': 'str',
                },
            'src_dst_pair_entry_total': {
                'type': 'str',
                },
            'src_dst_pair_entry_udp': {
                'type': 'str',
                },
            'src_dst_pair_entry_tcp': {
                'type': 'str',
                },
            'src_dst_pair_entry_icmp': {
                'type': 'str',
                },
            'src_dst_pair_entry_other': {
                'type': 'str',
                },
            'dst_clist_overflow_policy_at_learning': {
                'type': 'str',
                },
            'tcp_rexmit_syn_limit_drop': {
                'type': 'str',
                },
            'tcp_rexmit_syn_limit_bl': {
                'type': 'str',
                },
            'dst_tcp_wellknown_sport_drop': {
                'type': 'str',
                },
            'src_tcp_wellknown_sport_drop': {
                'type': 'str',
                },
            'dst_frag_rcvd': {
                'type': 'str',
                },
            'no_policy_class_list_match': {
                'type': 'str',
                },
            'src_udp_retry_gap_drop': {
                'type': 'str',
                },
            'dst_entry_kbit_rate_exceed_count': {
                'type': 'str',
                },
            'dst_port_undef_hit': {
                'type': 'str',
                },
            'dst_tcp_action_on_ack_timeout': {
                'type': 'str',
                },
            'dst_tcp_action_on_ack_reset': {
                'type': 'str',
                },
            'dst_tcp_action_on_ack_blacklist': {
                'type': 'str',
                },
            'src_tcp_action_on_ack_timeout': {
                'type': 'str',
                },
            'src_tcp_action_on_ack_reset': {
                'type': 'str',
                },
            'src_tcp_action_on_ack_blacklist': {
                'type': 'str',
                },
            'dst_tcp_action_on_syn_timeout': {
                'type': 'str',
                },
            'dst_tcp_action_on_syn_reset': {
                'type': 'str',
                },
            'dst_tcp_action_on_syn_blacklist': {
                'type': 'str',
                },
            'src_tcp_action_on_syn_timeout': {
                'type': 'str',
                },
            'src_tcp_action_on_syn_reset': {
                'type': 'str',
                },
            'src_tcp_action_on_syn_blacklist': {
                'type': 'str',
                },
            'dst_udp_frag_pkt_rate_exceed': {
                'type': 'str',
                },
            'dst_udp_frag_src_rate_drop': {
                'type': 'str',
                },
            'dst_tcp_frag_pkt_rate_exceed': {
                'type': 'str',
                },
            'dst_tcp_frag_src_rate_drop': {
                'type': 'str',
                },
            'dst_icmp_frag_pkt_rate_exceed': {
                'type': 'str',
                },
            'dst_icmp_frag_src_rate_drop': {
                'type': 'str',
                },
            'sflow_internal_samples_packed': {
                'type': 'str',
                },
            'sflow_external_samples_packed': {
                'type': 'str',
                },
            'sflow_internal_packets_sent': {
                'type': 'str',
                },
            'sflow_external_packets_sent': {
                'type': 'str',
                },
            'dns_outbound_total_query': {
                'type': 'str',
                },
            'dns_outbound_query_malformed': {
                'type': 'str',
                },
            'dns_outbound_query_resp_chk_failed': {
                'type': 'str',
                },
            'dns_outbound_query_resp_chk_blacklisted': {
                'type': 'str',
                },
            'dns_outbound_query_resp_chk_refused_sent': {
                'type': 'str',
                },
            'dns_outbound_query_resp_chk_reset_sent': {
                'type': 'str',
                },
            'dns_outbound_query_resp_chk_no_resp_sent': {
                'type': 'str',
                },
            'dns_outbound_query_resp_size_exceed': {
                'type': 'str',
                },
            'dns_outbound_query_sess_timed_out': {
                'type': 'str',
                },
            'dst_exceed_action_tunnel': {
                'type': 'str',
                },
            'src_udp_auth_timeout': {
                'type': 'str',
                },
            'src_udp_retry_pass': {
                'type': 'str',
                },
            'dst_hw_drop_rule_insert': {
                'type': 'str',
                },
            'dst_hw_drop_rule_remove': {
                'type': 'str',
                },
            'src_hw_drop_rule_insert': {
                'type': 'str',
                },
            'src_hw_drop_rule_remove': {
                'type': 'str',
                },
            'prog_first_req_time_exceed': {
                'type': 'str',
                },
            'prog_req_resp_time_exceed': {
                'type': 'str',
                },
            'prog_request_len_exceed': {
                'type': 'str',
                },
            'prog_response_len_exceed': {
                'type': 'str',
                },
            'prog_resp_req_ratio_exceed': {
                'type': 'str',
                },
            'prog_resp_req_time_exceed': {
                'type': 'str',
                },
            'entry_sync_message_received': {
                'type': 'str',
                },
            'entry_sync_message_sent': {
                'type': 'str',
                },
            'prog_conn_sent_exceed': {
                'type': 'str',
                },
            'prog_conn_rcvd_exceed': {
                'type': 'str',
                },
            'prog_conn_time_exceed': {
                'type': 'str',
                },
            'prog_conn_rcvd_sent_ratio_exceed': {
                'type': 'str',
                },
            'prog_win_sent_exceed': {
                'type': 'str',
                },
            'prog_win_rcvd_exceed': {
                'type': 'str',
                },
            'prog_win_rcvd_sent_ratio_exceed': {
                'type': 'str',
                },
            'prog_exceed_drop': {
                'type': 'str',
                },
            'prog_exceed_bl': {
                'type': 'str',
                },
            'prog_conn_exceed_drop': {
                'type': 'str',
                },
            'prog_conn_exceed_bl': {
                'type': 'str',
                },
            'prog_win_exceed_drop': {
                'type': 'str',
                },
            'prog_win_exceed_bl': {
                'type': 'str',
                },
            'dst_exceed_action_drop': {
                'type': 'str',
                },
            'prog_conn_samples': {
                'type': 'str',
                },
            'prog_req_samples': {
                'type': 'str',
                },
            'prog_win_samples': {
                'type': 'str',
                },
            'dst_entry_name': {
                'type': 'str',
                'required': True,
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/dst/entry/{dst_entry_name}"

    f_dict = {}
    if '/' in str(module.params["dst_entry_name"]):
        f_dict["dst_entry_name"] = module.params["dst_entry_name"].replace("/", "%2F")
    else:
        f_dict["dst_entry_name"] = module.params["dst_entry_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/dst/entry"

    f_dict = {}
    f_dict["dst_entry_name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["entry"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["entry"].get(k) != v:
            change_results["changed"] = True
            config_changes["entry"][k] = v

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
    payload = utils.build_json("entry", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["entry"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["entry-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["entry"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["entry"]["stats"] if info != "NotFound" else info
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
