#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_dst_zone
description:
    - Configure a static zone entry
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
    zone_name:
        description:
        - "Field zone_name"
        type: str
        required: True
    operational_mode:
        description:
        - "'idle'= Idle mode; 'monitor'= Monitor mode; 'learning'= Learning mode;"
        type: str
        required: False
    force_operational_mode:
        description:
        - "Force configure operational mode"
        type: bool
        required: False
    continuous_learning:
        description:
        - "Continuous learning of detection"
        type: bool
        required: False
    traffic_distribution_mode:
        description:
        - "'default'= Distribute traffic to one slot using default distribution mechanism;
          'source-ip-based'= Distribute traffic between slots, based on source ip;"
        type: str
        required: False
    threshold_sensitivity:
        description:
        - "tune threshold ranges with levels LOW/MEDIUM/HIGH/OFF(default) or multiplier of
          threshold value (available options are LOW=5x/MEDIUM=3x/HIGH=1.5x/OFF=1x, or
          float value between 1.0-10.0)"
        type: str
        required: False
    ip:
        description:
        - "Field ip"
        type: list
        required: False
        suboptions:
            ip_addr:
                description:
                - "Specify IP address"
                type: str
            subnet_ip_addr:
                description:
                - "IP Subnet"
                type: str
            expand_ip_subnet:
                description:
                - "Expand this subnet to individual IP address"
                type: bool
            expand_ip_subnet_mode:
                description:
                - "'default'= Default learning mechanism (Default= Dynamic); 'dynamic'= Dynamic
          learning; 'static'= Static learning;"
                type: str
    ipv6:
        description:
        - "Field ipv6"
        type: list
        required: False
        suboptions:
            ip6_addr:
                description:
                - "Specify IPv6 address"
                type: str
            subnet_ipv6_addr:
                description:
                - "IPV6 Subnet"
                type: str
            expand_ipv6_subnet:
                description:
                - "Expand this subnet to individual IPv6 address"
                type: bool
            expand_ipv6_subnet_mode:
                description:
                - "'default'= Default learning mechanism (Default= Dynamic); 'dynamic'= Dynamic
          learning; 'static'= Static learning;"
                type: str
    description:
        description:
        - "Description for this Destination Zone"
        type: str
        required: False
    zone_profile:
        description:
        - "Apply threshold profile"
        type: str
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
            topk_sort_key:
                description:
                - "'avg'= window average; 'max-peak'= max peak;"
                type: str
    glid:
        description:
        - "Global limit ID for the whole zone"
        type: str
        required: False
    action_list:
        description:
        - "Configure action-list to take"
        type: str
        required: False
    per_addr_glid:
        description:
        - "Global limit ID per address"
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
    source_nat_pool:
        description:
        - "Configure source NAT"
        type: str
        required: False
    non_restrictive:
        description:
        - "Non-restrictive mode ignores Zero Thresholds Indicators"
        type: bool
        required: False
    drop_frag_pkt:
        description:
        - "Drop fragmented packets"
        type: bool
        required: False
    sflow_common:
        description:
        - "Enable sFlow counter polling packets, tcp-basic, tcp-stateful and http.
          WARNING= May induce heavy CPU load."
        type: bool
        required: False
    sflow_packets:
        description:
        - "Enable sFlow packet-level counter polling. WARNING= May induce heavy CPU load."
        type: bool
        required: False
    sflow_layer_4:
        description:
        - "Enable sFlow Layer 4 counter polling. WARNING= May induce heavy CPU load."
        type: bool
        required: False
    sflow_tcp:
        description:
        - "Field sflow_tcp"
        type: dict
        required: False
        suboptions:
            sflow_tcp_basic:
                description:
                - "Enable sFlow basic TCP counter polling. WARNING= May induce heavy CPU load."
                type: bool
            sflow_tcp_stateful:
                description:
                - "Enable sFlow stateful TCP counter polling. WARNING= May induce heavy CPU load."
                type: bool
    sflow_http:
        description:
        - "Enable sFlow HTTP counter polling. WARNING= May induce heavy CPU load."
        type: bool
        required: False
    advertised_enable:
        description:
        - "BGP advertised"
        type: bool
        required: False
    telemetry_enable:
        description:
        - "Enable from-l3-peer flag for the zone, thus all the ip entries in the zone will
          be dynamically created/deleted based on the BGP"
        type: bool
        required: False
    zone_template:
        description:
        - "Field zone_template"
        type: dict
        required: False
        suboptions:
            logging:
                description:
                - "DDOS logging template"
                type: str
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
    reporting_disabled:
        description:
        - "Disable Reporting"
        type: bool
        required: False
    log_enable:
        description:
        - "Enable logging"
        type: bool
        required: False
    log_periodic:
        description:
        - "Enable log periodic"
        type: bool
        required: False
    log_high_frequency:
        description:
        - "Enable High frequency logging for non-event logs per zone"
        type: bool
        required: False
    rate_limit:
        description:
        - "Rate limit per second per zone(Default = 1 per second)"
        type: int
        required: False
    set_counter_base_val:
        description:
        - "Set T2 counter value of current context to specified value"
        type: int
        required: False
    is_from_wizard:
        description:
        - "Is It Created from Onbox GUI Wizard"
        type: bool
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
    collector:
        description:
        - "Field collector"
        type: list
        required: False
        suboptions:
            sflow_name:
                description:
                - "Name of configured custom sFlow collector"
                type: str
    src_prefix_len:
        description:
        - "Specify src prefix length for IPv6 (default= not set)"
        type: int
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
                - "'all'= all; 'zone_tcp_any_exceed'= TCP Dst IP-Proto Rate= Total Exceeded;
          'zone_tcp_pkt_rate_exceed'= TCP Dst IP-Proto Rate= Packet Exceeded;
          'zone_tcp_conn_rate_exceed'= TCP Dst IP-Proto Rate= Conn Exceeded;
          'zone_udp_any_exceed'= UDP Dst IP-Proto Rate= Total Exceeded;
          'zone_udp_pkt_rate_exceed'= UDP Dst IP-Proto Rate= Packet Exceeded;
          'zone_udp_conn_limit_exceed'= UDP Dst IP-Proto Limit= Conn Exceeded;
          'zone_udp_conn_rate_exceed'= UDP Dst IP-Proto Rate= Conn Exceeded;
          'zone_icmp_pkt_rate_exceed'= ICMP Dst Rate= Packet Exceeded;
          'zone_other_pkt_rate_exceed'= OTHER Dst IP-Proto Rate= Packet Exceeded;
          'zone_other_frag_pkt_rate_exceed'= OTHER Dst IP-Proto Rate= Frag Exceeded;
          'zone_port_pkt_rate_exceed'= Port Rate= Packet Exceeded;
          'zone_port_conn_limit_exceed'= Port Limit= Conn Exceeded;
          'zone_port_conn_rate_exceed'= Port Rate= Conn Exceeded; 'zone_pkt_sent'=
          Inbound= Packets Forwarded; 'zone_udp_pkt_sent'= UDP Total Packets Forwarded;
          'zone_tcp_pkt_sent'= TCP Total Packets Forwarded; 'zone_icmp_pkt_sent'= ICMP
          Total Packets Forwarded; 'zone_other_pkt_sent'= OTHER Total Packets Forwarded;
          'zone_tcp_conn_limit_exceed'= TCP Dst IP-Proto Limit= Conn Exceeded;
          'zone_tcp_pkt_rcvd'= TCP Total Packets Received; 'zone_udp_pkt_rcvd'= UDP Total
          Packets Received; 'zone_icmp_pkt_rcvd'= ICMP Total Packets Received;
          'zone_other_pkt_rcvd'= OTHER Total Packets Received; 'zone_udp_filter_match'=
          UDP Filter Match; 'zone_udp_filter_not_match'= UDP Filter Not Matched on Pkt;
          'zone_udp_filter_action_blacklist'= UDP Filter Action Blacklist;
          'zone_udp_filter_action_drop'= UDP Filter Action Drop; 'zone_tcp_syn'= TCP
          Total SYN Received; 'zone_tcp_syn_drop'= TCP SYN Packets Dropped;
          'zone_tcp_src_rate_drop'= TCP Src Rate= Total Exceeded;
          'zone_udp_src_rate_drop'= UDP Src Rate= Total Exceeded;
          'zone_icmp_src_rate_drop'= ICMP Src Rate= Total Exceeded;
          'zone_other_frag_src_rate_drop'= OTHER Src Rate= Frag Exceeded;
          'zone_other_src_rate_drop'= OTHER Src Rate= Total Exceeded; 'zone_tcp_drop'=
          TCP Total Packets Dropped; 'zone_udp_drop'= UDP Total Packets Dropped;
          'zone_icmp_drop'= ICMP Total Packets Dropped; 'zone_frag_drop'= Fragmented
          Packets Dropped; 'zone_other_drop'= OTHER Total Packets Dropped;
          'zone_tcp_auth'= TCP Auth= SYN Cookie Sent;
          'zone_udp_filter_action_default_pass'= UDP Filter Action Default Pass;
          'zone_tcp_filter_match'= TCP Filter Match; 'zone_tcp_filter_not_match'= TCP
          Filter Not Matched on Pkt; 'zone_tcp_filter_action_blacklist'= TCP Filter
          Action Blacklist; 'zone_tcp_filter_action_drop'= TCP Filter Action Drop;
          'zone_tcp_filter_action_default_pass'= TCP Filter Action Default Pass;
          'zone_udp_filter_action_whitelist'= UDP Filter Action WL; 'zone_over_limit_on'=
          Zone overlimit Trigger ON; 'zone_over_limit_off'= Zone overlimit Trigger OFF;
          'zone_port_over_limit_on'= Zone port overlimit Trigger ON;
          'zone_port_over_limit_off'= Zone port overlimit Trigger OFF;
          'zone_over_limit_action'= Zone overlimit action; 'zone_port_over_limit_action'=
          Zone port overlimit action; 'scanning_detected_drop'= Scanning Detected drop
          (deprecated); 'scanning_detected_blacklist'= Scanning Detected blacklist
          (deprecated); 'zone_udp_kibit_rate_drop'= UDP Dst IP-Proto Rate= KiBit
          Exceeded; 'zone_tcp_kibit_rate_drop'= TCP Dst IP-Proto Rate= KiBit Exceeded;
          'zone_icmp_kibit_rate_drop'= ICMP Dst Rate= KiBit Exceeded;
          'zone_other_kibit_rate_drop'= OTHER Dst IP-Proto Rate= KiBit Exceeded;
          'zone_port_undef_drop'= Dst Port Undefined Dropped; 'zone_port_bl'= Dst Port
          Blacklist Packets Dropped; 'zone_src_port_bl'= Dst SrcPort Blacklist Packets
          Dropped; 'zone_port_kbit_rate_exceed'= Port Rate= KiBit Exceeded;
          'zone_tcp_src_drop'= TCP Src Packets Dropped; 'zone_udp_src_drop'= UDP Src
          Packets Dropped; 'zone_icmp_src_drop'= ICMP Src Packets Dropped;
          'zone_other_src_drop'= OTHER Src Packets Dropped; 'tcp_syn_rcvd'= TCP Inbound
          SYN Received; 'tcp_syn_ack_rcvd'= TCP SYN ACK Received; 'tcp_ack_rcvd'= TCP ACK
          Received; 'tcp_fin_rcvd'= TCP FIN Received; 'tcp_rst_rcvd'= TCP RST Received;
          'ingress_bytes'= Inbound= Bytes Received; 'egress_bytes'= Outbound= Bytes
          Received; 'ingress_packets'= Inbound= Packets Received; 'egress_packets'=
          Outbound= Packets Received; 'tcp_fwd_recv'= TCP Inbound Packets Received;
          'udp_fwd_recv'= UDP Inbound Packets Received; 'icmp_fwd_recv'= ICMP Inbound
          Packets Received; 'tcp_syn_cookie_fail'= TCP Auth= SYN Cookie Failed;
          'zone_tcp_session_created'= TCP Sessions Created; 'zone_udp_session_created'=
          UDP Sessions Created; 'zone_tcp_filter_action_whitelist'= TCP Filter Action WL;
          'zone_other_filter_match'= OTHER Filter Match; 'zone_other_filter_not_match'=
          OTHER Filter Not Matched on Pkt; 'zone_other_filter_action_blacklist'= OTHER
          Filter Action Blacklist; 'zone_other_filter_action_drop'= OTHER Filter Action
          Drop; 'zone_other_filter_action_whitelist'= OTHER Filter Action WL;
          'zone_other_filter_action_default_pass'= OTHER Filter Action Default Pass;
          'zone_blackhole_inject'= Dst Blackhole Inject; 'zone_blackhole_withdraw'= Dst
          Blackhole Withdraw; 'zone_tcp_out_of_seq_excd'= TCP Out-Of-Seq Exceeded;
          'zone_tcp_retransmit_excd'= TCP Retransmit Exceeded;
          'zone_tcp_zero_window_excd'= TCP Zero-Window Exceeded;
          'zone_tcp_conn_prate_excd'= TCP Rate= Conn Pkt Exceeded;
          'zone_tcp_action_on_ack_init'= TCP Auth= ACK Retry Init;
          'zone_tcp_action_on_ack_gap_drop'= TCP Auth= ACK Retry Retry-Gap Dropped;
          'zone_tcp_action_on_ack_fail'= TCP Auth= ACK Retry Dropped;
          'zone_tcp_action_on_ack_pass'= TCP Auth= ACK Retry Passed;
          'zone_tcp_action_on_syn_init'= TCP Auth= SYN Retry Init;
          'zone_tcp_action_on_syn_gap_drop'= TCP Auth= SYN Retry-Gap Dropped;
          'zone_tcp_action_on_syn_fail'= TCP Auth= SYN Retry Dropped;
          'zone_tcp_action_on_syn_pass'= TCP Auth= SYN Retry Passed;
          'zone_payload_too_small'= UDP Payload Too Small; 'zone_payload_too_big'= UDP
          Payload Too Large; 'zone_udp_conn_prate_excd'= UDP Rate= Conn Pkt Exceeded;
          'zone_udp_ntp_monlist_req'= UDP NTP Monlist Request;
          'zone_udp_ntp_monlist_resp'= UDP NTP Monlist Response;
          'zone_udp_wellknown_sport_drop'= UDP SrcPort Wellknown; 'zone_udp_retry_init'=
          UDP Auth= Retry Init; 'zone_udp_retry_pass'= UDP Auth= Retry Passed;
          'zone_tcp_bytes_drop'= TCP Total Bytes Dropped; 'zone_udp_bytes_drop'= UDP
          Total Bytes Dropped; 'zone_icmp_bytes_drop'= ICMP Total Bytes Dropped;
          'zone_other_bytes_drop'= OTHER Total Bytes Dropped; 'zone_out_no_route'= Dst
          IPv4/v6 Out No Route; 'outbound_bytes_sent'= Outbound= Bytes Forwarded;
          'outbound_drop'= Outbound= Packets Dropped; 'outbound_bytes_drop'= Outbound=
          Bytes Dropped; 'outbound_pkt_sent'= Outbound= Packets Forwarded;
          'inbound_bytes_sent'= Inbound= Bytes Forwarded; 'inbound_bytes_drop'= Inbound=
          Bytes Dropped; 'zone_src_port_pkt_rate_exceed'= SrcPort Rate= Packet Exceeded;
          'zone_src_port_kbit_rate_exceed'= SrcPort Rate= KiBit Exceeded;
          'zone_src_port_conn_limit_exceed'= SrcPort Limit= Conn Exceeded;
          'zone_src_port_conn_rate_exceed'= SrcPort Rate= Conn Exceeded;
          'zone_ip_proto_pkt_rate_exceed'= IP-Proto Rate= Packet Exceeded;
          'zone_ip_proto_kbit_rate_exceed'= IP-Proto Rate= KiBit Exceeded;
          'zone_tcp_port_any_exceed'= TCP Port Rate= Total Exceed;
          'zone_udp_port_any_exceed'= UDP Port Rate= Total Exceed; 'zone_tcp_auth_pass'=
          TCP Auth= SYN Auth Passed; 'zone_tcp_rst_cookie_fail'= TCP Auth= RST Cookie
          Failed; 'zone_tcp_unauth_drop'= TCP Auth= Unauth Dropped;
          'src_tcp_syn_auth_fail'= Src TCP Auth= SYN Auth Failed;
          'src_tcp_syn_cookie_sent'= Src TCP Auth= SYN Cookie Sent;
          'src_tcp_syn_cookie_fail'= Src TCP Auth= SYN Cookie Failed;
          'src_tcp_rst_cookie_fail'= Src TCP Auth= RST Cookie Failed;"
                type: str
            counters2:
                description:
                - "'src_tcp_unauth_drop'= Src TCP Auth= Unauth Dropped;
          'src_tcp_action_on_syn_init'= Src TCP Auth= SYN Retry Init;
          'src_tcp_action_on_syn_gap_drop'= Src TCP Auth= SYN Retry-Gap Dropped;
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
          'dst_drop_frag_pkt'= Fragmented Packets Dropped;
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
          'src_frag_drop'= Src Fragmented Packets Dropped;
          'zone_port_kbit_rate_exceed_pkt'= Port Rate= KiBit Pkt Exceeded;
          'dst_tcp_bytes_rcv'= TCP Total Bytes Received; 'dst_udp_bytes_rcv'= UDP Total
          Bytes Received; 'dst_icmp_bytes_rcv'= ICMP Total Bytes Received;
          'dst_other_bytes_rcv'= OTHER Total Bytes Received; 'dst_tcp_bytes_sent'= TCP
          Total Bytes Forwarded; 'dst_udp_bytes_sent'= UDP Total Bytes Forwarded;
          'dst_icmp_bytes_sent'= ICMP Total Bytes Forwarded; 'dst_other_bytes_sent'=
          OTHER Total Bytes Forwarded; 'dst_udp_auth_drop'= UDP Auth= Dropped;
          'dst_tcp_auth_drop'= TCP Auth= Dropped; 'dst_tcp_auth_resp'= TCP Auth=
          Responded; 'dst_drop'= Inbound= Packets Dropped; 'dst_entry_pkt_rate_exceed'=
          Entry Rate= Packet Exceeded; 'dst_entry_kbit_rate_exceed'= Entry Rate= KiBit
          Exceeded; 'dst_entry_conn_limit_exceed'= Entry Limit= Conn Exceeded;
          'dst_entry_conn_rate_exceed'= Entry Rate= Conn Exceeded;
          'dst_entry_frag_pkt_rate_exceed'= Entry Rate= Frag Packet Exceeded;
          'dst_l4_tcp_blacklist_drop'= Dst TCP IP-Proto Blacklist Dropped;
          'dst_l4_udp_blacklist_drop'= Dst UDP IP-Proto Blacklist Dropped;
          'dst_l4_icmp_blacklist_drop'= Dst ICMP IP-Proto Blacklist Dropped;
          'dst_l4_other_blacklist_drop'= Dst OTHER IP-Proto Blacklist Dropped;
          'dst_frag_timeout_drop'= Fragment Reassemble Timeout Drop;
          'dst_icmp_any_exceed'= ICMP Rate= Total Exceed; 'dst_other_any_exceed'= OTHER
          Rate= Total Exceed; 'tcp_rexmit_syn_limit_drop'= TCP SYN Retransmit Exceeded
          Drop; 'tcp_rexmit_syn_limit_bl'= TCP SYN Retransmit Exceeded Blacklist;
          'dst_clist_overflow_policy_at_learning'= Dst Src-Based Overflow Policy Hit;
          'zone_frag_rcvd'= Fragmented Packets Received; 'zone_tcp_wellknown_sport_drop'=
          TCP SrcPort Wellknown; 'src_tcp_wellknown_sport_drop'= Src TCP SrcPort
          Wellknown; 'secondary_dst_entry_pkt_rate_exceed'= Per Addr Rate= Packet
          Exceeded; 'secondary_dst_entry_kbit_rate_exceed'= Per Addr Rate= KiBit
          Exceeded; 'secondary_dst_entry_conn_limit_exceed'= Per Addr Limit= Conn
          Exceeded; 'secondary_dst_entry_conn_rate_exceed'= Per Addr Rate= Conn Exceeded;
          'secondary_dst_entry_frag_pkt_rate_exceed'= Per Addr Rate= Frag Packet
          Exceeded; 'src_udp_retry_gap_drop'= Src UDP Auth= Retry-Gap Dropped;
          'dst_entry_kbit_rate_exceed_count'= Entry Rate= KiBit Exceeded Count;
          'secondary_entry_learn'= Per Addr Entry Learned; 'secondary_entry_hit'= Per
          Addr Entry Hit; 'secondary_entry_miss'= Per Addr Entry Missed;
          'secondary_entry_aged'= Per Addr Entry Aged;
          'secondary_entry_learning_thre_exceed'= Per Addr Entry Count Overflow;
          'zone_port_undef_hit'= Dst Port undefined Hit;
          'zone_tcp_action_on_ack_timeout'= TCP Auth= ACK Retry Timeout;
          'zone_tcp_action_on_ack_reset'= TCP Auth= ACK Retry Timeout Reset;
          'zone_tcp_action_on_ack_blacklist'= TCP Auth= ACK Retry Timeout Blacklisted;
          'src_tcp_action_on_ack_timeout'= Src TCP Auth= ACK Retry Timeout;
          'src_tcp_action_on_ack_reset'= Src TCP Auth= ACK Retry Timeout Reset;
          'src_tcp_action_on_ack_blacklist'= Src TCP Auth= ACK Retry Timeout Blacklisted;
          'zone_tcp_action_on_syn_timeout'= TCP Auth= SYN Retry Timeout;
          'zone_tcp_action_on_syn_reset'= TCP Auth= SYN Retry Timeout Reset;
          'zone_tcp_action_on_syn_blacklist'= TCP Auth= SYN Retry Timeout Blacklisted;
          'src_tcp_action_on_syn_timeout'= Src TCP Auth= SYN Retry Timeout;
          'src_tcp_action_on_syn_reset'= Src TCP Auth= SYN Retry Timeout Reset;
          'src_tcp_action_on_syn_blacklist'= Src TCP Auth= SYN Retry Timeout Blacklisted;
          'zone_udp_frag_pkt_rate_exceed'= UDP Dst IP-Proto Rate= Frag Exceeded;
          'zone_udp_frag_src_rate_drop'= UDP Src Rate= Frag Exceeded;
          'zone_tcp_frag_pkt_rate_exceed'= TCP Dst IP-Proto Rate= Frag Exceeded;
          'zone_tcp_frag_src_rate_drop'= TCP Src Rate= Frag Exceeded;
          'zone_icmp_frag_pkt_rate_exceed'= ICMP Dst IP-Proto Rate= Frag Exceeded;
          'zone_icmp_frag_src_rate_drop'= ICMP Src Rate= Frag Exceeded;
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
          'source_entry_total'= Source Entry Total Count; 'source_entry_udp'= Source
          Entry UDP Count; 'source_entry_tcp'= Source Entry TCP Count;
          'source_entry_icmp'= Source Entry ICMP Count; 'source_entry_other'= Source
          Entry OTHER Count; 'dst_exceed_action_tunnel'= Entry Exceed Action= Tunnel;"
                type: str
            counters3:
                description:
                - "'dst_udp_retry_timeout_blacklist'= UDP Auth= Retry Timeout Blacklisted;
          'src_udp_auth_timeout'= Src UDP Auth= Retry Timeout;
          'zone_src_udp_retry_timeout_blacklist'= Src UDP Auth= Retry Timeout
          Blacklisted; 'src_udp_retry_pass'= Src UDP Retry Passed;
          'secondary_port_learn'= Per Addr Port Learned; 'secondary_port_aged'= Per Addr
          Port Aged; 'dst_entry_outbound_udp_session_created'= Outbound= UDP Sessions
          Created; 'dst_entry_outbound_udp_session_aged'= Outbound= UDP Sessions Aged;
          'dst_entry_outbound_tcp_session_created'= Outbound= TCP Sessions Created;
          'dst_entry_outbound_tcp_session_aged'= Outbound= TCP Sessions Aged;
          'dst_entry_outbound_pkt_rate_exceed'= Outbound Rate= Packet Exceeded;
          'dst_entry_outbound_kbit_rate_exceed'= Outbound Rate= KiBit Exceeded;
          'dst_entry_outbound_kbit_rate_exceed_count'= Outbound Rate= KiBit Exceeded
          Count; 'dst_entry_outbound_conn_limit_exceed'= Outbound Limit= Conn Exceeded;
          'dst_entry_outbound_conn_rate_exceed'= Outbound Rate= Conn Exceeded;
          'dst_entry_outbound_frag_pkt_rate_exceed'= Outbound Rate= Frag Packet Exceeded;
          'prog_first_req_time_exceed'= Req-Resp= First Request Time Exceed;
          'prog_req_resp_time_exceed'= Req-Resp= Request to Response Time Exceed;
          'prog_request_len_exceed'= Req-Resp= Request Length Exceed;
          'prog_response_len_exceed'= Req-Resp= Response Length Exceed;
          'prog_resp_pkt_rate_exceed'= Req-Resp= Response Packet Rate Exceed;
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
          'east_west_inbound_rcv_pkt'= East West= Inbound Packets Received;
          'east_west_inbound_drop_pkt'= East West= Inbound Packets Dropped;
          'east_west_inbound_fwd_pkt'= East West= Inbound Packets Forwarded;
          'east_west_inbound_rcv_byte'= East West= Inbound Bytes Received;
          'east_west_inbound_drop_byte'= East West= Inbound Bytes Dropped;
          'east_west_inbound_fwd_byte'= East West= Inbound Bytes Forwarded;
          'east_west_outbound_rcv_pkt'= East West= Outbound Packets Received;
          'east_west_outbound_drop_pkt'= East West= Outbound Packets Dropped;
          'east_west_outbound_fwd_pkt'= East West= Outbound Packets Forwarded;
          'east_west_outbound_rcv_byte'= East West= Outbound Bytes Received;
          'east_west_outbound_drop_byte'= East West= Outbound Bytes Dropped;
          'east_west_outbound_fwd_byte'= East West= Outbound Bytes Forwarded;
          'dst_exceed_action_drop'= Entry Exceed Action= Dropped;
          'dst_src_learn_overflow'= Src Dynamic Entry Count Overflow; 'dst_tcp_auth_rst'=
          TCP Auth= Reset; 'prog_query_exceed'= Req-Resp= Client Query Time Exceed;
          'prog_think_exceed'= Req-Resp= Server Think Time Exceed; 'prog_conn_samples'=
          Sample Collected= Connection; 'prog_req_samples'= Sample Collected= Req-Resp;
          'prog_win_samples'= Sample Collected= Time Window; 'victim_ip_learned'= Victim
          Identification= IP Entry Learned; 'victim_ip_aged'= Victim Identification= IP
          Entry Aged; 'prog_conn_samples_processed'= Sample Processed= Connnection;
          'prog_req_samples_processed'= Sample Processed= Req-Resp;
          'prog_win_samples_processed'= Sample Processed= Time Window;
          'token_auth_mismatched_packets'= Token Authentication Mismatched Packets;
          'token_auth_invalid_packets'= Token Authentication Invalid Packets;
          'token_auth_current_salt_matched'= Token Authentication Current Salt Matched;
          'token_auth_previous_salt_matched'= Token Authentication Previous Salt Matched;
          'token_auth_session_created'= Token Authentication Session Created;
          'token_auth_session_created_fail'= Token Authentication Session Created Fail;
          'tcp_invalid_synack'= TCP Invalid SYNACK Received;
          'zone_tcp_small_window_excd'= TCP Small-Window Exceeded;
          'src_tcp_small_window_excd'= Src TCP Small-Window Exceeded; 'small_window_rcv'=
          Small Window Received;"
                type: str
    detection:
        description:
        - "Field detection"
        type: dict
        required: False
        suboptions:
            settings:
                description:
                - "'settings'= settings;"
                type: str
            toggle:
                description:
                - "'enable'= Enable detection; 'disable'= Disable detection;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            notification:
                description:
                - "Field notification"
                type: dict
            outbound_detection:
                description:
                - "Field outbound_detection"
                type: dict
            service_discovery:
                description:
                - "Field service_discovery"
                type: dict
            packet_anomaly_detection:
                description:
                - "Field packet_anomaly_detection"
                type: dict
            victim_ip_detection:
                description:
                - "Field victim_ip_detection"
                type: dict
    packet_anomaly_detection:
        description:
        - "Field packet_anomaly_detection"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    outbound_policy:
        description:
        - "Field outbound_policy"
        type: dict
        required: False
        suboptions:
            name:
                description:
                - "Specify name of the outbound policy"
                type: str
            uuid:
                description:
                - "uuid of the object"
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
                - "'udp'= UDP port; 'tcp'= TCP Port;"
                type: str
            deny:
                description:
                - "Blacklist and Drop all incoming packets for protocol"
                type: bool
            glid_cfg:
                description:
                - "Field glid_cfg"
                type: dict
            zone_template:
                description:
                - "Field zone_template"
                type: dict
            default_action_list:
                description:
                - "Configure default-action-list"
                type: str
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
            level_list:
                description:
                - "Field level_list"
                type: list
    src_port:
        description:
        - "Field src_port"
        type: dict
        required: False
        suboptions:
            zone_src_port_list:
                description:
                - "Field zone_src_port_list"
                type: list
            zone_src_port_other_list:
                description:
                - "Field zone_src_port_other_list"
                type: list
    ip_proto:
        description:
        - "Field ip_proto"
        type: dict
        required: False
        suboptions:
            proto_number_list:
                description:
                - "Field proto_number_list"
                type: list
            proto_tcp_udp_list:
                description:
                - "Field proto_tcp_udp_list"
                type: list
            proto_name_list:
                description:
                - "Field proto_name_list"
                type: list
    port:
        description:
        - "Field port"
        type: dict
        required: False
        suboptions:
            zone_service_list:
                description:
                - "Field zone_service_list"
                type: list
            zone_service_other_list:
                description:
                - "Field zone_service_other_list"
                type: list
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
          tcp'= SIP-TCP Port; 'quic'= QUIC Port;"
                type: str
            manual_mode_enable:
                description:
                - "Toggle manual mode to use fix templates"
                type: bool
            deny:
                description:
                - "Blacklist and Drop all incoming packets for protocol"
                type: bool
            glid_cfg:
                description:
                - "Field glid_cfg"
                type: dict
            stateful:
                description:
                - "Enable stateful tracking of sessions (Default is stateless)"
                type: bool
            default_action_list:
                description:
                - "Configure default-action-list"
                type: str
            sflow_common:
                description:
                - "Enable all sFlow polling options under this zone port"
                type: bool
            sflow_packets:
                description:
                - "Enable sFlow packet-level counter polling"
                type: bool
            sflow_ip_filtering_policy:
                description:
                - "Enable sFlow IP filtering policy per port per rule counter polling"
                type: bool
            sflow_tcp:
                description:
                - "Field sflow_tcp"
                type: dict
            sflow_http:
                description:
                - "Enable sFlow HTTP counter polling"
                type: bool
            unlimited_dynamic_entry_count:
                description:
                - "No limit for maximum dynamic src entry count"
                type: bool
            max_dynamic_entry_count:
                description:
                - "Maximum count for dynamic source zone service entry"
                type: int
            dynamic_entry_count_warn_threshold:
                description:
                - "Set threshold percentage of 'max-src-dst-entry' for generating warning logs.
          Including start and end."
                type: int
            apply_policy_on_overflow:
                description:
                - "Enable this flag to apply overflow policy when dynamic entry count overflows"
                type: bool
            enable_class_list_overflow:
                description:
                - "Apply class-list overflow policy upon exceeding dynamic entry count specified
          under zone port or each class-list"
                type: bool
            enable_top_k:
                description:
                - "Enable ddos top-k source IP detection"
                type: bool
            topk_num_records:
                description:
                - "Maximum number of records to show in topk"
                type: int
            topk_sort_key:
                description:
                - "'avg'= window average; 'max-peak'= max peak;"
                type: str
            enable_top_k_destination:
                description:
                - "Enable ddos top-k destination IP detection"
                type: bool
            topk_dst_num_records:
                description:
                - "Maximum number of records to show in topk"
                type: int
            topk_dst_sort_key:
                description:
                - "'avg'= window average; 'max-peak'= max peak;"
                type: str
            set_counter_base_val:
                description:
                - "Set T2 counter value of current context to specified value"
                type: int
            age:
                description:
                - "Idle age for ip entry"
                type: int
            outbound_only:
                description:
                - "Only allow outbound traffic"
                type: bool
            faster_de_escalation:
                description:
                - "De-escalate faster in standalone mode"
                type: bool
            capture_config:
                description:
                - "Field capture_config"
                type: dict
            ip_filtering_policy:
                description:
                - "Configure IP Filter"
                type: str
            same_source_dest_port_drop:
                description:
                - "Drop packet with same Source Port and Dest Port"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            ip_filtering_policy_statistics:
                description:
                - "Field ip_filtering_policy_statistics"
                type: dict
            pattern_recognition:
                description:
                - "Field pattern_recognition"
                type: dict
            pattern_recognition_pu_details:
                description:
                - "Field pattern_recognition_pu_details"
                type: dict
            level_list:
                description:
                - "Field level_list"
                type: list
            manual_mode_list:
                description:
                - "Field manual_mode_list"
                type: list
            port_ind:
                description:
                - "Field port_ind"
                type: dict
            topk_sources:
                description:
                - "Field topk_sources"
                type: dict
            topk_destinations:
                description:
                - "Field topk_destinations"
                type: dict
            progression_tracking:
                description:
                - "Field progression_tracking"
                type: dict
            src_based_policy_list:
                description:
                - "Field src_based_policy_list"
                type: list
            dynamic_entry_overflow_policy_list:
                description:
                - "Field dynamic_entry_overflow_policy_list"
                type: list
            virtualhosts:
                description:
                - "Field virtualhosts"
                type: dict
    web_gui:
        description:
        - "Field web_gui"
        type: dict
        required: False
        suboptions:
            status:
                description:
                - "'newly'= newly; 'learning'= learning; 'learned'= learned; 'activated'=
          activated;"
                type: str
            activated_after_learning:
                description:
                - "Activate it after learning"
                type: bool
            create_time:
                description:
                - "Configure create time"
                type: str
            modify_time:
                description:
                - "Configure modify time"
                type: str
            sensitivity:
                description:
                - "'5'= Low; '3'= Medium; '1.5'= High;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            learning:
                description:
                - "Field learning"
                type: dict
            protection:
                description:
                - "Field protection"
                type: dict
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
            total_dynamic_entry_count:
                description:
                - "Field total_dynamic_entry_count"
                type: str
            udp_dynamic_entry_count:
                description:
                - "Field udp_dynamic_entry_count"
                type: str
            tcp_dynamic_entry_count:
                description:
                - "Field tcp_dynamic_entry_count"
                type: str
            icmp_dynamic_entry_count:
                description:
                - "Field icmp_dynamic_entry_count"
                type: str
            other_dynamic_entry_count:
                description:
                - "Field other_dynamic_entry_count"
                type: str
            traffic_distribution_status:
                description:
                - "Field traffic_distribution_status"
                type: list
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
            addresses:
                description:
                - "Field addresses"
                type: bool
            subnet_ip_addr:
                description:
                - "Field subnet_ip_addr"
                type: str
            subnet_ipv6_addr:
                description:
                - "Field subnet_ipv6_addr"
                type: str
            all_addresses:
                description:
                - "Field all_addresses"
                type: bool
            ip_proto_num:
                description:
                - "Field ip_proto_num"
                type: int
            all_ip_protos:
                description:
                - "Field all_ip_protos"
                type: bool
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
            protocol:
                description:
                - "Field protocol"
                type: str
            all_ports:
                description:
                - "Field all_ports"
                type: bool
            dynamic_expand_subnet:
                description:
                - "Field dynamic_expand_subnet"
                type: bool
            blackhole:
                description:
                - "Field blackhole"
                type: bool
            zone_name:
                description:
                - "Field zone_name"
                type: str
            detection:
                description:
                - "Field detection"
                type: dict
            packet_anomaly_detection:
                description:
                - "Field packet_anomaly_detection"
                type: dict
            outbound_policy:
                description:
                - "Field outbound_policy"
                type: dict
            topk_destinations:
                description:
                - "Field topk_destinations"
                type: dict
            src_port_range_list:
                description:
                - "Field src_port_range_list"
                type: list
            src_port:
                description:
                - "Field src_port"
                type: dict
            ip_proto:
                description:
                - "Field ip_proto"
                type: dict
            port:
                description:
                - "Field port"
                type: dict
            port_range_list:
                description:
                - "Field port_range_list"
                type: list
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            zone_tcp_any_exceed:
                description:
                - "TCP Dst IP-Proto Rate= Total Exceeded"
                type: str
            zone_tcp_pkt_rate_exceed:
                description:
                - "TCP Dst IP-Proto Rate= Packet Exceeded"
                type: str
            zone_tcp_conn_rate_exceed:
                description:
                - "TCP Dst IP-Proto Rate= Conn Exceeded"
                type: str
            zone_udp_any_exceed:
                description:
                - "UDP Dst IP-Proto Rate= Total Exceeded"
                type: str
            zone_udp_pkt_rate_exceed:
                description:
                - "UDP Dst IP-Proto Rate= Packet Exceeded"
                type: str
            zone_udp_conn_limit_exceed:
                description:
                - "UDP Dst IP-Proto Limit= Conn Exceeded"
                type: str
            zone_udp_conn_rate_exceed:
                description:
                - "UDP Dst IP-Proto Rate= Conn Exceeded"
                type: str
            zone_icmp_pkt_rate_exceed:
                description:
                - "ICMP Dst Rate= Packet Exceeded"
                type: str
            zone_other_pkt_rate_exceed:
                description:
                - "OTHER Dst IP-Proto Rate= Packet Exceeded"
                type: str
            zone_other_frag_pkt_rate_exceed:
                description:
                - "OTHER Dst IP-Proto Rate= Frag Exceeded"
                type: str
            zone_port_pkt_rate_exceed:
                description:
                - "Port Rate= Packet Exceeded"
                type: str
            zone_port_conn_limit_exceed:
                description:
                - "Port Limit= Conn Exceeded"
                type: str
            zone_port_conn_rate_exceed:
                description:
                - "Port Rate= Conn Exceeded"
                type: str
            zone_pkt_sent:
                description:
                - "Inbound= Packets Forwarded"
                type: str
            zone_udp_pkt_sent:
                description:
                - "UDP Total Packets Forwarded"
                type: str
            zone_tcp_pkt_sent:
                description:
                - "TCP Total Packets Forwarded"
                type: str
            zone_icmp_pkt_sent:
                description:
                - "ICMP Total Packets Forwarded"
                type: str
            zone_other_pkt_sent:
                description:
                - "OTHER Total Packets Forwarded"
                type: str
            zone_tcp_conn_limit_exceed:
                description:
                - "TCP Dst IP-Proto Limit= Conn Exceeded"
                type: str
            zone_tcp_pkt_rcvd:
                description:
                - "TCP Total Packets Received"
                type: str
            zone_udp_pkt_rcvd:
                description:
                - "UDP Total Packets Received"
                type: str
            zone_icmp_pkt_rcvd:
                description:
                - "ICMP Total Packets Received"
                type: str
            zone_other_pkt_rcvd:
                description:
                - "OTHER Total Packets Received"
                type: str
            zone_udp_filter_match:
                description:
                - "UDP Filter Match"
                type: str
            zone_udp_filter_not_match:
                description:
                - "UDP Filter Not Matched on Pkt"
                type: str
            zone_udp_filter_action_blacklist:
                description:
                - "UDP Filter Action Blacklist"
                type: str
            zone_udp_filter_action_drop:
                description:
                - "UDP Filter Action Drop"
                type: str
            zone_tcp_syn:
                description:
                - "TCP Total SYN Received"
                type: str
            zone_tcp_syn_drop:
                description:
                - "TCP SYN Packets Dropped"
                type: str
            zone_tcp_src_rate_drop:
                description:
                - "TCP Src Rate= Total Exceeded"
                type: str
            zone_udp_src_rate_drop:
                description:
                - "UDP Src Rate= Total Exceeded"
                type: str
            zone_icmp_src_rate_drop:
                description:
                - "ICMP Src Rate= Total Exceeded"
                type: str
            zone_other_frag_src_rate_drop:
                description:
                - "OTHER Src Rate= Frag Exceeded"
                type: str
            zone_other_src_rate_drop:
                description:
                - "OTHER Src Rate= Total Exceeded"
                type: str
            zone_tcp_drop:
                description:
                - "TCP Total Packets Dropped"
                type: str
            zone_udp_drop:
                description:
                - "UDP Total Packets Dropped"
                type: str
            zone_icmp_drop:
                description:
                - "ICMP Total Packets Dropped"
                type: str
            zone_frag_drop:
                description:
                - "Fragmented Packets Dropped"
                type: str
            zone_other_drop:
                description:
                - "OTHER Total Packets Dropped"
                type: str
            zone_tcp_auth:
                description:
                - "TCP Auth= SYN Cookie Sent"
                type: str
            zone_udp_filter_action_default_pass:
                description:
                - "UDP Filter Action Default Pass"
                type: str
            zone_tcp_filter_match:
                description:
                - "TCP Filter Match"
                type: str
            zone_tcp_filter_not_match:
                description:
                - "TCP Filter Not Matched on Pkt"
                type: str
            zone_tcp_filter_action_blacklist:
                description:
                - "TCP Filter Action Blacklist"
                type: str
            zone_tcp_filter_action_drop:
                description:
                - "TCP Filter Action Drop"
                type: str
            zone_tcp_filter_action_default_pass:
                description:
                - "TCP Filter Action Default Pass"
                type: str
            zone_udp_filter_action_whitelist:
                description:
                - "UDP Filter Action WL"
                type: str
            zone_udp_kibit_rate_drop:
                description:
                - "UDP Dst IP-Proto Rate= KiBit Exceeded"
                type: str
            zone_tcp_kibit_rate_drop:
                description:
                - "TCP Dst IP-Proto Rate= KiBit Exceeded"
                type: str
            zone_icmp_kibit_rate_drop:
                description:
                - "ICMP Dst Rate= KiBit Exceeded"
                type: str
            zone_other_kibit_rate_drop:
                description:
                - "OTHER Dst IP-Proto Rate= KiBit Exceeded"
                type: str
            zone_port_undef_drop:
                description:
                - "Dst Port Undefined Dropped"
                type: str
            zone_port_bl:
                description:
                - "Dst Port Blacklist Packets Dropped"
                type: str
            zone_src_port_bl:
                description:
                - "Dst SrcPort Blacklist Packets Dropped"
                type: str
            zone_port_kbit_rate_exceed:
                description:
                - "Port Rate= KiBit Exceeded"
                type: str
            zone_tcp_src_drop:
                description:
                - "TCP Src Packets Dropped"
                type: str
            zone_udp_src_drop:
                description:
                - "UDP Src Packets Dropped"
                type: str
            zone_icmp_src_drop:
                description:
                - "ICMP Src Packets Dropped"
                type: str
            zone_other_src_drop:
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
            zone_tcp_session_created:
                description:
                - "TCP Sessions Created"
                type: str
            zone_udp_session_created:
                description:
                - "UDP Sessions Created"
                type: str
            zone_tcp_filter_action_whitelist:
                description:
                - "TCP Filter Action WL"
                type: str
            zone_other_filter_match:
                description:
                - "OTHER Filter Match"
                type: str
            zone_other_filter_not_match:
                description:
                - "OTHER Filter Not Matched on Pkt"
                type: str
            zone_other_filter_action_blacklist:
                description:
                - "OTHER Filter Action Blacklist"
                type: str
            zone_other_filter_action_drop:
                description:
                - "OTHER Filter Action Drop"
                type: str
            zone_other_filter_action_whitelist:
                description:
                - "OTHER Filter Action WL"
                type: str
            zone_other_filter_action_default_pass:
                description:
                - "OTHER Filter Action Default Pass"
                type: str
            zone_blackhole_inject:
                description:
                - "Dst Blackhole Inject"
                type: str
            zone_blackhole_withdraw:
                description:
                - "Dst Blackhole Withdraw"
                type: str
            zone_tcp_out_of_seq_excd:
                description:
                - "TCP Out-Of-Seq Exceeded"
                type: str
            zone_tcp_retransmit_excd:
                description:
                - "TCP Retransmit Exceeded"
                type: str
            zone_tcp_zero_window_excd:
                description:
                - "TCP Zero-Window Exceeded"
                type: str
            zone_tcp_conn_prate_excd:
                description:
                - "TCP Rate= Conn Pkt Exceeded"
                type: str
            zone_tcp_action_on_ack_init:
                description:
                - "TCP Auth= ACK Retry Init"
                type: str
            zone_tcp_action_on_ack_gap_drop:
                description:
                - "TCP Auth= ACK Retry Retry-Gap Dropped"
                type: str
            zone_tcp_action_on_ack_fail:
                description:
                - "TCP Auth= ACK Retry Dropped"
                type: str
            zone_tcp_action_on_ack_pass:
                description:
                - "TCP Auth= ACK Retry Passed"
                type: str
            zone_tcp_action_on_syn_init:
                description:
                - "TCP Auth= SYN Retry Init"
                type: str
            zone_tcp_action_on_syn_gap_drop:
                description:
                - "TCP Auth= SYN Retry-Gap Dropped"
                type: str
            zone_tcp_action_on_syn_fail:
                description:
                - "TCP Auth= SYN Retry Dropped"
                type: str
            zone_tcp_action_on_syn_pass:
                description:
                - "TCP Auth= SYN Retry Passed"
                type: str
            zone_payload_too_small:
                description:
                - "UDP Payload Too Small"
                type: str
            zone_payload_too_big:
                description:
                - "UDP Payload Too Large"
                type: str
            zone_udp_conn_prate_excd:
                description:
                - "UDP Rate= Conn Pkt Exceeded"
                type: str
            zone_udp_ntp_monlist_req:
                description:
                - "UDP NTP Monlist Request"
                type: str
            zone_udp_ntp_monlist_resp:
                description:
                - "UDP NTP Monlist Response"
                type: str
            zone_udp_wellknown_sport_drop:
                description:
                - "UDP SrcPort Wellknown"
                type: str
            zone_udp_retry_init:
                description:
                - "UDP Auth= Retry Init"
                type: str
            zone_udp_retry_pass:
                description:
                - "UDP Auth= Retry Passed"
                type: str
            zone_tcp_bytes_drop:
                description:
                - "TCP Total Bytes Dropped"
                type: str
            zone_udp_bytes_drop:
                description:
                - "UDP Total Bytes Dropped"
                type: str
            zone_icmp_bytes_drop:
                description:
                - "ICMP Total Bytes Dropped"
                type: str
            zone_other_bytes_drop:
                description:
                - "OTHER Total Bytes Dropped"
                type: str
            zone_out_no_route:
                description:
                - "Dst IPv4/v6 Out No Route"
                type: str
            outbound_bytes_sent:
                description:
                - "Outbound= Bytes Forwarded"
                type: str
            outbound_drop:
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
            zone_src_port_pkt_rate_exceed:
                description:
                - "SrcPort Rate= Packet Exceeded"
                type: str
            zone_src_port_kbit_rate_exceed:
                description:
                - "SrcPort Rate= KiBit Exceeded"
                type: str
            zone_src_port_conn_limit_exceed:
                description:
                - "SrcPort Limit= Conn Exceeded"
                type: str
            zone_src_port_conn_rate_exceed:
                description:
                - "SrcPort Rate= Conn Exceeded"
                type: str
            zone_ip_proto_pkt_rate_exceed:
                description:
                - "IP-Proto Rate= Packet Exceeded"
                type: str
            zone_ip_proto_kbit_rate_exceed:
                description:
                - "IP-Proto Rate= KiBit Exceeded"
                type: str
            zone_tcp_port_any_exceed:
                description:
                - "TCP Port Rate= Total Exceed"
                type: str
            zone_udp_port_any_exceed:
                description:
                - "UDP Port Rate= Total Exceed"
                type: str
            zone_tcp_auth_pass:
                description:
                - "TCP Auth= SYN Auth Passed"
                type: str
            zone_tcp_rst_cookie_fail:
                description:
                - "TCP Auth= RST Cookie Failed"
                type: str
            zone_tcp_unauth_drop:
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
            zone_port_kbit_rate_exceed_pkt:
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
            dst_drop:
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
            dst_l4_tcp_blacklist_drop:
                description:
                - "Dst TCP IP-Proto Blacklist Dropped"
                type: str
            dst_l4_udp_blacklist_drop:
                description:
                - "Dst UDP IP-Proto Blacklist Dropped"
                type: str
            dst_l4_icmp_blacklist_drop:
                description:
                - "Dst ICMP IP-Proto Blacklist Dropped"
                type: str
            dst_l4_other_blacklist_drop:
                description:
                - "Dst OTHER IP-Proto Blacklist Dropped"
                type: str
            dst_icmp_any_exceed:
                description:
                - "ICMP Rate= Total Exceed"
                type: str
            dst_other_any_exceed:
                description:
                - "OTHER Rate= Total Exceed"
                type: str
            tcp_rexmit_syn_limit_drop:
                description:
                - "TCP SYN Retransmit Exceeded Drop"
                type: str
            tcp_rexmit_syn_limit_bl:
                description:
                - "TCP SYN Retransmit Exceeded Blacklist"
                type: str
            dst_clist_overflow_policy_at_learning:
                description:
                - "Dst Src-Based Overflow Policy Hit"
                type: str
            zone_frag_rcvd:
                description:
                - "Fragmented Packets Received"
                type: str
            zone_tcp_wellknown_sport_drop:
                description:
                - "TCP SrcPort Wellknown"
                type: str
            src_tcp_wellknown_sport_drop:
                description:
                - "Src TCP SrcPort Wellknown"
                type: str
            secondary_dst_entry_pkt_rate_exceed:
                description:
                - "Per Addr Rate= Packet Exceeded"
                type: str
            secondary_dst_entry_kbit_rate_exceed:
                description:
                - "Per Addr Rate= KiBit Exceeded"
                type: str
            secondary_dst_entry_conn_limit_exceed:
                description:
                - "Per Addr Limit= Conn Exceeded"
                type: str
            secondary_dst_entry_conn_rate_exceed:
                description:
                - "Per Addr Rate= Conn Exceeded"
                type: str
            secondary_dst_entry_frag_pkt_rate_exceed:
                description:
                - "Per Addr Rate= Frag Packet Exceeded"
                type: str
            src_udp_retry_gap_drop:
                description:
                - "Src UDP Auth= Retry-Gap Dropped"
                type: str
            dst_entry_kbit_rate_exceed_count:
                description:
                - "Entry Rate= KiBit Exceeded Count"
                type: str
            secondary_entry_learn:
                description:
                - "Per Addr Entry Learned"
                type: str
            secondary_entry_hit:
                description:
                - "Per Addr Entry Hit"
                type: str
            secondary_entry_miss:
                description:
                - "Per Addr Entry Missed"
                type: str
            secondary_entry_aged:
                description:
                - "Per Addr Entry Aged"
                type: str
            secondary_entry_learning_thre_exceed:
                description:
                - "Per Addr Entry Count Overflow"
                type: str
            zone_port_undef_hit:
                description:
                - "Dst Port undefined Hit"
                type: str
            zone_tcp_action_on_ack_timeout:
                description:
                - "TCP Auth= ACK Retry Timeout"
                type: str
            zone_tcp_action_on_ack_reset:
                description:
                - "TCP Auth= ACK Retry Timeout Reset"
                type: str
            zone_tcp_action_on_ack_blacklist:
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
            zone_tcp_action_on_syn_timeout:
                description:
                - "TCP Auth= SYN Retry Timeout"
                type: str
            zone_tcp_action_on_syn_reset:
                description:
                - "TCP Auth= SYN Retry Timeout Reset"
                type: str
            zone_tcp_action_on_syn_blacklist:
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
            zone_udp_frag_pkt_rate_exceed:
                description:
                - "UDP Dst IP-Proto Rate= Frag Exceeded"
                type: str
            zone_udp_frag_src_rate_drop:
                description:
                - "UDP Src Rate= Frag Exceeded"
                type: str
            zone_tcp_frag_pkt_rate_exceed:
                description:
                - "TCP Dst IP-Proto Rate= Frag Exceeded"
                type: str
            zone_tcp_frag_src_rate_drop:
                description:
                - "TCP Src Rate= Frag Exceeded"
                type: str
            zone_icmp_frag_pkt_rate_exceed:
                description:
                - "ICMP Dst IP-Proto Rate= Frag Exceeded"
                type: str
            zone_icmp_frag_src_rate_drop:
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
            source_entry_total:
                description:
                - "Source Entry Total Count"
                type: str
            source_entry_udp:
                description:
                - "Source Entry UDP Count"
                type: str
            source_entry_tcp:
                description:
                - "Source Entry TCP Count"
                type: str
            source_entry_icmp:
                description:
                - "Source Entry ICMP Count"
                type: str
            source_entry_other:
                description:
                - "Source Entry OTHER Count"
                type: str
            dst_exceed_action_tunnel:
                description:
                - "Entry Exceed Action= Tunnel"
                type: str
            dst_udp_retry_timeout_blacklist:
                description:
                - "UDP Auth= Retry Timeout Blacklisted"
                type: str
            src_udp_auth_timeout:
                description:
                - "Src UDP Auth= Retry Timeout"
                type: str
            zone_src_udp_retry_timeout_blacklist:
                description:
                - "Src UDP Auth= Retry Timeout Blacklisted"
                type: str
            src_udp_retry_pass:
                description:
                - "Src UDP Retry Passed"
                type: str
            secondary_port_learn:
                description:
                - "Per Addr Port Learned"
                type: str
            secondary_port_aged:
                description:
                - "Per Addr Port Aged"
                type: str
            dst_entry_outbound_udp_session_created:
                description:
                - "Outbound= UDP Sessions Created"
                type: str
            dst_entry_outbound_udp_session_aged:
                description:
                - "Outbound= UDP Sessions Aged"
                type: str
            dst_entry_outbound_tcp_session_created:
                description:
                - "Outbound= TCP Sessions Created"
                type: str
            dst_entry_outbound_tcp_session_aged:
                description:
                - "Outbound= TCP Sessions Aged"
                type: str
            dst_entry_outbound_pkt_rate_exceed:
                description:
                - "Outbound Rate= Packet Exceeded"
                type: str
            dst_entry_outbound_kbit_rate_exceed:
                description:
                - "Outbound Rate= KiBit Exceeded"
                type: str
            dst_entry_outbound_kbit_rate_exceed_count:
                description:
                - "Outbound Rate= KiBit Exceeded Count"
                type: str
            dst_entry_outbound_conn_limit_exceed:
                description:
                - "Outbound Limit= Conn Exceeded"
                type: str
            dst_entry_outbound_conn_rate_exceed:
                description:
                - "Outbound Rate= Conn Exceeded"
                type: str
            dst_entry_outbound_frag_pkt_rate_exceed:
                description:
                - "Outbound Rate= Frag Packet Exceeded"
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
            prog_resp_pkt_rate_exceed:
                description:
                - "Req-Resp= Response Packet Rate Exceed"
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
            east_west_inbound_rcv_pkt:
                description:
                - "East West= Inbound Packets Received"
                type: str
            east_west_inbound_drop_pkt:
                description:
                - "East West= Inbound Packets Dropped"
                type: str
            east_west_inbound_fwd_pkt:
                description:
                - "East West= Inbound Packets Forwarded"
                type: str
            east_west_inbound_rcv_byte:
                description:
                - "East West= Inbound Bytes Received"
                type: str
            east_west_inbound_drop_byte:
                description:
                - "East West= Inbound Bytes Dropped"
                type: str
            east_west_inbound_fwd_byte:
                description:
                - "East West= Inbound Bytes Forwarded"
                type: str
            east_west_outbound_rcv_pkt:
                description:
                - "East West= Outbound Packets Received"
                type: str
            east_west_outbound_drop_pkt:
                description:
                - "East West= Outbound Packets Dropped"
                type: str
            east_west_outbound_fwd_pkt:
                description:
                - "East West= Outbound Packets Forwarded"
                type: str
            east_west_outbound_rcv_byte:
                description:
                - "East West= Outbound Bytes Received"
                type: str
            east_west_outbound_drop_byte:
                description:
                - "East West= Outbound Bytes Dropped"
                type: str
            east_west_outbound_fwd_byte:
                description:
                - "East West= Outbound Bytes Forwarded"
                type: str
            dst_exceed_action_drop:
                description:
                - "Entry Exceed Action= Dropped"
                type: str
            dst_src_learn_overflow:
                description:
                - "Src Dynamic Entry Count Overflow"
                type: str
            dst_tcp_auth_rst:
                description:
                - "TCP Auth= Reset"
                type: str
            prog_query_exceed:
                description:
                - "Req-Resp= Client Query Time Exceed"
                type: str
            prog_think_exceed:
                description:
                - "Req-Resp= Server Think Time Exceed"
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
            victim_ip_learned:
                description:
                - "Victim Identification= IP Entry Learned"
                type: str
            victim_ip_aged:
                description:
                - "Victim Identification= IP Entry Aged"
                type: str
            prog_conn_samples_processed:
                description:
                - "Sample Processed= Connnection"
                type: str
            prog_req_samples_processed:
                description:
                - "Sample Processed= Req-Resp"
                type: str
            prog_win_samples_processed:
                description:
                - "Sample Processed= Time Window"
                type: str
            token_auth_mismatched_packets:
                description:
                - "Token Authentication Mismatched Packets"
                type: str
            token_auth_invalid_packets:
                description:
                - "Token Authentication Invalid Packets"
                type: str
            token_auth_current_salt_matched:
                description:
                - "Token Authentication Current Salt Matched"
                type: str
            token_auth_previous_salt_matched:
                description:
                - "Token Authentication Previous Salt Matched"
                type: str
            token_auth_session_created:
                description:
                - "Token Authentication Session Created"
                type: str
            token_auth_session_created_fail:
                description:
                - "Token Authentication Session Created Fail"
                type: str
            tcp_invalid_synack:
                description:
                - "TCP Invalid SYNACK Received"
                type: str
            zone_tcp_small_window_excd:
                description:
                - "TCP Small-Window Exceeded"
                type: str
            src_tcp_small_window_excd:
                description:
                - "Src TCP Small-Window Exceeded"
                type: str
            small_window_rcv:
                description:
                - "Small Window Received"
                type: str
            zone_name:
                description:
                - "Field zone_name"
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
    "action_list", "advertised_enable", "capture_config_list", "collector", "continuous_learning", "description", "dest_nat_ip", "dest_nat_ipv6", "detection", "drop_frag_pkt", "enable_top_k", "force_operational_mode", "glid", "hw_blacklist_blocking", "inbound_forward_dscp", "ip", "ip_proto", "ipv6", "is_from_wizard", "log_enable",
    "log_high_frequency", "log_periodic", "non_restrictive", "oper", "operational_mode", "outbound_forward_dscp", "outbound_policy", "packet_anomaly_detection", "pattern_recognition_hw_filter_enable", "pattern_recognition_sensitivity", "per_addr_glid", "port", "port_range_list", "rate_limit", "reporting_disabled", "sampling_enable",
    "set_counter_base_val", "sflow_common", "sflow_http", "sflow_layer_4", "sflow_packets", "sflow_tcp", "source_nat_pool", "src_port", "src_port_range_list", "src_prefix_len", "stats", "telemetry_enable", "threshold_sensitivity", "topk_destinations", "traffic_distribution_mode", "user_tag", "uuid", "web_gui", "zone_name", "zone_profile",
    "zone_template",
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
        'zone_name': {
            'type': 'str',
            'required': True,
            },
        'operational_mode': {
            'type': 'str',
            'choices': ['idle', 'monitor', 'learning']
            },
        'force_operational_mode': {
            'type': 'bool',
            },
        'continuous_learning': {
            'type': 'bool',
            },
        'traffic_distribution_mode': {
            'type': 'str',
            'choices': ['default', 'source-ip-based']
            },
        'threshold_sensitivity': {
            'type': 'str',
            },
        'ip': {
            'type': 'list',
            'ip_addr': {
                'type': 'str',
                },
            'subnet_ip_addr': {
                'type': 'str',
                },
            'expand_ip_subnet': {
                'type': 'bool',
                },
            'expand_ip_subnet_mode': {
                'type': 'str',
                'choices': ['default', 'dynamic', 'static']
                }
            },
        'ipv6': {
            'type': 'list',
            'ip6_addr': {
                'type': 'str',
                },
            'subnet_ipv6_addr': {
                'type': 'str',
                },
            'expand_ipv6_subnet': {
                'type': 'bool',
                },
            'expand_ipv6_subnet_mode': {
                'type': 'str',
                'choices': ['default', 'dynamic', 'static']
                }
            },
        'description': {
            'type': 'str',
            },
        'zone_profile': {
            'type': 'str',
            },
        'enable_top_k': {
            'type': 'list',
            'topk_type': {
                'type': 'str',
                'choices': ['destination']
                },
            'topk_num_records': {
                'type': 'int',
                },
            'topk_sort_key': {
                'type': 'str',
                'choices': ['avg', 'max-peak']
                }
            },
        'glid': {
            'type': 'str',
            },
        'action_list': {
            'type': 'str',
            },
        'per_addr_glid': {
            'type': 'str',
            },
        'dest_nat_ip': {
            'type': 'str',
            },
        'dest_nat_ipv6': {
            'type': 'str',
            },
        'source_nat_pool': {
            'type': 'str',
            },
        'non_restrictive': {
            'type': 'bool',
            },
        'drop_frag_pkt': {
            'type': 'bool',
            },
        'sflow_common': {
            'type': 'bool',
            },
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
        'advertised_enable': {
            'type': 'bool',
            },
        'telemetry_enable': {
            'type': 'bool',
            },
        'zone_template': {
            'type': 'dict',
            'logging': {
                'type': 'str',
                }
            },
        'inbound_forward_dscp': {
            'type': 'int',
            },
        'outbound_forward_dscp': {
            'type': 'int',
            },
        'reporting_disabled': {
            'type': 'bool',
            },
        'log_enable': {
            'type': 'bool',
            },
        'log_periodic': {
            'type': 'bool',
            },
        'log_high_frequency': {
            'type': 'bool',
            },
        'rate_limit': {
            'type': 'int',
            },
        'set_counter_base_val': {
            'type': 'int',
            },
        'is_from_wizard': {
            'type': 'bool',
            },
        'pattern_recognition_sensitivity': {
            'type': 'str',
            'choices': ['high', 'medium', 'low']
            },
        'pattern_recognition_hw_filter_enable': {
            'type': 'bool',
            },
        'collector': {
            'type': 'list',
            'sflow_name': {
                'type': 'str',
                }
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
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'zone_tcp_any_exceed', 'zone_tcp_pkt_rate_exceed', 'zone_tcp_conn_rate_exceed', 'zone_udp_any_exceed', 'zone_udp_pkt_rate_exceed', 'zone_udp_conn_limit_exceed', 'zone_udp_conn_rate_exceed', 'zone_icmp_pkt_rate_exceed', 'zone_other_pkt_rate_exceed', 'zone_other_frag_pkt_rate_exceed', 'zone_port_pkt_rate_exceed',
                    'zone_port_conn_limit_exceed', 'zone_port_conn_rate_exceed', 'zone_pkt_sent', 'zone_udp_pkt_sent', 'zone_tcp_pkt_sent', 'zone_icmp_pkt_sent', 'zone_other_pkt_sent', 'zone_tcp_conn_limit_exceed', 'zone_tcp_pkt_rcvd', 'zone_udp_pkt_rcvd', 'zone_icmp_pkt_rcvd', 'zone_other_pkt_rcvd', 'zone_udp_filter_match',
                    'zone_udp_filter_not_match', 'zone_udp_filter_action_blacklist', 'zone_udp_filter_action_drop', 'zone_tcp_syn', 'zone_tcp_syn_drop', 'zone_tcp_src_rate_drop', 'zone_udp_src_rate_drop', 'zone_icmp_src_rate_drop', 'zone_other_frag_src_rate_drop', 'zone_other_src_rate_drop', 'zone_tcp_drop', 'zone_udp_drop', 'zone_icmp_drop',
                    'zone_frag_drop', 'zone_other_drop', 'zone_tcp_auth', 'zone_udp_filter_action_default_pass', 'zone_tcp_filter_match', 'zone_tcp_filter_not_match', 'zone_tcp_filter_action_blacklist', 'zone_tcp_filter_action_drop', 'zone_tcp_filter_action_default_pass', 'zone_udp_filter_action_whitelist', 'zone_over_limit_on',
                    'zone_over_limit_off', 'zone_port_over_limit_on', 'zone_port_over_limit_off', 'zone_over_limit_action', 'zone_port_over_limit_action', 'scanning_detected_drop', 'scanning_detected_blacklist', 'zone_udp_kibit_rate_drop', 'zone_tcp_kibit_rate_drop', 'zone_icmp_kibit_rate_drop', 'zone_other_kibit_rate_drop', 'zone_port_undef_drop',
                    'zone_port_bl', 'zone_src_port_bl', 'zone_port_kbit_rate_exceed', 'zone_tcp_src_drop', 'zone_udp_src_drop', 'zone_icmp_src_drop', 'zone_other_src_drop', 'tcp_syn_rcvd', 'tcp_syn_ack_rcvd', 'tcp_ack_rcvd', 'tcp_fin_rcvd', 'tcp_rst_rcvd', 'ingress_bytes', 'egress_bytes', 'ingress_packets', 'egress_packets', 'tcp_fwd_recv',
                    'udp_fwd_recv', 'icmp_fwd_recv', 'tcp_syn_cookie_fail', 'zone_tcp_session_created', 'zone_udp_session_created', 'zone_tcp_filter_action_whitelist', 'zone_other_filter_match', 'zone_other_filter_not_match', 'zone_other_filter_action_blacklist', 'zone_other_filter_action_drop', 'zone_other_filter_action_whitelist',
                    'zone_other_filter_action_default_pass', 'zone_blackhole_inject', 'zone_blackhole_withdraw', 'zone_tcp_out_of_seq_excd', 'zone_tcp_retransmit_excd', 'zone_tcp_zero_window_excd', 'zone_tcp_conn_prate_excd', 'zone_tcp_action_on_ack_init', 'zone_tcp_action_on_ack_gap_drop', 'zone_tcp_action_on_ack_fail',
                    'zone_tcp_action_on_ack_pass', 'zone_tcp_action_on_syn_init', 'zone_tcp_action_on_syn_gap_drop', 'zone_tcp_action_on_syn_fail', 'zone_tcp_action_on_syn_pass', 'zone_payload_too_small', 'zone_payload_too_big', 'zone_udp_conn_prate_excd', 'zone_udp_ntp_monlist_req', 'zone_udp_ntp_monlist_resp', 'zone_udp_wellknown_sport_drop',
                    'zone_udp_retry_init', 'zone_udp_retry_pass', 'zone_tcp_bytes_drop', 'zone_udp_bytes_drop', 'zone_icmp_bytes_drop', 'zone_other_bytes_drop', 'zone_out_no_route', 'outbound_bytes_sent', 'outbound_drop', 'outbound_bytes_drop', 'outbound_pkt_sent', 'inbound_bytes_sent', 'inbound_bytes_drop', 'zone_src_port_pkt_rate_exceed',
                    'zone_src_port_kbit_rate_exceed', 'zone_src_port_conn_limit_exceed', 'zone_src_port_conn_rate_exceed', 'zone_ip_proto_pkt_rate_exceed', 'zone_ip_proto_kbit_rate_exceed', 'zone_tcp_port_any_exceed', 'zone_udp_port_any_exceed', 'zone_tcp_auth_pass', 'zone_tcp_rst_cookie_fail', 'zone_tcp_unauth_drop', 'src_tcp_syn_auth_fail',
                    'src_tcp_syn_cookie_sent', 'src_tcp_syn_cookie_fail', 'src_tcp_rst_cookie_fail'
                    ]
                },
            'counters2': {
                'type':
                'str',
                'choices': [
                    'src_tcp_unauth_drop', 'src_tcp_action_on_syn_init', 'src_tcp_action_on_syn_gap_drop', 'src_tcp_action_on_syn_fail', 'src_tcp_action_on_ack_init', 'src_tcp_action_on_ack_gap_drop', 'src_tcp_action_on_ack_fail', 'src_tcp_out_of_seq_excd', 'src_tcp_retransmit_excd', 'src_tcp_zero_window_excd', 'src_tcp_conn_prate_excd',
                    'src_udp_min_payload', 'src_udp_max_payload', 'src_udp_conn_prate_excd', 'src_udp_ntp_monlist_req', 'src_udp_ntp_monlist_resp', 'src_udp_wellknown_sport_drop', 'src_udp_retry_init', 'dst_udp_retry_gap_drop', 'dst_udp_retry_fail', 'dst_tcp_session_aged', 'dst_udp_session_aged', 'dst_tcp_conn_close',
                    'dst_tcp_conn_close_half_open', 'dst_drop_frag_pkt', 'src_tcp_filter_action_blacklist', 'src_tcp_filter_action_whitelist', 'src_tcp_filter_action_drop', 'src_tcp_filter_action_default_pass', 'src_udp_filter_action_blacklist', 'src_udp_filter_action_whitelist', 'src_udp_filter_action_drop', 'src_udp_filter_action_default_pass',
                    'src_other_filter_action_blacklist', 'src_other_filter_action_whitelist', 'src_other_filter_action_drop', 'src_other_filter_action_default_pass', 'tcp_invalid_syn', 'dst_tcp_conn_close_w_rst', 'dst_tcp_conn_close_w_fin', 'dst_tcp_conn_close_w_idle', 'dst_tcp_conn_create_from_syn', 'dst_tcp_conn_create_from_ack', 'src_frag_drop',
                    'zone_port_kbit_rate_exceed_pkt', 'dst_tcp_bytes_rcv', 'dst_udp_bytes_rcv', 'dst_icmp_bytes_rcv', 'dst_other_bytes_rcv', 'dst_tcp_bytes_sent', 'dst_udp_bytes_sent', 'dst_icmp_bytes_sent', 'dst_other_bytes_sent', 'dst_udp_auth_drop', 'dst_tcp_auth_drop', 'dst_tcp_auth_resp', 'dst_drop', 'dst_entry_pkt_rate_exceed',
                    'dst_entry_kbit_rate_exceed', 'dst_entry_conn_limit_exceed', 'dst_entry_conn_rate_exceed', 'dst_entry_frag_pkt_rate_exceed', 'dst_l4_tcp_blacklist_drop', 'dst_l4_udp_blacklist_drop', 'dst_l4_icmp_blacklist_drop', 'dst_l4_other_blacklist_drop', 'dst_frag_timeout_drop', 'dst_icmp_any_exceed', 'dst_other_any_exceed',
                    'tcp_rexmit_syn_limit_drop', 'tcp_rexmit_syn_limit_bl', 'dst_clist_overflow_policy_at_learning', 'zone_frag_rcvd', 'zone_tcp_wellknown_sport_drop', 'src_tcp_wellknown_sport_drop', 'secondary_dst_entry_pkt_rate_exceed', 'secondary_dst_entry_kbit_rate_exceed', 'secondary_dst_entry_conn_limit_exceed',
                    'secondary_dst_entry_conn_rate_exceed', 'secondary_dst_entry_frag_pkt_rate_exceed', 'src_udp_retry_gap_drop', 'dst_entry_kbit_rate_exceed_count', 'secondary_entry_learn', 'secondary_entry_hit', 'secondary_entry_miss', 'secondary_entry_aged', 'secondary_entry_learning_thre_exceed', 'zone_port_undef_hit',
                    'zone_tcp_action_on_ack_timeout', 'zone_tcp_action_on_ack_reset', 'zone_tcp_action_on_ack_blacklist', 'src_tcp_action_on_ack_timeout', 'src_tcp_action_on_ack_reset', 'src_tcp_action_on_ack_blacklist', 'zone_tcp_action_on_syn_timeout', 'zone_tcp_action_on_syn_reset', 'zone_tcp_action_on_syn_blacklist',
                    'src_tcp_action_on_syn_timeout', 'src_tcp_action_on_syn_reset', 'src_tcp_action_on_syn_blacklist', 'zone_udp_frag_pkt_rate_exceed', 'zone_udp_frag_src_rate_drop', 'zone_tcp_frag_pkt_rate_exceed', 'zone_tcp_frag_src_rate_drop', 'zone_icmp_frag_pkt_rate_exceed', 'zone_icmp_frag_src_rate_drop', 'sflow_internal_samples_packed',
                    'sflow_external_samples_packed', 'sflow_internal_packets_sent', 'sflow_external_packets_sent', 'dns_outbound_total_query', 'dns_outbound_query_malformed', 'dns_outbound_query_resp_chk_failed', 'dns_outbound_query_resp_chk_blacklisted', 'dns_outbound_query_resp_chk_refused_sent', 'dns_outbound_query_resp_chk_reset_sent',
                    'dns_outbound_query_resp_chk_no_resp_sent', 'dns_outbound_query_resp_size_exceed', 'dns_outbound_query_sess_timed_out', 'source_entry_total', 'source_entry_udp', 'source_entry_tcp', 'source_entry_icmp', 'source_entry_other', 'dst_exceed_action_tunnel'
                    ]
                },
            'counters3': {
                'type':
                'str',
                'choices': [
                    'dst_udp_retry_timeout_blacklist', 'src_udp_auth_timeout', 'zone_src_udp_retry_timeout_blacklist', 'src_udp_retry_pass', 'secondary_port_learn', 'secondary_port_aged', 'dst_entry_outbound_udp_session_created', 'dst_entry_outbound_udp_session_aged', 'dst_entry_outbound_tcp_session_created', 'dst_entry_outbound_tcp_session_aged',
                    'dst_entry_outbound_pkt_rate_exceed', 'dst_entry_outbound_kbit_rate_exceed', 'dst_entry_outbound_kbit_rate_exceed_count', 'dst_entry_outbound_conn_limit_exceed', 'dst_entry_outbound_conn_rate_exceed', 'dst_entry_outbound_frag_pkt_rate_exceed', 'prog_first_req_time_exceed', 'prog_req_resp_time_exceed', 'prog_request_len_exceed',
                    'prog_response_len_exceed', 'prog_resp_pkt_rate_exceed', 'prog_resp_req_time_exceed', 'entry_sync_message_received', 'entry_sync_message_sent', 'prog_conn_sent_exceed', 'prog_conn_rcvd_exceed', 'prog_conn_time_exceed', 'prog_conn_rcvd_sent_ratio_exceed', 'prog_win_sent_exceed', 'prog_win_rcvd_exceed',
                    'prog_win_rcvd_sent_ratio_exceed', 'prog_exceed_drop', 'prog_exceed_bl', 'prog_conn_exceed_drop', 'prog_conn_exceed_bl', 'prog_win_exceed_drop', 'prog_win_exceed_bl', 'east_west_inbound_rcv_pkt', 'east_west_inbound_drop_pkt', 'east_west_inbound_fwd_pkt', 'east_west_inbound_rcv_byte', 'east_west_inbound_drop_byte',
                    'east_west_inbound_fwd_byte', 'east_west_outbound_rcv_pkt', 'east_west_outbound_drop_pkt', 'east_west_outbound_fwd_pkt', 'east_west_outbound_rcv_byte', 'east_west_outbound_drop_byte', 'east_west_outbound_fwd_byte', 'dst_exceed_action_drop', 'dst_src_learn_overflow', 'dst_tcp_auth_rst', 'prog_query_exceed', 'prog_think_exceed',
                    'prog_conn_samples', 'prog_req_samples', 'prog_win_samples', 'victim_ip_learned', 'victim_ip_aged', 'prog_conn_samples_processed', 'prog_req_samples_processed', 'prog_win_samples_processed', 'token_auth_mismatched_packets', 'token_auth_invalid_packets', 'token_auth_current_salt_matched', 'token_auth_previous_salt_matched',
                    'token_auth_session_created', 'token_auth_session_created_fail', 'tcp_invalid_synack', 'zone_tcp_small_window_excd', 'src_tcp_small_window_excd', 'small_window_rcv'
                    ]
                }
            },
        'detection': {
            'type': 'dict',
            'settings': {
                'type': 'str',
                'choices': ['settings']
                },
            'toggle': {
                'type': 'str',
                'choices': ['enable', 'disable']
                },
            'uuid': {
                'type': 'str',
                },
            'notification': {
                'type': 'dict',
                'configuration': {
                    'type': 'str',
                    'choices': ['configuration']
                    },
                'notification': {
                    'type': 'list',
                    'notification_template_name': {
                        'type': 'str',
                        }
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'outbound_detection': {
                'type': 'dict',
                'configuration': {
                    'type': 'str',
                    'choices': ['configuration']
                    },
                'toggle': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                    },
                'discovery_method': {
                    'type': 'str',
                    'choices': ['asn', 'country']
                    },
                'discovery_record': {
                    'type': 'int',
                    },
                'enable_top_k': {
                    'type': 'list',
                    'topk_type': {
                        'type': 'str',
                        'choices': ['source-subnet']
                        },
                    'topk_netmask': {
                        'type': 'int',
                        },
                    'topk_num_records': {
                        'type': 'int',
                        }
                    },
                'uuid': {
                    'type': 'str',
                    },
                'indicator_list': {
                    'type': 'list',
                    'ntype': {
                        'type': 'str',
                        'required': True,
                        'choices': ['pkt-rate', 'pkt-drop-rate', 'bit-rate', 'pkt-drop-ratio', 'bytes-to-bytes-from-ratio', 'syn-rate', 'fin-rate', 'rst-rate', 'small-window-ack-rate', 'empty-ack-rate', 'small-payload-rate', 'syn-fin-ratio']
                        },
                    'tcp_window_size': {
                        'type': 'int',
                        },
                    'data_packet_size': {
                        'type': 'int',
                        },
                    'threshold_num': {
                        'type': 'int',
                        },
                    'threshold_large_num': {
                        'type': 'int',
                        },
                    'threshold_str': {
                        'type': 'str',
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        }
                    },
                'topk_source_subnet': {
                    'type': 'dict',
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'service_discovery': {
                'type': 'dict',
                'configuration': {
                    'type': 'str',
                    'choices': ['configuration']
                    },
                'toggle': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                    },
                'pkt_rate_threshold': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'packet_anomaly_detection': {
                'type': 'dict',
                'configuration': {
                    'type': 'str',
                    'choices': ['configuration']
                    },
                'toggle': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                    },
                'uuid': {
                    'type': 'str',
                    },
                'indicator_list': {
                    'type': 'list',
                    'ntype': {
                        'type': 'str',
                        'required': True,
                        'choices': ['port-zero-pkt-rate']
                        },
                    'threshold_num': {
                        'type': 'int',
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        }
                    }
                },
            'victim_ip_detection': {
                'type': 'dict',
                'configuration': {
                    'type': 'str',
                    'choices': ['configuration']
                    },
                'toggle': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                    },
                'histogram_toggle': {
                    'type': 'str',
                    'choices': ['histogram-enable', 'histogram-disable']
                    },
                'uuid': {
                    'type': 'str',
                    },
                'indicator_list': {
                    'type': 'list',
                    'ntype': {
                        'type': 'str',
                        'required': True,
                        'choices': ['pkt-rate', 'reverse-pkt-rate', 'fwd-byte-rate', 'rev-byte-rate']
                        },
                    'ip_threshold_num': {
                        'type': 'int',
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
        'packet_anomaly_detection': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'outbound_policy': {
            'type': 'dict',
            'name': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
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
            'glid_cfg': {
                'type': 'dict',
                'glid': {
                    'type': 'str',
                    },
                'glid_action': {
                    'type': 'str',
                    'choices': ['drop', 'ignore']
                    }
                },
            'zone_template': {
                'type': 'dict',
                'src_udp': {
                    'type': 'str',
                    },
                'src_tcp': {
                    'type': 'str',
                    }
                },
            'default_action_list': {
                'type': 'str',
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
                    }
                },
            'level_list': {
                'type': 'list',
                'level_num': {
                    'type': 'str',
                    'required': True,
                    'choices': ['0', '1']
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'indicator_list': {
                    'type': 'list',
                    'ntype': {
                        'type': 'str',
                        'required': True,
                        'choices': ['pkt-rate', 'bit-rate']
                        },
                    'zone_threshold_num': {
                        'type': 'int',
                        },
                    'zone_threshold_large_num': {
                        'type': 'int',
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
        'src_port': {
            'type': 'dict',
            'zone_src_port_list': {
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
                'glid_cfg': {
                    'type': 'dict',
                    'glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore']
                        }
                    },
                'outbound_src_tracking': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                    },
                'zone_template': {
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
                'default_action_list': {
                    'type': 'str',
                    },
                'set_counter_base_val': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'port_ind': {
                    'type': 'dict',
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'level_list': {
                    'type': 'list',
                    'level_num': {
                        'type': 'str',
                        'required': True,
                        'choices': ['0', '1']
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        },
                    'indicator_list': {
                        'type': 'list',
                        'ntype': {
                            'type': 'str',
                            'required': True,
                            'choices': ['pkt-rate', 'bit-rate']
                            },
                        'zone_threshold_num': {
                            'type': 'int',
                            },
                        'zone_threshold_large_num': {
                            'type': 'int',
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
            'zone_src_port_other_list': {
                'type': 'list',
                'port_other': {
                    'type': 'str',
                    'required': True,
                    'choices': ['other']
                    },
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['udp', 'tcp']
                    },
                'deny': {
                    'type': 'bool',
                    },
                'glid_cfg': {
                    'type': 'dict',
                    'glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore']
                        }
                    },
                'zone_template': {
                    'type': 'dict',
                    'src_udp': {
                        'type': 'str',
                        },
                    'src_tcp': {
                        'type': 'str',
                        }
                    },
                'default_action_list': {
                    'type': 'str',
                    },
                'set_counter_base_val': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'port_ind': {
                    'type': 'dict',
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'level_list': {
                    'type': 'list',
                    'level_num': {
                        'type': 'str',
                        'required': True,
                        'choices': ['0', '1']
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        },
                    'indicator_list': {
                        'type': 'list',
                        'ntype': {
                            'type': 'str',
                            'required': True,
                            'choices': ['pkt-rate', 'bit-rate']
                            },
                        'zone_threshold_num': {
                            'type': 'int',
                            },
                        'zone_threshold_large_num': {
                            'type': 'int',
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
        'ip_proto': {
            'type': 'dict',
            'proto_number_list': {
                'type': 'list',
                'protocol_num': {
                    'type': 'int',
                    'required': True,
                    },
                'manual_mode_enable': {
                    'type': 'bool',
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
                'glid_cfg': {
                    'type': 'dict',
                    'glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore']
                        },
                    'action_list': {
                        'type': 'str',
                        },
                    'per_addr_glid': {
                        'type': 'str',
                        }
                    },
                'drop_frag_pkt': {
                    'type': 'bool',
                    },
                'unlimited_dynamic_entry_count': {
                    'type': 'bool',
                    },
                'max_dynamic_entry_count': {
                    'type': 'int',
                    },
                'dynamic_entry_count_warn_threshold': {
                    'type': 'int',
                    },
                'apply_policy_on_overflow': {
                    'type': 'bool',
                    },
                'enable_top_k': {
                    'type': 'bool',
                    },
                'topk_num_records': {
                    'type': 'int',
                    },
                'topk_sort_key': {
                    'type': 'str',
                    'choices': ['avg', 'max-peak']
                    },
                'enable_top_k_destination': {
                    'type': 'bool',
                    },
                'topk_dst_num_records': {
                    'type': 'int',
                    },
                'topk_dst_sort_key': {
                    'type': 'str',
                    'choices': ['avg', 'max-peak']
                    },
                'set_counter_base_val': {
                    'type': 'int',
                    },
                'age': {
                    'type': 'int',
                    },
                'enable_class_list_overflow': {
                    'type': 'bool',
                    },
                'faster_de_escalation': {
                    'type': 'bool',
                    },
                'sflow_ip_filtering_policy': {
                    'type': 'bool',
                    },
                'ip_filtering_policy': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'ip_filtering_policy_statistics': {
                    'type': 'dict',
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'src_based_policy_list': {
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
                        'class_list_glid': {
                            'type': 'str',
                            },
                        'glid': {
                            'type': 'str',
                            },
                        'glid_action': {
                            'type': 'str',
                            'choices': ['drop', 'blacklist-src', 'ignore']
                            },
                        'action': {
                            'type': 'str',
                            'choices': ['bypass', 'deny']
                            },
                        'log_enable': {
                            'type': 'bool',
                            },
                        'log_periodic': {
                            'type': 'bool',
                            },
                        'max_dynamic_entry_count': {
                            'type': 'int',
                            },
                        'dynamic_entry_count_warn_threshold': {
                            'type': 'int',
                            },
                        'zone_template': {
                            'type': 'dict',
                            'logging': {
                                'type': 'str',
                                },
                            'ip_proto': {
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
                                'type': 'str',
                                'choices': ['all', 'packet_received', 'packet_dropped', 'entry_learned', 'entry_count_overflow', 'exceed_drop_pkt_rate_clist', 'exceed_drop_conn_rate_clist', 'exceed_drop_conn_limit_clist', 'exceed_drop_kbit_rate_clist', 'exceed_drop_kbit_rate_clist_pkt', 'exceed_drop_frag_rate_clist']
                                }
                            },
                        'class_list_overflow_policy_list': {
                            'type': 'list',
                            'dummy_name': {
                                'type': 'str',
                                'required': True,
                                'choices': ['configuration']
                                },
                            'glid': {
                                'type': 'str',
                                },
                            'action': {
                                'type': 'str',
                                'choices': ['bypass', 'deny']
                                },
                            'log_enable': {
                                'type': 'bool',
                                },
                            'log_periodic': {
                                'type': 'bool',
                                },
                            'zone_template': {
                                'type': 'dict',
                                'ip_proto': {
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
                    'glid': {
                        'type': 'str',
                        },
                    'action': {
                        'type': 'str',
                        'choices': ['bypass', 'deny']
                        },
                    'zone_template': {
                        'type': 'dict',
                        'ip_proto': {
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
                'level_list': {
                    'type': 'list',
                    'level_num': {
                        'type': 'str',
                        'required': True,
                        'choices': ['0', '1', '2', '3', '4']
                        },
                    'src_default_glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'blacklist-src', 'ignore']
                        },
                    'zone_escalation_score': {
                        'type': 'int',
                        },
                    'zone_violation_actions': {
                        'type': 'str',
                        },
                    'src_escalation_score': {
                        'type': 'int',
                        },
                    'src_violation_actions': {
                        'type': 'str',
                        },
                    'zone_template': {
                        'type': 'dict',
                        'ip_proto': {
                            'type': 'str',
                            },
                        'encap': {
                            'type': 'str',
                            }
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        },
                    'indicator_list': {
                        'type': 'list',
                        'ntype': {
                            'type': 'str',
                            'required': True,
                            'choices': ['pkt-rate', 'pkt-drop-rate', 'bit-rate', 'pkt-drop-ratio', 'bytes-to-bytes-from-ratio', 'frag-rate', 'cpu-utilization', 'interface-utilization', 'learnt-sources']
                            },
                        'data_packet_size': {
                            'type': 'int',
                            },
                        'score': {
                            'type': 'int',
                            },
                        'src_threshold_num': {
                            'type': 'int',
                            },
                        'src_threshold_large_num': {
                            'type': 'int',
                            },
                        'src_threshold_str': {
                            'type': 'str',
                            },
                        'src_violation_actions': {
                            'type': 'str',
                            },
                        'zone_threshold_num': {
                            'type': 'int',
                            },
                        'zone_threshold_large_num': {
                            'type': 'int',
                            },
                        'zone_threshold_str': {
                            'type': 'str',
                            },
                        'zone_violation_actions': {
                            'type': 'str',
                            },
                        'uuid': {
                            'type': 'str',
                            },
                        'user_tag': {
                            'type': 'str',
                            }
                        }
                    },
                'manual_mode_list': {
                    'type': 'list',
                    'config': {
                        'type': 'str',
                        'required': True,
                        'choices': ['configuration']
                        },
                    'src_default_glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'blacklist-src', 'ignore']
                        },
                    'zone_template': {
                        'type': 'dict',
                        'ip_proto': {
                            'type': 'str',
                            },
                        'encap': {
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
                                'all', 'ip-proto-type', 'ddet_ind_pkt_rate_current', 'ddet_ind_pkt_rate_min', 'ddet_ind_pkt_rate_max', 'ddet_ind_pkt_rate_adaptive_threshold', 'ddet_ind_pkt_drop_rate_current', 'ddet_ind_pkt_drop_rate_min', 'ddet_ind_pkt_drop_rate_max', 'ddet_ind_pkt_drop_rate_adaptive_threshold', 'ddet_ind_syn_rate_current',
                                'ddet_ind_syn_rate_min', 'ddet_ind_syn_rate_max', 'ddet_ind_syn_rate_adaptive_threshold', 'ddet_ind_fin_rate_current', 'ddet_ind_fin_rate_min', 'ddet_ind_fin_rate_max', 'ddet_ind_fin_rate_adaptive_threshold', 'ddet_ind_rst_rate_current', 'ddet_ind_rst_rate_min', 'ddet_ind_rst_rate_max',
                                'ddet_ind_rst_rate_adaptive_threshold', 'ddet_ind_small_window_ack_rate_current', 'ddet_ind_small_window_ack_rate_min', 'ddet_ind_small_window_ack_rate_max', 'ddet_ind_small_window_ack_rate_adaptive_threshold', 'ddet_ind_empty_ack_rate_current', 'ddet_ind_empty_ack_rate_min', 'ddet_ind_empty_ack_rate_max',
                                'ddet_ind_empty_ack_rate_adaptive_threshold', 'ddet_ind_small_payload_rate_current', 'ddet_ind_small_payload_rate_min', 'ddet_ind_small_payload_rate_max', 'ddet_ind_small_payload_rate_adaptive_threshold', 'ddet_ind_pkt_drop_ratio_current', 'ddet_ind_pkt_drop_ratio_min', 'ddet_ind_pkt_drop_ratio_max',
                                'ddet_ind_pkt_drop_ratio_adaptive_threshold', 'ddet_ind_inb_per_outb_current', 'ddet_ind_inb_per_outb_min', 'ddet_ind_inb_per_outb_max', 'ddet_ind_inb_per_outb_adaptive_threshold', 'ddet_ind_syn_per_fin_rate_current', 'ddet_ind_syn_per_fin_rate_min', 'ddet_ind_syn_per_fin_rate_max',
                                'ddet_ind_syn_per_fin_rate_adaptive_threshold', 'ddet_ind_conn_miss_rate_current', 'ddet_ind_conn_miss_rate_min', 'ddet_ind_conn_miss_rate_max', 'ddet_ind_conn_miss_rate_adaptive_threshold', 'ddet_ind_concurrent_conns_current', 'ddet_ind_concurrent_conns_min', 'ddet_ind_concurrent_conns_max',
                                'ddet_ind_concurrent_conns_adaptive_threshold', 'ddet_ind_data_cpu_util_current', 'ddet_ind_data_cpu_util_min', 'ddet_ind_data_cpu_util_max', 'ddet_ind_data_cpu_util_adaptive_threshold', 'ddet_ind_outside_intf_util_current', 'ddet_ind_outside_intf_util_min', 'ddet_ind_outside_intf_util_max',
                                'ddet_ind_outside_intf_util_adaptive_threshold', 'ddet_ind_frag_rate_current', 'ddet_ind_frag_rate_min', 'ddet_ind_frag_rate_max', 'ddet_ind_frag_rate_adaptive_threshold', 'ddet_ind_bit_rate_current', 'ddet_ind_bit_rate_min', 'ddet_ind_bit_rate_max', 'ddet_ind_bit_rate_adaptive_threshold',
                                'ddet_ind_total_szp_current', 'ddet_ind_total_szp_min', 'ddet_ind_total_szp_max', 'ddet_ind_total_szp_adaptive_threshold', 'ddet_ind_syn_ack_rate_current', 'ddet_ind_syn_ack_rate_min', 'ddet_ind_syn_ack_rate_max', 'ddet_ind_syn_ack_rate_adaptive_threshold'
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
                'topk_destinations': {
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
            'proto_tcp_udp_list': {
                'type': 'list',
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['tcp', 'udp']
                    },
                'deny': {
                    'type': 'bool',
                    },
                'glid_cfg': {
                    'type': 'dict',
                    'glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore']
                        },
                    'per_addr_glid': {
                        'type': 'str',
                        },
                    'action_list': {
                        'type': 'str',
                        }
                    },
                'drop_frag_pkt': {
                    'type': 'bool',
                    },
                'set_counter_base_val': {
                    'type': 'int',
                    },
                'sflow_ip_filtering_policy': {
                    'type': 'bool',
                    },
                'ip_filtering_policy': {
                    'type': 'str',
                    },
                'same_source_dest_port_drop': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'ip_filtering_policy_statistics': {
                    'type': 'dict',
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'proto_name_list': {
                'type': 'list',
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['icmp-v4', 'icmp-v6', 'other', 'gre', 'ipv4-encap', 'ipv6-encap']
                    },
                'manual_mode_enable': {
                    'type': 'bool',
                    },
                'deny': {
                    'type': 'bool',
                    },
                'glid_cfg': {
                    'type': 'dict',
                    'glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore']
                        },
                    'action_list': {
                        'type': 'str',
                        },
                    'per_addr_glid': {
                        'type': 'str',
                        }
                    },
                'tunnel_decap': {
                    'type': 'bool',
                    },
                'key_cfg': {
                    'type': 'list',
                    'key': {
                        'type': 'str',
                        }
                    },
                'tunnel_rate_limit': {
                    'type': 'bool',
                    },
                'drop_frag_pkt': {
                    'type': 'bool',
                    },
                'unlimited_dynamic_entry_count': {
                    'type': 'bool',
                    },
                'max_dynamic_entry_count': {
                    'type': 'int',
                    },
                'dynamic_entry_count_warn_threshold': {
                    'type': 'int',
                    },
                'apply_policy_on_overflow': {
                    'type': 'bool',
                    },
                'enable_top_k': {
                    'type': 'bool',
                    },
                'topk_num_records': {
                    'type': 'int',
                    },
                'topk_sort_key': {
                    'type': 'str',
                    'choices': ['avg', 'max-peak']
                    },
                'enable_top_k_destination': {
                    'type': 'bool',
                    },
                'topk_dst_num_records': {
                    'type': 'int',
                    },
                'topk_dst_sort_key': {
                    'type': 'str',
                    'choices': ['avg', 'max-peak']
                    },
                'set_counter_base_val': {
                    'type': 'int',
                    },
                'age': {
                    'type': 'int',
                    },
                'enable_class_list_overflow': {
                    'type': 'bool',
                    },
                'faster_de_escalation': {
                    'type': 'bool',
                    },
                'sflow_ip_filtering_policy': {
                    'type': 'bool',
                    },
                'ip_filtering_policy': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'ip_filtering_policy_statistics': {
                    'type': 'dict',
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'level_list': {
                    'type': 'list',
                    'level_num': {
                        'type': 'str',
                        'required': True,
                        'choices': ['0', '1', '2', '3', '4']
                        },
                    'src_default_glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'blacklist-src', 'ignore']
                        },
                    'zone_escalation_score': {
                        'type': 'int',
                        },
                    'zone_violation_actions': {
                        'type': 'str',
                        },
                    'src_escalation_score': {
                        'type': 'int',
                        },
                    'src_violation_actions': {
                        'type': 'str',
                        },
                    'zone_template': {
                        'type': 'dict',
                        'icmp_v4': {
                            'type': 'str',
                            },
                        'icmp_v6': {
                            'type': 'str',
                            },
                        'ip_proto': {
                            'type': 'str',
                            },
                        'encap': {
                            'type': 'str',
                            }
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        },
                    'indicator_list': {
                        'type': 'list',
                        'ntype': {
                            'type': 'str',
                            'required': True,
                            'choices': ['pkt-rate', 'pkt-drop-rate', 'bit-rate', 'pkt-drop-ratio', 'bytes-to-bytes-from-ratio', 'frag-rate', 'cpu-utilization', 'interface-utilization', 'learnt-sources']
                            },
                        'data_packet_size': {
                            'type': 'int',
                            },
                        'score': {
                            'type': 'int',
                            },
                        'src_threshold_num': {
                            'type': 'int',
                            },
                        'src_threshold_large_num': {
                            'type': 'int',
                            },
                        'src_threshold_str': {
                            'type': 'str',
                            },
                        'src_violation_actions': {
                            'type': 'str',
                            },
                        'zone_threshold_num': {
                            'type': 'int',
                            },
                        'zone_threshold_large_num': {
                            'type': 'int',
                            },
                        'zone_threshold_str': {
                            'type': 'str',
                            },
                        'zone_violation_actions': {
                            'type': 'str',
                            },
                        'uuid': {
                            'type': 'str',
                            },
                        'user_tag': {
                            'type': 'str',
                            }
                        }
                    },
                'manual_mode_list': {
                    'type': 'list',
                    'config': {
                        'type': 'str',
                        'required': True,
                        'choices': ['configuration']
                        },
                    'src_default_glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'blacklist-src', 'ignore']
                        },
                    'zone_template': {
                        'type': 'dict',
                        'icmp_v4': {
                            'type': 'str',
                            },
                        'icmp_v6': {
                            'type': 'str',
                            },
                        'ip_proto': {
                            'type': 'str',
                            },
                        'encap': {
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
                'src_based_policy_list': {
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
                        'class_list_glid': {
                            'type': 'str',
                            },
                        'glid': {
                            'type': 'str',
                            },
                        'glid_action': {
                            'type': 'str',
                            'choices': ['drop', 'blacklist-src', 'ignore']
                            },
                        'action': {
                            'type': 'str',
                            'choices': ['bypass', 'deny']
                            },
                        'log_enable': {
                            'type': 'bool',
                            },
                        'log_periodic': {
                            'type': 'bool',
                            },
                        'max_dynamic_entry_count': {
                            'type': 'int',
                            },
                        'dynamic_entry_count_warn_threshold': {
                            'type': 'int',
                            },
                        'zone_template': {
                            'type': 'dict',
                            'logging': {
                                'type': 'str',
                                },
                            'icmp_v4': {
                                'type': 'str',
                                },
                            'icmp_v6': {
                                'type': 'str',
                                },
                            'ip_proto': {
                                'type': 'str',
                                },
                            'encap': {
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
                                'type': 'str',
                                'choices': ['all', 'packet_received', 'packet_dropped', 'entry_learned', 'entry_count_overflow', 'exceed_drop_pkt_rate_clist', 'exceed_drop_conn_rate_clist', 'exceed_drop_conn_limit_clist', 'exceed_drop_kbit_rate_clist', 'exceed_drop_kbit_rate_clist_pkt', 'exceed_drop_frag_rate_clist']
                                }
                            },
                        'class_list_overflow_policy_list': {
                            'type': 'list',
                            'dummy_name': {
                                'type': 'str',
                                'required': True,
                                'choices': ['configuration']
                                },
                            'glid': {
                                'type': 'str',
                                },
                            'action': {
                                'type': 'str',
                                'choices': ['bypass', 'deny']
                                },
                            'log_enable': {
                                'type': 'bool',
                                },
                            'log_periodic': {
                                'type': 'bool',
                                },
                            'zone_template': {
                                'type': 'dict',
                                'icmp_v4': {
                                    'type': 'str',
                                    },
                                'icmp_v6': {
                                    'type': 'str',
                                    },
                                'ip_proto': {
                                    'type': 'str',
                                    },
                                'encap': {
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
                    'glid': {
                        'type': 'str',
                        },
                    'action': {
                        'type': 'str',
                        'choices': ['bypass', 'deny']
                        },
                    'zone_template': {
                        'type': 'dict',
                        'icmp_v4': {
                            'type': 'str',
                            },
                        'icmp_v6': {
                            'type': 'str',
                            },
                        'ip_proto': {
                            'type': 'str',
                            },
                        'encap': {
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
                                'all', 'ip-proto-type', 'ddet_ind_pkt_rate_current', 'ddet_ind_pkt_rate_min', 'ddet_ind_pkt_rate_max', 'ddet_ind_pkt_rate_adaptive_threshold', 'ddet_ind_pkt_drop_rate_current', 'ddet_ind_pkt_drop_rate_min', 'ddet_ind_pkt_drop_rate_max', 'ddet_ind_pkt_drop_rate_adaptive_threshold', 'ddet_ind_syn_rate_current',
                                'ddet_ind_syn_rate_min', 'ddet_ind_syn_rate_max', 'ddet_ind_syn_rate_adaptive_threshold', 'ddet_ind_fin_rate_current', 'ddet_ind_fin_rate_min', 'ddet_ind_fin_rate_max', 'ddet_ind_fin_rate_adaptive_threshold', 'ddet_ind_rst_rate_current', 'ddet_ind_rst_rate_min', 'ddet_ind_rst_rate_max',
                                'ddet_ind_rst_rate_adaptive_threshold', 'ddet_ind_small_window_ack_rate_current', 'ddet_ind_small_window_ack_rate_min', 'ddet_ind_small_window_ack_rate_max', 'ddet_ind_small_window_ack_rate_adaptive_threshold', 'ddet_ind_empty_ack_rate_current', 'ddet_ind_empty_ack_rate_min', 'ddet_ind_empty_ack_rate_max',
                                'ddet_ind_empty_ack_rate_adaptive_threshold', 'ddet_ind_small_payload_rate_current', 'ddet_ind_small_payload_rate_min', 'ddet_ind_small_payload_rate_max', 'ddet_ind_small_payload_rate_adaptive_threshold', 'ddet_ind_pkt_drop_ratio_current', 'ddet_ind_pkt_drop_ratio_min', 'ddet_ind_pkt_drop_ratio_max',
                                'ddet_ind_pkt_drop_ratio_adaptive_threshold', 'ddet_ind_inb_per_outb_current', 'ddet_ind_inb_per_outb_min', 'ddet_ind_inb_per_outb_max', 'ddet_ind_inb_per_outb_adaptive_threshold', 'ddet_ind_syn_per_fin_rate_current', 'ddet_ind_syn_per_fin_rate_min', 'ddet_ind_syn_per_fin_rate_max',
                                'ddet_ind_syn_per_fin_rate_adaptive_threshold', 'ddet_ind_conn_miss_rate_current', 'ddet_ind_conn_miss_rate_min', 'ddet_ind_conn_miss_rate_max', 'ddet_ind_conn_miss_rate_adaptive_threshold', 'ddet_ind_concurrent_conns_current', 'ddet_ind_concurrent_conns_min', 'ddet_ind_concurrent_conns_max',
                                'ddet_ind_concurrent_conns_adaptive_threshold', 'ddet_ind_data_cpu_util_current', 'ddet_ind_data_cpu_util_min', 'ddet_ind_data_cpu_util_max', 'ddet_ind_data_cpu_util_adaptive_threshold', 'ddet_ind_outside_intf_util_current', 'ddet_ind_outside_intf_util_min', 'ddet_ind_outside_intf_util_max',
                                'ddet_ind_outside_intf_util_adaptive_threshold', 'ddet_ind_frag_rate_current', 'ddet_ind_frag_rate_min', 'ddet_ind_frag_rate_max', 'ddet_ind_frag_rate_adaptive_threshold', 'ddet_ind_bit_rate_current', 'ddet_ind_bit_rate_min', 'ddet_ind_bit_rate_max', 'ddet_ind_bit_rate_adaptive_threshold',
                                'ddet_ind_total_szp_current', 'ddet_ind_total_szp_min', 'ddet_ind_total_szp_max', 'ddet_ind_total_szp_adaptive_threshold', 'ddet_ind_syn_ack_rate_current', 'ddet_ind_syn_ack_rate_min', 'ddet_ind_syn_ack_rate_max', 'ddet_ind_syn_ack_rate_adaptive_threshold'
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
                'topk_destinations': {
                    'type': 'dict',
                    'uuid': {
                        'type': 'str',
                        }
                    }
                }
            },
        'port': {
            'type': 'dict',
            'zone_service_list': {
                'type': 'list',
                'port_num': {
                    'type': 'int',
                    'required': True,
                    },
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4', 'sip-udp', 'sip-tcp', 'quic']
                    },
                'manual_mode_enable': {
                    'type': 'bool',
                    },
                'deny': {
                    'type': 'bool',
                    },
                'glid_cfg': {
                    'type': 'dict',
                    'glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore']
                        },
                    'action_list': {
                        'type': 'str',
                        },
                    'per_addr_glid': {
                        'type': 'str',
                        }
                    },
                'stateful': {
                    'type': 'bool',
                    },
                'default_action_list': {
                    'type': 'str',
                    },
                'sflow_common': {
                    'type': 'bool',
                    },
                'sflow_packets': {
                    'type': 'bool',
                    },
                'sflow_ip_filtering_policy': {
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
                'unlimited_dynamic_entry_count': {
                    'type': 'bool',
                    },
                'max_dynamic_entry_count': {
                    'type': 'int',
                    },
                'dynamic_entry_count_warn_threshold': {
                    'type': 'int',
                    },
                'apply_policy_on_overflow': {
                    'type': 'bool',
                    },
                'enable_class_list_overflow': {
                    'type': 'bool',
                    },
                'age': {
                    'type': 'int',
                    },
                'enable_top_k': {
                    'type': 'bool',
                    },
                'topk_num_records': {
                    'type': 'int',
                    },
                'topk_sort_key': {
                    'type': 'str',
                    'choices': ['avg', 'max-peak']
                    },
                'enable_top_k_destination': {
                    'type': 'bool',
                    },
                'topk_dst_num_records': {
                    'type': 'int',
                    },
                'topk_dst_sort_key': {
                    'type': 'str',
                    'choices': ['avg', 'max-peak']
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
                'outbound_only': {
                    'type': 'bool',
                    },
                'faster_de_escalation': {
                    'type': 'bool',
                    },
                'ip_filtering_policy': {
                    'type': 'str',
                    },
                'same_source_dest_port_drop': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
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
                    'triggered_by': {
                        'type': 'str',
                        'choices': ['zone-escalation', 'packet-rate-exceeds']
                        },
                    'capture_traffic': {
                        'type': 'str',
                        'choices': ['all', 'dropped']
                        },
                    'app_payload_offset': {
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
                    },
                'ip_filtering_policy_statistics': {
                    'type': 'dict',
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'level_list': {
                    'type': 'list',
                    'level_num': {
                        'type': 'str',
                        'required': True,
                        'choices': ['0', '1', '2', '3', '4']
                        },
                    'src_default_glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'blacklist-src', 'ignore']
                        },
                    'zone_escalation_score': {
                        'type': 'int',
                        },
                    'zone_violation_actions': {
                        'type': 'str',
                        },
                    'src_escalation_score': {
                        'type': 'int',
                        },
                    'src_violation_actions': {
                        'type': 'str',
                        },
                    'zone_template': {
                        'type': 'dict',
                        'quic': {
                            'type': 'str',
                            },
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
                            },
                        'encap': {
                            'type': 'str',
                            }
                        },
                    'close_sessions_for_unauth_sources': {
                        'type': 'bool',
                        },
                    'close_sessions_for_all_sources': {
                        'type': 'bool',
                        },
                    'clear_sources_upon_deescalation': {
                        'type': 'bool',
                        },
                    'start_signature_extraction': {
                        'type': 'bool',
                        },
                    'start_pattern_recognition': {
                        'type': 'bool',
                        },
                    'apply_extracted_filters': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        },
                    'indicator_list': {
                        'type': 'list',
                        'ntype': {
                            'type':
                            'str',
                            'required':
                            True,
                            'choices': [
                                'pkt-rate', 'pkt-drop-rate', 'bit-rate', 'pkt-drop-ratio', 'bytes-to-bytes-from-ratio', 'concurrent-conns', 'conn-miss-rate', 'syn-rate', 'fin-rate', 'rst-rate', 'syn-ack-rate', 'small-window-ack-rate', 'empty-ack-rate', 'small-payload-rate', 'syn-fin-ratio', 'cpu-utilization', 'interface-utilization',
                                'learnt-sources'
                                ]
                            },
                        'tcp_window_size': {
                            'type': 'int',
                            },
                        'data_packet_size': {
                            'type': 'int',
                            },
                        'score': {
                            'type': 'int',
                            },
                        'src_threshold_num': {
                            'type': 'int',
                            },
                        'src_threshold_large_num': {
                            'type': 'int',
                            },
                        'src_threshold_str': {
                            'type': 'str',
                            },
                        'src_violation_actions': {
                            'type': 'str',
                            },
                        'zone_threshold_large_num': {
                            'type': 'int',
                            },
                        'zone_threshold_num': {
                            'type': 'int',
                            },
                        'zone_threshold_str': {
                            'type': 'str',
                            },
                        'zone_violation_actions': {
                            'type': 'str',
                            },
                        'uuid': {
                            'type': 'str',
                            },
                        'user_tag': {
                            'type': 'str',
                            }
                        }
                    },
                'manual_mode_list': {
                    'type': 'list',
                    'config': {
                        'type': 'str',
                        'required': True,
                        'choices': ['configuration']
                        },
                    'src_default_glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'blacklist-src', 'ignore']
                        },
                    'zone_template': {
                        'type': 'dict',
                        'quic': {
                            'type': 'str',
                            },
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
                            },
                        'encap': {
                            'type': 'str',
                            }
                        },
                    'close_sessions_for_unauth_sources': {
                        'type': 'bool',
                        },
                    'close_sessions_for_all_sources': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        }
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
                                'all', 'ip-proto-type', 'ddet_ind_pkt_rate_current', 'ddet_ind_pkt_rate_min', 'ddet_ind_pkt_rate_max', 'ddet_ind_pkt_rate_adaptive_threshold', 'ddet_ind_pkt_drop_rate_current', 'ddet_ind_pkt_drop_rate_min', 'ddet_ind_pkt_drop_rate_max', 'ddet_ind_pkt_drop_rate_adaptive_threshold', 'ddet_ind_syn_rate_current',
                                'ddet_ind_syn_rate_min', 'ddet_ind_syn_rate_max', 'ddet_ind_syn_rate_adaptive_threshold', 'ddet_ind_fin_rate_current', 'ddet_ind_fin_rate_min', 'ddet_ind_fin_rate_max', 'ddet_ind_fin_rate_adaptive_threshold', 'ddet_ind_rst_rate_current', 'ddet_ind_rst_rate_min', 'ddet_ind_rst_rate_max',
                                'ddet_ind_rst_rate_adaptive_threshold', 'ddet_ind_small_window_ack_rate_current', 'ddet_ind_small_window_ack_rate_min', 'ddet_ind_small_window_ack_rate_max', 'ddet_ind_small_window_ack_rate_adaptive_threshold', 'ddet_ind_empty_ack_rate_current', 'ddet_ind_empty_ack_rate_min', 'ddet_ind_empty_ack_rate_max',
                                'ddet_ind_empty_ack_rate_adaptive_threshold', 'ddet_ind_small_payload_rate_current', 'ddet_ind_small_payload_rate_min', 'ddet_ind_small_payload_rate_max', 'ddet_ind_small_payload_rate_adaptive_threshold', 'ddet_ind_pkt_drop_ratio_current', 'ddet_ind_pkt_drop_ratio_min', 'ddet_ind_pkt_drop_ratio_max',
                                'ddet_ind_pkt_drop_ratio_adaptive_threshold', 'ddet_ind_inb_per_outb_current', 'ddet_ind_inb_per_outb_min', 'ddet_ind_inb_per_outb_max', 'ddet_ind_inb_per_outb_adaptive_threshold', 'ddet_ind_syn_per_fin_rate_current', 'ddet_ind_syn_per_fin_rate_min', 'ddet_ind_syn_per_fin_rate_max',
                                'ddet_ind_syn_per_fin_rate_adaptive_threshold', 'ddet_ind_conn_miss_rate_current', 'ddet_ind_conn_miss_rate_min', 'ddet_ind_conn_miss_rate_max', 'ddet_ind_conn_miss_rate_adaptive_threshold', 'ddet_ind_concurrent_conns_current', 'ddet_ind_concurrent_conns_min', 'ddet_ind_concurrent_conns_max',
                                'ddet_ind_concurrent_conns_adaptive_threshold', 'ddet_ind_data_cpu_util_current', 'ddet_ind_data_cpu_util_min', 'ddet_ind_data_cpu_util_max', 'ddet_ind_data_cpu_util_adaptive_threshold', 'ddet_ind_outside_intf_util_current', 'ddet_ind_outside_intf_util_min', 'ddet_ind_outside_intf_util_max',
                                'ddet_ind_outside_intf_util_adaptive_threshold', 'ddet_ind_frag_rate_current', 'ddet_ind_frag_rate_min', 'ddet_ind_frag_rate_max', 'ddet_ind_frag_rate_adaptive_threshold', 'ddet_ind_bit_rate_current', 'ddet_ind_bit_rate_min', 'ddet_ind_bit_rate_max', 'ddet_ind_bit_rate_adaptive_threshold',
                                'ddet_ind_total_szp_current', 'ddet_ind_total_szp_min', 'ddet_ind_total_szp_max', 'ddet_ind_total_szp_adaptive_threshold', 'ddet_ind_syn_ack_rate_current', 'ddet_ind_syn_ack_rate_min', 'ddet_ind_syn_ack_rate_max', 'ddet_ind_syn_ack_rate_adaptive_threshold'
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
                'topk_destinations': {
                    'type': 'dict',
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'src_based_policy_list': {
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
                        'class_list_glid': {
                            'type': 'str',
                            },
                        'glid': {
                            'type': 'str',
                            },
                        'glid_action': {
                            'type': 'str',
                            'choices': ['drop', 'blacklist-src', 'ignore']
                            },
                        'action': {
                            'type': 'str',
                            'choices': ['bypass', 'deny']
                            },
                        'log_enable': {
                            'type': 'bool',
                            },
                        'log_periodic': {
                            'type': 'bool',
                            },
                        'max_dynamic_entry_count': {
                            'type': 'int',
                            },
                        'dynamic_entry_count_warn_threshold': {
                            'type': 'int',
                            },
                        'zone_template': {
                            'type': 'dict',
                            'quic': {
                                'type': 'str',
                                },
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
                                },
                            'encap': {
                                'type': 'str',
                                },
                            'logging': {
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
                                'type': 'str',
                                'choices': ['all', 'packet_received', 'packet_dropped', 'entry_learned', 'entry_count_overflow', 'exceed_drop_pkt_rate_clist', 'exceed_drop_conn_rate_clist', 'exceed_drop_conn_limit_clist', 'exceed_drop_kbit_rate_clist', 'exceed_drop_kbit_rate_clist_pkt', 'exceed_drop_frag_rate_clist']
                                }
                            },
                        'class_list_overflow_policy_list': {
                            'type': 'list',
                            'dummy_name': {
                                'type': 'str',
                                'required': True,
                                'choices': ['configuration']
                                },
                            'glid': {
                                'type': 'str',
                                },
                            'action': {
                                'type': 'str',
                                'choices': ['bypass', 'deny']
                                },
                            'log_enable': {
                                'type': 'bool',
                                },
                            'log_periodic': {
                                'type': 'bool',
                                },
                            'zone_template': {
                                'type': 'dict',
                                'quic': {
                                    'type': 'str',
                                    },
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
                                    },
                                'encap': {
                                    'type': 'str',
                                    },
                                'logging': {
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
                    'glid': {
                        'type': 'str',
                        },
                    'action': {
                        'type': 'str',
                        'choices': ['bypass', 'deny']
                        },
                    'log_enable': {
                        'type': 'bool',
                        },
                    'log_periodic': {
                        'type': 'bool',
                        },
                    'zone_template': {
                        'type': 'dict',
                        'quic': {
                            'type': 'str',
                            },
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
                            },
                        'encap': {
                            'type': 'str',
                            },
                        'logging': {
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
                'virtualhosts': {
                    'type': 'dict',
                    'vhosts_config': {
                        'type': 'str',
                        'choices': ['configuration']
                        },
                    'source_tracking_all': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'virtualhost_list': {
                        'type': 'list',
                        'vhost': {
                            'type': 'str',
                            'required': True,
                            },
                        'servername': {
                            'type': 'list',
                            'match_type': {
                                'type': 'str',
                                'choices': ['contains', 'ends-with', 'equals', 'starts-with']
                                },
                            'host_match_string': {
                                'type': 'str',
                                }
                            },
                        'servername_list': {
                            'type': 'str',
                            },
                        'servername_match_any': {
                            'type': 'bool',
                            },
                        'servername_no_sni': {
                            'type': 'bool',
                            },
                        'source_tracking': {
                            'type': 'str',
                            'choices': ['follow', 'enable', 'disable']
                            },
                        'glid_cfg': {
                            'type': 'dict',
                            'glid': {
                                'type': 'str',
                                },
                            'glid_action': {
                                'type': 'str',
                                'choices': ['drop', 'ignore']
                                }
                            },
                        'deny': {
                            'type': 'bool',
                            },
                        'uuid': {
                            'type': 'str',
                            },
                        'user_tag': {
                            'type': 'str',
                            },
                        'level_list': {
                            'type': 'list',
                            'level_num': {
                                'type': 'str',
                                'required': True,
                                'choices': ['0']
                                },
                            'src_default_glid': {
                                'type': 'str',
                                },
                            'glid_action': {
                                'type': 'str',
                                'choices': ['drop', 'blacklist-src', 'ignore']
                                },
                            'zone_template': {
                                'type': 'dict',
                                'ssl_l4': {
                                    'type': 'str',
                                    },
                                'tcp': {
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
            'zone_service_other_list': {
                'type': 'list',
                'port_other': {
                    'type': 'str',
                    'required': True,
                    'choices': ['other']
                    },
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['tcp', 'udp']
                    },
                'manual_mode_enable': {
                    'type': 'bool',
                    },
                'enable_top_k': {
                    'type': 'bool',
                    },
                'topk_num_records': {
                    'type': 'int',
                    },
                'topk_sort_key': {
                    'type': 'str',
                    'choices': ['avg', 'max-peak']
                    },
                'enable_top_k_destination': {
                    'type': 'bool',
                    },
                'topk_dst_num_records': {
                    'type': 'int',
                    },
                'topk_dst_sort_key': {
                    'type': 'str',
                    'choices': ['avg', 'max-peak']
                    },
                'deny': {
                    'type': 'bool',
                    },
                'glid_cfg': {
                    'type': 'dict',
                    'glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore']
                        },
                    'action_list': {
                        'type': 'str',
                        },
                    'per_addr_glid': {
                        'type': 'str',
                        }
                    },
                'stateful': {
                    'type': 'bool',
                    },
                'default_action_list': {
                    'type': 'str',
                    },
                'sflow_common': {
                    'type': 'bool',
                    },
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
                'sflow_ip_filtering_policy': {
                    'type': 'bool',
                    },
                'unlimited_dynamic_entry_count': {
                    'type': 'bool',
                    },
                'max_dynamic_entry_count': {
                    'type': 'int',
                    },
                'dynamic_entry_count_warn_threshold': {
                    'type': 'int',
                    },
                'apply_policy_on_overflow': {
                    'type': 'bool',
                    },
                'set_counter_base_val': {
                    'type': 'int',
                    },
                'enable_class_list_overflow': {
                    'type': 'bool',
                    },
                'age': {
                    'type': 'int',
                    },
                'outbound_only': {
                    'type': 'bool',
                    },
                'faster_de_escalation': {
                    'type': 'bool',
                    },
                'ip_filtering_policy': {
                    'type': 'str',
                    },
                'same_source_dest_port_drop': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'ip_filtering_policy_statistics': {
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
                    'triggered_by': {
                        'type': 'str',
                        'choices': ['zone-escalation', 'packet-rate-exceeds']
                        },
                    'capture_traffic': {
                        'type': 'str',
                        'choices': ['all', 'dropped']
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
                    },
                'level_list': {
                    'type': 'list',
                    'level_num': {
                        'type': 'str',
                        'required': True,
                        'choices': ['0', '1', '2', '3', '4']
                        },
                    'src_default_glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'blacklist-src', 'ignore']
                        },
                    'zone_escalation_score': {
                        'type': 'int',
                        },
                    'zone_violation_actions': {
                        'type': 'str',
                        },
                    'src_escalation_score': {
                        'type': 'int',
                        },
                    'src_violation_actions': {
                        'type': 'str',
                        },
                    'zone_template': {
                        'type': 'dict',
                        'tcp': {
                            'type': 'str',
                            },
                        'udp': {
                            'type': 'str',
                            },
                        'encap': {
                            'type': 'str',
                            }
                        },
                    'close_sessions_for_unauth_sources': {
                        'type': 'bool',
                        },
                    'close_sessions_for_all_sources': {
                        'type': 'bool',
                        },
                    'clear_sources_upon_deescalation': {
                        'type': 'bool',
                        },
                    'start_pattern_recognition': {
                        'type': 'bool',
                        },
                    'apply_extracted_filters': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        },
                    'indicator_list': {
                        'type': 'list',
                        'ntype': {
                            'type':
                            'str',
                            'required':
                            True,
                            'choices': [
                                'pkt-rate', 'pkt-drop-rate', 'bit-rate', 'pkt-drop-ratio', 'bytes-to-bytes-from-ratio', 'concurrent-conns', 'conn-miss-rate', 'syn-rate', 'fin-rate', 'rst-rate', 'syn-ack-rate', 'small-window-ack-rate', 'empty-ack-rate', 'small-payload-rate', 'syn-fin-ratio', 'cpu-utilization', 'interface-utilization',
                                'learnt-sources'
                                ]
                            },
                        'tcp_window_size': {
                            'type': 'int',
                            },
                        'data_packet_size': {
                            'type': 'int',
                            },
                        'score': {
                            'type': 'int',
                            },
                        'src_threshold_num': {
                            'type': 'int',
                            },
                        'src_threshold_large_num': {
                            'type': 'int',
                            },
                        'src_threshold_str': {
                            'type': 'str',
                            },
                        'src_violation_actions': {
                            'type': 'str',
                            },
                        'zone_threshold_num': {
                            'type': 'int',
                            },
                        'zone_threshold_large_num': {
                            'type': 'int',
                            },
                        'zone_threshold_str': {
                            'type': 'str',
                            },
                        'zone_violation_actions': {
                            'type': 'str',
                            },
                        'uuid': {
                            'type': 'str',
                            },
                        'user_tag': {
                            'type': 'str',
                            }
                        }
                    },
                'manual_mode_list': {
                    'type': 'list',
                    'config': {
                        'type': 'str',
                        'required': True,
                        'choices': ['configuration']
                        },
                    'src_default_glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'blacklist-src', 'ignore']
                        },
                    'zone_template': {
                        'type': 'dict',
                        'tcp': {
                            'type': 'str',
                            },
                        'udp': {
                            'type': 'str',
                            },
                        'encap': {
                            'type': 'str',
                            }
                        },
                    'close_sessions_for_unauth_sources': {
                        'type': 'bool',
                        },
                    'close_sessions_for_all_sources': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        }
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
                                'all', 'ip-proto-type', 'ddet_ind_pkt_rate_current', 'ddet_ind_pkt_rate_min', 'ddet_ind_pkt_rate_max', 'ddet_ind_pkt_rate_adaptive_threshold', 'ddet_ind_pkt_drop_rate_current', 'ddet_ind_pkt_drop_rate_min', 'ddet_ind_pkt_drop_rate_max', 'ddet_ind_pkt_drop_rate_adaptive_threshold', 'ddet_ind_syn_rate_current',
                                'ddet_ind_syn_rate_min', 'ddet_ind_syn_rate_max', 'ddet_ind_syn_rate_adaptive_threshold', 'ddet_ind_fin_rate_current', 'ddet_ind_fin_rate_min', 'ddet_ind_fin_rate_max', 'ddet_ind_fin_rate_adaptive_threshold', 'ddet_ind_rst_rate_current', 'ddet_ind_rst_rate_min', 'ddet_ind_rst_rate_max',
                                'ddet_ind_rst_rate_adaptive_threshold', 'ddet_ind_small_window_ack_rate_current', 'ddet_ind_small_window_ack_rate_min', 'ddet_ind_small_window_ack_rate_max', 'ddet_ind_small_window_ack_rate_adaptive_threshold', 'ddet_ind_empty_ack_rate_current', 'ddet_ind_empty_ack_rate_min', 'ddet_ind_empty_ack_rate_max',
                                'ddet_ind_empty_ack_rate_adaptive_threshold', 'ddet_ind_small_payload_rate_current', 'ddet_ind_small_payload_rate_min', 'ddet_ind_small_payload_rate_max', 'ddet_ind_small_payload_rate_adaptive_threshold', 'ddet_ind_pkt_drop_ratio_current', 'ddet_ind_pkt_drop_ratio_min', 'ddet_ind_pkt_drop_ratio_max',
                                'ddet_ind_pkt_drop_ratio_adaptive_threshold', 'ddet_ind_inb_per_outb_current', 'ddet_ind_inb_per_outb_min', 'ddet_ind_inb_per_outb_max', 'ddet_ind_inb_per_outb_adaptive_threshold', 'ddet_ind_syn_per_fin_rate_current', 'ddet_ind_syn_per_fin_rate_min', 'ddet_ind_syn_per_fin_rate_max',
                                'ddet_ind_syn_per_fin_rate_adaptive_threshold', 'ddet_ind_conn_miss_rate_current', 'ddet_ind_conn_miss_rate_min', 'ddet_ind_conn_miss_rate_max', 'ddet_ind_conn_miss_rate_adaptive_threshold', 'ddet_ind_concurrent_conns_current', 'ddet_ind_concurrent_conns_min', 'ddet_ind_concurrent_conns_max',
                                'ddet_ind_concurrent_conns_adaptive_threshold', 'ddet_ind_data_cpu_util_current', 'ddet_ind_data_cpu_util_min', 'ddet_ind_data_cpu_util_max', 'ddet_ind_data_cpu_util_adaptive_threshold', 'ddet_ind_outside_intf_util_current', 'ddet_ind_outside_intf_util_min', 'ddet_ind_outside_intf_util_max',
                                'ddet_ind_outside_intf_util_adaptive_threshold', 'ddet_ind_frag_rate_current', 'ddet_ind_frag_rate_min', 'ddet_ind_frag_rate_max', 'ddet_ind_frag_rate_adaptive_threshold', 'ddet_ind_bit_rate_current', 'ddet_ind_bit_rate_min', 'ddet_ind_bit_rate_max', 'ddet_ind_bit_rate_adaptive_threshold',
                                'ddet_ind_total_szp_current', 'ddet_ind_total_szp_min', 'ddet_ind_total_szp_max', 'ddet_ind_total_szp_adaptive_threshold', 'ddet_ind_syn_ack_rate_current', 'ddet_ind_syn_ack_rate_min', 'ddet_ind_syn_ack_rate_max', 'ddet_ind_syn_ack_rate_adaptive_threshold'
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
                'topk_destinations': {
                    'type': 'dict',
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'src_based_policy_list': {
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
                        'class_list_glid': {
                            'type': 'str',
                            },
                        'glid': {
                            'type': 'str',
                            },
                        'glid_action': {
                            'type': 'str',
                            'choices': ['drop', 'blacklist-src', 'ignore']
                            },
                        'action': {
                            'type': 'str',
                            'choices': ['bypass', 'deny']
                            },
                        'max_dynamic_entry_count': {
                            'type': 'int',
                            },
                        'dynamic_entry_count_warn_threshold': {
                            'type': 'int',
                            },
                        'zone_template': {
                            'type': 'dict',
                            'tcp': {
                                'type': 'str',
                                },
                            'udp': {
                                'type': 'str',
                                },
                            'encap': {
                                'type': 'str',
                                },
                            'logging': {
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
                                'type': 'str',
                                'choices': ['all', 'packet_received', 'packet_dropped', 'entry_learned', 'entry_count_overflow', 'exceed_drop_pkt_rate_clist', 'exceed_drop_conn_rate_clist', 'exceed_drop_conn_limit_clist', 'exceed_drop_kbit_rate_clist', 'exceed_drop_kbit_rate_clist_pkt', 'exceed_drop_frag_rate_clist']
                                }
                            },
                        'class_list_overflow_policy_list': {
                            'type': 'list',
                            'dummy_name': {
                                'type': 'str',
                                'required': True,
                                'choices': ['configuration']
                                },
                            'glid': {
                                'type': 'str',
                                },
                            'action': {
                                'type': 'str',
                                'choices': ['bypass', 'deny']
                                },
                            'log_enable': {
                                'type': 'bool',
                                },
                            'log_periodic': {
                                'type': 'bool',
                                },
                            'zone_template': {
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
                                    },
                                'encap': {
                                    'type': 'str',
                                    },
                                'logging': {
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
                    'glid': {
                        'type': 'str',
                        },
                    'action': {
                        'type': 'str',
                        'choices': ['bypass', 'deny']
                        },
                    'log_enable': {
                        'type': 'bool',
                        },
                    'log_periodic': {
                        'type': 'bool',
                        },
                    'zone_template': {
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
                            },
                        'encap': {
                            'type': 'str',
                            },
                        'logging': {
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
                'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4', 'sip-udp', 'sip-tcp', 'quic']
                },
            'manual_mode_enable': {
                'type': 'bool',
                },
            'deny': {
                'type': 'bool',
                },
            'glid_cfg': {
                'type': 'dict',
                'glid': {
                    'type': 'str',
                    },
                'glid_action': {
                    'type': 'str',
                    'choices': ['drop', 'ignore']
                    },
                'action_list': {
                    'type': 'str',
                    },
                'per_addr_glid': {
                    'type': 'str',
                    }
                },
            'stateful': {
                'type': 'bool',
                },
            'default_action_list': {
                'type': 'str',
                },
            'sflow_common': {
                'type': 'bool',
                },
            'sflow_packets': {
                'type': 'bool',
                },
            'sflow_ip_filtering_policy': {
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
            'unlimited_dynamic_entry_count': {
                'type': 'bool',
                },
            'max_dynamic_entry_count': {
                'type': 'int',
                },
            'dynamic_entry_count_warn_threshold': {
                'type': 'int',
                },
            'apply_policy_on_overflow': {
                'type': 'bool',
                },
            'enable_class_list_overflow': {
                'type': 'bool',
                },
            'enable_top_k': {
                'type': 'bool',
                },
            'topk_num_records': {
                'type': 'int',
                },
            'topk_sort_key': {
                'type': 'str',
                'choices': ['avg', 'max-peak']
                },
            'enable_top_k_destination': {
                'type': 'bool',
                },
            'topk_dst_num_records': {
                'type': 'int',
                },
            'topk_dst_sort_key': {
                'type': 'str',
                'choices': ['avg', 'max-peak']
                },
            'set_counter_base_val': {
                'type': 'int',
                },
            'age': {
                'type': 'int',
                },
            'outbound_only': {
                'type': 'bool',
                },
            'faster_de_escalation': {
                'type': 'bool',
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
            'ip_filtering_policy': {
                'type': 'str',
                },
            'same_source_dest_port_drop': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'ip_filtering_policy_statistics': {
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
                'triggered_by': {
                    'type': 'str',
                    'choices': ['zone-escalation', 'packet-rate-exceeds']
                    },
                'capture_traffic': {
                    'type': 'str',
                    'choices': ['all', 'dropped']
                    },
                'app_payload_offset': {
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
                },
            'level_list': {
                'type': 'list',
                'level_num': {
                    'type': 'str',
                    'required': True,
                    'choices': ['0', '1', '2', '3', '4']
                    },
                'src_default_glid': {
                    'type': 'str',
                    },
                'glid_action': {
                    'type': 'str',
                    'choices': ['drop', 'blacklist-src', 'ignore']
                    },
                'zone_escalation_score': {
                    'type': 'int',
                    },
                'zone_violation_actions': {
                    'type': 'str',
                    },
                'src_escalation_score': {
                    'type': 'int',
                    },
                'src_violation_actions': {
                    'type': 'str',
                    },
                'zone_template': {
                    'type': 'dict',
                    'quic': {
                        'type': 'str',
                        },
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
                        },
                    'encap': {
                        'type': 'str',
                        }
                    },
                'close_sessions_for_unauth_sources': {
                    'type': 'bool',
                    },
                'close_sessions_for_all_sources': {
                    'type': 'bool',
                    },
                'clear_sources_upon_deescalation': {
                    'type': 'bool',
                    },
                'start_pattern_recognition': {
                    'type': 'bool',
                    },
                'apply_extracted_filters': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'indicator_list': {
                    'type': 'list',
                    'ntype': {
                        'type':
                        'str',
                        'required':
                        True,
                        'choices':
                        ['pkt-rate', 'pkt-drop-rate', 'bit-rate', 'pkt-drop-ratio', 'bytes-to-bytes-from-ratio', 'concurrent-conns', 'conn-miss-rate', 'syn-rate', 'fin-rate', 'rst-rate', 'syn-ack-rate', 'small-window-ack-rate', 'empty-ack-rate', 'small-payload-rate', 'syn-fin-ratio', 'cpu-utilization', 'interface-utilization', 'learnt-sources']
                        },
                    'tcp_window_size': {
                        'type': 'int',
                        },
                    'data_packet_size': {
                        'type': 'int',
                        },
                    'score': {
                        'type': 'int',
                        },
                    'src_threshold_num': {
                        'type': 'int',
                        },
                    'src_threshold_large_num': {
                        'type': 'int',
                        },
                    'src_threshold_str': {
                        'type': 'str',
                        },
                    'src_violation_actions': {
                        'type': 'str',
                        },
                    'zone_threshold_num': {
                        'type': 'int',
                        },
                    'zone_threshold_large_num': {
                        'type': 'int',
                        },
                    'zone_threshold_str': {
                        'type': 'str',
                        },
                    'zone_violation_actions': {
                        'type': 'str',
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        }
                    }
                },
            'manual_mode_list': {
                'type': 'list',
                'config': {
                    'type': 'str',
                    'required': True,
                    'choices': ['configuration']
                    },
                'src_default_glid': {
                    'type': 'str',
                    },
                'glid_action': {
                    'type': 'str',
                    'choices': ['drop', 'blacklist-src', 'ignore']
                    },
                'zone_template': {
                    'type': 'dict',
                    'quic': {
                        'type': 'str',
                        },
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
                        },
                    'encap': {
                        'type': 'str',
                        }
                    },
                'close_sessions_for_unauth_sources': {
                    'type': 'bool',
                    },
                'close_sessions_for_all_sources': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    }
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
                            'all', 'ip-proto-type', 'ddet_ind_pkt_rate_current', 'ddet_ind_pkt_rate_min', 'ddet_ind_pkt_rate_max', 'ddet_ind_pkt_rate_adaptive_threshold', 'ddet_ind_pkt_drop_rate_current', 'ddet_ind_pkt_drop_rate_min', 'ddet_ind_pkt_drop_rate_max', 'ddet_ind_pkt_drop_rate_adaptive_threshold', 'ddet_ind_syn_rate_current',
                            'ddet_ind_syn_rate_min', 'ddet_ind_syn_rate_max', 'ddet_ind_syn_rate_adaptive_threshold', 'ddet_ind_fin_rate_current', 'ddet_ind_fin_rate_min', 'ddet_ind_fin_rate_max', 'ddet_ind_fin_rate_adaptive_threshold', 'ddet_ind_rst_rate_current', 'ddet_ind_rst_rate_min', 'ddet_ind_rst_rate_max',
                            'ddet_ind_rst_rate_adaptive_threshold', 'ddet_ind_small_window_ack_rate_current', 'ddet_ind_small_window_ack_rate_min', 'ddet_ind_small_window_ack_rate_max', 'ddet_ind_small_window_ack_rate_adaptive_threshold', 'ddet_ind_empty_ack_rate_current', 'ddet_ind_empty_ack_rate_min', 'ddet_ind_empty_ack_rate_max',
                            'ddet_ind_empty_ack_rate_adaptive_threshold', 'ddet_ind_small_payload_rate_current', 'ddet_ind_small_payload_rate_min', 'ddet_ind_small_payload_rate_max', 'ddet_ind_small_payload_rate_adaptive_threshold', 'ddet_ind_pkt_drop_ratio_current', 'ddet_ind_pkt_drop_ratio_min', 'ddet_ind_pkt_drop_ratio_max',
                            'ddet_ind_pkt_drop_ratio_adaptive_threshold', 'ddet_ind_inb_per_outb_current', 'ddet_ind_inb_per_outb_min', 'ddet_ind_inb_per_outb_max', 'ddet_ind_inb_per_outb_adaptive_threshold', 'ddet_ind_syn_per_fin_rate_current', 'ddet_ind_syn_per_fin_rate_min', 'ddet_ind_syn_per_fin_rate_max',
                            'ddet_ind_syn_per_fin_rate_adaptive_threshold', 'ddet_ind_conn_miss_rate_current', 'ddet_ind_conn_miss_rate_min', 'ddet_ind_conn_miss_rate_max', 'ddet_ind_conn_miss_rate_adaptive_threshold', 'ddet_ind_concurrent_conns_current', 'ddet_ind_concurrent_conns_min', 'ddet_ind_concurrent_conns_max',
                            'ddet_ind_concurrent_conns_adaptive_threshold', 'ddet_ind_data_cpu_util_current', 'ddet_ind_data_cpu_util_min', 'ddet_ind_data_cpu_util_max', 'ddet_ind_data_cpu_util_adaptive_threshold', 'ddet_ind_outside_intf_util_current', 'ddet_ind_outside_intf_util_min', 'ddet_ind_outside_intf_util_max',
                            'ddet_ind_outside_intf_util_adaptive_threshold', 'ddet_ind_frag_rate_current', 'ddet_ind_frag_rate_min', 'ddet_ind_frag_rate_max', 'ddet_ind_frag_rate_adaptive_threshold', 'ddet_ind_bit_rate_current', 'ddet_ind_bit_rate_min', 'ddet_ind_bit_rate_max', 'ddet_ind_bit_rate_adaptive_threshold', 'ddet_ind_total_szp_current',
                            'ddet_ind_total_szp_min', 'ddet_ind_total_szp_max', 'ddet_ind_total_szp_adaptive_threshold', 'ddet_ind_syn_ack_rate_current', 'ddet_ind_syn_ack_rate_min', 'ddet_ind_syn_ack_rate_max', 'ddet_ind_syn_ack_rate_adaptive_threshold'
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
            'topk_destinations': {
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
            'src_based_policy_list': {
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
                    'class_list_glid': {
                        'type': 'str',
                        },
                    'glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'blacklist-src', 'ignore']
                        },
                    'action': {
                        'type': 'str',
                        'choices': ['bypass', 'deny']
                        },
                    'max_dynamic_entry_count': {
                        'type': 'int',
                        },
                    'dynamic_entry_count_warn_threshold': {
                        'type': 'int',
                        },
                    'zone_template': {
                        'type': 'dict',
                        'quic': {
                            'type': 'str',
                            },
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
                            },
                        'encap': {
                            'type': 'str',
                            },
                        'logging': {
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
                            'type': 'str',
                            'choices': ['all', 'packet_received', 'packet_dropped', 'entry_learned', 'entry_count_overflow', 'exceed_drop_pkt_rate_clist', 'exceed_drop_conn_rate_clist', 'exceed_drop_conn_limit_clist', 'exceed_drop_kbit_rate_clist', 'exceed_drop_kbit_rate_clist_pkt', 'exceed_drop_frag_rate_clist']
                            }
                        },
                    'class_list_overflow_policy_list': {
                        'type': 'list',
                        'dummy_name': {
                            'type': 'str',
                            'required': True,
                            'choices': ['configuration']
                            },
                        'glid': {
                            'type': 'str',
                            },
                        'action': {
                            'type': 'str',
                            'choices': ['bypass', 'deny']
                            },
                        'log_enable': {
                            'type': 'bool',
                            },
                        'log_periodic': {
                            'type': 'bool',
                            },
                        'zone_template': {
                            'type': 'dict',
                            'quic': {
                                'type': 'str',
                                },
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
                                },
                            'encap': {
                                'type': 'str',
                                },
                            'logging': {
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
                'glid': {
                    'type': 'str',
                    },
                'action': {
                    'type': 'str',
                    'choices': ['bypass', 'deny']
                    },
                'log_enable': {
                    'type': 'bool',
                    },
                'log_periodic': {
                    'type': 'bool',
                    },
                'zone_template': {
                    'type': 'dict',
                    'quic': {
                        'type': 'str',
                        },
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
                        },
                    'encap': {
                        'type': 'str',
                        },
                    'logging': {
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
            'virtualhosts': {
                'type': 'dict',
                'vhosts_config': {
                    'type': 'str',
                    'choices': ['configuration']
                    },
                'source_tracking_all': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'virtualhost_list': {
                    'type': 'list',
                    'vhost': {
                        'type': 'str',
                        'required': True,
                        },
                    'servername': {
                        'type': 'list',
                        'match_type': {
                            'type': 'str',
                            'choices': ['contains', 'ends-with', 'equals', 'starts-with']
                            },
                        'host_match_string': {
                            'type': 'str',
                            }
                        },
                    'servername_list': {
                        'type': 'str',
                        },
                    'servername_match_any': {
                        'type': 'bool',
                        },
                    'source_tracking': {
                        'type': 'str',
                        'choices': ['follow', 'enable', 'disable']
                        },
                    'glid_cfg': {
                        'type': 'dict',
                        'glid': {
                            'type': 'str',
                            },
                        'glid_action': {
                            'type': 'str',
                            'choices': ['drop', 'ignore']
                            }
                        },
                    'deny': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        },
                    'level_list': {
                        'type': 'list',
                        'level_num': {
                            'type': 'str',
                            'required': True,
                            'choices': ['0']
                            },
                        'src_default_glid': {
                            'type': 'str',
                            },
                        'glid_action': {
                            'type': 'str',
                            'choices': ['drop', 'blacklist-src', 'ignore']
                            },
                        'zone_template': {
                            'type': 'dict',
                            'ssl_l4': {
                                'type': 'str',
                                },
                            'tcp': {
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
        'web_gui': {
            'type': 'dict',
            'status': {
                'type': 'str',
                'choices': ['newly', 'learning', 'learned', 'activated']
                },
            'activated_after_learning': {
                'type': 'bool',
                },
            'create_time': {
                'type': 'str',
                },
            'modify_time': {
                'type': 'str',
                },
            'sensitivity': {
                'type': 'str',
                'choices': ['5', '3', '1.5']
                },
            'uuid': {
                'type': 'str',
                },
            'learning': {
                'type': 'dict',
                'duration': {
                    'type': 'str',
                    'choices': ['1minute', '6hour', '12hour', '24hour', '7day']
                    },
                'starting_time': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'protection': {
                'type': 'dict',
                'port': {
                    'type': 'dict',
                    'zone_service_list': {
                        'type': 'list',
                        'port_num': {
                            'type': 'int',
                            'required': True,
                            },
                        'protocol': {
                            'type': 'str',
                            'required': True,
                            'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4']
                            },
                        'pbe': {
                            'type': 'str',
                            },
                        'uuid': {
                            'type': 'str',
                            }
                        },
                    'zone_service_other_list': {
                        'type': 'list',
                        'port_other': {
                            'type': 'str',
                            'required': True,
                            'choices': ['other']
                            },
                        'protocol': {
                            'type': 'str',
                            'required': True,
                            'choices': ['tcp', 'udp']
                            },
                        'pbe': {
                            'type': 'str',
                            },
                        'uuid': {
                            'type': 'str',
                            }
                        }
                    },
                'ip_proto': {
                    'type': 'dict',
                    'proto_name_list': {
                        'type': 'list',
                        'protocol': {
                            'type': 'str',
                            'required': True,
                            'choices': ['icmp-v4', 'icmp-v6']
                            },
                        'pbe': {
                            'type': 'str',
                            },
                        'uuid': {
                            'type': 'str',
                            },
                        'user_tag': {
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
                        'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4']
                        },
                    'pbe': {
                        'type': 'str',
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
        'oper': {
            'type': 'dict',
            'ddos_entry_list': {
                'type': 'list',
                'dst_address_str': {
                    'type': 'str',
                    },
                'port_str': {
                    'type': 'str',
                    },
                'operational_mode': {
                    'type': 'str',
                    },
                'bw_state': {
                    'type': 'str',
                    },
                'current_connections': {
                    'type': 'str',
                    },
                'is_connections_exceed': {
                    'type': 'int',
                    },
                'connection_limit': {
                    'type': 'str',
                    },
                'current_connection_rate': {
                    'type': 'str',
                    },
                'is_connection_rate_exceed': {
                    'type': 'int',
                    },
                'connection_rate_limit': {
                    'type': 'str',
                    },
                'current_packet_rate': {
                    'type': 'str',
                    },
                'is_packet_rate_exceed': {
                    'type': 'int',
                    },
                'packet_rate_limit': {
                    'type': 'str',
                    },
                'current_kBit_rate': {
                    'type': 'str',
                    },
                'is_kBit_rate_exceed': {
                    'type': 'int',
                    },
                'kBit_rate_limit': {
                    'type': 'str',
                    },
                'current_frag_packet_rate': {
                    'type': 'str',
                    },
                'is_frag_packet_rate_exceed': {
                    'type': 'int',
                    },
                'frag_packet_rate_limit': {
                    'type': 'str',
                    },
                'dynamic_entry_count': {
                    'type': 'str',
                    },
                'dynamic_entry_limit': {
                    'type': 'str',
                    },
                'dynamic_entry_warn_state': {
                    'type': 'str',
                    },
                'age_str': {
                    'type': 'str',
                    },
                'lockup_time': {
                    'type': 'int',
                    },
                'sflow_source_id': {
                    'type': 'int',
                    },
                'debug_str': {
                    'type': 'str',
                    }
                },
            'total_dynamic_entry_count': {
                'type': 'str',
                },
            'udp_dynamic_entry_count': {
                'type': 'str',
                },
            'tcp_dynamic_entry_count': {
                'type': 'str',
                },
            'icmp_dynamic_entry_count': {
                'type': 'str',
                },
            'other_dynamic_entry_count': {
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
            'entry_displayed_count': {
                'type': 'int',
                },
            'service_displayed_count': {
                'type': 'int',
                },
            'no_t2_idx_port_count': {
                'type': 'int',
                },
            'addresses': {
                'type': 'bool',
                },
            'subnet_ip_addr': {
                'type': 'str',
                },
            'subnet_ipv6_addr': {
                'type': 'str',
                },
            'all_addresses': {
                'type': 'bool',
                },
            'ip_proto_num': {
                'type': 'int',
                },
            'all_ip_protos': {
                'type': 'bool',
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
            'protocol': {
                'type': 'str',
                },
            'all_ports': {
                'type': 'bool',
                },
            'dynamic_expand_subnet': {
                'type': 'bool',
                },
            'blackhole': {
                'type': 'bool',
                },
            'zone_name': {
                'type': 'str',
                'required': True,
                },
            'detection': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    },
                'outbound_detection': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'discovery_timestamp': {
                            'type': 'str',
                            },
                        'entry_list': {
                            'type': 'list',
                            'location_type': {
                                'type': 'str',
                                },
                            'location_name': {
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
                                'maximum': {
                                    'type': 'str',
                                    },
                                'minimum': {
                                    'type': 'str',
                                    },
                                'non_zero_minimum': {
                                    'type': 'str',
                                    },
                                'average': {
                                    'type': 'str',
                                    },
                                'adaptive_threshold': {
                                    'type': 'str',
                                    }
                                },
                            'data_source': {
                                'type': 'str',
                                },
                            'anomaly': {
                                'type': 'str',
                                },
                            'anomaly_timestamp': {
                                'type': 'str',
                                },
                            'initial_learning': {
                                'type': 'str',
                                'choices': ['None', 'Initializing', 'Completed']
                                },
                            'active_time': {
                                'type': 'int',
                                }
                            }
                        },
                    'topk_source_subnet': {
                        'type': 'dict',
                        'oper': {
                            'type': 'dict',
                            'entry_list': {
                                'type': 'list',
                                'location_type': {
                                    'type': 'str',
                                    },
                                'location_name': {
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
                                    'source_subnets': {
                                        'type': 'list',
                                        'address': {
                                            'type': 'str',
                                            },
                                        'rate': {
                                            'type': 'str',
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                'service_discovery': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'discovered_service_list': {
                            'type': 'list',
                            'port': {
                                'type': 'int',
                                },
                            'protocol': {
                                'type': 'str',
                                },
                            'rate': {
                                'type': 'int',
                                }
                            }
                        }
                    },
                'victim_ip_detection': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'ip_entry_list': {
                            'type': 'list',
                            'ip_address_str': {
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
                                'value': {
                                    'type': 'list',
                                    'current': {
                                        'type': 'str',
                                        },
                                    'threshold': {
                                        'type': 'str',
                                        }
                                    },
                                'is_anomaly': {
                                    'type': 'int',
                                    }
                                },
                            'is_learning_done': {
                                'type': 'int',
                                },
                            'is_histogram_learning_done': {
                                'type': 'int',
                                },
                            'is_ip_anomaly': {
                                'type': 'int',
                                },
                            'is_static_threshold': {
                                'type': 'int',
                                },
                            'escalation_timestamp': {
                                'type': 'str',
                                },
                            'de_escalation_timestamp': {
                                'type': 'str',
                                }
                            },
                        'ip_entry_count': {
                            'type': 'int',
                            },
                        'total_ip_entry_count': {
                            'type': 'int',
                            },
                        'active_list': {
                            'type': 'bool',
                            },
                        'victim_list': {
                            'type': 'bool',
                            },
                        'ipv4_ip': {
                            'type': 'str',
                            },
                        'ipv6_ip': {
                            'type': 'str',
                            }
                        }
                    }
                },
            'packet_anomaly_detection': {
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
                        'maximum': {
                            'type': 'str',
                            },
                        'minimum': {
                            'type': 'str',
                            },
                        'threshold': {
                            'type': 'str',
                            },
                        'is_anomaly': {
                            'type': 'int',
                            }
                        },
                    'data_source': {
                        'type': 'str',
                        }
                    }
                },
            'outbound_policy': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'policy_name': {
                        'type': 'str',
                        },
                    'no_class_list_match': {
                        'type': 'int',
                        },
                    'policy_class_list': {
                        'type': 'list',
                        'class_list_name': {
                            'type': 'str',
                            },
                        'current_packet_rate': {
                            'type': 'str',
                            },
                        'is_packet_rate_exceed': {
                            'type': 'int',
                            },
                        'packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_kBit_rate': {
                            'type': 'str',
                            },
                        'is_kBit_rate_exceed': {
                            'type': 'int',
                            },
                        'kBit_rate_limit': {
                            'type': 'str',
                            },
                        'current_connections': {
                            'type': 'str',
                            },
                        'is_connections_exceed': {
                            'type': 'int',
                            },
                        'connection_limit': {
                            'type': 'str',
                            },
                        'current_connection_rate': {
                            'type': 'str',
                            },
                        'is_connection_rate_exceed': {
                            'type': 'int',
                            },
                        'connection_rate_limit': {
                            'type': 'str',
                            },
                        'current_frag_packet_rate': {
                            'type': 'str',
                            },
                        'is_frag_packet_rate_exceed': {
                            'type': 'int',
                            },
                        'frag_packet_rate_limit': {
                            'type': 'str',
                            },
                        'age_str': {
                            'type': 'str',
                            },
                        'lockup_time': {
                            'type': 'int',
                            },
                        'packet_received': {
                            'type': 'int',
                            },
                        'packet_dropped': {
                            'type': 'int',
                            },
                        'packet_rate_exceed': {
                            'type': 'int',
                            },
                        'kBit_rate_exceed': {
                            'type': 'int',
                            },
                        'kBit_rate_exceed_count': {
                            'type': 'int',
                            },
                        'connections_exceed': {
                            'type': 'int',
                            },
                        'connection_rate_exceed': {
                            'type': 'int',
                            },
                        'frag_packet_rate': {
                            'type': 'int',
                            }
                        },
                    'geo_tracking_statistics': {
                        'type': 'dict',
                        'packet_received': {
                            'type': 'int',
                            },
                        'packet_dropped': {
                            'type': 'int',
                            },
                        'packet_rate_exceed': {
                            'type': 'int',
                            },
                        'kBit_rate_exceed': {
                            'type': 'int',
                            },
                        'kBit_rate_exceed_count': {
                            'type': 'int',
                            },
                        'connections_exceed': {
                            'type': 'int',
                            },
                        'connection_rate_exceed': {
                            'type': 'int',
                            },
                        'frag_packet_rate': {
                            'type': 'int',
                            },
                        'tracking_entry_learn': {
                            'type': 'int',
                            },
                        'tracking_entry_aged': {
                            'type': 'int',
                            },
                        'tracking_entry_learning_thre_exceed': {
                            'type': 'int',
                            }
                        },
                    'tracking_entry_list': {
                        'type': 'list',
                        'geo_location_name': {
                            'type': 'str',
                            },
                        'current_connections': {
                            'type': 'str',
                            },
                        'is_connections_exceed': {
                            'type': 'int',
                            },
                        'connection_limit': {
                            'type': 'str',
                            },
                        'current_connection_rate': {
                            'type': 'str',
                            },
                        'is_connection_rate_exceed': {
                            'type': 'int',
                            },
                        'connection_rate_limit': {
                            'type': 'str',
                            },
                        'current_packet_rate': {
                            'type': 'str',
                            },
                        'is_packet_rate_exceed': {
                            'type': 'int',
                            },
                        'packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_kBit_rate': {
                            'type': 'str',
                            },
                        'is_kBit_rate_exceed': {
                            'type': 'int',
                            },
                        'kBit_rate_limit': {
                            'type': 'str',
                            },
                        'current_frag_packet_rate': {
                            'type': 'str',
                            },
                        'is_frag_packet_rate_exceed': {
                            'type': 'int',
                            },
                        'frag_packet_rate_limit': {
                            'type': 'str',
                            },
                        'age': {
                            'type': 'int',
                            }
                        },
                    'policy_rate': {
                        'type': 'bool',
                        },
                    'policy_statistics': {
                        'type': 'bool',
                        },
                    'tracking_entry_filter': {
                        'type': 'bool',
                        }
                    }
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
                    'next_indicator': {
                        'type': 'int',
                        },
                    'finished': {
                        'type': 'int',
                        },
                    'details': {
                        'type': 'bool',
                        },
                    'top_k_key': {
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
                        'bw_state': {
                            'type': 'str',
                            },
                        'is_auth_passed': {
                            'type': 'str',
                            },
                        'level': {
                            'type': 'int',
                            },
                        'current_connections': {
                            'type': 'str',
                            },
                        'is_connections_exceed': {
                            'type': 'int',
                            },
                        'connection_limit': {
                            'type': 'str',
                            },
                        'current_connection_rate': {
                            'type': 'str',
                            },
                        'is_connection_rate_exceed': {
                            'type': 'int',
                            },
                        'connection_rate_limit': {
                            'type': 'str',
                            },
                        'current_packet_rate': {
                            'type': 'str',
                            },
                        'is_packet_rate_exceed': {
                            'type': 'int',
                            },
                        'packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_kBit_rate': {
                            'type': 'str',
                            },
                        'is_kBit_rate_exceed': {
                            'type': 'int',
                            },
                        'kBit_rate_limit': {
                            'type': 'str',
                            },
                        'current_frag_packet_rate': {
                            'type': 'str',
                            },
                        'is_frag_packet_rate_exceed': {
                            'type': 'int',
                            },
                        'frag_packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_app_stat1': {
                            'type': 'str',
                            },
                        'is_app_stat1_exceed': {
                            'type': 'int',
                            },
                        'app_stat1_limit': {
                            'type': 'str',
                            },
                        'current_app_stat2': {
                            'type': 'str',
                            },
                        'is_app_stat2_exceed': {
                            'type': 'int',
                            },
                        'app_stat2_limit': {
                            'type': 'str',
                            },
                        'current_app_stat3': {
                            'type': 'str',
                            },
                        'is_app_stat3_exceed': {
                            'type': 'int',
                            },
                        'app_stat3_limit': {
                            'type': 'str',
                            },
                        'current_app_stat4': {
                            'type': 'str',
                            },
                        'is_app_stat4_exceed': {
                            'type': 'int',
                            },
                        'app_stat4_limit': {
                            'type': 'str',
                            },
                        'current_app_stat5': {
                            'type': 'str',
                            },
                        'is_app_stat5_exceed': {
                            'type': 'int',
                            },
                        'app_stat5_limit': {
                            'type': 'str',
                            },
                        'current_app_stat6': {
                            'type': 'str',
                            },
                        'is_app_stat6_exceed': {
                            'type': 'int',
                            },
                        'app_stat6_limit': {
                            'type': 'str',
                            },
                        'current_app_stat7': {
                            'type': 'str',
                            },
                        'is_app_stat7_exceed': {
                            'type': 'int',
                            },
                        'app_stat7_limit': {
                            'type': 'str',
                            },
                        'current_app_stat8': {
                            'type': 'str',
                            },
                        'is_app_stat8_exceed': {
                            'type': 'int',
                            },
                        'app_stat8_limit': {
                            'type': 'str',
                            },
                        'age': {
                            'type': 'int',
                            },
                        'lockup_time': {
                            'type': 'int',
                            },
                        'dynamic_entry_count': {
                            'type': 'str',
                            },
                        'dynamic_entry_limit': {
                            'type': 'str',
                            },
                        'dynamic_entry_warn_state': {
                            'type': 'str',
                            },
                        'sflow_source_id': {
                            'type': 'int',
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
                    'sources': {
                        'type': 'bool',
                        },
                    'sources_all_entries': {
                        'type': 'bool',
                        },
                    'subnet_ip_addr': {
                        'type': 'str',
                        },
                    'subnet_ipv6_addr': {
                        'type': 'str',
                        },
                    'ipv6': {
                        'type': 'str',
                        },
                    'hw_blacklisted': {
                        'type': 'bool',
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
                            'indicator_cfg': {
                                'type': 'list',
                                'level': {
                                    'type': 'int',
                                    },
                                'zone_threshold': {
                                    'type': 'str',
                                    },
                                'source_threshold': {
                                    'type': 'str',
                                    }
                                }
                            },
                        'detection_data_source': {
                            'type': 'str',
                            },
                        'current_level': {
                            'type': 'str',
                            },
                        'details': {
                            'type': 'bool',
                            }
                        }
                    }
                },
            'src_port': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    },
                'zone_src_port_list': {
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
                            'bw_state': {
                                'type': 'str',
                                },
                            'is_auth_passed': {
                                'type': 'str',
                                },
                            'level': {
                                'type': 'int',
                                },
                            'current_connections': {
                                'type': 'str',
                                },
                            'is_connections_exceed': {
                                'type': 'int',
                                },
                            'connection_limit': {
                                'type': 'str',
                                },
                            'current_connection_rate': {
                                'type': 'str',
                                },
                            'is_connection_rate_exceed': {
                                'type': 'int',
                                },
                            'connection_rate_limit': {
                                'type': 'str',
                                },
                            'current_packet_rate': {
                                'type': 'str',
                                },
                            'is_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'packet_rate_limit': {
                                'type': 'str',
                                },
                            'current_kBit_rate': {
                                'type': 'str',
                                },
                            'is_kBit_rate_exceed': {
                                'type': 'int',
                                },
                            'kBit_rate_limit': {
                                'type': 'str',
                                },
                            'current_frag_packet_rate': {
                                'type': 'str',
                                },
                            'is_frag_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'frag_packet_rate_limit': {
                                'type': 'str',
                                },
                            'current_app_stat1': {
                                'type': 'str',
                                },
                            'is_app_stat1_exceed': {
                                'type': 'int',
                                },
                            'app_stat1_limit': {
                                'type': 'str',
                                },
                            'current_app_stat2': {
                                'type': 'str',
                                },
                            'is_app_stat2_exceed': {
                                'type': 'int',
                                },
                            'app_stat2_limit': {
                                'type': 'str',
                                },
                            'current_app_stat3': {
                                'type': 'str',
                                },
                            'is_app_stat3_exceed': {
                                'type': 'int',
                                },
                            'app_stat3_limit': {
                                'type': 'str',
                                },
                            'current_app_stat4': {
                                'type': 'str',
                                },
                            'is_app_stat4_exceed': {
                                'type': 'int',
                                },
                            'app_stat4_limit': {
                                'type': 'str',
                                },
                            'current_app_stat5': {
                                'type': 'str',
                                },
                            'is_app_stat5_exceed': {
                                'type': 'int',
                                },
                            'app_stat5_limit': {
                                'type': 'str',
                                },
                            'current_app_stat6': {
                                'type': 'str',
                                },
                            'is_app_stat6_exceed': {
                                'type': 'int',
                                },
                            'app_stat6_limit': {
                                'type': 'str',
                                },
                            'current_app_stat7': {
                                'type': 'str',
                                },
                            'is_app_stat7_exceed': {
                                'type': 'int',
                                },
                            'app_stat7_limit': {
                                'type': 'str',
                                },
                            'current_app_stat8': {
                                'type': 'str',
                                },
                            'is_app_stat8_exceed': {
                                'type': 'int',
                                },
                            'app_stat8_limit': {
                                'type': 'str',
                                },
                            'age': {
                                'type': 'int',
                                },
                            'lockup_time': {
                                'type': 'int',
                                },
                            'dynamic_entry_count': {
                                'type': 'str',
                                },
                            'dynamic_entry_limit': {
                                'type': 'str',
                                },
                            'dynamic_entry_warn_state': {
                                'type': 'str',
                                },
                            'sflow_source_id': {
                                'type': 'int',
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
                        'sources': {
                            'type': 'bool',
                            },
                        'sources_all_entries': {
                            'type': 'bool',
                            },
                        'subnet_ip_addr': {
                            'type': 'str',
                            },
                        'subnet_ipv6_addr': {
                            'type': 'str',
                            },
                        'ipv6': {
                            'type': 'str',
                            },
                        'hw_blacklisted': {
                            'type': 'bool',
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
                                'indicator_cfg': {
                                    'type': 'list',
                                    'level': {
                                        'type': 'int',
                                        },
                                    'zone_threshold': {
                                        'type': 'str',
                                        },
                                    'source_threshold': {
                                        'type': 'str',
                                        }
                                    }
                                },
                            'detection_data_source': {
                                'type': 'str',
                                },
                            'current_level': {
                                'type': 'str',
                                },
                            'details': {
                                'type': 'bool',
                                }
                            }
                        }
                    },
                'zone_src_port_other_list': {
                    'type': 'list',
                    'port_other': {
                        'type': 'str',
                        'required': True,
                        'choices': ['other']
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
                            'bw_state': {
                                'type': 'str',
                                },
                            'is_auth_passed': {
                                'type': 'str',
                                },
                            'level': {
                                'type': 'int',
                                },
                            'current_connections': {
                                'type': 'str',
                                },
                            'is_connections_exceed': {
                                'type': 'int',
                                },
                            'connection_limit': {
                                'type': 'str',
                                },
                            'current_connection_rate': {
                                'type': 'str',
                                },
                            'is_connection_rate_exceed': {
                                'type': 'int',
                                },
                            'connection_rate_limit': {
                                'type': 'str',
                                },
                            'current_packet_rate': {
                                'type': 'str',
                                },
                            'is_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'packet_rate_limit': {
                                'type': 'str',
                                },
                            'current_kBit_rate': {
                                'type': 'str',
                                },
                            'is_kBit_rate_exceed': {
                                'type': 'int',
                                },
                            'kBit_rate_limit': {
                                'type': 'str',
                                },
                            'current_frag_packet_rate': {
                                'type': 'str',
                                },
                            'is_frag_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'frag_packet_rate_limit': {
                                'type': 'str',
                                },
                            'current_app_stat1': {
                                'type': 'str',
                                },
                            'is_app_stat1_exceed': {
                                'type': 'int',
                                },
                            'app_stat1_limit': {
                                'type': 'str',
                                },
                            'current_app_stat2': {
                                'type': 'str',
                                },
                            'is_app_stat2_exceed': {
                                'type': 'int',
                                },
                            'app_stat2_limit': {
                                'type': 'str',
                                },
                            'current_app_stat3': {
                                'type': 'str',
                                },
                            'is_app_stat3_exceed': {
                                'type': 'int',
                                },
                            'app_stat3_limit': {
                                'type': 'str',
                                },
                            'current_app_stat4': {
                                'type': 'str',
                                },
                            'is_app_stat4_exceed': {
                                'type': 'int',
                                },
                            'app_stat4_limit': {
                                'type': 'str',
                                },
                            'current_app_stat5': {
                                'type': 'str',
                                },
                            'is_app_stat5_exceed': {
                                'type': 'int',
                                },
                            'app_stat5_limit': {
                                'type': 'str',
                                },
                            'current_app_stat6': {
                                'type': 'str',
                                },
                            'is_app_stat6_exceed': {
                                'type': 'int',
                                },
                            'app_stat6_limit': {
                                'type': 'str',
                                },
                            'current_app_stat7': {
                                'type': 'str',
                                },
                            'is_app_stat7_exceed': {
                                'type': 'int',
                                },
                            'app_stat7_limit': {
                                'type': 'str',
                                },
                            'current_app_stat8': {
                                'type': 'str',
                                },
                            'is_app_stat8_exceed': {
                                'type': 'int',
                                },
                            'app_stat8_limit': {
                                'type': 'str',
                                },
                            'age': {
                                'type': 'int',
                                },
                            'lockup_time': {
                                'type': 'int',
                                },
                            'dynamic_entry_count': {
                                'type': 'str',
                                },
                            'dynamic_entry_limit': {
                                'type': 'str',
                                },
                            'dynamic_entry_warn_state': {
                                'type': 'str',
                                },
                            'sflow_source_id': {
                                'type': 'int',
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
                        'sources': {
                            'type': 'bool',
                            },
                        'sources_all_entries': {
                            'type': 'bool',
                            },
                        'subnet_ip_addr': {
                            'type': 'str',
                            },
                        'subnet_ipv6_addr': {
                            'type': 'str',
                            },
                        'ipv6': {
                            'type': 'str',
                            },
                        'hw_blacklisted': {
                            'type': 'bool',
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
                                'indicator_cfg': {
                                    'type': 'list',
                                    'level': {
                                        'type': 'int',
                                        },
                                    'zone_threshold': {
                                        'type': 'str',
                                        },
                                    'source_threshold': {
                                        'type': 'str',
                                        }
                                    }
                                },
                            'detection_data_source': {
                                'type': 'str',
                                },
                            'current_level': {
                                'type': 'str',
                                },
                            'details': {
                                'type': 'bool',
                                }
                            }
                        }
                    }
                },
            'ip_proto': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    },
                'proto_number_list': {
                    'type': 'list',
                    'protocol_num': {
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
                            'bw_state': {
                                'type': 'str',
                                },
                            'is_auth_passed': {
                                'type': 'str',
                                },
                            'level': {
                                'type': 'int',
                                },
                            'bl_reasoning_rcode': {
                                'type': 'str',
                                },
                            'bl_reasoning_timestamp': {
                                'type': 'str',
                                },
                            'current_connections': {
                                'type': 'str',
                                },
                            'is_connections_exceed': {
                                'type': 'int',
                                },
                            'connection_limit': {
                                'type': 'str',
                                },
                            'current_connection_rate': {
                                'type': 'str',
                                },
                            'is_connection_rate_exceed': {
                                'type': 'int',
                                },
                            'connection_rate_limit': {
                                'type': 'str',
                                },
                            'current_packet_rate': {
                                'type': 'str',
                                },
                            'is_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'packet_rate_limit': {
                                'type': 'str',
                                },
                            'current_kBit_rate': {
                                'type': 'str',
                                },
                            'is_kBit_rate_exceed': {
                                'type': 'int',
                                },
                            'kBit_rate_limit': {
                                'type': 'str',
                                },
                            'current_frag_packet_rate': {
                                'type': 'str',
                                },
                            'is_frag_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'frag_packet_rate_limit': {
                                'type': 'str',
                                },
                            'age': {
                                'type': 'int',
                                },
                            'lockup_time': {
                                'type': 'int',
                                },
                            'dynamic_entry_count': {
                                'type': 'str',
                                },
                            'dynamic_entry_limit': {
                                'type': 'str',
                                },
                            'dynamic_entry_warn_state': {
                                'type': 'str',
                                },
                            'sflow_source_id': {
                                'type': 'int',
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
                        'sources': {
                            'type': 'bool',
                            },
                        'overflow_policy': {
                            'type': 'bool',
                            },
                        'sources_all_entries': {
                            'type': 'bool',
                            },
                        'class_list': {
                            'type': 'str',
                            },
                        'subnet_ip_addr': {
                            'type': 'str',
                            },
                        'subnet_ipv6_addr': {
                            'type': 'str',
                            },
                        'ipv6': {
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
                        'level': {
                            'type': 'bool',
                            },
                        'app_stat': {
                            'type': 'bool',
                            },
                        'indicators': {
                            'type': 'bool',
                            },
                        'indicator_detail': {
                            'type': 'bool',
                            },
                        'hw_blacklisted': {
                            'type': 'bool',
                            },
                        'suffix_request_rate': {
                            'type': 'bool',
                            },
                        'domain_name': {
                            'type': 'str',
                            }
                        },
                    'ip_filtering_policy_statistics': {
                        'type': 'dict',
                        'oper': {
                            'type': 'dict',
                            'rule_list': {
                                'type': 'list',
                                'seq': {
                                    'type': 'int',
                                    },
                                'hits': {
                                    'type': 'int',
                                    },
                                'blacklisted_src_count': {
                                    'type': 'int',
                                    }
                                }
                            }
                        },
                    'src_based_policy_list': {
                        'type': 'list',
                        'src_based_policy_name': {
                            'type': 'str',
                            'required': True,
                            },
                        'oper': {
                            'type': 'dict',
                            },
                        'policy_class_list_list': {
                            'type': 'list',
                            'class_list_name': {
                                'type': 'str',
                                'required': True,
                                },
                            'oper': {
                                'type': 'dict',
                                'current_connections': {
                                    'type': 'int',
                                    },
                                'is_connections_exceed': {
                                    'type': 'int',
                                    },
                                'connection_limit': {
                                    'type': 'int',
                                    },
                                'current_connection_rate': {
                                    'type': 'int',
                                    },
                                'is_connection_rate_exceed': {
                                    'type': 'int',
                                    },
                                'connection_rate_limit': {
                                    'type': 'int',
                                    },
                                'current_packet_rate': {
                                    'type': 'int',
                                    },
                                'is_packet_rate_exceed': {
                                    'type': 'int',
                                    },
                                'packet_rate_limit': {
                                    'type': 'int',
                                    },
                                'current_kBit_rate': {
                                    'type': 'int',
                                    },
                                'is_kBit_rate_exceed': {
                                    'type': 'int',
                                    },
                                'kBit_rate_limit': {
                                    'type': 'int',
                                    },
                                'current_frag_packet_rate': {
                                    'type': 'int',
                                    },
                                'is_frag_packet_rate_exceed': {
                                    'type': 'int',
                                    },
                                'frag_packet_rate_limit': {
                                    'type': 'int',
                                    },
                                'debug_str': {
                                    'type': 'str',
                                    }
                                }
                            }
                        },
                    'port_ind': {
                        'type': 'dict',
                        'oper': {
                            'type': 'dict',
                            'src_entry_list': {
                                'type': 'list',
                                'src_address_str': {
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
                                    'src_maximum': {
                                        'type': 'str',
                                        },
                                    'src_minimum': {
                                        'type': 'str',
                                        },
                                    'src_non_zero_minimum': {
                                        'type': 'str',
                                        },
                                    'src_average': {
                                        'type': 'str',
                                        },
                                    'score': {
                                        'type': 'str',
                                        }
                                    },
                                'detection_data_source': {
                                    'type': 'str',
                                    },
                                'total_score': {
                                    'type': 'str',
                                    },
                                'current_level': {
                                    'type': 'str',
                                    },
                                'src_level': {
                                    'type': 'str',
                                    },
                                'escalation_timestamp': {
                                    'type': 'str',
                                    },
                                'initial_learning': {
                                    'type': 'str',
                                    'choices': ['None', 'Initializing', 'Completed']
                                    },
                                'active_time': {
                                    'type': 'int',
                                    }
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
                                'zone_maximum': {
                                    'type': 'str',
                                    },
                                'zone_minimum': {
                                    'type': 'str',
                                    },
                                'zone_non_zero_minimum': {
                                    'type': 'str',
                                    },
                                'zone_average': {
                                    'type': 'str',
                                    },
                                'zone_adaptive_threshold': {
                                    'type': 'str',
                                    },
                                'src_maximum': {
                                    'type': 'str',
                                    },
                                'indicator_cfg': {
                                    'type': 'list',
                                    'level': {
                                        'type': 'int',
                                        },
                                    'zone_threshold': {
                                        'type': 'str',
                                        },
                                    'source_threshold': {
                                        'type': 'str',
                                        }
                                    },
                                'score': {
                                    'type': 'str',
                                    }
                                },
                            'detection_data_source': {
                                'type': 'str',
                                },
                            'total_score': {
                                'type': 'str',
                                },
                            'current_level': {
                                'type': 'str',
                                },
                            'escalation_timestamp': {
                                'type': 'str',
                                },
                            'initial_learning': {
                                'type': 'str',
                                'choices': ['None', 'Initializing', 'Completed']
                                },
                            'active_time': {
                                'type': 'int',
                                },
                            'sources_all_entries': {
                                'type': 'bool',
                                },
                            'subnet_ip_addr': {
                                'type': 'str',
                                },
                            'subnet_ipv6_addr': {
                                'type': 'str',
                                },
                            'ipv6': {
                                'type': 'str',
                                },
                            'details': {
                                'type': 'bool',
                                },
                            'sources': {
                                'type': 'bool',
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
                            'next_indicator': {
                                'type': 'int',
                                },
                            'finished': {
                                'type': 'int',
                                },
                            'details': {
                                'type': 'bool',
                                },
                            'top_k_key': {
                                'type': 'str',
                                }
                            }
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
                            'next_indicator': {
                                'type': 'int',
                                },
                            'finished': {
                                'type': 'int',
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
                                },
                            'learning_details': {
                                'type': 'bool',
                                },
                            'learning_brief': {
                                'type': 'bool',
                                },
                            'recommended_template': {
                                'type': 'bool',
                                },
                            'template_debug_table': {
                                'type': 'bool',
                                }
                            }
                        }
                    },
                'proto_tcp_udp_list': {
                    'type': 'list',
                    'protocol': {
                        'type': 'str',
                        'required': True,
                        'choices': ['tcp', 'udp']
                        },
                    'oper': {
                        'type': 'dict',
                        'ddos_entry_list': {
                            'type': 'list',
                            'dst_address_str': {
                                'type': 'str',
                                },
                            'bw_state': {
                                'type': 'str',
                                },
                            'is_auth_passed': {
                                'type': 'str',
                                },
                            'level': {
                                'type': 'int',
                                },
                            'bl_reasoning_rcode': {
                                'type': 'str',
                                },
                            'bl_reasoning_timestamp': {
                                'type': 'str',
                                },
                            'current_connections': {
                                'type': 'str',
                                },
                            'is_connections_exceed': {
                                'type': 'int',
                                },
                            'connection_limit': {
                                'type': 'str',
                                },
                            'current_connection_rate': {
                                'type': 'str',
                                },
                            'is_connection_rate_exceed': {
                                'type': 'int',
                                },
                            'connection_rate_limit': {
                                'type': 'str',
                                },
                            'current_packet_rate': {
                                'type': 'str',
                                },
                            'is_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'packet_rate_limit': {
                                'type': 'str',
                                },
                            'current_kBit_rate': {
                                'type': 'str',
                                },
                            'is_kBit_rate_exceed': {
                                'type': 'int',
                                },
                            'kBit_rate_limit': {
                                'type': 'str',
                                },
                            'current_frag_packet_rate': {
                                'type': 'str',
                                },
                            'is_frag_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'frag_packet_rate_limit': {
                                'type': 'str',
                                },
                            'age': {
                                'type': 'int',
                                },
                            'lockup_time': {
                                'type': 'int',
                                },
                            'dynamic_entry_count': {
                                'type': 'str',
                                },
                            'dynamic_entry_limit': {
                                'type': 'str',
                                },
                            'dynamic_entry_warn_state': {
                                'type': 'str',
                                },
                            'sflow_source_id': {
                                'type': 'int',
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
                        'sources': {
                            'type': 'bool',
                            },
                        'overflow_policy': {
                            'type': 'bool',
                            },
                        'sources_all_entries': {
                            'type': 'bool',
                            },
                        'class_list': {
                            'type': 'str',
                            },
                        'subnet_ip_addr': {
                            'type': 'str',
                            },
                        'subnet_ipv6_addr': {
                            'type': 'str',
                            },
                        'ipv6': {
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
                        'level': {
                            'type': 'bool',
                            },
                        'app_stat': {
                            'type': 'bool',
                            },
                        'indicators': {
                            'type': 'bool',
                            },
                        'indicator_detail': {
                            'type': 'bool',
                            },
                        'hw_blacklisted': {
                            'type': 'bool',
                            },
                        'suffix_request_rate': {
                            'type': 'bool',
                            },
                        'domain_name': {
                            'type': 'str',
                            }
                        },
                    'ip_filtering_policy_statistics': {
                        'type': 'dict',
                        'oper': {
                            'type': 'dict',
                            'rule_list': {
                                'type': 'list',
                                'seq': {
                                    'type': 'int',
                                    },
                                'hits': {
                                    'type': 'int',
                                    },
                                'blacklisted_src_count': {
                                    'type': 'int',
                                    }
                                }
                            }
                        }
                    },
                'proto_name_list': {
                    'type': 'list',
                    'protocol': {
                        'type': 'str',
                        'required': True,
                        'choices': ['icmp-v4', 'icmp-v6', 'other', 'gre', 'ipv4-encap', 'ipv6-encap']
                        },
                    'oper': {
                        'type': 'dict',
                        'ddos_entry_list': {
                            'type': 'list',
                            'dst_address_str': {
                                'type': 'str',
                                },
                            'bw_state': {
                                'type': 'str',
                                },
                            'is_auth_passed': {
                                'type': 'str',
                                },
                            'level': {
                                'type': 'int',
                                },
                            'bl_reasoning_rcode': {
                                'type': 'str',
                                },
                            'bl_reasoning_timestamp': {
                                'type': 'str',
                                },
                            'current_connections': {
                                'type': 'str',
                                },
                            'is_connections_exceed': {
                                'type': 'int',
                                },
                            'connection_limit': {
                                'type': 'str',
                                },
                            'current_connection_rate': {
                                'type': 'str',
                                },
                            'is_connection_rate_exceed': {
                                'type': 'int',
                                },
                            'connection_rate_limit': {
                                'type': 'str',
                                },
                            'current_packet_rate': {
                                'type': 'str',
                                },
                            'is_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'packet_rate_limit': {
                                'type': 'str',
                                },
                            'current_kBit_rate': {
                                'type': 'str',
                                },
                            'is_kBit_rate_exceed': {
                                'type': 'int',
                                },
                            'kBit_rate_limit': {
                                'type': 'str',
                                },
                            'current_frag_packet_rate': {
                                'type': 'str',
                                },
                            'is_frag_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'frag_packet_rate_limit': {
                                'type': 'str',
                                },
                            'age': {
                                'type': 'int',
                                },
                            'lockup_time': {
                                'type': 'int',
                                },
                            'dynamic_entry_count': {
                                'type': 'str',
                                },
                            'dynamic_entry_limit': {
                                'type': 'str',
                                },
                            'dynamic_entry_warn_state': {
                                'type': 'str',
                                },
                            'sflow_source_id': {
                                'type': 'int',
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
                        'sources': {
                            'type': 'bool',
                            },
                        'overflow_policy': {
                            'type': 'bool',
                            },
                        'sources_all_entries': {
                            'type': 'bool',
                            },
                        'class_list': {
                            'type': 'str',
                            },
                        'subnet_ip_addr': {
                            'type': 'str',
                            },
                        'subnet_ipv6_addr': {
                            'type': 'str',
                            },
                        'ipv6': {
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
                        'level': {
                            'type': 'bool',
                            },
                        'app_stat': {
                            'type': 'bool',
                            },
                        'indicators': {
                            'type': 'bool',
                            },
                        'indicator_detail': {
                            'type': 'bool',
                            },
                        'hw_blacklisted': {
                            'type': 'bool',
                            },
                        'suffix_request_rate': {
                            'type': 'bool',
                            },
                        'domain_name': {
                            'type': 'str',
                            }
                        },
                    'ip_filtering_policy_statistics': {
                        'type': 'dict',
                        'oper': {
                            'type': 'dict',
                            'rule_list': {
                                'type': 'list',
                                'seq': {
                                    'type': 'int',
                                    },
                                'hits': {
                                    'type': 'int',
                                    },
                                'blacklisted_src_count': {
                                    'type': 'int',
                                    }
                                }
                            }
                        },
                    'src_based_policy_list': {
                        'type': 'list',
                        'src_based_policy_name': {
                            'type': 'str',
                            'required': True,
                            },
                        'oper': {
                            'type': 'dict',
                            },
                        'policy_class_list_list': {
                            'type': 'list',
                            'class_list_name': {
                                'type': 'str',
                                'required': True,
                                },
                            'oper': {
                                'type': 'dict',
                                'current_connections': {
                                    'type': 'int',
                                    },
                                'is_connections_exceed': {
                                    'type': 'int',
                                    },
                                'connection_limit': {
                                    'type': 'int',
                                    },
                                'current_connection_rate': {
                                    'type': 'int',
                                    },
                                'is_connection_rate_exceed': {
                                    'type': 'int',
                                    },
                                'connection_rate_limit': {
                                    'type': 'int',
                                    },
                                'current_packet_rate': {
                                    'type': 'int',
                                    },
                                'is_packet_rate_exceed': {
                                    'type': 'int',
                                    },
                                'packet_rate_limit': {
                                    'type': 'int',
                                    },
                                'current_kBit_rate': {
                                    'type': 'int',
                                    },
                                'is_kBit_rate_exceed': {
                                    'type': 'int',
                                    },
                                'kBit_rate_limit': {
                                    'type': 'int',
                                    },
                                'current_frag_packet_rate': {
                                    'type': 'int',
                                    },
                                'is_frag_packet_rate_exceed': {
                                    'type': 'int',
                                    },
                                'frag_packet_rate_limit': {
                                    'type': 'int',
                                    },
                                'debug_str': {
                                    'type': 'str',
                                    }
                                }
                            }
                        },
                    'port_ind': {
                        'type': 'dict',
                        'oper': {
                            'type': 'dict',
                            'src_entry_list': {
                                'type': 'list',
                                'src_address_str': {
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
                                    'src_maximum': {
                                        'type': 'str',
                                        },
                                    'src_minimum': {
                                        'type': 'str',
                                        },
                                    'src_non_zero_minimum': {
                                        'type': 'str',
                                        },
                                    'src_average': {
                                        'type': 'str',
                                        },
                                    'score': {
                                        'type': 'str',
                                        }
                                    },
                                'detection_data_source': {
                                    'type': 'str',
                                    },
                                'total_score': {
                                    'type': 'str',
                                    },
                                'current_level': {
                                    'type': 'str',
                                    },
                                'src_level': {
                                    'type': 'str',
                                    },
                                'escalation_timestamp': {
                                    'type': 'str',
                                    },
                                'initial_learning': {
                                    'type': 'str',
                                    'choices': ['None', 'Initializing', 'Completed']
                                    },
                                'active_time': {
                                    'type': 'int',
                                    }
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
                                'zone_maximum': {
                                    'type': 'str',
                                    },
                                'zone_minimum': {
                                    'type': 'str',
                                    },
                                'zone_non_zero_minimum': {
                                    'type': 'str',
                                    },
                                'zone_average': {
                                    'type': 'str',
                                    },
                                'zone_adaptive_threshold': {
                                    'type': 'str',
                                    },
                                'src_maximum': {
                                    'type': 'str',
                                    },
                                'indicator_cfg': {
                                    'type': 'list',
                                    'level': {
                                        'type': 'int',
                                        },
                                    'zone_threshold': {
                                        'type': 'str',
                                        },
                                    'source_threshold': {
                                        'type': 'str',
                                        }
                                    },
                                'score': {
                                    'type': 'str',
                                    }
                                },
                            'detection_data_source': {
                                'type': 'str',
                                },
                            'total_score': {
                                'type': 'str',
                                },
                            'current_level': {
                                'type': 'str',
                                },
                            'escalation_timestamp': {
                                'type': 'str',
                                },
                            'initial_learning': {
                                'type': 'str',
                                'choices': ['None', 'Initializing', 'Completed']
                                },
                            'active_time': {
                                'type': 'int',
                                },
                            'sources_all_entries': {
                                'type': 'bool',
                                },
                            'subnet_ip_addr': {
                                'type': 'str',
                                },
                            'subnet_ipv6_addr': {
                                'type': 'str',
                                },
                            'ipv6': {
                                'type': 'str',
                                },
                            'details': {
                                'type': 'bool',
                                },
                            'sources': {
                                'type': 'bool',
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
                            'next_indicator': {
                                'type': 'int',
                                },
                            'finished': {
                                'type': 'int',
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
                                },
                            'learning_details': {
                                'type': 'bool',
                                },
                            'learning_brief': {
                                'type': 'bool',
                                },
                            'recommended_template': {
                                'type': 'bool',
                                },
                            'template_debug_table': {
                                'type': 'bool',
                                }
                            }
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
                            'next_indicator': {
                                'type': 'int',
                                },
                            'finished': {
                                'type': 'int',
                                },
                            'details': {
                                'type': 'bool',
                                },
                            'top_k_key': {
                                'type': 'str',
                                }
                            }
                        }
                    }
                },
            'port': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    },
                'zone_service_list': {
                    'type': 'list',
                    'port_num': {
                        'type': 'int',
                        'required': True,
                        },
                    'protocol': {
                        'type': 'str',
                        'required': True,
                        'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4', 'sip-udp', 'sip-tcp', 'quic']
                        },
                    'oper': {
                        'type': 'dict',
                        'ddos_entry_list': {
                            'type': 'list',
                            'dst_address_str': {
                                'type': 'str',
                                },
                            'bw_state': {
                                'type': 'str',
                                },
                            'is_auth_passed': {
                                'type': 'str',
                                },
                            'level': {
                                'type': 'int',
                                },
                            'bl_reasoning_rcode': {
                                'type': 'str',
                                },
                            'bl_reasoning_timestamp': {
                                'type': 'str',
                                },
                            'current_connections': {
                                'type': 'str',
                                },
                            'is_connections_exceed': {
                                'type': 'int',
                                },
                            'connection_limit': {
                                'type': 'str',
                                },
                            'current_connection_rate': {
                                'type': 'str',
                                },
                            'is_connection_rate_exceed': {
                                'type': 'int',
                                },
                            'connection_rate_limit': {
                                'type': 'str',
                                },
                            'current_packet_rate': {
                                'type': 'str',
                                },
                            'is_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'packet_rate_limit': {
                                'type': 'str',
                                },
                            'current_kBit_rate': {
                                'type': 'str',
                                },
                            'is_kBit_rate_exceed': {
                                'type': 'int',
                                },
                            'kBit_rate_limit': {
                                'type': 'str',
                                },
                            'current_frag_packet_rate': {
                                'type': 'str',
                                },
                            'is_frag_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'frag_packet_rate_limit': {
                                'type': 'str',
                                },
                            'current_app_stat1': {
                                'type': 'str',
                                },
                            'is_app_stat1_exceed': {
                                'type': 'int',
                                },
                            'app_stat1_limit': {
                                'type': 'str',
                                },
                            'current_app_stat2': {
                                'type': 'str',
                                },
                            'is_app_stat2_exceed': {
                                'type': 'int',
                                },
                            'app_stat2_limit': {
                                'type': 'str',
                                },
                            'current_app_stat3': {
                                'type': 'str',
                                },
                            'is_app_stat3_exceed': {
                                'type': 'int',
                                },
                            'app_stat3_limit': {
                                'type': 'str',
                                },
                            'current_app_stat4': {
                                'type': 'str',
                                },
                            'is_app_stat4_exceed': {
                                'type': 'int',
                                },
                            'app_stat4_limit': {
                                'type': 'str',
                                },
                            'current_app_stat5': {
                                'type': 'str',
                                },
                            'is_app_stat5_exceed': {
                                'type': 'int',
                                },
                            'app_stat5_limit': {
                                'type': 'str',
                                },
                            'current_app_stat6': {
                                'type': 'str',
                                },
                            'is_app_stat6_exceed': {
                                'type': 'int',
                                },
                            'app_stat6_limit': {
                                'type': 'str',
                                },
                            'current_app_stat7': {
                                'type': 'str',
                                },
                            'is_app_stat7_exceed': {
                                'type': 'int',
                                },
                            'app_stat7_limit': {
                                'type': 'str',
                                },
                            'current_app_stat8': {
                                'type': 'str',
                                },
                            'is_app_stat8_exceed': {
                                'type': 'int',
                                },
                            'app_stat8_limit': {
                                'type': 'str',
                                },
                            'age': {
                                'type': 'int',
                                },
                            'lockup_time': {
                                'type': 'int',
                                },
                            'dynamic_entry_count': {
                                'type': 'str',
                                },
                            'dynamic_entry_limit': {
                                'type': 'str',
                                },
                            'dynamic_entry_warn_state': {
                                'type': 'str',
                                },
                            'sflow_source_id': {
                                'type': 'int',
                                },
                            'http_filter_rates': {
                                'type': 'list',
                                'http_filter_rate_name': {
                                    'type': 'str',
                                    },
                                'is_http_filter_rate_limit_exceed': {
                                    'type': 'int',
                                    },
                                'current_http_filter_rate': {
                                    'type': 'str',
                                    },
                                'http_filter_rate_limit': {
                                    'type': 'str',
                                    }
                                },
                            'response_size_rates': {
                                'type': 'list',
                                'response_size_rate_name': {
                                    'type': 'str',
                                    },
                                'is_response_size_rate_limit_exceed': {
                                    'type': 'int',
                                    },
                                'current_response_size_rate': {
                                    'type': 'str',
                                    },
                                'response_size_rate_limit': {
                                    'type': 'str',
                                    }
                                },
                            'hw_blocked_rules': {
                                'type': 'list',
                                'rule_dst_ip': {
                                    'type': 'str',
                                    },
                                'hw_blocking_state': {
                                    'type': 'str',
                                    }
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
                        'sources': {
                            'type': 'bool',
                            },
                        'overflow_policy': {
                            'type': 'bool',
                            },
                        'sources_all_entries': {
                            'type': 'bool',
                            },
                        'class_list': {
                            'type': 'str',
                            },
                        'subnet_ip_addr': {
                            'type': 'str',
                            },
                        'subnet_ipv6_addr': {
                            'type': 'str',
                            },
                        'ipv6': {
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
                        'level': {
                            'type': 'bool',
                            },
                        'app_stat': {
                            'type': 'bool',
                            },
                        'indicators': {
                            'type': 'bool',
                            },
                        'indicator_detail': {
                            'type': 'bool',
                            },
                        'l4_ext_rate': {
                            'type': 'bool',
                            },
                        'hw_blacklisted': {
                            'type': 'bool',
                            },
                        'hw_blacklisted_stats': {
                            'type': 'bool',
                            },
                        'suffix_request_rate': {
                            'type': 'bool',
                            },
                        'domain_name': {
                            'type': 'str',
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
                        },
                    'ip_filtering_policy_statistics': {
                        'type': 'dict',
                        'oper': {
                            'type': 'dict',
                            'rule_list': {
                                'type': 'list',
                                'seq': {
                                    'type': 'int',
                                    },
                                'hits': {
                                    'type': 'int',
                                    },
                                'blacklisted_src_count': {
                                    'type': 'int',
                                    }
                                }
                            }
                        },
                    'port_ind': {
                        'type': 'dict',
                        'oper': {
                            'type': 'dict',
                            'src_entry_list': {
                                'type': 'list',
                                'src_address_str': {
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
                                    'src_maximum': {
                                        'type': 'str',
                                        },
                                    'src_minimum': {
                                        'type': 'str',
                                        },
                                    'src_non_zero_minimum': {
                                        'type': 'str',
                                        },
                                    'src_average': {
                                        'type': 'str',
                                        },
                                    'score': {
                                        'type': 'str',
                                        }
                                    },
                                'detection_data_source': {
                                    'type': 'str',
                                    },
                                'total_score': {
                                    'type': 'str',
                                    },
                                'current_level': {
                                    'type': 'str',
                                    },
                                'src_level': {
                                    'type': 'str',
                                    },
                                'escalation_timestamp': {
                                    'type': 'str',
                                    },
                                'initial_learning': {
                                    'type': 'str',
                                    'choices': ['None', 'Initializing', 'Completed']
                                    },
                                'active_time': {
                                    'type': 'int',
                                    }
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
                                'zone_maximum': {
                                    'type': 'str',
                                    },
                                'zone_minimum': {
                                    'type': 'str',
                                    },
                                'zone_non_zero_minimum': {
                                    'type': 'str',
                                    },
                                'zone_average': {
                                    'type': 'str',
                                    },
                                'zone_adaptive_threshold': {
                                    'type': 'str',
                                    },
                                'src_maximum': {
                                    'type': 'str',
                                    },
                                'indicator_cfg': {
                                    'type': 'list',
                                    'level': {
                                        'type': 'int',
                                        },
                                    'zone_threshold': {
                                        'type': 'str',
                                        },
                                    'source_threshold': {
                                        'type': 'str',
                                        }
                                    },
                                'score': {
                                    'type': 'str',
                                    }
                                },
                            'detection_data_source': {
                                'type': 'str',
                                },
                            'total_score': {
                                'type': 'str',
                                },
                            'current_level': {
                                'type': 'str',
                                },
                            'escalation_timestamp': {
                                'type': 'str',
                                },
                            'initial_learning': {
                                'type': 'str',
                                'choices': ['None', 'Initializing', 'Completed']
                                },
                            'active_time': {
                                'type': 'int',
                                },
                            'sources_all_entries': {
                                'type': 'bool',
                                },
                            'subnet_ip_addr': {
                                'type': 'str',
                                },
                            'subnet_ipv6_addr': {
                                'type': 'str',
                                },
                            'ipv6': {
                                'type': 'str',
                                },
                            'details': {
                                'type': 'bool',
                                },
                            'sources': {
                                'type': 'bool',
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
                            'next_indicator': {
                                'type': 'int',
                                },
                            'finished': {
                                'type': 'int',
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
                                },
                            'learning_details': {
                                'type': 'bool',
                                },
                            'learning_brief': {
                                'type': 'bool',
                                },
                            'recommended_template': {
                                'type': 'bool',
                                },
                            'template_debug_table': {
                                'type': 'bool',
                                }
                            }
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
                            'next_indicator': {
                                'type': 'int',
                                },
                            'finished': {
                                'type': 'int',
                                },
                            'details': {
                                'type': 'bool',
                                },
                            'top_k_key': {
                                'type': 'str',
                                }
                            }
                        },
                    'src_based_policy_list': {
                        'type': 'list',
                        'src_based_policy_name': {
                            'type': 'str',
                            'required': True,
                            },
                        'oper': {
                            'type': 'dict',
                            },
                        'policy_class_list_list': {
                            'type': 'list',
                            'class_list_name': {
                                'type': 'str',
                                'required': True,
                                },
                            'oper': {
                                'type': 'dict',
                                'current_connections': {
                                    'type': 'int',
                                    },
                                'is_connections_exceed': {
                                    'type': 'int',
                                    },
                                'connection_limit': {
                                    'type': 'int',
                                    },
                                'current_connection_rate': {
                                    'type': 'int',
                                    },
                                'is_connection_rate_exceed': {
                                    'type': 'int',
                                    },
                                'connection_rate_limit': {
                                    'type': 'int',
                                    },
                                'current_packet_rate': {
                                    'type': 'int',
                                    },
                                'is_packet_rate_exceed': {
                                    'type': 'int',
                                    },
                                'packet_rate_limit': {
                                    'type': 'int',
                                    },
                                'current_kBit_rate': {
                                    'type': 'int',
                                    },
                                'is_kBit_rate_exceed': {
                                    'type': 'int',
                                    },
                                'kBit_rate_limit': {
                                    'type': 'int',
                                    },
                                'current_frag_packet_rate': {
                                    'type': 'int',
                                    },
                                'is_frag_packet_rate_exceed': {
                                    'type': 'int',
                                    },
                                'frag_packet_rate_limit': {
                                    'type': 'int',
                                    },
                                'debug_str': {
                                    'type': 'str',
                                    }
                                }
                            }
                        },
                    'virtualhosts': {
                        'type': 'dict',
                        'oper': {
                            'type': 'dict',
                            },
                        'virtualhost_list': {
                            'type': 'list',
                            'vhost': {
                                'type': 'str',
                                'required': True,
                                },
                            'oper': {
                                'type': 'dict',
                                'ddos_entry_list': {
                                    'type': 'list',
                                    'dst_address_str': {
                                        'type': 'str',
                                        },
                                    'bw_state': {
                                        'type': 'str',
                                        },
                                    'is_auth_passed': {
                                        'type': 'str',
                                        },
                                    'level': {
                                        'type': 'int',
                                        },
                                    'bl_reasoning_rcode': {
                                        'type': 'str',
                                        },
                                    'bl_reasoning_timestamp': {
                                        'type': 'str',
                                        },
                                    'current_connections': {
                                        'type': 'str',
                                        },
                                    'is_connections_exceed': {
                                        'type': 'int',
                                        },
                                    'connection_limit': {
                                        'type': 'str',
                                        },
                                    'current_connection_rate': {
                                        'type': 'str',
                                        },
                                    'is_connection_rate_exceed': {
                                        'type': 'int',
                                        },
                                    'connection_rate_limit': {
                                        'type': 'str',
                                        },
                                    'current_packet_rate': {
                                        'type': 'str',
                                        },
                                    'is_packet_rate_exceed': {
                                        'type': 'int',
                                        },
                                    'packet_rate_limit': {
                                        'type': 'str',
                                        },
                                    'current_kBit_rate': {
                                        'type': 'str',
                                        },
                                    'is_kBit_rate_exceed': {
                                        'type': 'int',
                                        },
                                    'kBit_rate_limit': {
                                        'type': 'str',
                                        },
                                    'current_frag_packet_rate': {
                                        'type': 'str',
                                        },
                                    'is_frag_packet_rate_exceed': {
                                        'type': 'int',
                                        },
                                    'frag_packet_rate_limit': {
                                        'type': 'str',
                                        },
                                    'current_app_stat1': {
                                        'type': 'str',
                                        },
                                    'is_app_stat1_exceed': {
                                        'type': 'int',
                                        },
                                    'app_stat1_limit': {
                                        'type': 'str',
                                        },
                                    'current_app_stat2': {
                                        'type': 'str',
                                        },
                                    'is_app_stat2_exceed': {
                                        'type': 'int',
                                        },
                                    'app_stat2_limit': {
                                        'type': 'str',
                                        },
                                    'current_app_stat3': {
                                        'type': 'str',
                                        },
                                    'is_app_stat3_exceed': {
                                        'type': 'int',
                                        },
                                    'app_stat3_limit': {
                                        'type': 'str',
                                        },
                                    'current_app_stat4': {
                                        'type': 'str',
                                        },
                                    'is_app_stat4_exceed': {
                                        'type': 'int',
                                        },
                                    'app_stat4_limit': {
                                        'type': 'str',
                                        },
                                    'current_app_stat5': {
                                        'type': 'str',
                                        },
                                    'is_app_stat5_exceed': {
                                        'type': 'int',
                                        },
                                    'app_stat5_limit': {
                                        'type': 'str',
                                        },
                                    'current_app_stat6': {
                                        'type': 'str',
                                        },
                                    'is_app_stat6_exceed': {
                                        'type': 'int',
                                        },
                                    'app_stat6_limit': {
                                        'type': 'str',
                                        },
                                    'current_app_stat7': {
                                        'type': 'str',
                                        },
                                    'is_app_stat7_exceed': {
                                        'type': 'int',
                                        },
                                    'app_stat7_limit': {
                                        'type': 'str',
                                        },
                                    'current_app_stat8': {
                                        'type': 'str',
                                        },
                                    'is_app_stat8_exceed': {
                                        'type': 'int',
                                        },
                                    'app_stat8_limit': {
                                        'type': 'str',
                                        },
                                    'age': {
                                        'type': 'int',
                                        },
                                    'lockup_time': {
                                        'type': 'int',
                                        },
                                    'dynamic_entry_count': {
                                        'type': 'str',
                                        },
                                    'dynamic_entry_limit': {
                                        'type': 'str',
                                        },
                                    'dynamic_entry_warn_state': {
                                        'type': 'str',
                                        },
                                    'sflow_source_id': {
                                        'type': 'int',
                                        },
                                    'http_filter_rates': {
                                        'type': 'list',
                                        'http_filter_rate_name': {
                                            'type': 'str',
                                            },
                                        'is_http_filter_rate_limit_exceed': {
                                            'type': 'int',
                                            },
                                        'current_http_filter_rate': {
                                            'type': 'str',
                                            },
                                        'http_filter_rate_limit': {
                                            'type': 'str',
                                            }
                                        },
                                    'response_size_rates': {
                                        'type': 'list',
                                        'response_size_rate_name': {
                                            'type': 'str',
                                            },
                                        'is_response_size_rate_limit_exceed': {
                                            'type': 'int',
                                            },
                                        'current_response_size_rate': {
                                            'type': 'str',
                                            },
                                        'response_size_rate_limit': {
                                            'type': 'str',
                                            }
                                        },
                                    'hw_blocked_rules': {
                                        'type': 'list',
                                        'rule_dst_ip': {
                                            'type': 'str',
                                            },
                                        'hw_blocking_state': {
                                            'type': 'str',
                                            }
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
                                'sources': {
                                    'type': 'bool',
                                    },
                                'overflow_policy': {
                                    'type': 'bool',
                                    },
                                'sources_all_entries': {
                                    'type': 'bool',
                                    },
                                'class_list': {
                                    'type': 'str',
                                    },
                                'subnet_ip_addr': {
                                    'type': 'str',
                                    },
                                'subnet_ipv6_addr': {
                                    'type': 'str',
                                    },
                                'ipv6': {
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
                                'level': {
                                    'type': 'bool',
                                    },
                                'app_stat': {
                                    'type': 'bool',
                                    },
                                'indicators': {
                                    'type': 'bool',
                                    },
                                'indicator_detail': {
                                    'type': 'bool',
                                    },
                                'l4_ext_rate': {
                                    'type': 'bool',
                                    },
                                'hw_blacklisted': {
                                    'type': 'bool',
                                    },
                                'suffix_request_rate': {
                                    'type': 'bool',
                                    },
                                'domain_name': {
                                    'type': 'str',
                                    }
                                }
                            }
                        }
                    },
                'zone_service_other_list': {
                    'type': 'list',
                    'port_other': {
                        'type': 'str',
                        'required': True,
                        'choices': ['other']
                        },
                    'protocol': {
                        'type': 'str',
                        'required': True,
                        'choices': ['tcp', 'udp']
                        },
                    'oper': {
                        'type': 'dict',
                        'ddos_entry_list': {
                            'type': 'list',
                            'dst_address_str': {
                                'type': 'str',
                                },
                            'bw_state': {
                                'type': 'str',
                                },
                            'is_auth_passed': {
                                'type': 'str',
                                },
                            'level': {
                                'type': 'int',
                                },
                            'bl_reasoning_rcode': {
                                'type': 'str',
                                },
                            'bl_reasoning_timestamp': {
                                'type': 'str',
                                },
                            'current_connections': {
                                'type': 'str',
                                },
                            'is_connections_exceed': {
                                'type': 'int',
                                },
                            'connection_limit': {
                                'type': 'str',
                                },
                            'current_connection_rate': {
                                'type': 'str',
                                },
                            'is_connection_rate_exceed': {
                                'type': 'int',
                                },
                            'connection_rate_limit': {
                                'type': 'str',
                                },
                            'current_packet_rate': {
                                'type': 'str',
                                },
                            'is_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'packet_rate_limit': {
                                'type': 'str',
                                },
                            'current_kBit_rate': {
                                'type': 'str',
                                },
                            'is_kBit_rate_exceed': {
                                'type': 'int',
                                },
                            'kBit_rate_limit': {
                                'type': 'str',
                                },
                            'current_frag_packet_rate': {
                                'type': 'str',
                                },
                            'is_frag_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'frag_packet_rate_limit': {
                                'type': 'str',
                                },
                            'current_app_stat1': {
                                'type': 'str',
                                },
                            'is_app_stat1_exceed': {
                                'type': 'int',
                                },
                            'app_stat1_limit': {
                                'type': 'str',
                                },
                            'current_app_stat2': {
                                'type': 'str',
                                },
                            'is_app_stat2_exceed': {
                                'type': 'int',
                                },
                            'app_stat2_limit': {
                                'type': 'str',
                                },
                            'current_app_stat3': {
                                'type': 'str',
                                },
                            'is_app_stat3_exceed': {
                                'type': 'int',
                                },
                            'app_stat3_limit': {
                                'type': 'str',
                                },
                            'current_app_stat4': {
                                'type': 'str',
                                },
                            'is_app_stat4_exceed': {
                                'type': 'int',
                                },
                            'app_stat4_limit': {
                                'type': 'str',
                                },
                            'current_app_stat5': {
                                'type': 'str',
                                },
                            'is_app_stat5_exceed': {
                                'type': 'int',
                                },
                            'app_stat5_limit': {
                                'type': 'str',
                                },
                            'current_app_stat6': {
                                'type': 'str',
                                },
                            'is_app_stat6_exceed': {
                                'type': 'int',
                                },
                            'app_stat6_limit': {
                                'type': 'str',
                                },
                            'current_app_stat7': {
                                'type': 'str',
                                },
                            'is_app_stat7_exceed': {
                                'type': 'int',
                                },
                            'app_stat7_limit': {
                                'type': 'str',
                                },
                            'current_app_stat8': {
                                'type': 'str',
                                },
                            'is_app_stat8_exceed': {
                                'type': 'int',
                                },
                            'app_stat8_limit': {
                                'type': 'str',
                                },
                            'age': {
                                'type': 'int',
                                },
                            'lockup_time': {
                                'type': 'int',
                                },
                            'dynamic_entry_count': {
                                'type': 'str',
                                },
                            'dynamic_entry_limit': {
                                'type': 'str',
                                },
                            'dynamic_entry_warn_state': {
                                'type': 'str',
                                },
                            'sflow_source_id': {
                                'type': 'int',
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
                        'sources': {
                            'type': 'bool',
                            },
                        'overflow_policy': {
                            'type': 'bool',
                            },
                        'sources_all_entries': {
                            'type': 'bool',
                            },
                        'class_list': {
                            'type': 'str',
                            },
                        'subnet_ip_addr': {
                            'type': 'str',
                            },
                        'subnet_ipv6_addr': {
                            'type': 'str',
                            },
                        'ipv6': {
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
                        'level': {
                            'type': 'bool',
                            },
                        'app_stat': {
                            'type': 'bool',
                            },
                        'indicators': {
                            'type': 'bool',
                            },
                        'indicator_detail': {
                            'type': 'bool',
                            },
                        'l4_ext_rate': {
                            'type': 'bool',
                            },
                        'hw_blacklisted': {
                            'type': 'bool',
                            },
                        'suffix_request_rate': {
                            'type': 'bool',
                            },
                        'domain_name': {
                            'type': 'str',
                            }
                        },
                    'ip_filtering_policy_statistics': {
                        'type': 'dict',
                        'oper': {
                            'type': 'dict',
                            'rule_list': {
                                'type': 'list',
                                'seq': {
                                    'type': 'int',
                                    },
                                'hits': {
                                    'type': 'int',
                                    },
                                'blacklisted_src_count': {
                                    'type': 'int',
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
                        },
                    'port_ind': {
                        'type': 'dict',
                        'oper': {
                            'type': 'dict',
                            'src_entry_list': {
                                'type': 'list',
                                'src_address_str': {
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
                                    'src_maximum': {
                                        'type': 'str',
                                        },
                                    'src_minimum': {
                                        'type': 'str',
                                        },
                                    'src_non_zero_minimum': {
                                        'type': 'str',
                                        },
                                    'src_average': {
                                        'type': 'str',
                                        },
                                    'score': {
                                        'type': 'str',
                                        }
                                    },
                                'detection_data_source': {
                                    'type': 'str',
                                    },
                                'total_score': {
                                    'type': 'str',
                                    },
                                'current_level': {
                                    'type': 'str',
                                    },
                                'src_level': {
                                    'type': 'str',
                                    },
                                'escalation_timestamp': {
                                    'type': 'str',
                                    },
                                'initial_learning': {
                                    'type': 'str',
                                    'choices': ['None', 'Initializing', 'Completed']
                                    },
                                'active_time': {
                                    'type': 'int',
                                    }
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
                                'zone_maximum': {
                                    'type': 'str',
                                    },
                                'zone_minimum': {
                                    'type': 'str',
                                    },
                                'zone_non_zero_minimum': {
                                    'type': 'str',
                                    },
                                'zone_average': {
                                    'type': 'str',
                                    },
                                'zone_adaptive_threshold': {
                                    'type': 'str',
                                    },
                                'src_maximum': {
                                    'type': 'str',
                                    },
                                'indicator_cfg': {
                                    'type': 'list',
                                    'level': {
                                        'type': 'int',
                                        },
                                    'zone_threshold': {
                                        'type': 'str',
                                        },
                                    'source_threshold': {
                                        'type': 'str',
                                        }
                                    },
                                'score': {
                                    'type': 'str',
                                    }
                                },
                            'detection_data_source': {
                                'type': 'str',
                                },
                            'total_score': {
                                'type': 'str',
                                },
                            'current_level': {
                                'type': 'str',
                                },
                            'escalation_timestamp': {
                                'type': 'str',
                                },
                            'initial_learning': {
                                'type': 'str',
                                'choices': ['None', 'Initializing', 'Completed']
                                },
                            'active_time': {
                                'type': 'int',
                                },
                            'sources_all_entries': {
                                'type': 'bool',
                                },
                            'subnet_ip_addr': {
                                'type': 'str',
                                },
                            'subnet_ipv6_addr': {
                                'type': 'str',
                                },
                            'ipv6': {
                                'type': 'str',
                                },
                            'details': {
                                'type': 'bool',
                                },
                            'sources': {
                                'type': 'bool',
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
                            'next_indicator': {
                                'type': 'int',
                                },
                            'finished': {
                                'type': 'int',
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
                                },
                            'learning_details': {
                                'type': 'bool',
                                },
                            'learning_brief': {
                                'type': 'bool',
                                },
                            'recommended_template': {
                                'type': 'bool',
                                },
                            'template_debug_table': {
                                'type': 'bool',
                                }
                            }
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
                            'next_indicator': {
                                'type': 'int',
                                },
                            'finished': {
                                'type': 'int',
                                },
                            'details': {
                                'type': 'bool',
                                },
                            'top_k_key': {
                                'type': 'str',
                                }
                            }
                        },
                    'src_based_policy_list': {
                        'type': 'list',
                        'src_based_policy_name': {
                            'type': 'str',
                            'required': True,
                            },
                        'oper': {
                            'type': 'dict',
                            },
                        'policy_class_list_list': {
                            'type': 'list',
                            'class_list_name': {
                                'type': 'str',
                                'required': True,
                                },
                            'oper': {
                                'type': 'dict',
                                'current_connections': {
                                    'type': 'int',
                                    },
                                'is_connections_exceed': {
                                    'type': 'int',
                                    },
                                'connection_limit': {
                                    'type': 'int',
                                    },
                                'current_connection_rate': {
                                    'type': 'int',
                                    },
                                'is_connection_rate_exceed': {
                                    'type': 'int',
                                    },
                                'connection_rate_limit': {
                                    'type': 'int',
                                    },
                                'current_packet_rate': {
                                    'type': 'int',
                                    },
                                'is_packet_rate_exceed': {
                                    'type': 'int',
                                    },
                                'packet_rate_limit': {
                                    'type': 'int',
                                    },
                                'current_kBit_rate': {
                                    'type': 'int',
                                    },
                                'is_kBit_rate_exceed': {
                                    'type': 'int',
                                    },
                                'kBit_rate_limit': {
                                    'type': 'int',
                                    },
                                'current_frag_packet_rate': {
                                    'type': 'int',
                                    },
                                'is_frag_packet_rate_exceed': {
                                    'type': 'int',
                                    },
                                'frag_packet_rate_limit': {
                                    'type': 'int',
                                    },
                                'debug_str': {
                                    'type': 'str',
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
                    'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4', 'sip-udp', 'sip-tcp', 'quic']
                    },
                'oper': {
                    'type': 'dict',
                    'ddos_entry_list': {
                        'type': 'list',
                        'dst_address_str': {
                            'type': 'str',
                            },
                        'bw_state': {
                            'type': 'str',
                            },
                        'is_auth_passed': {
                            'type': 'str',
                            },
                        'level': {
                            'type': 'int',
                            },
                        'bl_reasoning_rcode': {
                            'type': 'str',
                            },
                        'bl_reasoning_timestamp': {
                            'type': 'str',
                            },
                        'current_connections': {
                            'type': 'str',
                            },
                        'is_connections_exceed': {
                            'type': 'int',
                            },
                        'connection_limit': {
                            'type': 'str',
                            },
                        'current_connection_rate': {
                            'type': 'str',
                            },
                        'is_connection_rate_exceed': {
                            'type': 'int',
                            },
                        'connection_rate_limit': {
                            'type': 'str',
                            },
                        'current_packet_rate': {
                            'type': 'str',
                            },
                        'is_packet_rate_exceed': {
                            'type': 'int',
                            },
                        'packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_kBit_rate': {
                            'type': 'str',
                            },
                        'is_kBit_rate_exceed': {
                            'type': 'int',
                            },
                        'kBit_rate_limit': {
                            'type': 'str',
                            },
                        'current_frag_packet_rate': {
                            'type': 'str',
                            },
                        'is_frag_packet_rate_exceed': {
                            'type': 'int',
                            },
                        'frag_packet_rate_limit': {
                            'type': 'str',
                            },
                        'current_app_stat1': {
                            'type': 'str',
                            },
                        'is_app_stat1_exceed': {
                            'type': 'int',
                            },
                        'app_stat1_limit': {
                            'type': 'str',
                            },
                        'current_app_stat2': {
                            'type': 'str',
                            },
                        'is_app_stat2_exceed': {
                            'type': 'int',
                            },
                        'app_stat2_limit': {
                            'type': 'str',
                            },
                        'current_app_stat3': {
                            'type': 'str',
                            },
                        'is_app_stat3_exceed': {
                            'type': 'int',
                            },
                        'app_stat3_limit': {
                            'type': 'str',
                            },
                        'current_app_stat4': {
                            'type': 'str',
                            },
                        'is_app_stat4_exceed': {
                            'type': 'int',
                            },
                        'app_stat4_limit': {
                            'type': 'str',
                            },
                        'current_app_stat5': {
                            'type': 'str',
                            },
                        'is_app_stat5_exceed': {
                            'type': 'int',
                            },
                        'app_stat5_limit': {
                            'type': 'str',
                            },
                        'current_app_stat6': {
                            'type': 'str',
                            },
                        'is_app_stat6_exceed': {
                            'type': 'int',
                            },
                        'app_stat6_limit': {
                            'type': 'str',
                            },
                        'current_app_stat7': {
                            'type': 'str',
                            },
                        'is_app_stat7_exceed': {
                            'type': 'int',
                            },
                        'app_stat7_limit': {
                            'type': 'str',
                            },
                        'current_app_stat8': {
                            'type': 'str',
                            },
                        'is_app_stat8_exceed': {
                            'type': 'int',
                            },
                        'app_stat8_limit': {
                            'type': 'str',
                            },
                        'age': {
                            'type': 'int',
                            },
                        'lockup_time': {
                            'type': 'int',
                            },
                        'dynamic_entry_count': {
                            'type': 'str',
                            },
                        'dynamic_entry_limit': {
                            'type': 'str',
                            },
                        'dynamic_entry_warn_state': {
                            'type': 'str',
                            },
                        'sflow_source_id': {
                            'type': 'int',
                            },
                        'http_filter_rates': {
                            'type': 'list',
                            'http_filter_rate_name': {
                                'type': 'str',
                                },
                            'is_http_filter_rate_limit_exceed': {
                                'type': 'int',
                                },
                            'current_http_filter_rate': {
                                'type': 'str',
                                },
                            'http_filter_rate_limit': {
                                'type': 'str',
                                }
                            },
                        'response_size_rates': {
                            'type': 'list',
                            'response_size_rate_name': {
                                'type': 'str',
                                },
                            'is_response_size_rate_limit_exceed': {
                                'type': 'int',
                                },
                            'current_response_size_rate': {
                                'type': 'str',
                                },
                            'response_size_rate_limit': {
                                'type': 'str',
                                }
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
                    'sources': {
                        'type': 'bool',
                        },
                    'overflow_policy': {
                        'type': 'bool',
                        },
                    'sources_all_entries': {
                        'type': 'bool',
                        },
                    'class_list': {
                        'type': 'str',
                        },
                    'subnet_ip_addr': {
                        'type': 'str',
                        },
                    'subnet_ipv6_addr': {
                        'type': 'str',
                        },
                    'ipv6': {
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
                    'level': {
                        'type': 'bool',
                        },
                    'app_stat': {
                        'type': 'bool',
                        },
                    'indicators': {
                        'type': 'bool',
                        },
                    'indicator_detail': {
                        'type': 'bool',
                        },
                    'l4_ext_rate': {
                        'type': 'bool',
                        },
                    'hw_blacklisted': {
                        'type': 'bool',
                        },
                    'suffix_request_rate': {
                        'type': 'bool',
                        },
                    'domain_name': {
                        'type': 'str',
                        }
                    },
                'ip_filtering_policy_statistics': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'rule_list': {
                            'type': 'list',
                            'seq': {
                                'type': 'int',
                                },
                            'hits': {
                                'type': 'int',
                                },
                            'blacklisted_src_count': {
                                'type': 'int',
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
                    },
                'port_ind': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        'src_entry_list': {
                            'type': 'list',
                            'src_address_str': {
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
                                'src_maximum': {
                                    'type': 'str',
                                    },
                                'src_minimum': {
                                    'type': 'str',
                                    },
                                'src_non_zero_minimum': {
                                    'type': 'str',
                                    },
                                'src_average': {
                                    'type': 'str',
                                    },
                                'score': {
                                    'type': 'str',
                                    }
                                },
                            'detection_data_source': {
                                'type': 'str',
                                },
                            'total_score': {
                                'type': 'str',
                                },
                            'current_level': {
                                'type': 'str',
                                },
                            'src_level': {
                                'type': 'str',
                                },
                            'escalation_timestamp': {
                                'type': 'str',
                                },
                            'initial_learning': {
                                'type': 'str',
                                'choices': ['None', 'Initializing', 'Completed']
                                },
                            'active_time': {
                                'type': 'int',
                                }
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
                            'zone_maximum': {
                                'type': 'str',
                                },
                            'zone_minimum': {
                                'type': 'str',
                                },
                            'zone_non_zero_minimum': {
                                'type': 'str',
                                },
                            'zone_average': {
                                'type': 'str',
                                },
                            'zone_adaptive_threshold': {
                                'type': 'str',
                                },
                            'src_maximum': {
                                'type': 'str',
                                },
                            'indicator_cfg': {
                                'type': 'list',
                                'level': {
                                    'type': 'int',
                                    },
                                'zone_threshold': {
                                    'type': 'str',
                                    },
                                'source_threshold': {
                                    'type': 'str',
                                    }
                                },
                            'score': {
                                'type': 'str',
                                }
                            },
                        'detection_data_source': {
                            'type': 'str',
                            },
                        'total_score': {
                            'type': 'str',
                            },
                        'current_level': {
                            'type': 'str',
                            },
                        'escalation_timestamp': {
                            'type': 'str',
                            },
                        'initial_learning': {
                            'type': 'str',
                            'choices': ['None', 'Initializing', 'Completed']
                            },
                        'active_time': {
                            'type': 'int',
                            },
                        'sources_all_entries': {
                            'type': 'bool',
                            },
                        'subnet_ip_addr': {
                            'type': 'str',
                            },
                        'subnet_ipv6_addr': {
                            'type': 'str',
                            },
                        'ipv6': {
                            'type': 'str',
                            },
                        'details': {
                            'type': 'bool',
                            },
                        'sources': {
                            'type': 'bool',
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
                        'next_indicator': {
                            'type': 'int',
                            },
                        'finished': {
                            'type': 'int',
                            },
                        'details': {
                            'type': 'bool',
                            },
                        'top_k_key': {
                            'type': 'str',
                            }
                        }
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
                        'next_indicator': {
                            'type': 'int',
                            },
                        'finished': {
                            'type': 'int',
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
                            },
                        'learning_details': {
                            'type': 'bool',
                            },
                        'learning_brief': {
                            'type': 'bool',
                            },
                        'recommended_template': {
                            'type': 'bool',
                            },
                        'template_debug_table': {
                            'type': 'bool',
                            }
                        }
                    },
                'src_based_policy_list': {
                    'type': 'list',
                    'src_based_policy_name': {
                        'type': 'str',
                        'required': True,
                        },
                    'oper': {
                        'type': 'dict',
                        },
                    'policy_class_list_list': {
                        'type': 'list',
                        'class_list_name': {
                            'type': 'str',
                            'required': True,
                            },
                        'oper': {
                            'type': 'dict',
                            'current_connections': {
                                'type': 'int',
                                },
                            'is_connections_exceed': {
                                'type': 'int',
                                },
                            'connection_limit': {
                                'type': 'int',
                                },
                            'current_connection_rate': {
                                'type': 'int',
                                },
                            'is_connection_rate_exceed': {
                                'type': 'int',
                                },
                            'connection_rate_limit': {
                                'type': 'int',
                                },
                            'current_packet_rate': {
                                'type': 'int',
                                },
                            'is_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'packet_rate_limit': {
                                'type': 'int',
                                },
                            'current_kBit_rate': {
                                'type': 'int',
                                },
                            'is_kBit_rate_exceed': {
                                'type': 'int',
                                },
                            'kBit_rate_limit': {
                                'type': 'int',
                                },
                            'current_frag_packet_rate': {
                                'type': 'int',
                                },
                            'is_frag_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'frag_packet_rate_limit': {
                                'type': 'int',
                                },
                            'debug_str': {
                                'type': 'str',
                                }
                            }
                        }
                    },
                'virtualhosts': {
                    'type': 'dict',
                    'oper': {
                        'type': 'dict',
                        },
                    'virtualhost_list': {
                        'type': 'list',
                        'vhost': {
                            'type': 'str',
                            'required': True,
                            },
                        'oper': {
                            'type': 'dict',
                            'ddos_entry_list': {
                                'type': 'list',
                                'dst_address_str': {
                                    'type': 'str',
                                    },
                                'bw_state': {
                                    'type': 'str',
                                    },
                                'is_auth_passed': {
                                    'type': 'str',
                                    },
                                'level': {
                                    'type': 'int',
                                    },
                                'bl_reasoning_rcode': {
                                    'type': 'str',
                                    },
                                'bl_reasoning_timestamp': {
                                    'type': 'str',
                                    },
                                'current_connections': {
                                    'type': 'str',
                                    },
                                'is_connections_exceed': {
                                    'type': 'int',
                                    },
                                'connection_limit': {
                                    'type': 'str',
                                    },
                                'current_connection_rate': {
                                    'type': 'str',
                                    },
                                'is_connection_rate_exceed': {
                                    'type': 'int',
                                    },
                                'connection_rate_limit': {
                                    'type': 'str',
                                    },
                                'current_packet_rate': {
                                    'type': 'str',
                                    },
                                'is_packet_rate_exceed': {
                                    'type': 'int',
                                    },
                                'packet_rate_limit': {
                                    'type': 'str',
                                    },
                                'current_kBit_rate': {
                                    'type': 'str',
                                    },
                                'is_kBit_rate_exceed': {
                                    'type': 'int',
                                    },
                                'kBit_rate_limit': {
                                    'type': 'str',
                                    },
                                'current_frag_packet_rate': {
                                    'type': 'str',
                                    },
                                'is_frag_packet_rate_exceed': {
                                    'type': 'int',
                                    },
                                'frag_packet_rate_limit': {
                                    'type': 'str',
                                    },
                                'current_app_stat1': {
                                    'type': 'str',
                                    },
                                'is_app_stat1_exceed': {
                                    'type': 'int',
                                    },
                                'app_stat1_limit': {
                                    'type': 'str',
                                    },
                                'current_app_stat2': {
                                    'type': 'str',
                                    },
                                'is_app_stat2_exceed': {
                                    'type': 'int',
                                    },
                                'app_stat2_limit': {
                                    'type': 'str',
                                    },
                                'current_app_stat3': {
                                    'type': 'str',
                                    },
                                'is_app_stat3_exceed': {
                                    'type': 'int',
                                    },
                                'app_stat3_limit': {
                                    'type': 'str',
                                    },
                                'current_app_stat4': {
                                    'type': 'str',
                                    },
                                'is_app_stat4_exceed': {
                                    'type': 'int',
                                    },
                                'app_stat4_limit': {
                                    'type': 'str',
                                    },
                                'current_app_stat5': {
                                    'type': 'str',
                                    },
                                'is_app_stat5_exceed': {
                                    'type': 'int',
                                    },
                                'app_stat5_limit': {
                                    'type': 'str',
                                    },
                                'current_app_stat6': {
                                    'type': 'str',
                                    },
                                'is_app_stat6_exceed': {
                                    'type': 'int',
                                    },
                                'app_stat6_limit': {
                                    'type': 'str',
                                    },
                                'current_app_stat7': {
                                    'type': 'str',
                                    },
                                'is_app_stat7_exceed': {
                                    'type': 'int',
                                    },
                                'app_stat7_limit': {
                                    'type': 'str',
                                    },
                                'current_app_stat8': {
                                    'type': 'str',
                                    },
                                'is_app_stat8_exceed': {
                                    'type': 'int',
                                    },
                                'app_stat8_limit': {
                                    'type': 'str',
                                    },
                                'age': {
                                    'type': 'int',
                                    },
                                'lockup_time': {
                                    'type': 'int',
                                    },
                                'dynamic_entry_count': {
                                    'type': 'str',
                                    },
                                'dynamic_entry_limit': {
                                    'type': 'str',
                                    },
                                'dynamic_entry_warn_state': {
                                    'type': 'str',
                                    },
                                'sflow_source_id': {
                                    'type': 'int',
                                    },
                                'http_filter_rates': {
                                    'type': 'list',
                                    'http_filter_rate_name': {
                                        'type': 'str',
                                        },
                                    'is_http_filter_rate_limit_exceed': {
                                        'type': 'int',
                                        },
                                    'current_http_filter_rate': {
                                        'type': 'str',
                                        },
                                    'http_filter_rate_limit': {
                                        'type': 'str',
                                        }
                                    },
                                'response_size_rates': {
                                    'type': 'list',
                                    'response_size_rate_name': {
                                        'type': 'str',
                                        },
                                    'is_response_size_rate_limit_exceed': {
                                        'type': 'int',
                                        },
                                    'current_response_size_rate': {
                                        'type': 'str',
                                        },
                                    'response_size_rate_limit': {
                                        'type': 'str',
                                        }
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
                            'sources': {
                                'type': 'bool',
                                },
                            'overflow_policy': {
                                'type': 'bool',
                                },
                            'sources_all_entries': {
                                'type': 'bool',
                                },
                            'class_list': {
                                'type': 'str',
                                },
                            'subnet_ip_addr': {
                                'type': 'str',
                                },
                            'subnet_ipv6_addr': {
                                'type': 'str',
                                },
                            'ipv6': {
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
                            'level': {
                                'type': 'bool',
                                },
                            'app_stat': {
                                'type': 'bool',
                                },
                            'indicators': {
                                'type': 'bool',
                                },
                            'indicator_detail': {
                                'type': 'bool',
                                },
                            'l4_ext_rate': {
                                'type': 'bool',
                                },
                            'hw_blacklisted': {
                                'type': 'bool',
                                },
                            'suffix_request_rate': {
                                'type': 'bool',
                                },
                            'domain_name': {
                                'type': 'str',
                                }
                            }
                        }
                    }
                }
            },
        'stats': {
            'type': 'dict',
            'zone_tcp_any_exceed': {
                'type': 'str',
                },
            'zone_tcp_pkt_rate_exceed': {
                'type': 'str',
                },
            'zone_tcp_conn_rate_exceed': {
                'type': 'str',
                },
            'zone_udp_any_exceed': {
                'type': 'str',
                },
            'zone_udp_pkt_rate_exceed': {
                'type': 'str',
                },
            'zone_udp_conn_limit_exceed': {
                'type': 'str',
                },
            'zone_udp_conn_rate_exceed': {
                'type': 'str',
                },
            'zone_icmp_pkt_rate_exceed': {
                'type': 'str',
                },
            'zone_other_pkt_rate_exceed': {
                'type': 'str',
                },
            'zone_other_frag_pkt_rate_exceed': {
                'type': 'str',
                },
            'zone_port_pkt_rate_exceed': {
                'type': 'str',
                },
            'zone_port_conn_limit_exceed': {
                'type': 'str',
                },
            'zone_port_conn_rate_exceed': {
                'type': 'str',
                },
            'zone_pkt_sent': {
                'type': 'str',
                },
            'zone_udp_pkt_sent': {
                'type': 'str',
                },
            'zone_tcp_pkt_sent': {
                'type': 'str',
                },
            'zone_icmp_pkt_sent': {
                'type': 'str',
                },
            'zone_other_pkt_sent': {
                'type': 'str',
                },
            'zone_tcp_conn_limit_exceed': {
                'type': 'str',
                },
            'zone_tcp_pkt_rcvd': {
                'type': 'str',
                },
            'zone_udp_pkt_rcvd': {
                'type': 'str',
                },
            'zone_icmp_pkt_rcvd': {
                'type': 'str',
                },
            'zone_other_pkt_rcvd': {
                'type': 'str',
                },
            'zone_udp_filter_match': {
                'type': 'str',
                },
            'zone_udp_filter_not_match': {
                'type': 'str',
                },
            'zone_udp_filter_action_blacklist': {
                'type': 'str',
                },
            'zone_udp_filter_action_drop': {
                'type': 'str',
                },
            'zone_tcp_syn': {
                'type': 'str',
                },
            'zone_tcp_syn_drop': {
                'type': 'str',
                },
            'zone_tcp_src_rate_drop': {
                'type': 'str',
                },
            'zone_udp_src_rate_drop': {
                'type': 'str',
                },
            'zone_icmp_src_rate_drop': {
                'type': 'str',
                },
            'zone_other_frag_src_rate_drop': {
                'type': 'str',
                },
            'zone_other_src_rate_drop': {
                'type': 'str',
                },
            'zone_tcp_drop': {
                'type': 'str',
                },
            'zone_udp_drop': {
                'type': 'str',
                },
            'zone_icmp_drop': {
                'type': 'str',
                },
            'zone_frag_drop': {
                'type': 'str',
                },
            'zone_other_drop': {
                'type': 'str',
                },
            'zone_tcp_auth': {
                'type': 'str',
                },
            'zone_udp_filter_action_default_pass': {
                'type': 'str',
                },
            'zone_tcp_filter_match': {
                'type': 'str',
                },
            'zone_tcp_filter_not_match': {
                'type': 'str',
                },
            'zone_tcp_filter_action_blacklist': {
                'type': 'str',
                },
            'zone_tcp_filter_action_drop': {
                'type': 'str',
                },
            'zone_tcp_filter_action_default_pass': {
                'type': 'str',
                },
            'zone_udp_filter_action_whitelist': {
                'type': 'str',
                },
            'zone_udp_kibit_rate_drop': {
                'type': 'str',
                },
            'zone_tcp_kibit_rate_drop': {
                'type': 'str',
                },
            'zone_icmp_kibit_rate_drop': {
                'type': 'str',
                },
            'zone_other_kibit_rate_drop': {
                'type': 'str',
                },
            'zone_port_undef_drop': {
                'type': 'str',
                },
            'zone_port_bl': {
                'type': 'str',
                },
            'zone_src_port_bl': {
                'type': 'str',
                },
            'zone_port_kbit_rate_exceed': {
                'type': 'str',
                },
            'zone_tcp_src_drop': {
                'type': 'str',
                },
            'zone_udp_src_drop': {
                'type': 'str',
                },
            'zone_icmp_src_drop': {
                'type': 'str',
                },
            'zone_other_src_drop': {
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
            'zone_tcp_session_created': {
                'type': 'str',
                },
            'zone_udp_session_created': {
                'type': 'str',
                },
            'zone_tcp_filter_action_whitelist': {
                'type': 'str',
                },
            'zone_other_filter_match': {
                'type': 'str',
                },
            'zone_other_filter_not_match': {
                'type': 'str',
                },
            'zone_other_filter_action_blacklist': {
                'type': 'str',
                },
            'zone_other_filter_action_drop': {
                'type': 'str',
                },
            'zone_other_filter_action_whitelist': {
                'type': 'str',
                },
            'zone_other_filter_action_default_pass': {
                'type': 'str',
                },
            'zone_blackhole_inject': {
                'type': 'str',
                },
            'zone_blackhole_withdraw': {
                'type': 'str',
                },
            'zone_tcp_out_of_seq_excd': {
                'type': 'str',
                },
            'zone_tcp_retransmit_excd': {
                'type': 'str',
                },
            'zone_tcp_zero_window_excd': {
                'type': 'str',
                },
            'zone_tcp_conn_prate_excd': {
                'type': 'str',
                },
            'zone_tcp_action_on_ack_init': {
                'type': 'str',
                },
            'zone_tcp_action_on_ack_gap_drop': {
                'type': 'str',
                },
            'zone_tcp_action_on_ack_fail': {
                'type': 'str',
                },
            'zone_tcp_action_on_ack_pass': {
                'type': 'str',
                },
            'zone_tcp_action_on_syn_init': {
                'type': 'str',
                },
            'zone_tcp_action_on_syn_gap_drop': {
                'type': 'str',
                },
            'zone_tcp_action_on_syn_fail': {
                'type': 'str',
                },
            'zone_tcp_action_on_syn_pass': {
                'type': 'str',
                },
            'zone_payload_too_small': {
                'type': 'str',
                },
            'zone_payload_too_big': {
                'type': 'str',
                },
            'zone_udp_conn_prate_excd': {
                'type': 'str',
                },
            'zone_udp_ntp_monlist_req': {
                'type': 'str',
                },
            'zone_udp_ntp_monlist_resp': {
                'type': 'str',
                },
            'zone_udp_wellknown_sport_drop': {
                'type': 'str',
                },
            'zone_udp_retry_init': {
                'type': 'str',
                },
            'zone_udp_retry_pass': {
                'type': 'str',
                },
            'zone_tcp_bytes_drop': {
                'type': 'str',
                },
            'zone_udp_bytes_drop': {
                'type': 'str',
                },
            'zone_icmp_bytes_drop': {
                'type': 'str',
                },
            'zone_other_bytes_drop': {
                'type': 'str',
                },
            'zone_out_no_route': {
                'type': 'str',
                },
            'outbound_bytes_sent': {
                'type': 'str',
                },
            'outbound_drop': {
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
            'zone_src_port_pkt_rate_exceed': {
                'type': 'str',
                },
            'zone_src_port_kbit_rate_exceed': {
                'type': 'str',
                },
            'zone_src_port_conn_limit_exceed': {
                'type': 'str',
                },
            'zone_src_port_conn_rate_exceed': {
                'type': 'str',
                },
            'zone_ip_proto_pkt_rate_exceed': {
                'type': 'str',
                },
            'zone_ip_proto_kbit_rate_exceed': {
                'type': 'str',
                },
            'zone_tcp_port_any_exceed': {
                'type': 'str',
                },
            'zone_udp_port_any_exceed': {
                'type': 'str',
                },
            'zone_tcp_auth_pass': {
                'type': 'str',
                },
            'zone_tcp_rst_cookie_fail': {
                'type': 'str',
                },
            'zone_tcp_unauth_drop': {
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
            'zone_port_kbit_rate_exceed_pkt': {
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
            'dst_drop': {
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
            'dst_icmp_any_exceed': {
                'type': 'str',
                },
            'dst_other_any_exceed': {
                'type': 'str',
                },
            'tcp_rexmit_syn_limit_drop': {
                'type': 'str',
                },
            'tcp_rexmit_syn_limit_bl': {
                'type': 'str',
                },
            'dst_clist_overflow_policy_at_learning': {
                'type': 'str',
                },
            'zone_frag_rcvd': {
                'type': 'str',
                },
            'zone_tcp_wellknown_sport_drop': {
                'type': 'str',
                },
            'src_tcp_wellknown_sport_drop': {
                'type': 'str',
                },
            'secondary_dst_entry_pkt_rate_exceed': {
                'type': 'str',
                },
            'secondary_dst_entry_kbit_rate_exceed': {
                'type': 'str',
                },
            'secondary_dst_entry_conn_limit_exceed': {
                'type': 'str',
                },
            'secondary_dst_entry_conn_rate_exceed': {
                'type': 'str',
                },
            'secondary_dst_entry_frag_pkt_rate_exceed': {
                'type': 'str',
                },
            'src_udp_retry_gap_drop': {
                'type': 'str',
                },
            'dst_entry_kbit_rate_exceed_count': {
                'type': 'str',
                },
            'secondary_entry_learn': {
                'type': 'str',
                },
            'secondary_entry_hit': {
                'type': 'str',
                },
            'secondary_entry_miss': {
                'type': 'str',
                },
            'secondary_entry_aged': {
                'type': 'str',
                },
            'secondary_entry_learning_thre_exceed': {
                'type': 'str',
                },
            'zone_port_undef_hit': {
                'type': 'str',
                },
            'zone_tcp_action_on_ack_timeout': {
                'type': 'str',
                },
            'zone_tcp_action_on_ack_reset': {
                'type': 'str',
                },
            'zone_tcp_action_on_ack_blacklist': {
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
            'zone_tcp_action_on_syn_timeout': {
                'type': 'str',
                },
            'zone_tcp_action_on_syn_reset': {
                'type': 'str',
                },
            'zone_tcp_action_on_syn_blacklist': {
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
            'zone_udp_frag_pkt_rate_exceed': {
                'type': 'str',
                },
            'zone_udp_frag_src_rate_drop': {
                'type': 'str',
                },
            'zone_tcp_frag_pkt_rate_exceed': {
                'type': 'str',
                },
            'zone_tcp_frag_src_rate_drop': {
                'type': 'str',
                },
            'zone_icmp_frag_pkt_rate_exceed': {
                'type': 'str',
                },
            'zone_icmp_frag_src_rate_drop': {
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
            'source_entry_total': {
                'type': 'str',
                },
            'source_entry_udp': {
                'type': 'str',
                },
            'source_entry_tcp': {
                'type': 'str',
                },
            'source_entry_icmp': {
                'type': 'str',
                },
            'source_entry_other': {
                'type': 'str',
                },
            'dst_exceed_action_tunnel': {
                'type': 'str',
                },
            'dst_udp_retry_timeout_blacklist': {
                'type': 'str',
                },
            'src_udp_auth_timeout': {
                'type': 'str',
                },
            'zone_src_udp_retry_timeout_blacklist': {
                'type': 'str',
                },
            'src_udp_retry_pass': {
                'type': 'str',
                },
            'secondary_port_learn': {
                'type': 'str',
                },
            'secondary_port_aged': {
                'type': 'str',
                },
            'dst_entry_outbound_udp_session_created': {
                'type': 'str',
                },
            'dst_entry_outbound_udp_session_aged': {
                'type': 'str',
                },
            'dst_entry_outbound_tcp_session_created': {
                'type': 'str',
                },
            'dst_entry_outbound_tcp_session_aged': {
                'type': 'str',
                },
            'dst_entry_outbound_pkt_rate_exceed': {
                'type': 'str',
                },
            'dst_entry_outbound_kbit_rate_exceed': {
                'type': 'str',
                },
            'dst_entry_outbound_kbit_rate_exceed_count': {
                'type': 'str',
                },
            'dst_entry_outbound_conn_limit_exceed': {
                'type': 'str',
                },
            'dst_entry_outbound_conn_rate_exceed': {
                'type': 'str',
                },
            'dst_entry_outbound_frag_pkt_rate_exceed': {
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
            'prog_resp_pkt_rate_exceed': {
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
            'east_west_inbound_rcv_pkt': {
                'type': 'str',
                },
            'east_west_inbound_drop_pkt': {
                'type': 'str',
                },
            'east_west_inbound_fwd_pkt': {
                'type': 'str',
                },
            'east_west_inbound_rcv_byte': {
                'type': 'str',
                },
            'east_west_inbound_drop_byte': {
                'type': 'str',
                },
            'east_west_inbound_fwd_byte': {
                'type': 'str',
                },
            'east_west_outbound_rcv_pkt': {
                'type': 'str',
                },
            'east_west_outbound_drop_pkt': {
                'type': 'str',
                },
            'east_west_outbound_fwd_pkt': {
                'type': 'str',
                },
            'east_west_outbound_rcv_byte': {
                'type': 'str',
                },
            'east_west_outbound_drop_byte': {
                'type': 'str',
                },
            'east_west_outbound_fwd_byte': {
                'type': 'str',
                },
            'dst_exceed_action_drop': {
                'type': 'str',
                },
            'dst_src_learn_overflow': {
                'type': 'str',
                },
            'dst_tcp_auth_rst': {
                'type': 'str',
                },
            'prog_query_exceed': {
                'type': 'str',
                },
            'prog_think_exceed': {
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
            'victim_ip_learned': {
                'type': 'str',
                },
            'victim_ip_aged': {
                'type': 'str',
                },
            'prog_conn_samples_processed': {
                'type': 'str',
                },
            'prog_req_samples_processed': {
                'type': 'str',
                },
            'prog_win_samples_processed': {
                'type': 'str',
                },
            'token_auth_mismatched_packets': {
                'type': 'str',
                },
            'token_auth_invalid_packets': {
                'type': 'str',
                },
            'token_auth_current_salt_matched': {
                'type': 'str',
                },
            'token_auth_previous_salt_matched': {
                'type': 'str',
                },
            'token_auth_session_created': {
                'type': 'str',
                },
            'token_auth_session_created_fail': {
                'type': 'str',
                },
            'tcp_invalid_synack': {
                'type': 'str',
                },
            'zone_tcp_small_window_excd': {
                'type': 'str',
                },
            'src_tcp_small_window_excd': {
                'type': 'str',
                },
            'small_window_rcv': {
                'type': 'str',
                },
            'zone_name': {
                'type': 'str',
                'required': True,
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/dst/zone/{zone_name}"

    f_dict = {}
    if '/' in str(module.params["zone_name"]):
        f_dict["zone_name"] = module.params["zone_name"].replace("/", "%2F")
    else:
        f_dict["zone_name"] = module.params["zone_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/dst/zone"

    f_dict = {}
    f_dict["zone_name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["zone"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["zone"].get(k) != v:
            change_results["changed"] = True
            config_changes["zone"][k] = v

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
    payload = utils.build_json("zone", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["zone"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["zone-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["zone"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["zone"]["stats"] if info != "NotFound" else info
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
