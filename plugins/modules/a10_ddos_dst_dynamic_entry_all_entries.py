#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_dst_dynamic_entry_all_entries
description:
    - All Entries
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
          Auth= Retry-Gap Dropped; 'dst_udp_retry_fail'= UDP P Sessions Aged;
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
          Blacklist Dropped; 'dst_l4_icmp_blacklist_drop'= No Policy Class-list Match;
          'dst_l4_other_blacklist_drop'= Dst L4-type OTHER Blacklist Dropped;
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
          'prog_resp_pkt_rate_exceed'= Req-Resp= Response Packet Rate Exceed;
          'prog_resp_req_time_exceed'= Req-Resp= Response to Request Time Exceed;
          'entry_sync_message_received'= Entry Sync Message Received;
          'entry_sync_message_sent'= Entry Sync Message Sent; 'prog_conn_sent_exceed'=
          Connection= Sent Exceed; 'prog_conn_rcvd_exceed'= Connection= Received Exceed;
          'prog_conn_time_exceed'= Connection= Time Exceed;
          'prog_conn_rcvd_sent_ratio_exceed'= Connection= Reveived to Sent Ratio Exceed;
          'prog_win_sent_exceed'= Time Window= Sent Exceed; 'prog_win_rcvd_exceed'= Time
          Window= Received Exceed; 'prog_win_rcvd_sent_ratio_exceed'= Time Window=
          Received to Sent Exceed; 'prog_exceed_drop'= Req-Resp= Violation Exceed
          Dropped; 'prog_exceed_bl'= Req-Resp= Violation Exceed Blacklisted;
          'prog_conn_exceed_drop'= Connection= Violation Exceed Dropped;
          'prog_conn_exceed_bl'= Connection= Violation Exceed Blacklisted;
          'prog_win_exceed_drop'= Time Window= Violation Exceed Dropped;
          'prog_win_exceed_bl'= Time Window= Violation Exceed Blacklisted;
          'dst_exceed_action_drop'= Entry Exceed Action= Dropped; 'src_hw_drop'= Src
          Hardware Packets Dropped; 'dst_tcp_auth_rst'= TCP Auth= Reset;
          'dst_src_learn_overflow'= Src Dynamic Entry Count Overflow; 'tcp_fwd_sent'= TCP
          Inbound Packets Forwarded; 'udp_fwd_sent'= UDP Inbound Packets Forwarded;
          'prog_query_exceed'= Req-Resp= Client Query Time Exceed; 'prog_think_exceed'=
          Req-Resp= Server Think Time Exceed;"
                type: str
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
                - "UDP P Sessions Aged"
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
                - "No Policy Class-list Match"
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
                - "Connection= Reveived to Sent Ratio Exceed"
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
            src_hw_drop:
                description:
                - "Src Hardware Packets Dropped"
                type: str
            dst_tcp_auth_rst:
                description:
                - "TCP Auth= Reset"
                type: str
            dst_src_learn_overflow:
                description:
                - "Src Dynamic Entry Count Overflow"
                type: str
            tcp_fwd_sent:
                description:
                - "TCP Inbound Packets Forwarded"
                type: str
            udp_fwd_sent:
                description:
                - "UDP Inbound Packets Forwarded"
                type: str
            prog_query_exceed:
                description:
                - "Req-Resp= Client Query Time Exceed"
                type: str
            prog_think_exceed:
                description:
                - "Req-Resp= Server Think Time Exceed"
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
AVAILABLE_PROPERTIES = ["sampling_enable", "stats", "uuid", ]


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
        'uuid': {
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
                    'dst_hw_drop_rule_insert', 'dst_hw_drop_rule_remove', 'src_hw_drop_rule_insert', 'src_hw_drop_rule_remove', 'prog_first_req_time_exceed', 'prog_req_resp_time_exceed', 'prog_request_len_exceed', 'prog_response_len_exceed', 'prog_resp_pkt_rate_exceed', 'prog_resp_req_time_exceed', 'entry_sync_message_received',
                    'entry_sync_message_sent', 'prog_conn_sent_exceed', 'prog_conn_rcvd_exceed', 'prog_conn_time_exceed', 'prog_conn_rcvd_sent_ratio_exceed', 'prog_win_sent_exceed', 'prog_win_rcvd_exceed', 'prog_win_rcvd_sent_ratio_exceed', 'prog_exceed_drop', 'prog_exceed_bl', 'prog_conn_exceed_drop', 'prog_conn_exceed_bl', 'prog_win_exceed_drop',
                    'prog_win_exceed_bl', 'dst_exceed_action_drop', 'src_hw_drop', 'dst_tcp_auth_rst', 'dst_src_learn_overflow', 'tcp_fwd_sent', 'udp_fwd_sent', 'prog_query_exceed', 'prog_think_exceed'
                    ]
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
            'dst_exceed_action_drop': {
                'type': 'str',
                },
            'src_hw_drop': {
                'type': 'str',
                },
            'dst_tcp_auth_rst': {
                'type': 'str',
                },
            'dst_src_learn_overflow': {
                'type': 'str',
                },
            'tcp_fwd_sent': {
                'type': 'str',
                },
            'udp_fwd_sent': {
                'type': 'str',
                },
            'prog_query_exceed': {
                'type': 'str',
                },
            'prog_think_exceed': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/dst/dynamic-entry/all-entries"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/dst/dynamic-entry/all-entries"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["all-entries"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["all-entries"].get(k) != v:
            change_results["changed"] = True
            config_changes["all-entries"][k] = v

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
    payload = utils.build_json("all-entries", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["all-entries"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["all-entries-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["all-entries"]["stats"] if info != "NotFound" else info
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
