#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_lsn_global
description:
    - Set Large-Scale NAT config parameters
short_description: Configures A10 cgnv6.lsn.global
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
    logging:
        description:
        - "Field logging"
        required: False
        suboptions:
            partition_name:
                description:
                - "Select partition name for logging"
            shared:
                description:
                - "Select shared partition"
            default_template:
                description:
                - "Bind the default NAT logging template for LSN (Bind a NAT logging template)"
            pool:
                description:
                - "Field pool"
    uuid:
        description:
        - "uuid of the object"
        required: False
    inbound_refresh:
        description:
        - "'disable'= Disable NAT Inbound Refresh Behavior; "
        required: False
    hairpinning:
        description:
        - "'filter-none'= Allow self-hairpinning (default). Warning= Only applies to UDP.  TCP will use filter-self-ip-port; 'filter-self-ip'= Block hairpinning to the user's own IP; 'filter-self-ip-port'= Block hairpinning to the user's same IP and port combination; "
        required: False
    port_batching:
        description:
        - "Field port_batching"
        required: False
        suboptions:
            tcp_time_wait_interval:
                description:
                - "Minutes before TCP NAT ports can be reused (default= 2)"
            size:
                description:
                - "'1'= Allocate 1 port at a time (default); '8'= Allocate 8 ports at a time; '16'= Allocate 16 ports at a time; '32'= Allocate 32 ports at a time; '64'= Allocate 64 ports at a time; '128'= Allocate 128 ports at a time; '256'= Allocate 256 ports at a time; '512'= Allocate 512 ports at a time; "
    half_close_timeout:
        description:
        - "Set LSN Half close timeout (Half close timeout in seconds (default not set))"
        required: False
    attempt_port_preservation:
        description:
        - "'disable'= Don't attempt port preservation for NAT allocation; "
        required: False
    ip_selection:
        description:
        - "'random'= Random (long-run uniformly distributed) NAT IP selection (default); 'round-robin'= Round-robin; 'least-used-strict'= Fewest NAT ports used; 'least-udp-used-strict'= Fewest UDP NAT ports used; 'least-tcp-used-strict'= Fewest TCP NAT ports used; 'least-reserved-strict'= Fewest NAT ports reserved; 'least-udp-reserved-strict'= Fewest UDP NAT ports reserved; 'least-tcp-reserved-strict'= Fewest TCP NAT ports reserved; 'least-users-strict'= Fewest number of users; "
        required: False
    syn_timeout:
        description:
        - "Set LSN SYN timeout (SYN idle-timeout in seconds (default= 4 seconds))"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters4:
                description:
                - "'adc_port_allocation_ineligible'= ADC Port Allocation Not Allowed; 'acl_http_domain_node_exceeded'= ACL HTTP Domain Node Exceeded; "
            counters1:
                description:
                - "'all'= all; 'total_tcp_allocated'= Total TCP Ports Allocated; 'total_tcp_freed'= Total TCP Ports Freed; 'total_udp_allocated'= Total UDP Ports Allocated; 'total_udp_freed'= Total UDP Ports Freed; 'total_icmp_allocated'= Total ICMP Ports Allocated; 'total_icmp_freed'= Total ICMP Ports Freed; 'data_session_created'= Data Session Created; 'data_session_freed'= Data Session Freed; 'user_quota_created'= User-Quota Created; 'user_quota_put_in_del_q'= User-Quota Freed; 'user_quota_failure'= User-Quota Creation Failed; 'nat_port_unavailable_tcp'= TCP NAT Port Unavailable; 'nat_port_unavailable_udp'= UDP NAT Port Unavailable; 'nat_port_unavailable_icmp'= ICMP NAT Port Unavailable; 'new_user_resource_unavailable'= New User NAT Resource Unavailable; 'tcp_user_quota_exceeded'= TCP User-Quota Exceeded; 'udp_user_quota_exceeded'= UDP User-Quota Exceeded; 'icmp_user_quota_exceeded'= ICMP User-Quota Exceeded; 'extended_quota_matched'= Extended User-Quota Matched; 'extended_quota_exceeded'= Extended User-Quota Exceeded; 'data_sesn_user_quota_exceeded'= Data Session User-Quota Exceeded; 'data_sesn_rate_user_quota_exceeded'= Conn Rate User-Quota Exceeded; 'tcp_fullcone_created'= TCP Full-cone Session Created; 'tcp_fullcone_freed'= TCP Full-cone Session Freed; 'udp_fullcone_created'= UDP Full-cone Session Created; 'udp_fullcone_freed'= UDP Full-cone Session Freed; 'fullcone_failure'= Full-cone Session Creation Failed; 'hairpin'= Hairpin Session Created; 'fullcone_self_hairpinning_drop'= Self-Hairpinning Drop; 'endpoint_indep_map_match'= Endpoint-Independent Mapping Matched; 'endpoint_indep_filter_match'= Endpoint-Independent Filtering Matched; 'inbound_filtered'= Endpoint-Dependent Filtering Drop; 'eif_limit_exceeded'= Endpoint-Independent Filtering Inbound Limit Exceeded; 'nat_mismatch_drop'= NAT Pool Mismatch Drop; 'total_tcp_overloaded'= TCP Port Overloaded; 'total_udp_overloaded'= UDP Port Overloaded; 'port_overloading_smp_inserted_tcp'= TCP Port Overloading Session Created; 'port_overloading_smp_inserted_udp'= UDP Port Overloading Session Created; 'port_overloading_smp_free_tcp'= TCP Port Overloading Session Freed; 'port_overloading_smp_free_udp'= UDP Port Overloading Session Freed; 'nat_pool_unusable'= nat_pool_unusable; 'ha_nat_pool_unusable'= HA NAT Pool Unusable; 'ha_nat_pool_batch_type_mismatch'= HA NAT Pool Batch Type Mismatch; 'no_radius_profile_match'= No RADIUS Profile Match; 'nat_ip_max_tcp_ports_allocated'= NAT IP TCP Max Ports Allocated; 'nat_ip_max_udp_ports_allocated'= NAT IP UDP Max Ports Allocated; 'no_class_list_match'= No Class-List Match; 'lid_drop'= LSN LID Drop; 'lid_pass_through'= LSN LID Pass-through; 'fullcone_in_del_q'= Full-cone session found in delete queue; 'fullcone_retry_lookup'= Full-cone session retry look-up; 'fullcone_not_found'= Full-cone session not found; 'nat_port_double_free'= NAT Port Double Free; 'nat_port_chunk_freed_from_cpu'= NAT Port Chunks Freed From CPU; 'nat_port_freed_from_diff_cpu'= NAT Port Freed On Different CPU; 'nat_pool_deleted'= NAT Pool Deleted; 'nat_esp_ip_conflicts'= LSN NAT ESP IP Conflicts; 'nat_esp_no_control_sesn'= LSN NAT ESP No Control Session; 'esp_user_quota_exceeded'= ESP User-Quota exceeded; 'udp_alg_user_quota_exceeded'= UDP ALG User-Quota exceeded; 'gre_user_quota_exceeded'= GRE User-Quota exceeded; 'ha_classlist_mismatch'= HA Class-list Mismatch; 'ha_user_quota_mismatch'= HA User-Quota Mismatch; 'ha_fullcone_mismatch'= HA Full-cone Mismatch; 'ha_port_mismatch'= HA Port Mismatch; 'ha_dnat_mismatch'= HA Destination NAT Config Mismatch; 'ha_nat_port_unavailable'= HA NAT Port Unavailable; 'ha_unknown_nat_ip'= HA Unknown NAT IP; 'ha_fullcone_failure'= HA Full-cone Session Failure; 'ha_fullcone_create_race_failure'= HA Full-cone Create Race Failure; 'ha_endpoint_indep_map_match'= HA Endpoint-independent Matching; 'standby_class_list_drop'= HA Standby Class-List drop; 'bad_tuple_nat_ip'= Bad NAT IP from tuple; 'bad_smp_tuple_nat_ip'= Bad NAT IP from SMP tuple; 'fullcone_inbound_nat_pool_mismatch'= Full-cone Session NAT Pool Mismatch; 'fullcone_overflow_eim'= Full-cone Session EIM Overflow; 'fullcone_overflow_eif'= Full-cone Session EIF Overflow; 'cross_cpu_helper_created'= Cross CPU Session Helper Created; 'cross_cpu_sent'= Cross CPU Helper Packets Sent; 'cross_cpu_rcv'= Cross CPU Helper Packets Received; 'cross_cpu_bad_l3'= Cross CPU Unsupported L3; 'cross_cpu_bad_l4'= Cross CPU Unsupported L4; 'cross_cpu_no_session'= Cross CPU No Session Found; 'cross_cpu_helper_free'= Cross CPU Helper Free; 'cross_cpu_helper_free_retry_lookup'= Cross CPU Helper Free Retry Lookup; 'cross_cpu_helper_free_not_found'= Cross CPU Helper Free Not Found; 'cross_cpu_helper_deleted'= Cross CPU Helper Deleted; 'cross_cpu_helper_cpu_mismatch'= Cross CPU Helper CPU Mismatch; 'cross_cpu_helper_nat_pool_standby'= Cross CPU Helper NAT Pool Standby; 'cross_cpu_helper_double_add'= Cross CPU Helper Double Add Attempt; 'mtu_exceeded'= Packet Exceeded MTU; 'frag'= Fragmented Packets; 'dslite_tunnel_frag'= IPv4 Fragment DS-Lite Packet; 'sixrd_tunnel_frag'= IPv6 Fragment IPv6-in-IPv4 Packet; 'frag_icmp'= ICMP Packet Too Big Sent; 'frag_tunnel_icmp'= DS-Lite ICMP Packet Too Big Sent; 'quota_ext_mem_allocated'= Quota Extension Memory Allocated; 'quota_ext_mem_alloc_failure'= Quota Extension Out of Memory; 'quota_ext_mem_freed'= Quota Extension Memory Freed; 'quota_ext_put_in_del_q'= Quota Extension Put in Delete Queue; 'port_batch_num_mismatch'= Specific Port Batch Num Ports Mismatch; 'port_batch_interval_mismatch'= Specific Port Batch Port Interval Mismatch; 'port_pair_alloc_bad_math'= Port Pair Alloc Bad Math; 'free_port_from_quota_no_container'= Free Port from Quota No Container; 'free_port_from_quota_no_port_info'= Free Port From Quota No Port Info; 'static_nat_cross_cpu_helper_created'= Cross CPU Helper Created for Static NAT; 'static_nat_cross_cpu_helper_deleted'= Cross CPU Helper Deleted for Static NAT; 'static_nat_cross_cpu_helper_standby'= Cross CPU Helper Static NAT Standby; 'static_nat_cross_cpu_helper_cpu_mismatch'= Static NAT Cross CPU Helper CPU Mismatch; 'static_nat_cross_cpu_sent'= Static NAT Cross CPU Helper Sent; 'static_nat_cross_cpu_rcv'= Static NAT Cross CPU Helper Packets Received; 'static_nat_cross_cpu_bad_l3'= Static NAT Cross CPU Unsupported L3; 'static_nat_cross_cpu_bad_l4'= Static NAT Cross CPU Unsupported L4; 'static_nat_cross_cpu_no_session'= Static NAT Cross CPU No Session Found; 'static_nat_cross_cpu_helper_free'= Static NAT Cross CPU Helper Free; 'static_nat_cross_cpu_helper_free_retry_lookup'= Static NAT Cross CPU Helper Free Retry Lookup; 'static_nat_cross_cpu_helper_free_not_found'= Static NAT Cross CPU Helper Free Not Found; 'static_nat_ha_map_mismatch'= Static NAT Mapping Mismatch on HA Standby; 'ip_slb_cross_cpu_sent'= IP SLB Cross CPU Packets Sent; 'fullcone_force_deleted'= Full-cone Session Force Deleted; 'user_quota_mem_allocated'= User-Quota Memory Allocated; 'user_quota_mem_freed'= User-Quota Memory Freed; 'user_quota_created_shadow'= Total User-Quota Created; 'quota_marked_deleted'= User-Quota Marked Deleted; 'quota_delete_not_in_bucket'= User-Quota Delete Not In Bucket; 'user_quota_put_in_del_q_shadow'= Total User-Quota Put In Del Q; 'tcp_out_of_state_rst_sent'= Total Out of State TCP RST sent; 'tcp_out_of_state_rst_dropped'= Total Out of State TCP RST dropped; 'icmp_out_of_state_uqe_admin_filtered_sent'= Total User Quota Exceeded ICMP admin filtered sent; 'icmp_out_of_state_uqe_host_unreachable_sent'= Total User Quota Exceeded ICMP host unreachable sent; "
            counters2:
                description:
                - "'icmp_out_of_state_uqe_dropped'= Total User Queue Exceeded ICMP notification dropped; 'user_quota_not_found'= User-Quota Not Found; 'tcp_fullcone_created_shadow'= Total TCP Full-cone sessions created; 'tcp_fullcone_freed_shadow'= Total TCP Full-cone sessions freed; 'udp_fullcone_created_shadow'= Total UDP Full-cone sessions created; 'udp_fullcone_freed_shadow'= Total UDP Full-cone sessions freed; 'udp_alg_fullcone_created'= Total UDP ALG Full-cone sessions created; 'udp_alg_fullcone_freed'= Total UDP ALG Full-cone sessions freed; 'fullcone_created'= Total Full-cone sessions created; 'fullcone_freed'= Total Full-cone sessions freed; 'data_session_created_shadow'= Total Data Sessions Created; 'data_session_freed_shadow'= Total Data Sessions Freed; 'data_session_user_quota_mismatch'= Data Session Counter Per User Mismatch; 'extended_quota_mismatched'= Extended User-Quota Mismatched; 'nat_port_unavailable_other'= Other NAT Port Unavailable; 'nat_port_unavailable'= Total NAT Port Unavailable; 'new_user_resource_unavailable_tcp'= TCP New User NAT Resource Unavailable; 'new_user_resource_unavailable_udp'= UDP New User NAT Resource Unavailable; 'new_user_resource_unavailable_icmp'= ICMP New User NAT Resource Unavailable; 'new_user_resource_unavailable_other'= Other New User NAT Resource Unavailable; 'total_tcp_allocated_shadow'= Total TCP Ports Allocated; 'total_tcp_freed_shadow'= Total TCP Ports Freed; 'total_udp_allocated_shadow'= Total UDP Ports Allocated; 'total_udp_freed_shadow'= Total UDP Ports Freed; 'total_icmp_allocated_shadow'= Total ICMP Ports Allocated; 'total_icmp_freed_shadow'= Total ICMP Ports Freed; 'udp_alg_no_quota'= UDP ALG User-Quota Not Found; 'udp_alg_eim_mismatch'= UDP ALG Endpoint-Independent Mapping Mismatch; 'udp_alg_no_nat_ip'= UDP ALG User-Quota Unknown NAT IP; 'udp_alg_alloc_failure'= UDP ALG Port Allocation Failure; 'sip_alg_no_quota'= SIP ALG User-Quota Not Found; 'sip_alg_quota_inc_failure'= SIP ALG User-Quota Exceeded; 'sip_alg_no_nat_ip'= SIP ALG Unknown NAT IP; 'sip_alg_reuse_contact_fullcone'= SIP ALG Reuse Contact Full-cone Session; 'sip_alg_contact_fullcone_mismatch'= SIP ALG Contact Full-cone Session Mismatch; 'sip_alg_alloc_contact_port_failure'= SIP ALG Alloc Contact NAT Port Failure; 'sip_alg_create_contact_fullcone_failure'= SIP ALG Create Contact Full-cone Session Failure; 'sip_alg_release_contact_port_failure'= SIP ALG Release Contact NAT Port Failure; 'sip_alg_single_rtp_fullcone'= SIP ALG Single RTP Full-cone Found; 'sip_alg_single_rtcp_fullcone'= SIP ALG Single RTCP Full-cone Found; 'sip_alg_rtcp_fullcone_mismatch'= SIP ALG RTCP Full-cone NAT Port Mismatch; 'sip_alg_reuse_rtp_rtcp_fullcone'= SIP ALG Reuse RTP/RTCP Full-cone Session; 'sip_alg_alloc_rtp_rtcp_port_failure'= SIP ALG Alloc RTP/RTCP NAT Ports Failure; 'sip_alg_alloc_single_port_failure'= SIP ALG Alloc Single RTP or RTCP NAT Port Failure; 'sip_alg_create_single_fullcone_failure'= SIP ALG Create Single RTP or RTCP Full-cone Session Failure; 'sip_alg_create_rtp_fullcone_failure'= SIP ALG Create RTP Full-cone Session Failure; 'sip_alg_create_rtcp_fullcone_failure'= SIP ALG Create RTCP Full-cone Session Failure; 'sip_alg_port_pair_alloc_from_consecutive'= SIP ALG Port Pair Allocated From Consecutive; 'sip_alg_port_pair_alloc_from_partition'= SIP ALG Port Pair Allocated From Partition; 'sip_alg_port_pair_alloc_from_pool_port_batch'= SIP ALG Port Pair Allocated From Pool Port Batch; 'sip_alg_port_pair_alloc_from_quota_consecutive'= SIP ALG Port Pair Allocated From Quota Consecutive; 'sip_alg_port_pair_alloc_from_quota_partition'= SIP ALG Port Pair Allocated From Quota Partition; 'sip_alg_port_pair_alloc_from_quota_partition_error'= SIP ALG Port Pair Allocated From Quota Partition Error; 'sip_alg_port_pair_alloc_from_quota_pool_port_batch'= SIP ALG Port Pair Allocated From Quota Pool Port Batch; 'sip_alg_port_pair_alloc_from_quota_pool_port_batch_with_frag'= SIP ALG Port Pair Allocated From Quota Port Batch Version 2 with Frag Free Ports; 'h323_alg_no_quota'= H323 ALG User-Quota Not Found; 'h323_alg_quota_inc_failure'= H323 ALG User-Quota Exceeded; 'h323_alg_no_nat_ip'= H323 ALG Unknown NAT IP; 'h323_alg_reuse_fullcone'= H323 ALG Reuse Full-cone Session; 'h323_alg_fullcone_mismatch'= H323 ALG Full-cone Session Mismatch; 'h323_alg_alloc_port_failure'= H323 ALG Alloc NAT Port Failure; 'h323_alg_create_fullcone_failure'= H323 ALG Create Full-cone Session Failure; 'h323_alg_release_port_failure'= H323 ALG Release NAT Port Failure; 'h323_alg_single_rtp_fullcone'= H323 ALG Single RTP Full-cone Found; 'h323_alg_single_rtcp_fullcone'= H323 ALG Single RTCP Full-cone Found; 'h323_alg_rtcp_fullcone_mismatch'= H323 ALG RTCP Full-cone NAT Port Mismatch; 'h323_alg_reuse_rtp_rtcp_fullcone'= H323 ALG Reuse RTP/RTCP Full-cone Session; 'h323_alg_alloc_rtp_rtcp_port_failure'= H323 ALG Alloc RTP/RTCP NAT Ports Failure; 'h323_alg_alloc_single_port_failure'= H323 ALG Alloc Single RTP or RTCP NAT Port Failure; 'h323_alg_create_single_fullcone_failure'= H323 ALG Create Single RTP or RTCP Full-cone Session Failure; 'h323_alg_create_rtp_fullcone_failure'= H323 ALG Create RTP Full-cone Session Failure; 'h323_alg_create_rtcp_fullcone_failure'= H323 ALG Create RTCP Full-cone Session Failure; 'h323_alg_port_pair_alloc_from_consecutive'= H323 ALG Port Pair Allocated From Consecutive; 'h323_alg_port_pair_alloc_from_partition'= H323 ALG Port Pair Allocated From Partition; 'h323_alg_port_pair_alloc_from_pool_port_batch'= H323 ALG Port Pair Allocated From Pool Port Batch; 'h323_alg_port_pair_alloc_from_quota_consecutive'= H323 ALG Port Pair Allocated From Quota Consecutive; 'h323_alg_port_pair_alloc_from_quota_partition'= H323 ALG Port Pair Allocated From Quota Partition; 'h323_alg_port_pair_alloc_from_quota_partition_error'= H323 ALG Port Pair Allocated From Quota Partition Error; 'h323_alg_port_pair_alloc_from_quota_pool_port_batch'= H323 ALG Port Pair Allocated From Quota Pool Port Batch; 'port_batch_quota_extension_alloc_failure'= Port Batch Extension Alloc Failure (No memory); 'port_batch_free_quota_not_found'= Port Batch Quota Not Found on Free; 'port_batch_free_port_not_found'= Port Batch Port Not Found on Free; 'port_batch_free_wrong_partition'= Port Batch Free Wrong Partition; 'radius_query_quota_ext_alloc_failure'= RADIUS Query Container Alloc (No Memoty); 'radius_query_quota_ext_alloc_race_free'= RADIUS Query Container Alloc Race Free; 'quota_extension_added'= Quota Extension Added to Quota; 'quota_extension_removed'= Quota Extension Removed from Quota; 'quota_extension_remove_not_found'= Quota Extension Not Found on Remove; 'ha_sync_port_batch_sent'= HA Port Batch Extension Sync Sent; 'ha_sync_port_batch_rcv'= HA Port Batch Extension Sync Received; 'ha_send_port_batch_not_found'= HA Port Batch Not Found on Sync Send; 'ha_rcv_port_not_in_port_batch'= HA Port Not in Port Batch on Sync Rcv; 'bad_port_to_free'= Freeing Bad Port; 'consecutive_port_free'= Port Freed from Consecutive Pool; 'partition_port_free'= Port Freed from Partition; 'pool_port_batch_port_free'= Port Freed from Pool Port Batch; 'port_allocated_from_quota_consecutive'= Port Allocated from Quota Consecutive; 'port_allocated_from_quota_partition'= Port Allocated from Quota Partition; 'port_allocated_from_quota_pool_port_batch'= Port Allocated from Quota Pool Port Batch; 'port_freed_from_quota_consecutive'= Port Freed from Quota Consecutive; 'port_freed_from_quota_partition'= Port Freed from Quota Partition; 'port_freed_from_quota_pool_port_batch'= Port Freed from Quota Pool Port Batch; 'port_batch_allocated_to_quota'= Port Batch Allocated to Quota; 'port_batch_freed_from_quota'= Port Batch Freed From Quota; "
            counters3:
                description:
                - "'specific_port_allocated_from_quota_consecutive'= Specific Port Allocated from Quota Consecutive; 'specific_port_allocated_from_quota_partition'= Specific Port Allocated from Quota Partition; 'specific_port_allocated_from_quota_pool_port_batch'= Specific Port Allocated from Quota Pool Port Batch; 'port_batch_container_alloc_failure'= Port Batch Container Alloc Out of Memory; 'port_batch_container_alloc_race_free'= Port Batch Container Race Free; 'port_overloading_destination_conflict'= Port Overloading Destination Conflict; 'port_overloading_out_of_memory'= Port Overloading Out of Memory; 'port_overloading_assign_user'= Port Overloading Port Assign User; 'port_overloading_assign_user_port_batch'= Port Overloading Port Assign User Port Batch; 'port_overloading_inc'= Port Overloading Port Increment; 'port_overloading_dec_on_conflict'= Port Overloading Port Decrement on Conflict; 'port_overloading_dec_on_free'= Port Overloading Port Decrement on Free; 'port_overloading_free_port_on_conflict'= Port Overloading Free Port on Conflict; 'port_overloading_free_port_batch_on_conflict'= Port Overloading Free Port Batch on Conflict; 'port_overloading_inc_overflow'= Port Overloading Inc Overflow; 'port_overloading_attempt_consecutive_ports'= Port Overloading on Consecutive Ports; 'port_overloading_attempt_same_partition'= Port Overloading on Same Partition; 'port_overloading_attempt_diff_partition'= Port Overloading on Different Partition; 'port_overloading_attempt_failed'= Port Overloading Attempt Failed; 'port_overloading_conn_free_retry_lookup'= Port Overloading Conn Free Retry Lookup; 'port_overloading_conn_free_not_found'= Port Overloading Conn Free Not Found; 'port_overloading_smp_mem_allocated'= Port Overloading SMP Session Allocated; 'port_overloading_smp_mem_freed'= Port Overloading SMP Session Freed; 'port_overloading_smp_inserted'= Port Overloading SMP Inserted; 'port_overloading_smp_inserted_tcp_shadow'= Total Port Overloading SMP TCP Inserted; 'port_overloading_smp_inserted_udp_shadow'= Total Port Overloading SMP UDP Inserted; 'port_overloading_smp_free_tcp_shadow'= Total Port Overloading SMP TCP Freed; 'port_overloading_smp_free_udp_shadow'= Total Port Overloading SMP UDP Freed; 'port_overloading_smp_put_in_del_q_from_conn'= Port Overloading SMP Free From Conn; 'port_overloading_smp_free_dec_failure'= Port Overloading SMP Free Dec Failure; 'port_overloading_smp_free_no_quota'= Port Overloading SMP Free No Quota; 'port_overloading_smp_free_port'= Port Overloading SMP Free Port; 'port_overloading_smp_free_port_from_quota'= Port Overloading SMP Free Port From Quota; 'port_overloading_for_no_ports'= Port Overloading for No Ports; 'port_overloading_for_no_ports_success'= Port Overloading for No Ports Success; 'port_overloading_for_quota_exceeded'= Port Overloading for Quota Exceeded; 'port_overloading_for_quota_exceeded_success'= Port Overloading for Quota Exceeded Success; 'port_overloading_for_quota_exceeded_race'= Port Overloading for Quota Exceeded Race; 'port_overloading_for_quota_exceeded_race_success'= Port Overloading for Quota Exceeded Race Success; 'port_overloading_for_new_user'= Port Overloading for New User; 'port_overloading_for_new_user_success'= Port Overloading for New User Success; 'ha_port_overloading_attempt_failed'= HA Port Overloading Attempt Failed; 'ha_port_overloading_for_no_ports'= HA Port Overloading for No Ports; 'ha_port_overloading_for_no_ports_success'= HA Port Overloading for No Ports Success; 'ha_port_overloading_for_quota_exceeded'= HA Port Overloading for Quota Exceeded; 'ha_port_overloading_for_quota_exceeded_success'= HA Port Overloading for Quota Exceeded Success; 'ha_port_overloading_for_quota_exceeded_race'= HA Port Overloading for Quota Exceeded Race; 'ha_port_overloading_for_quota_exceeded_race_success'= HA Port Overloading for Quota Exceeded Race Success; 'ha_port_overloading_for_new_user'= HA Port Overloading for New User; 'ha_port_overloading_for_new_user_success'= HA Port Overloading for New User Success; 'nat_pool_force_delete'= NAT Pool Force Delete; 'quota_ext_too_many'= Quota Ext Too Many; 'nat_pool_not_found_on_free'= NAT Pool Not Found on Free; 'fullcone_ext_mem_freed'= LSN Fullcone Extension Memory Freed; 'fullcone_ext_mem_allocated'= LSN Fullcone Extension Memory Allocated; 'fullcone_ext_mem_alloc_failure'= LSN Fullcone Extension Memory Allocate Failure; 'fullcone_ext_mem_alloc_init_faulure'= LSN Fullcone Extension Initialization Failure; 'fullcone_ext_added'= LSN Fullcone Extension Added; 'fullcone_ext_too_many'= LSN Fullcone Extension Too Many; 'nat_pool_attempt_adding_multiple_free_batches'= Attempt Adding Multiple Free Batches to Quota; 'nat_pool_add_free_batch_failed'= Add Batch to Quota Failed; 'mgcp_alg_no_quota'= MGCP ALG User-Quota Not Found; 'mgcp_alg_quota_inc_failure'= MGCP ALG User-Quota Exceeded; 'mgcp_alg_no_nat_ip'= MGCP ALG Unknown NAT IP; 'mgcp_alg_reuse_fullcone'= MGCP ALG Reuse Full-cone Session; 'mgcp_alg_fullcone_mismatch'= MGCP ALG Full-cone Session Mismatch; 'mgcp_alg_alloc_port_failure'= MGCP ALG Alloc NAT Port Failure; 'mgcp_alg_create_fullcone_failure'= MGCP ALG Create Full-cone Session Failure; 'mgcp_alg_release_port_failure'= MGCP ALG Release NAT Port Failure; 'mgcp_alg_single_rtp_fullcone'= MGCP ALG Single RTP Full-cone Found; 'mgcp_alg_single_rtcp_fullcone'= MGCP ALG Single RTCP Full-cone Found; 'mgcp_alg_rtcp_fullcone_mismatch'= MGCP ALG RTCP Full-cone NAT Port Mismatch; 'mgcp_alg_reuse_rtp_rtcp_fullcone'= MGCP ALG Reuse RTP/RTCP Full-cone Session; 'mgcp_alg_alloc_rtp_rtcp_port_failure'= MGCP ALG Alloc RTP/RTCP NAT Ports Failure; 'mgcp_alg_alloc_single_port_failure'= MGCP ALG Alloc Single RTP or RTCP NAT Port Failure; 'mgcp_alg_create_single_fullcone_failure'= MGCP ALG Create Single RTP or RTCP Full-cone Session Failure; 'mgcp_alg_create_rtp_fullcone_failure'= MGCP ALG Create RTP Full-cone Session Failure; 'mgcp_alg_create_rtcp_fullcone_failure'= MGCP ALG Create RTCP Full-cone Session Failure; 'mgcp_alg_port_pair_alloc_from_consecutive'= MGCP ALG Port Pair Allocated From Consecutive; 'mgcp_alg_port_pair_alloc_from_partition'= MGCP ALG Port Pair Allocated From Partition; 'mgcp_alg_port_pair_alloc_from_pool_port_batch'= MGCP ALG Port Pair Allocated From Pool Port Batch; 'mgcp_alg_port_pair_alloc_from_quota_consecutive'= MGCP ALG Port Pair Allocated From Quota Consecutive; 'mgcp_alg_port_pair_alloc_from_quota_partition'= MGCP ALG Port Pair Allocated From Quota Partition; 'mgcp_alg_port_pair_alloc_from_quota_partition_error'= MGCP ALG Port Pair Allocated From Quota Partition Error; 'mgcp_alg_port_pair_alloc_from_quota_pool_port_batch'= MGCP ALG Port Pair Allocated From Quota Pool Port Batch; 'user_quota_unusable_drop'= User-Quota Unusable Drop; 'user_quota_unusable'= User-Quota Marked Unusable; 'nat_pool_same_port_batch_udp_failed'= Simultaneous Batch Allocation UDP Port Allocation Failed; 'cross_cpu_helper_created_eim'= EIM Cross CPU Session Helper Created; 'cross_cpu_helper_created_eif'= EIF Cross CPU Session Helper Created; 'cross_cpu_helper_created_udp'= UDP Cross CPU Session Helper Created; 'cross_cpu_helper_created_tcp'= TCP Cross CPU Session Helper Created; 'cross_cpu_helper_created_icmp'= ICMP Cross CPU Session Helper Created; 'cross_cpu_helper_created_ip'= IP Cross CPU Session Helper Created; 'cross_cpu_helper_free_not_found_ip'= IP Cross CPU Helper Free Not Found; 'cross_cpu_helper_free_not_found_icmp'= ICMP Cross CPU Helper Free Not Found; 'cross_cpu_helper_free_not_found_tcp'= TCP Cross CPU Helper Free Not Found; 'cross_cpu_helper_free_not_found_udp'= UDP Cross CPU Helper Free Not Found; 'adc_port_allocation_failed'= ADC Port Allocation Failed; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            data_session_freed:
                description:
                - "Data Session Freed"
            port_overloading_smp_inserted_udp:
                description:
                - "UDP Port Overloading Session Created"
            total_udp_overloaded:
                description:
                - "UDP Port Overloaded"
            endpoint_indep_filter_match:
                description:
                - "Endpoint-Independent Filtering Matched"
            udp_fullcone_freed:
                description:
                - "UDP Full-cone Session Freed"
            nat_pool_unusable:
                description:
                - "Field nat_pool_unusable"
            nat_port_unavailable_udp:
                description:
                - "UDP NAT Port Unavailable"
            lid_pass_through:
                description:
                - "LSN LID Pass-through"
            total_icmp_freed:
                description:
                - "Total ICMP Ports Freed"
            hairpin:
                description:
                - "Hairpin Session Created"
            tcp_fullcone_created:
                description:
                - "TCP Full-cone Session Created"
            nat_port_unavailable_icmp:
                description:
                - "ICMP NAT Port Unavailable"
            udp_fullcone_created:
                description:
                - "UDP Full-cone Session Created"
            extended_quota_matched:
                description:
                - "Extended User-Quota Matched"
            icmp_user_quota_exceeded:
                description:
                - "ICMP User-Quota Exceeded"
            ha_nat_pool_unusable:
                description:
                - "HA NAT Pool Unusable"
            port_overloading_smp_free_udp:
                description:
                - "UDP Port Overloading Session Freed"
            total_tcp_allocated:
                description:
                - "Total TCP Ports Allocated"
            acl_http_domain_node_exceeded:
                description:
                - "ACL HTTP Domain Node Exceeded"
            tcp_user_quota_exceeded:
                description:
                - "TCP User-Quota Exceeded"
            port_overloading_smp_inserted_tcp:
                description:
                - "TCP Port Overloading Session Created"
            eif_limit_exceeded:
                description:
                - "Endpoint-Independent Filtering Inbound Limit Exceeded"
            adc_port_allocation_failed:
                description:
                - "ADC Port Allocation Failed"
            udp_user_quota_exceeded:
                description:
                - "UDP User-Quota Exceeded"
            ha_nat_pool_batch_type_mismatch:
                description:
                - "HA NAT Pool Batch Type Mismatch"
            user_quota_failure:
                description:
                - "User-Quota Creation Failed"
            user_quota_put_in_del_q:
                description:
                - "User-Quota Freed"
            adc_port_allocation_ineligible:
                description:
                - "ADC Port Allocation Not Allowed"
            total_udp_freed:
                description:
                - "Total UDP Ports Freed"
            nat_port_unavailable_tcp:
                description:
                - "TCP NAT Port Unavailable"
            total_tcp_overloaded:
                description:
                - "TCP Port Overloaded"
            fullcone_failure:
                description:
                - "Full-cone Session Creation Failed"
            user_quota_created:
                description:
                - "User-Quota Created"
            data_sesn_user_quota_exceeded:
                description:
                - "Data Session User-Quota Exceeded"
            nat_ip_max_udp_ports_allocated:
                description:
                - "NAT IP UDP Max Ports Allocated"
            data_sesn_rate_user_quota_exceeded:
                description:
                - "Conn Rate User-Quota Exceeded"
            nat_ip_max_tcp_ports_allocated:
                description:
                - "NAT IP TCP Max Ports Allocated"
            fullcone_self_hairpinning_drop:
                description:
                - "Self-Hairpinning Drop"
            nat_mismatch_drop:
                description:
                - "NAT Pool Mismatch Drop"
            new_user_resource_unavailable:
                description:
                - "New User NAT Resource Unavailable"
            extended_quota_exceeded:
                description:
                - "Extended User-Quota Exceeded"
            total_udp_allocated:
                description:
                - "Total UDP Ports Allocated"
            data_session_created:
                description:
                - "Data Session Created"
            port_overloading_smp_free_tcp:
                description:
                - "TCP Port Overloading Session Freed"
            endpoint_indep_map_match:
                description:
                - "Endpoint-Independent Mapping Matched"
            tcp_fullcone_freed:
                description:
                - "TCP Full-cone Session Freed"
            no_radius_profile_match:
                description:
                - "No RADIUS Profile Match"
            total_icmp_allocated:
                description:
                - "Total ICMP Ports Allocated"
            no_class_list_match:
                description:
                - "No Class-List Match"
            inbound_filtered:
                description:
                - "Endpoint-Dependent Filtering Drop"
            total_tcp_freed:
                description:
                - "Total TCP Ports Freed"
            lid_drop:
                description:
                - "LSN LID Drop"
    icmp:
        description:
        - "Field icmp"
        required: False
        suboptions:
            send_on_user_quota_exceeded:
                description:
                - "'host-unreachable'= Send ICMP destination host unreachable; 'admin-filtered'= Send ICMP admin filtered (default); 'disable'= Disable ICMP quota exceeded message; "
            send_on_port_unavailable:
                description:
                - "'host-unreachable'= Send ICMP destination host unreachable; 'admin-filtered'= Send ICMP admin filtered; 'disable'= Disable ICMP port unavailable message (default); "


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["attempt_port_preservation","hairpinning","half_close_timeout","icmp","inbound_refresh","ip_selection","logging","port_batching","sampling_enable","stats","syn_timeout","uuid",]

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
        logging=dict(type='dict',partition_name=dict(type='str',),shared=dict(type='bool',),default_template=dict(type='str',),pool=dict(type='list',template=dict(type='str',),pool_name=dict(type='str',))),
        uuid=dict(type='str',),
        inbound_refresh=dict(type='str',choices=['disable']),
        hairpinning=dict(type='str',choices=['filter-none','filter-self-ip','filter-self-ip-port']),
        port_batching=dict(type='dict',tcp_time_wait_interval=dict(type='int',),size=dict(type='str',choices=['1','8','16','32','64','128','256','512'])),
        half_close_timeout=dict(type='int',),
        attempt_port_preservation=dict(type='str',choices=['disable']),
        ip_selection=dict(type='str',choices=['random','round-robin','least-used-strict','least-udp-used-strict','least-tcp-used-strict','least-reserved-strict','least-udp-reserved-strict','least-tcp-reserved-strict','least-users-strict']),
        syn_timeout=dict(type='int',),
        sampling_enable=dict(type='list',counters4=dict(type='str',choices=['adc_port_allocation_ineligible','acl_http_domain_node_exceeded']),counters1=dict(type='str',choices=['all','total_tcp_allocated','total_tcp_freed','total_udp_allocated','total_udp_freed','total_icmp_allocated','total_icmp_freed','data_session_created','data_session_freed','user_quota_created','user_quota_put_in_del_q','user_quota_failure','nat_port_unavailable_tcp','nat_port_unavailable_udp','nat_port_unavailable_icmp','new_user_resource_unavailable','tcp_user_quota_exceeded','udp_user_quota_exceeded','icmp_user_quota_exceeded','extended_quota_matched','extended_quota_exceeded','data_sesn_user_quota_exceeded','data_sesn_rate_user_quota_exceeded','tcp_fullcone_created','tcp_fullcone_freed','udp_fullcone_created','udp_fullcone_freed','fullcone_failure','hairpin','fullcone_self_hairpinning_drop','endpoint_indep_map_match','endpoint_indep_filter_match','inbound_filtered','eif_limit_exceeded','nat_mismatch_drop','total_tcp_overloaded','total_udp_overloaded','port_overloading_smp_inserted_tcp','port_overloading_smp_inserted_udp','port_overloading_smp_free_tcp','port_overloading_smp_free_udp','nat_pool_unusable','ha_nat_pool_unusable','ha_nat_pool_batch_type_mismatch','no_radius_profile_match','nat_ip_max_tcp_ports_allocated','nat_ip_max_udp_ports_allocated','no_class_list_match','lid_drop','lid_pass_through','fullcone_in_del_q','fullcone_retry_lookup','fullcone_not_found','nat_port_double_free','nat_port_chunk_freed_from_cpu','nat_port_freed_from_diff_cpu','nat_pool_deleted','nat_esp_ip_conflicts','nat_esp_no_control_sesn','esp_user_quota_exceeded','udp_alg_user_quota_exceeded','gre_user_quota_exceeded','ha_classlist_mismatch','ha_user_quota_mismatch','ha_fullcone_mismatch','ha_port_mismatch','ha_dnat_mismatch','ha_nat_port_unavailable','ha_unknown_nat_ip','ha_fullcone_failure','ha_fullcone_create_race_failure','ha_endpoint_indep_map_match','standby_class_list_drop','bad_tuple_nat_ip','bad_smp_tuple_nat_ip','fullcone_inbound_nat_pool_mismatch','fullcone_overflow_eim','fullcone_overflow_eif','cross_cpu_helper_created','cross_cpu_sent','cross_cpu_rcv','cross_cpu_bad_l3','cross_cpu_bad_l4','cross_cpu_no_session','cross_cpu_helper_free','cross_cpu_helper_free_retry_lookup','cross_cpu_helper_free_not_found','cross_cpu_helper_deleted','cross_cpu_helper_cpu_mismatch','cross_cpu_helper_nat_pool_standby','cross_cpu_helper_double_add','mtu_exceeded','frag','dslite_tunnel_frag','sixrd_tunnel_frag','frag_icmp','frag_tunnel_icmp','quota_ext_mem_allocated','quota_ext_mem_alloc_failure','quota_ext_mem_freed','quota_ext_put_in_del_q','port_batch_num_mismatch','port_batch_interval_mismatch','port_pair_alloc_bad_math','free_port_from_quota_no_container','free_port_from_quota_no_port_info','static_nat_cross_cpu_helper_created','static_nat_cross_cpu_helper_deleted','static_nat_cross_cpu_helper_standby','static_nat_cross_cpu_helper_cpu_mismatch','static_nat_cross_cpu_sent','static_nat_cross_cpu_rcv','static_nat_cross_cpu_bad_l3','static_nat_cross_cpu_bad_l4','static_nat_cross_cpu_no_session','static_nat_cross_cpu_helper_free','static_nat_cross_cpu_helper_free_retry_lookup','static_nat_cross_cpu_helper_free_not_found','static_nat_ha_map_mismatch','ip_slb_cross_cpu_sent','fullcone_force_deleted','user_quota_mem_allocated','user_quota_mem_freed','user_quota_created_shadow','quota_marked_deleted','quota_delete_not_in_bucket','user_quota_put_in_del_q_shadow','tcp_out_of_state_rst_sent','tcp_out_of_state_rst_dropped','icmp_out_of_state_uqe_admin_filtered_sent','icmp_out_of_state_uqe_host_unreachable_sent']),counters2=dict(type='str',choices=['icmp_out_of_state_uqe_dropped','user_quota_not_found','tcp_fullcone_created_shadow','tcp_fullcone_freed_shadow','udp_fullcone_created_shadow','udp_fullcone_freed_shadow','udp_alg_fullcone_created','udp_alg_fullcone_freed','fullcone_created','fullcone_freed','data_session_created_shadow','data_session_freed_shadow','data_session_user_quota_mismatch','extended_quota_mismatched','nat_port_unavailable_other','nat_port_unavailable','new_user_resource_unavailable_tcp','new_user_resource_unavailable_udp','new_user_resource_unavailable_icmp','new_user_resource_unavailable_other','total_tcp_allocated_shadow','total_tcp_freed_shadow','total_udp_allocated_shadow','total_udp_freed_shadow','total_icmp_allocated_shadow','total_icmp_freed_shadow','udp_alg_no_quota','udp_alg_eim_mismatch','udp_alg_no_nat_ip','udp_alg_alloc_failure','sip_alg_no_quota','sip_alg_quota_inc_failure','sip_alg_no_nat_ip','sip_alg_reuse_contact_fullcone','sip_alg_contact_fullcone_mismatch','sip_alg_alloc_contact_port_failure','sip_alg_create_contact_fullcone_failure','sip_alg_release_contact_port_failure','sip_alg_single_rtp_fullcone','sip_alg_single_rtcp_fullcone','sip_alg_rtcp_fullcone_mismatch','sip_alg_reuse_rtp_rtcp_fullcone','sip_alg_alloc_rtp_rtcp_port_failure','sip_alg_alloc_single_port_failure','sip_alg_create_single_fullcone_failure','sip_alg_create_rtp_fullcone_failure','sip_alg_create_rtcp_fullcone_failure','sip_alg_port_pair_alloc_from_consecutive','sip_alg_port_pair_alloc_from_partition','sip_alg_port_pair_alloc_from_pool_port_batch','sip_alg_port_pair_alloc_from_quota_consecutive','sip_alg_port_pair_alloc_from_quota_partition','sip_alg_port_pair_alloc_from_quota_partition_error','sip_alg_port_pair_alloc_from_quota_pool_port_batch','sip_alg_port_pair_alloc_from_quota_pool_port_batch_with_frag','h323_alg_no_quota','h323_alg_quota_inc_failure','h323_alg_no_nat_ip','h323_alg_reuse_fullcone','h323_alg_fullcone_mismatch','h323_alg_alloc_port_failure','h323_alg_create_fullcone_failure','h323_alg_release_port_failure','h323_alg_single_rtp_fullcone','h323_alg_single_rtcp_fullcone','h323_alg_rtcp_fullcone_mismatch','h323_alg_reuse_rtp_rtcp_fullcone','h323_alg_alloc_rtp_rtcp_port_failure','h323_alg_alloc_single_port_failure','h323_alg_create_single_fullcone_failure','h323_alg_create_rtp_fullcone_failure','h323_alg_create_rtcp_fullcone_failure','h323_alg_port_pair_alloc_from_consecutive','h323_alg_port_pair_alloc_from_partition','h323_alg_port_pair_alloc_from_pool_port_batch','h323_alg_port_pair_alloc_from_quota_consecutive','h323_alg_port_pair_alloc_from_quota_partition','h323_alg_port_pair_alloc_from_quota_partition_error','h323_alg_port_pair_alloc_from_quota_pool_port_batch','port_batch_quota_extension_alloc_failure','port_batch_free_quota_not_found','port_batch_free_port_not_found','port_batch_free_wrong_partition','radius_query_quota_ext_alloc_failure','radius_query_quota_ext_alloc_race_free','quota_extension_added','quota_extension_removed','quota_extension_remove_not_found','ha_sync_port_batch_sent','ha_sync_port_batch_rcv','ha_send_port_batch_not_found','ha_rcv_port_not_in_port_batch','bad_port_to_free','consecutive_port_free','partition_port_free','pool_port_batch_port_free','port_allocated_from_quota_consecutive','port_allocated_from_quota_partition','port_allocated_from_quota_pool_port_batch','port_freed_from_quota_consecutive','port_freed_from_quota_partition','port_freed_from_quota_pool_port_batch','port_batch_allocated_to_quota','port_batch_freed_from_quota']),counters3=dict(type='str',choices=['specific_port_allocated_from_quota_consecutive','specific_port_allocated_from_quota_partition','specific_port_allocated_from_quota_pool_port_batch','port_batch_container_alloc_failure','port_batch_container_alloc_race_free','port_overloading_destination_conflict','port_overloading_out_of_memory','port_overloading_assign_user','port_overloading_assign_user_port_batch','port_overloading_inc','port_overloading_dec_on_conflict','port_overloading_dec_on_free','port_overloading_free_port_on_conflict','port_overloading_free_port_batch_on_conflict','port_overloading_inc_overflow','port_overloading_attempt_consecutive_ports','port_overloading_attempt_same_partition','port_overloading_attempt_diff_partition','port_overloading_attempt_failed','port_overloading_conn_free_retry_lookup','port_overloading_conn_free_not_found','port_overloading_smp_mem_allocated','port_overloading_smp_mem_freed','port_overloading_smp_inserted','port_overloading_smp_inserted_tcp_shadow','port_overloading_smp_inserted_udp_shadow','port_overloading_smp_free_tcp_shadow','port_overloading_smp_free_udp_shadow','port_overloading_smp_put_in_del_q_from_conn','port_overloading_smp_free_dec_failure','port_overloading_smp_free_no_quota','port_overloading_smp_free_port','port_overloading_smp_free_port_from_quota','port_overloading_for_no_ports','port_overloading_for_no_ports_success','port_overloading_for_quota_exceeded','port_overloading_for_quota_exceeded_success','port_overloading_for_quota_exceeded_race','port_overloading_for_quota_exceeded_race_success','port_overloading_for_new_user','port_overloading_for_new_user_success','ha_port_overloading_attempt_failed','ha_port_overloading_for_no_ports','ha_port_overloading_for_no_ports_success','ha_port_overloading_for_quota_exceeded','ha_port_overloading_for_quota_exceeded_success','ha_port_overloading_for_quota_exceeded_race','ha_port_overloading_for_quota_exceeded_race_success','ha_port_overloading_for_new_user','ha_port_overloading_for_new_user_success','nat_pool_force_delete','quota_ext_too_many','nat_pool_not_found_on_free','fullcone_ext_mem_freed','fullcone_ext_mem_allocated','fullcone_ext_mem_alloc_failure','fullcone_ext_mem_alloc_init_faulure','fullcone_ext_added','fullcone_ext_too_many','nat_pool_attempt_adding_multiple_free_batches','nat_pool_add_free_batch_failed','mgcp_alg_no_quota','mgcp_alg_quota_inc_failure','mgcp_alg_no_nat_ip','mgcp_alg_reuse_fullcone','mgcp_alg_fullcone_mismatch','mgcp_alg_alloc_port_failure','mgcp_alg_create_fullcone_failure','mgcp_alg_release_port_failure','mgcp_alg_single_rtp_fullcone','mgcp_alg_single_rtcp_fullcone','mgcp_alg_rtcp_fullcone_mismatch','mgcp_alg_reuse_rtp_rtcp_fullcone','mgcp_alg_alloc_rtp_rtcp_port_failure','mgcp_alg_alloc_single_port_failure','mgcp_alg_create_single_fullcone_failure','mgcp_alg_create_rtp_fullcone_failure','mgcp_alg_create_rtcp_fullcone_failure','mgcp_alg_port_pair_alloc_from_consecutive','mgcp_alg_port_pair_alloc_from_partition','mgcp_alg_port_pair_alloc_from_pool_port_batch','mgcp_alg_port_pair_alloc_from_quota_consecutive','mgcp_alg_port_pair_alloc_from_quota_partition','mgcp_alg_port_pair_alloc_from_quota_partition_error','mgcp_alg_port_pair_alloc_from_quota_pool_port_batch','user_quota_unusable_drop','user_quota_unusable','nat_pool_same_port_batch_udp_failed','cross_cpu_helper_created_eim','cross_cpu_helper_created_eif','cross_cpu_helper_created_udp','cross_cpu_helper_created_tcp','cross_cpu_helper_created_icmp','cross_cpu_helper_created_ip','cross_cpu_helper_free_not_found_ip','cross_cpu_helper_free_not_found_icmp','cross_cpu_helper_free_not_found_tcp','cross_cpu_helper_free_not_found_udp','adc_port_allocation_failed'])),
        stats=dict(type='dict',data_session_freed=dict(type='str',),port_overloading_smp_inserted_udp=dict(type='str',),total_udp_overloaded=dict(type='str',),endpoint_indep_filter_match=dict(type='str',),udp_fullcone_freed=dict(type='str',),nat_pool_unusable=dict(type='str',),nat_port_unavailable_udp=dict(type='str',),lid_pass_through=dict(type='str',),total_icmp_freed=dict(type='str',),hairpin=dict(type='str',),tcp_fullcone_created=dict(type='str',),nat_port_unavailable_icmp=dict(type='str',),udp_fullcone_created=dict(type='str',),extended_quota_matched=dict(type='str',),icmp_user_quota_exceeded=dict(type='str',),ha_nat_pool_unusable=dict(type='str',),port_overloading_smp_free_udp=dict(type='str',),total_tcp_allocated=dict(type='str',),acl_http_domain_node_exceeded=dict(type='str',),tcp_user_quota_exceeded=dict(type='str',),port_overloading_smp_inserted_tcp=dict(type='str',),eif_limit_exceeded=dict(type='str',),adc_port_allocation_failed=dict(type='str',),udp_user_quota_exceeded=dict(type='str',),ha_nat_pool_batch_type_mismatch=dict(type='str',),user_quota_failure=dict(type='str',),user_quota_put_in_del_q=dict(type='str',),adc_port_allocation_ineligible=dict(type='str',),total_udp_freed=dict(type='str',),nat_port_unavailable_tcp=dict(type='str',),total_tcp_overloaded=dict(type='str',),fullcone_failure=dict(type='str',),user_quota_created=dict(type='str',),data_sesn_user_quota_exceeded=dict(type='str',),nat_ip_max_udp_ports_allocated=dict(type='str',),data_sesn_rate_user_quota_exceeded=dict(type='str',),nat_ip_max_tcp_ports_allocated=dict(type='str',),fullcone_self_hairpinning_drop=dict(type='str',),nat_mismatch_drop=dict(type='str',),new_user_resource_unavailable=dict(type='str',),extended_quota_exceeded=dict(type='str',),total_udp_allocated=dict(type='str',),data_session_created=dict(type='str',),port_overloading_smp_free_tcp=dict(type='str',),endpoint_indep_map_match=dict(type='str',),tcp_fullcone_freed=dict(type='str',),no_radius_profile_match=dict(type='str',),total_icmp_allocated=dict(type='str',),no_class_list_match=dict(type='str',),inbound_filtered=dict(type='str',),total_tcp_freed=dict(type='str',),lid_drop=dict(type='str',)),
        icmp=dict(type='dict',send_on_user_quota_exceeded=dict(type='str',choices=['host-unreachable','admin-filtered','disable']),send_on_port_unavailable=dict(type='str',choices=['host-unreachable','admin-filtered','disable']))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/lsn/global"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/lsn/global"

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
        for k, v in payload["global"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["global"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["global"][k] = v
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
    payload = build_json("global", module)
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