#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_netflow_monitor
description:
    - Configure NetFlow Monitor
short_description: Configures A10 netflow.monitor
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
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
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
    custom_record:
        description:
        - "Field custom_record"
        required: False
        suboptions:
            custom_cfg:
                description:
                - "Field custom_cfg"
            uuid:
                description:
                - "uuid of the object"
    disable_log_by_destination:
        description:
        - "Field disable_log_by_destination"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            ip_list:
                description:
                - "Field ip_list"
            tcp_list:
                description:
                - "Field tcp_list"
            others:
                description:
                - "Disable logging for other L4 protocols"
            ip6_list:
                description:
                - "Field ip6_list"
            udp_list:
                description:
                - "Field udp_list"
            icmp:
                description:
                - "Disable logging for icmp traffic"
    source_ip_use_mgmt:
        description:
        - "Use management interface's IP address for source ip of netflow packets"
        required: False
    protocol:
        description:
        - "'v9'= Netflow version 9; 'v10'= Netflow version 10 (IPFIX); "
        required: False
    name:
        description:
        - "Name of netflow monitor"
        required: True
    source_address:
        description:
        - "Field source_address"
        required: False
        suboptions:
            ip:
                description:
                - "Specify source IP address"
            uuid:
                description:
                - "uuid of the object"
            ipv6:
                description:
                - "Specify source IPv6 address"
    destination:
        description:
        - "Field destination"
        required: False
        suboptions:
            ip_cfg:
                description:
                - "Field ip_cfg"
            service_group:
                description:
                - "Service-group for load balancing between multiple collector servers"
            uuid:
                description:
                - "uuid of the object"
            ipv6_cfg:
                description:
                - "Field ipv6_cfg"
    user_tag:
        description:
        - "Customized tag"
        required: False
    sample:
        description:
        - "Field sample"
        required: False
        suboptions:
            ethernet_list:
                description:
                - "Field ethernet_list"
            nat_pool_list:
                description:
                - "Field nat_pool_list"
            ve_list:
                description:
                - "Field ve_list"
    record:
        description:
        - "Field record"
        required: False
        suboptions:
            nat44:
                description:
                - "NAT44 Flow Record Template"
            uuid:
                description:
                - "uuid of the object"
            sesn_event_nat64:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only creation events; 'deletion'= Export only deletion events; "
            nat64:
                description:
                - "NAT64 Flow Record Template"
            port_batch_v2_nat64:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only creation events; 'deletion'= Export only deletion events; "
            dslite:
                description:
                - "DS-Lite Flow Record Template"
            port_batch_v2_dslite:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only creation events; 'deletion'= Export only deletion events; "
            sesn_event_fw6:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only creation events; 'deletion'= Export only deletion events; "
            netflow_v5_ext:
                description:
                - "Extended NetFlow V5 Flow Record Template, supports ipv6"
            port_mapping_nat64:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only creation events; 'deletion'= Export only deletion events; "
            sesn_event_dslite:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only creation events; 'deletion'= Export only deletion events; "
            sesn_event_nat44:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only creation events; 'deletion'= Export only deletion events; "
            port_batch_v2_nat44:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only creation events; 'deletion'= Export only deletion events; "
            netflow_v5:
                description:
                - "NetFlow V5 Flow Record Template"
            port_batch_dslite:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only creation events; 'deletion'= Export only deletion events; "
            port_mapping_dslite:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only creation events; 'deletion'= Export only deletion events; "
            port_mapping_nat44:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only creation events; 'deletion'= Export only deletion events; "
            sesn_event_fw4:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only creation events; 'deletion'= Export only deletion events; "
            port_batch_nat64:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only creation events; 'deletion'= Export only deletion events; "
            port_batch_nat44:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only creation events; 'deletion'= Export only deletion events; "
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'packets-sent'= Sent Packets Count; 'bytes-sent'= Sent Bytes Count; 'nat44-records-sent'= NAT44 Flow Records Sent; 'nat44-records-sent-failure'= NAT44 Flow Records Failed; 'nat64-records-sent'= NAT64 Flow Records Sent; 'nat64-records-sent-failure'= NAT64 Flow Records Failed; 'dslite-records-sent'= Dslite Flow Records Sent; 'dslite-records-sent-failure'= Dslite Flow Records Failed; 'session-event-nat44-records-sent'= Nat44 Session Event Records Sent; 'session-event-nat44-records-sent-failure'= Nat44 Session Event Records Failed; 'session-event-nat64-records-sent'= Nat64 Session Event Records Sent; 'session-event-nat64-records-sent-failure'= Nat64 Session Event Records Falied; 'session-event-dslite-records-sent'= Dslite Session Event Records Sent; 'session-event-dslite-records-sent-failure'= Dslite Session Event Records Failed; 'session-event-fw4-records-sent'= FW4 Session Event Records Sent; 'session-event-fw4-records-sent-failure'= FW4 Session Event Records Failed; 'session-event-fw6-records-sent'= FW6 Session Event Records Sent; 'session-event-fw6-records-sent-failure'= FW6 Session Event Records Failed; 'port-mapping-nat44-records-sent'= Port Mapping Nat44 Event Records Sent; 'port-mapping-nat44-records-sent-failure'= Port Mapping Nat44 Event Records Failed; 'port-mapping-nat64-records-sent'= Port Mapping Nat64 Event Records Sent; 'port-mapping-nat64-records-sent-failure'= Port Mapping Nat64 Event Records Failed; 'port-mapping-dslite-records-sent'= Port Mapping Dslite Event Records Sent; 'port-mapping-dslite-records-sent-failure'= Port Mapping Dslite Event Records failed; 'netflow-v5-records-sent'= Netflow v5 Records Sent; 'netflow-v5-records-sent-failure'= Netflow v5 Records Failed; 'netflow-v5-ext-records-sent'= Netflow v5 Ext Records Sent; 'netflow-v5-ext-records-sent-failure'= Netflow v5 Ext Records Failed; 'port-batching-nat44-records-sent'= Port Batching Nat44 Records Sent; 'port-batching-nat44-records-sent-failure'= Port Batching Nat44 Records Failed; 'port-batching-nat64-records-sent'= Port Batching Nat64 Records Sent; 'port-batching-nat64-records-sent-failure'= Port Batching Nat64 Records Failed; 'port-batching-dslite-records-sent'= Port Batching Dslite Records Sent; 'port-batching-dslite-records-sent-failure'= Port Batching Dslite Records Failed; 'port-batching-v2-nat44-records-sent'= Port Batching V2 Nat44 Records Sent; 'port-batching-v2-nat44-records-sent-failure'= Port Batching V2 Nat44 Records Failed; 'port-batching-v2-nat64-records-sent'= Port Batching V2 Nat64 Records Sent; 'port-batching-v2-nat64-records-sent-failure'= Port Batching V2 Nat64 Records Failed; 'port-batching-v2-dslite-records-sent'= Port Batching V2 Dslite Records Sent; 'port-batching-v2-dslite-records-sent-failure'= Port Batching V2 Dslite Records Falied; 'custom-session-event-nat44-creation-records-sent'= Custom Nat44 Session Creation Records Sent; 'custom-session-event-nat44-creation-records-sent-failure'= Custom Nat44 Session Creation Records Failed; 'custom-session-event-nat64-creation-records-sent'= Custom Nat64 Session Creation Records Sent; 'custom-session-event-nat64-creation-records-sent-failure'= Custom Nat64 Session Creation Records Failed; 'custom-session-event-dslite-creation-records-sent'= Custom Dslite Session Creation Records Sent; 'custom-session-event-dslite-creation-records-sent-failure'= Custom Dslite Session Creation Records Failed; 'custom-session-event-nat44-deletion-records-sent'= Custom Nat44 Session Deletion Records Sent; 'custom-session-event-nat44-deletion-records-sent-failure'= Custom Nat44 Session Deletion Records Failed; 'custom-session-event-nat64-deletion-records-sent'= Custom Nat64 Session Deletion Records Sent; 'custom-session-event-nat64-deletion-records-sent-failure'= Custom Nat64 Session Deletion Records Failed; 'custom-session-event-dslite-deletion-records-sent'= Custom Dslite Session Deletion Records Sent; 'custom-session-event-dslite-deletion-records-sent-failure'= Custom Dslite Session Deletion Records Failed; 'custom-session-event-fw4-creation-records-sent'= Custom FW4 Session Creation Records Sent; 'custom-session-event-fw4-creation-records-sent-failure'= Custom FW4 Session Creation Records Failed; 'custom-session-event-fw6-creation-records-sent'= Custom FW6 Session Creation Records Sent; 'custom-session-event-fw6-creation-records-sent-failure'= Custom FW6 Session Creation Records Failed; 'custom-session-event-fw4-deletion-records-sent'= Custom FW4 Session Deletion Records Sent; 'custom-session-event-fw4-deletion-records-sent-failure'= Custom FW4 Session Deletion Records Failed; 'custom-session-event-fw6-deletion-records-sent'= Custom FW6 Session Deletion Records Sent; 'custom-session-event-fw6-deletion-records-sent-failure'= Custom FW6 Session Deletion Records Failed; 'custom-deny-reset-event-fw4-records-sent'= Custom FW4 Deny/Reset Event Records Sent; 'custom-deny-reset-event-fw4-records-sent-failure'= Custom FW4 Deny/Reset Event Records Failed; 'custom-deny-reset-event-fw6-records-sent'= Custom FW6 Deny/Reset Event Records Sent; 'custom-deny-reset-event-fw6-records-sent-failure'= Custom FW6 Deny/Reset Event Records Failed; 'custom-port-mapping-nat44-creation-records-sent'= Custom Nat44 Port Map Creation Records Sent; 'custom-port-mapping-nat44-creation-records-sent-failure'= Custom Nat44 Port Map Creation Records Failed; 'custom-port-mapping-nat64-creation-records-sent'= Custom Nat64 Port Map Creation Records Sent; 'custom-port-mapping-nat64-creation-records-sent-failure'= Custom Nat64 Port Map Creation Records Failed; 'custom-port-mapping-dslite-creation-records-sent'= Custom Dslite Port Map Creation Records Sent; 'custom-port-mapping-dslite-creation-records-sent-failure'= Custom Dslite Port Map Creation Records Failed; 'custom-port-mapping-nat44-deletion-records-sent'= Custom Nat44 Port Map Deletion Records Sent; 'custom-port-mapping-nat44-deletion-records-sent-failure'= Custom Nat44 Port Map Deletion Records Failed; 'custom-port-mapping-nat64-deletion-records-sent'= Custom Nat64 Port Map Deletion Records Sent; 'custom-port-mapping-nat64-deletion-records-sent-failure'= Custom Nat64 Port Map Deletion Records Failed; 'custom-port-mapping-dslite-deletion-records-sent'= Custom Dslite Port Map Deletion Records Sent; 'custom-port-mapping-dslite-deletion-records-sent-failure'= Custom Dslite Port Map Deletion Records Failed; 'custom-port-batching-nat44-creation-records-sent'= Custom Nat44 Port Batch Creation Records Sent; 'custom-port-batching-nat44-creation-records-sent-failure'= Custom Nat44 Port Batch Creation Records Failed; 'custom-port-batching-nat64-creation-records-sent'= Custom Nat64 Port Batch Creation Records Sent; 'custom-port-batching-nat64-creation-records-sent-failure'= Custom Nat64 Port Batch Creation Records Failed; 'custom-port-batching-dslite-creation-records-sent'= Custom Dslite Port Batch Creation Records Sent; 'custom-port-batching-dslite-creation-records-sent-failure'= Custom Dslite Port Batch Creation Records Failed; 'custom-port-batching-nat44-deletion-records-sent'= Custom Nat44 Port Batch Deletion Records Sent; 'custom-port-batching-nat44-deletion-records-sent-failure'= Custom Nat44 Port Batch Deletion Records Failed; 'custom-port-batching-nat64-deletion-records-sent'= Custom Nat64 Port Batch Deletion Records Sent; 'custom-port-batching-nat64-deletion-records-sent-failure'= Custom Nat64 Port Batch Deletion Records Failed; 'custom-port-batching-dslite-deletion-records-sent'= Custom Dslite Port Batch Deletion Records Sent; 'custom-port-batching-dslite-deletion-records-sent-failure'= Custom Dslite Port Batch Deletion Records Failed; 'custom-port-batching-v2-nat44-creation-records-sent'= Custom Nat44 Port Batch V2 Creation Records Sent; "
            counters2:
                description:
                - "'custom-port-batching-v2-nat44-creation-records-sent-failure'= Custom Nat44 Port Batch V2 Creation Records Failed; 'custom-port-batching-v2-nat64-creation-records-sent'= Custom Nat64 Port Batch V2 Creation Records Sent; 'custom-port-batching-v2-nat64-creation-records-sent-failure'= Custom Nat64 Port Batch V2 Creation Records Failed; 'custom-port-batching-v2-dslite-creation-records-sent'= Custom Dslite Port Batch V2 Creation Records Sent; 'custom-port-batching-v2-dslite-creation-records-sent-failure'= Custom Dslite Port Batch V2 Creation Records Failed; 'custom-port-batching-v2-nat44-deletion-records-sent'= Custom Nat44 Port Batch V2 Deletion Records Sent; 'custom-port-batching-v2-nat44-deletion-records-sent-failure'= Custom Nat44 Port Batch V2 Deletion Records Failed; 'custom-port-batching-v2-nat64-deletion-records-sent'= Custom Nat64 Port Batch V2 Deletion Records Sent; 'custom-port-batching-v2-nat64-deletion-records-sent-failure'= Custom Nat64 Port Batch V2 Deletion Records Failed; 'custom-port-batching-v2-dslite-deletion-records-sent'= Custom Dslite Port Batch V2 Deletion Records Sent; 'custom-port-batching-v2-dslite-deletion-records-sent-failure'= Custom Dslite Port Batch V2 Deletion Records Failed; 'reduced-logs-by-destination'= Reduced Logs by Destination Protocol and Port; "
    disable:
        description:
        - "Disable this netflow monitor"
        required: False
    resend_template:
        description:
        - "Field resend_template"
        required: False
        suboptions:
            records:
                description:
                - "To resend template once for each number of records (Number of records= default is 1000, 0 means disable template resend based on record-count)"
            uuid:
                description:
                - "uuid of the object"
            timeout:
                description:
                - "To set time interval to resend template (number of seconds= default is 1800, 0 means disable template resend based on timeout)"
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            port_mapping_nat64_records_sent:
                description:
                - "Port Mapping Nat64 Event Records Sent"
            port_batching_v2_dslite_records_sent:
                description:
                - "Port Batching V2 Dslite Records Sent"
            custom_deny_reset_event_fw4_records_sent:
                description:
                - "Custom FW4 Deny/Reset Event Records Sent"
            custom_session_event_dslite_deletion_records_sent:
                description:
                - "Custom Dslite Session Deletion Records Sent"
            session_event_nat64_records_sent:
                description:
                - "Nat64 Session Event Records Sent"
            port_batching_nat64_records_sent_failure:
                description:
                - "Port Batching Nat64 Records Failed"
            custom_port_batching_v2_nat64_creation_records_sent_failure:
                description:
                - "Custom Nat64 Port Batch V2 Creation Records Failed"
            session_event_dslite_records_sent:
                description:
                - "Dslite Session Event Records Sent"
            custom_port_batching_nat44_deletion_records_sent_failure:
                description:
                - "Custom Nat44 Port Batch Deletion Records Failed"
            port_batching_v2_nat44_records_sent_failure:
                description:
                - "Port Batching V2 Nat44 Records Failed"
            custom_session_event_nat44_deletion_records_sent:
                description:
                - "Custom Nat44 Session Deletion Records Sent"
            custom_session_event_nat64_creation_records_sent:
                description:
                - "Custom Nat64 Session Creation Records Sent"
            session_event_fw6_records_sent_failure:
                description:
                - "FW6 Session Event Records Failed"
            custom_port_batching_v2_nat44_deletion_records_sent:
                description:
                - "Custom Nat44 Port Batch V2 Deletion Records Sent"
            custom_port_mapping_dslite_creation_records_sent:
                description:
                - "Custom Dslite Port Map Creation Records Sent"
            custom_port_batching_nat44_deletion_records_sent:
                description:
                - "Custom Nat44 Port Batch Deletion Records Sent"
            custom_session_event_nat64_deletion_records_sent:
                description:
                - "Custom Nat64 Session Deletion Records Sent"
            custom_session_event_fw6_deletion_records_sent:
                description:
                - "Custom FW6 Session Deletion Records Sent"
            session_event_dslite_records_sent_failure:
                description:
                - "Dslite Session Event Records Failed"
            name:
                description:
                - "Name of netflow monitor"
            nat44_records_sent:
                description:
                - "NAT44 Flow Records Sent"
            custom_session_event_nat44_deletion_records_sent_failure:
                description:
                - "Custom Nat44 Session Deletion Records Failed"
            custom_port_batching_v2_nat44_creation_records_sent_failure:
                description:
                - "Custom Nat44 Port Batch V2 Creation Records Failed"
            custom_port_batching_nat64_deletion_records_sent:
                description:
                - "Custom Nat64 Port Batch Deletion Records Sent"
            nat64_records_sent_failure:
                description:
                - "NAT64 Flow Records Failed"
            netflow_v5_records_sent_failure:
                description:
                - "Netflow v5 Records Failed"
            port_batching_v2_nat64_records_sent:
                description:
                - "Port Batching V2 Nat64 Records Sent"
            netflow_v5_records_sent:
                description:
                - "Netflow v5 Records Sent"
            session_event_fw6_records_sent:
                description:
                - "FW6 Session Event Records Sent"
            custom_port_mapping_nat44_deletion_records_sent_failure:
                description:
                - "Custom Nat44 Port Map Deletion Records Failed"
            port_mapping_nat44_records_sent_failure:
                description:
                - "Port Mapping Nat44 Event Records Failed"
            custom_port_batching_dslite_creation_records_sent_failure:
                description:
                - "Custom Dslite Port Batch Creation Records Failed"
            custom_port_batching_v2_dslite_creation_records_sent_failure:
                description:
                - "Custom Dslite Port Batch V2 Creation Records Failed"
            custom_session_event_dslite_creation_records_sent_failure:
                description:
                - "Custom Dslite Session Creation Records Failed"
            custom_port_batching_nat44_creation_records_sent:
                description:
                - "Custom Nat44 Port Batch Creation Records Sent"
            custom_port_mapping_nat64_deletion_records_sent:
                description:
                - "Custom Nat64 Port Map Deletion Records Sent"
            netflow_v5_ext_records_sent_failure:
                description:
                - "Netflow v5 Ext Records Failed"
            port_batching_nat64_records_sent:
                description:
                - "Port Batching Nat64 Records Sent"
            custom_session_event_fw4_creation_records_sent:
                description:
                - "Custom FW4 Session Creation Records Sent"
            dslite_records_sent_failure:
                description:
                - "Dslite Flow Records Failed"
            custom_port_mapping_nat44_creation_records_sent_failure:
                description:
                - "Custom Nat44 Port Map Creation Records Failed"
            port_batching_v2_dslite_records_sent_failure:
                description:
                - "Port Batching V2 Dslite Records Falied"
            custom_port_batching_v2_nat64_deletion_records_sent:
                description:
                - "Custom Nat64 Port Batch V2 Deletion Records Sent"
            custom_port_mapping_nat44_deletion_records_sent:
                description:
                - "Custom Nat44 Port Map Deletion Records Sent"
            custom_port_batching_v2_nat44_creation_records_sent:
                description:
                - "Custom Nat44 Port Batch V2 Creation Records Sent"
            bytes_sent:
                description:
                - "Sent Bytes Count"
            custom_session_event_fw6_creation_records_sent_failure:
                description:
                - "Custom FW6 Session Creation Records Failed"
            custom_port_mapping_dslite_creation_records_sent_failure:
                description:
                - "Custom Dslite Port Map Creation Records Failed"
            netflow_v5_ext_records_sent:
                description:
                - "Netflow v5 Ext Records Sent"
            custom_port_batching_nat64_creation_records_sent:
                description:
                - "Custom Nat64 Port Batch Creation Records Sent"
            session_event_fw4_records_sent_failure:
                description:
                - "FW4 Session Event Records Failed"
            custom_deny_reset_event_fw4_records_sent_failure:
                description:
                - "Custom FW4 Deny/Reset Event Records Failed"
            custom_port_batching_nat64_deletion_records_sent_failure:
                description:
                - "Custom Nat64 Port Batch Deletion Records Failed"
            custom_port_batching_v2_nat44_deletion_records_sent_failure:
                description:
                - "Custom Nat44 Port Batch V2 Deletion Records Failed"
            custom_session_event_nat64_deletion_records_sent_failure:
                description:
                - "Custom Nat64 Session Deletion Records Failed"
            custom_port_mapping_nat44_creation_records_sent:
                description:
                - "Custom Nat44 Port Map Creation Records Sent"
            custom_deny_reset_event_fw6_records_sent_failure:
                description:
                - "Custom FW6 Deny/Reset Event Records Failed"
            custom_session_event_nat44_creation_records_sent:
                description:
                - "Custom Nat44 Session Creation Records Sent"
            custom_session_event_fw6_creation_records_sent:
                description:
                - "Custom FW6 Session Creation Records Sent"
            port_mapping_dslite_records_sent_failure:
                description:
                - "Port Mapping Dslite Event Records failed"
            custom_session_event_fw4_creation_records_sent_failure:
                description:
                - "Custom FW4 Session Creation Records Failed"
            custom_port_mapping_dslite_deletion_records_sent:
                description:
                - "Custom Dslite Port Map Deletion Records Sent"
            custom_port_mapping_nat64_creation_records_sent_failure:
                description:
                - "Custom Nat64 Port Map Creation Records Failed"
            port_batching_v2_nat64_records_sent_failure:
                description:
                - "Port Batching V2 Nat64 Records Failed"
            session_event_nat44_records_sent:
                description:
                - "Nat44 Session Event Records Sent"
            custom_port_batching_v2_dslite_deletion_records_sent:
                description:
                - "Custom Dslite Port Batch V2 Deletion Records Sent"
            port_mapping_nat64_records_sent_failure:
                description:
                - "Port Mapping Nat64 Event Records Failed"
            custom_session_event_fw4_deletion_records_sent:
                description:
                - "Custom FW4 Session Deletion Records Sent"
            custom_port_batching_dslite_deletion_records_sent_failure:
                description:
                - "Custom Dslite Port Batch Deletion Records Failed"
            port_mapping_dslite_records_sent:
                description:
                - "Port Mapping Dslite Event Records Sent"
            reduced_logs_by_destination:
                description:
                - "Reduced Logs by Destination Protocol and Port"
            dslite_records_sent:
                description:
                - "Dslite Flow Records Sent"
            port_mapping_nat44_records_sent:
                description:
                - "Port Mapping Nat44 Event Records Sent"
            custom_session_event_dslite_deletion_records_sent_failure:
                description:
                - "Custom Dslite Session Deletion Records Failed"
            custom_session_event_dslite_creation_records_sent:
                description:
                - "Custom Dslite Session Creation Records Sent"
            session_event_fw4_records_sent:
                description:
                - "FW4 Session Event Records Sent"
            custom_port_mapping_nat64_creation_records_sent:
                description:
                - "Custom Nat64 Port Map Creation Records Sent"
            custom_session_event_nat64_creation_records_sent_failure:
                description:
                - "Custom Nat64 Session Creation Records Failed"
            port_batching_dslite_records_sent:
                description:
                - "Port Batching Dslite Records Sent"
            custom_port_batching_v2_dslite_creation_records_sent:
                description:
                - "Custom Dslite Port Batch V2 Creation Records Sent"
            port_batching_v2_nat44_records_sent:
                description:
                - "Port Batching V2 Nat44 Records Sent"
            custom_port_mapping_nat64_deletion_records_sent_failure:
                description:
                - "Custom Nat64 Port Map Deletion Records Failed"
            custom_port_batching_v2_nat64_deletion_records_sent_failure:
                description:
                - "Custom Nat64 Port Batch V2 Deletion Records Failed"
            custom_port_batching_dslite_creation_records_sent:
                description:
                - "Custom Dslite Port Batch Creation Records Sent"
            custom_port_batching_nat64_creation_records_sent_failure:
                description:
                - "Custom Nat64 Port Batch Creation Records Failed"
            custom_session_event_fw4_deletion_records_sent_failure:
                description:
                - "Custom FW4 Session Deletion Records Failed"
            nat64_records_sent:
                description:
                - "NAT64 Flow Records Sent"
            custom_port_mapping_dslite_deletion_records_sent_failure:
                description:
                - "Custom Dslite Port Map Deletion Records Failed"
            port_batching_dslite_records_sent_failure:
                description:
                - "Port Batching Dslite Records Failed"
            custom_deny_reset_event_fw6_records_sent:
                description:
                - "Custom FW6 Deny/Reset Event Records Sent"
            port_batching_nat44_records_sent:
                description:
                - "Port Batching Nat44 Records Sent"
            custom_port_batching_dslite_deletion_records_sent:
                description:
                - "Custom Dslite Port Batch Deletion Records Sent"
            port_batching_nat44_records_sent_failure:
                description:
                - "Port Batching Nat44 Records Failed"
            custom_session_event_nat44_creation_records_sent_failure:
                description:
                - "Custom Nat44 Session Creation Records Failed"
            nat44_records_sent_failure:
                description:
                - "NAT44 Flow Records Failed"
            custom_session_event_fw6_deletion_records_sent_failure:
                description:
                - "Custom FW6 Session Deletion Records Failed"
            session_event_nat64_records_sent_failure:
                description:
                - "Nat64 Session Event Records Falied"
            custom_port_batching_nat44_creation_records_sent_failure:
                description:
                - "Custom Nat44 Port Batch Creation Records Failed"
            custom_port_batching_v2_nat64_creation_records_sent:
                description:
                - "Custom Nat64 Port Batch V2 Creation Records Sent"
            session_event_nat44_records_sent_failure:
                description:
                - "Nat44 Session Event Records Failed"
            packets_sent:
                description:
                - "Sent Packets Count"
            custom_port_batching_v2_dslite_deletion_records_sent_failure:
                description:
                - "Custom Dslite Port Batch V2 Deletion Records Failed"
    flow_timeout:
        description:
        - "Configure timeout value to export flow records periodically for long-live session ( Number of minutes= default is 10, 0 means only send flow record when session is deleted)"
        required: False
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
AVAILABLE_PROPERTIES = ["custom_record","destination","disable","disable_log_by_destination","flow_timeout","name","protocol","record","resend_template","sample","sampling_enable","source_address","source_ip_use_mgmt","stats","user_tag","uuid",]

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
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        custom_record=dict(type='dict', custom_cfg=dict(type='list', event=dict(type='str', choices=['sesn-event-nat44-creation', 'sesn-event-nat44-deletion', 'sesn-event-nat64-creation', 'sesn-event-nat64-deletion', 'sesn-event-dslite-creation', 'sesn-event-dslite-deletion', 'sesn-event-fw4-creation', 'sesn-event-fw4-deletion', 'sesn-event-fw6-creation', 'sesn-event-fw6-deletion', 'deny-reset-event-fw4', 'deny-reset-event-fw6', 'port-mapping-nat44-creation', 'port-mapping-nat44-deletion', 'port-mapping-nat64-creation', 'port-mapping-nat64-deletion', 'port-mapping-dslite-creation', 'port-mapping-dslite-deletion', 'port-batch-nat44-creation', 'port-batch-nat44-deletion', 'port-batch-nat64-creation', 'port-batch-nat64-deletion', 'port-batch-dslite-creation', 'port-batch-dslite-deletion', 'port-batch-v2-nat44-creation', 'port-batch-v2-nat44-deletion', 'port-batch-v2-nat64-creation', 'port-batch-v2-nat64-deletion', 'port-batch-v2-dslite-creation', 'port-batch-v2-dslite-deletion']), ipfix_template=dict(type='str', )), uuid=dict(type='str', )),
        disable_log_by_destination=dict(type='dict', uuid=dict(type='str', ), ip_list=dict(type='list', uuid=dict(type='str', ), ipv4_addr=dict(type='str', required=True, ), user_tag=dict(type='str', ), tcp_list=dict(type='list', tcp_port_start=dict(type='int', ), tcp_port_end=dict(type='int', )), others=dict(type='bool', ), udp_list=dict(type='list', udp_port_start=dict(type='int', ), udp_port_end=dict(type='int', )), icmp=dict(type='bool', )), tcp_list=dict(type='list', tcp_port_start=dict(type='int', ), tcp_port_end=dict(type='int', )), others=dict(type='bool', ), ip6_list=dict(type='list', uuid=dict(type='str', ), ipv6_addr=dict(type='str', required=True, ), user_tag=dict(type='str', ), tcp_list=dict(type='list', tcp_port_start=dict(type='int', ), tcp_port_end=dict(type='int', )), others=dict(type='bool', ), udp_list=dict(type='list', udp_port_start=dict(type='int', ), udp_port_end=dict(type='int', )), icmp=dict(type='bool', )), udp_list=dict(type='list', udp_port_start=dict(type='int', ), udp_port_end=dict(type='int', )), icmp=dict(type='bool', )),
        source_ip_use_mgmt=dict(type='bool', ),
        protocol=dict(type='str', choices=['v9', 'v10']),
        name=dict(type='str', required=True, ),
        source_address=dict(type='dict', ip=dict(type='str', ), uuid=dict(type='str', ), ipv6=dict(type='str', )),
        destination=dict(type='dict', ip_cfg=dict(type='dict', ip=dict(type='str', ), port4=dict(type='int', )), service_group=dict(type='str', ), uuid=dict(type='str', ), ipv6_cfg=dict(type='dict', port6=dict(type='int', ), ipv6=dict(type='str', ))),
        user_tag=dict(type='str', ),
        sample=dict(type='dict', ethernet_list=dict(type='list', ifindex=dict(type='str', required=True, ), uuid=dict(type='str', )), nat_pool_list=dict(type='list', uuid=dict(type='str', ), pool_name=dict(type='str', required=True, )), ve_list=dict(type='list', uuid=dict(type='str', ), ve_num=dict(type='int', required=True, ))),
        record=dict(type='dict', nat44=dict(type='bool', ), uuid=dict(type='str', ), sesn_event_nat64=dict(type='str', choices=['both', 'creation', 'deletion']), nat64=dict(type='bool', ), port_batch_v2_nat64=dict(type='str', choices=['both', 'creation', 'deletion']), dslite=dict(type='bool', ), port_batch_v2_dslite=dict(type='str', choices=['both', 'creation', 'deletion']), sesn_event_fw6=dict(type='str', choices=['both', 'creation', 'deletion']), netflow_v5_ext=dict(type='bool', ), port_mapping_nat64=dict(type='str', choices=['both', 'creation', 'deletion']), sesn_event_dslite=dict(type='str', choices=['both', 'creation', 'deletion']), sesn_event_nat44=dict(type='str', choices=['both', 'creation', 'deletion']), port_batch_v2_nat44=dict(type='str', choices=['both', 'creation', 'deletion']), netflow_v5=dict(type='bool', ), port_batch_dslite=dict(type='str', choices=['both', 'creation', 'deletion']), port_mapping_dslite=dict(type='str', choices=['both', 'creation', 'deletion']), port_mapping_nat44=dict(type='str', choices=['both', 'creation', 'deletion']), sesn_event_fw4=dict(type='str', choices=['both', 'creation', 'deletion']), port_batch_nat64=dict(type='str', choices=['both', 'creation', 'deletion']), port_batch_nat44=dict(type='str', choices=['both', 'creation', 'deletion'])),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'packets-sent', 'bytes-sent', 'nat44-records-sent', 'nat44-records-sent-failure', 'nat64-records-sent', 'nat64-records-sent-failure', 'dslite-records-sent', 'dslite-records-sent-failure', 'session-event-nat44-records-sent', 'session-event-nat44-records-sent-failure', 'session-event-nat64-records-sent', 'session-event-nat64-records-sent-failure', 'session-event-dslite-records-sent', 'session-event-dslite-records-sent-failure', 'session-event-fw4-records-sent', 'session-event-fw4-records-sent-failure', 'session-event-fw6-records-sent', 'session-event-fw6-records-sent-failure', 'port-mapping-nat44-records-sent', 'port-mapping-nat44-records-sent-failure', 'port-mapping-nat64-records-sent', 'port-mapping-nat64-records-sent-failure', 'port-mapping-dslite-records-sent', 'port-mapping-dslite-records-sent-failure', 'netflow-v5-records-sent', 'netflow-v5-records-sent-failure', 'netflow-v5-ext-records-sent', 'netflow-v5-ext-records-sent-failure', 'port-batching-nat44-records-sent', 'port-batching-nat44-records-sent-failure', 'port-batching-nat64-records-sent', 'port-batching-nat64-records-sent-failure', 'port-batching-dslite-records-sent', 'port-batching-dslite-records-sent-failure', 'port-batching-v2-nat44-records-sent', 'port-batching-v2-nat44-records-sent-failure', 'port-batching-v2-nat64-records-sent', 'port-batching-v2-nat64-records-sent-failure', 'port-batching-v2-dslite-records-sent', 'port-batching-v2-dslite-records-sent-failure', 'custom-session-event-nat44-creation-records-sent', 'custom-session-event-nat44-creation-records-sent-failure', 'custom-session-event-nat64-creation-records-sent', 'custom-session-event-nat64-creation-records-sent-failure', 'custom-session-event-dslite-creation-records-sent', 'custom-session-event-dslite-creation-records-sent-failure', 'custom-session-event-nat44-deletion-records-sent', 'custom-session-event-nat44-deletion-records-sent-failure', 'custom-session-event-nat64-deletion-records-sent', 'custom-session-event-nat64-deletion-records-sent-failure', 'custom-session-event-dslite-deletion-records-sent', 'custom-session-event-dslite-deletion-records-sent-failure', 'custom-session-event-fw4-creation-records-sent', 'custom-session-event-fw4-creation-records-sent-failure', 'custom-session-event-fw6-creation-records-sent', 'custom-session-event-fw6-creation-records-sent-failure', 'custom-session-event-fw4-deletion-records-sent', 'custom-session-event-fw4-deletion-records-sent-failure', 'custom-session-event-fw6-deletion-records-sent', 'custom-session-event-fw6-deletion-records-sent-failure', 'custom-deny-reset-event-fw4-records-sent', 'custom-deny-reset-event-fw4-records-sent-failure', 'custom-deny-reset-event-fw6-records-sent', 'custom-deny-reset-event-fw6-records-sent-failure', 'custom-port-mapping-nat44-creation-records-sent', 'custom-port-mapping-nat44-creation-records-sent-failure', 'custom-port-mapping-nat64-creation-records-sent', 'custom-port-mapping-nat64-creation-records-sent-failure', 'custom-port-mapping-dslite-creation-records-sent', 'custom-port-mapping-dslite-creation-records-sent-failure', 'custom-port-mapping-nat44-deletion-records-sent', 'custom-port-mapping-nat44-deletion-records-sent-failure', 'custom-port-mapping-nat64-deletion-records-sent', 'custom-port-mapping-nat64-deletion-records-sent-failure', 'custom-port-mapping-dslite-deletion-records-sent', 'custom-port-mapping-dslite-deletion-records-sent-failure', 'custom-port-batching-nat44-creation-records-sent', 'custom-port-batching-nat44-creation-records-sent-failure', 'custom-port-batching-nat64-creation-records-sent', 'custom-port-batching-nat64-creation-records-sent-failure', 'custom-port-batching-dslite-creation-records-sent', 'custom-port-batching-dslite-creation-records-sent-failure', 'custom-port-batching-nat44-deletion-records-sent', 'custom-port-batching-nat44-deletion-records-sent-failure', 'custom-port-batching-nat64-deletion-records-sent', 'custom-port-batching-nat64-deletion-records-sent-failure', 'custom-port-batching-dslite-deletion-records-sent', 'custom-port-batching-dslite-deletion-records-sent-failure', 'custom-port-batching-v2-nat44-creation-records-sent']), counters2=dict(type='str', choices=['custom-port-batching-v2-nat44-creation-records-sent-failure', 'custom-port-batching-v2-nat64-creation-records-sent', 'custom-port-batching-v2-nat64-creation-records-sent-failure', 'custom-port-batching-v2-dslite-creation-records-sent', 'custom-port-batching-v2-dslite-creation-records-sent-failure', 'custom-port-batching-v2-nat44-deletion-records-sent', 'custom-port-batching-v2-nat44-deletion-records-sent-failure', 'custom-port-batching-v2-nat64-deletion-records-sent', 'custom-port-batching-v2-nat64-deletion-records-sent-failure', 'custom-port-batching-v2-dslite-deletion-records-sent', 'custom-port-batching-v2-dslite-deletion-records-sent-failure', 'reduced-logs-by-destination'])),
        disable=dict(type='bool', ),
        resend_template=dict(type='dict', records=dict(type='int', ), uuid=dict(type='str', ), timeout=dict(type='int', )),
        stats=dict(type='dict', port_mapping_nat64_records_sent=dict(type='str', ), port_batching_v2_dslite_records_sent=dict(type='str', ), custom_deny_reset_event_fw4_records_sent=dict(type='str', ), custom_session_event_dslite_deletion_records_sent=dict(type='str', ), session_event_nat64_records_sent=dict(type='str', ), port_batching_nat64_records_sent_failure=dict(type='str', ), custom_port_batching_v2_nat64_creation_records_sent_failure=dict(type='str', ), session_event_dslite_records_sent=dict(type='str', ), custom_port_batching_nat44_deletion_records_sent_failure=dict(type='str', ), port_batching_v2_nat44_records_sent_failure=dict(type='str', ), custom_session_event_nat44_deletion_records_sent=dict(type='str', ), custom_session_event_nat64_creation_records_sent=dict(type='str', ), session_event_fw6_records_sent_failure=dict(type='str', ), custom_port_batching_v2_nat44_deletion_records_sent=dict(type='str', ), custom_port_mapping_dslite_creation_records_sent=dict(type='str', ), custom_port_batching_nat44_deletion_records_sent=dict(type='str', ), custom_session_event_nat64_deletion_records_sent=dict(type='str', ), custom_session_event_fw6_deletion_records_sent=dict(type='str', ), session_event_dslite_records_sent_failure=dict(type='str', ), name=dict(type='str', required=True, ), nat44_records_sent=dict(type='str', ), custom_session_event_nat44_deletion_records_sent_failure=dict(type='str', ), custom_port_batching_v2_nat44_creation_records_sent_failure=dict(type='str', ), custom_port_batching_nat64_deletion_records_sent=dict(type='str', ), nat64_records_sent_failure=dict(type='str', ), netflow_v5_records_sent_failure=dict(type='str', ), port_batching_v2_nat64_records_sent=dict(type='str', ), netflow_v5_records_sent=dict(type='str', ), session_event_fw6_records_sent=dict(type='str', ), custom_port_mapping_nat44_deletion_records_sent_failure=dict(type='str', ), port_mapping_nat44_records_sent_failure=dict(type='str', ), custom_port_batching_dslite_creation_records_sent_failure=dict(type='str', ), custom_port_batching_v2_dslite_creation_records_sent_failure=dict(type='str', ), custom_session_event_dslite_creation_records_sent_failure=dict(type='str', ), custom_port_batching_nat44_creation_records_sent=dict(type='str', ), custom_port_mapping_nat64_deletion_records_sent=dict(type='str', ), netflow_v5_ext_records_sent_failure=dict(type='str', ), port_batching_nat64_records_sent=dict(type='str', ), custom_session_event_fw4_creation_records_sent=dict(type='str', ), dslite_records_sent_failure=dict(type='str', ), custom_port_mapping_nat44_creation_records_sent_failure=dict(type='str', ), port_batching_v2_dslite_records_sent_failure=dict(type='str', ), custom_port_batching_v2_nat64_deletion_records_sent=dict(type='str', ), custom_port_mapping_nat44_deletion_records_sent=dict(type='str', ), custom_port_batching_v2_nat44_creation_records_sent=dict(type='str', ), bytes_sent=dict(type='str', ), custom_session_event_fw6_creation_records_sent_failure=dict(type='str', ), custom_port_mapping_dslite_creation_records_sent_failure=dict(type='str', ), netflow_v5_ext_records_sent=dict(type='str', ), custom_port_batching_nat64_creation_records_sent=dict(type='str', ), session_event_fw4_records_sent_failure=dict(type='str', ), custom_deny_reset_event_fw4_records_sent_failure=dict(type='str', ), custom_port_batching_nat64_deletion_records_sent_failure=dict(type='str', ), custom_port_batching_v2_nat44_deletion_records_sent_failure=dict(type='str', ), custom_session_event_nat64_deletion_records_sent_failure=dict(type='str', ), custom_port_mapping_nat44_creation_records_sent=dict(type='str', ), custom_deny_reset_event_fw6_records_sent_failure=dict(type='str', ), custom_session_event_nat44_creation_records_sent=dict(type='str', ), custom_session_event_fw6_creation_records_sent=dict(type='str', ), port_mapping_dslite_records_sent_failure=dict(type='str', ), custom_session_event_fw4_creation_records_sent_failure=dict(type='str', ), custom_port_mapping_dslite_deletion_records_sent=dict(type='str', ), custom_port_mapping_nat64_creation_records_sent_failure=dict(type='str', ), port_batching_v2_nat64_records_sent_failure=dict(type='str', ), session_event_nat44_records_sent=dict(type='str', ), custom_port_batching_v2_dslite_deletion_records_sent=dict(type='str', ), port_mapping_nat64_records_sent_failure=dict(type='str', ), custom_session_event_fw4_deletion_records_sent=dict(type='str', ), custom_port_batching_dslite_deletion_records_sent_failure=dict(type='str', ), port_mapping_dslite_records_sent=dict(type='str', ), reduced_logs_by_destination=dict(type='str', ), dslite_records_sent=dict(type='str', ), port_mapping_nat44_records_sent=dict(type='str', ), custom_session_event_dslite_deletion_records_sent_failure=dict(type='str', ), custom_session_event_dslite_creation_records_sent=dict(type='str', ), session_event_fw4_records_sent=dict(type='str', ), custom_port_mapping_nat64_creation_records_sent=dict(type='str', ), custom_session_event_nat64_creation_records_sent_failure=dict(type='str', ), port_batching_dslite_records_sent=dict(type='str', ), custom_port_batching_v2_dslite_creation_records_sent=dict(type='str', ), port_batching_v2_nat44_records_sent=dict(type='str', ), custom_port_mapping_nat64_deletion_records_sent_failure=dict(type='str', ), custom_port_batching_v2_nat64_deletion_records_sent_failure=dict(type='str', ), custom_port_batching_dslite_creation_records_sent=dict(type='str', ), custom_port_batching_nat64_creation_records_sent_failure=dict(type='str', ), custom_session_event_fw4_deletion_records_sent_failure=dict(type='str', ), nat64_records_sent=dict(type='str', ), custom_port_mapping_dslite_deletion_records_sent_failure=dict(type='str', ), port_batching_dslite_records_sent_failure=dict(type='str', ), custom_deny_reset_event_fw6_records_sent=dict(type='str', ), port_batching_nat44_records_sent=dict(type='str', ), custom_port_batching_dslite_deletion_records_sent=dict(type='str', ), port_batching_nat44_records_sent_failure=dict(type='str', ), custom_session_event_nat44_creation_records_sent_failure=dict(type='str', ), nat44_records_sent_failure=dict(type='str', ), custom_session_event_fw6_deletion_records_sent_failure=dict(type='str', ), session_event_nat64_records_sent_failure=dict(type='str', ), custom_port_batching_nat44_creation_records_sent_failure=dict(type='str', ), custom_port_batching_v2_nat64_creation_records_sent=dict(type='str', ), session_event_nat44_records_sent_failure=dict(type='str', ), packets_sent=dict(type='str', ), custom_port_batching_v2_dslite_deletion_records_sent_failure=dict(type='str', )),
        flow_timeout=dict(type='int', ),
        uuid=dict(type='str', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/netflow/monitor/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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
    url_base = "/axapi/v3/netflow/monitor/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
        for k, v in payload["monitor"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["monitor"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["monitor"][k] = v
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
    payload = build_json("monitor", module)
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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)
    
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