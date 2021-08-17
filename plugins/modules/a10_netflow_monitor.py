#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_netflow_monitor
description:
    - Configure NetFlow Monitor
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
        - "Name of netflow monitor"
        type: str
        required: True
    disable:
        description:
        - "Disable this netflow monitor"
        type: bool
        required: False
    source_ip_use_mgmt:
        description:
        - "Use management interface's IP address for source ip of netflow packets"
        type: bool
        required: False
    flow_timeout:
        description:
        - "Configure timeout value to export flow records periodically for long-live
          session ( Number of minutes= default is 10, 0 means only send flow record when
          session is deleted)"
        type: int
        required: False
    protocol:
        description:
        - "'v9'= Netflow version 9; 'v10'= Netflow version 10 (IPFIX);"
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
                - "'all'= all; 'packets-sent'= Sent Packets Count; 'bytes-sent'= Sent Bytes Count;
          'nat44-records-sent'= NAT44 Flow Records Sent; 'nat44-records-sent-failure'=
          NAT44 Flow Records Failed; 'nat64-records-sent'= NAT64 Flow Records Sent;
          'nat64-records-sent-failure'= NAT64 Flow Records Failed; 'dslite-records-sent'=
          Dslite Flow Records Sent; 'dslite-records-sent-failure'= Dslite Flow Records
          Failed; 'session-event-nat44-records-sent'= Nat44 Session Event Records Sent;
          'session-event-nat44-records-sent-failure'= Nat44 Session Event Records Failed;
          'session-event-nat64-records-sent'= Nat64 Session Event Records Sent; 'session-
          event-nat64-records-sent-failure'= Nat64 Session Event Records Falied;
          'session-event-dslite-records-sent'= Dslite Session Event Records Sent;
          'session-event-dslite-records-sent-failure'= Dslite Session Event Records
          Failed; 'session-event-fw4-records-sent'= FW4 Session Event Records Sent;
          'session-event-fw4-records-sent-failure'= FW4 Session Event Records Failed;
          'session-event-fw6-records-sent'= FW6 Session Event Records Sent; 'session-
          event-fw6-records-sent-failure'= FW6 Session Event Records Failed; 'port-
          mapping-nat44-records-sent'= Port Mapping Nat44 Event Records Sent; 'port-
          mapping-nat44-records-sent-failure'= Port Mapping Nat44 Event Records Failed;
          'port-mapping-nat64-records-sent'= Port Mapping Nat64 Event Records Sent;
          'port-mapping-nat64-records-sent-failure'= Port Mapping Nat64 Event Records
          Failed; 'port-mapping-dslite-records-sent'= Port Mapping Dslite Event Records
          Sent; 'port-mapping-dslite-records-sent-failure'= Port Mapping Dslite Event
          Records failed; 'netflow-v5-records-sent'= Netflow v5 Records Sent;
          'netflow-v5-records-sent-failure'= Netflow v5 Records Failed; 'netflow-v5-ext-
          records-sent'= Netflow v5 Ext Records Sent; 'netflow-v5-ext-records-sent-
          failure'= Netflow v5 Ext Records Failed; 'port-batching-nat44-records-sent'=
          Port Batching Nat44 Records Sent; 'port-batching-nat44-records-sent-failure'=
          Port Batching Nat44 Records Failed; 'port-batching-nat64-records-sent'= Port
          Batching Nat64 Records Sent; 'port-batching-nat64-records-sent-failure'= Port
          Batching Nat64 Records Failed; 'port-batching-dslite-records-sent'= Port
          Batching Dslite Records Sent; 'port-batching-dslite-records-sent-failure'= Port
          Batching Dslite Records Failed; 'port-batching-v2-nat44-records-sent'= Port
          Batching V2 Nat44 Records Sent; 'port-batching-v2-nat44-records-sent-failure'=
          Port Batching V2 Nat44 Records Failed; 'port-batching-v2-nat64-records-sent'=
          Port Batching V2 Nat64 Records Sent; 'port-batching-v2-nat64-records-sent-
          failure'= Port Batching V2 Nat64 Records Failed; 'port-batching-v2-dslite-
          records-sent'= Port Batching V2 Dslite Records Sent; 'port-batching-v2-dslite-
          records-sent-failure'= Port Batching V2 Dslite Records Falied; 'custom-session-
          event-nat44-creation-records-sent'= Custom Nat44 Session Creation Records Sent;
          'custom-session-event-nat44-creation-records-sent-failure'= Custom Nat44
          Session Creation Records Failed; 'custom-session-event-nat64-creation-records-
          sent'= Custom Nat64 Session Creation Records Sent; 'custom-session-event-
          nat64-creation-records-sent-failure'= Custom Nat64 Session Creation Records
          Failed; 'custom-session-event-dslite-creation-records-sent'= Custom Dslite
          Session Creation Records Sent; 'custom-session-event-dslite-creation-records-
          sent-failure'= Custom Dslite Session Creation Records Failed; 'custom-session-
          event-nat44-deletion-records-sent'= Custom Nat44 Session Deletion Records Sent;
          'custom-session-event-nat44-deletion-records-sent-failure'= Custom Nat44
          Session Deletion Records Failed; 'custom-session-event-nat64-deletion-records-
          sent'= Custom Nat64 Session Deletion Records Sent; 'custom-session-event-
          nat64-deletion-records-sent-failure'= Custom Nat64 Session Deletion Records
          Failed; 'custom-session-event-dslite-deletion-records-sent'= Custom Dslite
          Session Deletion Records Sent; 'custom-session-event-dslite-deletion-records-
          sent-failure'= Custom Dslite Session Deletion Records Failed; 'custom-session-
          event-fw4-creation-records-sent'= Custom FW4 Session Creation Records Sent;
          'custom-session-event-fw4-creation-records-sent-failure'= Custom FW4 Session
          Creation Records Failed; 'custom-session-event-fw6-creation-records-sent'=
          Custom FW6 Session Creation Records Sent; 'custom-session-event-fw6-creation-
          records-sent-failure'= Custom FW6 Session Creation Records Failed; 'custom-
          session-event-fw4-deletion-records-sent'= Custom FW4 Session Deletion Records
          Sent; 'custom-session-event-fw4-deletion-records-sent-failure'= Custom FW4
          Session Deletion Records Failed; 'custom-session-event-fw6-deletion-records-
          sent'= Custom FW6 Session Deletion Records Sent; 'custom-session-event-
          fw6-deletion-records-sent-failure'= Custom FW6 Session Deletion Records Failed;
          'custom-deny-reset-event-fw4-records-sent'= Custom FW4 Deny/Reset Event Records
          Sent; 'custom-deny-reset-event-fw4-records-sent-failure'= Custom FW4 Deny/Reset
          Event Records Failed; 'custom-deny-reset-event-fw6-records-sent'= Custom FW6
          Deny/Reset Event Records Sent; 'custom-deny-reset-event-fw6-records-sent-
          failure'= Custom FW6 Deny/Reset Event Records Failed; 'custom-port-mapping-
          nat44-creation-records-sent'= Custom Nat44 Port Map Creation Records Sent;
          'custom-port-mapping-nat44-creation-records-sent-failure'= Custom Nat44 Port
          Map Creation Records Failed; 'custom-port-mapping-nat64-creation-records-sent'=
          Custom Nat64 Port Map Creation Records Sent; 'custom-port-mapping-
          nat64-creation-records-sent-failure'= Custom Nat64 Port Map Creation Records
          Failed; 'custom-port-mapping-dslite-creation-records-sent'= Custom Dslite Port
          Map Creation Records Sent; 'custom-port-mapping-dslite-creation-records-sent-
          failure'= Custom Dslite Port Map Creation Records Failed; 'custom-port-mapping-
          nat44-deletion-records-sent'= Custom Nat44 Port Map Deletion Records Sent;
          'custom-port-mapping-nat44-deletion-records-sent-failure'= Custom Nat44 Port
          Map Deletion Records Failed; 'custom-port-mapping-nat64-deletion-records-sent'=
          Custom Nat64 Port Map Deletion Records Sent; 'custom-port-mapping-
          nat64-deletion-records-sent-failure'= Custom Nat64 Port Map Deletion Records
          Failed; 'custom-port-mapping-dslite-deletion-records-sent'= Custom Dslite Port
          Map Deletion Records Sent; 'custom-port-mapping-dslite-deletion-records-sent-
          failure'= Custom Dslite Port Map Deletion Records Failed; 'custom-port-
          batching-nat44-creation-records-sent'= Custom Nat44 Port Batch Creation Records
          Sent; 'custom-port-batching-nat44-creation-records-sent-failure'= Custom Nat44
          Port Batch Creation Records Failed; 'custom-port-batching-nat64-creation-
          records-sent'= Custom Nat64 Port Batch Creation Records Sent; 'custom-port-
          batching-nat64-creation-records-sent-failure'= Custom Nat64 Port Batch Creation
          Records Failed; 'custom-port-batching-dslite-creation-records-sent'= Custom
          Dslite Port Batch Creation Records Sent; 'custom-port-batching-dslite-creation-
          records-sent-failure'= Custom Dslite Port Batch Creation Records Failed;
          'custom-port-batching-nat44-deletion-records-sent'= Custom Nat44 Port Batch
          Deletion Records Sent; 'custom-port-batching-nat44-deletion-records-sent-
          failure'= Custom Nat44 Port Batch Deletion Records Failed; 'custom-port-
          batching-nat64-deletion-records-sent'= Custom Nat64 Port Batch Deletion Records
          Sent; 'custom-port-batching-nat64-deletion-records-sent-failure'= Custom Nat64
          Port Batch Deletion Records Failed; 'custom-port-batching-dslite-deletion-
          records-sent'= Custom Dslite Port Batch Deletion Records Sent; 'custom-port-
          batching-dslite-deletion-records-sent-failure'= Custom Dslite Port Batch
          Deletion Records Failed; 'custom-port-batching-v2-nat44-creation-records-sent'=
          Custom Nat44 Port Batch V2 Creation Records Sent;"
                type: str
            counters2:
                description:
                - "'custom-port-batching-v2-nat44-creation-records-sent-failure'= Custom Nat44
          Port Batch V2 Creation Records Failed; 'custom-port-batching-v2-nat64-creation-
          records-sent'= Custom Nat64 Port Batch V2 Creation Records Sent; 'custom-port-
          batching-v2-nat64-creation-records-sent-failure'= Custom Nat64 Port Batch V2
          Creation Records Failed; 'custom-port-batching-v2-dslite-creation-records-
          sent'= Custom Dslite Port Batch V2 Creation Records Sent; 'custom-port-
          batching-v2-dslite-creation-records-sent-failure'= Custom Dslite Port Batch V2
          Creation Records Failed; 'custom-port-batching-v2-nat44-deletion-records-sent'=
          Custom Nat44 Port Batch V2 Deletion Records Sent; 'custom-port-
          batching-v2-nat44-deletion-records-sent-failure'= Custom Nat44 Port Batch V2
          Deletion Records Failed; 'custom-port-batching-v2-nat64-deletion-records-sent'=
          Custom Nat64 Port Batch V2 Deletion Records Sent; 'custom-port-
          batching-v2-nat64-deletion-records-sent-failure'= Custom Nat64 Port Batch V2
          Deletion Records Failed; 'custom-port-batching-v2-dslite-deletion-records-
          sent'= Custom Dslite Port Batch V2 Deletion Records Sent; 'custom-port-
          batching-v2-dslite-deletion-records-sent-failure'= Custom Dslite Port Batch V2
          Deletion Records Failed; 'reduced-logs-by-destination'= Reduced Logs by
          Destination Protocol and Port;"
                type: str
    disable_log_by_destination:
        description:
        - "Field disable_log_by_destination"
        type: dict
        required: False
        suboptions:
            tcp_list:
                description:
                - "Field tcp_list"
                type: list
            udp_list:
                description:
                - "Field udp_list"
                type: list
            icmp:
                description:
                - "Disable logging for icmp traffic"
                type: bool
            others:
                description:
                - "Disable logging for other L4 protocols"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            ip_list:
                description:
                - "Field ip_list"
                type: list
            ip6_list:
                description:
                - "Field ip6_list"
                type: list
    record:
        description:
        - "Field record"
        type: dict
        required: False
        suboptions:
            netflow_v5:
                description:
                - "NetFlow V5 Flow Record Template"
                type: bool
            netflow_v5_ext:
                description:
                - "Extended NetFlow V5 Flow Record Template, supports ipv6"
                type: bool
            nat44:
                description:
                - "NAT44 Flow Record Template"
                type: bool
            nat64:
                description:
                - "NAT64 Flow Record Template"
                type: bool
            dslite:
                description:
                - "DS-Lite Flow Record Template"
                type: bool
            sesn_event_nat44:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only
          creation events; 'deletion'= Export only deletion events;"
                type: str
            sesn_event_nat64:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only
          creation events; 'deletion'= Export only deletion events;"
                type: str
            sesn_event_dslite:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only
          creation events; 'deletion'= Export only deletion events;"
                type: str
            sesn_event_fw4:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only
          creation events; 'deletion'= Export only deletion events;"
                type: str
            sesn_event_fw6:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only
          creation events; 'deletion'= Export only deletion events;"
                type: str
            port_mapping_nat44:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only
          creation events; 'deletion'= Export only deletion events;"
                type: str
            port_mapping_nat64:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only
          creation events; 'deletion'= Export only deletion events;"
                type: str
            port_mapping_dslite:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only
          creation events; 'deletion'= Export only deletion events;"
                type: str
            port_batch_nat44:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only
          creation events; 'deletion'= Export only deletion events;"
                type: str
            port_batch_nat64:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only
          creation events; 'deletion'= Export only deletion events;"
                type: str
            port_batch_dslite:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only
          creation events; 'deletion'= Export only deletion events;"
                type: str
            port_batch_v2_nat44:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only
          creation events; 'deletion'= Export only deletion events;"
                type: str
            port_batch_v2_nat64:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only
          creation events; 'deletion'= Export only deletion events;"
                type: str
            port_batch_v2_dslite:
                description:
                - "'both'= Export both creation and deletion events; 'creation'= Export only
          creation events; 'deletion'= Export only deletion events;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    custom_record:
        description:
        - "Field custom_record"
        type: dict
        required: False
        suboptions:
            custom_cfg:
                description:
                - "Field custom_cfg"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
    destination:
        description:
        - "Field destination"
        type: dict
        required: False
        suboptions:
            service_group:
                description:
                - "Service-group for load balancing between multiple collector servers"
                type: str
            ip_cfg:
                description:
                - "Field ip_cfg"
                type: dict
            ipv6_cfg:
                description:
                - "Field ipv6_cfg"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
    source_address:
        description:
        - "Field source_address"
        type: dict
        required: False
        suboptions:
            ip:
                description:
                - "Specify source IP address"
                type: str
            ipv6:
                description:
                - "Specify source IPv6 address"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    resend_template:
        description:
        - "Field resend_template"
        type: dict
        required: False
        suboptions:
            timeout:
                description:
                - "To set time interval to resend template (number of seconds= default is 1800, 0
          means disable template resend based on timeout)"
                type: int
            records:
                description:
                - "To resend template once for each number of records (Number of records= default
          is 1000, 0 means disable template resend based on record-count)"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    sample:
        description:
        - "Field sample"
        type: dict
        required: False
        suboptions:
            ethernet_list:
                description:
                - "Field ethernet_list"
                type: list
            ve_list:
                description:
                - "Field ve_list"
                type: list
            nat_pool_list:
                description:
                - "Field nat_pool_list"
                type: list
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            packets_sent:
                description:
                - "Sent Packets Count"
                type: str
            bytes_sent:
                description:
                - "Sent Bytes Count"
                type: str
            nat44_records_sent:
                description:
                - "NAT44 Flow Records Sent"
                type: str
            nat44_records_sent_failure:
                description:
                - "NAT44 Flow Records Failed"
                type: str
            nat64_records_sent:
                description:
                - "NAT64 Flow Records Sent"
                type: str
            nat64_records_sent_failure:
                description:
                - "NAT64 Flow Records Failed"
                type: str
            dslite_records_sent:
                description:
                - "Dslite Flow Records Sent"
                type: str
            dslite_records_sent_failure:
                description:
                - "Dslite Flow Records Failed"
                type: str
            session_event_nat44_records_sent:
                description:
                - "Nat44 Session Event Records Sent"
                type: str
            session_event_nat44_records_sent_failure:
                description:
                - "Nat44 Session Event Records Failed"
                type: str
            session_event_nat64_records_sent:
                description:
                - "Nat64 Session Event Records Sent"
                type: str
            session_event_nat64_records_sent_failure:
                description:
                - "Nat64 Session Event Records Falied"
                type: str
            session_event_dslite_records_sent:
                description:
                - "Dslite Session Event Records Sent"
                type: str
            session_event_dslite_records_sent_failure:
                description:
                - "Dslite Session Event Records Failed"
                type: str
            session_event_fw4_records_sent:
                description:
                - "FW4 Session Event Records Sent"
                type: str
            session_event_fw4_records_sent_failure:
                description:
                - "FW4 Session Event Records Failed"
                type: str
            session_event_fw6_records_sent:
                description:
                - "FW6 Session Event Records Sent"
                type: str
            session_event_fw6_records_sent_failure:
                description:
                - "FW6 Session Event Records Failed"
                type: str
            port_mapping_nat44_records_sent:
                description:
                - "Port Mapping Nat44 Event Records Sent"
                type: str
            port_mapping_nat44_records_sent_failure:
                description:
                - "Port Mapping Nat44 Event Records Failed"
                type: str
            port_mapping_nat64_records_sent:
                description:
                - "Port Mapping Nat64 Event Records Sent"
                type: str
            port_mapping_nat64_records_sent_failure:
                description:
                - "Port Mapping Nat64 Event Records Failed"
                type: str
            port_mapping_dslite_records_sent:
                description:
                - "Port Mapping Dslite Event Records Sent"
                type: str
            port_mapping_dslite_records_sent_failure:
                description:
                - "Port Mapping Dslite Event Records failed"
                type: str
            netflow_v5_records_sent:
                description:
                - "Netflow v5 Records Sent"
                type: str
            netflow_v5_records_sent_failure:
                description:
                - "Netflow v5 Records Failed"
                type: str
            netflow_v5_ext_records_sent:
                description:
                - "Netflow v5 Ext Records Sent"
                type: str
            netflow_v5_ext_records_sent_failure:
                description:
                - "Netflow v5 Ext Records Failed"
                type: str
            port_batching_nat44_records_sent:
                description:
                - "Port Batching Nat44 Records Sent"
                type: str
            port_batching_nat44_records_sent_failure:
                description:
                - "Port Batching Nat44 Records Failed"
                type: str
            port_batching_nat64_records_sent:
                description:
                - "Port Batching Nat64 Records Sent"
                type: str
            port_batching_nat64_records_sent_failure:
                description:
                - "Port Batching Nat64 Records Failed"
                type: str
            port_batching_dslite_records_sent:
                description:
                - "Port Batching Dslite Records Sent"
                type: str
            port_batching_dslite_records_sent_failure:
                description:
                - "Port Batching Dslite Records Failed"
                type: str
            port_batching_v2_nat44_records_sent:
                description:
                - "Port Batching V2 Nat44 Records Sent"
                type: str
            port_batching_v2_nat44_records_sent_failure:
                description:
                - "Port Batching V2 Nat44 Records Failed"
                type: str
            port_batching_v2_nat64_records_sent:
                description:
                - "Port Batching V2 Nat64 Records Sent"
                type: str
            port_batching_v2_nat64_records_sent_failure:
                description:
                - "Port Batching V2 Nat64 Records Failed"
                type: str
            port_batching_v2_dslite_records_sent:
                description:
                - "Port Batching V2 Dslite Records Sent"
                type: str
            port_batching_v2_dslite_records_sent_failure:
                description:
                - "Port Batching V2 Dslite Records Falied"
                type: str
            custom_session_event_nat44_creation_records_sent:
                description:
                - "Custom Nat44 Session Creation Records Sent"
                type: str
            custom_session_event_nat44_creation_records_sent_failure:
                description:
                - "Custom Nat44 Session Creation Records Failed"
                type: str
            custom_session_event_nat64_creation_records_sent:
                description:
                - "Custom Nat64 Session Creation Records Sent"
                type: str
            custom_session_event_nat64_creation_records_sent_failure:
                description:
                - "Custom Nat64 Session Creation Records Failed"
                type: str
            custom_session_event_dslite_creation_records_sent:
                description:
                - "Custom Dslite Session Creation Records Sent"
                type: str
            custom_session_event_dslite_creation_records_sent_failure:
                description:
                - "Custom Dslite Session Creation Records Failed"
                type: str
            custom_session_event_nat44_deletion_records_sent:
                description:
                - "Custom Nat44 Session Deletion Records Sent"
                type: str
            custom_session_event_nat44_deletion_records_sent_failure:
                description:
                - "Custom Nat44 Session Deletion Records Failed"
                type: str
            custom_session_event_nat64_deletion_records_sent:
                description:
                - "Custom Nat64 Session Deletion Records Sent"
                type: str
            custom_session_event_nat64_deletion_records_sent_failure:
                description:
                - "Custom Nat64 Session Deletion Records Failed"
                type: str
            custom_session_event_dslite_deletion_records_sent:
                description:
                - "Custom Dslite Session Deletion Records Sent"
                type: str
            custom_session_event_dslite_deletion_records_sent_failure:
                description:
                - "Custom Dslite Session Deletion Records Failed"
                type: str
            custom_session_event_fw4_creation_records_sent:
                description:
                - "Custom FW4 Session Creation Records Sent"
                type: str
            custom_session_event_fw4_creation_records_sent_failure:
                description:
                - "Custom FW4 Session Creation Records Failed"
                type: str
            custom_session_event_fw6_creation_records_sent:
                description:
                - "Custom FW6 Session Creation Records Sent"
                type: str
            custom_session_event_fw6_creation_records_sent_failure:
                description:
                - "Custom FW6 Session Creation Records Failed"
                type: str
            custom_session_event_fw4_deletion_records_sent:
                description:
                - "Custom FW4 Session Deletion Records Sent"
                type: str
            custom_session_event_fw4_deletion_records_sent_failure:
                description:
                - "Custom FW4 Session Deletion Records Failed"
                type: str
            custom_session_event_fw6_deletion_records_sent:
                description:
                - "Custom FW6 Session Deletion Records Sent"
                type: str
            custom_session_event_fw6_deletion_records_sent_failure:
                description:
                - "Custom FW6 Session Deletion Records Failed"
                type: str
            custom_deny_reset_event_fw4_records_sent:
                description:
                - "Custom FW4 Deny/Reset Event Records Sent"
                type: str
            custom_deny_reset_event_fw4_records_sent_failure:
                description:
                - "Custom FW4 Deny/Reset Event Records Failed"
                type: str
            custom_deny_reset_event_fw6_records_sent:
                description:
                - "Custom FW6 Deny/Reset Event Records Sent"
                type: str
            custom_deny_reset_event_fw6_records_sent_failure:
                description:
                - "Custom FW6 Deny/Reset Event Records Failed"
                type: str
            custom_port_mapping_nat44_creation_records_sent:
                description:
                - "Custom Nat44 Port Map Creation Records Sent"
                type: str
            custom_port_mapping_nat44_creation_records_sent_failure:
                description:
                - "Custom Nat44 Port Map Creation Records Failed"
                type: str
            custom_port_mapping_nat64_creation_records_sent:
                description:
                - "Custom Nat64 Port Map Creation Records Sent"
                type: str
            custom_port_mapping_nat64_creation_records_sent_failure:
                description:
                - "Custom Nat64 Port Map Creation Records Failed"
                type: str
            custom_port_mapping_dslite_creation_records_sent:
                description:
                - "Custom Dslite Port Map Creation Records Sent"
                type: str
            custom_port_mapping_dslite_creation_records_sent_failure:
                description:
                - "Custom Dslite Port Map Creation Records Failed"
                type: str
            custom_port_mapping_nat44_deletion_records_sent:
                description:
                - "Custom Nat44 Port Map Deletion Records Sent"
                type: str
            custom_port_mapping_nat44_deletion_records_sent_failure:
                description:
                - "Custom Nat44 Port Map Deletion Records Failed"
                type: str
            custom_port_mapping_nat64_deletion_records_sent:
                description:
                - "Custom Nat64 Port Map Deletion Records Sent"
                type: str
            custom_port_mapping_nat64_deletion_records_sent_failure:
                description:
                - "Custom Nat64 Port Map Deletion Records Failed"
                type: str
            custom_port_mapping_dslite_deletion_records_sent:
                description:
                - "Custom Dslite Port Map Deletion Records Sent"
                type: str
            custom_port_mapping_dslite_deletion_records_sent_failure:
                description:
                - "Custom Dslite Port Map Deletion Records Failed"
                type: str
            custom_port_batching_nat44_creation_records_sent:
                description:
                - "Custom Nat44 Port Batch Creation Records Sent"
                type: str
            custom_port_batching_nat44_creation_records_sent_failure:
                description:
                - "Custom Nat44 Port Batch Creation Records Failed"
                type: str
            custom_port_batching_nat64_creation_records_sent:
                description:
                - "Custom Nat64 Port Batch Creation Records Sent"
                type: str
            custom_port_batching_nat64_creation_records_sent_failure:
                description:
                - "Custom Nat64 Port Batch Creation Records Failed"
                type: str
            custom_port_batching_dslite_creation_records_sent:
                description:
                - "Custom Dslite Port Batch Creation Records Sent"
                type: str
            custom_port_batching_dslite_creation_records_sent_failure:
                description:
                - "Custom Dslite Port Batch Creation Records Failed"
                type: str
            custom_port_batching_nat44_deletion_records_sent:
                description:
                - "Custom Nat44 Port Batch Deletion Records Sent"
                type: str
            custom_port_batching_nat44_deletion_records_sent_failure:
                description:
                - "Custom Nat44 Port Batch Deletion Records Failed"
                type: str
            custom_port_batching_nat64_deletion_records_sent:
                description:
                - "Custom Nat64 Port Batch Deletion Records Sent"
                type: str
            custom_port_batching_nat64_deletion_records_sent_failure:
                description:
                - "Custom Nat64 Port Batch Deletion Records Failed"
                type: str
            custom_port_batching_dslite_deletion_records_sent:
                description:
                - "Custom Dslite Port Batch Deletion Records Sent"
                type: str
            custom_port_batching_dslite_deletion_records_sent_failure:
                description:
                - "Custom Dslite Port Batch Deletion Records Failed"
                type: str
            custom_port_batching_v2_nat44_creation_records_sent:
                description:
                - "Custom Nat44 Port Batch V2 Creation Records Sent"
                type: str
            custom_port_batching_v2_nat44_creation_records_sent_failure:
                description:
                - "Custom Nat44 Port Batch V2 Creation Records Failed"
                type: str
            custom_port_batching_v2_nat64_creation_records_sent:
                description:
                - "Custom Nat64 Port Batch V2 Creation Records Sent"
                type: str
            custom_port_batching_v2_nat64_creation_records_sent_failure:
                description:
                - "Custom Nat64 Port Batch V2 Creation Records Failed"
                type: str
            custom_port_batching_v2_dslite_creation_records_sent:
                description:
                - "Custom Dslite Port Batch V2 Creation Records Sent"
                type: str
            custom_port_batching_v2_dslite_creation_records_sent_failure:
                description:
                - "Custom Dslite Port Batch V2 Creation Records Failed"
                type: str
            custom_port_batching_v2_nat44_deletion_records_sent:
                description:
                - "Custom Nat44 Port Batch V2 Deletion Records Sent"
                type: str
            custom_port_batching_v2_nat44_deletion_records_sent_failure:
                description:
                - "Custom Nat44 Port Batch V2 Deletion Records Failed"
                type: str
            custom_port_batching_v2_nat64_deletion_records_sent:
                description:
                - "Custom Nat64 Port Batch V2 Deletion Records Sent"
                type: str
            custom_port_batching_v2_nat64_deletion_records_sent_failure:
                description:
                - "Custom Nat64 Port Batch V2 Deletion Records Failed"
                type: str
            custom_port_batching_v2_dslite_deletion_records_sent:
                description:
                - "Custom Dslite Port Batch V2 Deletion Records Sent"
                type: str
            custom_port_batching_v2_dslite_deletion_records_sent_failure:
                description:
                - "Custom Dslite Port Batch V2 Deletion Records Failed"
                type: str
            reduced_logs_by_destination:
                description:
                - "Reduced Logs by Destination Protocol and Port"
                type: str
            name:
                description:
                - "Name of netflow monitor"
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

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "custom_record",
    "destination",
    "disable",
    "disable_log_by_destination",
    "flow_timeout",
    "name",
    "protocol",
    "record",
    "resend_template",
    "sample",
    "sampling_enable",
    "source_address",
    "source_ip_use_mgmt",
    "stats",
    "user_tag",
    "uuid",
]


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
            type='str',
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
        'disable': {
            'type': 'bool',
        },
        'source_ip_use_mgmt': {
            'type': 'bool',
        },
        'flow_timeout': {
            'type': 'int',
        },
        'protocol': {
            'type': 'str',
            'choices': ['v9', 'v10']
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
                    'all', 'packets-sent', 'bytes-sent', 'nat44-records-sent',
                    'nat44-records-sent-failure', 'nat64-records-sent',
                    'nat64-records-sent-failure', 'dslite-records-sent',
                    'dslite-records-sent-failure',
                    'session-event-nat44-records-sent',
                    'session-event-nat44-records-sent-failure',
                    'session-event-nat64-records-sent',
                    'session-event-nat64-records-sent-failure',
                    'session-event-dslite-records-sent',
                    'session-event-dslite-records-sent-failure',
                    'session-event-fw4-records-sent',
                    'session-event-fw4-records-sent-failure',
                    'session-event-fw6-records-sent',
                    'session-event-fw6-records-sent-failure',
                    'port-mapping-nat44-records-sent',
                    'port-mapping-nat44-records-sent-failure',
                    'port-mapping-nat64-records-sent',
                    'port-mapping-nat64-records-sent-failure',
                    'port-mapping-dslite-records-sent',
                    'port-mapping-dslite-records-sent-failure',
                    'netflow-v5-records-sent',
                    'netflow-v5-records-sent-failure',
                    'netflow-v5-ext-records-sent',
                    'netflow-v5-ext-records-sent-failure',
                    'port-batching-nat44-records-sent',
                    'port-batching-nat44-records-sent-failure',
                    'port-batching-nat64-records-sent',
                    'port-batching-nat64-records-sent-failure',
                    'port-batching-dslite-records-sent',
                    'port-batching-dslite-records-sent-failure',
                    'port-batching-v2-nat44-records-sent',
                    'port-batching-v2-nat44-records-sent-failure',
                    'port-batching-v2-nat64-records-sent',
                    'port-batching-v2-nat64-records-sent-failure',
                    'port-batching-v2-dslite-records-sent',
                    'port-batching-v2-dslite-records-sent-failure',
                    'custom-session-event-nat44-creation-records-sent',
                    'custom-session-event-nat44-creation-records-sent-failure',
                    'custom-session-event-nat64-creation-records-sent',
                    'custom-session-event-nat64-creation-records-sent-failure',
                    'custom-session-event-dslite-creation-records-sent',
                    'custom-session-event-dslite-creation-records-sent-failure',
                    'custom-session-event-nat44-deletion-records-sent',
                    'custom-session-event-nat44-deletion-records-sent-failure',
                    'custom-session-event-nat64-deletion-records-sent',
                    'custom-session-event-nat64-deletion-records-sent-failure',
                    'custom-session-event-dslite-deletion-records-sent',
                    'custom-session-event-dslite-deletion-records-sent-failure',
                    'custom-session-event-fw4-creation-records-sent',
                    'custom-session-event-fw4-creation-records-sent-failure',
                    'custom-session-event-fw6-creation-records-sent',
                    'custom-session-event-fw6-creation-records-sent-failure',
                    'custom-session-event-fw4-deletion-records-sent',
                    'custom-session-event-fw4-deletion-records-sent-failure',
                    'custom-session-event-fw6-deletion-records-sent',
                    'custom-session-event-fw6-deletion-records-sent-failure',
                    'custom-deny-reset-event-fw4-records-sent',
                    'custom-deny-reset-event-fw4-records-sent-failure',
                    'custom-deny-reset-event-fw6-records-sent',
                    'custom-deny-reset-event-fw6-records-sent-failure',
                    'custom-port-mapping-nat44-creation-records-sent',
                    'custom-port-mapping-nat44-creation-records-sent-failure',
                    'custom-port-mapping-nat64-creation-records-sent',
                    'custom-port-mapping-nat64-creation-records-sent-failure',
                    'custom-port-mapping-dslite-creation-records-sent',
                    'custom-port-mapping-dslite-creation-records-sent-failure',
                    'custom-port-mapping-nat44-deletion-records-sent',
                    'custom-port-mapping-nat44-deletion-records-sent-failure',
                    'custom-port-mapping-nat64-deletion-records-sent',
                    'custom-port-mapping-nat64-deletion-records-sent-failure',
                    'custom-port-mapping-dslite-deletion-records-sent',
                    'custom-port-mapping-dslite-deletion-records-sent-failure',
                    'custom-port-batching-nat44-creation-records-sent',
                    'custom-port-batching-nat44-creation-records-sent-failure',
                    'custom-port-batching-nat64-creation-records-sent',
                    'custom-port-batching-nat64-creation-records-sent-failure',
                    'custom-port-batching-dslite-creation-records-sent',
                    'custom-port-batching-dslite-creation-records-sent-failure',
                    'custom-port-batching-nat44-deletion-records-sent',
                    'custom-port-batching-nat44-deletion-records-sent-failure',
                    'custom-port-batching-nat64-deletion-records-sent',
                    'custom-port-batching-nat64-deletion-records-sent-failure',
                    'custom-port-batching-dslite-deletion-records-sent',
                    'custom-port-batching-dslite-deletion-records-sent-failure',
                    'custom-port-batching-v2-nat44-creation-records-sent'
                ]
            },
            'counters2': {
                'type':
                'str',
                'choices': [
                    'custom-port-batching-v2-nat44-creation-records-sent-failure',
                    'custom-port-batching-v2-nat64-creation-records-sent',
                    'custom-port-batching-v2-nat64-creation-records-sent-failure',
                    'custom-port-batching-v2-dslite-creation-records-sent',
                    'custom-port-batching-v2-dslite-creation-records-sent-failure',
                    'custom-port-batching-v2-nat44-deletion-records-sent',
                    'custom-port-batching-v2-nat44-deletion-records-sent-failure',
                    'custom-port-batching-v2-nat64-deletion-records-sent',
                    'custom-port-batching-v2-nat64-deletion-records-sent-failure',
                    'custom-port-batching-v2-dslite-deletion-records-sent',
                    'custom-port-batching-v2-dslite-deletion-records-sent-failure',
                    'reduced-logs-by-destination'
                ]
            }
        },
        'disable_log_by_destination': {
            'type': 'dict',
            'tcp_list': {
                'type': 'list',
                'tcp_port_start': {
                    'type': 'int',
                },
                'tcp_port_end': {
                    'type': 'int',
                }
            },
            'udp_list': {
                'type': 'list',
                'udp_port_start': {
                    'type': 'int',
                },
                'udp_port_end': {
                    'type': 'int',
                }
            },
            'icmp': {
                'type': 'bool',
            },
            'others': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            },
            'ip_list': {
                'type': 'list',
                'ipv4_addr': {
                    'type': 'str',
                    'required': True,
                },
                'tcp_list': {
                    'type': 'list',
                    'tcp_port_start': {
                        'type': 'int',
                    },
                    'tcp_port_end': {
                        'type': 'int',
                    }
                },
                'udp_list': {
                    'type': 'list',
                    'udp_port_start': {
                        'type': 'int',
                    },
                    'udp_port_end': {
                        'type': 'int',
                    }
                },
                'icmp': {
                    'type': 'bool',
                },
                'others': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                },
                'user_tag': {
                    'type': 'str',
                }
            },
            'ip6_list': {
                'type': 'list',
                'ipv6_addr': {
                    'type': 'str',
                    'required': True,
                },
                'tcp_list': {
                    'type': 'list',
                    'tcp_port_start': {
                        'type': 'int',
                    },
                    'tcp_port_end': {
                        'type': 'int',
                    }
                },
                'udp_list': {
                    'type': 'list',
                    'udp_port_start': {
                        'type': 'int',
                    },
                    'udp_port_end': {
                        'type': 'int',
                    }
                },
                'icmp': {
                    'type': 'bool',
                },
                'others': {
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
        'record': {
            'type': 'dict',
            'netflow_v5': {
                'type': 'bool',
            },
            'netflow_v5_ext': {
                'type': 'bool',
            },
            'nat44': {
                'type': 'bool',
            },
            'nat64': {
                'type': 'bool',
            },
            'dslite': {
                'type': 'bool',
            },
            'sesn_event_nat44': {
                'type': 'str',
                'choices': ['both', 'creation', 'deletion']
            },
            'sesn_event_nat64': {
                'type': 'str',
                'choices': ['both', 'creation', 'deletion']
            },
            'sesn_event_dslite': {
                'type': 'str',
                'choices': ['both', 'creation', 'deletion']
            },
            'sesn_event_fw4': {
                'type': 'str',
                'choices': ['both', 'creation', 'deletion']
            },
            'sesn_event_fw6': {
                'type': 'str',
                'choices': ['both', 'creation', 'deletion']
            },
            'port_mapping_nat44': {
                'type': 'str',
                'choices': ['both', 'creation', 'deletion']
            },
            'port_mapping_nat64': {
                'type': 'str',
                'choices': ['both', 'creation', 'deletion']
            },
            'port_mapping_dslite': {
                'type': 'str',
                'choices': ['both', 'creation', 'deletion']
            },
            'port_batch_nat44': {
                'type': 'str',
                'choices': ['both', 'creation', 'deletion']
            },
            'port_batch_nat64': {
                'type': 'str',
                'choices': ['both', 'creation', 'deletion']
            },
            'port_batch_dslite': {
                'type': 'str',
                'choices': ['both', 'creation', 'deletion']
            },
            'port_batch_v2_nat44': {
                'type': 'str',
                'choices': ['both', 'creation', 'deletion']
            },
            'port_batch_v2_nat64': {
                'type': 'str',
                'choices': ['both', 'creation', 'deletion']
            },
            'port_batch_v2_dslite': {
                'type': 'str',
                'choices': ['both', 'creation', 'deletion']
            },
            'uuid': {
                'type': 'str',
            }
        },
        'custom_record': {
            'type': 'dict',
            'custom_cfg': {
                'type': 'list',
                'event': {
                    'type':
                    'str',
                    'choices': [
                        'sesn-event-nat44-creation',
                        'sesn-event-nat44-deletion',
                        'sesn-event-nat64-creation',
                        'sesn-event-nat64-deletion',
                        'sesn-event-dslite-creation',
                        'sesn-event-dslite-deletion',
                        'sesn-event-fw4-creation', 'sesn-event-fw4-deletion',
                        'sesn-event-fw6-creation', 'sesn-event-fw6-deletion',
                        'deny-reset-event-fw4', 'deny-reset-event-fw6',
                        'port-mapping-nat44-creation',
                        'port-mapping-nat44-deletion',
                        'port-mapping-nat64-creation',
                        'port-mapping-nat64-deletion',
                        'port-mapping-dslite-creation',
                        'port-mapping-dslite-deletion',
                        'port-batch-nat44-creation',
                        'port-batch-nat44-deletion',
                        'port-batch-nat64-creation',
                        'port-batch-nat64-deletion',
                        'port-batch-dslite-creation',
                        'port-batch-dslite-deletion',
                        'port-batch-v2-nat44-creation',
                        'port-batch-v2-nat44-deletion',
                        'port-batch-v2-nat64-creation',
                        'port-batch-v2-nat64-deletion',
                        'port-batch-v2-dslite-creation',
                        'port-batch-v2-dslite-deletion'
                    ]
                },
                'ipfix_template': {
                    'type': 'str',
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'destination': {
            'type': 'dict',
            'service_group': {
                'type': 'str',
            },
            'ip_cfg': {
                'type': 'dict',
                'ip': {
                    'type': 'str',
                },
                'port4': {
                    'type': 'int',
                }
            },
            'ipv6_cfg': {
                'type': 'dict',
                'ipv6': {
                    'type': 'str',
                },
                'port6': {
                    'type': 'int',
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'source_address': {
            'type': 'dict',
            'ip': {
                'type': 'str',
            },
            'ipv6': {
                'type': 'str',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'resend_template': {
            'type': 'dict',
            'timeout': {
                'type': 'int',
            },
            'records': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'sample': {
            'type': 'dict',
            'ethernet_list': {
                'type': 'list',
                'ifindex': {
                    'type': 'str',
                    'required': True,
                },
                'uuid': {
                    'type': 'str',
                }
            },
            've_list': {
                'type': 'list',
                've_num': {
                    'type': 'int',
                    'required': True,
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'nat_pool_list': {
                'type': 'list',
                'pool_name': {
                    'type': 'str',
                    'required': True,
                },
                'uuid': {
                    'type': 'str',
                }
            }
        },
        'stats': {
            'type': 'dict',
            'packets_sent': {
                'type': 'str',
            },
            'bytes_sent': {
                'type': 'str',
            },
            'nat44_records_sent': {
                'type': 'str',
            },
            'nat44_records_sent_failure': {
                'type': 'str',
            },
            'nat64_records_sent': {
                'type': 'str',
            },
            'nat64_records_sent_failure': {
                'type': 'str',
            },
            'dslite_records_sent': {
                'type': 'str',
            },
            'dslite_records_sent_failure': {
                'type': 'str',
            },
            'session_event_nat44_records_sent': {
                'type': 'str',
            },
            'session_event_nat44_records_sent_failure': {
                'type': 'str',
            },
            'session_event_nat64_records_sent': {
                'type': 'str',
            },
            'session_event_nat64_records_sent_failure': {
                'type': 'str',
            },
            'session_event_dslite_records_sent': {
                'type': 'str',
            },
            'session_event_dslite_records_sent_failure': {
                'type': 'str',
            },
            'session_event_fw4_records_sent': {
                'type': 'str',
            },
            'session_event_fw4_records_sent_failure': {
                'type': 'str',
            },
            'session_event_fw6_records_sent': {
                'type': 'str',
            },
            'session_event_fw6_records_sent_failure': {
                'type': 'str',
            },
            'port_mapping_nat44_records_sent': {
                'type': 'str',
            },
            'port_mapping_nat44_records_sent_failure': {
                'type': 'str',
            },
            'port_mapping_nat64_records_sent': {
                'type': 'str',
            },
            'port_mapping_nat64_records_sent_failure': {
                'type': 'str',
            },
            'port_mapping_dslite_records_sent': {
                'type': 'str',
            },
            'port_mapping_dslite_records_sent_failure': {
                'type': 'str',
            },
            'netflow_v5_records_sent': {
                'type': 'str',
            },
            'netflow_v5_records_sent_failure': {
                'type': 'str',
            },
            'netflow_v5_ext_records_sent': {
                'type': 'str',
            },
            'netflow_v5_ext_records_sent_failure': {
                'type': 'str',
            },
            'port_batching_nat44_records_sent': {
                'type': 'str',
            },
            'port_batching_nat44_records_sent_failure': {
                'type': 'str',
            },
            'port_batching_nat64_records_sent': {
                'type': 'str',
            },
            'port_batching_nat64_records_sent_failure': {
                'type': 'str',
            },
            'port_batching_dslite_records_sent': {
                'type': 'str',
            },
            'port_batching_dslite_records_sent_failure': {
                'type': 'str',
            },
            'port_batching_v2_nat44_records_sent': {
                'type': 'str',
            },
            'port_batching_v2_nat44_records_sent_failure': {
                'type': 'str',
            },
            'port_batching_v2_nat64_records_sent': {
                'type': 'str',
            },
            'port_batching_v2_nat64_records_sent_failure': {
                'type': 'str',
            },
            'port_batching_v2_dslite_records_sent': {
                'type': 'str',
            },
            'port_batching_v2_dslite_records_sent_failure': {
                'type': 'str',
            },
            'custom_session_event_nat44_creation_records_sent': {
                'type': 'str',
            },
            'custom_session_event_nat44_creation_records_sent_failure': {
                'type': 'str',
            },
            'custom_session_event_nat64_creation_records_sent': {
                'type': 'str',
            },
            'custom_session_event_nat64_creation_records_sent_failure': {
                'type': 'str',
            },
            'custom_session_event_dslite_creation_records_sent': {
                'type': 'str',
            },
            'custom_session_event_dslite_creation_records_sent_failure': {
                'type': 'str',
            },
            'custom_session_event_nat44_deletion_records_sent': {
                'type': 'str',
            },
            'custom_session_event_nat44_deletion_records_sent_failure': {
                'type': 'str',
            },
            'custom_session_event_nat64_deletion_records_sent': {
                'type': 'str',
            },
            'custom_session_event_nat64_deletion_records_sent_failure': {
                'type': 'str',
            },
            'custom_session_event_dslite_deletion_records_sent': {
                'type': 'str',
            },
            'custom_session_event_dslite_deletion_records_sent_failure': {
                'type': 'str',
            },
            'custom_session_event_fw4_creation_records_sent': {
                'type': 'str',
            },
            'custom_session_event_fw4_creation_records_sent_failure': {
                'type': 'str',
            },
            'custom_session_event_fw6_creation_records_sent': {
                'type': 'str',
            },
            'custom_session_event_fw6_creation_records_sent_failure': {
                'type': 'str',
            },
            'custom_session_event_fw4_deletion_records_sent': {
                'type': 'str',
            },
            'custom_session_event_fw4_deletion_records_sent_failure': {
                'type': 'str',
            },
            'custom_session_event_fw6_deletion_records_sent': {
                'type': 'str',
            },
            'custom_session_event_fw6_deletion_records_sent_failure': {
                'type': 'str',
            },
            'custom_deny_reset_event_fw4_records_sent': {
                'type': 'str',
            },
            'custom_deny_reset_event_fw4_records_sent_failure': {
                'type': 'str',
            },
            'custom_deny_reset_event_fw6_records_sent': {
                'type': 'str',
            },
            'custom_deny_reset_event_fw6_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_mapping_nat44_creation_records_sent': {
                'type': 'str',
            },
            'custom_port_mapping_nat44_creation_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_mapping_nat64_creation_records_sent': {
                'type': 'str',
            },
            'custom_port_mapping_nat64_creation_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_mapping_dslite_creation_records_sent': {
                'type': 'str',
            },
            'custom_port_mapping_dslite_creation_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_mapping_nat44_deletion_records_sent': {
                'type': 'str',
            },
            'custom_port_mapping_nat44_deletion_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_mapping_nat64_deletion_records_sent': {
                'type': 'str',
            },
            'custom_port_mapping_nat64_deletion_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_mapping_dslite_deletion_records_sent': {
                'type': 'str',
            },
            'custom_port_mapping_dslite_deletion_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_batching_nat44_creation_records_sent': {
                'type': 'str',
            },
            'custom_port_batching_nat44_creation_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_batching_nat64_creation_records_sent': {
                'type': 'str',
            },
            'custom_port_batching_nat64_creation_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_batching_dslite_creation_records_sent': {
                'type': 'str',
            },
            'custom_port_batching_dslite_creation_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_batching_nat44_deletion_records_sent': {
                'type': 'str',
            },
            'custom_port_batching_nat44_deletion_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_batching_nat64_deletion_records_sent': {
                'type': 'str',
            },
            'custom_port_batching_nat64_deletion_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_batching_dslite_deletion_records_sent': {
                'type': 'str',
            },
            'custom_port_batching_dslite_deletion_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_batching_v2_nat44_creation_records_sent': {
                'type': 'str',
            },
            'custom_port_batching_v2_nat44_creation_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_batching_v2_nat64_creation_records_sent': {
                'type': 'str',
            },
            'custom_port_batching_v2_nat64_creation_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_batching_v2_dslite_creation_records_sent': {
                'type': 'str',
            },
            'custom_port_batching_v2_dslite_creation_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_batching_v2_nat44_deletion_records_sent': {
                'type': 'str',
            },
            'custom_port_batching_v2_nat44_deletion_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_batching_v2_nat64_deletion_records_sent': {
                'type': 'str',
            },
            'custom_port_batching_v2_nat64_deletion_records_sent_failure': {
                'type': 'str',
            },
            'custom_port_batching_v2_dslite_deletion_records_sent': {
                'type': 'str',
            },
            'custom_port_batching_v2_dslite_deletion_records_sent_failure': {
                'type': 'str',
            },
            'reduced_logs_by_destination': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            }
        }
    })
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


def _get(module, url, params={}):

    resp = None
    try:
        resp = module.client.get(url, params=params)
    except a10_ex.NotFound:
        resp = "Not Found"

    call_result = {
        "endpoint": url,
        "http_method": "GET",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _post(module, url, params={}, file_content=None, file_name=None):
    resp = module.client.post(url, params=params)
    resp = resp if resp else {}
    call_result = {
        "endpoint": url,
        "http_method": "POST",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _delete(module, url):
    call_result = {
        "endpoint": url,
        "http_method": "DELETE",
        "request_body": {},
        "response_body": module.client.delete(url),
    }
    return call_result


def _switch_device_context(module, device_id):
    call_result = {
        "endpoint": "/axapi/v3/device-context",
        "http_method": "POST",
        "request_body": {
            "device-id": device_id
        },
        "response_body": module.client.change_context(device_id)
    }
    return call_result


def _active_partition(module, a10_partition):
    call_result = {
        "endpoint": "/axapi/v3/active-partition",
        "http_method": "POST",
        "request_body": {
            "curr_part_name": a10_partition
        },
        "response_body": module.client.activate_partition(a10_partition)
    }
    return call_result


def get(module):
    return _get(module, existing_url(module))


def get_list(module):
    return _get(module, list_url(module))


def get_stats(module):
    query_params = {}
    if module.params.get("stats"):
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, stats_url(module), params=query_params)


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
    url_base = "/axapi/v3/netflow/monitor/{name}"

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
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["monitor"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["monitor"].get(k) != v:
            change_results["changed"] = True
            config_changes["monitor"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload):
    try:
        call_result = _post(module, new_url(module), payload)
        result["axapi_calls"].append(call_result)
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        module.client.session.close()
    return result


def update(module, result, existing_config, payload):
    try:
        call_result = _post(module, existing_url(module), payload)
        result["axapi_calls"].append(call_result)
        if call_result["response_body"] == existing_config:
            result["changed"] = False
        else:
            result["modified_values"].update(**call_result["response_body"])
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        module.client.session.close()
    return result


def present(module, result, existing_config):
    payload = build_json("monitor", module)
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
        call_result = _delete(module, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        module.client.session.close()
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

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
    finally:
        module.client.session.close()
    return result


def run_command(module):
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[])

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

    run_errors = []
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
        result["axapi_calls"].append(_active_partition(module, a10_partition))

    if a10_device_context_id:
        result["axapi_calls"].append(
            _switch_device_context(module, a10_device_context_id))

    existing_config = get(module)
    result["axapi_calls"].append(existing_config)
    if existing_config['response_body'] != 'Not Found':
        existing_config = existing_config["response_body"]
    else:
        existing_config = None

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["axapi_calls"].append(get(module))
        elif module.params.get("get_type") == "list":
            result["axapi_calls"].append(get_list(module))
        elif module.params.get("get_type") == "stats":
            result["axapi_calls"].append(get_stats(module))

    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
