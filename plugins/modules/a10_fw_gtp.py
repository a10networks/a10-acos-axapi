#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_fw_gtp
description:
    - Configure GTP
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
    gtp_value:
        description:
        - "'enable'= Enable GTP Inspection;"
        type: str
        required: False
    network_element_list_v4:
        description:
        - "Class List (Class List Name)"
        type: str
        required: False
    ne_v4_log_periodicity:
        description:
        - "Periodic Logging Frequency(In Minutes)"
        type: int
        required: False
    network_element_list_v6:
        description:
        - "Class List (Class List Name)"
        type: str
        required: False
    ne_v6_log_periodicity:
        description:
        - "Periodic Logging Frequency(In Minutes)"
        type: int
        required: False
    apn_prefix_list:
        description:
        - "Class List (Class List Name)"
        type: str
        required: False
    apn_log_periodicity:
        description:
        - "Periodic Logging Frequency(In Minutes)"
        type: int
        required: False
    echo_timeout:
        description:
        - "echo message timeout (minutes) (echo-timeout (default 120))"
        type: int
        required: False
    path_mgmt_logging:
        description:
        - "'enable-log'= Enable Log for Path Management;"
        type: str
        required: False
    insertion_mode:
        description:
        - "'monitor'= Enable inline view-only mode; 'skip-state-checks'= Enable skip
          stateful checks mode;"
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
                - "'all'= all; 'out-of-session-memory'= Out of Tunnel Memory; 'no-fwd-route'= No
          Forward Route; 'no-rev-route'= No Reverse Route; 'gtp-smp-created'= GTP SMP
          Created; 'gtp-smp-marked-deleted'= GTP SMP Marked Deleted; 'gtp-smp-deleted'=
          GTP SMP Deleted; 'smp-creation-failed'= GTP-U SMP Helper Session Creation
          Failed; 'gtp-smp-path-created'= GTP SMP PATH Created; 'gtp-smp-path-freed'= GTP
          SMP PATH MEM freed; 'gtp-smp-path-allocated'= GTP SMP PATH MEM allocated; 'gtp-
          smp-path-creation-failed'= GTP SMP PATH creation Failed; 'gtp-smp-path-check-
          failed'= GTP SMP PATH check Failed; 'gtp-smp-check-failed'= GTP SMP check
          Failed; 'gtp-smp-session-count-check-failed'= GTP-U session count is not in
          range of 0-11 in GTP-C SMP; 'gtp-c-ref-count-smp-exceeded'= GTP-C session count
          on C-smp exceeded 2; 'gtp-u-smp-in-rml-with-sess'= GTP-U smp is marked RML with
          U-session; 'gtp-u-pkt-fwd-conn-create'= GTP-U pkt fwded while creating conn
          with gtp toggling; 'gtp-c-pkt-fwd-conn-create'= GTP-C pkt fwded while creating
          conn with gtp toggling; 'gtp-echo-pkt-fwd-conn-create'= GTP-ECHO pkt fwded
          while creating conn with gtp toggling; 'gtp-tunnel-rate-limit-entry-create-
          success'= GTP Tunnel Level Rate Limit Entry Create Success; 'gtp-tunnel-rate-
          limit-entry-create-failure'= GTP Tunnel Level Rate Limit Entry Create Failure;
          'gtp-tunnel-rate-limit-entry-deleted'= GTP Tunnel Level Rate Limit Entry
          Deleted; 'gtp-rate-limit-smp-created'= GTP Rate Limit SMP Created; 'gtp-rate-
          limit-smp-freed'= GTP Rate Limit SMP Freed; 'gtp-rate-limit-smp-create-
          failure'= GTP Rate Limit SMP Create Failure; 'gtp-rate-limit-t3-ctr-create-
          failure'= GTP Rate Limit Dynamic Counters Create Failure; 'gtp-rate-limit-
          entry-create-failure'= GTP Rate Limit Entry Create Failure; 'gtp-echo-conn-
          created'= GTP Echo Request Conn Created; 'gtp-echo-conn-deleted'= GTP Echo
          Request conn Deleted; 'gtp-node-restart-echo'= GTP Node Restoration due to
          Recovery IE in Echo; 'gtp-c-echo-path-failure'= GTP-C Path Failure due to Echo;
          'drop-vld-gtp-echo-out-of-state-'= GTP Echo Out of State Drop; 'drop-vld-gtp-
          echo-ie-len-exceed-msg-len'= GTP Echo IE Length Exceeds Message Length; 'gtp-
          create-session-request-retransmit'= GTP-C Retransmitted Create Session Request;
          'gtp-add-bearer-request-retransmit'= GTP-C Retransmitted Add Bearer Request;
          'gtp-delete-session-request-retransmit'= GTP-C Retransmitted Delete Session
          Request; 'gtp-handover-request-retransmit'= GTP Handover Request Retransmit;
          'gtp-del-bearer-request-retransmit'= GTP-C Retransmitted Delete Bearer Request;
          'gtp-add-bearer-response-retransmit'= GTP-C Retransmitted Add Bearer Response;
          'gtp-create-session-request-retx-drop'= GTP-C Retransmitted Create Session
          Request dropped; 'gtp-u-out-of-state-drop'= GTP-U Out of state Drop; 'gtp-c-
          handover-request-out-of-state-drop'= GTP-C Handover Request Out of state Drop;
          'gtp-v1-c-nsapi-not-found-in-delete-req'= GTPv1-C NSAPI Not Found in GTP
          Request; 'gtp-v2-c-bearer-not-found-in-delete-req'= GTPv2-C Bearer Not Found in
          GTP Request; 'gtp-v2-c-bearer-not-found-in-delete-resp'= GTPv2-C Bearer Not
          Found in GTP Response; 'gtp-multiple-handover-request'= GTP Multiple Handover
          Request; 'gtp-rr-message-drop'= GTP Message Dropped in RR Mode; 'gtp-rr-echo-
          message-dcmsg'= GTP Echo Message Sent to home CPU in RR Mode; 'gtp-rr-c-
          message-dcmsg'= GTP-C Message Sent to home CPU in RR Mode; 'drop-gtp-frag-or-
          jumbo-pkt'= GTP Fragmented or JUMBO packet Drop; 'response-with-reject-cause-
          forwarded'= GTP-C Response with Reject Cause Forwarded; 'gtp-c-message-
          forwarded-without-conn'= GTP-C Message Forwarded without Conn; 'gtp-v0-c-ver-
          not-supp'= GTPv0-C Version not supported indication; 'gtp-v1-c-ver-not-supp'=
          GTPv1-C Version not supported indication; 'gtp-v2-c-ver-not-supp'= GTPv2-C
          Version not supported indication; 'gtp-v1-extn-hdt-notif'= GTPV1 Supported
          Extension header notification; 'gtp-u-error-ind'= GTP-U Error Indication; 'gtp-
          c-handover-in-progress-with-conn'= GTP-C mesg matching conn with HO In
          Progress; 'gtp-ho-in-progress-handover-request'= GTP-C ho mesg matching conn
          with HO In Progress; 'gtp-correct-conn-ho-in-progress-handover-request'= GTP-C
          ho mesg matching correct conn(reuse teid) with HO In Progress; 'gtp-wrong-conn-
          ho-in-progress-handover-request'= GTP-C ho mesg matching wrong conn(new teid)
          with HO In Progress; 'gtp-ho-in-progress-handover-response'= GTP-C ho response
          matching a conn with HO In Progress; 'gtp-ho-in-progress-c-mesg'= GTP-C other
          than ho mesg matching conn with HO In Progress; 'gtp-unset-ho-flag-reuse-teid'=
          GTP-C SGW reuse teid with ho and unset ho flag; 'gtp-refresh-c-conn-reuse-
          teid'= GTP-C SGW reuse teid with ho and refresh old conn; 'gtp-rematch-smp-
          matching-conn'= GTP-C rematch smp with packet matching conn; 'gtp-wrong-conn-
          handover-request'= GTP-C ho mesg matching wrong conn(new teid) with no HO flag;
          'gtp-refresh-conn-set-ho-flag-latest'= GTP-C SGW refresh old conn and set ho
          flag on latest smp; 'gtp-c-process-pkt-drop'= GTP-C process pkt drop; 'gtp-c-
          fwd-pkt-drop'= GTP-C fwd pkt drop; 'gtp-c-rev-pkt-drop'= GTP-C rev pkt drop;
          'gtp-c-fwd-v1-other'= GTP-C fwd v1 other messages; 'gtp-c-fwd-v2-other'= GTP-C
          fwd v2 other messages; 'gtp-c-rev-v1-other'= GTP-C rev v1 other messages; 'gtp-
          c-rev-v2-other'= GTP-C rev v2 other messages; 'gtp-c-going-thru-fw-lookup'=
          GTP-C mesg going thru fw lookup can be resp or l5 mesg not matching smp; 'gtp-
          c-conn-create-pkt-drop'= GTP-C conn creation drop; 'gtp-c-pkt-fwd-conn-create-
          no-fteid'= GTP-C pkt fwded while creating conn when no FTEID; 'gtp-v0-c-uplink-
          ingress-packets'= GTPv0-C Uplink Ingress Packets; 'gtp-v0-c-uplink-egress-
          packets'= GTPv0-C Uplink Egress Packets; 'gtp-v0-c-downlink-ingress-packets'=
          GTPv0-C Downlink Ingress Packets; 'gtp-v0-c-downlink-egress-packets'= GTPv0-C
          Downlink Egress Packets; 'gtp-v0-c-uplink-ingress-bytes'= GTPv0-C Uplink
          Ingress Bytes; 'gtp-v0-c-uplink-egress-bytes'= GTPv0-C Uplink Egress Bytes;
          'gtp-v0-c-downlink-ingress-bytes'= GTPv0-C Downlink Ingress Bytes;
          'gtp-v0-c-downlink-egress-bytes'= GTPv0-C Downlink Egress Bytes;
          'gtp-v1-c-uplink-ingress-packets'= GTPv1-C Uplink Ingress Packets;
          'gtp-v1-c-uplink-egress-packets'= GTPv1-C Uplink Egress Packets;
          'gtp-v1-c-downlink-ingress-packets'= GTPv1-C Downlink Ingress Packets;
          'gtp-v1-c-downlink-egress-packets'= GTPv1-C Downlink Egress Packets;
          'gtp-v1-c-uplink-ingress-bytes'= GTPv1-C Uplink Ingress Bytes;
          'gtp-v1-c-uplink-egress-bytes'= GTPv1-C Uplink Egress Bytes;
          'gtp-v1-c-downlink-ingress-bytes'= GTPv1-C Downlink Ingress Bytes;
          'gtp-v1-c-downlink-egress-bytes'= GTPv1-C Downlink Egress Bytes;
          'gtp-v2-c-uplink-ingress-packets'= GTPv2-C Uplink Ingress Packets;
          'gtp-v2-c-uplink-egress-packets'= GTPv2-C Uplink Egress Packets;
          'gtp-v2-c-downlink-ingress-packets'= GTPv2-C Downlink Ingress Packets;
          'gtp-v2-c-downlink-egress-packets'= GTPv2-C Downlink Egress Packets;
          'gtp-v2-c-uplink-ingress-bytes'= GTPv2-C Uplink Ingress Bytes;
          'gtp-v2-c-uplink-egress-bytes'= GTPv2-C Uplink Egress Bytes;
          'gtp-v2-c-downlink-ingress-bytes'= GTPv2-C Downlink Ingress Bytes;
          'gtp-v2-c-downlink-egress-bytes'= GTPv2-C Downlink Egress Bytes; 'gtp-u-uplink-
          ingress-packets'= GTP-U Uplink Ingress Packets; 'gtp-u-uplink-egress-packets'=
          GTP-U Uplink Egress Packets; 'gtp-u-downlink-ingress-packets'= GTP-U Downlink
          Ingress Packets; 'gtp-u-downlink-egress-packets'= GTP-U Downlink Egress
          Packets; 'gtp-u-uplink-ingress-bytes'= GTP-U Uplink Ingress Bytes; 'gtp-u-
          uplink-egress-bytes'= GTP-U Uplink Egress Bytes; 'gtp-u-downlink-ingress-
          bytes'= GTP-U Downlink Ingress Bytes; 'gtp-u-downlink-egress-bytes'= GTP-U
          Downlink Egress Bytes; 'gtp-v0-c-create-synced'= GTPv0-C Tunnel Create Synced;"
                type: str
            counters2:
                description:
                - "'gtp-v1-c-create-synced'= GTPv1-C Tunnel Create Synced; 'gtp-v2-c-create-
          synced'= GTPv2-C Tunnel Create Synced; 'gtp-v0-c-delete-synced'= GTPv0-C Tunnel
          Delete Synced; 'gtp-v1-c-delete-synced'= GTPv1-C Tunnel Delete Synced;
          'gtp-v2-c-delete-synced'= GTPv2-C Tunnel Delete Synced; 'gtp-v0-c-create-sync-
          rx'= GTPv0-C Tunnel Create Sync Received on Standby; 'gtp-v1-c-create-sync-rx'=
          GTPv1-C Tunnel Create Sync Received on Standby; 'gtp-v2-c-create-sync-rx'=
          GTPv2-C Tunnel Create Sync Received on Standby; 'gtp-v0-c-delete-sync-rx'=
          GTPv0-C Tunnel Delete Sync Received on Standby; 'gtp-v1-c-delete-sync-rx'=
          GTPv1-C Tunnel Delete Sync Received on Standby; 'gtp-v2-c-delete-sync-rx'=
          GTPv2-C Tunnel Delete Sync Received on Standby; 'gtp-handover-synced'= GTP
          Handover Synced; 'gtp-handover-sync-rx'= GTP Handover Sync Received on Standby;
          'gtp-smp-add-bearer-synced'= GTP SMP Add Bearer Synced; 'gtp-smp-del-bearer-
          synced'= GTP SMP Del Bearer Synced; 'gtp-smp-additional-bearer-synced'= GTP SMP
          Additional Bearer Synced; 'gtp-smp-add-bearer-sync-rx'= GTP SMP Add Bearer Sync
          Received on Standby; 'gtp-smp-del-bearer-sync-rx'= GTP SMP Del Bearer Sync
          Received on Standby; 'gtp-smp-additional-bearer-sync-rx'= GTP SMP Additional
          Bearer Sync Received on Standby; 'gtp-add-bearer-sync-not-rx-on-standby'= GTP
          Add Bearer Sync Not Received on Standby; 'gtp-add-bearer-sync-with-periodic-
          update-on-standby'= GTP Bearer Added on Standby with Periodic Sync; 'gtp-
          delete-bearer-sync-with-periodic-update-on-standby'= GTP Bearer Deleted on
          Standy with Periodic Sync; 'gtp-v0-c-echo-create-synced'= GTPv0-C Echo Create
          Synced; 'gtp-v1-c-echo-create-synced'= GTPv1-C Echo Create Synced;
          'gtp-v2-c-echo-create-synced'= GTPv2-C Echo Create Synced; 'gtp-v0-c-echo-
          create-sync-rx'= GTPv0-C-Echo Create Sync Received on Standby; 'gtp-v1-c-echo-
          create-sync-rx'= GTPv1-C-Echo Create Sync Received on Standby; 'gtp-v2-c-echo-
          create-sync-rx'= GTPv2-C-Echo Create Sync Received on Standby; 'gtp-v0-c-echo-
          del-synced'= GTPv0-C Echo Delete Synced; 'gtp-v1-c-echo-del-synced'= GTPv1-C
          Echo Delete Synced; 'gtp-v2-c-echo-del-synced'= GTPv2-C Echo Delete Synced;
          'gtp-v0-c-echo-del-sync-rx'= GTPv0-C-Echo Delete Sync Received on Standby;
          'gtp-v1-c-echo-del-sync-rx'= GTPv1-C-Echo Delete Sync Received on Standby;
          'gtp-v2-c-echo-del-sync-rx'= GTPv2-C-Echo Delete Sync Received on Standby;
          'drop-gtp-conn-creation-standby'= GTP Conn creation on Standby Drop; 'gtp-u-
          synced-before-control'= GTP-U Tunnel synced before corresponding GTP-C; 'gtp-
          c-l5-synced-before-l3'= GTP-C L5 conn synced before corresponding L3 GTP-C
          conn; 'gtp-smp-path-del-synced'= GTP SMP path delete Synced; 'gtp-smp-path-del-
          sync-rx'= GTP SMP path delete Sync Received on Standby; 'gtp-not-enabled-on-
          standby'= GTP Not Enabled on Standby; 'gtp-ip-version-v4-v6'= GTP IP versions
          of V4&V6 in FTEID; 'drop-gtp-ip-version-mismatch-fteid'= GTP IP version
          mismatch for req & response FTEIDs; 'drop-gtp-ip-version-mismatch-ho-fteid'=
          GTP IP version mismatch in Handover SGW FTEID; 'gtp-u-message-length-mismatch'=
          GTP-U Message Length Mismatch Across Layers; 'gtp-path-message-length-
          mismatch'= GTP-Path Message Length Mismatch Across Layers; 'drop-gtp-missing-
          cond-ie-bearer-ctx'= Missing conditional IE in bearer context Drop; 'drop-gtp-
          bearer-not-found-in-resp'= GTP Bearer not found in response; 'gtp-stateless-
          forward'= GTP Stateless Forward; 'gtp-l3-conn-deleted'= GTP L3 conn deleted;
          'gtp-l5-conn-created'= GTP L5 conn created; 'gtp-monitor-forward'= GTP messages
          forwarded via monitor mode; 'gtp-u_inner-ip-not-present'= GTP-U inner IP not
          present; 'gtp-ext_hdr-incorrect-length'= GTP Extension header incorrect length;"
                type: str
    apn_prefix:
        description:
        - "Field apn_prefix"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    network_element:
        description:
        - "Field network_element"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            out_of_session_memory:
                description:
                - "Out of Tunnel Memory"
                type: str
            no_fwd_route:
                description:
                - "No Forward Route"
                type: str
            no_rev_route:
                description:
                - "No Reverse Route"
                type: str
            gtp_smp_path_check_failed:
                description:
                - "GTP SMP PATH check Failed"
                type: str
            gtp_smp_check_failed:
                description:
                - "GTP SMP check Failed"
                type: str
            gtp_smp_session_count_check_failed:
                description:
                - "GTP-U session count is not in range of 0-11 in GTP-C SMP"
                type: str
            gtp_c_ref_count_smp_exceeded:
                description:
                - "GTP-C session count on C-smp exceeded 2"
                type: str
            gtp_u_smp_in_rml_with_sess:
                description:
                - "GTP-U smp is marked RML with U-session"
                type: str
            gtp_tunnel_rate_limit_entry_create_failure:
                description:
                - "GTP Tunnel Level Rate Limit Entry Create Failure"
                type: str
            gtp_rate_limit_smp_create_failure:
                description:
                - "GTP Rate Limit SMP Create Failure"
                type: str
            gtp_rate_limit_t3_ctr_create_failure:
                description:
                - "GTP Rate Limit Dynamic Counters Create Failure"
                type: str
            gtp_rate_limit_entry_create_failure:
                description:
                - "GTP Rate Limit Entry Create Failure"
                type: str
            gtp_node_restart_echo:
                description:
                - "GTP Node Restoration due to Recovery IE in Echo"
                type: str
            gtp_c_echo_path_failure:
                description:
                - "GTP-C Path Failure due to Echo"
                type: str
            drop_vld_gtp_echo_out_of_state_:
                description:
                - "GTP Echo Out of State Drop"
                type: str
            drop_vld_gtp_echo_ie_len_exceed_msg_len:
                description:
                - "GTP Echo IE Length Exceeds Message Length"
                type: str
            gtp_del_bearer_request_retransmit:
                description:
                - "GTP-C Retransmitted Delete Bearer Request"
                type: str
            gtp_add_bearer_response_retransmit:
                description:
                - "GTP-C Retransmitted Add Bearer Response"
                type: str
            gtp_u_out_of_state_drop:
                description:
                - "GTP-U Out of state Drop"
                type: str
            gtp_c_handover_request_out_of_state_drop:
                description:
                - "GTP-C Handover Request Out of state Drop"
                type: str
            gtp_v1_c_nsapi_not_found_in_delete_req:
                description:
                - "GTPv1-C NSAPI Not Found in GTP Request"
                type: str
            gtp_v2_c_bearer_not_found_in_delete_req:
                description:
                - "GTPv2-C Bearer Not Found in GTP Request"
                type: str
            gtp_v2_c_bearer_not_found_in_delete_resp:
                description:
                - "GTPv2-C Bearer Not Found in GTP Response"
                type: str
            gtp_rr_message_drop:
                description:
                - "GTP Message Dropped in RR Mode"
                type: str
            drop_gtp_frag_or_jumbo_pkt:
                description:
                - "GTP Fragmented or JUMBO packet Drop"
                type: str
            gtp_c_handover_in_progress_with_conn:
                description:
                - "GTP-C mesg matching conn with HO In Progress"
                type: str
            gtp_v0_c_uplink_ingress_packets:
                description:
                - "GTPv0-C Uplink Ingress Packets"
                type: str
            gtp_v0_c_uplink_egress_packets:
                description:
                - "GTPv0-C Uplink Egress Packets"
                type: str
            gtp_v0_c_downlink_ingress_packets:
                description:
                - "GTPv0-C Downlink Ingress Packets"
                type: str
            gtp_v0_c_downlink_egress_packets:
                description:
                - "GTPv0-C Downlink Egress Packets"
                type: str
            gtp_v0_c_uplink_ingress_bytes:
                description:
                - "GTPv0-C Uplink Ingress Bytes"
                type: str
            gtp_v0_c_uplink_egress_bytes:
                description:
                - "GTPv0-C Uplink Egress Bytes"
                type: str
            gtp_v0_c_downlink_ingress_bytes:
                description:
                - "GTPv0-C Downlink Ingress Bytes"
                type: str
            gtp_v0_c_downlink_egress_bytes:
                description:
                - "GTPv0-C Downlink Egress Bytes"
                type: str
            gtp_v1_c_uplink_ingress_packets:
                description:
                - "GTPv1-C Uplink Ingress Packets"
                type: str
            gtp_v1_c_uplink_egress_packets:
                description:
                - "GTPv1-C Uplink Egress Packets"
                type: str
            gtp_v1_c_downlink_ingress_packets:
                description:
                - "GTPv1-C Downlink Ingress Packets"
                type: str
            gtp_v1_c_downlink_egress_packets:
                description:
                - "GTPv1-C Downlink Egress Packets"
                type: str
            gtp_v1_c_uplink_ingress_bytes:
                description:
                - "GTPv1-C Uplink Ingress Bytes"
                type: str
            gtp_v1_c_uplink_egress_bytes:
                description:
                - "GTPv1-C Uplink Egress Bytes"
                type: str
            gtp_v1_c_downlink_ingress_bytes:
                description:
                - "GTPv1-C Downlink Ingress Bytes"
                type: str
            gtp_v1_c_downlink_egress_bytes:
                description:
                - "GTPv1-C Downlink Egress Bytes"
                type: str
            gtp_v2_c_uplink_ingress_packets:
                description:
                - "GTPv2-C Uplink Ingress Packets"
                type: str
            gtp_v2_c_uplink_egress_packets:
                description:
                - "GTPv2-C Uplink Egress Packets"
                type: str
            gtp_v2_c_downlink_ingress_packets:
                description:
                - "GTPv2-C Downlink Ingress Packets"
                type: str
            gtp_v2_c_downlink_egress_packets:
                description:
                - "GTPv2-C Downlink Egress Packets"
                type: str
            gtp_v2_c_uplink_ingress_bytes:
                description:
                - "GTPv2-C Uplink Ingress Bytes"
                type: str
            gtp_v2_c_uplink_egress_bytes:
                description:
                - "GTPv2-C Uplink Egress Bytes"
                type: str
            gtp_v2_c_downlink_ingress_bytes:
                description:
                - "GTPv2-C Downlink Ingress Bytes"
                type: str
            gtp_v2_c_downlink_egress_bytes:
                description:
                - "GTPv2-C Downlink Egress Bytes"
                type: str
            gtp_u_uplink_ingress_packets:
                description:
                - "GTP-U Uplink Ingress Packets"
                type: str
            gtp_u_uplink_egress_packets:
                description:
                - "GTP-U Uplink Egress Packets"
                type: str
            gtp_u_downlink_ingress_packets:
                description:
                - "GTP-U Downlink Ingress Packets"
                type: str
            gtp_u_downlink_egress_packets:
                description:
                - "GTP-U Downlink Egress Packets"
                type: str
            gtp_u_uplink_ingress_bytes:
                description:
                - "GTP-U Uplink Ingress Bytes"
                type: str
            gtp_u_uplink_egress_bytes:
                description:
                - "GTP-U Uplink Egress Bytes"
                type: str
            gtp_u_downlink_ingress_bytes:
                description:
                - "GTP-U Downlink Ingress Bytes"
                type: str
            gtp_u_downlink_egress_bytes:
                description:
                - "GTP-U Downlink Egress Bytes"
                type: str
            gtp_u_message_length_mismatch:
                description:
                - "GTP-U Message Length Mismatch Across Layers"
                type: str
            gtp_path_message_length_mismatch:
                description:
                - "GTP-Path Message Length Mismatch Across Layers"
                type: str
            drop_gtp_missing_cond_ie_bearer_ctx:
                description:
                - "Missing conditional IE in bearer context Drop"
                type: str
            drop_gtp_bearer_not_found_in_resp:
                description:
                - "GTP Bearer not found in response"
                type: str
            gtp_stateless_forward:
                description:
                - "GTP Stateless Forward"
                type: str
            gtp_monitor_forward:
                description:
                - "GTP messages forwarded via monitor mode"
                type: str
            apn_prefix:
                description:
                - "Field apn_prefix"
                type: dict
            network_element:
                description:
                - "Field network_element"
                type: dict

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
    "apn_log_periodicity", "apn_prefix", "apn_prefix_list", "echo_timeout", "gtp_value", "insertion_mode", "ne_v4_log_periodicity", "ne_v6_log_periodicity", "network_element", "network_element_list_v4", "network_element_list_v6", "path_mgmt_logging", "sampling_enable", "stats", "uuid",
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
        'gtp_value': {
            'type': 'str',
            'choices': ['enable']
            },
        'network_element_list_v4': {
            'type': 'str',
            },
        'ne_v4_log_periodicity': {
            'type': 'int',
            },
        'network_element_list_v6': {
            'type': 'str',
            },
        'ne_v6_log_periodicity': {
            'type': 'int',
            },
        'apn_prefix_list': {
            'type': 'str',
            },
        'apn_log_periodicity': {
            'type': 'int',
            },
        'echo_timeout': {
            'type': 'int',
            },
        'path_mgmt_logging': {
            'type': 'str',
            'choices': ['enable-log']
            },
        'insertion_mode': {
            'type': 'str',
            'choices': ['monitor', 'skip-state-checks']
            },
        'uuid': {
            'type': 'str',
            },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'out-of-session-memory', 'no-fwd-route', 'no-rev-route', 'gtp-smp-created', 'gtp-smp-marked-deleted', 'gtp-smp-deleted', 'smp-creation-failed', 'gtp-smp-path-created', 'gtp-smp-path-freed', 'gtp-smp-path-allocated', 'gtp-smp-path-creation-failed',
                    'gtp-smp-path-check-failed', 'gtp-smp-check-failed', 'gtp-smp-session-count-check-failed', 'gtp-c-ref-count-smp-exceeded', 'gtp-u-smp-in-rml-with-sess', 'gtp-u-pkt-fwd-conn-create', 'gtp-c-pkt-fwd-conn-create', 'gtp-echo-pkt-fwd-conn-create',
                    'gtp-tunnel-rate-limit-entry-create-success', 'gtp-tunnel-rate-limit-entry-create-failure', 'gtp-tunnel-rate-limit-entry-deleted', 'gtp-rate-limit-smp-created', 'gtp-rate-limit-smp-freed', 'gtp-rate-limit-smp-create-failure', 'gtp-rate-limit-t3-ctr-create-failure',
                    'gtp-rate-limit-entry-create-failure', 'gtp-echo-conn-created', 'gtp-echo-conn-deleted', 'gtp-node-restart-echo', 'gtp-c-echo-path-failure', 'drop-vld-gtp-echo-out-of-state-', 'drop-vld-gtp-echo-ie-len-exceed-msg-len', 'gtp-create-session-request-retransmit',
                    'gtp-add-bearer-request-retransmit', 'gtp-delete-session-request-retransmit', 'gtp-handover-request-retransmit', 'gtp-del-bearer-request-retransmit', 'gtp-add-bearer-response-retransmit', 'gtp-create-session-request-retx-drop', 'gtp-u-out-of-state-drop',
                    'gtp-c-handover-request-out-of-state-drop', 'gtp-v1-c-nsapi-not-found-in-delete-req', 'gtp-v2-c-bearer-not-found-in-delete-req', 'gtp-v2-c-bearer-not-found-in-delete-resp', 'gtp-multiple-handover-request', 'gtp-rr-message-drop', 'gtp-rr-echo-message-dcmsg',
                    'gtp-rr-c-message-dcmsg', 'drop-gtp-frag-or-jumbo-pkt', 'response-with-reject-cause-forwarded', 'gtp-c-message-forwarded-without-conn', 'gtp-v0-c-ver-not-supp', 'gtp-v1-c-ver-not-supp', 'gtp-v2-c-ver-not-supp', 'gtp-v1-extn-hdt-notif', 'gtp-u-error-ind',
                    'gtp-c-handover-in-progress-with-conn', 'gtp-ho-in-progress-handover-request', 'gtp-correct-conn-ho-in-progress-handover-request', 'gtp-wrong-conn-ho-in-progress-handover-request', 'gtp-ho-in-progress-handover-response', 'gtp-ho-in-progress-c-mesg',
                    'gtp-unset-ho-flag-reuse-teid', 'gtp-refresh-c-conn-reuse-teid', 'gtp-rematch-smp-matching-conn', 'gtp-wrong-conn-handover-request', 'gtp-refresh-conn-set-ho-flag-latest', 'gtp-c-process-pkt-drop', 'gtp-c-fwd-pkt-drop', 'gtp-c-rev-pkt-drop', 'gtp-c-fwd-v1-other',
                    'gtp-c-fwd-v2-other', 'gtp-c-rev-v1-other', 'gtp-c-rev-v2-other', 'gtp-c-going-thru-fw-lookup', 'gtp-c-conn-create-pkt-drop', 'gtp-c-pkt-fwd-conn-create-no-fteid', 'gtp-v0-c-uplink-ingress-packets', 'gtp-v0-c-uplink-egress-packets', 'gtp-v0-c-downlink-ingress-packets',
                    'gtp-v0-c-downlink-egress-packets', 'gtp-v0-c-uplink-ingress-bytes', 'gtp-v0-c-uplink-egress-bytes', 'gtp-v0-c-downlink-ingress-bytes', 'gtp-v0-c-downlink-egress-bytes', 'gtp-v1-c-uplink-ingress-packets', 'gtp-v1-c-uplink-egress-packets', 'gtp-v1-c-downlink-ingress-packets',
                    'gtp-v1-c-downlink-egress-packets', 'gtp-v1-c-uplink-ingress-bytes', 'gtp-v1-c-uplink-egress-bytes', 'gtp-v1-c-downlink-ingress-bytes', 'gtp-v1-c-downlink-egress-bytes', 'gtp-v2-c-uplink-ingress-packets', 'gtp-v2-c-uplink-egress-packets', 'gtp-v2-c-downlink-ingress-packets',
                    'gtp-v2-c-downlink-egress-packets', 'gtp-v2-c-uplink-ingress-bytes', 'gtp-v2-c-uplink-egress-bytes', 'gtp-v2-c-downlink-ingress-bytes', 'gtp-v2-c-downlink-egress-bytes', 'gtp-u-uplink-ingress-packets', 'gtp-u-uplink-egress-packets', 'gtp-u-downlink-ingress-packets',
                    'gtp-u-downlink-egress-packets', 'gtp-u-uplink-ingress-bytes', 'gtp-u-uplink-egress-bytes', 'gtp-u-downlink-ingress-bytes', 'gtp-u-downlink-egress-bytes', 'gtp-v0-c-create-synced'
                    ]
                },
            'counters2': {
                'type':
                'str',
                'choices': [
                    'gtp-v1-c-create-synced', 'gtp-v2-c-create-synced', 'gtp-v0-c-delete-synced', 'gtp-v1-c-delete-synced', 'gtp-v2-c-delete-synced', 'gtp-v0-c-create-sync-rx', 'gtp-v1-c-create-sync-rx', 'gtp-v2-c-create-sync-rx', 'gtp-v0-c-delete-sync-rx', 'gtp-v1-c-delete-sync-rx',
                    'gtp-v2-c-delete-sync-rx', 'gtp-handover-synced', 'gtp-handover-sync-rx', 'gtp-smp-add-bearer-synced', 'gtp-smp-del-bearer-synced', 'gtp-smp-additional-bearer-synced', 'gtp-smp-add-bearer-sync-rx', 'gtp-smp-del-bearer-sync-rx', 'gtp-smp-additional-bearer-sync-rx',
                    'gtp-add-bearer-sync-not-rx-on-standby', 'gtp-add-bearer-sync-with-periodic-update-on-standby', 'gtp-delete-bearer-sync-with-periodic-update-on-standby', 'gtp-v0-c-echo-create-synced', 'gtp-v1-c-echo-create-synced', 'gtp-v2-c-echo-create-synced', 'gtp-v0-c-echo-create-sync-rx',
                    'gtp-v1-c-echo-create-sync-rx', 'gtp-v2-c-echo-create-sync-rx', 'gtp-v0-c-echo-del-synced', 'gtp-v1-c-echo-del-synced', 'gtp-v2-c-echo-del-synced', 'gtp-v0-c-echo-del-sync-rx', 'gtp-v1-c-echo-del-sync-rx', 'gtp-v2-c-echo-del-sync-rx', 'drop-gtp-conn-creation-standby',
                    'gtp-u-synced-before-control', 'gtp-c-l5-synced-before-l3', 'gtp-smp-path-del-synced', 'gtp-smp-path-del-sync-rx', 'gtp-not-enabled-on-standby', 'gtp-ip-version-v4-v6', 'drop-gtp-ip-version-mismatch-fteid', 'drop-gtp-ip-version-mismatch-ho-fteid', 'gtp-u-message-length-mismatch',
                    'gtp-path-message-length-mismatch', 'drop-gtp-missing-cond-ie-bearer-ctx', 'drop-gtp-bearer-not-found-in-resp', 'gtp-stateless-forward', 'gtp-l3-conn-deleted', 'gtp-l5-conn-created', 'gtp-monitor-forward', 'gtp-u_inner-ip-not-present', 'gtp-ext_hdr-incorrect-length'
                    ]
                }
            },
        'apn_prefix': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'network_element': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'stats': {
            'type': 'dict',
            'out_of_session_memory': {
                'type': 'str',
                },
            'no_fwd_route': {
                'type': 'str',
                },
            'no_rev_route': {
                'type': 'str',
                },
            'gtp_smp_path_check_failed': {
                'type': 'str',
                },
            'gtp_smp_check_failed': {
                'type': 'str',
                },
            'gtp_smp_session_count_check_failed': {
                'type': 'str',
                },
            'gtp_c_ref_count_smp_exceeded': {
                'type': 'str',
                },
            'gtp_u_smp_in_rml_with_sess': {
                'type': 'str',
                },
            'gtp_tunnel_rate_limit_entry_create_failure': {
                'type': 'str',
                },
            'gtp_rate_limit_smp_create_failure': {
                'type': 'str',
                },
            'gtp_rate_limit_t3_ctr_create_failure': {
                'type': 'str',
                },
            'gtp_rate_limit_entry_create_failure': {
                'type': 'str',
                },
            'gtp_node_restart_echo': {
                'type': 'str',
                },
            'gtp_c_echo_path_failure': {
                'type': 'str',
                },
            'drop_vld_gtp_echo_out_of_state_': {
                'type': 'str',
                },
            'drop_vld_gtp_echo_ie_len_exceed_msg_len': {
                'type': 'str',
                },
            'gtp_del_bearer_request_retransmit': {
                'type': 'str',
                },
            'gtp_add_bearer_response_retransmit': {
                'type': 'str',
                },
            'gtp_u_out_of_state_drop': {
                'type': 'str',
                },
            'gtp_c_handover_request_out_of_state_drop': {
                'type': 'str',
                },
            'gtp_v1_c_nsapi_not_found_in_delete_req': {
                'type': 'str',
                },
            'gtp_v2_c_bearer_not_found_in_delete_req': {
                'type': 'str',
                },
            'gtp_v2_c_bearer_not_found_in_delete_resp': {
                'type': 'str',
                },
            'gtp_rr_message_drop': {
                'type': 'str',
                },
            'drop_gtp_frag_or_jumbo_pkt': {
                'type': 'str',
                },
            'gtp_c_handover_in_progress_with_conn': {
                'type': 'str',
                },
            'gtp_v0_c_uplink_ingress_packets': {
                'type': 'str',
                },
            'gtp_v0_c_uplink_egress_packets': {
                'type': 'str',
                },
            'gtp_v0_c_downlink_ingress_packets': {
                'type': 'str',
                },
            'gtp_v0_c_downlink_egress_packets': {
                'type': 'str',
                },
            'gtp_v0_c_uplink_ingress_bytes': {
                'type': 'str',
                },
            'gtp_v0_c_uplink_egress_bytes': {
                'type': 'str',
                },
            'gtp_v0_c_downlink_ingress_bytes': {
                'type': 'str',
                },
            'gtp_v0_c_downlink_egress_bytes': {
                'type': 'str',
                },
            'gtp_v1_c_uplink_ingress_packets': {
                'type': 'str',
                },
            'gtp_v1_c_uplink_egress_packets': {
                'type': 'str',
                },
            'gtp_v1_c_downlink_ingress_packets': {
                'type': 'str',
                },
            'gtp_v1_c_downlink_egress_packets': {
                'type': 'str',
                },
            'gtp_v1_c_uplink_ingress_bytes': {
                'type': 'str',
                },
            'gtp_v1_c_uplink_egress_bytes': {
                'type': 'str',
                },
            'gtp_v1_c_downlink_ingress_bytes': {
                'type': 'str',
                },
            'gtp_v1_c_downlink_egress_bytes': {
                'type': 'str',
                },
            'gtp_v2_c_uplink_ingress_packets': {
                'type': 'str',
                },
            'gtp_v2_c_uplink_egress_packets': {
                'type': 'str',
                },
            'gtp_v2_c_downlink_ingress_packets': {
                'type': 'str',
                },
            'gtp_v2_c_downlink_egress_packets': {
                'type': 'str',
                },
            'gtp_v2_c_uplink_ingress_bytes': {
                'type': 'str',
                },
            'gtp_v2_c_uplink_egress_bytes': {
                'type': 'str',
                },
            'gtp_v2_c_downlink_ingress_bytes': {
                'type': 'str',
                },
            'gtp_v2_c_downlink_egress_bytes': {
                'type': 'str',
                },
            'gtp_u_uplink_ingress_packets': {
                'type': 'str',
                },
            'gtp_u_uplink_egress_packets': {
                'type': 'str',
                },
            'gtp_u_downlink_ingress_packets': {
                'type': 'str',
                },
            'gtp_u_downlink_egress_packets': {
                'type': 'str',
                },
            'gtp_u_uplink_ingress_bytes': {
                'type': 'str',
                },
            'gtp_u_uplink_egress_bytes': {
                'type': 'str',
                },
            'gtp_u_downlink_ingress_bytes': {
                'type': 'str',
                },
            'gtp_u_downlink_egress_bytes': {
                'type': 'str',
                },
            'gtp_u_message_length_mismatch': {
                'type': 'str',
                },
            'gtp_path_message_length_mismatch': {
                'type': 'str',
                },
            'drop_gtp_missing_cond_ie_bearer_ctx': {
                'type': 'str',
                },
            'drop_gtp_bearer_not_found_in_resp': {
                'type': 'str',
                },
            'gtp_stateless_forward': {
                'type': 'str',
                },
            'gtp_monitor_forward': {
                'type': 'str',
                },
            'apn_prefix': {
                'type': 'dict',
                'stats': {
                    'type': 'dict',
                    'key_name': {
                        'type': 'str',
                        },
                    'uplink_bytes': {
                        'type': 'str',
                        },
                    'downlink_bytes': {
                        'type': 'str',
                        },
                    'uplink_pkts': {
                        'type': 'str',
                        },
                    'downlink_pkts': {
                        'type': 'str',
                        },
                    'gtp_v0_c_tunnel_created': {
                        'type': 'str',
                        },
                    'gtp_v0_c_tunnel_half_open': {
                        'type': 'str',
                        },
                    'gtp_v0_c_tunnel_half_closed': {
                        'type': 'str',
                        },
                    'gtp_v0_c_tunnel_closed': {
                        'type': 'str',
                        },
                    'gtp_v0_c_tunnel_deleted': {
                        'type': 'str',
                        },
                    'gtp_v0_c_half_open_tunnel_closed': {
                        'type': 'str',
                        },
                    'gtp_v1_c_tunnel_created': {
                        'type': 'str',
                        },
                    'gtp_v1_c_tunnel_half_open': {
                        'type': 'str',
                        },
                    'gtp_v1_c_tunnel_half_closed': {
                        'type': 'str',
                        },
                    'gtp_v1_c_tunnel_closed': {
                        'type': 'str',
                        },
                    'gtp_v1_c_tunnel_deleted': {
                        'type': 'str',
                        },
                    'gtp_v1_c_half_open_tunnel_closed': {
                        'type': 'str',
                        },
                    'gtp_v2_c_tunnel_created': {
                        'type': 'str',
                        },
                    'gtp_v2_c_tunnel_half_open': {
                        'type': 'str',
                        },
                    'gtp_v2_c_tunnel_half_closed': {
                        'type': 'str',
                        },
                    'gtp_v2_c_tunnel_closed': {
                        'type': 'str',
                        },
                    'gtp_v2_c_tunnel_deleted': {
                        'type': 'str',
                        },
                    'gtp_v2_c_half_open_tunnel_closed': {
                        'type': 'str',
                        },
                    'gtp_u_tunnel_created': {
                        'type': 'str',
                        },
                    'gtp_u_tunnel_deleted': {
                        'type': 'str',
                        },
                    'gtp_v0_c_update_pdp_resp_unsuccess': {
                        'type': 'str',
                        },
                    'gtp_v1_c_update_pdp_resp_unsuccess': {
                        'type': 'str',
                        },
                    'gtp_v2_c_mod_bearer_resp_unsuccess': {
                        'type': 'str',
                        },
                    'gtp_v0_c_create_pdp_resp_unsuccess': {
                        'type': 'str',
                        },
                    'gtp_v1_c_create_pdp_resp_unsuccess': {
                        'type': 'str',
                        },
                    'gtp_v2_c_create_sess_resp_unsuccess': {
                        'type': 'str',
                        },
                    'gtp_v2_c_piggyback_message': {
                        'type': 'str',
                        },
                    'gtp_path_management_message': {
                        'type': 'str',
                        },
                    'gtp_v0_c_tunnel_deleted_restart': {
                        'type': 'str',
                        },
                    'gtp_v1_c_tunnel_deleted_restart': {
                        'type': 'str',
                        },
                    'gtp_v2_c_tunnel_deleted_restart': {
                        'type': 'str',
                        },
                    'gtp_v0_c_reserved_message_allow': {
                        'type': 'str',
                        },
                    'gtp_v1_c_reserved_message_allow': {
                        'type': 'str',
                        },
                    'gtp_v2_c_reserved_message_allow': {
                        'type': 'str',
                        },
                    'gtp_v1_c_pdu_notification_request_forward': {
                        'type': 'str',
                        },
                    'gtp_v1_c_pdu_notification_reject_request_forward': {
                        'type': 'str',
                        },
                    'gtp_v0_c_pdu_notification_request_forward': {
                        'type': 'str',
                        },
                    'gtp_v0_c_pdu_notification_reject_request_forward': {
                        'type': 'str',
                        },
                    'gtp_v0_c_message_skipped_apn_filtering_no_imsi': {
                        'type': 'str',
                        },
                    'gtp_v1_c_message_skipped_apn_filtering_no_imsi': {
                        'type': 'str',
                        },
                    'gtp_v2_c_message_skipped_apn_filtering_no_imsi': {
                        'type': 'str',
                        },
                    'gtp_v0_c_message_skipped_msisdn_filtering_no_msisdn': {
                        'type': 'str',
                        },
                    'gtp_v1_c_message_skipped_msisdn_filtering_no_msisdn': {
                        'type': 'str',
                        },
                    'gtp_v2_c_message_skipped_msisdn_filtering_no_msisdn': {
                        'type': 'str',
                        },
                    'gtp_v0_c_packet_dummy_msisdn': {
                        'type': 'str',
                        },
                    'gtp_v1_c_packet_dummy_msisdn': {
                        'type': 'str',
                        },
                    'gtp_v2_c_packet_dummy_msisdn': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v2_c_message_with_teid_zero_expected': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v1_c_message_with_teid_zero_expected': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v0_c_message_with_teid_zero_expected': {
                        'type': 'str',
                        },
                    'drop_vld_reserved_field_set': {
                        'type': 'str',
                        },
                    'drop_vld_tunnel_id_flag': {
                        'type': 'str',
                        },
                    'drop_vld_invalid_flow_label_v0': {
                        'type': 'str',
                        },
                    'drop_vld_invalid_teid': {
                        'type': 'str',
                        },
                    'drop_vld_unsupported_message_type': {
                        'type': 'str',
                        },
                    'drop_vld_out_of_state': {
                        'type': 'str',
                        },
                    'drop_vld_mandatory_information_element': {
                        'type': 'str',
                        },
                    'drop_vld_out_of_order_ie': {
                        'type': 'str',
                        },
                    'drop_vld_out_of_state_ie': {
                        'type': 'str',
                        },
                    'drop_vld_reserved_information_element': {
                        'type': 'str',
                        },
                    'drop_vld_version_not_supported': {
                        'type': 'str',
                        },
                    'drop_vld_message_length': {
                        'type': 'str',
                        },
                    'drop_vld_cross_layer_correlation': {
                        'type': 'str',
                        },
                    'drop_vld_country_code_mismatch': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_u_spoofed_source_address': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_bearer_count_exceed': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v2_wrong_lbi_create_bearer_req': {
                        'type': 'str',
                        },
                    'gtp_c_handover_in_progress_with_conn': {
                        'type': 'str',
                        },
                    'drop_vld_v0_reserved_message_drop': {
                        'type': 'str',
                        },
                    'drop_vld_v1_reserved_message_drop': {
                        'type': 'str',
                        },
                    'drop_vld_v2_reserved_message_drop': {
                        'type': 'str',
                        },
                    'drop_vld_invalid_pkt_len_piggyback': {
                        'type': 'str',
                        },
                    'drop_vld_sanity_failed_piggyback': {
                        'type': 'str',
                        },
                    'drop_vld_sequence_num_correlation': {
                        'type': 'str',
                        },
                    'drop_vld_gtpv0_seqnum_buffer_full': {
                        'type': 'str',
                        },
                    'drop_vld_gtpv1_seqnum_buffer_full': {
                        'type': 'str',
                        },
                    'drop_vld_gtpv2_seqnum_buffer_full': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_invalid_imsi_len_drop': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_invalid_apn_len_drop': {
                        'type': 'str',
                        },
                    'drop_vld_protocol_flag_unset': {
                        'type': 'str',
                        },
                    'drop_vld_gtpv0_subscriber_attr_miss': {
                        'type': 'str',
                        },
                    'drop_vld_gtpv1_subscriber_attr_miss': {
                        'type': 'str',
                        },
                    'drop_vld_gtpv2_subscriber_attr_miss': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v0_c_ie_len_exceed_msg_len': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v1_c_ie_len_exceed_msg_len': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v2_c_ie_len_exceed_msg_len': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v0_c_message_length_mismatch': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v1_c_message_length_mismatch': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v2_c_message_length_mismatch': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v0_c_message_dropped_apn_filtering_no_apn': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v1_c_message_dropped_apn_filtering_no_apn': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v2_c_message_dropped_apn_filtering_no_apn': {
                        'type': 'str',
                        },
                    'drop_flt_message_filtering': {
                        'type': 'str',
                        },
                    'drop_flt_apn_filtering': {
                        'type': 'str',
                        },
                    'drop_flt_msisdn_filtering': {
                        'type': 'str',
                        },
                    'drop_flt_rat_type_filtering': {
                        'type': 'str',
                        },
                    'drop_flt_gtp_in_gtp': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_v0_c_agg': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_v1_c_agg': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_v2_c_agg': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_v1_c_create_pdp_request': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_v2_c_create_session_request': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_v1_c_update_pdp_request': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_v2_c_modify_bearer_request': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_u_tunnel_create': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_u_uplink_byte': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_u_uplink_packet': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_u_downlink_byte': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_u_downlink_packet': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_u_total_byte': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_u_total_packet': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_u_max_concurrent_tunnels': {
                        'type': 'str',
                        }
                    }
                },
            'network_element': {
                'type': 'dict',
                'stats': {
                    'type': 'dict',
                    'key_name': {
                        'type': 'str',
                        },
                    'key_type': {
                        'type': 'str',
                        },
                    'uplink_bytes': {
                        'type': 'str',
                        },
                    'downlink_bytes': {
                        'type': 'str',
                        },
                    'uplink_pkts': {
                        'type': 'str',
                        },
                    'downlink_pkts': {
                        'type': 'str',
                        },
                    'gtp_v0_c_tunnel_created': {
                        'type': 'str',
                        },
                    'gtp_v0_c_tunnel_half_open': {
                        'type': 'str',
                        },
                    'gtp_v0_c_tunnel_half_closed': {
                        'type': 'str',
                        },
                    'gtp_v0_c_tunnel_closed': {
                        'type': 'str',
                        },
                    'gtp_v0_c_tunnel_deleted': {
                        'type': 'str',
                        },
                    'gtp_v0_c_half_open_tunnel_closed': {
                        'type': 'str',
                        },
                    'gtp_v1_c_tunnel_created': {
                        'type': 'str',
                        },
                    'gtp_v1_c_tunnel_half_open': {
                        'type': 'str',
                        },
                    'gtp_v1_c_tunnel_half_closed': {
                        'type': 'str',
                        },
                    'gtp_v1_c_tunnel_closed': {
                        'type': 'str',
                        },
                    'gtp_v1_c_tunnel_deleted': {
                        'type': 'str',
                        },
                    'gtp_v1_c_half_open_tunnel_closed': {
                        'type': 'str',
                        },
                    'gtp_v2_c_tunnel_created': {
                        'type': 'str',
                        },
                    'gtp_v2_c_tunnel_half_open': {
                        'type': 'str',
                        },
                    'gtp_v2_c_tunnel_half_closed': {
                        'type': 'str',
                        },
                    'gtp_v2_c_tunnel_closed': {
                        'type': 'str',
                        },
                    'gtp_v2_c_tunnel_deleted': {
                        'type': 'str',
                        },
                    'gtp_v2_c_half_open_tunnel_closed': {
                        'type': 'str',
                        },
                    'gtp_u_tunnel_created': {
                        'type': 'str',
                        },
                    'gtp_u_tunnel_deleted': {
                        'type': 'str',
                        },
                    'gtp_v0_c_update_pdp_resp_unsuccess': {
                        'type': 'str',
                        },
                    'gtp_v1_c_update_pdp_resp_unsuccess': {
                        'type': 'str',
                        },
                    'gtp_v2_c_mod_bearer_resp_unsuccess': {
                        'type': 'str',
                        },
                    'gtp_v0_c_create_pdp_resp_unsuccess': {
                        'type': 'str',
                        },
                    'gtp_v1_c_create_pdp_resp_unsuccess': {
                        'type': 'str',
                        },
                    'gtp_v2_c_create_sess_resp_unsuccess': {
                        'type': 'str',
                        },
                    'gtp_v2_c_piggyback_message': {
                        'type': 'str',
                        },
                    'gtp_path_management_message': {
                        'type': 'str',
                        },
                    'gtp_v0_c_tunnel_deleted_restart': {
                        'type': 'str',
                        },
                    'gtp_v1_c_tunnel_deleted_restart': {
                        'type': 'str',
                        },
                    'gtp_v2_c_tunnel_deleted_restart': {
                        'type': 'str',
                        },
                    'gtp_node_restart_gtp_c': {
                        'type': 'str',
                        },
                    'gtp_v0_c_reserved_message_allow': {
                        'type': 'str',
                        },
                    'gtp_v1_c_reserved_message_allow': {
                        'type': 'str',
                        },
                    'gtp_v2_c_reserved_message_allow': {
                        'type': 'str',
                        },
                    'gtp_v1_c_pdu_notification_request_forward': {
                        'type': 'str',
                        },
                    'gtp_v1_c_pdu_notification_reject_request_forward': {
                        'type': 'str',
                        },
                    'gtp_v0_c_pdu_notification_request_forward': {
                        'type': 'str',
                        },
                    'gtp_v0_c_pdu_notification_reject_request_forward': {
                        'type': 'str',
                        },
                    'gtp_v0_c_message_skipped_apn_filtering_no_imsi': {
                        'type': 'str',
                        },
                    'gtp_v1_c_message_skipped_apn_filtering_no_imsi': {
                        'type': 'str',
                        },
                    'gtp_v2_c_message_skipped_apn_filtering_no_imsi': {
                        'type': 'str',
                        },
                    'gtp_v0_c_message_skipped_msisdn_filtering_no_msisdn': {
                        'type': 'str',
                        },
                    'gtp_v1_c_message_skipped_msisdn_filtering_no_msisdn': {
                        'type': 'str',
                        },
                    'gtp_v2_c_message_skipped_msisdn_filtering_no_msisdn': {
                        'type': 'str',
                        },
                    'gtp_v0_c_packet_dummy_msisdn': {
                        'type': 'str',
                        },
                    'gtp_v1_c_packet_dummy_msisdn': {
                        'type': 'str',
                        },
                    'gtp_v2_c_packet_dummy_msisdn': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v2_c_message_with_teid_zero_expected': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v1_c_message_with_teid_zero_expected': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v0_c_message_with_teid_zero_expected': {
                        'type': 'str',
                        },
                    'drop_vld_reserved_field_set': {
                        'type': 'str',
                        },
                    'drop_vld_tunnel_id_flag': {
                        'type': 'str',
                        },
                    'drop_vld_invalid_flow_label_v0': {
                        'type': 'str',
                        },
                    'drop_vld_invalid_teid': {
                        'type': 'str',
                        },
                    'drop_vld_unsupported_message_type': {
                        'type': 'str',
                        },
                    'drop_vld_out_of_state': {
                        'type': 'str',
                        },
                    'drop_vld_mandatory_information_element': {
                        'type': 'str',
                        },
                    'drop_vld_out_of_order_ie': {
                        'type': 'str',
                        },
                    'drop_vld_out_of_state_ie': {
                        'type': 'str',
                        },
                    'drop_vld_reserved_information_element': {
                        'type': 'str',
                        },
                    'drop_vld_version_not_supported': {
                        'type': 'str',
                        },
                    'drop_vld_message_length': {
                        'type': 'str',
                        },
                    'drop_vld_cross_layer_correlation': {
                        'type': 'str',
                        },
                    'drop_vld_country_code_mismatch': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_u_spoofed_source_address': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_bearer_count_exceed': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v2_wrong_lbi_create_bearer_req': {
                        'type': 'str',
                        },
                    'gtp_c_handover_in_progress_with_conn': {
                        'type': 'str',
                        },
                    'drop_vld_v0_reserved_message_drop': {
                        'type': 'str',
                        },
                    'drop_vld_v1_reserved_message_drop': {
                        'type': 'str',
                        },
                    'drop_vld_v2_reserved_message_drop': {
                        'type': 'str',
                        },
                    'drop_vld_invalid_pkt_len_piggyback': {
                        'type': 'str',
                        },
                    'drop_vld_sanity_failed_piggyback': {
                        'type': 'str',
                        },
                    'drop_vld_sequence_num_correlation': {
                        'type': 'str',
                        },
                    'drop_vld_gtpv0_seqnum_buffer_full': {
                        'type': 'str',
                        },
                    'drop_vld_gtpv1_seqnum_buffer_full': {
                        'type': 'str',
                        },
                    'drop_vld_gtpv2_seqnum_buffer_full': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_invalid_imsi_len_drop': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_invalid_apn_len_drop': {
                        'type': 'str',
                        },
                    'drop_vld_protocol_flag_unset': {
                        'type': 'str',
                        },
                    'drop_vld_gtpv0_subscriber_attr_miss': {
                        'type': 'str',
                        },
                    'drop_vld_gtpv1_subscriber_attr_miss': {
                        'type': 'str',
                        },
                    'drop_vld_gtpv2_subscriber_attr_miss': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v0_c_message_dropped_apn_filtering_no_apn': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v1_c_message_dropped_apn_filtering_no_apn': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v2_c_message_dropped_apn_filtering_no_apn': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v0_c_ie_len_exceed_msg_len': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v1_c_ie_len_exceed_msg_len': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v2_c_ie_len_exceed_msg_len': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v0_c_message_length_mismatch': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v1_c_message_length_mismatch': {
                        'type': 'str',
                        },
                    'drop_vld_gtp_v2_c_message_length_mismatch': {
                        'type': 'str',
                        },
                    'drop_flt_message_filtering': {
                        'type': 'str',
                        },
                    'drop_flt_apn_filtering': {
                        'type': 'str',
                        },
                    'drop_flt_msisdn_filtering': {
                        'type': 'str',
                        },
                    'drop_flt_rat_type_filtering': {
                        'type': 'str',
                        },
                    'drop_flt_gtp_in_gtp': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_v0_c_agg': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_v1_c_agg': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_v2_c_agg': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_v1_c_create_pdp_request': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_v2_c_create_session_request': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_v1_c_update_pdp_request': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_v2_c_modify_bearer_request': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_u_tunnel_create': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_u_uplink_byte': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_u_uplink_packet': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_u_downlink_byte': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_u_downlink_packet': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_u_total_byte': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_u_total_packet': {
                        'type': 'str',
                        },
                    'drop_rl_gtp_u_max_concurrent_tunnels': {
                        'type': 'str',
                        }
                    }
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/gtp"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/fw/gtp"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["gtp"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["gtp"].get(k) != v:
            change_results["changed"] = True
            config_changes["gtp"][k] = v

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
    payload = utils.build_json("gtp", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["gtp"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["gtp-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["gtp"]["stats"] if info != "NotFound" else info
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
