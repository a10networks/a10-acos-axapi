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
                - "'all'= all; 'out-of-session-memory'= Out of Tunnel Memory for GTP-C; 'no-fwd-
          route'= No Forward Route for GTP-C; 'no-rev-route'= No Reverse Route for GTP-C;
          'blade-out-of-session-memory'= Out of Tunnel Memory on PU2; 'blade-no-fwd-
          route'= No Forward Route on PU2; 'blade-no-rev-route'= No Reverse Route on PU2;
          'gtp-smp-created'= GTP SMP Created; 'gtp-smp-marked-deleted'= GTP SMP Marked
          Deleted; 'gtp-smp-deleted'= GTP SMP Deleted; 'smp-creation-failed'= GTP SMP
          Helper Session Creation Failed; 'gtp-smp-path-created'= GTP SMP PATH Created;
          'gtp-smp-path-freed'= GTP SMP PATH MEM freed; 'gtp-smp-path-allocated'= GTP SMP
          PATH MEM allocated; 'gtp-smp-path-creation-failed'= GTP SMP PATH creation
          Failed; 'gtp-smp-path-check-failed'= GTP SMP PATH check Failed; 'gtp-smp-c-
          check-failed'= GTP-C SMP check Failed; 'blade-gtp-smp-created'= GTP SMP Created
          on PU2; 'blade-gtp-smp-marked-deleted'= GTP SMP Marked Deleted on PU2; 'blade-
          gtp-smp-deleted'= GTP SMP Deleted on PU2; 'blade-smp-creation-failed'= GTP SMP
          Helper Session Creation Failed on PU2; 'blade-gtp-smp-path-created'= GTP SMP
          PATH Created on PU2; 'blade-gtp-smp-path-freed'= GTP SMP PATH MEM freed on PU2;
          'blade-gtp-smp-path-allocated'= GTP SMP PATH MEM allocated on PU2; 'blade-gtp-
          smp-path-creation-failed'= GTP SMP PATH creation Failed on PU2; 'blade-gtp-smp-
          path-check-failed'= GTP SMP PATH check Failed on PU2; 'blade-gtp-smp-c-check-
          failed'= GTP-C SMP check Failed on PU2; 'gtp-smp-session-count-check-failed'=
          GTP-U session count is not in range of 0-11 in GTP-C SMP; 'gtp-c-ref-count-smp-
          exceeded'= GTP-C session count on C-smp exceeded 2; 'blade-gtp-c-ref-count-smp-
          exceeded'= GTP-C session count on C-smp exceeded 2 on PU2; 'gtp-u-smp-in-rml-
          with-sess'= GTP-U smp is linked when C-smp is in rml; 'blade-gtp-u-smp-in-rml-
          with-sess'= GTP-U smp is linked when C-smp is in rml on PU2; 'gtp-u-pkt-fwd-
          conn-create'= GTP-U pkt fwded while creating conn with gtp toggling; 'gtp-c-
          pkt-fwd-conn-create'= GTP-C pkt fwded while creating conn with gtp toggling;
          'gtp-echo-pkt-fwd-conn-create'= GTP-ECHO pkt fwded while creating conn with gtp
          toggling; 'gtp-tunnel-rate-limit-entry-create-success'= GTP Tunnel Level Rate
          Limit Entry Create Success; 'gtp-tunnel-rate-limit-entry-inc-ref-count'= GTP
          Tunnel Level Rate Limit Entry Inc ref count; 'gtp-tunnel-rate-limit-entry-
          create-failure'= GTP Tunnel Level Rate Limit Entry Create Failure; 'gtp-tunnel-
          rate-limit-entry-deleted'= GTP Tunnel Level Rate Limit Entry Deleted; 'gtp-u-
          tunnel-rate-limit-entry-create-success'= GTP-U Tunnel Level Rate Limit Entry
          Create Success; 'gtp-u-tunnel-rate-limit-entry-inc-ref-count'= GTP-U Tunnel
          Level Rate Limit Entry Inc ref count; 'gtp-u-tunnel-rate-limit-entry-create-
          failure'= GTP-U Tunnel Level Rate Limit Entry Create Failure; 'gtp-u-tunnel-
          rate-limit-entry-deleted'= GTP-U Tunnel Level Rate Limit Entry Deleted; 'gtp-
          rate-limit-smp-created'= GTP Rate Limit SMP Created; 'gtp-rate-limit-smp-
          freed'= GTP Rate Limit SMP Freed; 'gtp-rate-limit-smp-create-failure'= GTP Rate
          Limit SMP Create Failure; 'gtp-rate-limit-t3-ctr-create-failure'= GTP Rate
          Limit Dynamic Counters Create Failure; 'gtp-rate-limit-entry-create-failure'=
          GTP Rate Limit Entry Create Failure; 'blade-gtp-rate-limit-smp-created'= GTP
          Rate Limit SMP Created on PU2; 'blade-gtp-rate-limit-smp-freed'= GTP Rate Limit
          SMP Freed on PU2; 'blade-gtp-rate-limit-smp-create-failure'= GTP Rate Limit SMP
          Create Failure on PU2; 'blade-gtp-rate-limit-t3-ctr-create-failure'= GTP Rate
          Limit Dynamic Counters Create Failure on PU2; 'blade-gtp-rate-limit-entry-
          create-failure'= GTP Rate Limit Entry Create Failure on PU2; 'gtp-echo-conn-
          created'= GTP Echo Request Conn Created; 'gtp-echo-conn-deleted'= GTP Echo
          Request conn Deleted; 'gtp-node-restart-echo'= GTP Node Restoration due to
          Recovery IE in Echo; 'gtp-c-echo-path-failure'= GTP-C Path Failure due to Echo;
          'drop-vld-gtp-echo-out-of-state-'= GTP Echo Out of State Drop; 'drop-vld-gtp-
          echo-ie-len-exceed-msg-len'= GTP Echo IE Length Exceeds Message Length; 'drop-
          vld-gtp-u-echo-out-of-state-'= GTP-U Echo Out of State Drop; 'gtp-create-
          session-request-retransmit'= GTP-C Retransmitted Create Session Request; 'gtp-
          add-bearer-request-retransmit'= GTP-C Retransmitted Add Bearer Request; 'gtp-
          delete-session-request-retransmit'= GTP-C Retransmitted Delete Session Request;
          'gtp-handover-request-retransmit'= GTP Handover Request Retransmit; 'gtp-del-
          bearer-request-retransmit'= GTP-C Retransmitted Delete Bearer Request; 'gtp-
          add-bearer-response-retransmit'= GTP-C Retransmitted Add Bearer Response; 'gtp-
          create-session-request-retx-drop'= GTP-C Retransmitted Create Session Request
          dropped; 'gtp-u-out-of-state-drop'= GTP-U Out of state Drop; 'gtp-c-handover-
          request-out-of-state-drop'= GTP-C Handover Request Out of state Drop;
          'gtp-v1-c-nsapi-not-found-in-delete-req'= GTPv1-C NSAPI Not Found in GTP
          Request; 'gtp-v2-c-bearer-not-found-in-delete-req'= GTPv2-C Bearer Not Found in
          GTP Request; 'gtp-v2-c-bearer-not-found-in-delete-resp'= GTPv2-C Bearer Not
          Found in GTP Response; 'gtp-multiple-handover-request'= GTP Multiple Handover
          Request; 'gtp-rr-message-drop'= GTP Message Dropped in RR Mode; 'gtp-u-rr-
          message-drop'= GTP-U Message Dropped in RR Mode; 'gtp-rr-echo-message-dcmsg'=
          GTP Echo Message Sent to home CPU in RR Mode; 'gtp-rr-c-message-dcmsg'= GTP-C
          Message Sent to home CPU in RR Mode; 'drop-gtp-frag-or-jumbo-pkt'= GTP
          Fragmented or JUMBO packet Drop; 'response-with-reject-cause-forwarded'= GTP-C
          Response with Reject Cause Forwarded; 'gtp-c-message-forwarded-without-conn'=
          GTP-C Message Forwarded without Conn; 'gtp-v0-c-ver-not-supp'= GTPv0-C Version
          not supported indication; 'gtp-v1-c-ver-not-supp'= GTPv1-C Version not
          supported indication; 'gtp-v2-c-ver-not-supp'= GTPv2-C Version not supported
          indication; 'gtp-v1-extn-hdt-notif'= GTPV1 Supported Extension header
          notification; 'gtp-u-error-ind'= GTP-U Error Indication; 'gtp-c-handover-in-
          progress-with-conn'= GTP-C mesg matching conn with HO In Progress; 'gtp-ho-in-
          progress-handover-request'= GTP-C ho mesg matching conn with HO In Progress;
          'gtp-correct-conn-ho-in-progress-handover-request'= GTP-C ho mesg matching
          correct conn(reuse teid) with HO In Progress; 'gtp-wrong-conn-ho-in-progress-
          handover-request'= GTP-C ho mesg matching wrong conn(new teid) with HO In
          Progress; 'gtp-ho-in-progress-handover-response'= GTP-C ho response matching a
          conn with HO In Progress; 'gtp-ho-in-progress-c-mesg'= GTP-C other than ho mesg
          matching conn with HO In Progress; 'gtp-unset-ho-flag-reuse-teid'= GTP-C SGW
          reuse teid with ho and unset ho flag; 'gtp-refresh-c-conn-reuse-teid'= GTP-C
          SGW reuse teid with ho and refresh old conn; 'gtp-rematch-smp-matching-conn'=
          GTP-C rematch smp with packet matching conn; 'gtp-wrong-conn-handover-request'=
          GTP-C ho mesg matching wrong conn(new teid) with no HO flag; 'gtp-refresh-conn-
          set-ho-flag-latest'= GTP-C SGW refresh old conn and set ho flag on latest smp;
          'gtp-c-process-pkt-drop'= GTP-C process pkt drop; 'gtp-c-fwd-pkt-drop'= GTP-C
          fwd pkt drop; 'gtp-c-rev-pkt-drop'= GTP-C rev pkt drop; 'gtp-c-fwd-v1-other'=
          GTP-C fwd v1 other messages; 'gtp-c-fwd-v2-other'= GTP-C fwd v2 other messages;
          'gtp-c-rev-v1-other'= GTP-C rev v1 other messages; 'gtp-c-rev-v2-other'= GTP-C
          rev v2 other messages; 'gtp-c-going-thru-fw-lookup'= GTP-C mesg going thru fw
          lookup can be resp or l5 mesg not matching smp; 'gtp-c-conn-create-pkt-drop'=
          GTP-C conn creation drop; 'gtp-c-pkt-fwd-conn-create-no-fteid'= GTP-C pkt fwded
          while creating conn when no FTEID; 'gtp-inter-pu-mstr-to-bld-dcmsg-fail'= GTP
          inter-PU dcmsg failed from Master to Blade; 'gtp-inter-pu-mstr-to-bld-dcmsg-
          sent'= GTP inter-PU Master to Blade dcmsg sent;"
                type: str
            counters2:
                description:
                - "'gtp-inter-pu-mstr-to-bld-dcmsg-recv'= GTP inter-PU dcmsg received on blade;
          'gtp-inter-pu-mstr-to-bld-query-sent'= GTP inter-PU query sent from Master to
          Blade; 'gtp-inter-pu-mstr-to-bld-query-recv'= GTP inter-PU GTP-C mesg received
          on Blade; 'gtp-inter-pu-mstr-to-bld-query-resp-sent'= GTP inter-PU GTP-C query
          response sent from Master to Blade; 'gtp-inter-pu-bld-to-mstr-dcmsg-fail'= GTP
          inter-PU dcmsg failed from Blade to Master; 'gtp-inter-pu-bld-to-mstr-dcmsg-
          sent'= GTP inter-PU Blade to Master dcmsg sent; 'gtp-inter-pu-bld-to-mstr-
          dcmsg-recv'= GTP inter-PU dcmsg received on Master; 'gtp-inter-pu-bld-to-mstr-
          query-sent'= GTP inter-PU query sent from Blade to Master; 'gtp-inter-pu-bld-
          to-mstr-query-recv'= GTP inter-PU GTP-C mesg received on Master; 'gtp-inter-pu-
          bld-to-mstr-query-resp-sent'= GTP inter-PU GTP-C query response sent from Blade
          to Master; 'gtp-mstr-to-bld-query-resp-fail'= GTP inter-PU dcmsg of query
          response failed from Master to Blade; 'gtp-bld-to-mstr-query-resp-fail'= GTP
          inter-PU dcmsg of query response failed from Blade to Master; 'gtp-c-smp-refer-
          stale-idx'= GTP-C SMP referring stale C-conn idx; 'gtp-smp-dec-sess-count-
          check-failed'= GTP-U session count is 0 in GTP-C SMP; 'gtp-c-freed-conn-check'=
          GTP-C freed conn accessed; 'gtp-c-conn-not-in-rml-when-freed'= GTP-C conn not
          in rml when tuple is freed; 'gtp-u-smp-check-failed'= GTP U-SMP check Failed;
          'gtp-c-smp-already-in-rml'= GTP-C smp already in rml; 'gtp-u-smp-already-in-
          rml'= GTP-U smp already in rml; 'gtp-info-ext-not-found'= GTP-Info ext not
          found while freeing C-smp; 'gtp-c-smp-unlink-from-hash-fail'= GTP-C smp unlink
          from hash table failed; 'gtp-u-smp-unlink-from-hash-fail'= GTP-U smp unlink
          from hash table failed; 'gtp-smp-link-to-hash-in-rml'= GTP smp linked to hash
          table when in rml; 'gtp-c-conn-ptr-not-found'= GTP-C conn ptr not found; 'gtp-
          smp-already-in-del-queue'= GTP SMP already in del queue, cannot be added again;
          'gtp-smp-path-already-in-del-queue'= GTP SMP-PATH already in del queue, cannot
          be added again; 'blade-gtp-c-smp-refer-stale-idx'= GTP-C SMP referring stale
          C-conn idx on PU2; 'blade-gtp-smp-dec-sess-count-check-failed'= GTP-U session
          count is 0 in GTP-C SMP on PU2; 'blade-gtp-c-freed-conn-check'= GTP-C freed
          conn accessed on PU2; 'blade-gtp-c-conn-not-in-rml-when-freed'= GTP-C conn not
          in rml when tuple is freed on PU2; 'blade-gtp-u-smp-check-failed'= GTP U-SMP
          check Failed on PU2; 'blade-gtp-c-smp-already-in-rml'= GTP-C smp already in rml
          on PU2; 'blade-gtp-u-smp-already-in-rml'= GTP-U smp already in rml on PU2;
          'blade-gtp-info-ext-not-found'= GTP-Info ext not found while freeing C-smp on
          PU2; 'blade-gtp-c-smp-unlink-from-hash-fail'= GTP-C smp unlink from hash table
          failed on PU2; 'blade-gtp-u-smp-unlink-from-hash-fail'= GTP-U smp unlink from
          hash table failed on PU2; 'blade-gtp-smp-link-to-hash-in-rml'= GTP smp linked
          to hash table when in rml on PU2; 'blade-gtp-c-conn-ptr-not-found'= GTP-C conn
          ptr not found on PU2; 'blade-gtp-smp-already-in-del-queue'= GTP SMP already in
          del queue, cannot be added again on PU2; 'blade-gtp-smp-path-already-in-del-
          queue'= GTP SMP-PATH already in del queue, cannot be added again on PU2; 'gtp-
          smp-double-free'= GTP SMP added twice to del queue; 'gtp-smp-path-double-free'=
          GTP SMP path added twice to del queue, cannot be added again; 'gtp-c-smp-not-
          found-in-hash'= GTP-C SMP not found in hash table to unlink; 'gtp-u-smp-not-
          found-in-hash'= GTP-U SMP not found in hash table to unlink; 'gtp-smp-already-
          in-UL-hash'= GTP SMP already linked in uplink hash; 'gtp-smp-already-in-DL-
          hash'= GTP SMP already linked in downlink hash; 'gtp-c-smp-in-rml-c-conn-age-
          upd'= GTP-C SMP in RML during C-conn age update; 'gtp-c-ref-count-max-smp-set-
          for-ageout'= GTP-C SMP set for deletion during age out with refcount max; 'gtp-
          c-smp-del-max-ref-count'= GTP-C SMP with del flag and max ref count during
          ageout; 'gtp-u-smp-unlinked-u-conn-creation'= GTP-U smp unlinked from HT while
          creating U-conn; 'blade-gtp-smp-double-free'= GTP SMP added twice to del queue
          on PU2; 'blade-gtp-smp-path-double-free'= GTP SMP path added twice to del queue
          on PU2, cannot be added again; 'blade-gtp-c-smp-not-found-in-hash'= GTP-C SMP
          not found in hash table to unlink on PU2; 'blade-gtp-u-smp-not-found-in-hash'=
          GTP-U SMP not found in hash table to unlink on PU2; 'blade-gtp-smp-already-in-
          UL-hash'= GTP SMP already linked in uplink hash on PU2; 'blade-gtp-smp-already-
          in-DL-hash'= GTP SMP already linked in downlink hash on PU2; 'blade-gtp-c-smp-
          in-rml-c-conn-age-upd'= GTP-C SMP in RML during C-conn age update on PU2;
          'blade-gtp-c-ref-count-max-smp-set-for-ageout'= GTP-C SMP set for deletion
          during age out with refcount max on PU2; 'blade-gtp-c-smp-del-max-ref-count'=
          GTP-C SMP with del flag and max ref count during ageout on PU2; 'blade-gtp-u-
          smp-unlinked-u-conn-creation'= GTP-U smp unlinked from HT while creating U-conn
          on PU2; 'gtp-u-stateless-forward'= GTP-U Stateless Forward; 'gtp-u-smp-not-
          found-conn-creation'= GTP-U smp not found during conn creation; 'gtp-u-match-c-
          smp-with-del-flag'= GTP-U match C-smp with deletion flag; 'gtp-u-match-c-smp-
          with-ho-flag'= GTP-U match C-smp with HO flag; 'gtp-u-match-dbr-u-smp-conn-
          create'= GTP-U match U-smp with dbr during conn creation; 'gtp-c-info-extract-
          failed'= unable to extract GTP-C extension during pkt processing; 'gtp-c-smp-
          extract-failed'= unable to extract GTP-C smp during pkt processing; 'gtp-u-
          info-extract-failed'= unable to extract GTP-U extension during pkt processing;
          'gtp-u-match-c-smp-in-rml'= GTP-U match C-smp in rml; 'blade-gtp-c-info-
          extract-failed'= unable to extract GTP-C extension during pkt processing on
          PU2; 'blade-gtp-c-smp-extract-failed'= unable to extract GTP-C smp during pkt
          processing on PU2; 'blade-gtp-u-info-extract-failed'= unable to extract GTP-U
          extension during pkt processing on PU2; 'blade-gtp-u-match-c-smp-in-rml'= GTP-U
          match C-smp in rml on PU2; 'gtp-echo-stateless-forward'= GTP-echo Stateless
          Forward; 'gtp-u-smp-not-found-c-processing'= unable to extract GTP-U smp not
          found in C-processing; 'gtp-u-pkt-u-smp-validation-failed'= gtp-u smp ip
          validation failed; 'blade-gtp-u-pkt-u-smp-validation-failed'= gtp-u smp ip
          validation failed on PU2; 'gtp-u-frag-pkt-processed'= GTP-U Fragmented packet
          processed; 'gtp-c-frag-pkt-received'= GTP-C Fragmented packet received; 'gtp-u-
          frag-pkt-received'= GTP-U Fragmented packet received; 'gtp-u-attempt-for-
          double-free'= GTP-U smp double free attempted; 'gtp-c-attempt-for-double-free'=
          GTP-C smp double free attempted; 'gtp-c-smp-access-after-reuse'= GTP-C smp
          access after reuse; 'gtp-u-smp-access-after-reuse'= GTP-U smp access after
          reuse; 'gtp-c-smp-cleared-by-standalone'= GTP-C smp cleared by standalone conn;
          'gtp-c-smp-cleared-by-l3-with-l5'= GTP-C smp cleared by l3-conn with l5;
          'blade-gtp-u-attempt-for-double-free'= GTP-U smp double free attempted on PU2;
          'blade-gtp-c-attempt-for-double-free'= GTP-C smp double free attempted on PU2;
          'blade-gtp-c-smp-access-after-reuse'= GTP-C smp access after reuse on PU2;
          'blade-gtp-u-smp-access-after-reuse'= GTP-U smp access after reuse on PU2;
          'blade-gtp-c-smp-cleared-by-standalone'= GTP-C smp cleared by standalone conn
          on PU2; 'blade-gtp-c-smp-cleared-by-l3-with-l5'= GTP-C smp cleared by l3-conn
          with l5 on PU2; 'blade-gtp-smp-session-count-check-failed'= GTP-U session count
          is not in range of 0-11 in GTP-C SMP on PU2; 'gtp-smp-no-action-with-u-create'=
          GTP-C SMP no action with u-create at inter-pu sync; 'blade-gtp-smp-no-action-
          with-u-create'= GTP-C SMP no action with u-create at inter-pu sync on PU2;
          'gtp-info-ext-not-packed'= GTP-C info not packed; 'gtp-sync-new-conn-create'=
          GTP-C sync new conn create;"
                type: str
            counters3:
                description:
                - "'gtp-smp-not-found-inter-pu'= GTP smp not found during inter-pu comm; 'blade-
          gtp-smp-not-found-inter-pu'= GTP smp not found during inter-pu comm on PU2;
          'gtp-inter-pu-u-create-sent'= GTP inter-pu U-creation sync sent; 'gtp-inter-pu-
          u-delete-sent'= GTP inter-pu U-deletion sync sent; 'gtp-inter-pu-c-query-sent'=
          GTP inter-pu C-query sync sent; 'blade-gtp-inter-pu-u-create-sent'= GTP inter-
          pu U-creation sync sent on PU2; 'blade-gtp-inter-pu-u-delete-sent'= GTP inter-
          pu U-deletion sync sent on PU2; 'blade-gtp-inter-pu-c-query-sent'= GTP inter-pu
          C-query sync sent on PU2; 'gtp-inter-pu-u-create-tx-fail'= GTP inter-pu
          U-creation tx fail; 'gtp-inter-pu-u-delete-tx-fail'= GTP inter-pu U-deletion tx
          fail; 'gtp-inter-pu-c-query-tx-fail'= GTP inter-pu C-query tx fail; 'blade-gtp-
          inter-pu-u-create-tx-fail'= GTP inter-pu U-creation tx fail on PU2; 'blade-gtp-
          inter-pu-u-delete-tx-fail'= GTP inter-pu U-deletion tx fail on PU2; 'blade-gtp-
          inter-pu-c-query-tx-fail'= GTP inter-pu C-query tx fail on PU2; 'gtp-inter-pu-
          u-create-recv'= GTP inter-pu U-creation recv; 'gtp-inter-pu-u-delete-recv'= GTP
          inter-pu U-deletion recv; 'gtp-inter-pu-c-query-recv'= GTP inter-pu C-mesg
          recv; 'blade-gtp-inter-pu-u-create-recv'= GTP inter-pu U-creation recv on PU2;
          'blade-gtp-inter-pu-u-delete-recv'= GTP inter-pu U-deletion recv on PU2;
          'blade-gtp-inter-pu-c-query-recv'= GTP inter-pu C-mesg recv on PU2; 'gtp-inter-
          pu-u-create-drop-no-smp'= GTP inter-pu U-create rx drop no smp; 'blade-gtp-
          inter-pu-u-create-drop-no-smp'= GTP inter-pu U-create rx drop no smp PU2; 'gtp-
          inter-pu-u-delete-drop-no-smp'= GTP inter-pu U-delete rx drop no smp; 'blade-
          gtp-inter-pu-u-delete-drop-no-smp'= GTP inter-pu U-delete rx drop no smp PU2;
          'gtp-inter-pu-u-create-error'= GTP inter-pu U-create rx drop with error;
          'blade-gtp-inter-pu-u-create-error'= GTP inter-pu U-create rx drop with error
          PU2; 'gtp-inter-pu-u-delete-error'= GTP inter-pu U-delete rx drop with error;
          'blade-gtp-inter-pu-u-delete-error'= GTP inter-pu U-delete rx drop with error
          PU2; 'gtp-inter-pu-no-rsp-to-query'= GTP inter-pu No response to query; 'blade-
          gtp-inter-pu-no-rsp-to-query'= GTP inter-pu No response to query on PU2; 'gtp-
          fwd-tuple-dst-updated'= GTP FWD tuple updated with dst; 'gtp-rev-tuple-dst-
          updated'= GTP REV tuple updated with dst; 'gtp-c-conn-with-no-dst'= GTP-C
          created on active with no dst; 'gtp-sync-rx-create-ext-bit-counter-inter-pu'=
          Conn Sync Create with Ext Received with inter-pu comm counter; 'gtp-query-pkt-
          tx-counter-gtp-c'= Conn Query GTP-C sent counter; 'gtp-query-pkt-tx-counter-
          gtp-u'= Conn Query GTP-U sent counter; 'gtp-query-pkt-tx-counter-gtp-echo'=
          Conn Query GTP-ECHO sent counter; 'gtp-sync-tx-inter-pu-no-vnp-error'= send of
          inter-pu msg failed with no vnp error; 'gtp-sync-tx-inter-pu-no-gtp-u-ext'=
          send of inter-pu msg failed with no GTP-U ext; 'gtp-sync-tx-inter-pu-no-ug-
          error'= send of inter-pu msg failed with no user group error; 'gtp-sync-tx-
          inter-pu-no-msg-hdr-error'= send of inter-pu msg failed as msg header ext
          failed; 'gtp-sync-tx-inter-pu-no-data-error'= send of inter-pu msg failed with
          no data to pack; 'gtp-sync-tx-fw-drop-session-create'= Conn Sync FW gtp Create
          Session Sent dropped; 'gtp-query-pkt-rx-counter-gtp-c'= Conn Query GTP-C recv
          counter; 'gtp-query-pkt-rx-counter-gtp-u'= Conn Query GTP-U recv counter; 'gtp-
          query-pkt-rx-counter-gtp-echo'= Conn Query GTP-ECHO recv counter; 'gtp-sync-rx-
          del-c-counter'= Conn Sync Del Session GTP-C Received counter; 'gtp-sync-rx-del-
          u-counter'= Conn Sync Del Session GTP-U Received counter; 'gtp-sync-rx-del-
          echo-counter'= Conn Sync Del Session ECHO Received counter; 'gtp-sync-rx-
          create-c-counter'= Conn Sync create Session GTP-C Received counter; 'gtp-sync-
          rx-create-u-counter'= Conn Sync create Session GTP-U Received counter; 'gtp-
          sync-rx-create-echo-counter'= Conn Sync create Session ECHO Received counter;
          'gtp-sync-tx-create-c-counter'= Conn Sync create Session GTP-C sent counter;
          'gtp-sync-tx-create-u-counter'= Conn Sync create Session GTP-U sent counter;
          'gtp-sync-tx-create-echo-counter'= Conn Sync create Session ECHO sent counter;
          'gtp-sync-tx-delete-c-counter'= Conn Sync delete Session GTP-C sent counter;
          'gtp-sync-tx-delete-u-counter'= Conn Sync delete Session GTP-U sent counter;
          'gtp-sync-tx-delete-echo-counter'= Conn Sync delete Session ECHO sent counter;
          'gtp-sync-rx-del-no-such-c-session'= Conn Sync Del C-Conn not Found; 'gtp-sync-
          rx-del-no-such-u-session'= Conn Sync Del U-Conn not Found; 'gtp-sync-rx-del-no-
          such-echo-session'= Conn Sync Del ECHO-Conn not Found; 'gtp-c-match-c-smp-with-
          del-flag'= GTP-C match C-smp with deletion flag; 'gtp-c-match-c-smp-with-ho-
          flag'= GTP-C match C-smp with HO flag; 'gtp-c-smp-sig-check-failed'= GTP-C SMP
          signature check Failed; 'blade-gtp-c-smp-sig-check-failed'= GTP-C SMP signature
          check Failed on PU2; 'gtp-u-smp-sig-check-failed'= GTP SMP signature check
          Failed; 'blade-gtp-u-smp-sig-check-failed'= GTP-U SMP signature check Failed on
          PU2; 'gtp-smp-sig-check-failed'= GTP SMP signature check Failed; 'blade-gtp-
          smp-sig-check-failed'= GTP SMP signature check Failed on PU2; 'gtp-c-fail-conn-
          create-slow'= GTP-C packet failed creating L4-session in slowpath; 'gtp-u-fail-
          conn-create-slow'= GTP-U packet failed while creating L4-session in slowpath;
          'gtp-pathm-fail-conn-create-slow'= GTP path packet failed while creating
          L4-session in slowpath; 'gtp-v0-c-uplink-ingress-packets'= GTPv0-C Uplink
          Ingress Packets; 'gtp-v0-c-uplink-egress-packets'= GTPv0-C Uplink Egress
          Packets; 'gtp-v0-c-downlink-ingress-packets'= GTPv0-C Downlink Ingress Packets;
          'gtp-v0-c-downlink-egress-packets'= GTPv0-C Downlink Egress Packets;
          'gtp-v0-c-uplink-ingress-bytes'= GTPv0-C Uplink Ingress Bytes;
          'gtp-v0-c-uplink-egress-bytes'= GTPv0-C Uplink Egress Bytes;
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
          Downlink Egress Bytes; 'gtp-v0-c-create-synced'= GTPv0-C Tunnel Create Synced;
          'gtp-v1-c-create-synced'= GTPv1-C Tunnel Create Synced; 'gtp-v2-c-create-
          synced'= GTPv2-C Tunnel Create Synced; 'gtp-v0-c-delete-synced'= GTPv0-C Tunnel
          Delete Synced;"
                type: str
            counters4:
                description:
                - "'gtp-v1-c-delete-synced'= GTPv1-C Tunnel Delete Synced; 'gtp-v2-c-delete-
          synced'= GTPv2-C Tunnel Delete Synced; 'gtp-v0-c-create-sync-rx'= GTPv0-C
          Tunnel Create Sync Received on Standby; 'gtp-v1-c-create-sync-rx'= GTPv1-C
          Tunnel Create Sync Received on Standby; 'gtp-v2-c-create-sync-rx'= GTPv2-C
          Tunnel Create Sync Received on Standby; 'gtp-v0-c-delete-sync-rx'= GTPv0-C
          Tunnel Delete Sync Received on Standby; 'gtp-v1-c-delete-sync-rx'= GTPv1-C
          Tunnel Delete Sync Received on Standby; 'gtp-v2-c-delete-sync-rx'= GTPv2-C
          Tunnel Delete Sync Received on Standby; 'gtp-handover-synced'= GTP Handover
          Synced; 'gtp-handover-sync-rx'= GTP Handover Sync Received on Standby; 'gtp-
          smp-add-bearer-synced'= GTP SMP Add Bearer Synced; 'gtp-smp-del-bearer-synced'=
          GTP SMP Del Bearer Synced; 'gtp-smp-additional-bearer-synced'= GTP SMP
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
          forwarded via monitor mode; 'gtp-u-monitor-forward'= GTP-U messages forwarded
          via monitor mode; 'gtp-u_inner-ip-not-present'= GTP-U inner IP not present;
          'gtp-ext_hdr-incorrect-length'= GTP Extension header incorrect length;"
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
                - "Out of Tunnel Memory for GTP-C"
                type: str
            no_fwd_route:
                description:
                - "No Forward Route for GTP-C"
                type: str
            no_rev_route:
                description:
                - "No Reverse Route for GTP-C"
                type: str
            blade_out_of_session_memory:
                description:
                - "Out of Tunnel Memory on PU2"
                type: str
            blade_no_fwd_route:
                description:
                - "No Forward Route on PU2"
                type: str
            blade_no_rev_route:
                description:
                - "No Reverse Route on PU2"
                type: str
            gtp_smp_path_check_failed:
                description:
                - "GTP SMP PATH check Failed"
                type: str
            gtp_smp_c_check_failed:
                description:
                - "GTP-C SMP check Failed"
                type: str
            blade_gtp_smp_path_check_failed:
                description:
                - "GTP SMP PATH check Failed on PU2"
                type: str
            blade_gtp_smp_c_check_failed:
                description:
                - "GTP-C SMP check Failed on PU2"
                type: str
            gtp_tunnel_rate_limit_entry_create_failure:
                description:
                - "GTP Tunnel Level Rate Limit Entry Create Failure"
                type: str
            gtp_u_tunnel_rate_limit_entry_create_failure:
                description:
                - "GTP-U Tunnel Level Rate Limit Entry Create Failure"
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
            blade_gtp_rate_limit_smp_create_failure:
                description:
                - "GTP Rate Limit SMP Create Failure on PU2"
                type: str
            blade_gtp_rate_limit_t3_ctr_create_failure:
                description:
                - "GTP Rate Limit Dynamic Counters Create Failure on PU2"
                type: str
            blade_gtp_rate_limit_entry_create_failure:
                description:
                - "GTP Rate Limit Entry Create Failure on PU2"
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
            drop_vld_gtp_u_echo_out_of_state_:
                description:
                - "GTP-U Echo Out of State Drop"
                type: str
            gtp_create_session_request_retx_drop:
                description:
                - "GTP-C Retransmitted Create Session Request dropped"
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
            gtp_u_rr_message_drop:
                description:
                - "GTP-U Message Dropped in RR Mode"
                type: str
            drop_gtp_frag_or_jumbo_pkt:
                description:
                - "GTP Fragmented or JUMBO packet Drop"
                type: str
            gtp_v0_c_ver_not_supp:
                description:
                - "GTPv0-C Version not supported indication"
                type: str
            gtp_v1_c_ver_not_supp:
                description:
                - "GTPv1-C Version not supported indication"
                type: str
            gtp_v2_c_ver_not_supp:
                description:
                - "GTPv2-C Version not supported indication"
                type: str
            gtp_c_handover_in_progress_with_conn:
                description:
                - "GTP-C mesg matching conn with HO In Progress"
                type: str
            gtp_c_conn_create_pkt_drop:
                description:
                - "GTP-C conn creation drop"
                type: str
            gtp_smp_dec_sess_count_check_failed:
                description:
                - "GTP-U session count is 0 in GTP-C SMP"
                type: str
            gtp_u_smp_check_failed:
                description:
                - "GTP U-SMP check Failed"
                type: str
            gtp_info_ext_not_found:
                description:
                - "GTP-Info ext not found while freeing C-smp"
                type: str
            blade_gtp_smp_dec_sess_count_check_failed:
                description:
                - "GTP-U session count is 0 in GTP-C SMP on PU2"
                type: str
            blade_gtp_u_smp_check_failed:
                description:
                - "GTP U-SMP check Failed on PU2"
                type: str
            blade_gtp_info_ext_not_found:
                description:
                - "GTP-Info ext not found while freeing C-smp on PU2"
                type: str
            gtp_u_stateless_forward:
                description:
                - "GTP-U Stateless Forward"
                type: str
            gtp_echo_stateless_forward:
                description:
                - "GTP-echo Stateless Forward"
                type: str
            gtp_u_frag_pkt_processed:
                description:
                - "GTP-U Fragmented packet processed"
                type: str
            gtp_c_frag_pkt_received:
                description:
                - "GTP-C Fragmented packet received"
                type: str
            gtp_u_frag_pkt_received:
                description:
                - "GTP-U Fragmented packet received"
                type: str
            blade_gtp_smp_session_count_check_failed:
                description:
                - "GTP-U session count is not in range of 0-11 in GTP-C SMP on PU2"
                type: str
            gtp_sync_tx_fw_drop_session_create:
                description:
                - "Conn Sync FW gtp Create Session Sent dropped"
                type: str
            gtp_c_smp_sig_check_failed:
                description:
                - "GTP-C SMP signature check Failed"
                type: str
            blade_gtp_c_smp_sig_check_failed:
                description:
                - "GTP-C SMP signature check Failed on PU2"
                type: str
            gtp_u_smp_sig_check_failed:
                description:
                - "GTP SMP signature check Failed"
                type: str
            blade_gtp_u_smp_sig_check_failed:
                description:
                - "GTP-U SMP signature check Failed on PU2"
                type: str
            gtp_smp_sig_check_failed:
                description:
                - "GTP SMP signature check Failed"
                type: str
            blade_gtp_smp_sig_check_failed:
                description:
                - "GTP SMP signature check Failed on PU2"
                type: str
            gtp_c_fail_conn_create_slow:
                description:
                - "GTP-C packet failed creating L4-session in slowpath"
                type: str
            gtp_u_fail_conn_create_slow:
                description:
                - "GTP-U packet failed while creating L4-session in slowpath"
                type: str
            gtp_pathm_fail_conn_create_slow:
                description:
                - "GTP path packet failed while creating L4-session in slowpath"
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
            gtp_u_monitor_forward:
                description:
                - "GTP-U messages forwarded via monitor mode"
                type: str
            gtp_ext_hdr_incorrect_length:
                description:
                - "GTP Extension header incorrect length"
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
AVAILABLE_PROPERTIES = ["apn_log_periodicity", "apn_prefix", "apn_prefix_list", "echo_timeout", "gtp_value", "insertion_mode", "ne_v4_log_periodicity", "ne_v6_log_periodicity", "network_element", "network_element_list_v4", "network_element_list_v6", "path_mgmt_logging", "sampling_enable", "stats", "uuid", ]


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
                    'all', 'out-of-session-memory', 'no-fwd-route', 'no-rev-route', 'blade-out-of-session-memory', 'blade-no-fwd-route', 'blade-no-rev-route', 'gtp-smp-created', 'gtp-smp-marked-deleted', 'gtp-smp-deleted', 'smp-creation-failed', 'gtp-smp-path-created', 'gtp-smp-path-freed', 'gtp-smp-path-allocated', 'gtp-smp-path-creation-failed',
                    'gtp-smp-path-check-failed', 'gtp-smp-c-check-failed', 'blade-gtp-smp-created', 'blade-gtp-smp-marked-deleted', 'blade-gtp-smp-deleted', 'blade-smp-creation-failed', 'blade-gtp-smp-path-created', 'blade-gtp-smp-path-freed', 'blade-gtp-smp-path-allocated', 'blade-gtp-smp-path-creation-failed', 'blade-gtp-smp-path-check-failed',
                    'blade-gtp-smp-c-check-failed', 'gtp-smp-session-count-check-failed', 'gtp-c-ref-count-smp-exceeded', 'blade-gtp-c-ref-count-smp-exceeded', 'gtp-u-smp-in-rml-with-sess', 'blade-gtp-u-smp-in-rml-with-sess', 'gtp-u-pkt-fwd-conn-create', 'gtp-c-pkt-fwd-conn-create', 'gtp-echo-pkt-fwd-conn-create',
                    'gtp-tunnel-rate-limit-entry-create-success', 'gtp-tunnel-rate-limit-entry-inc-ref-count', 'gtp-tunnel-rate-limit-entry-create-failure', 'gtp-tunnel-rate-limit-entry-deleted', 'gtp-u-tunnel-rate-limit-entry-create-success', 'gtp-u-tunnel-rate-limit-entry-inc-ref-count', 'gtp-u-tunnel-rate-limit-entry-create-failure',
                    'gtp-u-tunnel-rate-limit-entry-deleted', 'gtp-rate-limit-smp-created', 'gtp-rate-limit-smp-freed', 'gtp-rate-limit-smp-create-failure', 'gtp-rate-limit-t3-ctr-create-failure', 'gtp-rate-limit-entry-create-failure', 'blade-gtp-rate-limit-smp-created', 'blade-gtp-rate-limit-smp-freed', 'blade-gtp-rate-limit-smp-create-failure',
                    'blade-gtp-rate-limit-t3-ctr-create-failure', 'blade-gtp-rate-limit-entry-create-failure', 'gtp-echo-conn-created', 'gtp-echo-conn-deleted', 'gtp-node-restart-echo', 'gtp-c-echo-path-failure', 'drop-vld-gtp-echo-out-of-state-', 'drop-vld-gtp-echo-ie-len-exceed-msg-len', 'drop-vld-gtp-u-echo-out-of-state-',
                    'gtp-create-session-request-retransmit', 'gtp-add-bearer-request-retransmit', 'gtp-delete-session-request-retransmit', 'gtp-handover-request-retransmit', 'gtp-del-bearer-request-retransmit', 'gtp-add-bearer-response-retransmit', 'gtp-create-session-request-retx-drop', 'gtp-u-out-of-state-drop',
                    'gtp-c-handover-request-out-of-state-drop', 'gtp-v1-c-nsapi-not-found-in-delete-req', 'gtp-v2-c-bearer-not-found-in-delete-req', 'gtp-v2-c-bearer-not-found-in-delete-resp', 'gtp-multiple-handover-request', 'gtp-rr-message-drop', 'gtp-u-rr-message-drop', 'gtp-rr-echo-message-dcmsg', 'gtp-rr-c-message-dcmsg',
                    'drop-gtp-frag-or-jumbo-pkt', 'response-with-reject-cause-forwarded', 'gtp-c-message-forwarded-without-conn', 'gtp-v0-c-ver-not-supp', 'gtp-v1-c-ver-not-supp', 'gtp-v2-c-ver-not-supp', 'gtp-v1-extn-hdt-notif', 'gtp-u-error-ind', 'gtp-c-handover-in-progress-with-conn', 'gtp-ho-in-progress-handover-request',
                    'gtp-correct-conn-ho-in-progress-handover-request', 'gtp-wrong-conn-ho-in-progress-handover-request', 'gtp-ho-in-progress-handover-response', 'gtp-ho-in-progress-c-mesg', 'gtp-unset-ho-flag-reuse-teid', 'gtp-refresh-c-conn-reuse-teid', 'gtp-rematch-smp-matching-conn', 'gtp-wrong-conn-handover-request',
                    'gtp-refresh-conn-set-ho-flag-latest', 'gtp-c-process-pkt-drop', 'gtp-c-fwd-pkt-drop', 'gtp-c-rev-pkt-drop', 'gtp-c-fwd-v1-other', 'gtp-c-fwd-v2-other', 'gtp-c-rev-v1-other', 'gtp-c-rev-v2-other', 'gtp-c-going-thru-fw-lookup', 'gtp-c-conn-create-pkt-drop', 'gtp-c-pkt-fwd-conn-create-no-fteid',
                    'gtp-inter-pu-mstr-to-bld-dcmsg-fail', 'gtp-inter-pu-mstr-to-bld-dcmsg-sent'
                    ]
                },
            'counters2': {
                'type':
                'str',
                'choices': [
                    'gtp-inter-pu-mstr-to-bld-dcmsg-recv', 'gtp-inter-pu-mstr-to-bld-query-sent', 'gtp-inter-pu-mstr-to-bld-query-recv', 'gtp-inter-pu-mstr-to-bld-query-resp-sent', 'gtp-inter-pu-bld-to-mstr-dcmsg-fail', 'gtp-inter-pu-bld-to-mstr-dcmsg-sent', 'gtp-inter-pu-bld-to-mstr-dcmsg-recv', 'gtp-inter-pu-bld-to-mstr-query-sent',
                    'gtp-inter-pu-bld-to-mstr-query-recv', 'gtp-inter-pu-bld-to-mstr-query-resp-sent', 'gtp-mstr-to-bld-query-resp-fail', 'gtp-bld-to-mstr-query-resp-fail', 'gtp-c-smp-refer-stale-idx', 'gtp-smp-dec-sess-count-check-failed', 'gtp-c-freed-conn-check', 'gtp-c-conn-not-in-rml-when-freed', 'gtp-u-smp-check-failed',
                    'gtp-c-smp-already-in-rml', 'gtp-u-smp-already-in-rml', 'gtp-info-ext-not-found', 'gtp-c-smp-unlink-from-hash-fail', 'gtp-u-smp-unlink-from-hash-fail', 'gtp-smp-link-to-hash-in-rml', 'gtp-c-conn-ptr-not-found', 'gtp-smp-already-in-del-queue', 'gtp-smp-path-already-in-del-queue', 'blade-gtp-c-smp-refer-stale-idx',
                    'blade-gtp-smp-dec-sess-count-check-failed', 'blade-gtp-c-freed-conn-check', 'blade-gtp-c-conn-not-in-rml-when-freed', 'blade-gtp-u-smp-check-failed', 'blade-gtp-c-smp-already-in-rml', 'blade-gtp-u-smp-already-in-rml', 'blade-gtp-info-ext-not-found', 'blade-gtp-c-smp-unlink-from-hash-fail',
                    'blade-gtp-u-smp-unlink-from-hash-fail', 'blade-gtp-smp-link-to-hash-in-rml', 'blade-gtp-c-conn-ptr-not-found', 'blade-gtp-smp-already-in-del-queue', 'blade-gtp-smp-path-already-in-del-queue', 'gtp-smp-double-free', 'gtp-smp-path-double-free', 'gtp-c-smp-not-found-in-hash', 'gtp-u-smp-not-found-in-hash',
                    'gtp-smp-already-in-UL-hash', 'gtp-smp-already-in-DL-hash', 'gtp-c-smp-in-rml-c-conn-age-upd', 'gtp-c-ref-count-max-smp-set-for-ageout', 'gtp-c-smp-del-max-ref-count', 'gtp-u-smp-unlinked-u-conn-creation', 'blade-gtp-smp-double-free', 'blade-gtp-smp-path-double-free', 'blade-gtp-c-smp-not-found-in-hash',
                    'blade-gtp-u-smp-not-found-in-hash', 'blade-gtp-smp-already-in-UL-hash', 'blade-gtp-smp-already-in-DL-hash', 'blade-gtp-c-smp-in-rml-c-conn-age-upd', 'blade-gtp-c-ref-count-max-smp-set-for-ageout', 'blade-gtp-c-smp-del-max-ref-count', 'blade-gtp-u-smp-unlinked-u-conn-creation', 'gtp-u-stateless-forward',
                    'gtp-u-smp-not-found-conn-creation', 'gtp-u-match-c-smp-with-del-flag', 'gtp-u-match-c-smp-with-ho-flag', 'gtp-u-match-dbr-u-smp-conn-create', 'gtp-c-info-extract-failed', 'gtp-c-smp-extract-failed', 'gtp-u-info-extract-failed', 'gtp-u-match-c-smp-in-rml', 'blade-gtp-c-info-extract-failed', 'blade-gtp-c-smp-extract-failed',
                    'blade-gtp-u-info-extract-failed', 'blade-gtp-u-match-c-smp-in-rml', 'gtp-echo-stateless-forward', 'gtp-u-smp-not-found-c-processing', 'gtp-u-pkt-u-smp-validation-failed', 'blade-gtp-u-pkt-u-smp-validation-failed', 'gtp-u-frag-pkt-processed', 'gtp-c-frag-pkt-received', 'gtp-u-frag-pkt-received', 'gtp-u-attempt-for-double-free',
                    'gtp-c-attempt-for-double-free', 'gtp-c-smp-access-after-reuse', 'gtp-u-smp-access-after-reuse', 'gtp-c-smp-cleared-by-standalone', 'gtp-c-smp-cleared-by-l3-with-l5', 'blade-gtp-u-attempt-for-double-free', 'blade-gtp-c-attempt-for-double-free', 'blade-gtp-c-smp-access-after-reuse', 'blade-gtp-u-smp-access-after-reuse',
                    'blade-gtp-c-smp-cleared-by-standalone', 'blade-gtp-c-smp-cleared-by-l3-with-l5', 'blade-gtp-smp-session-count-check-failed', 'gtp-smp-no-action-with-u-create', 'blade-gtp-smp-no-action-with-u-create', 'gtp-info-ext-not-packed', 'gtp-sync-new-conn-create'
                    ]
                },
            'counters3': {
                'type':
                'str',
                'choices': [
                    'gtp-smp-not-found-inter-pu', 'blade-gtp-smp-not-found-inter-pu', 'gtp-inter-pu-u-create-sent', 'gtp-inter-pu-u-delete-sent', 'gtp-inter-pu-c-query-sent', 'blade-gtp-inter-pu-u-create-sent', 'blade-gtp-inter-pu-u-delete-sent', 'blade-gtp-inter-pu-c-query-sent', 'gtp-inter-pu-u-create-tx-fail', 'gtp-inter-pu-u-delete-tx-fail',
                    'gtp-inter-pu-c-query-tx-fail', 'blade-gtp-inter-pu-u-create-tx-fail', 'blade-gtp-inter-pu-u-delete-tx-fail', 'blade-gtp-inter-pu-c-query-tx-fail', 'gtp-inter-pu-u-create-recv', 'gtp-inter-pu-u-delete-recv', 'gtp-inter-pu-c-query-recv', 'blade-gtp-inter-pu-u-create-recv', 'blade-gtp-inter-pu-u-delete-recv',
                    'blade-gtp-inter-pu-c-query-recv', 'gtp-inter-pu-u-create-drop-no-smp', 'blade-gtp-inter-pu-u-create-drop-no-smp', 'gtp-inter-pu-u-delete-drop-no-smp', 'blade-gtp-inter-pu-u-delete-drop-no-smp', 'gtp-inter-pu-u-create-error', 'blade-gtp-inter-pu-u-create-error', 'gtp-inter-pu-u-delete-error', 'blade-gtp-inter-pu-u-delete-error',
                    'gtp-inter-pu-no-rsp-to-query', 'blade-gtp-inter-pu-no-rsp-to-query', 'gtp-fwd-tuple-dst-updated', 'gtp-rev-tuple-dst-updated', 'gtp-c-conn-with-no-dst', 'gtp-sync-rx-create-ext-bit-counter-inter-pu', 'gtp-query-pkt-tx-counter-gtp-c', 'gtp-query-pkt-tx-counter-gtp-u', 'gtp-query-pkt-tx-counter-gtp-echo',
                    'gtp-sync-tx-inter-pu-no-vnp-error', 'gtp-sync-tx-inter-pu-no-gtp-u-ext', 'gtp-sync-tx-inter-pu-no-ug-error', 'gtp-sync-tx-inter-pu-no-msg-hdr-error', 'gtp-sync-tx-inter-pu-no-data-error', 'gtp-sync-tx-fw-drop-session-create', 'gtp-query-pkt-rx-counter-gtp-c', 'gtp-query-pkt-rx-counter-gtp-u',
                    'gtp-query-pkt-rx-counter-gtp-echo', 'gtp-sync-rx-del-c-counter', 'gtp-sync-rx-del-u-counter', 'gtp-sync-rx-del-echo-counter', 'gtp-sync-rx-create-c-counter', 'gtp-sync-rx-create-u-counter', 'gtp-sync-rx-create-echo-counter', 'gtp-sync-tx-create-c-counter', 'gtp-sync-tx-create-u-counter', 'gtp-sync-tx-create-echo-counter',
                    'gtp-sync-tx-delete-c-counter', 'gtp-sync-tx-delete-u-counter', 'gtp-sync-tx-delete-echo-counter', 'gtp-sync-rx-del-no-such-c-session', 'gtp-sync-rx-del-no-such-u-session', 'gtp-sync-rx-del-no-such-echo-session', 'gtp-c-match-c-smp-with-del-flag', 'gtp-c-match-c-smp-with-ho-flag', 'gtp-c-smp-sig-check-failed',
                    'blade-gtp-c-smp-sig-check-failed', 'gtp-u-smp-sig-check-failed', 'blade-gtp-u-smp-sig-check-failed', 'gtp-smp-sig-check-failed', 'blade-gtp-smp-sig-check-failed', 'gtp-c-fail-conn-create-slow', 'gtp-u-fail-conn-create-slow', 'gtp-pathm-fail-conn-create-slow', 'gtp-v0-c-uplink-ingress-packets', 'gtp-v0-c-uplink-egress-packets',
                    'gtp-v0-c-downlink-ingress-packets', 'gtp-v0-c-downlink-egress-packets', 'gtp-v0-c-uplink-ingress-bytes', 'gtp-v0-c-uplink-egress-bytes', 'gtp-v0-c-downlink-ingress-bytes', 'gtp-v0-c-downlink-egress-bytes', 'gtp-v1-c-uplink-ingress-packets', 'gtp-v1-c-uplink-egress-packets', 'gtp-v1-c-downlink-ingress-packets',
                    'gtp-v1-c-downlink-egress-packets', 'gtp-v1-c-uplink-ingress-bytes', 'gtp-v1-c-uplink-egress-bytes', 'gtp-v1-c-downlink-ingress-bytes', 'gtp-v1-c-downlink-egress-bytes', 'gtp-v2-c-uplink-ingress-packets', 'gtp-v2-c-uplink-egress-packets', 'gtp-v2-c-downlink-ingress-packets', 'gtp-v2-c-downlink-egress-packets',
                    'gtp-v2-c-uplink-ingress-bytes', 'gtp-v2-c-uplink-egress-bytes', 'gtp-v2-c-downlink-ingress-bytes', 'gtp-v2-c-downlink-egress-bytes', 'gtp-u-uplink-ingress-packets', 'gtp-u-uplink-egress-packets', 'gtp-u-downlink-ingress-packets', 'gtp-u-downlink-egress-packets', 'gtp-u-uplink-ingress-bytes', 'gtp-u-uplink-egress-bytes',
                    'gtp-u-downlink-ingress-bytes', 'gtp-u-downlink-egress-bytes', 'gtp-v0-c-create-synced', 'gtp-v1-c-create-synced', 'gtp-v2-c-create-synced', 'gtp-v0-c-delete-synced'
                    ]
                },
            'counters4': {
                'type':
                'str',
                'choices': [
                    'gtp-v1-c-delete-synced', 'gtp-v2-c-delete-synced', 'gtp-v0-c-create-sync-rx', 'gtp-v1-c-create-sync-rx', 'gtp-v2-c-create-sync-rx', 'gtp-v0-c-delete-sync-rx', 'gtp-v1-c-delete-sync-rx', 'gtp-v2-c-delete-sync-rx', 'gtp-handover-synced', 'gtp-handover-sync-rx', 'gtp-smp-add-bearer-synced', 'gtp-smp-del-bearer-synced',
                    'gtp-smp-additional-bearer-synced', 'gtp-smp-add-bearer-sync-rx', 'gtp-smp-del-bearer-sync-rx', 'gtp-smp-additional-bearer-sync-rx', 'gtp-add-bearer-sync-not-rx-on-standby', 'gtp-add-bearer-sync-with-periodic-update-on-standby', 'gtp-delete-bearer-sync-with-periodic-update-on-standby', 'gtp-v0-c-echo-create-synced',
                    'gtp-v1-c-echo-create-synced', 'gtp-v2-c-echo-create-synced', 'gtp-v0-c-echo-create-sync-rx', 'gtp-v1-c-echo-create-sync-rx', 'gtp-v2-c-echo-create-sync-rx', 'gtp-v0-c-echo-del-synced', 'gtp-v1-c-echo-del-synced', 'gtp-v2-c-echo-del-synced', 'gtp-v0-c-echo-del-sync-rx', 'gtp-v1-c-echo-del-sync-rx', 'gtp-v2-c-echo-del-sync-rx',
                    'drop-gtp-conn-creation-standby', 'gtp-u-synced-before-control', 'gtp-c-l5-synced-before-l3', 'gtp-smp-path-del-synced', 'gtp-smp-path-del-sync-rx', 'gtp-not-enabled-on-standby', 'gtp-ip-version-v4-v6', 'drop-gtp-ip-version-mismatch-fteid', 'drop-gtp-ip-version-mismatch-ho-fteid', 'gtp-u-message-length-mismatch',
                    'gtp-path-message-length-mismatch', 'drop-gtp-missing-cond-ie-bearer-ctx', 'drop-gtp-bearer-not-found-in-resp', 'gtp-stateless-forward', 'gtp-l3-conn-deleted', 'gtp-l5-conn-created', 'gtp-monitor-forward', 'gtp-u-monitor-forward', 'gtp-u_inner-ip-not-present', 'gtp-ext_hdr-incorrect-length'
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
            'blade_out_of_session_memory': {
                'type': 'str',
                },
            'blade_no_fwd_route': {
                'type': 'str',
                },
            'blade_no_rev_route': {
                'type': 'str',
                },
            'gtp_smp_path_check_failed': {
                'type': 'str',
                },
            'gtp_smp_c_check_failed': {
                'type': 'str',
                },
            'blade_gtp_smp_path_check_failed': {
                'type': 'str',
                },
            'blade_gtp_smp_c_check_failed': {
                'type': 'str',
                },
            'gtp_tunnel_rate_limit_entry_create_failure': {
                'type': 'str',
                },
            'gtp_u_tunnel_rate_limit_entry_create_failure': {
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
            'blade_gtp_rate_limit_smp_create_failure': {
                'type': 'str',
                },
            'blade_gtp_rate_limit_t3_ctr_create_failure': {
                'type': 'str',
                },
            'blade_gtp_rate_limit_entry_create_failure': {
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
            'drop_vld_gtp_u_echo_out_of_state_': {
                'type': 'str',
                },
            'gtp_create_session_request_retx_drop': {
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
            'gtp_u_rr_message_drop': {
                'type': 'str',
                },
            'drop_gtp_frag_or_jumbo_pkt': {
                'type': 'str',
                },
            'gtp_v0_c_ver_not_supp': {
                'type': 'str',
                },
            'gtp_v1_c_ver_not_supp': {
                'type': 'str',
                },
            'gtp_v2_c_ver_not_supp': {
                'type': 'str',
                },
            'gtp_c_handover_in_progress_with_conn': {
                'type': 'str',
                },
            'gtp_c_conn_create_pkt_drop': {
                'type': 'str',
                },
            'gtp_smp_dec_sess_count_check_failed': {
                'type': 'str',
                },
            'gtp_u_smp_check_failed': {
                'type': 'str',
                },
            'gtp_info_ext_not_found': {
                'type': 'str',
                },
            'blade_gtp_smp_dec_sess_count_check_failed': {
                'type': 'str',
                },
            'blade_gtp_u_smp_check_failed': {
                'type': 'str',
                },
            'blade_gtp_info_ext_not_found': {
                'type': 'str',
                },
            'gtp_u_stateless_forward': {
                'type': 'str',
                },
            'gtp_echo_stateless_forward': {
                'type': 'str',
                },
            'gtp_u_frag_pkt_processed': {
                'type': 'str',
                },
            'gtp_c_frag_pkt_received': {
                'type': 'str',
                },
            'gtp_u_frag_pkt_received': {
                'type': 'str',
                },
            'blade_gtp_smp_session_count_check_failed': {
                'type': 'str',
                },
            'gtp_sync_tx_fw_drop_session_create': {
                'type': 'str',
                },
            'gtp_c_smp_sig_check_failed': {
                'type': 'str',
                },
            'blade_gtp_c_smp_sig_check_failed': {
                'type': 'str',
                },
            'gtp_u_smp_sig_check_failed': {
                'type': 'str',
                },
            'blade_gtp_u_smp_sig_check_failed': {
                'type': 'str',
                },
            'gtp_smp_sig_check_failed': {
                'type': 'str',
                },
            'blade_gtp_smp_sig_check_failed': {
                'type': 'str',
                },
            'gtp_c_fail_conn_create_slow': {
                'type': 'str',
                },
            'gtp_u_fail_conn_create_slow': {
                'type': 'str',
                },
            'gtp_pathm_fail_conn_create_slow': {
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
            'gtp_u_monitor_forward': {
                'type': 'str',
                },
            'gtp_ext_hdr_incorrect_length': {
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
                    'u_uplink_bytes': {
                        'type': 'str',
                        },
                    'u_downlink_bytes': {
                        'type': 'str',
                        },
                    'u_uplink_pkts': {
                        'type': 'str',
                        },
                    'u_downlink_pkts': {
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
                    'vld_message_monitor': {
                        'type': 'str',
                        },
                    'gen_message_length_monitor': {
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
                    'flt_message_monitor': {
                        'type': 'str',
                        },
                    'rat_flt_message_monitor': {
                        'type': 'str',
                        },
                    'apn_imsi_flt_message_monitor': {
                        'type': 'str',
                        },
                    'msisdn_flt_message_monitor': {
                        'type': 'str',
                        },
                    'gtp_in_gtp_flt_message_monitor': {
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
                        },
                    'rl_message_monitor': {
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
                    'u_uplink_bytes': {
                        'type': 'str',
                        },
                    'u_downlink_bytes': {
                        'type': 'str',
                        },
                    'u_uplink_pkts': {
                        'type': 'str',
                        },
                    'u_downlink_pkts': {
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
                    'vld_message_monitor': {
                        'type': 'str',
                        },
                    'gen_message_length_monitor': {
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
                    'flt_message_monitor': {
                        'type': 'str',
                        },
                    'rat_flt_message_monitor': {
                        'type': 'str',
                        },
                    'apn_imsi_flt_message_monitor': {
                        'type': 'str',
                        },
                    'msisdn_flt_message_monitor': {
                        'type': 'str',
                        },
                    'gtp_in_gtp_flt_message_monitor': {
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
                        },
                    'rl_message_monitor': {
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
