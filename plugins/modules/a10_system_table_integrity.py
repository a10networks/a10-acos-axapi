#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_system_table_integrity
description:
    - Table integrity for multi-processing unit devices
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
    table:
        description:
        - "'all'= All tables;"
        type: str
        required: False
    audit_action:
        description:
        - "'enable'= Enable table integrity audit; 'disable'= Disable table integrity
          audit;"
        type: str
        required: False
    auto_sync_action:
        description:
        - "'enable'= Enable auto-sync; 'disable'= Disable auto-sync;"
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
                - "'all'= all; 'arp-tbl-sync-start-ts-m-1st'= arp table sync start time stamp
          master; 'nd6-tbl-sync-start-ts-m-1st'= nd6 table sync start time stamp master;
          'ipv4-fib-tbl-sync-start-ts-m-1st'= ipv4-fib table sync start time stamp
          master; 'ipv6-fib-tbl-sync-start-ts-m-1st'= ipv6-fib table sync start time
          stamp master; 'mac-tbl-sync-start-ts-m-1st'= mac table sync start time stamp
          master; 'arp-tbl-sync-start-ts-b-1st'= arp table sync start time stamp blade;
          'nd6-tbl-sync-start-ts-b-1st'= nd6 table sync start time stamp blade;
          'ipv4-fib-tbl-sync-start-ts-b-1st'= ipv4-fib table sync start time stamp blade;
          'ipv6-fib-tbl-sync-start-ts-b-1st'= ipv6-fib table sync start time stamp blade;
          'mac-tbl-sync-start-ts-b-1st'= mac table sync start time stamp blade; 'arp-tbl-
          sync-entries-sent-m-1st'= arp table entries sent from master for T0
          synchronization; 'nd6-tbl-sync-entries-sent-m-1st'= nd6 table entries sent from
          master for T0 synchronization; 'ipv4-fib-tbl-sync-entries-sent-m-1st'= ipv4-fib
          table entries sent from master for T0 synchronization; 'ipv6-fib-tbl-sync-
          entries-sent-m-1st'= ipv6-fib table entries sent from master for T0
          synchronization; 'mac-tbl-sync-entries-sent-m-1st'= mac table entries sent from
          master for T0 synchronization; 'arp-tbl-sync-entries-rcvd-b-1st'= arp table
          entries received on blade for T0 synchronization; 'nd6-tbl-sync-entries-
          rcvd-b-1st'= nd6 table entries received on blade for T0 synchronization;
          'ipv4-fib-tbl-sync-entries-rcvd-b-1st'= ipv4-fib table entries received on
          blade for T0 synchronization; 'ipv6-fib-tbl-sync-entries-rcvd-b-1st'= ipv6-fib
          table entries received on blade for T0 synchronization; 'mac-tbl-sync-entries-
          rcvd-b-1st'= mac table entries received on blade for T0 synchronization; 'arp-
          tbl-sync-entries-added-b-1st'= arp table entries added on blade for T0
          synchronization; 'nd6-tbl-sync-entries-added-b-1st'= nd6 table entries added on
          blade for T0 synchronization; 'ipv4-fib-tbl-sync-entries-added-b-1st'= ipv4-fib
          table entries added on blade for T0 synchronization; 'ipv6-fib-tbl-sync-
          entries-added-b-1st'= ipv6-fib table entries added on blade for T0
          synchronization; 'mac-tbl-sync-entries-added-b-1st'= mac table entries added on
          blade for T0 synchronization; 'arp-tbl-sync-entries-removed-b-1st'= arp table
          entries removed on blade for T0 synchronization; 'nd6-tbl-sync-entries-
          removed-b-1st'= arp table entries removed on blade for T0 synchronization;
          'ipv4-fib-tbl-sync-entries-removed-b-1st'= arp table entries removed on blade
          for T0 synchronization; 'ipv6-fib-tbl-sync-entries-removed-b-1st'= arp table
          entries removed on blade for T0 synchronization; 'mac-tbl-sync-entries-
          removed-b-1st'= arp table entries removed on blade for T0 synchronization;
          'arp-tbl-sync-end-ts-m-1st'= arp table sync end time stamp master for T0
          synchronization; 'nd6-tbl-sync-end-ts-m-1st'= nd6 table sync end time stamp
          master for T0 synchronization; 'ipv4-fib-tbl-sync-end-ts-m-1st'= ipv4-fib table
          sync end time stamp master for T0 synchronization; 'ipv6-fib-tbl-sync-end-
          ts-m-1st'= ipv6-fib table sync end time stamp master for T0 synchronization;
          'mac-tbl-sync-end-ts-m-1st'= mac table sync end time stamp master for T0
          synchronization; 'arp-tbl-sync-end-ts-b-1st'= arp table sync end time stamp
          blade for T0 synchronization; 'nd6-tbl-sync-end-ts-b-1st'= nd6 table sync end
          time stamp blade for T0 synchronization; 'ipv4-fib-tbl-sync-end-ts-b-1st'=
          ipv4-fib table sync end time stamp blade for T0 synchronization; 'ipv6-fib-tbl-
          sync-end-ts-b-1st'= ipv6-fib table sync end time stamp blade for T0
          synchronization; 'mac-tbl-sync-end-ts-b-1st'= mac table sync end time stamp
          blade for T0 synchronization; 'arp-tbl-sync-start-ts-m-2nd'= arp table sync
          start time stamp master for T-1 synchronization; 'nd6-tbl-sync-start-ts-m-2nd'=
          nd6 table sync start time stamp master for T-1 synchronization; 'ipv4-fib-tbl-
          sync-start-ts-m-2nd'= ipv4-fib table sync start time stamp master for T-1
          synchronization; 'ipv6-fib-tbl-sync-start-ts-m-2nd'= ipv6-fib table sync start
          time stamp master for T-1 synchronization; 'mac-tbl-sync-start-ts-m-2nd'= mac
          table sync start time stamp master for T-1 synchronization; 'arp-tbl-sync-
          start-ts-b-2nd'= arp table sync start time stamp blade for T-1 synchronization;
          'nd6-tbl-sync-start-ts-b-2nd'= nd6 table sync start time stamp blade for T-1
          synchronization; 'ipv4-fib-tbl-sync-start-ts-b-2nd'= ipv4-fib table sync start
          time stamp blade for T-1 synchronization; 'ipv6-fib-tbl-sync-start-ts-b-2nd'=
          ipv6-fib table sync start time stamp blade for T-1 synchronization; 'mac-tbl-
          sync-start-ts-b-2nd'= mac table sync start time stamp blade for T-1
          synchronization; 'arp-tbl-sync-entries-sent-m-2nd'= arp table entries sent from
          master for T-1 synchronization; 'nd6-tbl-sync-entries-sent-m-2nd'= nd6 table
          entries sent from master for T-1 synchronization; 'ipv4-fib-tbl-sync-entries-
          sent-m-2nd'= ipv4-fib table entries sent from master for T-1 synchronization;
          'ipv6-fib-tbl-sync-entries-sent-m-2nd'= ipv6-fib table entries sent from master
          for T-1 synchronization; 'mac-tbl-sync-entries-sent-m-2nd'= mac table entries
          sent from master for T-1 synchronization; 'arp-tbl-sync-entries-rcvd-b-2nd'=
          arp table entries received in blade for T-1 synchronization; 'nd6-tbl-sync-
          entries-rcvd-b-2nd'= nd6 table entries received in blade for T-1
          synchronization; 'ipv4-fib-tbl-sync-entries-rcvd-b-2nd'= ipv4-fib table entries
          received in blade for T-1 synchronization; 'ipv6-fib-tbl-sync-entries-
          rcvd-b-2nd'= ipv6-fib table entries received in blade for T-1 synchronization;
          'mac-tbl-sync-entries-rcvd-b-2nd'= mac table entries received in blade for T-1
          synchronization; 'arp-tbl-sync-entries-added-b-2nd'= arp table entries added in
          blade for T-1 synchronization; 'nd6-tbl-sync-entries-added-b-2nd'= nd6 table
          entries added in blade for T-1 synchronization; 'ipv4-fib-tbl-sync-entries-
          added-b-2nd'= ipv4-fib table entries added in blade for T-1 synchronization;
          'ipv6-fib-tbl-sync-entries-added-b-2nd'= ipv6-fib table entries added in blade
          for T-1 synchronization; 'mac-tbl-sync-entries-added-b-2nd'= mac table entries
          added in blade for T-1 synchronization; 'arp-tbl-sync-entries-removed-b-2nd'=
          arp table entries removed in blade for T-1 synchronization; 'nd6-tbl-sync-
          entries-removed-b-2nd'= nd6 table entries removed in blade for T-1
          synchronization; 'ipv4-fib-tbl-sync-entries-removed-b-2nd'= ipv4-fib table
          entries removed in blade for T-1 synchronization; 'ipv6-fib-tbl-sync-entries-
          removed-b-2nd'= ipv6-fib table entries removed in blade for T-1
          synchronization; 'mac-tbl-sync-entries-removed-b-2nd'= mac table entries
          removed in blade for T-1 synchronization; 'arp-tbl-sync-end-ts-m-2nd'= arp
          table sync end time stamp master for T-1 synchronization; 'nd6-tbl-sync-end-
          ts-m-2nd'= nd6 table sync end time stamp master for T-1 synchronization;
          'ipv4-fib-tbl-sync-end-ts-m-2nd'= ipv4-fib table sync end time stamp master for
          T-1 synchronization; 'ipv6-fib-tbl-sync-end-ts-m-2nd'= ipv6-fib table sync end
          time stamp master for T-1 synchronization; 'mac-tbl-sync-end-ts-m-2nd'= mac
          table sync end time stamp master for T-1 synchronization; 'arp-tbl-sync-end-
          ts-b-2nd'= arp table sync end time stamp blade for T-1 synchronization;
          'nd6-tbl-sync-end-ts-b-2nd'= nd6 table sync end time stamp blade for T-1
          synchronization; 'ipv4-fib-tbl-sync-end-ts-b-2nd'= ipv4-fib table sync end time
          stamp blade for T-1 synchronization; 'ipv6-fib-tbl-sync-end-ts-b-2nd'= ipv6-fib
          table sync end time stamp blade for T-1 synchronization; 'mac-tbl-sync-end-
          ts-b-2nd'= mac table sync end time stamp blade for T-1 synchronization; 'arp-
          tbl-sync-start-ts-m-3rd'= arp table sync start time stamp master for T-2
          synchronization; 'nd6-tbl-sync-start-ts-m-3rd'= nd6 table sync start time stamp
          master for T-2 synchronization;"
                type: str
            counters2:
                description:
                - "'ipv4-fib-tbl-sync-start-ts-m-3rd'= ipv4-fib table sync start time stamp master
          for T-2 synchronization; 'ipv6-fib-tbl-sync-start-ts-m-3rd'= ipv6-fib table
          sync start time stamp master for T-2 synchronization; 'mac-tbl-sync-start-
          ts-m-3rd'= mac table sync start time stamp master for T-2 synchronization;
          'arp-tbl-sync-start-ts-b-3rd'= arp table sync start time stamp blade for T-2
          synchronization; 'nd6-tbl-sync-start-ts-b-3rd'= nd6 table sync start time stamp
          blade for T-2 synchronization; 'ipv4-fib-tbl-sync-start-ts-b-3rd'= ipv4-fib
          table sync start time stamp blade for T-2 synchronization; 'ipv6-fib-tbl-sync-
          start-ts-b-3rd'= ipv6-fib table sync start time stamp blade for T-2
          synchronization; 'mac-tbl-sync-start-ts-b-3rd'= mac table sync start time stamp
          blade for T-2 synchronization; 'arp-tbl-sync-entries-sent-m-3rd'= arp table
          entries sent from master for T-2 synchronization; 'nd6-tbl-sync-entries-
          sent-m-3rd'= nd6 table entries sent from master for T-2 synchronization;
          'ipv4-fib-tbl-sync-entries-sent-m-3rd'= ipv4-fib table entries sent from master
          for T-2 synchronization; 'ipv6-fib-tbl-sync-entries-sent-m-3rd'= ipv6-fib table
          entries sent from master for T-2 synchronization; 'mac-tbl-sync-entries-
          sent-m-3rd'= mac table entries sent from master for T-2 synchronization; 'arp-
          tbl-sync-entries-rcvd-b-3rd'= arp table entries received in blade for T-2
          synchronization; 'nd6-tbl-sync-entries-rcvd-b-3rd'= nd6 table entries received
          in blade for T-2 synchronization; 'ipv4-fib-tbl-sync-entries-rcvd-b-3rd'=
          ipv4-fib table entries received in blade for T-2 synchronization; 'ipv6-fib-
          tbl-sync-entries-rcvd-b-3rd'= ipv6-fib table entries received in blade for T-2
          synchronization; 'mac-tbl-sync-entries-rcvd-b-3rd'= mac table entries received
          in blade for T-2 synchronization; 'arp-tbl-sync-entries-added-b-3rd'= arp table
          entries added in blade for T-2 synchronization; 'nd6-tbl-sync-entries-
          added-b-3rd'= nd6 table entries added in blade for T-2 synchronization;
          'ipv4-fib-tbl-sync-entries-added-b-3rd'= ipv4-fib table entries added in blade
          for T-2 synchronization; 'ipv6-fib-tbl-sync-entries-added-b-3rd'= ipv6-fib
          table entries added in blade for T-2 synchronization; 'mac-tbl-sync-entries-
          added-b-3rd'= mac table entries added in blade for T-2 synchronization; 'arp-
          tbl-sync-entries-removed-b-3rd'= arp table entries removed in blade for T-2
          synchronization; 'nd6-tbl-sync-entries-removed-b-3rd'= nd6 table entries
          removed in blade for T-2 synchronization; 'ipv4-fib-tbl-sync-entries-
          removed-b-3rd'= ipv4-fib table entries removed in blade for T-2
          synchronization; 'ipv6-fib-tbl-sync-entries-removed-b-3rd'= ipv6-fib table
          entries removed in blade for T-2 synchronization; 'mac-tbl-sync-entries-
          removed-b-3rd'= mac table entries removed in blade for T-2 synchronization;
          'arp-tbl-sync-end-ts-m-3rd'= arp table sync end time stamp master for T-2
          synchronization; 'nd6-tbl-sync-end-ts-m-3rd'= nd6 table sync end time stamp
          master for T-2 synchronization; 'ipv4-fib-tbl-sync-end-ts-m-3rd'= ipv4-fib
          table sync end time stamp master for T-2 synchronization; 'ipv6-fib-tbl-sync-
          end-ts-m-3rd'= ipv6-fib table sync end time stamp master for T-2
          synchronization; 'mac-tbl-sync-end-ts-m-3rd'= mac table sync end time stamp
          master for T-2 synchronization; 'arp-tbl-sync-end-ts-b-3rd'= arp table sync end
          time stamp blade for T-2 synchronization; 'nd6-tbl-sync-end-ts-b-3rd'= nd6
          table sync end time stamp blade for T-2 synchronization; 'ipv4-fib-tbl-sync-
          end-ts-b-3rd'= ipv4-fib table sync end time stamp blade for T-2
          synchronization; 'ipv6-fib-tbl-sync-end-ts-b-3rd'= ipv6-fib table sync end time
          stamp blade for T-2 synchronization; 'mac-tbl-sync-end-ts-b-3rd'= mac table
          sync end time stamp blade for T-2 synchronization; 'arp-tbl-sync-start-
          ts-m-4th'= arp table sync start time stamp master for T-3 synchronization;
          'nd6-tbl-sync-start-ts-m-4th'= nd6 table sync start time stamp master for T-3
          synchronization; 'ipv4-fib-tbl-sync-start-ts-m-4th'= ipv4-fib table sync start
          time stamp master for T-3 synchronization; 'ipv6-fib-tbl-sync-start-ts-m-4th'=
          ipv6-fib table sync start time stamp master for T-3 synchronization; 'mac-tbl-
          sync-start-ts-m-4th'= mac table sync start time stamp master for T-3
          synchronization; 'arp-tbl-sync-start-ts-b-4th'= arp table sync start time stamp
          blade for T-3 synchronization; 'nd6-tbl-sync-start-ts-b-4th'= nd6 table sync
          start time stamp blade for T-3 synchronization; 'ipv4-fib-tbl-sync-start-
          ts-b-4th'= ipv4-fib table sync start time stamp blade for T-3 synchronization;
          'ipv6-fib-tbl-sync-start-ts-b-4th'= ipv6-fib table sync start time stamp blade
          for T-3 synchronization; 'mac-tbl-sync-start-ts-b-4th'= mac table sync start
          time stamp blade for T-3 synchronization; 'arp-tbl-sync-entries-sent-m-4th'=
          arp table entries sent from master for T-3 synchronization; 'nd6-tbl-sync-
          entries-sent-m-4th'= nd6 table entries sent from master for T-3
          synchronization; 'ipv4-fib-tbl-sync-entries-sent-m-4th'= ipv4-fib table entries
          sent from master for T-3 synchronization; 'ipv6-fib-tbl-sync-entries-
          sent-m-4th'= ipv6-fib table entries sent from master for T-3 synchronization;
          'mac-tbl-sync-entries-sent-m-4th'= mac table entries sent from master for T-3
          synchronization; 'arp-tbl-sync-entries-rcvd-b-4th'= arp table entries received
          in blade for T-3 synchronization; 'nd6-tbl-sync-entries-rcvd-b-4th'= nd6 table
          entries received in blade for T-3 synchronization; 'ipv4-fib-tbl-sync-entries-
          rcvd-b-4th'= ipv4-fib table entries received in blade for T-3 synchronization;
          'ipv6-fib-tbl-sync-entries-rcvd-b-4th'= ipv6-fib table entries received in
          blade for T-3 synchronization; 'mac-tbl-sync-entries-rcvd-b-4th'= mac table
          entries received in blade for T-3 synchronization; 'arp-tbl-sync-entries-
          added-b-4th'= arp table entries added in blade for T-3 synchronization;
          'nd6-tbl-sync-entries-added-b-4th'= nd6 table entries added in blade for T-3
          synchronization; 'ipv4-fib-tbl-sync-entries-added-b-4th'= ipv4-fib table
          entries added in blade for T-3 synchronization; 'ipv6-fib-tbl-sync-entries-
          added-b-4th'= ipv6-fib table entries added in blade for T-3 synchronization;
          'mac-tbl-sync-entries-added-b-4th'= mac table entries added in blade for T-3
          synchronization; 'arp-tbl-sync-entries-removed-b-4th'= arp table entries
          removed in blade for T-3 synchronization; 'nd6-tbl-sync-entries-removed-b-4th'=
          nd6 table entries removed in blade for T-3 synchronization; 'ipv4-fib-tbl-sync-
          entries-removed-b-4th'= ipv4-fib table entries removed in blade for T-3
          synchronization; 'ipv6-fib-tbl-sync-entries-removed-b-4th'= ipv6-fib table
          entries removed in blade for T-3 synchronization; 'mac-tbl-sync-entries-
          removed-b-4th'= mac table entries removed in blade for T-3 synchronization;
          'arp-tbl-sync-end-ts-m-4th'= arp table sync end time stamp master for T-3
          synchronization; 'nd6-tbl-sync-end-ts-m-4th'= nd6 table sync end time stamp
          master for T-3 synchronization; 'ipv4-fib-tbl-sync-end-ts-m-4th'= ipv4-fib
          table sync end time stamp master for T-3 synchronization; 'ipv6-fib-tbl-sync-
          end-ts-m-4th'= ipv6-fib table sync end time stamp master for T-3
          synchronization; 'mac-tbl-sync-end-ts-m-4th'= mac table sync end time stamp
          master for T-3 synchronization; 'arp-tbl-sync-end-ts-b-4th'= arp table sync end
          time stamp blade for T-3 synchronization; 'nd6-tbl-sync-end-ts-b-4th'= nd6
          table sync end time stamp blade for T-3 synchronization; 'ipv4-fib-tbl-sync-
          end-ts-b-4th'= ipv4-fib table sync end time stamp blade for T-3
          synchronization; 'ipv6-fib-tbl-sync-end-ts-b-4th'= ipv6-fib table sync end time
          stamp blade for T-3 synchronization; 'mac-tbl-sync-end-ts-b-4th'= mac table
          sync end time stamp blade for T-3 synchronization; 'arp-tbl-sync-start-
          ts-m-5th'= arp table sync start time stamp master for T-4 synchronization;"
                type: str
            counters3:
                description:
                - "'nd6-tbl-sync-start-ts-m-5th'= nd6 table sync start time stamp master for T-4
          synchronization; 'ipv4-fib-tbl-sync-start-ts-m-5th'= ipv4-fib table sync start
          time stamp master for T-4 synchronization; 'ipv6-fib-tbl-sync-start-ts-m-5th'=
          ipv6-fib table sync start time stamp master for T-4 synchronization; 'mac-tbl-
          sync-start-ts-m-5th'= mac table sync start time stamp master for T-4
          synchronization; 'arp-tbl-sync-start-ts-b-5th'= arp table sync start time stamp
          blade for T-4 synchronization; 'nd6-tbl-sync-start-ts-b-5th'= nd6 table sync
          start time stamp blade for T-4 synchronization; 'ipv4-fib-tbl-sync-start-
          ts-b-5th'= ipv4-fib table sync start time stamp blade for T-4 synchronization;
          'ipv6-fib-tbl-sync-start-ts-b-5th'= ipv6-fib table sync start time stamp blade
          for T-4 synchronization; 'mac-tbl-sync-start-ts-b-5th'= mac table sync start
          time stamp blade for T-4 synchronization; 'arp-tbl-sync-entries-sent-m-5th'=
          arp table sync start time stamp blade for T-4 synchronization; 'nd6-tbl-sync-
          entries-sent-m-5th'= nd6 table sync start time stamp blade for T-4
          synchronization; 'ipv4-fib-tbl-sync-entries-sent-m-5th'= ipv4-fib table sync
          start time stamp blade for T-4 synchronization; 'ipv6-fib-tbl-sync-entries-
          sent-m-5th'= ipv6-fib table sync start time stamp blade for T-4
          synchronization; 'mac-tbl-sync-entries-sent-m-5th'= mac table sync start time
          stamp blade for T-4 synchronization; 'arp-tbl-sync-entries-rcvd-b-5th'= arp
          table entries received in blade for T-4 synchronization; 'nd6-tbl-sync-entries-
          rcvd-b-5th'= nd6 table entries received in blade for T-4 synchronization;
          'ipv4-fib-tbl-sync-entries-rcvd-b-5th'= ipv4-fib table entries received in
          blade for T-4 synchronization; 'ipv6-fib-tbl-sync-entries-rcvd-b-5th'= ipv6-fib
          table entries received in blade for T-4 synchronization; 'mac-tbl-sync-entries-
          rcvd-b-5th'= mac table entries received in blade for T-4 synchronization; 'arp-
          tbl-sync-entries-added-b-5th'= arp table entries added in blade for T-4
          synchronization; 'nd6-tbl-sync-entries-added-b-5th'= nd6 table entries added in
          blade for T-4 synchronization; 'ipv4-fib-tbl-sync-entries-added-b-5th'=
          ipv4-fib table entries added in blade for T-4 synchronization; 'ipv6-fib-tbl-
          sync-entries-added-b-5th'= ipv6-fib table entries added in blade for T-4
          synchronization; 'mac-tbl-sync-entries-added-b-5th'= mac table entries added in
          blade for T-4 synchronization; 'arp-tbl-sync-entries-removed-b-5th'= arp table
          entries removed in blade for T-4 synchronization; 'nd6-tbl-sync-entries-
          removed-b-5th'= nd6 table entries removed in blade for T-4 synchronization;
          'ipv4-fib-tbl-sync-entries-removed-b-5th'= ipv4-fib table entries removed in
          blade for T-4 synchronization; 'ipv6-fib-tbl-sync-entries-removed-b-5th'=
          ipv6-fib table entries removed in blade for T-4 synchronization; 'mac-tbl-sync-
          entries-removed-b-5th'= mac table entries removed in blade for T-4
          synchronization; 'arp-tbl-sync-end-ts-m-5th'= arp table sync end time stamp
          master for T-4 synchronization; 'nd6-tbl-sync-end-ts-m-5th'= nd6 table sync end
          time stamp master for T-4 synchronization; 'ipv4-fib-tbl-sync-end-ts-m-5th'=
          ipv4-fib table sync end time stamp master for T-4 synchronization; 'ipv6-fib-
          tbl-sync-end-ts-m-5th'= ipv6-fib table sync end time stamp master for T-4
          synchronization; 'mac-tbl-sync-end-ts-m-5th'= mac table sync end time stamp
          master for T-4 synchronization; 'arp-tbl-sync-end-ts-b-5th'= arp table sync end
          time stamp blade for T-4 synchronization; 'nd6-tbl-sync-end-ts-b-5th'= nd6
          table sync end time stamp blade for T-4 synchronization; 'ipv4-fib-tbl-sync-
          end-ts-b-5th'= ipv4-fib table sync end time stamp blade for T-4
          synchronization; 'ipv6-fib-tbl-sync-end-ts-b-5th'= ipv6-fib table sync end time
          stamp blade for T-4 synchronization; 'mac-tbl-sync-end-ts-b-5th'= mac table
          sync end time stamp blade for T-4 synchronization; 'arp-tbl-sync-m'= arp table
          sync count in master; 'nd6-tbl-sync-m'= nd6 table sync count in master;
          'ipv4-fib-tbl-sync-m'= ipv4-fib table sync count in master; 'ipv6-fib-tbl-
          sync-m'= ipv6-fib table sync count in master; 'mac-tbl-sync-m'= mac table sync
          count in master; 'arp-tbl-sync-b'= arp table sync count in blade; 'nd6-tbl-
          sync-b'= nd6 table sync count in blade; 'ipv4-fib-tbl-sync-b'= ipv4-fib table
          sync count in blade; 'ipv6-fib-tbl-sync-b'= ipv6-fib table sync count in blade;
          'mac-tbl-sync-b'= mac table sync count in blade; 'arp-tbl-cksum-m'= arp table
          checksum count in master; 'nd6-tbl-cksum-m'= nd6 table checksum count in
          master; 'ipv4-fib-tbl-cksum-m'= ipv4-fib table checksum count in master;
          'ipv6-fib-tbl-cksum-m'= ipv6-fib table checksum count in master; 'mac-tbl-
          cksum-m'= mac table checksum count in master; 'arp-tbl-cksum-b'= arp table
          checksum count in blade; 'nd6-tbl-cksum-b'= nd6 table checksum count in blade;
          'ipv4-fib-tbl-cksum-b'= ipv4-fib table checksum count in blade; 'ipv6-fib-tbl-
          cksum-b'= ipv6-fib table checksum count in blade; 'mac-tbl-cksum-b'= mac table
          checksum count in blade; 'arp-tbl-cksum-mismatch-b'= arp table checksum
          mismatch count in blade; 'nd6-tbl-cksum-mismatch-b'= nd6 table checksum
          mismatch count in blade; 'ipv4-fib-tbl-cksum-mismatch-b'= ipv4-fib table
          checksum mismatch count in blade; 'ipv6-fib-tbl-cksum-mismatch-b'= ipv6-fib
          table checksum mismatch count in blade; 'mac-tbl-cksum-mismatch-b'= mac table
          checksum mismatch count in blade; 'arp-tbl-cksum-cancel-m'= arp table checksum
          cancelled count in master; 'nd6-tbl-cksum-cancel-m'= nd6 table checksum
          cancelled count in master; 'ipv4-fib-tbl-cksum-cancel-m'= ipv4-fib table
          checksum cancelled count in master; 'ipv6-fib-tbl-cksum-cancel-m'= ipv6-fib
          table checksum cancelled count in master; 'mac-tbl-cksum-cancel-m'= mac table
          checksum cancelled count in master;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            arp_tbl_sync_start_ts_m_1st:
                description:
                - "arp table sync start time stamp master"
                type: str
            nd6_tbl_sync_start_ts_m_1st:
                description:
                - "nd6 table sync start time stamp master"
                type: str
            ipv4_fib_tbl_sync_start_ts_m_1st:
                description:
                - "ipv4-fib table sync start time stamp master"
                type: str
            ipv6_fib_tbl_sync_start_ts_m_1st:
                description:
                - "ipv6-fib table sync start time stamp master"
                type: str
            mac_tbl_sync_start_ts_m_1st:
                description:
                - "mac table sync start time stamp master"
                type: str
            arp_tbl_sync_start_ts_b_1st:
                description:
                - "arp table sync start time stamp blade"
                type: str
            nd6_tbl_sync_start_ts_b_1st:
                description:
                - "nd6 table sync start time stamp blade"
                type: str
            ipv4_fib_tbl_sync_start_ts_b_1st:
                description:
                - "ipv4-fib table sync start time stamp blade"
                type: str
            ipv6_fib_tbl_sync_start_ts_b_1st:
                description:
                - "ipv6-fib table sync start time stamp blade"
                type: str
            mac_tbl_sync_start_ts_b_1st:
                description:
                - "mac table sync start time stamp blade"
                type: str
            arp_tbl_sync_entries_sent_m_1st:
                description:
                - "arp table entries sent from master for T0 synchronization"
                type: str
            nd6_tbl_sync_entries_sent_m_1st:
                description:
                - "nd6 table entries sent from master for T0 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_sent_m_1st:
                description:
                - "ipv4-fib table entries sent from master for T0 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_sent_m_1st:
                description:
                - "ipv6-fib table entries sent from master for T0 synchronization"
                type: str
            mac_tbl_sync_entries_sent_m_1st:
                description:
                - "mac table entries sent from master for T0 synchronization"
                type: str
            arp_tbl_sync_entries_rcvd_b_1st:
                description:
                - "arp table entries received on blade for T0 synchronization"
                type: str
            nd6_tbl_sync_entries_rcvd_b_1st:
                description:
                - "nd6 table entries received on blade for T0 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_rcvd_b_1st:
                description:
                - "ipv4-fib table entries received on blade for T0 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_rcvd_b_1st:
                description:
                - "ipv6-fib table entries received on blade for T0 synchronization"
                type: str
            mac_tbl_sync_entries_rcvd_b_1st:
                description:
                - "mac table entries received on blade for T0 synchronization"
                type: str
            arp_tbl_sync_entries_added_b_1st:
                description:
                - "arp table entries added on blade for T0 synchronization"
                type: str
            nd6_tbl_sync_entries_added_b_1st:
                description:
                - "nd6 table entries added on blade for T0 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_added_b_1st:
                description:
                - "ipv4-fib table entries added on blade for T0 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_added_b_1st:
                description:
                - "ipv6-fib table entries added on blade for T0 synchronization"
                type: str
            mac_tbl_sync_entries_added_b_1st:
                description:
                - "mac table entries added on blade for T0 synchronization"
                type: str
            arp_tbl_sync_entries_removed_b_1st:
                description:
                - "arp table entries removed on blade for T0 synchronization"
                type: str
            nd6_tbl_sync_entries_removed_b_1st:
                description:
                - "arp table entries removed on blade for T0 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_removed_b_1st:
                description:
                - "arp table entries removed on blade for T0 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_removed_b_1st:
                description:
                - "arp table entries removed on blade for T0 synchronization"
                type: str
            mac_tbl_sync_entries_removed_b_1st:
                description:
                - "arp table entries removed on blade for T0 synchronization"
                type: str
            arp_tbl_sync_end_ts_m_1st:
                description:
                - "arp table sync end time stamp master for T0 synchronization"
                type: str
            nd6_tbl_sync_end_ts_m_1st:
                description:
                - "nd6 table sync end time stamp master for T0 synchronization"
                type: str
            ipv4_fib_tbl_sync_end_ts_m_1st:
                description:
                - "ipv4-fib table sync end time stamp master for T0 synchronization"
                type: str
            ipv6_fib_tbl_sync_end_ts_m_1st:
                description:
                - "ipv6-fib table sync end time stamp master for T0 synchronization"
                type: str
            mac_tbl_sync_end_ts_m_1st:
                description:
                - "mac table sync end time stamp master for T0 synchronization"
                type: str
            arp_tbl_sync_end_ts_b_1st:
                description:
                - "arp table sync end time stamp blade for T0 synchronization"
                type: str
            nd6_tbl_sync_end_ts_b_1st:
                description:
                - "nd6 table sync end time stamp blade for T0 synchronization"
                type: str
            ipv4_fib_tbl_sync_end_ts_b_1st:
                description:
                - "ipv4-fib table sync end time stamp blade for T0 synchronization"
                type: str
            ipv6_fib_tbl_sync_end_ts_b_1st:
                description:
                - "ipv6-fib table sync end time stamp blade for T0 synchronization"
                type: str
            mac_tbl_sync_end_ts_b_1st:
                description:
                - "mac table sync end time stamp blade for T0 synchronization"
                type: str
            arp_tbl_sync_start_ts_m_2nd:
                description:
                - "arp table sync start time stamp master for T-1 synchronization"
                type: str
            nd6_tbl_sync_start_ts_m_2nd:
                description:
                - "nd6 table sync start time stamp master for T-1 synchronization"
                type: str
            ipv4_fib_tbl_sync_start_ts_m_2nd:
                description:
                - "ipv4-fib table sync start time stamp master for T-1 synchronization"
                type: str
            ipv6_fib_tbl_sync_start_ts_m_2nd:
                description:
                - "ipv6-fib table sync start time stamp master for T-1 synchronization"
                type: str
            mac_tbl_sync_start_ts_m_2nd:
                description:
                - "mac table sync start time stamp master for T-1 synchronization"
                type: str
            arp_tbl_sync_start_ts_b_2nd:
                description:
                - "arp table sync start time stamp blade for T-1 synchronization"
                type: str
            nd6_tbl_sync_start_ts_b_2nd:
                description:
                - "nd6 table sync start time stamp blade for T-1 synchronization"
                type: str
            ipv4_fib_tbl_sync_start_ts_b_2nd:
                description:
                - "ipv4-fib table sync start time stamp blade for T-1 synchronization"
                type: str
            ipv6_fib_tbl_sync_start_ts_b_2nd:
                description:
                - "ipv6-fib table sync start time stamp blade for T-1 synchronization"
                type: str
            mac_tbl_sync_start_ts_b_2nd:
                description:
                - "mac table sync start time stamp blade for T-1 synchronization"
                type: str
            arp_tbl_sync_entries_sent_m_2nd:
                description:
                - "arp table entries sent from master for T-1 synchronization"
                type: str
            nd6_tbl_sync_entries_sent_m_2nd:
                description:
                - "nd6 table entries sent from master for T-1 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_sent_m_2nd:
                description:
                - "ipv4-fib table entries sent from master for T-1 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_sent_m_2nd:
                description:
                - "ipv6-fib table entries sent from master for T-1 synchronization"
                type: str
            mac_tbl_sync_entries_sent_m_2nd:
                description:
                - "mac table entries sent from master for T-1 synchronization"
                type: str
            arp_tbl_sync_entries_rcvd_b_2nd:
                description:
                - "arp table entries received in blade for T-1 synchronization"
                type: str
            nd6_tbl_sync_entries_rcvd_b_2nd:
                description:
                - "nd6 table entries received in blade for T-1 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_rcvd_b_2nd:
                description:
                - "ipv4-fib table entries received in blade for T-1 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_rcvd_b_2nd:
                description:
                - "ipv6-fib table entries received in blade for T-1 synchronization"
                type: str
            mac_tbl_sync_entries_rcvd_b_2nd:
                description:
                - "mac table entries received in blade for T-1 synchronization"
                type: str
            arp_tbl_sync_entries_added_b_2nd:
                description:
                - "arp table entries added in blade for T-1 synchronization"
                type: str
            nd6_tbl_sync_entries_added_b_2nd:
                description:
                - "nd6 table entries added in blade for T-1 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_added_b_2nd:
                description:
                - "ipv4-fib table entries added in blade for T-1 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_added_b_2nd:
                description:
                - "ipv6-fib table entries added in blade for T-1 synchronization"
                type: str
            mac_tbl_sync_entries_added_b_2nd:
                description:
                - "mac table entries added in blade for T-1 synchronization"
                type: str
            arp_tbl_sync_entries_removed_b_2nd:
                description:
                - "arp table entries removed in blade for T-1 synchronization"
                type: str
            nd6_tbl_sync_entries_removed_b_2nd:
                description:
                - "nd6 table entries removed in blade for T-1 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_removed_b_2nd:
                description:
                - "ipv4-fib table entries removed in blade for T-1 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_removed_b_2nd:
                description:
                - "ipv6-fib table entries removed in blade for T-1 synchronization"
                type: str
            mac_tbl_sync_entries_removed_b_2nd:
                description:
                - "mac table entries removed in blade for T-1 synchronization"
                type: str
            arp_tbl_sync_end_ts_m_2nd:
                description:
                - "arp table sync end time stamp master for T-1 synchronization"
                type: str
            nd6_tbl_sync_end_ts_m_2nd:
                description:
                - "nd6 table sync end time stamp master for T-1 synchronization"
                type: str
            ipv4_fib_tbl_sync_end_ts_m_2nd:
                description:
                - "ipv4-fib table sync end time stamp master for T-1 synchronization"
                type: str
            ipv6_fib_tbl_sync_end_ts_m_2nd:
                description:
                - "ipv6-fib table sync end time stamp master for T-1 synchronization"
                type: str
            mac_tbl_sync_end_ts_m_2nd:
                description:
                - "mac table sync end time stamp master for T-1 synchronization"
                type: str
            arp_tbl_sync_end_ts_b_2nd:
                description:
                - "arp table sync end time stamp blade for T-1 synchronization"
                type: str
            nd6_tbl_sync_end_ts_b_2nd:
                description:
                - "nd6 table sync end time stamp blade for T-1 synchronization"
                type: str
            ipv4_fib_tbl_sync_end_ts_b_2nd:
                description:
                - "ipv4-fib table sync end time stamp blade for T-1 synchronization"
                type: str
            ipv6_fib_tbl_sync_end_ts_b_2nd:
                description:
                - "ipv6-fib table sync end time stamp blade for T-1 synchronization"
                type: str
            mac_tbl_sync_end_ts_b_2nd:
                description:
                - "mac table sync end time stamp blade for T-1 synchronization"
                type: str
            arp_tbl_sync_start_ts_m_3rd:
                description:
                - "arp table sync start time stamp master for T-2 synchronization"
                type: str
            nd6_tbl_sync_start_ts_m_3rd:
                description:
                - "nd6 table sync start time stamp master for T-2 synchronization"
                type: str
            ipv4_fib_tbl_sync_start_ts_m_3rd:
                description:
                - "ipv4-fib table sync start time stamp master for T-2 synchronization"
                type: str
            ipv6_fib_tbl_sync_start_ts_m_3rd:
                description:
                - "ipv6-fib table sync start time stamp master for T-2 synchronization"
                type: str
            mac_tbl_sync_start_ts_m_3rd:
                description:
                - "mac table sync start time stamp master for T-2 synchronization"
                type: str
            arp_tbl_sync_start_ts_b_3rd:
                description:
                - "arp table sync start time stamp blade for T-2 synchronization"
                type: str
            nd6_tbl_sync_start_ts_b_3rd:
                description:
                - "nd6 table sync start time stamp blade for T-2 synchronization"
                type: str
            ipv4_fib_tbl_sync_start_ts_b_3rd:
                description:
                - "ipv4-fib table sync start time stamp blade for T-2 synchronization"
                type: str
            ipv6_fib_tbl_sync_start_ts_b_3rd:
                description:
                - "ipv6-fib table sync start time stamp blade for T-2 synchronization"
                type: str
            mac_tbl_sync_start_ts_b_3rd:
                description:
                - "mac table sync start time stamp blade for T-2 synchronization"
                type: str
            arp_tbl_sync_entries_sent_m_3rd:
                description:
                - "arp table entries sent from master for T-2 synchronization"
                type: str
            nd6_tbl_sync_entries_sent_m_3rd:
                description:
                - "nd6 table entries sent from master for T-2 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_sent_m_3rd:
                description:
                - "ipv4-fib table entries sent from master for T-2 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_sent_m_3rd:
                description:
                - "ipv6-fib table entries sent from master for T-2 synchronization"
                type: str
            mac_tbl_sync_entries_sent_m_3rd:
                description:
                - "mac table entries sent from master for T-2 synchronization"
                type: str
            arp_tbl_sync_entries_rcvd_b_3rd:
                description:
                - "arp table entries received in blade for T-2 synchronization"
                type: str
            nd6_tbl_sync_entries_rcvd_b_3rd:
                description:
                - "nd6 table entries received in blade for T-2 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_rcvd_b_3rd:
                description:
                - "ipv4-fib table entries received in blade for T-2 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_rcvd_b_3rd:
                description:
                - "ipv6-fib table entries received in blade for T-2 synchronization"
                type: str
            mac_tbl_sync_entries_rcvd_b_3rd:
                description:
                - "mac table entries received in blade for T-2 synchronization"
                type: str
            arp_tbl_sync_entries_added_b_3rd:
                description:
                - "arp table entries added in blade for T-2 synchronization"
                type: str
            nd6_tbl_sync_entries_added_b_3rd:
                description:
                - "nd6 table entries added in blade for T-2 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_added_b_3rd:
                description:
                - "ipv4-fib table entries added in blade for T-2 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_added_b_3rd:
                description:
                - "ipv6-fib table entries added in blade for T-2 synchronization"
                type: str
            mac_tbl_sync_entries_added_b_3rd:
                description:
                - "mac table entries added in blade for T-2 synchronization"
                type: str
            arp_tbl_sync_entries_removed_b_3rd:
                description:
                - "arp table entries removed in blade for T-2 synchronization"
                type: str
            nd6_tbl_sync_entries_removed_b_3rd:
                description:
                - "nd6 table entries removed in blade for T-2 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_removed_b_3rd:
                description:
                - "ipv4-fib table entries removed in blade for T-2 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_removed_b_3rd:
                description:
                - "ipv6-fib table entries removed in blade for T-2 synchronization"
                type: str
            mac_tbl_sync_entries_removed_b_3rd:
                description:
                - "mac table entries removed in blade for T-2 synchronization"
                type: str
            arp_tbl_sync_end_ts_m_3rd:
                description:
                - "arp table sync end time stamp master for T-2 synchronization"
                type: str
            nd6_tbl_sync_end_ts_m_3rd:
                description:
                - "nd6 table sync end time stamp master for T-2 synchronization"
                type: str
            ipv4_fib_tbl_sync_end_ts_m_3rd:
                description:
                - "ipv4-fib table sync end time stamp master for T-2 synchronization"
                type: str
            ipv6_fib_tbl_sync_end_ts_m_3rd:
                description:
                - "ipv6-fib table sync end time stamp master for T-2 synchronization"
                type: str
            mac_tbl_sync_end_ts_m_3rd:
                description:
                - "mac table sync end time stamp master for T-2 synchronization"
                type: str
            arp_tbl_sync_end_ts_b_3rd:
                description:
                - "arp table sync end time stamp blade for T-2 synchronization"
                type: str
            nd6_tbl_sync_end_ts_b_3rd:
                description:
                - "nd6 table sync end time stamp blade for T-2 synchronization"
                type: str
            ipv4_fib_tbl_sync_end_ts_b_3rd:
                description:
                - "ipv4-fib table sync end time stamp blade for T-2 synchronization"
                type: str
            ipv6_fib_tbl_sync_end_ts_b_3rd:
                description:
                - "ipv6-fib table sync end time stamp blade for T-2 synchronization"
                type: str
            mac_tbl_sync_end_ts_b_3rd:
                description:
                - "mac table sync end time stamp blade for T-2 synchronization"
                type: str
            arp_tbl_sync_start_ts_m_4th:
                description:
                - "arp table sync start time stamp master for T-3 synchronization"
                type: str
            nd6_tbl_sync_start_ts_m_4th:
                description:
                - "nd6 table sync start time stamp master for T-3 synchronization"
                type: str
            ipv4_fib_tbl_sync_start_ts_m_4th:
                description:
                - "ipv4-fib table sync start time stamp master for T-3 synchronization"
                type: str
            ipv6_fib_tbl_sync_start_ts_m_4th:
                description:
                - "ipv6-fib table sync start time stamp master for T-3 synchronization"
                type: str
            mac_tbl_sync_start_ts_m_4th:
                description:
                - "mac table sync start time stamp master for T-3 synchronization"
                type: str
            arp_tbl_sync_start_ts_b_4th:
                description:
                - "arp table sync start time stamp blade for T-3 synchronization"
                type: str
            nd6_tbl_sync_start_ts_b_4th:
                description:
                - "nd6 table sync start time stamp blade for T-3 synchronization"
                type: str
            ipv4_fib_tbl_sync_start_ts_b_4th:
                description:
                - "ipv4-fib table sync start time stamp blade for T-3 synchronization"
                type: str
            ipv6_fib_tbl_sync_start_ts_b_4th:
                description:
                - "ipv6-fib table sync start time stamp blade for T-3 synchronization"
                type: str
            mac_tbl_sync_start_ts_b_4th:
                description:
                - "mac table sync start time stamp blade for T-3 synchronization"
                type: str
            arp_tbl_sync_entries_sent_m_4th:
                description:
                - "arp table entries sent from master for T-3 synchronization"
                type: str
            nd6_tbl_sync_entries_sent_m_4th:
                description:
                - "nd6 table entries sent from master for T-3 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_sent_m_4th:
                description:
                - "ipv4-fib table entries sent from master for T-3 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_sent_m_4th:
                description:
                - "ipv6-fib table entries sent from master for T-3 synchronization"
                type: str
            mac_tbl_sync_entries_sent_m_4th:
                description:
                - "mac table entries sent from master for T-3 synchronization"
                type: str
            arp_tbl_sync_entries_rcvd_b_4th:
                description:
                - "arp table entries received in blade for T-3 synchronization"
                type: str
            nd6_tbl_sync_entries_rcvd_b_4th:
                description:
                - "nd6 table entries received in blade for T-3 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_rcvd_b_4th:
                description:
                - "ipv4-fib table entries received in blade for T-3 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_rcvd_b_4th:
                description:
                - "ipv6-fib table entries received in blade for T-3 synchronization"
                type: str
            mac_tbl_sync_entries_rcvd_b_4th:
                description:
                - "mac table entries received in blade for T-3 synchronization"
                type: str
            arp_tbl_sync_entries_added_b_4th:
                description:
                - "arp table entries added in blade for T-3 synchronization"
                type: str
            nd6_tbl_sync_entries_added_b_4th:
                description:
                - "nd6 table entries added in blade for T-3 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_added_b_4th:
                description:
                - "ipv4-fib table entries added in blade for T-3 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_added_b_4th:
                description:
                - "ipv6-fib table entries added in blade for T-3 synchronization"
                type: str
            mac_tbl_sync_entries_added_b_4th:
                description:
                - "mac table entries added in blade for T-3 synchronization"
                type: str
            arp_tbl_sync_entries_removed_b_4th:
                description:
                - "arp table entries removed in blade for T-3 synchronization"
                type: str
            nd6_tbl_sync_entries_removed_b_4th:
                description:
                - "nd6 table entries removed in blade for T-3 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_removed_b_4th:
                description:
                - "ipv4-fib table entries removed in blade for T-3 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_removed_b_4th:
                description:
                - "ipv6-fib table entries removed in blade for T-3 synchronization"
                type: str
            mac_tbl_sync_entries_removed_b_4th:
                description:
                - "mac table entries removed in blade for T-3 synchronization"
                type: str
            arp_tbl_sync_end_ts_m_4th:
                description:
                - "arp table sync end time stamp master for T-3 synchronization"
                type: str
            nd6_tbl_sync_end_ts_m_4th:
                description:
                - "nd6 table sync end time stamp master for T-3 synchronization"
                type: str
            ipv4_fib_tbl_sync_end_ts_m_4th:
                description:
                - "ipv4-fib table sync end time stamp master for T-3 synchronization"
                type: str
            ipv6_fib_tbl_sync_end_ts_m_4th:
                description:
                - "ipv6-fib table sync end time stamp master for T-3 synchronization"
                type: str
            mac_tbl_sync_end_ts_m_4th:
                description:
                - "mac table sync end time stamp master for T-3 synchronization"
                type: str
            arp_tbl_sync_end_ts_b_4th:
                description:
                - "arp table sync end time stamp blade for T-3 synchronization"
                type: str
            nd6_tbl_sync_end_ts_b_4th:
                description:
                - "nd6 table sync end time stamp blade for T-3 synchronization"
                type: str
            ipv4_fib_tbl_sync_end_ts_b_4th:
                description:
                - "ipv4-fib table sync end time stamp blade for T-3 synchronization"
                type: str
            ipv6_fib_tbl_sync_end_ts_b_4th:
                description:
                - "ipv6-fib table sync end time stamp blade for T-3 synchronization"
                type: str
            mac_tbl_sync_end_ts_b_4th:
                description:
                - "mac table sync end time stamp blade for T-3 synchronization"
                type: str
            arp_tbl_sync_start_ts_m_5th:
                description:
                - "arp table sync start time stamp master for T-4 synchronization"
                type: str
            nd6_tbl_sync_start_ts_m_5th:
                description:
                - "nd6 table sync start time stamp master for T-4 synchronization"
                type: str
            ipv4_fib_tbl_sync_start_ts_m_5th:
                description:
                - "ipv4-fib table sync start time stamp master for T-4 synchronization"
                type: str
            ipv6_fib_tbl_sync_start_ts_m_5th:
                description:
                - "ipv6-fib table sync start time stamp master for T-4 synchronization"
                type: str
            mac_tbl_sync_start_ts_m_5th:
                description:
                - "mac table sync start time stamp master for T-4 synchronization"
                type: str
            arp_tbl_sync_start_ts_b_5th:
                description:
                - "arp table sync start time stamp blade for T-4 synchronization"
                type: str
            nd6_tbl_sync_start_ts_b_5th:
                description:
                - "nd6 table sync start time stamp blade for T-4 synchronization"
                type: str
            ipv4_fib_tbl_sync_start_ts_b_5th:
                description:
                - "ipv4-fib table sync start time stamp blade for T-4 synchronization"
                type: str
            ipv6_fib_tbl_sync_start_ts_b_5th:
                description:
                - "ipv6-fib table sync start time stamp blade for T-4 synchronization"
                type: str
            mac_tbl_sync_start_ts_b_5th:
                description:
                - "mac table sync start time stamp blade for T-4 synchronization"
                type: str
            arp_tbl_sync_entries_sent_m_5th:
                description:
                - "arp table sync start time stamp blade for T-4 synchronization"
                type: str
            nd6_tbl_sync_entries_sent_m_5th:
                description:
                - "nd6 table sync start time stamp blade for T-4 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_sent_m_5th:
                description:
                - "ipv4-fib table sync start time stamp blade for T-4 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_sent_m_5th:
                description:
                - "ipv6-fib table sync start time stamp blade for T-4 synchronization"
                type: str
            mac_tbl_sync_entries_sent_m_5th:
                description:
                - "mac table sync start time stamp blade for T-4 synchronization"
                type: str
            arp_tbl_sync_entries_rcvd_b_5th:
                description:
                - "arp table entries received in blade for T-4 synchronization"
                type: str
            nd6_tbl_sync_entries_rcvd_b_5th:
                description:
                - "nd6 table entries received in blade for T-4 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_rcvd_b_5th:
                description:
                - "ipv4-fib table entries received in blade for T-4 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_rcvd_b_5th:
                description:
                - "ipv6-fib table entries received in blade for T-4 synchronization"
                type: str
            mac_tbl_sync_entries_rcvd_b_5th:
                description:
                - "mac table entries received in blade for T-4 synchronization"
                type: str
            arp_tbl_sync_entries_added_b_5th:
                description:
                - "arp table entries added in blade for T-4 synchronization"
                type: str
            nd6_tbl_sync_entries_added_b_5th:
                description:
                - "nd6 table entries added in blade for T-4 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_added_b_5th:
                description:
                - "ipv4-fib table entries added in blade for T-4 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_added_b_5th:
                description:
                - "ipv6-fib table entries added in blade for T-4 synchronization"
                type: str
            mac_tbl_sync_entries_added_b_5th:
                description:
                - "mac table entries added in blade for T-4 synchronization"
                type: str
            arp_tbl_sync_entries_removed_b_5th:
                description:
                - "arp table entries removed in blade for T-4 synchronization"
                type: str
            nd6_tbl_sync_entries_removed_b_5th:
                description:
                - "nd6 table entries removed in blade for T-4 synchronization"
                type: str
            ipv4_fib_tbl_sync_entries_removed_b_5th:
                description:
                - "ipv4-fib table entries removed in blade for T-4 synchronization"
                type: str
            ipv6_fib_tbl_sync_entries_removed_b_5th:
                description:
                - "ipv6-fib table entries removed in blade for T-4 synchronization"
                type: str
            mac_tbl_sync_entries_removed_b_5th:
                description:
                - "mac table entries removed in blade for T-4 synchronization"
                type: str
            arp_tbl_sync_end_ts_m_5th:
                description:
                - "arp table sync end time stamp master for T-4 synchronization"
                type: str
            nd6_tbl_sync_end_ts_m_5th:
                description:
                - "nd6 table sync end time stamp master for T-4 synchronization"
                type: str
            ipv4_fib_tbl_sync_end_ts_m_5th:
                description:
                - "ipv4-fib table sync end time stamp master for T-4 synchronization"
                type: str
            ipv6_fib_tbl_sync_end_ts_m_5th:
                description:
                - "ipv6-fib table sync end time stamp master for T-4 synchronization"
                type: str
            mac_tbl_sync_end_ts_m_5th:
                description:
                - "mac table sync end time stamp master for T-4 synchronization"
                type: str
            arp_tbl_sync_end_ts_b_5th:
                description:
                - "arp table sync end time stamp blade for T-4 synchronization"
                type: str
            nd6_tbl_sync_end_ts_b_5th:
                description:
                - "nd6 table sync end time stamp blade for T-4 synchronization"
                type: str
            ipv4_fib_tbl_sync_end_ts_b_5th:
                description:
                - "ipv4-fib table sync end time stamp blade for T-4 synchronization"
                type: str
            ipv6_fib_tbl_sync_end_ts_b_5th:
                description:
                - "ipv6-fib table sync end time stamp blade for T-4 synchronization"
                type: str
            mac_tbl_sync_end_ts_b_5th:
                description:
                - "mac table sync end time stamp blade for T-4 synchronization"
                type: str
            arp_tbl_sync_m:
                description:
                - "arp table sync count in master"
                type: str
            nd6_tbl_sync_m:
                description:
                - "nd6 table sync count in master"
                type: str
            ipv4_fib_tbl_sync_m:
                description:
                - "ipv4-fib table sync count in master"
                type: str
            ipv6_fib_tbl_sync_m:
                description:
                - "ipv6-fib table sync count in master"
                type: str
            mac_tbl_sync_m:
                description:
                - "mac table sync count in master"
                type: str
            arp_tbl_sync_b:
                description:
                - "arp table sync count in blade"
                type: str
            nd6_tbl_sync_b:
                description:
                - "nd6 table sync count in blade"
                type: str
            ipv4_fib_tbl_sync_b:
                description:
                - "ipv4-fib table sync count in blade"
                type: str
            ipv6_fib_tbl_sync_b:
                description:
                - "ipv6-fib table sync count in blade"
                type: str
            mac_tbl_sync_b:
                description:
                - "mac table sync count in blade"
                type: str
            arp_tbl_cksum_m:
                description:
                - "arp table checksum count in master"
                type: str
            nd6_tbl_cksum_m:
                description:
                - "nd6 table checksum count in master"
                type: str
            ipv4_fib_tbl_cksum_m:
                description:
                - "ipv4-fib table checksum count in master"
                type: str
            ipv6_fib_tbl_cksum_m:
                description:
                - "ipv6-fib table checksum count in master"
                type: str
            mac_tbl_cksum_m:
                description:
                - "mac table checksum count in master"
                type: str
            arp_tbl_cksum_b:
                description:
                - "arp table checksum count in blade"
                type: str
            nd6_tbl_cksum_b:
                description:
                - "nd6 table checksum count in blade"
                type: str
            ipv4_fib_tbl_cksum_b:
                description:
                - "ipv4-fib table checksum count in blade"
                type: str
            ipv6_fib_tbl_cksum_b:
                description:
                - "ipv6-fib table checksum count in blade"
                type: str
            mac_tbl_cksum_b:
                description:
                - "mac table checksum count in blade"
                type: str
            arp_tbl_cksum_mismatch_b:
                description:
                - "arp table checksum mismatch count in blade"
                type: str
            nd6_tbl_cksum_mismatch_b:
                description:
                - "nd6 table checksum mismatch count in blade"
                type: str
            ipv4_fib_tbl_cksum_mismatch_b:
                description:
                - "ipv4-fib table checksum mismatch count in blade"
                type: str
            ipv6_fib_tbl_cksum_mismatch_b:
                description:
                - "ipv6-fib table checksum mismatch count in blade"
                type: str
            mac_tbl_cksum_mismatch_b:
                description:
                - "mac table checksum mismatch count in blade"
                type: str
            arp_tbl_cksum_cancel_m:
                description:
                - "arp table checksum cancelled count in master"
                type: str
            nd6_tbl_cksum_cancel_m:
                description:
                - "nd6 table checksum cancelled count in master"
                type: str
            ipv4_fib_tbl_cksum_cancel_m:
                description:
                - "ipv4-fib table checksum cancelled count in master"
                type: str
            ipv6_fib_tbl_cksum_cancel_m:
                description:
                - "ipv6-fib table checksum cancelled count in master"
                type: str
            mac_tbl_cksum_cancel_m:
                description:
                - "mac table checksum cancelled count in master"
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
AVAILABLE_PROPERTIES = ["audit_action", "auto_sync_action", "sampling_enable", "stats", "table", "uuid", ]


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
        'table': {
            'type': 'str',
            'choices': ['all']
            },
        'audit_action': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'auto_sync_action': {
            'type': 'str',
            'choices': ['enable', 'disable']
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
                    'all', 'arp-tbl-sync-start-ts-m-1st', 'nd6-tbl-sync-start-ts-m-1st', 'ipv4-fib-tbl-sync-start-ts-m-1st', 'ipv6-fib-tbl-sync-start-ts-m-1st', 'mac-tbl-sync-start-ts-m-1st', 'arp-tbl-sync-start-ts-b-1st', 'nd6-tbl-sync-start-ts-b-1st', 'ipv4-fib-tbl-sync-start-ts-b-1st',
                    'ipv6-fib-tbl-sync-start-ts-b-1st', 'mac-tbl-sync-start-ts-b-1st', 'arp-tbl-sync-entries-sent-m-1st', 'nd6-tbl-sync-entries-sent-m-1st', 'ipv4-fib-tbl-sync-entries-sent-m-1st', 'ipv6-fib-tbl-sync-entries-sent-m-1st', 'mac-tbl-sync-entries-sent-m-1st',
                    'arp-tbl-sync-entries-rcvd-b-1st', 'nd6-tbl-sync-entries-rcvd-b-1st', 'ipv4-fib-tbl-sync-entries-rcvd-b-1st', 'ipv6-fib-tbl-sync-entries-rcvd-b-1st', 'mac-tbl-sync-entries-rcvd-b-1st', 'arp-tbl-sync-entries-added-b-1st', 'nd6-tbl-sync-entries-added-b-1st',
                    'ipv4-fib-tbl-sync-entries-added-b-1st', 'ipv6-fib-tbl-sync-entries-added-b-1st', 'mac-tbl-sync-entries-added-b-1st', 'arp-tbl-sync-entries-removed-b-1st', 'nd6-tbl-sync-entries-removed-b-1st', 'ipv4-fib-tbl-sync-entries-removed-b-1st', 'ipv6-fib-tbl-sync-entries-removed-b-1st',
                    'mac-tbl-sync-entries-removed-b-1st', 'arp-tbl-sync-end-ts-m-1st', 'nd6-tbl-sync-end-ts-m-1st', 'ipv4-fib-tbl-sync-end-ts-m-1st', 'ipv6-fib-tbl-sync-end-ts-m-1st', 'mac-tbl-sync-end-ts-m-1st', 'arp-tbl-sync-end-ts-b-1st', 'nd6-tbl-sync-end-ts-b-1st',
                    'ipv4-fib-tbl-sync-end-ts-b-1st', 'ipv6-fib-tbl-sync-end-ts-b-1st', 'mac-tbl-sync-end-ts-b-1st', 'arp-tbl-sync-start-ts-m-2nd', 'nd6-tbl-sync-start-ts-m-2nd', 'ipv4-fib-tbl-sync-start-ts-m-2nd', 'ipv6-fib-tbl-sync-start-ts-m-2nd', 'mac-tbl-sync-start-ts-m-2nd',
                    'arp-tbl-sync-start-ts-b-2nd', 'nd6-tbl-sync-start-ts-b-2nd', 'ipv4-fib-tbl-sync-start-ts-b-2nd', 'ipv6-fib-tbl-sync-start-ts-b-2nd', 'mac-tbl-sync-start-ts-b-2nd', 'arp-tbl-sync-entries-sent-m-2nd', 'nd6-tbl-sync-entries-sent-m-2nd', 'ipv4-fib-tbl-sync-entries-sent-m-2nd',
                    'ipv6-fib-tbl-sync-entries-sent-m-2nd', 'mac-tbl-sync-entries-sent-m-2nd', 'arp-tbl-sync-entries-rcvd-b-2nd', 'nd6-tbl-sync-entries-rcvd-b-2nd', 'ipv4-fib-tbl-sync-entries-rcvd-b-2nd', 'ipv6-fib-tbl-sync-entries-rcvd-b-2nd', 'mac-tbl-sync-entries-rcvd-b-2nd',
                    'arp-tbl-sync-entries-added-b-2nd', 'nd6-tbl-sync-entries-added-b-2nd', 'ipv4-fib-tbl-sync-entries-added-b-2nd', 'ipv6-fib-tbl-sync-entries-added-b-2nd', 'mac-tbl-sync-entries-added-b-2nd', 'arp-tbl-sync-entries-removed-b-2nd', 'nd6-tbl-sync-entries-removed-b-2nd',
                    'ipv4-fib-tbl-sync-entries-removed-b-2nd', 'ipv6-fib-tbl-sync-entries-removed-b-2nd', 'mac-tbl-sync-entries-removed-b-2nd', 'arp-tbl-sync-end-ts-m-2nd', 'nd6-tbl-sync-end-ts-m-2nd', 'ipv4-fib-tbl-sync-end-ts-m-2nd', 'ipv6-fib-tbl-sync-end-ts-m-2nd', 'mac-tbl-sync-end-ts-m-2nd',
                    'arp-tbl-sync-end-ts-b-2nd', 'nd6-tbl-sync-end-ts-b-2nd', 'ipv4-fib-tbl-sync-end-ts-b-2nd', 'ipv6-fib-tbl-sync-end-ts-b-2nd', 'mac-tbl-sync-end-ts-b-2nd', 'arp-tbl-sync-start-ts-m-3rd', 'nd6-tbl-sync-start-ts-m-3rd'
                    ]
                },
            'counters2': {
                'type':
                'str',
                'choices': [
                    'ipv4-fib-tbl-sync-start-ts-m-3rd', 'ipv6-fib-tbl-sync-start-ts-m-3rd', 'mac-tbl-sync-start-ts-m-3rd', 'arp-tbl-sync-start-ts-b-3rd', 'nd6-tbl-sync-start-ts-b-3rd', 'ipv4-fib-tbl-sync-start-ts-b-3rd', 'ipv6-fib-tbl-sync-start-ts-b-3rd', 'mac-tbl-sync-start-ts-b-3rd',
                    'arp-tbl-sync-entries-sent-m-3rd', 'nd6-tbl-sync-entries-sent-m-3rd', 'ipv4-fib-tbl-sync-entries-sent-m-3rd', 'ipv6-fib-tbl-sync-entries-sent-m-3rd', 'mac-tbl-sync-entries-sent-m-3rd', 'arp-tbl-sync-entries-rcvd-b-3rd', 'nd6-tbl-sync-entries-rcvd-b-3rd',
                    'ipv4-fib-tbl-sync-entries-rcvd-b-3rd', 'ipv6-fib-tbl-sync-entries-rcvd-b-3rd', 'mac-tbl-sync-entries-rcvd-b-3rd', 'arp-tbl-sync-entries-added-b-3rd', 'nd6-tbl-sync-entries-added-b-3rd', 'ipv4-fib-tbl-sync-entries-added-b-3rd', 'ipv6-fib-tbl-sync-entries-added-b-3rd',
                    'mac-tbl-sync-entries-added-b-3rd', 'arp-tbl-sync-entries-removed-b-3rd', 'nd6-tbl-sync-entries-removed-b-3rd', 'ipv4-fib-tbl-sync-entries-removed-b-3rd', 'ipv6-fib-tbl-sync-entries-removed-b-3rd', 'mac-tbl-sync-entries-removed-b-3rd', 'arp-tbl-sync-end-ts-m-3rd',
                    'nd6-tbl-sync-end-ts-m-3rd', 'ipv4-fib-tbl-sync-end-ts-m-3rd', 'ipv6-fib-tbl-sync-end-ts-m-3rd', 'mac-tbl-sync-end-ts-m-3rd', 'arp-tbl-sync-end-ts-b-3rd', 'nd6-tbl-sync-end-ts-b-3rd', 'ipv4-fib-tbl-sync-end-ts-b-3rd', 'ipv6-fib-tbl-sync-end-ts-b-3rd', 'mac-tbl-sync-end-ts-b-3rd',
                    'arp-tbl-sync-start-ts-m-4th', 'nd6-tbl-sync-start-ts-m-4th', 'ipv4-fib-tbl-sync-start-ts-m-4th', 'ipv6-fib-tbl-sync-start-ts-m-4th', 'mac-tbl-sync-start-ts-m-4th', 'arp-tbl-sync-start-ts-b-4th', 'nd6-tbl-sync-start-ts-b-4th', 'ipv4-fib-tbl-sync-start-ts-b-4th',
                    'ipv6-fib-tbl-sync-start-ts-b-4th', 'mac-tbl-sync-start-ts-b-4th', 'arp-tbl-sync-entries-sent-m-4th', 'nd6-tbl-sync-entries-sent-m-4th', 'ipv4-fib-tbl-sync-entries-sent-m-4th', 'ipv6-fib-tbl-sync-entries-sent-m-4th', 'mac-tbl-sync-entries-sent-m-4th',
                    'arp-tbl-sync-entries-rcvd-b-4th', 'nd6-tbl-sync-entries-rcvd-b-4th', 'ipv4-fib-tbl-sync-entries-rcvd-b-4th', 'ipv6-fib-tbl-sync-entries-rcvd-b-4th', 'mac-tbl-sync-entries-rcvd-b-4th', 'arp-tbl-sync-entries-added-b-4th', 'nd6-tbl-sync-entries-added-b-4th',
                    'ipv4-fib-tbl-sync-entries-added-b-4th', 'ipv6-fib-tbl-sync-entries-added-b-4th', 'mac-tbl-sync-entries-added-b-4th', 'arp-tbl-sync-entries-removed-b-4th', 'nd6-tbl-sync-entries-removed-b-4th', 'ipv4-fib-tbl-sync-entries-removed-b-4th', 'ipv6-fib-tbl-sync-entries-removed-b-4th',
                    'mac-tbl-sync-entries-removed-b-4th', 'arp-tbl-sync-end-ts-m-4th', 'nd6-tbl-sync-end-ts-m-4th', 'ipv4-fib-tbl-sync-end-ts-m-4th', 'ipv6-fib-tbl-sync-end-ts-m-4th', 'mac-tbl-sync-end-ts-m-4th', 'arp-tbl-sync-end-ts-b-4th', 'nd6-tbl-sync-end-ts-b-4th',
                    'ipv4-fib-tbl-sync-end-ts-b-4th', 'ipv6-fib-tbl-sync-end-ts-b-4th', 'mac-tbl-sync-end-ts-b-4th', 'arp-tbl-sync-start-ts-m-5th'
                    ]
                },
            'counters3': {
                'type':
                'str',
                'choices': [
                    'nd6-tbl-sync-start-ts-m-5th', 'ipv4-fib-tbl-sync-start-ts-m-5th', 'ipv6-fib-tbl-sync-start-ts-m-5th', 'mac-tbl-sync-start-ts-m-5th', 'arp-tbl-sync-start-ts-b-5th', 'nd6-tbl-sync-start-ts-b-5th', 'ipv4-fib-tbl-sync-start-ts-b-5th', 'ipv6-fib-tbl-sync-start-ts-b-5th',
                    'mac-tbl-sync-start-ts-b-5th', 'arp-tbl-sync-entries-sent-m-5th', 'nd6-tbl-sync-entries-sent-m-5th', 'ipv4-fib-tbl-sync-entries-sent-m-5th', 'ipv6-fib-tbl-sync-entries-sent-m-5th', 'mac-tbl-sync-entries-sent-m-5th', 'arp-tbl-sync-entries-rcvd-b-5th',
                    'nd6-tbl-sync-entries-rcvd-b-5th', 'ipv4-fib-tbl-sync-entries-rcvd-b-5th', 'ipv6-fib-tbl-sync-entries-rcvd-b-5th', 'mac-tbl-sync-entries-rcvd-b-5th', 'arp-tbl-sync-entries-added-b-5th', 'nd6-tbl-sync-entries-added-b-5th', 'ipv4-fib-tbl-sync-entries-added-b-5th',
                    'ipv6-fib-tbl-sync-entries-added-b-5th', 'mac-tbl-sync-entries-added-b-5th', 'arp-tbl-sync-entries-removed-b-5th', 'nd6-tbl-sync-entries-removed-b-5th', 'ipv4-fib-tbl-sync-entries-removed-b-5th', 'ipv6-fib-tbl-sync-entries-removed-b-5th', 'mac-tbl-sync-entries-removed-b-5th',
                    'arp-tbl-sync-end-ts-m-5th', 'nd6-tbl-sync-end-ts-m-5th', 'ipv4-fib-tbl-sync-end-ts-m-5th', 'ipv6-fib-tbl-sync-end-ts-m-5th', 'mac-tbl-sync-end-ts-m-5th', 'arp-tbl-sync-end-ts-b-5th', 'nd6-tbl-sync-end-ts-b-5th', 'ipv4-fib-tbl-sync-end-ts-b-5th', 'ipv6-fib-tbl-sync-end-ts-b-5th',
                    'mac-tbl-sync-end-ts-b-5th', 'arp-tbl-sync-m', 'nd6-tbl-sync-m', 'ipv4-fib-tbl-sync-m', 'ipv6-fib-tbl-sync-m', 'mac-tbl-sync-m', 'arp-tbl-sync-b', 'nd6-tbl-sync-b', 'ipv4-fib-tbl-sync-b', 'ipv6-fib-tbl-sync-b', 'mac-tbl-sync-b', 'arp-tbl-cksum-m', 'nd6-tbl-cksum-m',
                    'ipv4-fib-tbl-cksum-m', 'ipv6-fib-tbl-cksum-m', 'mac-tbl-cksum-m', 'arp-tbl-cksum-b', 'nd6-tbl-cksum-b', 'ipv4-fib-tbl-cksum-b', 'ipv6-fib-tbl-cksum-b', 'mac-tbl-cksum-b', 'arp-tbl-cksum-mismatch-b', 'nd6-tbl-cksum-mismatch-b', 'ipv4-fib-tbl-cksum-mismatch-b',
                    'ipv6-fib-tbl-cksum-mismatch-b', 'mac-tbl-cksum-mismatch-b', 'arp-tbl-cksum-cancel-m', 'nd6-tbl-cksum-cancel-m', 'ipv4-fib-tbl-cksum-cancel-m', 'ipv6-fib-tbl-cksum-cancel-m', 'mac-tbl-cksum-cancel-m'
                    ]
                }
            },
        'stats': {
            'type': 'dict',
            'arp_tbl_sync_start_ts_m_1st': {
                'type': 'str',
                },
            'nd6_tbl_sync_start_ts_m_1st': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_start_ts_m_1st': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_start_ts_m_1st': {
                'type': 'str',
                },
            'mac_tbl_sync_start_ts_m_1st': {
                'type': 'str',
                },
            'arp_tbl_sync_start_ts_b_1st': {
                'type': 'str',
                },
            'nd6_tbl_sync_start_ts_b_1st': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_start_ts_b_1st': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_start_ts_b_1st': {
                'type': 'str',
                },
            'mac_tbl_sync_start_ts_b_1st': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_sent_m_1st': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_sent_m_1st': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_sent_m_1st': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_sent_m_1st': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_sent_m_1st': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_rcvd_b_1st': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_rcvd_b_1st': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_rcvd_b_1st': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_rcvd_b_1st': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_rcvd_b_1st': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_added_b_1st': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_added_b_1st': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_added_b_1st': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_added_b_1st': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_added_b_1st': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_removed_b_1st': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_removed_b_1st': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_removed_b_1st': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_removed_b_1st': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_removed_b_1st': {
                'type': 'str',
                },
            'arp_tbl_sync_end_ts_m_1st': {
                'type': 'str',
                },
            'nd6_tbl_sync_end_ts_m_1st': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_end_ts_m_1st': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_end_ts_m_1st': {
                'type': 'str',
                },
            'mac_tbl_sync_end_ts_m_1st': {
                'type': 'str',
                },
            'arp_tbl_sync_end_ts_b_1st': {
                'type': 'str',
                },
            'nd6_tbl_sync_end_ts_b_1st': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_end_ts_b_1st': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_end_ts_b_1st': {
                'type': 'str',
                },
            'mac_tbl_sync_end_ts_b_1st': {
                'type': 'str',
                },
            'arp_tbl_sync_start_ts_m_2nd': {
                'type': 'str',
                },
            'nd6_tbl_sync_start_ts_m_2nd': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_start_ts_m_2nd': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_start_ts_m_2nd': {
                'type': 'str',
                },
            'mac_tbl_sync_start_ts_m_2nd': {
                'type': 'str',
                },
            'arp_tbl_sync_start_ts_b_2nd': {
                'type': 'str',
                },
            'nd6_tbl_sync_start_ts_b_2nd': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_start_ts_b_2nd': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_start_ts_b_2nd': {
                'type': 'str',
                },
            'mac_tbl_sync_start_ts_b_2nd': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_sent_m_2nd': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_sent_m_2nd': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_sent_m_2nd': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_sent_m_2nd': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_sent_m_2nd': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_rcvd_b_2nd': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_rcvd_b_2nd': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_rcvd_b_2nd': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_rcvd_b_2nd': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_rcvd_b_2nd': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_added_b_2nd': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_added_b_2nd': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_added_b_2nd': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_added_b_2nd': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_added_b_2nd': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_removed_b_2nd': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_removed_b_2nd': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_removed_b_2nd': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_removed_b_2nd': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_removed_b_2nd': {
                'type': 'str',
                },
            'arp_tbl_sync_end_ts_m_2nd': {
                'type': 'str',
                },
            'nd6_tbl_sync_end_ts_m_2nd': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_end_ts_m_2nd': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_end_ts_m_2nd': {
                'type': 'str',
                },
            'mac_tbl_sync_end_ts_m_2nd': {
                'type': 'str',
                },
            'arp_tbl_sync_end_ts_b_2nd': {
                'type': 'str',
                },
            'nd6_tbl_sync_end_ts_b_2nd': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_end_ts_b_2nd': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_end_ts_b_2nd': {
                'type': 'str',
                },
            'mac_tbl_sync_end_ts_b_2nd': {
                'type': 'str',
                },
            'arp_tbl_sync_start_ts_m_3rd': {
                'type': 'str',
                },
            'nd6_tbl_sync_start_ts_m_3rd': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_start_ts_m_3rd': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_start_ts_m_3rd': {
                'type': 'str',
                },
            'mac_tbl_sync_start_ts_m_3rd': {
                'type': 'str',
                },
            'arp_tbl_sync_start_ts_b_3rd': {
                'type': 'str',
                },
            'nd6_tbl_sync_start_ts_b_3rd': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_start_ts_b_3rd': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_start_ts_b_3rd': {
                'type': 'str',
                },
            'mac_tbl_sync_start_ts_b_3rd': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_sent_m_3rd': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_sent_m_3rd': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_sent_m_3rd': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_sent_m_3rd': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_sent_m_3rd': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_rcvd_b_3rd': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_rcvd_b_3rd': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_rcvd_b_3rd': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_rcvd_b_3rd': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_rcvd_b_3rd': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_added_b_3rd': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_added_b_3rd': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_added_b_3rd': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_added_b_3rd': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_added_b_3rd': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_removed_b_3rd': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_removed_b_3rd': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_removed_b_3rd': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_removed_b_3rd': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_removed_b_3rd': {
                'type': 'str',
                },
            'arp_tbl_sync_end_ts_m_3rd': {
                'type': 'str',
                },
            'nd6_tbl_sync_end_ts_m_3rd': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_end_ts_m_3rd': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_end_ts_m_3rd': {
                'type': 'str',
                },
            'mac_tbl_sync_end_ts_m_3rd': {
                'type': 'str',
                },
            'arp_tbl_sync_end_ts_b_3rd': {
                'type': 'str',
                },
            'nd6_tbl_sync_end_ts_b_3rd': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_end_ts_b_3rd': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_end_ts_b_3rd': {
                'type': 'str',
                },
            'mac_tbl_sync_end_ts_b_3rd': {
                'type': 'str',
                },
            'arp_tbl_sync_start_ts_m_4th': {
                'type': 'str',
                },
            'nd6_tbl_sync_start_ts_m_4th': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_start_ts_m_4th': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_start_ts_m_4th': {
                'type': 'str',
                },
            'mac_tbl_sync_start_ts_m_4th': {
                'type': 'str',
                },
            'arp_tbl_sync_start_ts_b_4th': {
                'type': 'str',
                },
            'nd6_tbl_sync_start_ts_b_4th': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_start_ts_b_4th': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_start_ts_b_4th': {
                'type': 'str',
                },
            'mac_tbl_sync_start_ts_b_4th': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_sent_m_4th': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_sent_m_4th': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_sent_m_4th': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_sent_m_4th': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_sent_m_4th': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_rcvd_b_4th': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_rcvd_b_4th': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_rcvd_b_4th': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_rcvd_b_4th': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_rcvd_b_4th': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_added_b_4th': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_added_b_4th': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_added_b_4th': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_added_b_4th': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_added_b_4th': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_removed_b_4th': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_removed_b_4th': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_removed_b_4th': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_removed_b_4th': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_removed_b_4th': {
                'type': 'str',
                },
            'arp_tbl_sync_end_ts_m_4th': {
                'type': 'str',
                },
            'nd6_tbl_sync_end_ts_m_4th': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_end_ts_m_4th': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_end_ts_m_4th': {
                'type': 'str',
                },
            'mac_tbl_sync_end_ts_m_4th': {
                'type': 'str',
                },
            'arp_tbl_sync_end_ts_b_4th': {
                'type': 'str',
                },
            'nd6_tbl_sync_end_ts_b_4th': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_end_ts_b_4th': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_end_ts_b_4th': {
                'type': 'str',
                },
            'mac_tbl_sync_end_ts_b_4th': {
                'type': 'str',
                },
            'arp_tbl_sync_start_ts_m_5th': {
                'type': 'str',
                },
            'nd6_tbl_sync_start_ts_m_5th': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_start_ts_m_5th': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_start_ts_m_5th': {
                'type': 'str',
                },
            'mac_tbl_sync_start_ts_m_5th': {
                'type': 'str',
                },
            'arp_tbl_sync_start_ts_b_5th': {
                'type': 'str',
                },
            'nd6_tbl_sync_start_ts_b_5th': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_start_ts_b_5th': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_start_ts_b_5th': {
                'type': 'str',
                },
            'mac_tbl_sync_start_ts_b_5th': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_sent_m_5th': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_sent_m_5th': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_sent_m_5th': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_sent_m_5th': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_sent_m_5th': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_rcvd_b_5th': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_rcvd_b_5th': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_rcvd_b_5th': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_rcvd_b_5th': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_rcvd_b_5th': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_added_b_5th': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_added_b_5th': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_added_b_5th': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_added_b_5th': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_added_b_5th': {
                'type': 'str',
                },
            'arp_tbl_sync_entries_removed_b_5th': {
                'type': 'str',
                },
            'nd6_tbl_sync_entries_removed_b_5th': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_entries_removed_b_5th': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_entries_removed_b_5th': {
                'type': 'str',
                },
            'mac_tbl_sync_entries_removed_b_5th': {
                'type': 'str',
                },
            'arp_tbl_sync_end_ts_m_5th': {
                'type': 'str',
                },
            'nd6_tbl_sync_end_ts_m_5th': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_end_ts_m_5th': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_end_ts_m_5th': {
                'type': 'str',
                },
            'mac_tbl_sync_end_ts_m_5th': {
                'type': 'str',
                },
            'arp_tbl_sync_end_ts_b_5th': {
                'type': 'str',
                },
            'nd6_tbl_sync_end_ts_b_5th': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_end_ts_b_5th': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_end_ts_b_5th': {
                'type': 'str',
                },
            'mac_tbl_sync_end_ts_b_5th': {
                'type': 'str',
                },
            'arp_tbl_sync_m': {
                'type': 'str',
                },
            'nd6_tbl_sync_m': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_m': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_m': {
                'type': 'str',
                },
            'mac_tbl_sync_m': {
                'type': 'str',
                },
            'arp_tbl_sync_b': {
                'type': 'str',
                },
            'nd6_tbl_sync_b': {
                'type': 'str',
                },
            'ipv4_fib_tbl_sync_b': {
                'type': 'str',
                },
            'ipv6_fib_tbl_sync_b': {
                'type': 'str',
                },
            'mac_tbl_sync_b': {
                'type': 'str',
                },
            'arp_tbl_cksum_m': {
                'type': 'str',
                },
            'nd6_tbl_cksum_m': {
                'type': 'str',
                },
            'ipv4_fib_tbl_cksum_m': {
                'type': 'str',
                },
            'ipv6_fib_tbl_cksum_m': {
                'type': 'str',
                },
            'mac_tbl_cksum_m': {
                'type': 'str',
                },
            'arp_tbl_cksum_b': {
                'type': 'str',
                },
            'nd6_tbl_cksum_b': {
                'type': 'str',
                },
            'ipv4_fib_tbl_cksum_b': {
                'type': 'str',
                },
            'ipv6_fib_tbl_cksum_b': {
                'type': 'str',
                },
            'mac_tbl_cksum_b': {
                'type': 'str',
                },
            'arp_tbl_cksum_mismatch_b': {
                'type': 'str',
                },
            'nd6_tbl_cksum_mismatch_b': {
                'type': 'str',
                },
            'ipv4_fib_tbl_cksum_mismatch_b': {
                'type': 'str',
                },
            'ipv6_fib_tbl_cksum_mismatch_b': {
                'type': 'str',
                },
            'mac_tbl_cksum_mismatch_b': {
                'type': 'str',
                },
            'arp_tbl_cksum_cancel_m': {
                'type': 'str',
                },
            'nd6_tbl_cksum_cancel_m': {
                'type': 'str',
                },
            'ipv4_fib_tbl_cksum_cancel_m': {
                'type': 'str',
                },
            'ipv6_fib_tbl_cksum_cancel_m': {
                'type': 'str',
                },
            'mac_tbl_cksum_cancel_m': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/table-integrity"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/system/table-integrity"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["table-integrity"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["table-integrity"].get(k) != v:
            change_results["changed"] = True
            config_changes["table-integrity"][k] = v

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
    payload = utils.build_json("table-integrity", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["table-integrity"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["table-integrity-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["table-integrity"]["stats"] if info != "NotFound" else info
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
