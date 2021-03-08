#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_service_group
description:
    - Service Group
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
        - "SLB Service Name"
        type: str
        required: True
    protocol:
        description:
        - "'tcp'= TCP LB service; 'udp'= UDP LB service;"
        type: str
        required: False
    template_port:
        description:
        - "Port template (Port template name)"
        type: str
        required: False
    template_policy:
        description:
        - "Policy template (Policy template name)"
        type: str
        required: False
    shared_partition_policy_template:
        description:
        - "Reference a policy template from shared partition"
        type: bool
        required: False
    template_policy_shared:
        description:
        - "Policy template"
        type: str
        required: False
    lb_method:
        description:
        - "'dst-ip-hash'= Load-balancing based on only Dst IP and Port hash; 'dst-ip-only-
          hash'= Load-balancing based on only Dst IP hash; 'fastest-response'= Fastest
          response time on service port level; 'least-request'= Least request on service
          port level; 'src-ip-hash'= Load-balancing based on only Src IP and Port hash;
          'src-ip-only-hash'= Load-balancing based on only Src IP hash; 'weighted-rr'=
          Weighted round robin on server level; 'service-weighted-rr'= Weighted round
          robin on service port level; 'round-robin'= Round robin on server level;
          'round-robin-strict'= Strict mode round robin on server level; 'odd-even-hash'=
          odd/even hash based of client src-ip;"
        type: str
        required: False
    lc_method:
        description:
        - "'least-connection'= Least connection on server level; 'service-least-
          connection'= Least connection on service port level; 'weighted-least-
          connection'= Weighted least connection on server level; 'service-weighted-
          least-connection'= Weighted least connection on service port level;"
        type: str
        required: False
    stateless_lb_method:
        description:
        - "'stateless-dst-ip-hash'= Stateless load-balancing based on Dst IP and Dst port
          hash; 'stateless-per-pkt-round-robin'= Stateless load-balancing using per-
          packet round-robin; 'stateless-src-dst-ip-hash'= Stateless load-balancing based
          on IP and port hash for both Src and Dst; 'stateless-src-dst-ip-only-hash'=
          Stateless load-balancing based on only IP hash for both Src and Dst;
          'stateless-src-ip-hash'= Stateless load-balancing based on Src IP and Src port
          hash; 'stateless-src-ip-only-hash'= Stateless load-balancing based on only Src
          IP hash;"
        type: str
        required: False
    pseudo_round_robin:
        description:
        - "PRR, select the oldest node for sub-select"
        type: bool
        required: False
    stateless_auto_switch:
        description:
        - "Enable auto stateless method"
        type: bool
        required: False
    stateless_lb_method2:
        description:
        - "'stateless-dst-ip-hash'= Stateless load-balancing based on Dst IP and Dst port
          hash; 'stateless-per-pkt-round-robin'= Stateless load-balancing using per-
          packet round-robin; 'stateless-src-dst-ip-hash'= Stateless load-balancing based
          on IP and port hash for both Src and Dst; 'stateless-src-dst-ip-only-hash'=
          Stateless load-balancing based on only IP hash for both Src and Dst;
          'stateless-src-ip-hash'= Stateless load-balancing based on Src IP and Src port
          hash; 'stateless-src-ip-only-hash'= Stateless load-balancing based on only Src
          IP hash;"
        type: str
        required: False
    conn_rate:
        description:
        - "Dynamically enable stateless method by conn-rate (Rate to trigger stateless
          method(conn/sec))"
        type: int
        required: False
    conn_rate_duration:
        description:
        - "Period that trigger condition consistently happens(seconds)"
        type: int
        required: False
    conn_revert_rate:
        description:
        - "Rate to revert to statelful method (conn/sec)"
        type: int
        required: False
    conn_rate_revert_duration:
        description:
        - "Period that revert condition consistently happens(seconds)"
        type: int
        required: False
    conn_rate_grace_period:
        description:
        - "Define the grace period during transition (Define the grace period during
          transition(seconds))"
        type: int
        required: False
    conn_rate_log:
        description:
        - "Send log if transition happens"
        type: bool
        required: False
    l4_session_usage:
        description:
        - "Dynamically enable stateless method by session usage (Usage to trigger
          stateless method)"
        type: int
        required: False
    l4_session_usage_duration:
        description:
        - "Period that trigger condition consistently happens(seconds)"
        type: int
        required: False
    l4_session_usage_revert_rate:
        description:
        - "Usage to revert to statelful method"
        type: int
        required: False
    l4_session_revert_duration:
        description:
        - "Period that revert condition consistently happens(seconds)"
        type: int
        required: False
    l4_session_usage_grace_period:
        description:
        - "Define the grace period during transition (Define the grace period during
          transition(seconds))"
        type: int
        required: False
    l4_session_usage_log:
        description:
        - "Send log if transition happens"
        type: bool
        required: False
    min_active_member:
        description:
        - "Minimum Active Member Per Priority (Minimum Active Member before Action)"
        type: int
        required: False
    min_active_member_action:
        description:
        - "'dynamic-priority'= dynamic change member priority to met the min-active-member
          requirement; 'skip-pri-set'= Skip Current Priority Set If Min not met;"
        type: str
        required: False
    reset_on_server_selection_fail:
        description:
        - "Send reset to client if server selection fails"
        type: bool
        required: False
    priority_affinity:
        description:
        - "Priority affinity. Persist to the same priority if possible."
        type: bool
        required: False
    reset_priority_affinity:
        description:
        - "Reset"
        type: bool
        required: False
    backup_server_event_log:
        description:
        - "Send log info on back up server events"
        type: bool
        required: False
    strict_select:
        description:
        - "strict selection"
        type: bool
        required: False
    stats_data_action:
        description:
        - "'stats-data-enable'= Enable statistical data collection for service group;
          'stats-data-disable'= Disable statistical data collection for service group;"
        type: str
        required: False
    extended_stats:
        description:
        - "Enable extended statistics on service group"
        type: bool
        required: False
    traffic_replication_mirror:
        description:
        - "Mirror Bi-directional Packet"
        type: bool
        required: False
    traffic_replication_mirror_da_repl:
        description:
        - "Replace Destination MAC"
        type: bool
        required: False
    traffic_replication_mirror_ip_repl:
        description:
        - "Replaces IP with server-IP"
        type: bool
        required: False
    traffic_replication_mirror_sa_da_repl:
        description:
        - "Replace Source MAC and Destination MAC"
        type: bool
        required: False
    traffic_replication_mirror_sa_repl:
        description:
        - "Replace Source MAC"
        type: bool
        required: False
    health_check:
        description:
        - "Health Check (Monitor Name)"
        type: str
        required: False
    shared_partition_svcgrp_health_check:
        description:
        - "Reference a health-check from shared partition"
        type: bool
        required: False
    svcgrp_health_check_shared:
        description:
        - "Health Check (Monitor Name)"
        type: str
        required: False
    health_check_disable:
        description:
        - "Disable health check"
        type: bool
        required: False
    priorities:
        description:
        - "Field priorities"
        type: list
        required: False
        suboptions:
            priority:
                description:
                - "Priority option. Define different action for each priority node. (Priority in
          the Group)"
                type: int
            priority_action:
                description:
                - "'drop'= Drop request when all priority nodes fail; 'drop-if-exceed-limit'= Drop
          request when connection over limit; 'proceed'= Proceed to next priority when
          all priority nodes fail(default); 'reset'= Send client reset when all priority
          nodes fail; 'reset-if-exceed-limit'= Send client reset when connection over
          limit;"
                type: str
    sample_rsp_time:
        description:
        - "sample server response time"
        type: bool
        required: False
    rpt_ext_server:
        description:
        - "Report top 10 fastest/slowest servers"
        type: bool
        required: False
    report_delay:
        description:
        - "Reporting frequency (in minutes)"
        type: int
        required: False
    top_slowest:
        description:
        - "Report top 10 slowest servers"
        type: bool
        required: False
    top_fastest:
        description:
        - "Report top 10 fastest servers"
        type: bool
        required: False
    persist_scoring:
        description:
        - "'global'= Use Global Configuration; 'enable'= Enable persist-scoring;
          'disable'= Disable persist-scoring;"
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
                - "'all'= all; 'server_selection_fail_drop'= Drops due to Service selection
          failure; 'server_selection_fail_reset'= Resets sent out for Service selection
          failure; 'service_peak_conn'= Peak connection count for the Service Group;
          'service_healthy_host'= Service Group healthy host count;
          'service_unhealthy_host'= Service Group unhealthy host count;
          'service_req_count'= Service Group request count; 'service_resp_count'= Service
          Group response count; 'service_resp_2xx'= Service Group response 2xx count;
          'service_resp_3xx'= Service Group response 3xx count; 'service_resp_4xx'=
          Service Group response 4xx count; 'service_resp_5xx'= Service Group response
          5xx count; 'service_curr_conn_overflow'= Current connection counter overflow
          count;"
                type: str
    reset:
        description:
        - "Field reset"
        type: dict
        required: False
        suboptions:
            auto_switch:
                description:
                - "Reset auto stateless state"
                type: bool
    member_list:
        description:
        - "Field member_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Member name"
                type: str
            port:
                description:
                - "Port number"
                type: int
            fqdn_name:
                description:
                - "Server hostname - Not applicable if real server is already defined"
                type: str
            resolve_as:
                description:
                - "'resolve-to-ipv4'= Use A Query only to resolve FQDN; 'resolve-to-ipv6'= Use
          AAAA Query only to resolve FQDN; 'resolve-to-ipv4-and-ipv6'= Use A as well as
          AAAA Query to resolve FQDN;"
                type: str
            host:
                description:
                - "IP Address - Not applicable if real server is already defined"
                type: str
            server_ipv6_addr:
                description:
                - "IPV6 Address - Not applicable if real server is already defined"
                type: str
            member_state:
                description:
                - "'enable'= Enable member service port; 'disable'= Disable member service port;
          'disable-with-health-check'= disable member service port, but health check
          work;"
                type: str
            member_stats_data_disable:
                description:
                - "Disable statistical data collection"
                type: bool
            member_template:
                description:
                - "Real server port template (Real server port template name)"
                type: str
            member_priority:
                description:
                - "Priority of Port in the Group (Priority of Port in the Group, default is 1)"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
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
            servers_up:
                description:
                - "Field servers_up"
                type: int
            servers_down:
                description:
                - "Field servers_down"
                type: int
            servers_disable:
                description:
                - "Field servers_disable"
                type: int
            servers_total:
                description:
                - "Field servers_total"
                type: int
            stateless_current_rate:
                description:
                - "Field stateless_current_rate"
                type: int
            stateless_current_usage:
                description:
                - "Field stateless_current_usage"
                type: int
            stateless_state:
                description:
                - "Field stateless_state"
                type: int
            stateless_type:
                description:
                - "Field stateless_type"
                type: int
            hm_dsr_enable_all_vip:
                description:
                - "Field hm_dsr_enable_all_vip"
                type: int
            pri_affinity_priority:
                description:
                - "Field pri_affinity_priority"
                type: int
            filter:
                description:
                - "Field filter"
                type: str
            sgm_list:
                description:
                - "Field sgm_list"
                type: list
            name:
                description:
                - "SLB Service Name"
                type: str
            member_list:
                description:
                - "Field member_list"
                type: list
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            server_selection_fail_drop:
                description:
                - "Drops due to Service selection failure"
                type: str
            server_selection_fail_reset:
                description:
                - "Resets sent out for Service selection failure"
                type: str
            service_peak_conn:
                description:
                - "Peak connection count for the Service Group"
                type: str
            service_healthy_host:
                description:
                - "Service Group healthy host count"
                type: str
            service_unhealthy_host:
                description:
                - "Service Group unhealthy host count"
                type: str
            service_req_count:
                description:
                - "Service Group request count"
                type: str
            service_resp_count:
                description:
                - "Service Group response count"
                type: str
            service_resp_2xx:
                description:
                - "Service Group response 2xx count"
                type: str
            service_resp_3xx:
                description:
                - "Service Group response 3xx count"
                type: str
            service_resp_4xx:
                description:
                - "Service Group response 4xx count"
                type: str
            service_resp_5xx:
                description:
                - "Service Group response 5xx count"
                type: str
            service_curr_conn_overflow:
                description:
                - "Current connection counter overflow count"
                type: str
            name:
                description:
                - "SLB Service Name"
                type: str
            member_list:
                description:
                - "Field member_list"
                type: list

'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "backup_server_event_log",
    "conn_rate",
    "conn_rate_duration",
    "conn_rate_grace_period",
    "conn_rate_log",
    "conn_rate_revert_duration",
    "conn_revert_rate",
    "extended_stats",
    "health_check",
    "health_check_disable",
    "l4_session_revert_duration",
    "l4_session_usage",
    "l4_session_usage_duration",
    "l4_session_usage_grace_period",
    "l4_session_usage_log",
    "l4_session_usage_revert_rate",
    "lb_method",
    "lc_method",
    "member_list",
    "min_active_member",
    "min_active_member_action",
    "name",
    "oper",
    "persist_scoring",
    "priorities",
    "priority_affinity",
    "protocol",
    "pseudo_round_robin",
    "report_delay",
    "reset",
    "reset_on_server_selection_fail",
    "reset_priority_affinity",
    "rpt_ext_server",
    "sample_rsp_time",
    "sampling_enable",
    "shared_partition_policy_template",
    "shared_partition_svcgrp_health_check",
    "stateless_auto_switch",
    "stateless_lb_method",
    "stateless_lb_method2",
    "stats",
    "stats_data_action",
    "strict_select",
    "svcgrp_health_check_shared",
    "template_policy",
    "template_policy_shared",
    "template_port",
    "top_fastest",
    "top_slowest",
    "traffic_replication_mirror",
    "traffic_replication_mirror_da_repl",
    "traffic_replication_mirror_ip_repl",
    "traffic_replication_mirror_sa_da_repl",
    "traffic_replication_mirror_sa_repl",
    "user_tag",
    "uuid",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


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
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
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
        'protocol': {
            'type': 'str',
            'choices': ['tcp', 'udp']
        },
        'template_port': {
            'type': 'str',
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
        'lb_method': {
            'type':
            'str',
            'choices': [
                'dst-ip-hash', 'dst-ip-only-hash', 'fastest-response',
                'least-request', 'src-ip-hash', 'src-ip-only-hash',
                'weighted-rr', 'service-weighted-rr', 'round-robin',
                'round-robin-strict', 'odd-even-hash'
            ]
        },
        'lc_method': {
            'type':
            'str',
            'choices': [
                'least-connection', 'service-least-connection',
                'weighted-least-connection',
                'service-weighted-least-connection'
            ]
        },
        'stateless_lb_method': {
            'type':
            'str',
            'choices': [
                'stateless-dst-ip-hash', 'stateless-per-pkt-round-robin',
                'stateless-src-dst-ip-hash', 'stateless-src-dst-ip-only-hash',
                'stateless-src-ip-hash', 'stateless-src-ip-only-hash'
            ]
        },
        'pseudo_round_robin': {
            'type': 'bool',
        },
        'stateless_auto_switch': {
            'type': 'bool',
        },
        'stateless_lb_method2': {
            'type':
            'str',
            'choices': [
                'stateless-dst-ip-hash', 'stateless-per-pkt-round-robin',
                'stateless-src-dst-ip-hash', 'stateless-src-dst-ip-only-hash',
                'stateless-src-ip-hash', 'stateless-src-ip-only-hash'
            ]
        },
        'conn_rate': {
            'type': 'int',
        },
        'conn_rate_duration': {
            'type': 'int',
        },
        'conn_revert_rate': {
            'type': 'int',
        },
        'conn_rate_revert_duration': {
            'type': 'int',
        },
        'conn_rate_grace_period': {
            'type': 'int',
        },
        'conn_rate_log': {
            'type': 'bool',
        },
        'l4_session_usage': {
            'type': 'int',
        },
        'l4_session_usage_duration': {
            'type': 'int',
        },
        'l4_session_usage_revert_rate': {
            'type': 'int',
        },
        'l4_session_revert_duration': {
            'type': 'int',
        },
        'l4_session_usage_grace_period': {
            'type': 'int',
        },
        'l4_session_usage_log': {
            'type': 'bool',
        },
        'min_active_member': {
            'type': 'int',
        },
        'min_active_member_action': {
            'type': 'str',
            'choices': ['dynamic-priority', 'skip-pri-set']
        },
        'reset_on_server_selection_fail': {
            'type': 'bool',
        },
        'priority_affinity': {
            'type': 'bool',
        },
        'reset_priority_affinity': {
            'type': 'bool',
        },
        'backup_server_event_log': {
            'type': 'bool',
        },
        'strict_select': {
            'type': 'bool',
        },
        'stats_data_action': {
            'type': 'str',
            'choices': ['stats-data-enable', 'stats-data-disable']
        },
        'extended_stats': {
            'type': 'bool',
        },
        'traffic_replication_mirror': {
            'type': 'bool',
        },
        'traffic_replication_mirror_da_repl': {
            'type': 'bool',
        },
        'traffic_replication_mirror_ip_repl': {
            'type': 'bool',
        },
        'traffic_replication_mirror_sa_da_repl': {
            'type': 'bool',
        },
        'traffic_replication_mirror_sa_repl': {
            'type': 'bool',
        },
        'health_check': {
            'type': 'str',
        },
        'shared_partition_svcgrp_health_check': {
            'type': 'bool',
        },
        'svcgrp_health_check_shared': {
            'type': 'str',
        },
        'health_check_disable': {
            'type': 'bool',
        },
        'priorities': {
            'type': 'list',
            'priority': {
                'type': 'int',
            },
            'priority_action': {
                'type':
                'str',
                'choices': [
                    'drop', 'drop-if-exceed-limit', 'proceed', 'reset',
                    'reset-if-exceed-limit'
                ]
            }
        },
        'sample_rsp_time': {
            'type': 'bool',
        },
        'rpt_ext_server': {
            'type': 'bool',
        },
        'report_delay': {
            'type': 'int',
        },
        'top_slowest': {
            'type': 'bool',
        },
        'top_fastest': {
            'type': 'bool',
        },
        'persist_scoring': {
            'type': 'str',
            'choices': ['global', 'enable', 'disable']
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
                    'all', 'server_selection_fail_drop',
                    'server_selection_fail_reset', 'service_peak_conn',
                    'service_healthy_host', 'service_unhealthy_host',
                    'service_req_count', 'service_resp_count',
                    'service_resp_2xx', 'service_resp_3xx', 'service_resp_4xx',
                    'service_resp_5xx', 'service_curr_conn_overflow'
                ]
            }
        },
        'reset': {
            'type': 'dict',
            'auto_switch': {
                'type': 'bool',
            }
        },
        'member_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
            },
            'port': {
                'type': 'int',
                'required': True,
            },
            'fqdn_name': {
                'type': 'str',
            },
            'resolve_as': {
                'type':
                'str',
                'choices': [
                    'resolve-to-ipv4', 'resolve-to-ipv6',
                    'resolve-to-ipv4-and-ipv6'
                ]
            },
            'host': {
                'type': 'str',
            },
            'server_ipv6_addr': {
                'type': 'str',
            },
            'member_state': {
                'type': 'str',
                'choices': ['enable', 'disable', 'disable-with-health-check']
            },
            'member_stats_data_disable': {
                'type': 'bool',
            },
            'member_template': {
                'type': 'str',
            },
            'member_priority': {
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
                        'all', 'total_fwd_bytes', 'total_fwd_pkts',
                        'total_rev_bytes', 'total_rev_pkts', 'total_conn',
                        'total_rev_pkts_inspected',
                        'total_rev_pkts_inspected_status_code_2xx',
                        'total_rev_pkts_inspected_status_code_non_5xx',
                        'curr_req', 'total_req', 'total_req_succ', 'peak_conn',
                        'response_time', 'fastest_rsp_time',
                        'slowest_rsp_time', 'curr_ssl_conn', 'total_ssl_conn',
                        'curr_conn_overflow', 'state_flaps'
                    ]
                }
            }
        },
        'oper': {
            'type': 'dict',
            'state': {
                'type': 'str',
                'choices': ['All Up', 'Functional Up', 'Down', 'Disb', 'Unkn']
            },
            'servers_up': {
                'type': 'int',
            },
            'servers_down': {
                'type': 'int',
            },
            'servers_disable': {
                'type': 'int',
            },
            'servers_total': {
                'type': 'int',
            },
            'stateless_current_rate': {
                'type': 'int',
            },
            'stateless_current_usage': {
                'type': 'int',
            },
            'stateless_state': {
                'type': 'int',
            },
            'stateless_type': {
                'type': 'int',
            },
            'hm_dsr_enable_all_vip': {
                'type': 'int',
            },
            'pri_affinity_priority': {
                'type': 'int',
            },
            'filter': {
                'type': 'str',
                'choices': ['sgm-sort-config']
            },
            'sgm_list': {
                'type': 'list',
                'sgm_name': {
                    'type': 'str',
                },
                'sgm_port': {
                    'type': 'int',
                }
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'member_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                },
                'port': {
                    'type': 'int',
                    'required': True,
                },
                'oper': {
                    'type': 'dict',
                    'state': {
                        'type':
                        'str',
                        'choices': [
                            'UP', 'DOWN', 'MAINTENANCE', 'DIS-UP', 'DIS-DOWN',
                            'DIS-MAINTENANCE', 'DIS-DAMP'
                        ]
                    },
                    'hm_key': {
                        'type': 'int',
                    },
                    'hm_index': {
                        'type': 'int',
                    },
                    'drs_list': {
                        'type': 'list',
                        'drs_name': {
                            'type': 'str',
                        },
                        'drs_state': {
                            'type': 'str',
                        },
                        'drs_hm_key': {
                            'type': 'int',
                        },
                        'drs_hm_index': {
                            'type': 'int',
                        },
                        'drs_port': {
                            'type': 'int',
                        },
                        'drs_priority': {
                            'type': 'int',
                        },
                        'drs_curr_conn': {
                            'type': 'int',
                        },
                        'drs_pers_conn': {
                            'type': 'int',
                        },
                        'drs_total_conn': {
                            'type': 'int',
                        },
                        'drs_curr_req': {
                            'type': 'int',
                        },
                        'drs_total_req': {
                            'type': 'int',
                        },
                        'drs_total_req_succ': {
                            'type': 'int',
                        },
                        'drs_rev_pkts': {
                            'type': 'int',
                        },
                        'drs_fwd_pkts': {
                            'type': 'int',
                        },
                        'drs_rev_bts': {
                            'type': 'int',
                        },
                        'drs_fwd_bts': {
                            'type': 'int',
                        },
                        'drs_peak_conn': {
                            'type': 'int',
                        },
                        'drs_rsp_time': {
                            'type': 'int',
                        },
                        'drs_frsp_time': {
                            'type': 'int',
                        },
                        'drs_srsp_time': {
                            'type': 'int',
                        }
                    },
                    'alt_list': {
                        'type': 'list',
                        'alt_name': {
                            'type': 'str',
                        },
                        'alt_port': {
                            'type': 'int',
                        },
                        'alt_state': {
                            'type': 'str',
                        },
                        'alt_curr_conn': {
                            'type': 'int',
                        },
                        'alt_total_conn': {
                            'type': 'int',
                        },
                        'alt_rev_pkts': {
                            'type': 'int',
                        },
                        'alt_fwd_pkts': {
                            'type': 'int',
                        },
                        'alt_peak_conn': {
                            'type': 'int',
                        }
                    }
                }
            }
        },
        'stats': {
            'type': 'dict',
            'server_selection_fail_drop': {
                'type': 'str',
            },
            'server_selection_fail_reset': {
                'type': 'str',
            },
            'service_peak_conn': {
                'type': 'str',
            },
            'service_healthy_host': {
                'type': 'str',
            },
            'service_unhealthy_host': {
                'type': 'str',
            },
            'service_req_count': {
                'type': 'str',
            },
            'service_resp_count': {
                'type': 'str',
            },
            'service_resp_2xx': {
                'type': 'str',
            },
            'service_resp_3xx': {
                'type': 'str',
            },
            'service_resp_4xx': {
                'type': 'str',
            },
            'service_resp_5xx': {
                'type': 'str',
            },
            'service_curr_conn_overflow': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'member_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                },
                'port': {
                    'type': 'int',
                    'required': True,
                },
                'stats': {
                    'type': 'dict',
                    'curr_conn': {
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
                    'total_conn': {
                        'type': 'str',
                    },
                    'total_rev_pkts_inspected': {
                        'type': 'str',
                    },
                    'total_rev_pkts_inspected_status_code_2xx': {
                        'type': 'str',
                    },
                    'total_rev_pkts_inspected_status_code_non_5xx': {
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
                    'response_time': {
                        'type': 'str',
                    },
                    'fastest_rsp_time': {
                        'type': 'str',
                    },
                    'slowest_rsp_time': {
                        'type': 'str',
                    },
                    'curr_ssl_conn': {
                        'type': 'str',
                    },
                    'total_ssl_conn': {
                        'type': 'str',
                    },
                    'curr_conn_overflow': {
                        'type': 'str',
                    },
                    'state_flaps': {
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
    url_base = "/axapi/v3/slb/service-group/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"


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


def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
    return module.client.get(oper_url(module))


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
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
    url_base = "/axapi/v3/slb/service-group/{name}"

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
    if existing_config:
        for k, v in payload["service-group"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["service-group"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["service-group"][k] = v
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
    payload = build_json("service-group", module)
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

    result = dict(changed=False, original_message="", message="", result={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
