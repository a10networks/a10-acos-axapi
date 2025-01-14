#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_protection
description:
    - DDOS protection
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
    toggle:
        description:
        - "'enable'= enable; 'disable'= disable;"
        type: str
        required: False
    rate_interval:
        description:
        - "'100ms'= 100ms; '1sec'= 1sec;"
        type: str
        required: False
    src_hash_function:
        description:
        - "'v1'= v1; 'v2'= v2;"
        type: str
        required: False
    src_ip_hash_bit:
        description:
        - "Configure which bit hashed on"
        type: int
        required: False
    src_ipv6_hash_bit:
        description:
        - "Configure which bit hashed on"
        type: int
        required: False
    force_routing_on_transp:
        description:
        - "Force use of routing in transparent mode"
        type: bool
        required: False
    disable_on_reboot:
        description:
        - "Disable DDoS protection upon reboot/reload"
        type: bool
        required: False
    rexmit_syn_log:
        description:
        - "Enable ddos per flow rexmit syn exceeded log"
        type: bool
        required: False
    use_route:
        description:
        - "Use route table, default use receive hop for device initiated traffic"
        type: bool
        required: False
    enable_now:
        description:
        - "Override disable-on-reboot to enable runtime DDOS protection"
        type: bool
        required: False
    disable_advanced_core_analysis:
        description:
        - "Disable advanced context info in coredump file"
        type: bool
        required: False
    mpls:
        description:
        - "Enable MPLS packet inspection"
        type: bool
        required: False
    disable_delay_dynamic_src_learning:
        description:
        - "Disable delay dynamic src entry learning"
        type: bool
        required: False
    fast_aging:
        description:
        - "Field fast_aging"
        type: dict
        required: False
        suboptions:
            half_open_conn_ratio:
                description:
                - "Minimum half-open session to total session ratio before session fast aging will
          take effect (default 25)"
                type: int
            half_open_conn_threshold:
                description:
                - "Minimum half-open session (percentage) before session fast aging will take
          effect (default 1)"
                type: int
    src_dst_entry_limit:
        description:
        - "'8M'= 8 Million; '16M'= 16 Million; 'unlimited'= Unlimited; 'platform-default'=
          Half of platform maximum;"
        type: str
        required: False
    src_zone_port_entry_limit:
        description:
        - "'8M'= 8 Million; '16M'= 16 Million; 'unlimited'= Unlimited; 'platform-default'=
          Half of platform maximum;"
        type: str
        required: False
    szp_clist_warn_threshold:
        description:
        - "Set threshold percentage of 'max-src-dst-entry' for generating warning logs.
          Including start and end."
        type: int
        required: False
    szp_warn_threshold:
        description:
        - "Set threshold percentage of 'max-src-dst-entry' for generating warning logs.
          Including start and end."
        type: int
        required: False
    szp_warn_exceed_enable:
        description:
        - "Send logs if src-zone-port count exceeds 'max-src-dst-entry'"
        type: bool
        required: False
    force_traffic_to_same_blade_disable:
        description:
        - "Allow traffic to be distributed among blades on Chassis"
        type: bool
        required: False
    non_zero_win_size_syncookie:
        description:
        - "Send syn-cookie with fix TCP window size if SYN packet has zero window size
          (default disabled)"
        type: bool
        required: False
    hw_blocking_enable:
        description:
        - "Enable hardware blacklist blocking for src or dst default entries (default
          disabled)"
        type: bool
        required: False
    hw_blocking_threshold_limit:
        description:
        - "Threshold to initiate hardware blocking (default 10000)"
        type: int
        required: False
    progression_tracking:
        description:
        - "'enable'= enable; 'disable'= disable;"
        type: str
        required: False
    disallow_rst_ack_in_syn_auth:
        description:
        - "Disallow RST-ACK passing syn-auth"
        type: bool
        required: False
    fast_path_disable:
        description:
        - "Disable fast path in SLB processing"
        type: bool
        required: False
    close_sess_for_unauth_src_without_rst:
        description:
        - "When closing unauthenticated sessions, don't send TCP RST for established TCP
          sessions. (Default disabled / sending TCP RST for"
        type: bool
        required: False
    vxlan_outbound_check:
        description:
        - "'enable'= enable; 'disable'= disable;"
        type: str
        required: False
    pkt_rate_limit_on_reassemble:
        description:
        - "'enable'= enable; 'disable'= disable (Default);"
        type: str
        required: False
    blacklist_reason_tracking:
        description:
        - "Enable blacklist reason tracking"
        type: bool
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    ipv6_src_hash_mask_bits:
        description:
        - "Field ipv6_src_hash_mask_bits"
        type: dict
        required: False
        suboptions:
            mask_bit_offset_1:
                description:
                - "Configure mask bits"
                type: int
            mask_bit_offset_2:
                description:
                - "Configure mask bits"
                type: int
            mask_bit_offset_3:
                description:
                - "Configure mask bits"
                type: int
            mask_bit_offset_4:
                description:
                - "Configure mask bits"
                type: int
            mask_bit_offset_5:
                description:
                - "Configure mask bits"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    multi_pu_zone_distribution:
        description:
        - "Field multi_pu_zone_distribution"
        type: dict
        required: False
        suboptions:
            distribution_method:
                description:
                - "'cpu-usage'= Entry/Zone distribution based on CPU usage percentage; 'traffic-
          rate'= Entry/Zone distribution based on traffic kbit/pkt rate (Default);"
                type: str
            cpu_threshold_per_entry:
                description:
                - "Entry/zone percentage threshold of CPU usage for source hash mode. Requires
          distribution-method cpu-usage. Default=60"
                type: int
            cpu_threshold_per_pu:
                description:
                - "Per PU percentage threshold of average CPU usage to start check entry usage.
          Requires distribution-method cpu-usage. Default=80"
                type: int
            rate_pkt_threshold:
                description:
                - "DDOS DST Entry/Zone packet rate threshold for source hash mode"
                type: int
            rate_kbit_threshold:
                description:
                - "DDOS DST Entry/Zone kbit rate threshold for source hash mode"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    per_service_szp_entry_limit:
        description:
        - "Field per_service_szp_entry_limit"
        type: dict
        required: False
        suboptions:
            dns_tcp_limit:
                description:
                - "Szp limit for port / port-range dns-tcp"
                type: int
            dns_udp_limit:
                description:
                - "Szp limit for port / port-range dns-udp"
                type: int
            http_limit:
                description:
                - "Szp limit for port / port-range http"
                type: int
            tcp_limit:
                description:
                - "Szp limit for port / port-range tcp"
                type: int
            udp_limit:
                description:
                - "Szp limit for port / port-range udp"
                type: int
            ssl_l4_limit:
                description:
                - "Szp limit for port / port-range ssl-l4"
                type: int
            sip_udp_limit:
                description:
                - "Szp limit for port / port-range sip-udp"
                type: int
            sip_tcp_limit:
                description:
                - "Szp limit for port / port-range sip-tcp"
                type: int
            quic_limit:
                description:
                - "Szp limit for port / port-range quic"
                type: int
            ip_proto_icmp_v4_limit:
                description:
                - "Szp limit for ip-proto icmp-v4"
                type: int
            ip_proto_icmp_v6_limit:
                description:
                - "Szp limit for ip-proto icmp-v6"
                type: int
            ip_proto_other_limit:
                description:
                - "Szp limit for ip-proto other"
                type: int
            ip_proto_gre_limit:
                description:
                - "Szp limit for ip-proto gre"
                type: int
            ip_proto_ipv4_encap_limit:
                description:
                - "Szp limit for ip-proto ipv4-encap"
                type: int
            ip_proto_ipv6_encap_limit:
                description:
                - "Szp limit for ip-proto ipv6-encap"
                type: int
            ip_proto_custom_limit:
                description:
                - "Szp limit for custom ip-proto"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            ddos_protection:
                description:
                - "Field ddos_protection"
                type: str
            rate_interval:
                description:
                - "Field rate_interval"
                type: str
            mode:
                description:
                - "Field mode"
                type: str
            use_route:
                description:
                - "Field use_route"
                type: str
            tap_interfaces:
                description:
                - "Field tap_interfaces"
                type: str
            dst_auto_learning_ipv4:
                description:
                - "Field dst_auto_learning_ipv4"
                type: str
            dst_auto_learning_ipv6:
                description:
                - "Field dst_auto_learning_ipv6"
                type: str
            src_auto_learning_ipv4:
                description:
                - "Field src_auto_learning_ipv4"
                type: str
            src_auto_learning_ipv6:
                description:
                - "Field src_auto_learning_ipv6"
                type: str
            src_delay_learning:
                description:
                - "Field src_delay_learning"
                type: str
            one_arm_mode:
                description:
                - "Field one_arm_mode"
                type: str
            hw_syn_cookie:
                description:
                - "Field hw_syn_cookie"
                type: str
            sync:
                description:
                - "Field sync"
                type: str
            sync_auto_wl:
                description:
                - "Field sync_auto_wl"
                type: str
            bgp:
                description:
                - "Field bgp"
                type: str
            bgp_auto_wl:
                description:
                - "Field bgp_auto_wl"
                type: str
            vrrp:
                description:
                - "Field vrrp"
                type: str
            vrrp_auto_wl:
                description:
                - "Field vrrp_auto_wl"
                type: str
            mpls_pkt_inspect:
                description:
                - "Field mpls_pkt_inspect"
                type: str
            detection:
                description:
                - "Field detection"
                type: str
            ddet_mode:
                description:
                - "Field ddet_mode"
                type: str
            ddet_cpus:
                description:
                - "Field ddet_cpus"
                type: int
            dst_dynamic_overflow_ipv4:
                description:
                - "Field dst_dynamic_overflow_ipv4"
                type: str
            dst_dynamic_overflow_ipv6:
                description:
                - "Field dst_dynamic_overflow_ipv6"
                type: str
            src_dynamic_overflow_ipv4:
                description:
                - "Field src_dynamic_overflow_ipv4"
                type: str
            src_dynamic_overflow_ipv6:
                description:
                - "Field src_dynamic_overflow_ipv6"
                type: str
            ip_ano_sec_l3:
                description:
                - "Field ip_ano_sec_l3"
                type: str
            ip_ano_sec_l4_tcp:
                description:
                - "Field ip_ano_sec_l4_tcp"
                type: str
            ip_ano_sec_l4_udp:
                description:
                - "Field ip_ano_sec_l4_udp"
                type: str
            ip_ano_def_l3:
                description:
                - "Field ip_ano_def_l3"
                type: str
            ip_ano_def_l4:
                description:
                - "Field ip_ano_def_l4"
                type: str
            dns_cache_mode:
                description:
                - "Field dns_cache_mode"
                type: str
            warm_up:
                description:
                - "Field warm_up"
                type: str
            dns_zone_transfer_dedicated_cpus:
                description:
                - "Field dns_zone_transfer_dedicated_cpus"
                type: int
            src_dst_entry_limit:
                description:
                - "Field src_dst_entry_limit"
                type: str
            src_zone_port_entry_limit:
                description:
                - "Field src_zone_port_entry_limit"
                type: str
            src_zone_port_entry_overflow_warning:
                description:
                - "Field src_zone_port_entry_overflow_warning"
                type: str
            src_zone_port_entry_warning_threshold:
                description:
                - "Field src_zone_port_entry_warning_threshold"
                type: int
            src_zone_port_entry_clist_warning_threshold:
                description:
                - "Field src_zone_port_entry_clist_warning_threshold"
                type: int
            interblade_sync_accuracy:
                description:
                - "Field interblade_sync_accuracy"
                type: str
            pattern_recognition:
                description:
                - "Field pattern_recognition"
                type: str
            pattern_recognition_cpus:
                description:
                - "Field pattern_recognition_cpus"
                type: int
            pattern_recognition_hardware_filter:
                description:
                - "Field pattern_recognition_hardware_filter"
                type: str
            detection_window_size:
                description:
                - "Field detection_window_size"
                type: int
            disallow_rst_ack_in_syn_auth:
                description:
                - "Field disallow_rst_ack_in_syn_auth"
                type: str
            non_zero_win_size_syncookie:
                description:
                - "Field non_zero_win_size_syncookie"
                type: str
            hw_blocking:
                description:
                - "Field hw_blocking"
                type: str
            hw_blocking_threshold:
                description:
                - "Field hw_blocking_threshold"
                type: int
            interface_http_health_check:
                description:
                - "Field interface_http_health_check"
                type: str
            ipv6_src_hash_mask_bits:
                description:
                - "Field ipv6_src_hash_mask_bits"
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
    "blacklist_reason_tracking", "close_sess_for_unauth_src_without_rst", "disable_advanced_core_analysis", "disable_delay_dynamic_src_learning", "disable_on_reboot", "disallow_rst_ack_in_syn_auth", "enable_now", "fast_aging", "fast_path_disable", "force_routing_on_transp", "force_traffic_to_same_blade_disable", "hw_blocking_enable",
    "hw_blocking_threshold_limit", "ipv6_src_hash_mask_bits", "mpls", "multi_pu_zone_distribution", "non_zero_win_size_syncookie", "oper", "per_service_szp_entry_limit", "pkt_rate_limit_on_reassemble", "progression_tracking", "rate_interval", "rexmit_syn_log", "src_dst_entry_limit", "src_hash_function", "src_ip_hash_bit", "src_ipv6_hash_bit",
    "src_zone_port_entry_limit", "szp_clist_warn_threshold", "szp_warn_exceed_enable", "szp_warn_threshold", "toggle", "use_route", "uuid", "vxlan_outbound_check",
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
        'toggle': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'rate_interval': {
            'type': 'str',
            'choices': ['100ms', '1sec']
            },
        'src_hash_function': {
            'type': 'str',
            'choices': ['v1', 'v2']
            },
        'src_ip_hash_bit': {
            'type': 'int',
            },
        'src_ipv6_hash_bit': {
            'type': 'int',
            },
        'force_routing_on_transp': {
            'type': 'bool',
            },
        'disable_on_reboot': {
            'type': 'bool',
            },
        'rexmit_syn_log': {
            'type': 'bool',
            },
        'use_route': {
            'type': 'bool',
            },
        'enable_now': {
            'type': 'bool',
            },
        'disable_advanced_core_analysis': {
            'type': 'bool',
            },
        'mpls': {
            'type': 'bool',
            },
        'disable_delay_dynamic_src_learning': {
            'type': 'bool',
            },
        'fast_aging': {
            'type': 'dict',
            'half_open_conn_ratio': {
                'type': 'int',
                },
            'half_open_conn_threshold': {
                'type': 'int',
                }
            },
        'src_dst_entry_limit': {
            'type': 'str',
            'choices': ['8M', '16M', 'unlimited', 'platform-default']
            },
        'src_zone_port_entry_limit': {
            'type': 'str',
            'choices': ['8M', '16M', 'unlimited', 'platform-default']
            },
        'szp_clist_warn_threshold': {
            'type': 'int',
            },
        'szp_warn_threshold': {
            'type': 'int',
            },
        'szp_warn_exceed_enable': {
            'type': 'bool',
            },
        'force_traffic_to_same_blade_disable': {
            'type': 'bool',
            },
        'non_zero_win_size_syncookie': {
            'type': 'bool',
            },
        'hw_blocking_enable': {
            'type': 'bool',
            },
        'hw_blocking_threshold_limit': {
            'type': 'int',
            },
        'progression_tracking': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'disallow_rst_ack_in_syn_auth': {
            'type': 'bool',
            },
        'fast_path_disable': {
            'type': 'bool',
            },
        'close_sess_for_unauth_src_without_rst': {
            'type': 'bool',
            },
        'vxlan_outbound_check': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'pkt_rate_limit_on_reassemble': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'blacklist_reason_tracking': {
            'type': 'bool',
            },
        'uuid': {
            'type': 'str',
            },
        'ipv6_src_hash_mask_bits': {
            'type': 'dict',
            'mask_bit_offset_1': {
                'type': 'int',
                },
            'mask_bit_offset_2': {
                'type': 'int',
                },
            'mask_bit_offset_3': {
                'type': 'int',
                },
            'mask_bit_offset_4': {
                'type': 'int',
                },
            'mask_bit_offset_5': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'multi_pu_zone_distribution': {
            'type': 'dict',
            'distribution_method': {
                'type': 'str',
                'choices': ['cpu-usage', 'traffic-rate']
                },
            'cpu_threshold_per_entry': {
                'type': 'int',
                },
            'cpu_threshold_per_pu': {
                'type': 'int',
                },
            'rate_pkt_threshold': {
                'type': 'int',
                },
            'rate_kbit_threshold': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'per_service_szp_entry_limit': {
            'type': 'dict',
            'dns_tcp_limit': {
                'type': 'int',
                },
            'dns_udp_limit': {
                'type': 'int',
                },
            'http_limit': {
                'type': 'int',
                },
            'tcp_limit': {
                'type': 'int',
                },
            'udp_limit': {
                'type': 'int',
                },
            'ssl_l4_limit': {
                'type': 'int',
                },
            'sip_udp_limit': {
                'type': 'int',
                },
            'sip_tcp_limit': {
                'type': 'int',
                },
            'quic_limit': {
                'type': 'int',
                },
            'ip_proto_icmp_v4_limit': {
                'type': 'int',
                },
            'ip_proto_icmp_v6_limit': {
                'type': 'int',
                },
            'ip_proto_other_limit': {
                'type': 'int',
                },
            'ip_proto_gre_limit': {
                'type': 'int',
                },
            'ip_proto_ipv4_encap_limit': {
                'type': 'int',
                },
            'ip_proto_ipv6_encap_limit': {
                'type': 'int',
                },
            'ip_proto_custom_limit': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'ddos_protection': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'rate_interval': {
                'type': 'str',
                'choices': ['100ms', '1sec']
                },
            'mode': {
                'type': 'str',
                },
            'use_route': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'tap_interfaces': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'dst_auto_learning_ipv4': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'dst_auto_learning_ipv6': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'src_auto_learning_ipv4': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'src_auto_learning_ipv6': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'src_delay_learning': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'one_arm_mode': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'hw_syn_cookie': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'sync': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'sync_auto_wl': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'bgp': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'bgp_auto_wl': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'vrrp': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'vrrp_auto_wl': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'mpls_pkt_inspect': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'detection': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'ddet_mode': {
                'type': 'str',
                },
            'ddet_cpus': {
                'type': 'int',
                },
            'dst_dynamic_overflow_ipv4': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'dst_dynamic_overflow_ipv6': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'src_dynamic_overflow_ipv4': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'src_dynamic_overflow_ipv6': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'ip_ano_sec_l3': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'ip_ano_sec_l4_tcp': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'ip_ano_sec_l4_udp': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'ip_ano_def_l3': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'ip_ano_def_l4': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'dns_cache_mode': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'warm_up': {
                'type': 'str',
                },
            'dns_zone_transfer_dedicated_cpus': {
                'type': 'int',
                },
            'src_dst_entry_limit': {
                'type': 'str',
                'choices': ['8M', '16M', 'unlimited', 'platform-default']
                },
            'src_zone_port_entry_limit': {
                'type': 'str',
                'choices': ['8M', '16M', 'unlimited', 'platform-default']
                },
            'src_zone_port_entry_overflow_warning': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'src_zone_port_entry_warning_threshold': {
                'type': 'int',
                },
            'src_zone_port_entry_clist_warning_threshold': {
                'type': 'int',
                },
            'interblade_sync_accuracy': {
                'type': 'str',
                'choices': ['High', 'Low', 'Medium']
                },
            'pattern_recognition': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'pattern_recognition_cpus': {
                'type': 'int',
                },
            'pattern_recognition_hardware_filter': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'detection_window_size': {
                'type': 'int',
                },
            'disallow_rst_ack_in_syn_auth': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'non_zero_win_size_syncookie': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'hw_blocking': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'hw_blocking_threshold': {
                'type': 'int',
                },
            'interface_http_health_check': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'ipv6_src_hash_mask_bits': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'offsets': {
                        'type': 'list',
                        'mask_bit_offset_1': {
                            'type': 'int',
                            },
                        'mask_bit_offset_2': {
                            'type': 'int',
                            },
                        'mask_bit_offset_3': {
                            'type': 'int',
                            },
                        'mask_bit_offset_4': {
                            'type': 'int',
                            },
                        'mask_bit_offset_5': {
                            'type': 'int',
                            }
                        }
                    }
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/protection"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/protection"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["protection"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["protection"].get(k) != v:
            change_results["changed"] = True
            config_changes["protection"][k] = v

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
    payload = utils.build_json("protection", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["protection"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["protection-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["protection"]["oper"] if info != "NotFound" else info
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
