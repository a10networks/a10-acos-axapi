#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_dst_zone_port_zone_service_other_port_ind
description:
    - zone port indicators
author: A10 Networks
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
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
    protocol:
        description:
        - Key to identify parent object
        type: str
        required: True
    zone_service_other_port_other:
        description:
        - Key to identify parent object
        type: str
        required: True
    zone_name:
        description:
        - Key to identify parent object
        type: str
        required: True
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
                - "'all'= all; 'ip-proto-type'= IP Protocol Type; 'ddet_ind_pkt_rate_current'= Pkt
          Rate Current; 'ddet_ind_pkt_rate_min'= Pkt Rate Min; 'ddet_ind_pkt_rate_max'=
          Pkt Rate Max; 'ddet_ind_pkt_rate_adaptive_threshold'= Pkt Rate Adaptive
          Threshold; 'ddet_ind_pkt_drop_rate_current'= Pkt Drop Rate Current;
          'ddet_ind_pkt_drop_rate_min'= Pkt Drop Rate Min; 'ddet_ind_pkt_drop_rate_max'=
          Pkt Drop Rate Max; 'ddet_ind_pkt_drop_rate_adaptive_threshold'= Pkt Drop Rate
          Adaptive Threshold; 'ddet_ind_syn_rate_current'= TCP SYN Rate Current;
          'ddet_ind_syn_rate_min'= TCP SYN Rate Min; 'ddet_ind_syn_rate_max'= TCP SYN
          Rate Max; 'ddet_ind_syn_rate_adaptive_threshold'= TCP SYN Rate Adaptive
          Threshold; 'ddet_ind_fin_rate_current'= TCP FIN Rate Current;
          'ddet_ind_fin_rate_min'= TCP FIN Rate Min; 'ddet_ind_fin_rate_max'= TCP FIN
          Rate Max; 'ddet_ind_fin_rate_adaptive_threshold'= TCP FIN Rate Adaptive
          Threshold; 'ddet_ind_rst_rate_current'= TCP RST Rate Current;
          'ddet_ind_rst_rate_min'= TCP RST Rate Min; 'ddet_ind_rst_rate_max'= TCP RST
          Rate Max; 'ddet_ind_rst_rate_adaptive_threshold'= TCP RST Rate Adaptive
          Threshold; 'ddet_ind_small_window_ack_rate_current'= TCP Small Window ACK Rate
          Current; 'ddet_ind_small_window_ack_rate_min'= TCP Small Window ACK Rate Min;
          'ddet_ind_small_window_ack_rate_max'= TCP Small Window ACK Rate Max;
          'ddet_ind_small_window_ack_rate_adaptive_threshold'= TCP Small Window ACK Rate
          Adaptive Threshold; 'ddet_ind_empty_ack_rate_current'= TCP Empty ACK Rate
          Current; 'ddet_ind_empty_ack_rate_min'= TCP Empty ACK Rate Min;
          'ddet_ind_empty_ack_rate_max'= TCP Empty ACK Rate Max;
          'ddet_ind_empty_ack_rate_adaptive_threshold'= TCP Empty ACK Rate Adaptive
          Threshold; 'ddet_ind_small_payload_rate_current'= TCP Small Payload Rate
          Current; 'ddet_ind_small_payload_rate_min'= TCP Small Payload Rate Min;
          'ddet_ind_small_payload_rate_max'= TCP Small Payload Rate Max;
          'ddet_ind_small_payload_rate_adaptive_threshold'= TCP Small Payload Rate
          Adaptive Threshold; 'ddet_ind_pkt_drop_ratio_current'= Pkt Drop / Pkt Rcvd
          Current; 'ddet_ind_pkt_drop_ratio_min'= Pkt Drop / Pkt Rcvd Min;
          'ddet_ind_pkt_drop_ratio_max'= Pkt Drop / Pkt Rcvd Max;
          'ddet_ind_pkt_drop_ratio_adaptive_threshold'= Pkt Drop / Pkt Rcvd Adaptive
          Threshold; 'ddet_ind_inb_per_outb_current'= Bytes-to / Bytes-from Current;
          'ddet_ind_inb_per_outb_min'= Bytes-to / Bytes-from Min;
          'ddet_ind_inb_per_outb_max'= Bytes-to / Bytes-from Max;
          'ddet_ind_inb_per_outb_adaptive_threshold'= Bytes-to / Bytes-from Adaptive
          Threshold; 'ddet_ind_syn_per_fin_rate_current'= TCP SYN Rate / FIN Rate
          Current; 'ddet_ind_syn_per_fin_rate_min'= TCP SYN Rate / FIN Rate Min;
          'ddet_ind_syn_per_fin_rate_max'= TCP SYN Rate / FIN Rate Max;
          'ddet_ind_syn_per_fin_rate_adaptive_threshold'= TCP SYN Rate / FIN Rate
          Adaptive Threshold; 'ddet_ind_conn_miss_rate_current'= TCP Session Miss Rate
          Current; 'ddet_ind_conn_miss_rate_min'= TCP Session Miss Rate Min;
          'ddet_ind_conn_miss_rate_max'= TCP Session Miss Rate Max;
          'ddet_ind_conn_miss_rate_adaptive_threshold'= TCP Session Miss Rate Adaptive
          Threshold; 'ddet_ind_concurrent_conns_current'= TCP/UDP Concurrent Sessions
          Current; 'ddet_ind_concurrent_conns_min'= TCP/UDP Concurrent Sessions Min;
          'ddet_ind_concurrent_conns_max'= TCP/UDP Concurrent Sessions Max;
          'ddet_ind_concurrent_conns_adaptive_threshold'= TCP/UDP Concurrent Sessions
          Adaptive Threshold; 'ddet_ind_data_cpu_util_current'= Data CPU Utilization
          Current; 'ddet_ind_data_cpu_util_min'= Data CPU Utilization Min;
          'ddet_ind_data_cpu_util_max'= Data CPU Utilization Max;
          'ddet_ind_data_cpu_util_adaptive_threshold'= Data CPU Utilization Adaptive
          Threshold; 'ddet_ind_outside_intf_util_current'= Outside Interface Utilization
          Current; 'ddet_ind_outside_intf_util_min'= Outside Interface Utilization Min;
          'ddet_ind_outside_intf_util_max'= Outside Interface Utilization Max;
          'ddet_ind_outside_intf_util_adaptive_threshold'= Outside Interface Utilization
          Adaptive Threshold; 'ddet_ind_frag_rate_current'= Frag Pkt Rate Current;
          'ddet_ind_frag_rate_min'= Frag Pkt Rate Min; 'ddet_ind_frag_rate_max'= Frag Pkt
          Rate Max; 'ddet_ind_frag_rate_adaptive_threshold'= Frag Pkt Rate Adaptive
          Threshold; 'ddet_ind_bit_rate_current'= Bit Rate Current;
          'ddet_ind_bit_rate_min'= Bit Rate Min; 'ddet_ind_bit_rate_max'= Bit Rate Max;
          'ddet_ind_bit_rate_adaptive_threshold'= Bit Rate Adaptive Threshold;
          'ddet_ind_total_szp_current'= Total Learnt Sources Current;
          'ddet_ind_total_szp_min'= Total Learnt Sources Min; 'ddet_ind_total_szp_max'=
          Total Learnt Sources Max; 'ddet_ind_total_szp_adaptive_threshold'= Total Learnt
          Sources Adaptive Threshold; 'ddet_ind_syn_ack_rate_current'= TCP SYN ACK Rate
          Current; 'ddet_ind_syn_ack_rate_min'= TCP SYN ACK Rate Min;
          'ddet_ind_syn_ack_rate_max'= TCP SYN ACK Rate Max;
          'ddet_ind_syn_ack_rate_adaptive_threshold'= TCP SYN ACK Adaptive Threshold;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            src_entry_list:
                description:
                - "Field src_entry_list"
                type: list
            indicators:
                description:
                - "Field indicators"
                type: list
            detection_data_source:
                description:
                - "Field detection_data_source"
                type: str
            total_score:
                description:
                - "Field total_score"
                type: str
            current_level:
                description:
                - "Field current_level"
                type: str
            escalation_timestamp:
                description:
                - "Field escalation_timestamp"
                type: str
            initial_learning:
                description:
                - "Field initial_learning"
                type: str
            active_time:
                description:
                - "Field active_time"
                type: int
            sources_all_entries:
                description:
                - "Field sources_all_entries"
                type: bool
            subnet_ip_addr:
                description:
                - "Field subnet_ip_addr"
                type: str
            subnet_ipv6_addr:
                description:
                - "Field subnet_ipv6_addr"
                type: str
            ipv6:
                description:
                - "Field ipv6"
                type: str
            details:
                description:
                - "Field details"
                type: bool
            sources:
                description:
                - "Field sources"
                type: bool
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            ip_proto_type:
                description:
                - "IP Protocol Type"
                type: str
            ddet_ind_pkt_rate_current:
                description:
                - "Pkt Rate Current"
                type: str
            ddet_ind_pkt_rate_min:
                description:
                - "Pkt Rate Min"
                type: str
            ddet_ind_pkt_rate_max:
                description:
                - "Pkt Rate Max"
                type: str
            ddet_ind_pkt_rate_adaptive_threshold:
                description:
                - "Pkt Rate Adaptive Threshold"
                type: str
            ddet_ind_pkt_drop_rate_current:
                description:
                - "Pkt Drop Rate Current"
                type: str
            ddet_ind_pkt_drop_rate_min:
                description:
                - "Pkt Drop Rate Min"
                type: str
            ddet_ind_pkt_drop_rate_max:
                description:
                - "Pkt Drop Rate Max"
                type: str
            ddet_ind_pkt_drop_rate_adaptive_threshold:
                description:
                - "Pkt Drop Rate Adaptive Threshold"
                type: str
            ddet_ind_syn_rate_current:
                description:
                - "TCP SYN Rate Current"
                type: str
            ddet_ind_syn_rate_min:
                description:
                - "TCP SYN Rate Min"
                type: str
            ddet_ind_syn_rate_max:
                description:
                - "TCP SYN Rate Max"
                type: str
            ddet_ind_syn_rate_adaptive_threshold:
                description:
                - "TCP SYN Rate Adaptive Threshold"
                type: str
            ddet_ind_fin_rate_current:
                description:
                - "TCP FIN Rate Current"
                type: str
            ddet_ind_fin_rate_min:
                description:
                - "TCP FIN Rate Min"
                type: str
            ddet_ind_fin_rate_max:
                description:
                - "TCP FIN Rate Max"
                type: str
            ddet_ind_fin_rate_adaptive_threshold:
                description:
                - "TCP FIN Rate Adaptive Threshold"
                type: str
            ddet_ind_rst_rate_current:
                description:
                - "TCP RST Rate Current"
                type: str
            ddet_ind_rst_rate_min:
                description:
                - "TCP RST Rate Min"
                type: str
            ddet_ind_rst_rate_max:
                description:
                - "TCP RST Rate Max"
                type: str
            ddet_ind_rst_rate_adaptive_threshold:
                description:
                - "TCP RST Rate Adaptive Threshold"
                type: str
            ddet_ind_small_window_ack_rate_current:
                description:
                - "TCP Small Window ACK Rate Current"
                type: str
            ddet_ind_small_window_ack_rate_min:
                description:
                - "TCP Small Window ACK Rate Min"
                type: str
            ddet_ind_small_window_ack_rate_max:
                description:
                - "TCP Small Window ACK Rate Max"
                type: str
            ddet_ind_small_window_ack_rate_adaptive_threshold:
                description:
                - "TCP Small Window ACK Rate Adaptive Threshold"
                type: str
            ddet_ind_empty_ack_rate_current:
                description:
                - "TCP Empty ACK Rate Current"
                type: str
            ddet_ind_empty_ack_rate_min:
                description:
                - "TCP Empty ACK Rate Min"
                type: str
            ddet_ind_empty_ack_rate_max:
                description:
                - "TCP Empty ACK Rate Max"
                type: str
            ddet_ind_empty_ack_rate_adaptive_threshold:
                description:
                - "TCP Empty ACK Rate Adaptive Threshold"
                type: str
            ddet_ind_small_payload_rate_current:
                description:
                - "TCP Small Payload Rate Current"
                type: str
            ddet_ind_small_payload_rate_min:
                description:
                - "TCP Small Payload Rate Min"
                type: str
            ddet_ind_small_payload_rate_max:
                description:
                - "TCP Small Payload Rate Max"
                type: str
            ddet_ind_small_payload_rate_adaptive_threshold:
                description:
                - "TCP Small Payload Rate Adaptive Threshold"
                type: str
            ddet_ind_pkt_drop_ratio_current:
                description:
                - "Pkt Drop / Pkt Rcvd Current"
                type: str
            ddet_ind_pkt_drop_ratio_min:
                description:
                - "Pkt Drop / Pkt Rcvd Min"
                type: str
            ddet_ind_pkt_drop_ratio_max:
                description:
                - "Pkt Drop / Pkt Rcvd Max"
                type: str
            ddet_ind_pkt_drop_ratio_adaptive_threshold:
                description:
                - "Pkt Drop / Pkt Rcvd Adaptive Threshold"
                type: str
            ddet_ind_inb_per_outb_current:
                description:
                - "Bytes-to / Bytes-from Current"
                type: str
            ddet_ind_inb_per_outb_min:
                description:
                - "Bytes-to / Bytes-from Min"
                type: str
            ddet_ind_inb_per_outb_max:
                description:
                - "Bytes-to / Bytes-from Max"
                type: str
            ddet_ind_inb_per_outb_adaptive_threshold:
                description:
                - "Bytes-to / Bytes-from Adaptive Threshold"
                type: str
            ddet_ind_syn_per_fin_rate_current:
                description:
                - "TCP SYN Rate / FIN Rate Current"
                type: str
            ddet_ind_syn_per_fin_rate_min:
                description:
                - "TCP SYN Rate / FIN Rate Min"
                type: str
            ddet_ind_syn_per_fin_rate_max:
                description:
                - "TCP SYN Rate / FIN Rate Max"
                type: str
            ddet_ind_syn_per_fin_rate_adaptive_threshold:
                description:
                - "TCP SYN Rate / FIN Rate Adaptive Threshold"
                type: str
            ddet_ind_conn_miss_rate_current:
                description:
                - "TCP Session Miss Rate Current"
                type: str
            ddet_ind_conn_miss_rate_min:
                description:
                - "TCP Session Miss Rate Min"
                type: str
            ddet_ind_conn_miss_rate_max:
                description:
                - "TCP Session Miss Rate Max"
                type: str
            ddet_ind_conn_miss_rate_adaptive_threshold:
                description:
                - "TCP Session Miss Rate Adaptive Threshold"
                type: str
            ddet_ind_concurrent_conns_current:
                description:
                - "TCP/UDP Concurrent Sessions Current"
                type: str
            ddet_ind_concurrent_conns_min:
                description:
                - "TCP/UDP Concurrent Sessions Min"
                type: str
            ddet_ind_concurrent_conns_max:
                description:
                - "TCP/UDP Concurrent Sessions Max"
                type: str
            ddet_ind_concurrent_conns_adaptive_threshold:
                description:
                - "TCP/UDP Concurrent Sessions Adaptive Threshold"
                type: str
            ddet_ind_data_cpu_util_current:
                description:
                - "Data CPU Utilization Current"
                type: str
            ddet_ind_data_cpu_util_min:
                description:
                - "Data CPU Utilization Min"
                type: str
            ddet_ind_data_cpu_util_max:
                description:
                - "Data CPU Utilization Max"
                type: str
            ddet_ind_data_cpu_util_adaptive_threshold:
                description:
                - "Data CPU Utilization Adaptive Threshold"
                type: str
            ddet_ind_outside_intf_util_current:
                description:
                - "Outside Interface Utilization Current"
                type: str
            ddet_ind_outside_intf_util_min:
                description:
                - "Outside Interface Utilization Min"
                type: str
            ddet_ind_outside_intf_util_max:
                description:
                - "Outside Interface Utilization Max"
                type: str
            ddet_ind_outside_intf_util_adaptive_threshold:
                description:
                - "Outside Interface Utilization Adaptive Threshold"
                type: str
            ddet_ind_frag_rate_current:
                description:
                - "Frag Pkt Rate Current"
                type: str
            ddet_ind_frag_rate_min:
                description:
                - "Frag Pkt Rate Min"
                type: str
            ddet_ind_frag_rate_max:
                description:
                - "Frag Pkt Rate Max"
                type: str
            ddet_ind_frag_rate_adaptive_threshold:
                description:
                - "Frag Pkt Rate Adaptive Threshold"
                type: str
            ddet_ind_bit_rate_current:
                description:
                - "Bit Rate Current"
                type: str
            ddet_ind_bit_rate_min:
                description:
                - "Bit Rate Min"
                type: str
            ddet_ind_bit_rate_max:
                description:
                - "Bit Rate Max"
                type: str
            ddet_ind_bit_rate_adaptive_threshold:
                description:
                - "Bit Rate Adaptive Threshold"
                type: str
            ddet_ind_total_szp_current:
                description:
                - "Total Learnt Sources Current"
                type: str
            ddet_ind_total_szp_min:
                description:
                - "Total Learnt Sources Min"
                type: str
            ddet_ind_total_szp_max:
                description:
                - "Total Learnt Sources Max"
                type: str
            ddet_ind_total_szp_adaptive_threshold:
                description:
                - "Total Learnt Sources Adaptive Threshold"
                type: str
            ddet_ind_syn_ack_rate_current:
                description:
                - "TCP SYN ACK Rate Current"
                type: str
            ddet_ind_syn_ack_rate_min:
                description:
                - "TCP SYN ACK Rate Min"
                type: str
            ddet_ind_syn_ack_rate_max:
                description:
                - "TCP SYN ACK Rate Max"
                type: str
            ddet_ind_syn_ack_rate_adaptive_threshold:
                description:
                - "TCP SYN ACK Adaptive Threshold"
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
AVAILABLE_PROPERTIES = ["oper", "sampling_enable", "stats", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present']),
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
                    'all', 'ip-proto-type', 'ddet_ind_pkt_rate_current', 'ddet_ind_pkt_rate_min', 'ddet_ind_pkt_rate_max', 'ddet_ind_pkt_rate_adaptive_threshold', 'ddet_ind_pkt_drop_rate_current', 'ddet_ind_pkt_drop_rate_min', 'ddet_ind_pkt_drop_rate_max', 'ddet_ind_pkt_drop_rate_adaptive_threshold', 'ddet_ind_syn_rate_current',
                    'ddet_ind_syn_rate_min', 'ddet_ind_syn_rate_max', 'ddet_ind_syn_rate_adaptive_threshold', 'ddet_ind_fin_rate_current', 'ddet_ind_fin_rate_min', 'ddet_ind_fin_rate_max', 'ddet_ind_fin_rate_adaptive_threshold', 'ddet_ind_rst_rate_current', 'ddet_ind_rst_rate_min', 'ddet_ind_rst_rate_max', 'ddet_ind_rst_rate_adaptive_threshold',
                    'ddet_ind_small_window_ack_rate_current', 'ddet_ind_small_window_ack_rate_min', 'ddet_ind_small_window_ack_rate_max', 'ddet_ind_small_window_ack_rate_adaptive_threshold', 'ddet_ind_empty_ack_rate_current', 'ddet_ind_empty_ack_rate_min', 'ddet_ind_empty_ack_rate_max', 'ddet_ind_empty_ack_rate_adaptive_threshold',
                    'ddet_ind_small_payload_rate_current', 'ddet_ind_small_payload_rate_min', 'ddet_ind_small_payload_rate_max', 'ddet_ind_small_payload_rate_adaptive_threshold', 'ddet_ind_pkt_drop_ratio_current', 'ddet_ind_pkt_drop_ratio_min', 'ddet_ind_pkt_drop_ratio_max', 'ddet_ind_pkt_drop_ratio_adaptive_threshold',
                    'ddet_ind_inb_per_outb_current', 'ddet_ind_inb_per_outb_min', 'ddet_ind_inb_per_outb_max', 'ddet_ind_inb_per_outb_adaptive_threshold', 'ddet_ind_syn_per_fin_rate_current', 'ddet_ind_syn_per_fin_rate_min', 'ddet_ind_syn_per_fin_rate_max', 'ddet_ind_syn_per_fin_rate_adaptive_threshold', 'ddet_ind_conn_miss_rate_current',
                    'ddet_ind_conn_miss_rate_min', 'ddet_ind_conn_miss_rate_max', 'ddet_ind_conn_miss_rate_adaptive_threshold', 'ddet_ind_concurrent_conns_current', 'ddet_ind_concurrent_conns_min', 'ddet_ind_concurrent_conns_max', 'ddet_ind_concurrent_conns_adaptive_threshold', 'ddet_ind_data_cpu_util_current', 'ddet_ind_data_cpu_util_min',
                    'ddet_ind_data_cpu_util_max', 'ddet_ind_data_cpu_util_adaptive_threshold', 'ddet_ind_outside_intf_util_current', 'ddet_ind_outside_intf_util_min', 'ddet_ind_outside_intf_util_max', 'ddet_ind_outside_intf_util_adaptive_threshold', 'ddet_ind_frag_rate_current', 'ddet_ind_frag_rate_min', 'ddet_ind_frag_rate_max',
                    'ddet_ind_frag_rate_adaptive_threshold', 'ddet_ind_bit_rate_current', 'ddet_ind_bit_rate_min', 'ddet_ind_bit_rate_max', 'ddet_ind_bit_rate_adaptive_threshold', 'ddet_ind_total_szp_current', 'ddet_ind_total_szp_min', 'ddet_ind_total_szp_max', 'ddet_ind_total_szp_adaptive_threshold', 'ddet_ind_syn_ack_rate_current',
                    'ddet_ind_syn_ack_rate_min', 'ddet_ind_syn_ack_rate_max', 'ddet_ind_syn_ack_rate_adaptive_threshold'
                    ]
                }
            },
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
            },
        'stats': {
            'type': 'dict',
            'ip_proto_type': {
                'type': 'str',
                },
            'ddet_ind_pkt_rate_current': {
                'type': 'str',
                },
            'ddet_ind_pkt_rate_min': {
                'type': 'str',
                },
            'ddet_ind_pkt_rate_max': {
                'type': 'str',
                },
            'ddet_ind_pkt_rate_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_pkt_drop_rate_current': {
                'type': 'str',
                },
            'ddet_ind_pkt_drop_rate_min': {
                'type': 'str',
                },
            'ddet_ind_pkt_drop_rate_max': {
                'type': 'str',
                },
            'ddet_ind_pkt_drop_rate_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_syn_rate_current': {
                'type': 'str',
                },
            'ddet_ind_syn_rate_min': {
                'type': 'str',
                },
            'ddet_ind_syn_rate_max': {
                'type': 'str',
                },
            'ddet_ind_syn_rate_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_fin_rate_current': {
                'type': 'str',
                },
            'ddet_ind_fin_rate_min': {
                'type': 'str',
                },
            'ddet_ind_fin_rate_max': {
                'type': 'str',
                },
            'ddet_ind_fin_rate_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_rst_rate_current': {
                'type': 'str',
                },
            'ddet_ind_rst_rate_min': {
                'type': 'str',
                },
            'ddet_ind_rst_rate_max': {
                'type': 'str',
                },
            'ddet_ind_rst_rate_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_small_window_ack_rate_current': {
                'type': 'str',
                },
            'ddet_ind_small_window_ack_rate_min': {
                'type': 'str',
                },
            'ddet_ind_small_window_ack_rate_max': {
                'type': 'str',
                },
            'ddet_ind_small_window_ack_rate_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_empty_ack_rate_current': {
                'type': 'str',
                },
            'ddet_ind_empty_ack_rate_min': {
                'type': 'str',
                },
            'ddet_ind_empty_ack_rate_max': {
                'type': 'str',
                },
            'ddet_ind_empty_ack_rate_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_small_payload_rate_current': {
                'type': 'str',
                },
            'ddet_ind_small_payload_rate_min': {
                'type': 'str',
                },
            'ddet_ind_small_payload_rate_max': {
                'type': 'str',
                },
            'ddet_ind_small_payload_rate_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_pkt_drop_ratio_current': {
                'type': 'str',
                },
            'ddet_ind_pkt_drop_ratio_min': {
                'type': 'str',
                },
            'ddet_ind_pkt_drop_ratio_max': {
                'type': 'str',
                },
            'ddet_ind_pkt_drop_ratio_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_inb_per_outb_current': {
                'type': 'str',
                },
            'ddet_ind_inb_per_outb_min': {
                'type': 'str',
                },
            'ddet_ind_inb_per_outb_max': {
                'type': 'str',
                },
            'ddet_ind_inb_per_outb_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_syn_per_fin_rate_current': {
                'type': 'str',
                },
            'ddet_ind_syn_per_fin_rate_min': {
                'type': 'str',
                },
            'ddet_ind_syn_per_fin_rate_max': {
                'type': 'str',
                },
            'ddet_ind_syn_per_fin_rate_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_conn_miss_rate_current': {
                'type': 'str',
                },
            'ddet_ind_conn_miss_rate_min': {
                'type': 'str',
                },
            'ddet_ind_conn_miss_rate_max': {
                'type': 'str',
                },
            'ddet_ind_conn_miss_rate_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_concurrent_conns_current': {
                'type': 'str',
                },
            'ddet_ind_concurrent_conns_min': {
                'type': 'str',
                },
            'ddet_ind_concurrent_conns_max': {
                'type': 'str',
                },
            'ddet_ind_concurrent_conns_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_data_cpu_util_current': {
                'type': 'str',
                },
            'ddet_ind_data_cpu_util_min': {
                'type': 'str',
                },
            'ddet_ind_data_cpu_util_max': {
                'type': 'str',
                },
            'ddet_ind_data_cpu_util_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_outside_intf_util_current': {
                'type': 'str',
                },
            'ddet_ind_outside_intf_util_min': {
                'type': 'str',
                },
            'ddet_ind_outside_intf_util_max': {
                'type': 'str',
                },
            'ddet_ind_outside_intf_util_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_frag_rate_current': {
                'type': 'str',
                },
            'ddet_ind_frag_rate_min': {
                'type': 'str',
                },
            'ddet_ind_frag_rate_max': {
                'type': 'str',
                },
            'ddet_ind_frag_rate_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_bit_rate_current': {
                'type': 'str',
                },
            'ddet_ind_bit_rate_min': {
                'type': 'str',
                },
            'ddet_ind_bit_rate_max': {
                'type': 'str',
                },
            'ddet_ind_bit_rate_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_total_szp_current': {
                'type': 'str',
                },
            'ddet_ind_total_szp_min': {
                'type': 'str',
                },
            'ddet_ind_total_szp_max': {
                'type': 'str',
                },
            'ddet_ind_total_szp_adaptive_threshold': {
                'type': 'str',
                },
            'ddet_ind_syn_ack_rate_current': {
                'type': 'str',
                },
            'ddet_ind_syn_ack_rate_min': {
                'type': 'str',
                },
            'ddet_ind_syn_ack_rate_max': {
                'type': 'str',
                },
            'ddet_ind_syn_ack_rate_adaptive_threshold': {
                'type': 'str',
                }
            }
        })
    # Parent keys
    rv.update(dict(protocol=dict(type='str', required=True), zone_service_other_port_other=dict(type='str', required=True), zone_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/dst/zone/{zone_name}/port/zone-service-other/{zone_service_other_port_other}+{protocol}/port-ind"

    f_dict = {}
    if '/' in module.params["protocol"]:
        f_dict["protocol"] = module.params["protocol"].replace("/", "%2F")
    else:
        f_dict["protocol"] = module.params["protocol"]
    if '/' in module.params["zone_service_other_port_other"]:
        f_dict["zone_service_other_port_other"] = module.params["zone_service_other_port_other"].replace("/", "%2F")
    else:
        f_dict["zone_service_other_port_other"] = module.params["zone_service_other_port_other"]
    if '/' in module.params["zone_name"]:
        f_dict["zone_name"] = module.params["zone_name"].replace("/", "%2F")
    else:
        f_dict["zone_name"] = module.params["zone_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/dst/zone/{zone_name}/port/zone-service-other/{zone_service_other_port_other}+{protocol}/port-ind"

    f_dict = {}
    f_dict["protocol"] = module.params["protocol"]
    f_dict["zone_service_other_port_other"] = module.params["zone_service_other_port_other"]
    f_dict["zone_name"] = module.params["zone_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["port-ind"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["port-ind"].get(k) != v:
            change_results["changed"] = True
            config_changes["port-ind"][k] = v

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
    payload = utils.build_json("port-ind", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


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

        if state == 'noop':
            if module.params.get("get_type") == "single" or module.params.get("get_type") is None:
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["port-ind"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["port-ind-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["port-ind"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["port-ind"]["stats"] if info != "NotFound" else info
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
