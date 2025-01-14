#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_network_object
description:
    - Configure DDoS a static Monitor Network Object
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
    object_name:
        description:
        - "Field object_name"
        type: str
        required: True
    operational_mode:
        description:
        - "'monitor'= Monitor mode; 'learning'= Learning mode;"
        type: str
        required: False
    threshold_sensitivity:
        description:
        - "tune threshold ranges with levels LOW/MEDIUM/HIGH/OFF(default) or multiplier of
          threshold value (available options are LOW=5x/MEDIUM=3x/HIGH=1.5x/OFF=1x, or
          float value between 1.0-10.0)"
        type: str
        required: False
    histogram_mode:
        description:
        - "'off'= histogram feature disabled; 'monitor'= histogram feature enabled with
          anomaly escalation; 'observe'= histogram feature enabled and observe only;"
        type: str
        required: False
    anomaly_detection_trigger:
        description:
        - "'all'= Use both learned and static thresholds (static thresholds take
          precedence); 'static-threshold-only'= Use static thresholds only;"
        type: str
        required: False
    service_discovery:
        description:
        - "'disable'= Disable service discovery for hosts (default= enabled);"
        type: str
        required: False
    host_sport_discovery:
        description:
        - "'enable'= Enable source port discovery.; 'disable'= Disable source port
          discovery.;"
        type: str
        required: False
    sport_anomaly_detection:
        description:
        - "'disable'= Disable source port anomaly detection (default= enabled);"
        type: str
        required: False
    flooding_multiplier:
        description:
        - "multiplier for flooding detection threshold in network objects (default 2x
          threshold)"
        type: int
        required: False
    relative_auto_break_down_threshold:
        description:
        - "Field relative_auto_break_down_threshold"
        type: dict
        required: False
        suboptions:
            network_percentage:
                description:
                - "percentage of parent node"
                type: int
            permil:
                description:
                - "permil of root node"
                type: int
    static_auto_break_down_threshold:
        description:
        - "Field static_auto_break_down_threshold"
        type: dict
        required: False
        suboptions:
            network_pkt_rate:
                description:
                - "packet rate of current node"
                type: int
    service_break_down_threshold_local:
        description:
        - "Field service_break_down_threshold_local"
        type: dict
        required: False
        suboptions:
            svc_percentage:
                description:
                - "percentage of parent ip node"
                type: int
    host_anomaly_threshold:
        description:
        - "Field host_anomaly_threshold"
        type: dict
        required: False
        suboptions:
            host_pkt_rate:
                description:
                - "Forward packet rate of per host"
                type: int
            host_bit_rate:
                description:
                - "Forward bit rate of per host"
                type: int
            host_rev_pkt_rate:
                description:
                - "Reverse packet rate of per host"
                type: int
            host_rev_bit_rate:
                description:
                - "Reverse bit rate of per host"
                type: int
            host_undiscovered_pkt_rate:
                description:
                - "Undiscovered forward packet rate of per host"
                type: int
            host_flow_count:
                description:
                - "Flow count of per host"
                type: int
            host_syn_rate:
                description:
                - "SYN packet rate of per host"
                type: int
            host_fin_rate:
                description:
                - "FIN packet rate of per host"
                type: int
            host_rst_rate:
                description:
                - "RST packet rate of per host"
                type: int
            host_tcp_pkt_rate:
                description:
                - "Tcp packet rate of per host"
                type: int
            host_udp_pkt_rate:
                description:
                - "Udp packet rate of per host"
                type: int
            host_icmp_pkt_rate:
                description:
                - "ICMP packet rate of per host"
                type: int
            host_undiscovered_host_pkt_rate:
                description:
                - "forward packet rate of per undiscovered host"
                type: int
            host_undiscovered_host_bit_rate:
                description:
                - "Forward bit rate of per undiscovered host"
                type: int
    sport_discovery_threshold:
        description:
        - "Field sport_discovery_threshold"
        type: dict
        required: False
        suboptions:
            sport_heavy_hitter_percentage:
                description:
                - "Percentage of the bit rate of undiscovered source ports (default= 10)"
                type: int
            sport_discovery_bit_rate_percentage:
                description:
                - "Percentage of the bit rate of source port's parent entry"
                type: int
    network_object_anomaly_threshold:
        description:
        - "Field network_object_anomaly_threshold"
        type: dict
        required: False
        suboptions:
            network_object_pkt_rate:
                description:
                - "Packet rate of the network-object"
                type: int
            network_object_bit_rate:
                description:
                - "Bit rate of the network-object"
                type: int
    enable_top_k:
        description:
        - "Field enable_top_k"
        type: list
        required: False
        suboptions:
            topk_type:
                description:
                - "'destination'= Topk destination IP;"
                type: str
            topk_dst_num_records:
                description:
                - "Maximum number of records to show in topk"
                type: int
            topk_sort_key:
                description:
                - "'average'= window average; 'max-peak'= max peak;"
                type: str
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
                - "'all'= all; 'subnet_learned'= Subnet Entry Learned; 'subnet_aged'= Subnet Entry
          Aged; 'subnet_create_fail'= Subnet Entry Create Failures; 'ip_learned'= IP
          Entry Learned; 'ip_aged'= IP Entry Aged; 'ip_create_fail'= IP Entry Create
          Failures; 'service_learned'= Service Entry Learned; 'service_aged'= Service
          Entry Aged; 'service_create_fail'= Service Entry Create Failures;
          'packet_rate'= PPS; 'bit_rate'= B(bits)PS; 'topk_allocate_fail'= Topk Allocate
          Failures; 'sport_learned'= Source Port Entry Learned; 'sport_aged'= Source Port
          Entry Aged; 'sport_create_fail'= Source Port Entry Create Failures;
          'agent_group_learned'= Agent Group Entry Learned; 'agent_group_aged'= Agent
          Group Entry Aged; 'agent_group_create_fail'= Agent Group Entry Create Failures;
          'duplicate_sample_pkt_rcv'= Duplicate Sample Packet Received;"
                type: str
    ip_list:
        description:
        - "Field ip_list"
        type: list
        required: False
        suboptions:
            subnet_ip_addr:
                description:
                - "IP Subnet, supported prefix range is from 8 to 31"
                type: str
            prefix_anomaly_threshold:
                description:
                - "Field prefix_anomaly_threshold"
                type: dict
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
    ipv6_list:
        description:
        - "Field ipv6_list"
        type: list
        required: False
        suboptions:
            subnet_ipv6_addr:
                description:
                - "IPV6 Subnet, supported prefix range is from 40 to 63"
                type: str
            prefix_anomaly_threshold:
                description:
                - "Field prefix_anomaly_threshold"
                type: dict
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
    notification:
        description:
        - "Field notification"
        type: dict
        required: False
        suboptions:
            configuration:
                description:
                - "'configuration'= configuration;"
                type: str
            notification:
                description:
                - "Field notification"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
    sub_network:
        description:
        - "Field sub_network"
        type: dict
        required: False
        suboptions:
            sub_network_v4_list:
                description:
                - "Field sub_network_v4_list"
                type: list
            sub_network_v6_list:
                description:
                - "Field sub_network_v6_list"
                type: list
    topk_destinations:
        description:
        - "Field topk_destinations"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    sport_anomaly_threshold:
        description:
        - "Field sport_anomaly_threshold"
        type: dict
        required: False
        suboptions:
            packet_rate:
                description:
                - "Field packet_rate"
                type: dict
            packet_rate_percentage:
                description:
                - "Field packet_rate_percentage"
                type: dict
            bit_rate:
                description:
                - "Field bit_rate"
                type: dict
            bit_rate_percentage:
                description:
                - "Field bit_rate_percentage"
                type: dict
            ip_list:
                description:
                - "Field ip_list"
                type: list
            ipv6_list:
                description:
                - "Field ipv6_list"
                type: list
            sport_list:
                description:
                - "Field sport_list"
                type: list
    sport_list:
        description:
        - "Field sport_list"
        type: list
        required: False
        suboptions:
            port_num:
                description:
                - "Port Number"
                type: int
            protocol:
                description:
                - "'udp'= UDP port; 'tcp'= TCP Port;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    trustlist:
        description:
        - "Field trustlist"
        type: dict
        required: False
        suboptions:
            v4_class_list:
                description:
                - "IPv4 Class-list name"
                type: str
            v6_class_list:
                description:
                - "IPv6 Class-list name"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    indicators_to_monitor:
        description:
        - "Field indicators_to_monitor"
        type: dict
        required: False
        suboptions:
            enable:
                description:
                - "Field enable"
                type: bool
            monitor_pkt_rate:
                description:
                - "Forward packet rate"
                type: bool
            monitor_bit_rate:
                description:
                - "Forward bit rate"
                type: bool
            monitor_rev_pkt_rate:
                description:
                - "Reverse packet rate"
                type: bool
            monitor_rev_bit_rate:
                description:
                - "Reverse bit rate"
                type: bool
            monitor_undiscovered_pkt_rate:
                description:
                - "Undiscovered forward packet rate"
                type: bool
            monitor_flow_count:
                description:
                - "Flow count"
                type: bool
            monitor_syn_rate:
                description:
                - "SYN packet rate"
                type: bool
            monitor_fin_rate:
                description:
                - "FIN packet rate"
                type: bool
            monitor_rst_rate:
                description:
                - "RST packet rate"
                type: bool
            monitor_tcp_pkt_rate:
                description:
                - "TCP packet rate"
                type: bool
            monitor_udp_pkt_rate:
                description:
                - "UDP packet rate"
                type: bool
            monitor_icmp_pkt_rate:
                description:
                - "ICMP packet rate"
                type: bool
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
            entry_list:
                description:
                - "Field entry_list"
                type: list
            entry_count:
                description:
                - "Field entry_count"
                type: int
            details:
                description:
                - "Field details"
                type: bool
            trusted_details:
                description:
                - "Field trusted_details"
                type: bool
            total_details:
                description:
                - "Field total_details"
                type: bool
            victim_list:
                description:
                - "Field victim_list"
                type: bool
            discovered_list:
                description:
                - "Field discovered_list"
                type: bool
            sport_list:
                description:
                - "Field sport_list"
                type: bool
            subnet_ip_addr:
                description:
                - "Field subnet_ip_addr"
                type: str
            subnet_ipv6_addr:
                description:
                - "Field subnet_ipv6_addr"
                type: str
            ipv4:
                description:
                - "Field ipv4"
                type: str
            discovered_ip_list:
                description:
                - "Field discovered_ip_list"
                type: bool
            anomaly_ip_list:
                description:
                - "Field anomaly_ip_list"
                type: bool
            sport:
                description:
                - "Field sport"
                type: bool
            port_start:
                description:
                - "Field port_start"
                type: int
            port_end:
                description:
                - "Field port_end"
                type: int
            protocol:
                description:
                - "Field protocol"
                type: int
            single_layer_discovered_list:
                description:
                - "Field single_layer_discovered_list"
                type: bool
            agent_group_details:
                description:
                - "Field agent_group_details"
                type: bool
            object_name:
                description:
                - "Field object_name"
                type: str
            topk_destinations:
                description:
                - "Field topk_destinations"
                type: dict
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            subnet_learned:
                description:
                - "Subnet Entry Learned"
                type: str
            subnet_aged:
                description:
                - "Subnet Entry Aged"
                type: str
            subnet_create_fail:
                description:
                - "Subnet Entry Create Failures"
                type: str
            ip_learned:
                description:
                - "IP Entry Learned"
                type: str
            ip_aged:
                description:
                - "IP Entry Aged"
                type: str
            ip_create_fail:
                description:
                - "IP Entry Create Failures"
                type: str
            service_learned:
                description:
                - "Service Entry Learned"
                type: str
            service_aged:
                description:
                - "Service Entry Aged"
                type: str
            service_create_fail:
                description:
                - "Service Entry Create Failures"
                type: str
            packet_rate:
                description:
                - "PPS"
                type: str
            bit_rate:
                description:
                - "B(bits)PS"
                type: str
            topk_allocate_fail:
                description:
                - "Topk Allocate Failures"
                type: str
            sport_learned:
                description:
                - "Source Port Entry Learned"
                type: str
            sport_aged:
                description:
                - "Source Port Entry Aged"
                type: str
            sport_create_fail:
                description:
                - "Source Port Entry Create Failures"
                type: str
            agent_group_learned:
                description:
                - "Agent Group Entry Learned"
                type: str
            agent_group_aged:
                description:
                - "Agent Group Entry Aged"
                type: str
            agent_group_create_fail:
                description:
                - "Agent Group Entry Create Failures"
                type: str
            duplicate_sample_pkt_rcv:
                description:
                - "Duplicate Sample Packet Received"
                type: str
            object_name:
                description:
                - "Field object_name"
                type: str
            ip_list:
                description:
                - "Field ip_list"
                type: list
            ipv6_list:
                description:
                - "Field ipv6_list"
                type: list

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
    "anomaly_detection_trigger", "enable_top_k", "flooding_multiplier", "histogram_mode", "host_anomaly_threshold", "host_sport_discovery", "indicators_to_monitor", "ip_list", "ipv6_list", "network_object_anomaly_threshold", "notification", "object_name", "oper", "operational_mode", "relative_auto_break_down_threshold", "sampling_enable",
    "service_break_down_threshold_local", "service_discovery", "sport_anomaly_detection", "sport_anomaly_threshold", "sport_discovery_threshold", "sport_list", "static_auto_break_down_threshold", "stats", "sub_network", "threshold_sensitivity", "topk_destinations", "trustlist", "user_tag", "uuid",
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
        'object_name': {
            'type': 'str',
            'required': True,
            },
        'operational_mode': {
            'type': 'str',
            'choices': ['monitor', 'learning']
            },
        'threshold_sensitivity': {
            'type': 'str',
            },
        'histogram_mode': {
            'type': 'str',
            'choices': ['off', 'monitor', 'observe']
            },
        'anomaly_detection_trigger': {
            'type': 'str',
            'choices': ['all', 'static-threshold-only']
            },
        'service_discovery': {
            'type': 'str',
            'choices': ['disable']
            },
        'host_sport_discovery': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'sport_anomaly_detection': {
            'type': 'str',
            'choices': ['disable']
            },
        'flooding_multiplier': {
            'type': 'int',
            },
        'relative_auto_break_down_threshold': {
            'type': 'dict',
            'network_percentage': {
                'type': 'int',
                },
            'permil': {
                'type': 'int',
                }
            },
        'static_auto_break_down_threshold': {
            'type': 'dict',
            'network_pkt_rate': {
                'type': 'int',
                }
            },
        'service_break_down_threshold_local': {
            'type': 'dict',
            'svc_percentage': {
                'type': 'int',
                }
            },
        'host_anomaly_threshold': {
            'type': 'dict',
            'host_pkt_rate': {
                'type': 'int',
                },
            'host_bit_rate': {
                'type': 'int',
                },
            'host_rev_pkt_rate': {
                'type': 'int',
                },
            'host_rev_bit_rate': {
                'type': 'int',
                },
            'host_undiscovered_pkt_rate': {
                'type': 'int',
                },
            'host_flow_count': {
                'type': 'int',
                },
            'host_syn_rate': {
                'type': 'int',
                },
            'host_fin_rate': {
                'type': 'int',
                },
            'host_rst_rate': {
                'type': 'int',
                },
            'host_tcp_pkt_rate': {
                'type': 'int',
                },
            'host_udp_pkt_rate': {
                'type': 'int',
                },
            'host_icmp_pkt_rate': {
                'type': 'int',
                },
            'host_undiscovered_host_pkt_rate': {
                'type': 'int',
                },
            'host_undiscovered_host_bit_rate': {
                'type': 'int',
                }
            },
        'sport_discovery_threshold': {
            'type': 'dict',
            'sport_heavy_hitter_percentage': {
                'type': 'int',
                },
            'sport_discovery_bit_rate_percentage': {
                'type': 'int',
                }
            },
        'network_object_anomaly_threshold': {
            'type': 'dict',
            'network_object_pkt_rate': {
                'type': 'int',
                },
            'network_object_bit_rate': {
                'type': 'int',
                }
            },
        'enable_top_k': {
            'type': 'list',
            'topk_type': {
                'type': 'str',
                'choices': ['destination']
                },
            'topk_dst_num_records': {
                'type': 'int',
                },
            'topk_sort_key': {
                'type': 'str',
                'choices': ['average', 'max-peak']
                }
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
                    'all', 'subnet_learned', 'subnet_aged', 'subnet_create_fail', 'ip_learned', 'ip_aged', 'ip_create_fail', 'service_learned', 'service_aged', 'service_create_fail', 'packet_rate', 'bit_rate', 'topk_allocate_fail', 'sport_learned', 'sport_aged', 'sport_create_fail', 'agent_group_learned', 'agent_group_aged',
                    'agent_group_create_fail', 'duplicate_sample_pkt_rcv'
                    ]
                }
            },
        'ip_list': {
            'type': 'list',
            'subnet_ip_addr': {
                'type': 'str',
                'required': True,
                },
            'prefix_anomaly_threshold': {
                'type': 'dict',
                'prefix_pkt_rate': {
                    'type': 'int',
                    },
                'prefix_bit_rate': {
                    'type': 'int',
                    }
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
                    'type': 'str',
                    'choices': ['all', 'packet_rate', 'bit_rate']
                    }
                }
            },
        'ipv6_list': {
            'type': 'list',
            'subnet_ipv6_addr': {
                'type': 'str',
                'required': True,
                },
            'prefix_anomaly_threshold': {
                'type': 'dict',
                'prefix_pkt_rate': {
                    'type': 'int',
                    },
                'prefix_bit_rate': {
                    'type': 'int',
                    }
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
                    'type': 'str',
                    'choices': ['all', 'packet_rate', 'bit_rate']
                    }
                }
            },
        'notification': {
            'type': 'dict',
            'configuration': {
                'type': 'str',
                'choices': ['configuration']
                },
            'notification': {
                'type': 'list',
                'notification_template_name': {
                    'type': 'str',
                    }
                },
            'uuid': {
                'type': 'str',
                }
            },
        'sub_network': {
            'type': 'dict',
            'sub_network_v4_list': {
                'type': 'list',
                'subnet_ip_addr': {
                    'type': 'str',
                    'required': True,
                    },
                'host_anomaly_threshold': {
                    'type': 'dict',
                    'static_pkt_rate_threshold': {
                        'type': 'int',
                        },
                    'static_rev_pkt_rate_threshold': {
                        'type': 'int',
                        },
                    'static_bit_rate_threshold': {
                        'type': 'int',
                        },
                    'static_rev_bit_rate_threshold': {
                        'type': 'int',
                        },
                    'static_undiscovered_pkt_rate_threshold': {
                        'type': 'int',
                        },
                    'static_flow_count_threshold': {
                        'type': 'int',
                        },
                    'static_syn_rate_threshold': {
                        'type': 'int',
                        },
                    'static_fin_rate_threshold': {
                        'type': 'int',
                        },
                    'static_rst_rate_threshold': {
                        'type': 'int',
                        },
                    'static_tcp_pkt_rate_threshold': {
                        'type': 'int',
                        },
                    'static_udp_pkt_rate_threshold': {
                        'type': 'int',
                        },
                    'static_icmp_pkt_rate_threshold': {
                        'type': 'int',
                        },
                    'static_undiscovered_host_pkt_rate_threshold': {
                        'type': 'int',
                        },
                    'static_undiscovered_host_bit_rate_threshold': {
                        'type': 'int',
                        }
                    },
                'sub_network_anomaly_threshold': {
                    'type': 'dict',
                    'static_sub_network_pkt_rate': {
                        'type': 'int',
                        },
                    'static_sub_network_bit_rate': {
                        'type': 'int',
                        }
                    },
                'subnet_breakdown': {
                    'type': 'int',
                    },
                'breakdown_subnet_threshold': {
                    'type': 'dict',
                    'breakdown_subnet_pkt_rate': {
                        'type': 'int',
                        },
                    'breakdown_subnet_bit_rate': {
                        'type': 'int',
                        }
                    },
                'uuid': {
                    'type': 'str',
                    },
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type': 'str',
                        'choices': ['all', 'packet_rate', 'bit_rate']
                        }
                    }
                },
            'sub_network_v6_list': {
                'type': 'list',
                'subnet_ipv6_addr': {
                    'type': 'str',
                    'required': True,
                    },
                'host_anomaly_threshold': {
                    'type': 'dict',
                    'static_pkt_rate_threshold': {
                        'type': 'int',
                        },
                    'static_rev_pkt_rate_threshold': {
                        'type': 'int',
                        },
                    'static_bit_rate_threshold': {
                        'type': 'int',
                        },
                    'static_rev_bit_rate_threshold': {
                        'type': 'int',
                        },
                    'static_undiscovered_pkt_rate_threshold': {
                        'type': 'int',
                        },
                    'static_flow_count_threshold': {
                        'type': 'int',
                        },
                    'static_syn_rate_threshold': {
                        'type': 'int',
                        },
                    'static_fin_rate_threshold': {
                        'type': 'int',
                        },
                    'static_rst_rate_threshold': {
                        'type': 'int',
                        },
                    'static_tcp_pkt_rate_threshold': {
                        'type': 'int',
                        },
                    'static_udp_pkt_rate_threshold': {
                        'type': 'int',
                        },
                    'static_icmp_pkt_rate_threshold': {
                        'type': 'int',
                        },
                    'static_undiscovered_host_pkt_rate_threshold': {
                        'type': 'int',
                        },
                    'static_undiscovered_host_bit_rate_threshold': {
                        'type': 'int',
                        }
                    },
                'sub_network_anomaly_threshold': {
                    'type': 'dict',
                    'static_sub_network_pkt_rate': {
                        'type': 'int',
                        },
                    'static_sub_network_bit_rate': {
                        'type': 'int',
                        }
                    },
                'subnet_breakdown': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type': 'str',
                        'choices': ['all', 'packet_rate', 'bit_rate']
                        }
                    }
                }
            },
        'topk_destinations': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'sport_anomaly_threshold': {
            'type': 'dict',
            'packet_rate': {
                'type': 'dict',
                'value': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'packet_rate_percentage': {
                'type': 'dict',
                'value': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'bit_rate': {
                'type': 'dict',
                'value': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'bit_rate_percentage': {
                'type': 'dict',
                'value': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'ip_list': {
                'type': 'list',
                'ip_addr': {
                    'type': 'str',
                    'required': True,
                    },
                'packet_rate_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['packet-rate']
                    },
                'packet_rate_percentage_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['packet-rate-percentage']
                    },
                'bit_rate_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['bit-rate']
                    },
                'bit_rate_percentage_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['bit-rate-percentage']
                    },
                'packet_rate': {
                    'type': 'int',
                    },
                'packet_rate_percentage': {
                    'type': 'int',
                    },
                'bit_rate': {
                    'type': 'int',
                    },
                'bit_rate_percentage': {
                    'type': 'int',
                    },
                'sport_num': {
                    'type': 'int',
                    'required': True,
                    },
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['udp', 'tcp']
                    },
                'ip_sport_packet_rate_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['packet-rate']
                    },
                'ip_sport_packet_rate_percentage_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['packet-rate-percentage']
                    },
                'ip_sport_bit_rate_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['bit-rate']
                    },
                'ip_sport_bit_rate_percentage_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['bit-rate-percentage']
                    },
                'ip_sport_packet_rate': {
                    'type': 'int',
                    },
                'ip_sport_packet_rate_percentage': {
                    'type': 'int',
                    },
                'ip_sport_bit_rate': {
                    'type': 'int',
                    },
                'ip_sport_bit_rate_percentage': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'ipv6_list': {
                'type': 'list',
                'ip_addr': {
                    'type': 'str',
                    'required': True,
                    },
                'packet_rate_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['packet-rate']
                    },
                'packet_rate_percentage_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['packet-rate-percentage']
                    },
                'bit_rate_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['bit-rate']
                    },
                'bit_rate_percentage_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['bit-rate-percentage']
                    },
                'packet_rate': {
                    'type': 'int',
                    },
                'packet_rate_percentage': {
                    'type': 'int',
                    },
                'bit_rate': {
                    'type': 'int',
                    },
                'bit_rate_percentage': {
                    'type': 'int',
                    },
                'sport_num': {
                    'type': 'int',
                    'required': True,
                    },
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['udp', 'tcp']
                    },
                'ip_sport_packet_rate_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['packet-rate']
                    },
                'ip_sport_packet_rate_percentage_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['packet-rate-percentage']
                    },
                'ip_sport_bit_rate_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['bit-rate']
                    },
                'ip_sport_bit_rate_percentage_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['bit-rate-percentage']
                    },
                'ip_sport_packet_rate': {
                    'type': 'int',
                    },
                'ip_sport_packet_rate_percentage': {
                    'type': 'int',
                    },
                'ip_sport_bit_rate': {
                    'type': 'int',
                    },
                'ip_sport_bit_rate_percentage': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'sport_list': {
                'type': 'list',
                'sport_num': {
                    'type': 'int',
                    'required': True,
                    },
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['udp', 'tcp']
                    },
                'packet_rate_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['packet-rate']
                    },
                'packet_rate_percentage_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['packet-rate-percentage']
                    },
                'bit_rate_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['bit-rate']
                    },
                'bit_rate_percentage_str': {
                    'type': 'str',
                    'required': True,
                    'choices': ['bit-rate-percentage']
                    },
                'packet_rate': {
                    'type': 'int',
                    },
                'packet_rate_percentage': {
                    'type': 'int',
                    },
                'bit_rate': {
                    'type': 'int',
                    },
                'bit_rate_percentage': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'sport_list': {
            'type': 'list',
            'port_num': {
                'type': 'int',
                'required': True,
                },
            'protocol': {
                'type': 'str',
                'required': True,
                'choices': ['udp', 'tcp']
                },
            'uuid': {
                'type': 'str',
                }
            },
        'trustlist': {
            'type': 'dict',
            'v4_class_list': {
                'type': 'str',
                },
            'v6_class_list': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'indicators_to_monitor': {
            'type': 'dict',
            'enable': {
                'type': 'bool',
                },
            'monitor_pkt_rate': {
                'type': 'bool',
                },
            'monitor_bit_rate': {
                'type': 'bool',
                },
            'monitor_rev_pkt_rate': {
                'type': 'bool',
                },
            'monitor_rev_bit_rate': {
                'type': 'bool',
                },
            'monitor_undiscovered_pkt_rate': {
                'type': 'bool',
                },
            'monitor_flow_count': {
                'type': 'bool',
                },
            'monitor_syn_rate': {
                'type': 'bool',
                },
            'monitor_fin_rate': {
                'type': 'bool',
                },
            'monitor_rst_rate': {
                'type': 'bool',
                },
            'monitor_tcp_pkt_rate': {
                'type': 'bool',
                },
            'monitor_udp_pkt_rate': {
                'type': 'bool',
                },
            'monitor_icmp_pkt_rate': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'entry_list': {
                'type': 'list',
                'address': {
                    'type': 'str',
                    },
                'children_count': {
                    'type': 'int',
                    },
                'port_range_start': {
                    'type': 'int',
                    },
                'port_range_end': {
                    'type': 'int',
                    },
                'port': {
                    'type': 'int',
                    },
                'service_protocol': {
                    'type': 'str',
                    },
                'agent_group_name': {
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
                    'value': {
                        'type': 'list',
                        'current': {
                            'type': 'str',
                            },
                        'threshold': {
                            'type': 'str',
                            },
                        'max': {
                            'type': 'str',
                            }
                        },
                    'is_anomaly': {
                        'type': 'int',
                        }
                    },
                'is_anomaly': {
                    'type': 'int',
                    },
                'is_learning_done': {
                    'type': 'int',
                    },
                'is_histogram_learning_done': {
                    'type': 'int',
                    },
                'operational_mode': {
                    'type': 'int',
                    },
                'histogram_mode': {
                    'type': 'int',
                    },
                'display_filter': {
                    'type': 'str',
                    },
                'es_timestamp': {
                    'type': 'str',
                    },
                'de_es_timestamp': {
                    'type': 'str',
                    }
                },
            'entry_count': {
                'type': 'int',
                },
            'details': {
                'type': 'bool',
                },
            'trusted_details': {
                'type': 'bool',
                },
            'total_details': {
                'type': 'bool',
                },
            'victim_list': {
                'type': 'bool',
                },
            'discovered_list': {
                'type': 'bool',
                },
            'sport_list': {
                'type': 'bool',
                },
            'subnet_ip_addr': {
                'type': 'str',
                },
            'subnet_ipv6_addr': {
                'type': 'str',
                },
            'ipv4': {
                'type': 'str',
                },
            'discovered_ip_list': {
                'type': 'bool',
                },
            'anomaly_ip_list': {
                'type': 'bool',
                },
            'sport': {
                'type': 'bool',
                },
            'port_start': {
                'type': 'int',
                },
            'port_end': {
                'type': 'int',
                },
            'protocol': {
                'type': 'int',
                },
            'single_layer_discovered_list': {
                'type': 'bool',
                },
            'agent_group_details': {
                'type': 'bool',
                },
            'object_name': {
                'type': 'str',
                'required': True,
                },
            'topk_destinations': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'indicators': {
                        'type': 'list',
                        'indicator_name': {
                            'type': 'str',
                            },
                        'indicator_index': {
                            'type': 'int',
                            },
                        'destinations': {
                            'type': 'list',
                            'address': {
                                'type': 'str',
                                },
                            'rate': {
                                'type': 'str',
                                }
                            }
                        },
                    'topk_type': {
                        'type': 'int',
                        },
                    'reset_time': {
                        'type': 'int',
                        }
                    }
                }
            },
        'stats': {
            'type': 'dict',
            'subnet_learned': {
                'type': 'str',
                },
            'subnet_aged': {
                'type': 'str',
                },
            'subnet_create_fail': {
                'type': 'str',
                },
            'ip_learned': {
                'type': 'str',
                },
            'ip_aged': {
                'type': 'str',
                },
            'ip_create_fail': {
                'type': 'str',
                },
            'service_learned': {
                'type': 'str',
                },
            'service_aged': {
                'type': 'str',
                },
            'service_create_fail': {
                'type': 'str',
                },
            'packet_rate': {
                'type': 'str',
                },
            'bit_rate': {
                'type': 'str',
                },
            'topk_allocate_fail': {
                'type': 'str',
                },
            'sport_learned': {
                'type': 'str',
                },
            'sport_aged': {
                'type': 'str',
                },
            'sport_create_fail': {
                'type': 'str',
                },
            'agent_group_learned': {
                'type': 'str',
                },
            'agent_group_aged': {
                'type': 'str',
                },
            'agent_group_create_fail': {
                'type': 'str',
                },
            'duplicate_sample_pkt_rcv': {
                'type': 'str',
                },
            'object_name': {
                'type': 'str',
                'required': True,
                },
            'ip_list': {
                'type': 'list',
                'subnet_ip_addr': {
                    'type': 'str',
                    'required': True,
                    },
                'stats': {
                    'type': 'dict',
                    'packet_rate': {
                        'type': 'str',
                        },
                    'bit_rate': {
                        'type': 'str',
                        }
                    }
                },
            'ipv6_list': {
                'type': 'list',
                'subnet_ipv6_addr': {
                    'type': 'str',
                    'required': True,
                    },
                'stats': {
                    'type': 'dict',
                    'packet_rate': {
                        'type': 'str',
                        },
                    'bit_rate': {
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
    url_base = "/axapi/v3/ddos/network-object/{object_name}"

    f_dict = {}
    if '/' in str(module.params["object_name"]):
        f_dict["object_name"] = module.params["object_name"].replace("/", "%2F")
    else:
        f_dict["object_name"] = module.params["object_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/network-object"

    f_dict = {}
    f_dict["object_name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["network-object"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["network-object"].get(k) != v:
            change_results["changed"] = True
            config_changes["network-object"][k] = v

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
    payload = utils.build_json("network-object", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["network-object"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["network-object-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["network-object"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["network-object"]["stats"] if info != "NotFound" else info
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
