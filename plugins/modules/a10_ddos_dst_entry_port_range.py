#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_dst_entry_port_range
description:
    - DDOS Port-Range & Protocol configuration
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
    entry_dst_entry_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    port_range_start:
        description:
        - "Port-Range Start Port Number"
        type: int
        required: True
    port_range_end:
        description:
        - "Port-Range End Port Number"
        type: int
        required: True
    protocol:
        description:
        - "'dns-tcp'= DNS-TCP Port; 'dns-udp'= DNS-UDP Port; 'http'= HTTP Port; 'tcp'= TCP
          Port; 'udp'= UDP Port; 'ssl-l4'= SSL-L4 Port; 'sip-udp'= SIP-UDP Port; 'sip-
          tcp'= SIP-TCP Port;"
        type: str
        required: True
    deny:
        description:
        - "Blacklist and Drop all incoming packets for protocol"
        type: bool
        required: False
    detection_enable:
        description:
        - "Enable ddos detection"
        type: bool
        required: False
    enable_top_k:
        description:
        - "Enable ddos top-k entries"
        type: bool
        required: False
    topk_num_records:
        description:
        - "Maximum number of records to show in topk"
        type: int
        required: False
    glid:
        description:
        - "Global limit ID"
        type: str
        required: False
    glid_exceed_action:
        description:
        - "Field glid_exceed_action"
        type: dict
        required: False
        suboptions:
            stateless_encap_action_cfg:
                description:
                - "Field stateless_encap_action_cfg"
                type: dict
    template:
        description:
        - "Field template"
        type: dict
        required: False
        suboptions:
            dns:
                description:
                - "DDOS dns template"
                type: str
            http:
                description:
                - "DDOS http template"
                type: str
            ssl_l4:
                description:
                - "DDOS SSL-L4 template"
                type: str
            sip:
                description:
                - "DDOS sip template"
                type: str
            tcp:
                description:
                - "DDOS tcp template"
                type: str
            udp:
                description:
                - "DDOS udp template"
                type: str
    sflow:
        description:
        - "Field sflow"
        type: dict
        required: False
        suboptions:
            polling:
                description:
                - "Field polling"
                type: dict
    capture_config:
        description:
        - "Field capture_config"
        type: dict
        required: False
        suboptions:
            capture_config_name:
                description:
                - "Capture-config name"
                type: str
            capture_config_mode:
                description:
                - "'drop'= Apply capture-config to dropped packets; 'forward'= Apply capture-
          config to forwarded packets; 'all'= Apply capture-config to both dropped and
          forwarded packets;"
                type: str
    set_counter_base_val:
        description:
        - "Set T2 counter value of current context to specified value"
        type: int
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
    port_ind:
        description:
        - "Field port_ind"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    topk_sources:
        description:
        - "Field topk_sources"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    progression_tracking:
        description:
        - "Field progression_tracking"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    pattern_recognition:
        description:
        - "Field pattern_recognition"
        type: dict
        required: False
        suboptions:
            algorithm:
                description:
                - "'heuristic'= heuristic algorithm;"
                type: str
            mode:
                description:
                - "'capture-never-expire'= War-time capture without rate exceeding and never
          expires; 'manual'= Manual mode;"
                type: str
            sensitivity:
                description:
                - "'high'= High Sensitivity; 'medium'= Medium Sensitivity; 'low'= Low Sensitivity;"
                type: str
            filter_threshold:
                description:
                - "Extracted filter threshold"
                type: int
            filter_inactive_threshold:
                description:
                - "Extracted filter inactive threshold"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    pattern_recognition_pu_details:
        description:
        - "Field pattern_recognition_pu_details"
        type: dict
        required: False
        suboptions:
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
            ddos_entry_list:
                description:
                - "Field ddos_entry_list"
                type: list
            resource_limit_config:
                description:
                - "Field resource_limit_config"
                type: str
            reource_limit_alloc:
                description:
                - "Field reource_limit_alloc"
                type: str
            resource_limit_remain:
                description:
                - "Field resource_limit_remain"
                type: str
            entry_displayed_count:
                description:
                - "Field entry_displayed_count"
                type: int
            service_displayed_count:
                description:
                - "Field service_displayed_count"
                type: int
            reporting_status:
                description:
                - "Field reporting_status"
                type: int
            all_ports:
                description:
                - "Field all_ports"
                type: bool
            all_src_ports:
                description:
                - "Field all_src_ports"
                type: bool
            all_ip_protos:
                description:
                - "Field all_ip_protos"
                type: bool
            port_protocol:
                description:
                - "Field port_protocol"
                type: str
            app_stat:
                description:
                - "Field app_stat"
                type: bool
            sflow_source_id:
                description:
                - "Field sflow_source_id"
                type: bool
            resource_usage:
                description:
                - "Field resource_usage"
                type: bool
            l4_ext_rate:
                description:
                - "Field l4_ext_rate"
                type: bool
            hw_blacklisted:
                description:
                - "Field hw_blacklisted"
                type: str
            suffix_request_rate:
                description:
                - "Field suffix_request_rate"
                type: bool
            domain_name:
                description:
                - "Field domain_name"
                type: str
            port_range_start:
                description:
                - "Port-Range Start Port Number"
                type: int
            port_range_end:
                description:
                - "Port-Range End Port Number"
                type: int
            protocol:
                description:
                - "'dns-tcp'= DNS-TCP Port; 'dns-udp'= DNS-UDP Port; 'http'= HTTP Port; 'tcp'= TCP
          Port; 'udp'= UDP Port; 'ssl-l4'= SSL-L4 Port; 'sip-udp'= SIP-UDP Port; 'sip-
          tcp'= SIP-TCP Port;"
                type: str
            port_ind:
                description:
                - "Field port_ind"
                type: dict
            topk_sources:
                description:
                - "Field topk_sources"
                type: dict
            progression_tracking:
                description:
                - "Field progression_tracking"
                type: dict
            pattern_recognition:
                description:
                - "Field pattern_recognition"
                type: dict
            pattern_recognition_pu_details:
                description:
                - "Field pattern_recognition_pu_details"
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
    "capture_config", "deny", "detection_enable", "enable_top_k", "glid", "glid_exceed_action", "oper", "pattern_recognition", "pattern_recognition_pu_details", "port_ind", "port_range_end", "port_range_start", "progression_tracking", "protocol", "set_counter_base_val", "sflow", "template", "topk_num_records", "topk_sources", "user_tag", "uuid",
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
        'port_range_start': {
            'type': 'int',
            'required': True,
            },
        'port_range_end': {
            'type': 'int',
            'required': True,
            },
        'protocol': {
            'type': 'str',
            'required': True,
            'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4', 'sip-udp', 'sip-tcp']
            },
        'deny': {
            'type': 'bool',
            },
        'detection_enable': {
            'type': 'bool',
            },
        'enable_top_k': {
            'type': 'bool',
            },
        'topk_num_records': {
            'type': 'int',
            },
        'glid': {
            'type': 'str',
            },
        'glid_exceed_action': {
            'type': 'dict',
            'stateless_encap_action_cfg': {
                'type': 'dict',
                'stateless_encap_action': {
                    'type': 'str',
                    'choices': ['stateless-tunnel-encap', 'stateless-tunnel-encap-scrubbed']
                    },
                'encap_template': {
                    'type': 'str',
                    }
                }
            },
        'template': {
            'type': 'dict',
            'dns': {
                'type': 'str',
                },
            'http': {
                'type': 'str',
                },
            'ssl_l4': {
                'type': 'str',
                },
            'sip': {
                'type': 'str',
                },
            'tcp': {
                'type': 'str',
                },
            'udp': {
                'type': 'str',
                }
            },
        'sflow': {
            'type': 'dict',
            'polling': {
                'type': 'dict',
                'sflow_packets': {
                    'type': 'bool',
                    },
                'sflow_tcp': {
                    'type': 'dict',
                    'sflow_tcp_basic': {
                        'type': 'bool',
                        },
                    'sflow_tcp_stateful': {
                        'type': 'bool',
                        }
                    },
                'sflow_http': {
                    'type': 'bool',
                    }
                }
            },
        'capture_config': {
            'type': 'dict',
            'capture_config_name': {
                'type': 'str',
                },
            'capture_config_mode': {
                'type': 'str',
                'choices': ['drop', 'forward', 'all']
                }
            },
        'set_counter_base_val': {
            'type': 'int',
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'port_ind': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'ip-proto-type', 'ddet_ind_pkt_rate_current', 'ddet_ind_pkt_rate_min', 'ddet_ind_pkt_rate_max', 'ddet_ind_pkt_drop_rate_current', 'ddet_ind_pkt_drop_rate_min', 'ddet_ind_pkt_drop_rate_max', 'ddet_ind_syn_rate_current', 'ddet_ind_syn_rate_min', 'ddet_ind_syn_rate_max', 'ddet_ind_fin_rate_current',
                        'ddet_ind_fin_rate_min', 'ddet_ind_fin_rate_max', 'ddet_ind_rst_rate_current', 'ddet_ind_rst_rate_min', 'ddet_ind_rst_rate_max', 'ddet_ind_small_window_ack_rate_current', 'ddet_ind_small_window_ack_rate_min', 'ddet_ind_small_window_ack_rate_max', 'ddet_ind_empty_ack_rate_current', 'ddet_ind_empty_ack_rate_min',
                        'ddet_ind_empty_ack_rate_max', 'ddet_ind_small_payload_rate_current', 'ddet_ind_small_payload_rate_min', 'ddet_ind_small_payload_rate_max', 'ddet_ind_pkt_drop_ratio_current', 'ddet_ind_pkt_drop_ratio_min', 'ddet_ind_pkt_drop_ratio_max', 'ddet_ind_inb_per_outb_current', 'ddet_ind_inb_per_outb_min',
                        'ddet_ind_inb_per_outb_max', 'ddet_ind_syn_per_fin_rate_current', 'ddet_ind_syn_per_fin_rate_min', 'ddet_ind_syn_per_fin_rate_max', 'ddet_ind_conn_miss_rate_current', 'ddet_ind_conn_miss_rate_min', 'ddet_ind_conn_miss_rate_max', 'ddet_ind_concurrent_conns_current', 'ddet_ind_concurrent_conns_min',
                        'ddet_ind_concurrent_conns_max', 'ddet_ind_data_cpu_util_current', 'ddet_ind_data_cpu_util_min', 'ddet_ind_data_cpu_util_max', 'ddet_ind_outside_intf_util_current', 'ddet_ind_outside_intf_util_min', 'ddet_ind_outside_intf_util_max', 'ddet_ind_frag_rate_current', 'ddet_ind_frag_rate_min', 'ddet_ind_frag_rate_max',
                        'ddet_ind_bit_rate_current', 'ddet_ind_bit_rate_min', 'ddet_ind_bit_rate_max'
                        ]
                    }
                }
            },
        'topk_sources': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'progression_tracking': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'pattern_recognition': {
            'type': 'dict',
            'algorithm': {
                'type': 'str',
                'choices': ['heuristic']
                },
            'mode': {
                'type': 'str',
                'choices': ['capture-never-expire', 'manual']
                },
            'sensitivity': {
                'type': 'str',
                'choices': ['high', 'medium', 'low']
                },
            'filter_threshold': {
                'type': 'int',
                },
            'filter_inactive_threshold': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'pattern_recognition_pu_details': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'ddos_entry_list': {
                'type': 'list',
                'dst_address_str': {
                    'type': 'str',
                    },
                'src_address_str': {
                    'type': 'str',
                    },
                'port_str': {
                    'type': 'str',
                    },
                'state_str': {
                    'type': 'str',
                    },
                'level_str': {
                    'type': 'str',
                    },
                'current_connections': {
                    'type': 'str',
                    },
                'connection_limit': {
                    'type': 'str',
                    },
                'current_connection_rate': {
                    'type': 'str',
                    },
                'connection_rate_limit': {
                    'type': 'str',
                    },
                'current_packet_rate': {
                    'type': 'str',
                    },
                'packet_rate_limit': {
                    'type': 'str',
                    },
                'current_kBit_rate': {
                    'type': 'str',
                    },
                'kBit_rate_limit': {
                    'type': 'str',
                    },
                'current_frag_packet_rate': {
                    'type': 'str',
                    },
                'frag_packet_rate_limit': {
                    'type': 'str',
                    },
                'current_app_stat1': {
                    'type': 'str',
                    },
                'app_stat1_limit': {
                    'type': 'str',
                    },
                'current_app_stat2': {
                    'type': 'str',
                    },
                'app_stat2_limit': {
                    'type': 'str',
                    },
                'current_app_stat3': {
                    'type': 'str',
                    },
                'app_stat3_limit': {
                    'type': 'str',
                    },
                'current_app_stat4': {
                    'type': 'str',
                    },
                'app_stat4_limit': {
                    'type': 'str',
                    },
                'current_app_stat5': {
                    'type': 'str',
                    },
                'app_stat5_limit': {
                    'type': 'str',
                    },
                'current_app_stat6': {
                    'type': 'str',
                    },
                'app_stat6_limit': {
                    'type': 'str',
                    },
                'current_app_stat7': {
                    'type': 'str',
                    },
                'app_stat7_limit': {
                    'type': 'str',
                    },
                'current_app_stat8': {
                    'type': 'str',
                    },
                'app_stat8_limit': {
                    'type': 'str',
                    },
                'age_str': {
                    'type': 'str',
                    },
                'lockup_time_str': {
                    'type': 'str',
                    },
                'dynamic_entry_count': {
                    'type': 'str',
                    },
                'dynamic_entry_limit': {
                    'type': 'str',
                    },
                'sflow_source_id': {
                    'type': 'str',
                    },
                'debug_str': {
                    'type': 'str',
                    }
                },
            'resource_limit_config': {
                'type': 'str',
                },
            'reource_limit_alloc': {
                'type': 'str',
                },
            'resource_limit_remain': {
                'type': 'str',
                },
            'entry_displayed_count': {
                'type': 'int',
                },
            'service_displayed_count': {
                'type': 'int',
                },
            'reporting_status': {
                'type': 'int',
                },
            'all_ports': {
                'type': 'bool',
                },
            'all_src_ports': {
                'type': 'bool',
                },
            'all_ip_protos': {
                'type': 'bool',
                },
            'port_protocol': {
                'type': 'str',
                },
            'app_stat': {
                'type': 'bool',
                },
            'sflow_source_id': {
                'type': 'bool',
                },
            'resource_usage': {
                'type': 'bool',
                },
            'l4_ext_rate': {
                'type': 'bool',
                },
            'hw_blacklisted': {
                'type': 'str',
                },
            'suffix_request_rate': {
                'type': 'bool',
                },
            'domain_name': {
                'type': 'str',
                },
            'port_range_start': {
                'type': 'int',
                'required': True,
                },
            'port_range_end': {
                'type': 'int',
                'required': True,
                },
            'protocol': {
                'type': 'str',
                'required': True,
                'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4', 'sip-udp', 'sip-tcp']
                },
            'port_ind': {
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
                        'rate': {
                            'type': 'str',
                            },
                        'entry_maximum': {
                            'type': 'str',
                            },
                        'entry_minimum': {
                            'type': 'str',
                            },
                        'entry_non_zero_minimum': {
                            'type': 'str',
                            },
                        'entry_average': {
                            'type': 'str',
                            },
                        'src_maximum': {
                            'type': 'str',
                            }
                        },
                    'detection_data_source': {
                        'type': 'str',
                        }
                    }
                },
            'topk_sources': {
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
                        'sources': {
                            'type': 'list',
                            'address': {
                                'type': 'str',
                                },
                            'rate': {
                                'type': 'str',
                                }
                            }
                        },
                    'next_indicator': {
                        'type': 'int',
                        },
                    'finished': {
                        'type': 'int',
                        },
                    'entry_list': {
                        'type': 'list',
                        'address_str': {
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
                            'max_peak': {
                                'type': 'str',
                                },
                            'psd_wdw_cnt': {
                                'type': 'int',
                                }
                            }
                        },
                    'details': {
                        'type': 'bool',
                        },
                    'top_k_key': {
                        'type': 'str',
                        }
                    }
                },
            'progression_tracking': {
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
                        'num_sample': {
                            'type': 'int',
                            },
                        'average': {
                            'type': 'str',
                            },
                        'maximum': {
                            'type': 'str',
                            },
                        'minimum': {
                            'type': 'str',
                            },
                        'standard_deviation': {
                            'type': 'str',
                            }
                        }
                    }
                },
            'pattern_recognition': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'state': {
                        'type': 'str',
                        },
                    'timestamp': {
                        'type': 'str',
                        },
                    'peace_pkt_count': {
                        'type': 'int',
                        },
                    'war_pkt_count': {
                        'type': 'int',
                        },
                    'war_pkt_percentage': {
                        'type': 'int',
                        },
                    'filter_threshold': {
                        'type': 'int',
                        },
                    'filter_count': {
                        'type': 'int',
                        },
                    'filter_list': {
                        'type': 'list',
                        'processing_unit': {
                            'type': 'str',
                            },
                        'filter_enabled': {
                            'type': 'int',
                            },
                        'hardware_filter': {
                            'type': 'int',
                            },
                        'filter_expr': {
                            'type': 'str',
                            },
                        'filter_desc': {
                            'type': 'str',
                            },
                        'sample_ratio': {
                            'type': 'int',
                            }
                        }
                    }
                },
            'pattern_recognition_pu_details': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'all_filters': {
                        'type': 'list',
                        'processing_unit': {
                            'type': 'str',
                            },
                        'state': {
                            'type': 'str',
                            },
                        'timestamp': {
                            'type': 'str',
                            },
                        'peace_pkt_count': {
                            'type': 'int',
                            },
                        'war_pkt_count': {
                            'type': 'int',
                            },
                        'war_pkt_percentage': {
                            'type': 'int',
                            },
                        'filter_threshold': {
                            'type': 'int',
                            },
                        'filter_count': {
                            'type': 'int',
                            },
                        'filter_list': {
                            'type': 'list',
                            'filter_enabled': {
                                'type': 'int',
                                },
                            'hardware_filter': {
                                'type': 'int',
                                },
                            'filter_expr': {
                                'type': 'str',
                                },
                            'filter_desc': {
                                'type': 'str',
                                },
                            'sample_ratio': {
                                'type': 'int',
                                }
                            }
                        }
                    }
                }
            }
        })
    # Parent keys
    rv.update(dict(entry_dst_entry_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/dst/entry/{entry_dst_entry_name}/port-range/{port_range_start}+{port_range_end}+{protocol}"

    f_dict = {}
    if '/' in str(module.params["port_range_start"]):
        f_dict["port_range_start"] = module.params["port_range_start"].replace("/", "%2F")
    else:
        f_dict["port_range_start"] = module.params["port_range_start"]
    if '/' in str(module.params["port_range_end"]):
        f_dict["port_range_end"] = module.params["port_range_end"].replace("/", "%2F")
    else:
        f_dict["port_range_end"] = module.params["port_range_end"]
    if '/' in str(module.params["protocol"]):
        f_dict["protocol"] = module.params["protocol"].replace("/", "%2F")
    else:
        f_dict["protocol"] = module.params["protocol"]
    if '/' in module.params["entry_dst_entry_name"]:
        f_dict["entry_dst_entry_name"] = module.params["entry_dst_entry_name"].replace("/", "%2F")
    else:
        f_dict["entry_dst_entry_name"] = module.params["entry_dst_entry_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/dst/entry/{entry_dst_entry_name}/port-range/+"

    f_dict = {}
    f_dict["port_range_start"] = ""
    f_dict["port_range_end"] = ""
    f_dict["protocol"] = ""
    f_dict["entry_dst_entry_name"] = module.params["entry_dst_entry_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["port-range"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["port-range"].get(k) != v:
            change_results["changed"] = True
            config_changes["port-range"][k] = v

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
    payload = utils.build_json("port-range", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["port-range"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["port-range-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["port-range"]["oper"] if info != "NotFound" else info
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
