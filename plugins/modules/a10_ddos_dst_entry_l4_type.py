#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_dst_entry_l4_type
description:
    - DDOS L4 type
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
    protocol:
        description:
        - "'tcp'= L4-Type TCP; 'udp'= L4-Type UDP; 'icmp'= L4-Type ICMP; 'other'= L4-Type
          OTHER;"
        type: str
        required: True
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
    deny:
        description:
        - "Blacklist and Drop all incoming packets for protocol"
        type: bool
        required: False
    max_rexmit_syn_per_flow:
        description:
        - "Maximum number of re-transmit SYN per flow"
        type: int
        required: False
    max_rexmit_syn_per_flow_exceed_action:
        description:
        - "'drop'= Drop the packet; 'black-list'= Add the source IP into black list;"
        type: str
        required: False
    disable_syn_auth:
        description:
        - "Disable TCP SYN Authentication"
        type: bool
        required: False
    syn_auth:
        description:
        - "'send-rst'= Send RST to client upon client ACK; 'force-rst-by-ack'= Force
          client RST via the use of ACK; 'force-rst-by-synack'= Force client RST via the
          use of bad SYN|ACK; 'disable'= Disable TCP SYN Authentication;"
        type: str
        required: False
    syn_cookie:
        description:
        - "Enable SYN Cookie"
        type: bool
        required: False
    tcp_reset_client:
        description:
        - "Send reset to client when rate exceeds or session ages out"
        type: bool
        required: False
    tcp_reset_server:
        description:
        - "Send reset to server when rate exceeds or session ages out"
        type: bool
        required: False
    drop_on_no_port_match:
        description:
        - "'disable'= disable; 'enable'= enable;"
        type: str
        required: False
    stateful:
        description:
        - "Enable stateful tracking of sessions (Default is stateless)"
        type: bool
        required: False
    tunnel_decap:
        description:
        - "Field tunnel_decap"
        type: dict
        required: False
        suboptions:
            ip_decap:
                description:
                - "Enable IP Tunnel decapsulation"
                type: bool
            gre_decap:
                description:
                - "Enable GRE Tunnel decapsulation"
                type: bool
            key_cfg:
                description:
                - "Field key_cfg"
                type: list
    tunnel_rate_limit:
        description:
        - "Field tunnel_rate_limit"
        type: dict
        required: False
        suboptions:
            ip_rate_limit:
                description:
                - "Enable inner IP rate limiting on IPinIP traffic"
                type: bool
            gre_rate_limit:
                description:
                - "Enable inner IP rate limiting on GRE traffic"
                type: bool
    drop_frag_pkt:
        description:
        - "Drop fragmented packets"
        type: bool
        required: False
    undefined_port_hit_statistics:
        description:
        - "Field undefined_port_hit_statistics"
        type: dict
        required: False
        suboptions:
            undefined_port_hit_statistics:
                description:
                - "Enable port scanning statistics"
                type: bool
            reset_interval:
                description:
                - "Configure port scanning counter reset interval (minutes), Default 60 mins"
                type: int
    template:
        description:
        - "Field template"
        type: dict
        required: False
        suboptions:
            template_icmp_v4:
                description:
                - "DDOS icmp-v4 template"
                type: str
            template_icmp_v6:
                description:
                - "DDOS icmp-v6 template"
                type: str
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
    topk_sort_key:
        description:
        - "'avg'= window average; 'max-peak'= max peak;"
        type: str
        required: False
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
            undefined_port_hit_stats_wellknown:
                description:
                - "Field undefined_port_hit_stats_wellknown"
                type: list
            undefined_port_hit_stats_non_wellknown:
                description:
                - "Field undefined_port_hit_stats_non_wellknown"
                type: list
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
            undefined_port_hit_statistics:
                description:
                - "Field undefined_port_hit_statistics"
                type: bool
            undefined_stats_port_num:
                description:
                - "Field undefined_stats_port_num"
                type: int
            all_l4_types:
                description:
                - "Field all_l4_types"
                type: bool
            hw_blacklisted:
                description:
                - "Field hw_blacklisted"
                type: str
            protocol:
                description:
                - "'tcp'= L4-Type TCP; 'udp'= L4-Type UDP; 'icmp'= L4-Type ICMP; 'other'= L4-Type
          OTHER;"
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
    "deny", "detection_enable", "disable_syn_auth", "drop_frag_pkt", "drop_on_no_port_match", "enable_top_k", "glid", "glid_exceed_action", "max_rexmit_syn_per_flow", "max_rexmit_syn_per_flow_exceed_action", "oper", "port_ind", "progression_tracking", "protocol", "set_counter_base_val", "stateful", "syn_auth", "syn_cookie", "tcp_reset_client",
    "tcp_reset_server", "template", "topk_num_records", "topk_sort_key", "topk_sources", "tunnel_decap", "tunnel_rate_limit", "undefined_port_hit_statistics", "user_tag", "uuid",
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
        'protocol': {
            'type': 'str',
            'required': True,
            'choices': ['tcp', 'udp', 'icmp', 'other']
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
        'deny': {
            'type': 'bool',
            },
        'max_rexmit_syn_per_flow': {
            'type': 'int',
            },
        'max_rexmit_syn_per_flow_exceed_action': {
            'type': 'str',
            'choices': ['drop', 'black-list']
            },
        'disable_syn_auth': {
            'type': 'bool',
            },
        'syn_auth': {
            'type': 'str',
            'choices': ['send-rst', 'force-rst-by-ack', 'force-rst-by-synack', 'disable']
            },
        'syn_cookie': {
            'type': 'bool',
            },
        'tcp_reset_client': {
            'type': 'bool',
            },
        'tcp_reset_server': {
            'type': 'bool',
            },
        'drop_on_no_port_match': {
            'type': 'str',
            'choices': ['disable', 'enable']
            },
        'stateful': {
            'type': 'bool',
            },
        'tunnel_decap': {
            'type': 'dict',
            'ip_decap': {
                'type': 'bool',
                },
            'gre_decap': {
                'type': 'bool',
                },
            'key_cfg': {
                'type': 'list',
                'key': {
                    'type': 'str',
                    }
                }
            },
        'tunnel_rate_limit': {
            'type': 'dict',
            'ip_rate_limit': {
                'type': 'bool',
                },
            'gre_rate_limit': {
                'type': 'bool',
                }
            },
        'drop_frag_pkt': {
            'type': 'bool',
            },
        'undefined_port_hit_statistics': {
            'type': 'dict',
            'undefined_port_hit_statistics': {
                'type': 'bool',
                },
            'reset_interval': {
                'type': 'int',
                }
            },
        'template': {
            'type': 'dict',
            'template_icmp_v4': {
                'type': 'str',
                },
            'template_icmp_v6': {
                'type': 'str',
                }
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
        'topk_sort_key': {
            'type': 'str',
            'choices': ['avg', 'max-peak']
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
                'dynamic_entry_warn_state': {
                    'type': 'str',
                    },
                'sflow_source_id': {
                    'type': 'str',
                    },
                'debug_str': {
                    'type': 'str',
                    }
                },
            'undefined_port_hit_stats_wellknown': {
                'type': 'list',
                'port': {
                    'type': 'str',
                    },
                'counter': {
                    'type': 'str',
                    }
                },
            'undefined_port_hit_stats_non_wellknown': {
                'type': 'list',
                'port_start': {
                    'type': 'str',
                    },
                'port_end': {
                    'type': 'str',
                    },
                'status': {
                    'type': 'str',
                    }
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
            'undefined_port_hit_statistics': {
                'type': 'bool',
                },
            'undefined_stats_port_num': {
                'type': 'int',
                },
            'all_l4_types': {
                'type': 'bool',
                },
            'hw_blacklisted': {
                'type': 'str',
                },
            'protocol': {
                'type': 'str',
                'required': True,
                'choices': ['tcp', 'udp', 'icmp', 'other']
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
                    'next_indicator': {
                        'type': 'int',
                        },
                    'finished': {
                        'type': 'int',
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
                }
            }
        })
    # Parent keys
    rv.update(dict(entry_dst_entry_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/dst/entry/{entry_dst_entry_name}/l4-type/{protocol}"

    f_dict = {}
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
    url_base = "/axapi/v3/ddos/dst/entry/{entry_dst_entry_name}/l4-type"

    f_dict = {}
    f_dict["protocol"] = ""
    f_dict["entry_dst_entry_name"] = module.params["entry_dst_entry_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["l4-type"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["l4-type"].get(k) != v:
            change_results["changed"] = True
            config_changes["l4-type"][k] = v

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
    payload = utils.build_json("l4-type", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["l4-type"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["l4-type-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["l4-type"]["oper"] if info != "NotFound" else info
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
