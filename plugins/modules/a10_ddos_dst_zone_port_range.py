#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_dst_zone_port_range
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
    zone_name:
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
          tcp'= SIP-TCP Port; 'quic'= QUIC Port;"
        type: str
        required: True
    manual_mode_enable:
        description:
        - "Toggle manual mode to use fix templates"
        type: bool
        required: False
    deny:
        description:
        - "Blacklist and Drop all incoming packets for protocol"
        type: bool
        required: False
    glid_cfg:
        description:
        - "Field glid_cfg"
        type: dict
        required: False
        suboptions:
            glid:
                description:
                - "Global limit ID for the whole zone"
                type: str
            glid_action:
                description:
                - "'drop'= Drop packets for glid exceed (Default if default-action-list is not
          configured); 'ignore'= Do nothing for glid exceed;"
                type: str
            action_list:
                description:
                - "Configure action-list to take"
                type: str
            per_addr_glid:
                description:
                - "Global limit ID per address"
                type: str
    stateful:
        description:
        - "Enable stateful tracking of sessions (Default is stateless)"
        type: bool
        required: False
    default_action_list:
        description:
        - "Configure default-action-list"
        type: str
        required: False
    sflow_common:
        description:
        - "Enable all sFlow polling options under this zone port"
        type: bool
        required: False
    sflow_packets:
        description:
        - "Enable sFlow packet-level counter polling"
        type: bool
        required: False
    sflow_tcp:
        description:
        - "Field sflow_tcp"
        type: dict
        required: False
        suboptions:
            sflow_tcp_basic:
                description:
                - "Enable sFlow basic TCP counter polling"
                type: bool
            sflow_tcp_stateful:
                description:
                - "Enable sFlow stateful TCP counter polling"
                type: bool
    sflow_http:
        description:
        - "Enable sFlow HTTP counter polling"
        type: bool
        required: False
    unlimited_dynamic_entry_count:
        description:
        - "No limit for maximum dynamic src entry count"
        type: bool
        required: False
    max_dynamic_entry_count:
        description:
        - "Maximum count for dynamic source zone service entry"
        type: int
        required: False
    dynamic_entry_count_warn_threshold:
        description:
        - "Set threshold percentage of 'max-src-dst-entry' for generating warning logs.
          Including start and end."
        type: int
        required: False
    apply_policy_on_overflow:
        description:
        - "Enable this flag to apply overflow policy when dynamic entry count overflows"
        type: bool
        required: False
    enable_class_list_overflow:
        description:
        - "Apply class-list overflow policy upon exceeding dynamic entry count specified
          under zone port or each class-list"
        type: bool
        required: False
    enable_top_k:
        description:
        - "Enable ddos top-k source IP detection"
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
    enable_top_k_destination:
        description:
        - "Enable ddos top-k destination IP detection"
        type: bool
        required: False
    topk_dst_num_records:
        description:
        - "Maximum number of records to show in topk"
        type: int
        required: False
    topk_dst_sort_key:
        description:
        - "'avg'= window average; 'max-peak'= max peak;"
        type: str
        required: False
    set_counter_base_val:
        description:
        - "Set T2 counter value of current context to specified value"
        type: int
        required: False
    age:
        description:
        - "Idle age for ip entry"
        type: int
        required: False
    outbound_only:
        description:
        - "Only allow outbound traffic"
        type: bool
        required: False
    faster_de_escalation:
        description:
        - "De-escalate faster in standalone mode"
        type: bool
        required: False
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
    ip_filtering_policy:
        description:
        - "Configure IP Filter"
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
    ip_filtering_policy_statistics:
        description:
        - "Field ip_filtering_policy_statistics"
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
            triggered_by:
                description:
                - "'zone-escalation'= Zone escalation trigger pattern recognition; 'packet-rate-
          exceeds'= Packet rate limit exceeds trigger pattern recognition (default);"
                type: str
            capture_traffic:
                description:
                - "'all'= Capture all packets; 'dropped'= Capture dropped packets (default);"
                type: str
            app_payload_offset:
                description:
                - "Set offset of the payload, default 0"
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
    level_list:
        description:
        - "Field level_list"
        type: list
        required: False
        suboptions:
            level_num:
                description:
                - "'0'= Default policy level; '1'= Policy level 1; '2'= Policy level 2; '3'=
          Policy level 3; '4'= Policy level 4;"
                type: str
            src_default_glid:
                description:
                - "Global limit ID"
                type: str
            glid_action:
                description:
                - "'drop'= Drop packets for glid exceed (Default); 'blacklist-src'= Blacklist-src
          for glid exceed; 'ignore'= Do nothing for glid exceed;"
                type: str
            zone_escalation_score:
                description:
                - "Zone activation score of this level"
                type: int
            zone_violation_actions:
                description:
                - "Violation actions apply due to zone escalate from this level"
                type: str
            src_escalation_score:
                description:
                - "Source activation score of this level"
                type: int
            src_violation_actions:
                description:
                - "Violation actions apply due to source escalate from this level"
                type: str
            zone_template:
                description:
                - "Field zone_template"
                type: dict
            close_sessions_for_unauth_sources:
                description:
                - "Close session for unauthenticated sources"
                type: bool
            close_sessions_for_all_sources:
                description:
                - "Close session for all sources"
                type: bool
            clear_sources_upon_deescalation:
                description:
                - "Clear sources upon de-escalation from level 1 to 0 or manual to 0"
                type: bool
            start_pattern_recognition:
                description:
                - "Start pattern recognition from this level"
                type: bool
            apply_extracted_filters:
                description:
                - "Apply extracted filters from this level"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            indicator_list:
                description:
                - "Field indicator_list"
                type: list
    manual_mode_list:
        description:
        - "Field manual_mode_list"
        type: list
        required: False
        suboptions:
            config:
                description:
                - "'configuration'= Manual-mode configuration;"
                type: str
            src_default_glid:
                description:
                - "Global limit ID"
                type: str
            glid_action:
                description:
                - "'drop'= Drop packets for glid exceed (Default); 'blacklist-src'= Blacklist-src
          for glid exceed; 'ignore'= Do nothing for glid exceed;"
                type: str
            zone_template:
                description:
                - "Field zone_template"
                type: dict
            close_sessions_for_unauth_sources:
                description:
                - "Close session for unauthenticated sources"
                type: bool
            close_sessions_for_all_sources:
                description:
                - "Close session for all sources"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
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
    src_based_policy_list:
        description:
        - "Field src_based_policy_list"
        type: list
        required: False
        suboptions:
            src_based_policy_name:
                description:
                - "Specify name of the policy"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            policy_class_list_list:
                description:
                - "Field policy_class_list_list"
                type: list
    dynamic_entry_overflow_policy_list:
        description:
        - "Field dynamic_entry_overflow_policy_list"
        type: list
        required: False
        suboptions:
            dummy_name:
                description:
                - "'configuration'= Configure overflow policy;"
                type: str
            glid:
                description:
                - "Global limit ID"
                type: str
            action:
                description:
                - "'bypass'= Always permit for the Source to bypass all feature & limit checks;
          'deny'= Blacklist incoming packets for service;"
                type: str
            log_enable:
                description:
                - "Enable logging"
                type: bool
            log_periodic:
                description:
                - "Enable log periodic"
                type: bool
            zone_template:
                description:
                - "Field zone_template"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    virtualhosts:
        description:
        - "Field virtualhosts"
        type: dict
        required: False
        suboptions:
            vhosts_config:
                description:
                - "'configuration'= configure virtualhost based mitigation for ssl services;"
                type: str
            source_tracking_all:
                description:
                - "enables creation of source entries for all virtualhosts"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            virtualhost_list:
                description:
                - "Field virtualhost_list"
                type: list
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
            sources:
                description:
                - "Field sources"
                type: bool
            overflow_policy:
                description:
                - "Field overflow_policy"
                type: bool
            sources_all_entries:
                description:
                - "Field sources_all_entries"
                type: bool
            class_list:
                description:
                - "Field class_list"
                type: str
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
            exceeded:
                description:
                - "Field exceeded"
                type: bool
            black_listed:
                description:
                - "Field black_listed"
                type: bool
            white_listed:
                description:
                - "Field white_listed"
                type: bool
            authenticated:
                description:
                - "Field authenticated"
                type: bool
            level:
                description:
                - "Field level"
                type: bool
            app_stat:
                description:
                - "Field app_stat"
                type: bool
            indicators:
                description:
                - "Field indicators"
                type: bool
            indicator_detail:
                description:
                - "Field indicator_detail"
                type: bool
            l4_ext_rate:
                description:
                - "Field l4_ext_rate"
                type: bool
            hw_blacklisted:
                description:
                - "Field hw_blacklisted"
                type: bool
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
          tcp'= SIP-TCP Port; 'quic'= QUIC Port;"
                type: str
            ip_filtering_policy_statistics:
                description:
                - "Field ip_filtering_policy_statistics"
                type: dict
            pattern_recognition:
                description:
                - "Field pattern_recognition"
                type: dict
            pattern_recognition_pu_details:
                description:
                - "Field pattern_recognition_pu_details"
                type: dict
            port_ind:
                description:
                - "Field port_ind"
                type: dict
            topk_sources:
                description:
                - "Field topk_sources"
                type: dict
            topk_destinations:
                description:
                - "Field topk_destinations"
                type: dict
            progression_tracking:
                description:
                - "Field progression_tracking"
                type: dict
            virtualhosts:
                description:
                - "Field virtualhosts"
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
    "age", "apply_policy_on_overflow", "capture_config", "default_action_list", "deny", "dynamic_entry_count_warn_threshold", "dynamic_entry_overflow_policy_list", "enable_class_list_overflow", "enable_top_k", "enable_top_k_destination", "faster_de_escalation", "glid_cfg", "ip_filtering_policy", "ip_filtering_policy_statistics", "level_list",
    "manual_mode_enable", "manual_mode_list", "max_dynamic_entry_count", "oper", "outbound_only", "pattern_recognition", "pattern_recognition_pu_details", "port_ind", "port_range_end", "port_range_start", "progression_tracking", "protocol", "set_counter_base_val", "sflow_common", "sflow_http", "sflow_packets", "sflow_tcp", "src_based_policy_list",
    "stateful", "topk_destinations", "topk_dst_num_records", "topk_dst_sort_key", "topk_num_records", "topk_sort_key", "topk_sources", "unlimited_dynamic_entry_count", "user_tag", "uuid", "virtualhosts",
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
            'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4', 'sip-udp', 'sip-tcp', 'quic']
            },
        'manual_mode_enable': {
            'type': 'bool',
            },
        'deny': {
            'type': 'bool',
            },
        'glid_cfg': {
            'type': 'dict',
            'glid': {
                'type': 'str',
                },
            'glid_action': {
                'type': 'str',
                'choices': ['drop', 'ignore']
                },
            'action_list': {
                'type': 'str',
                },
            'per_addr_glid': {
                'type': 'str',
                }
            },
        'stateful': {
            'type': 'bool',
            },
        'default_action_list': {
            'type': 'str',
            },
        'sflow_common': {
            'type': 'bool',
            },
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
            },
        'unlimited_dynamic_entry_count': {
            'type': 'bool',
            },
        'max_dynamic_entry_count': {
            'type': 'int',
            },
        'dynamic_entry_count_warn_threshold': {
            'type': 'int',
            },
        'apply_policy_on_overflow': {
            'type': 'bool',
            },
        'enable_class_list_overflow': {
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
        'enable_top_k_destination': {
            'type': 'bool',
            },
        'topk_dst_num_records': {
            'type': 'int',
            },
        'topk_dst_sort_key': {
            'type': 'str',
            'choices': ['avg', 'max-peak']
            },
        'set_counter_base_val': {
            'type': 'int',
            },
        'age': {
            'type': 'int',
            },
        'outbound_only': {
            'type': 'bool',
            },
        'faster_de_escalation': {
            'type': 'bool',
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
        'ip_filtering_policy': {
            'type': 'str',
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'ip_filtering_policy_statistics': {
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
            'triggered_by': {
                'type': 'str',
                'choices': ['zone-escalation', 'packet-rate-exceeds']
                },
            'capture_traffic': {
                'type': 'str',
                'choices': ['all', 'dropped']
                },
            'app_payload_offset': {
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
        'level_list': {
            'type': 'list',
            'level_num': {
                'type': 'str',
                'required': True,
                'choices': ['0', '1', '2', '3', '4']
                },
            'src_default_glid': {
                'type': 'str',
                },
            'glid_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'ignore']
                },
            'zone_escalation_score': {
                'type': 'int',
                },
            'zone_violation_actions': {
                'type': 'str',
                },
            'src_escalation_score': {
                'type': 'int',
                },
            'src_violation_actions': {
                'type': 'str',
                },
            'zone_template': {
                'type': 'dict',
                'quic': {
                    'type': 'str',
                    },
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
                    },
                'encap': {
                    'type': 'str',
                    }
                },
            'close_sessions_for_unauth_sources': {
                'type': 'bool',
                },
            'close_sessions_for_all_sources': {
                'type': 'bool',
                },
            'clear_sources_upon_deescalation': {
                'type': 'bool',
                },
            'start_pattern_recognition': {
                'type': 'bool',
                },
            'apply_extracted_filters': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'indicator_list': {
                'type': 'list',
                'ntype': {
                    'type': 'str',
                    'required': True,
                    'choices': ['pkt-rate', 'pkt-drop-rate', 'bit-rate', 'pkt-drop-ratio', 'bytes-to-bytes-from-ratio', 'concurrent-conns', 'conn-miss-rate', 'syn-rate', 'fin-rate', 'rst-rate', 'small-window-ack-rate', 'empty-ack-rate', 'small-payload-rate', 'syn-fin-ratio', 'cpu-utilization', 'interface-utilization', 'learnt-sources']
                    },
                'tcp_window_size': {
                    'type': 'int',
                    },
                'data_packet_size': {
                    'type': 'int',
                    },
                'score': {
                    'type': 'int',
                    },
                'src_threshold_num': {
                    'type': 'int',
                    },
                'src_threshold_large_num': {
                    'type': 'int',
                    },
                'src_threshold_str': {
                    'type': 'str',
                    },
                'src_violation_actions': {
                    'type': 'str',
                    },
                'zone_threshold_num': {
                    'type': 'int',
                    },
                'zone_threshold_large_num': {
                    'type': 'int',
                    },
                'zone_threshold_str': {
                    'type': 'str',
                    },
                'zone_violation_actions': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    }
                }
            },
        'manual_mode_list': {
            'type': 'list',
            'config': {
                'type': 'str',
                'required': True,
                'choices': ['configuration']
                },
            'src_default_glid': {
                'type': 'str',
                },
            'glid_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'ignore']
                },
            'zone_template': {
                'type': 'dict',
                'quic': {
                    'type': 'str',
                    },
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
                    },
                'encap': {
                    'type': 'str',
                    }
                },
            'close_sessions_for_unauth_sources': {
                'type': 'bool',
                },
            'close_sessions_for_all_sources': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
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
                        'all', 'ip-proto-type', 'ddet_ind_pkt_rate_current', 'ddet_ind_pkt_rate_min', 'ddet_ind_pkt_rate_max', 'ddet_ind_pkt_rate_adaptive_threshold', 'ddet_ind_pkt_drop_rate_current', 'ddet_ind_pkt_drop_rate_min', 'ddet_ind_pkt_drop_rate_max', 'ddet_ind_pkt_drop_rate_adaptive_threshold', 'ddet_ind_syn_rate_current',
                        'ddet_ind_syn_rate_min', 'ddet_ind_syn_rate_max', 'ddet_ind_syn_rate_adaptive_threshold', 'ddet_ind_fin_rate_current', 'ddet_ind_fin_rate_min', 'ddet_ind_fin_rate_max', 'ddet_ind_fin_rate_adaptive_threshold', 'ddet_ind_rst_rate_current', 'ddet_ind_rst_rate_min', 'ddet_ind_rst_rate_max',
                        'ddet_ind_rst_rate_adaptive_threshold', 'ddet_ind_small_window_ack_rate_current', 'ddet_ind_small_window_ack_rate_min', 'ddet_ind_small_window_ack_rate_max', 'ddet_ind_small_window_ack_rate_adaptive_threshold', 'ddet_ind_empty_ack_rate_current', 'ddet_ind_empty_ack_rate_min', 'ddet_ind_empty_ack_rate_max',
                        'ddet_ind_empty_ack_rate_adaptive_threshold', 'ddet_ind_small_payload_rate_current', 'ddet_ind_small_payload_rate_min', 'ddet_ind_small_payload_rate_max', 'ddet_ind_small_payload_rate_adaptive_threshold', 'ddet_ind_pkt_drop_ratio_current', 'ddet_ind_pkt_drop_ratio_min', 'ddet_ind_pkt_drop_ratio_max',
                        'ddet_ind_pkt_drop_ratio_adaptive_threshold', 'ddet_ind_inb_per_outb_current', 'ddet_ind_inb_per_outb_min', 'ddet_ind_inb_per_outb_max', 'ddet_ind_inb_per_outb_adaptive_threshold', 'ddet_ind_syn_per_fin_rate_current', 'ddet_ind_syn_per_fin_rate_min', 'ddet_ind_syn_per_fin_rate_max',
                        'ddet_ind_syn_per_fin_rate_adaptive_threshold', 'ddet_ind_conn_miss_rate_current', 'ddet_ind_conn_miss_rate_min', 'ddet_ind_conn_miss_rate_max', 'ddet_ind_conn_miss_rate_adaptive_threshold', 'ddet_ind_concurrent_conns_current', 'ddet_ind_concurrent_conns_min', 'ddet_ind_concurrent_conns_max',
                        'ddet_ind_concurrent_conns_adaptive_threshold', 'ddet_ind_data_cpu_util_current', 'ddet_ind_data_cpu_util_min', 'ddet_ind_data_cpu_util_max', 'ddet_ind_data_cpu_util_adaptive_threshold', 'ddet_ind_outside_intf_util_current', 'ddet_ind_outside_intf_util_min', 'ddet_ind_outside_intf_util_max',
                        'ddet_ind_outside_intf_util_adaptive_threshold', 'ddet_ind_frag_rate_current', 'ddet_ind_frag_rate_min', 'ddet_ind_frag_rate_max', 'ddet_ind_frag_rate_adaptive_threshold', 'ddet_ind_bit_rate_current', 'ddet_ind_bit_rate_min', 'ddet_ind_bit_rate_max', 'ddet_ind_bit_rate_adaptive_threshold', 'ddet_ind_total_szp_current',
                        'ddet_ind_total_szp_min', 'ddet_ind_total_szp_max', 'ddet_ind_total_szp_adaptive_threshold'
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
        'topk_destinations': {
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
        'src_based_policy_list': {
            'type': 'list',
            'src_based_policy_name': {
                'type': 'str',
                'required': True,
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'policy_class_list_list': {
                'type': 'list',
                'class_list_name': {
                    'type': 'str',
                    'required': True,
                    },
                'glid': {
                    'type': 'str',
                    },
                'glid_action': {
                    'type': 'str',
                    'choices': ['drop', 'blacklist-src', 'ignore']
                    },
                'action': {
                    'type': 'str',
                    'choices': ['bypass', 'deny']
                    },
                'max_dynamic_entry_count': {
                    'type': 'int',
                    },
                'dynamic_entry_count_warn_threshold': {
                    'type': 'int',
                    },
                'zone_template': {
                    'type': 'dict',
                    'quic': {
                        'type': 'str',
                        },
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
                        },
                    'encap': {
                        'type': 'str',
                        },
                    'logging': {
                        'type': 'str',
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
                        'choices': ['all', 'packet_received', 'packet_dropped', 'entry_learned', 'entry_count_overflow']
                        }
                    },
                'class_list_overflow_policy_list': {
                    'type': 'list',
                    'dummy_name': {
                        'type': 'str',
                        'required': True,
                        'choices': ['configuration']
                        },
                    'glid': {
                        'type': 'str',
                        },
                    'action': {
                        'type': 'str',
                        'choices': ['bypass', 'deny']
                        },
                    'log_enable': {
                        'type': 'bool',
                        },
                    'log_periodic': {
                        'type': 'bool',
                        },
                    'zone_template': {
                        'type': 'dict',
                        'quic': {
                            'type': 'str',
                            },
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
                            },
                        'encap': {
                            'type': 'str',
                            },
                        'logging': {
                            'type': 'str',
                            }
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        }
                    }
                }
            },
        'dynamic_entry_overflow_policy_list': {
            'type': 'list',
            'dummy_name': {
                'type': 'str',
                'required': True,
                'choices': ['configuration']
                },
            'glid': {
                'type': 'str',
                },
            'action': {
                'type': 'str',
                'choices': ['bypass', 'deny']
                },
            'log_enable': {
                'type': 'bool',
                },
            'log_periodic': {
                'type': 'bool',
                },
            'zone_template': {
                'type': 'dict',
                'quic': {
                    'type': 'str',
                    },
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
                    },
                'encap': {
                    'type': 'str',
                    },
                'logging': {
                    'type': 'str',
                    }
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            },
        'virtualhosts': {
            'type': 'dict',
            'vhosts_config': {
                'type': 'str',
                'choices': ['configuration']
                },
            'source_tracking_all': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                },
            'virtualhost_list': {
                'type': 'list',
                'vhost': {
                    'type': 'str',
                    'required': True,
                    },
                'servername': {
                    'type': 'list',
                    'match_type': {
                        'type': 'str',
                        'choices': ['contains', 'ends-with', 'equals', 'starts-with']
                        },
                    'host_match_string': {
                        'type': 'str',
                        }
                    },
                'servername_list': {
                    'type': 'str',
                    },
                'servername_match_any': {
                    'type': 'bool',
                    },
                'source_tracking': {
                    'type': 'str',
                    'choices': ['follow', 'enable', 'disable']
                    },
                'glid_cfg': {
                    'type': 'dict',
                    'glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore']
                        }
                    },
                'deny': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'level_list': {
                    'type': 'list',
                    'level_num': {
                        'type': 'str',
                        'required': True,
                        'choices': ['0']
                        },
                    'src_default_glid': {
                        'type': 'str',
                        },
                    'glid_action': {
                        'type': 'str',
                        'choices': ['drop', 'blacklist-src', 'ignore']
                        },
                    'zone_template': {
                        'type': 'dict',
                        'tcp': {
                            'type': 'str',
                            }
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        }
                    }
                }
            },
        'oper': {
            'type': 'dict',
            'ddos_entry_list': {
                'type': 'list',
                'dst_address_str': {
                    'type': 'str',
                    },
                'bw_state': {
                    'type': 'str',
                    },
                'is_auth_passed': {
                    'type': 'str',
                    },
                'level': {
                    'type': 'int',
                    },
                'bl_reasoning_rcode': {
                    'type': 'str',
                    },
                'bl_reasoning_timestamp': {
                    'type': 'str',
                    },
                'current_connections': {
                    'type': 'str',
                    },
                'is_connections_exceed': {
                    'type': 'int',
                    },
                'connection_limit': {
                    'type': 'str',
                    },
                'current_connection_rate': {
                    'type': 'str',
                    },
                'is_connection_rate_exceed': {
                    'type': 'int',
                    },
                'connection_rate_limit': {
                    'type': 'str',
                    },
                'current_packet_rate': {
                    'type': 'str',
                    },
                'is_packet_rate_exceed': {
                    'type': 'int',
                    },
                'packet_rate_limit': {
                    'type': 'str',
                    },
                'current_kBit_rate': {
                    'type': 'str',
                    },
                'is_kBit_rate_exceed': {
                    'type': 'int',
                    },
                'kBit_rate_limit': {
                    'type': 'str',
                    },
                'current_frag_packet_rate': {
                    'type': 'str',
                    },
                'is_frag_packet_rate_exceed': {
                    'type': 'int',
                    },
                'frag_packet_rate_limit': {
                    'type': 'str',
                    },
                'current_app_stat1': {
                    'type': 'str',
                    },
                'is_app_stat1_exceed': {
                    'type': 'int',
                    },
                'app_stat1_limit': {
                    'type': 'str',
                    },
                'current_app_stat2': {
                    'type': 'str',
                    },
                'is_app_stat2_exceed': {
                    'type': 'int',
                    },
                'app_stat2_limit': {
                    'type': 'str',
                    },
                'current_app_stat3': {
                    'type': 'str',
                    },
                'is_app_stat3_exceed': {
                    'type': 'int',
                    },
                'app_stat3_limit': {
                    'type': 'str',
                    },
                'current_app_stat4': {
                    'type': 'str',
                    },
                'is_app_stat4_exceed': {
                    'type': 'int',
                    },
                'app_stat4_limit': {
                    'type': 'str',
                    },
                'current_app_stat5': {
                    'type': 'str',
                    },
                'is_app_stat5_exceed': {
                    'type': 'int',
                    },
                'app_stat5_limit': {
                    'type': 'str',
                    },
                'current_app_stat6': {
                    'type': 'str',
                    },
                'is_app_stat6_exceed': {
                    'type': 'int',
                    },
                'app_stat6_limit': {
                    'type': 'str',
                    },
                'current_app_stat7': {
                    'type': 'str',
                    },
                'is_app_stat7_exceed': {
                    'type': 'int',
                    },
                'app_stat7_limit': {
                    'type': 'str',
                    },
                'current_app_stat8': {
                    'type': 'str',
                    },
                'is_app_stat8_exceed': {
                    'type': 'int',
                    },
                'app_stat8_limit': {
                    'type': 'str',
                    },
                'age': {
                    'type': 'int',
                    },
                'lockup_time': {
                    'type': 'int',
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
                    'type': 'int',
                    },
                'http_filter_rates': {
                    'type': 'list',
                    'http_filter_rate_name': {
                        'type': 'str',
                        },
                    'is_http_filter_rate_limit_exceed': {
                        'type': 'int',
                        },
                    'current_http_filter_rate': {
                        'type': 'str',
                        },
                    'http_filter_rate_limit': {
                        'type': 'str',
                        }
                    },
                'response_size_rates': {
                    'type': 'list',
                    'response_size_rate_name': {
                        'type': 'str',
                        },
                    'is_response_size_rate_limit_exceed': {
                        'type': 'int',
                        },
                    'current_response_size_rate': {
                        'type': 'str',
                        },
                    'response_size_rate_limit': {
                        'type': 'str',
                        }
                    },
                'debug_str': {
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
            'sources': {
                'type': 'bool',
                },
            'overflow_policy': {
                'type': 'bool',
                },
            'sources_all_entries': {
                'type': 'bool',
                },
            'class_list': {
                'type': 'str',
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
            'exceeded': {
                'type': 'bool',
                },
            'black_listed': {
                'type': 'bool',
                },
            'white_listed': {
                'type': 'bool',
                },
            'authenticated': {
                'type': 'bool',
                },
            'level': {
                'type': 'bool',
                },
            'app_stat': {
                'type': 'bool',
                },
            'indicators': {
                'type': 'bool',
                },
            'indicator_detail': {
                'type': 'bool',
                },
            'l4_ext_rate': {
                'type': 'bool',
                },
            'hw_blacklisted': {
                'type': 'bool',
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
                'choices': ['dns-tcp', 'dns-udp', 'http', 'tcp', 'udp', 'ssl-l4', 'sip-udp', 'sip-tcp', 'quic']
                },
            'ip_filtering_policy_statistics': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'rule_list': {
                        'type': 'list',
                        'seq': {
                            'type': 'int',
                            },
                        'hits': {
                            'type': 'int',
                            },
                        'blacklisted_src_count': {
                            'type': 'int',
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
                },
            'port_ind': {
                'type': 'dict',
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
                        },
                    'learning_details': {
                        'type': 'bool',
                        },
                    'learning_brief': {
                        'type': 'bool',
                        },
                    'recommended_template': {
                        'type': 'bool',
                        },
                    'template_debug_table': {
                        'type': 'bool',
                        }
                    }
                },
            'virtualhosts': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    },
                'virtualhost_list': {
                    'type': 'list',
                    'vhost': {
                        'type': 'str',
                        'required': True,
                        },
                    'oper': {
                        'type': 'dict',
                        'ddos_entry_list': {
                            'type': 'list',
                            'dst_address_str': {
                                'type': 'str',
                                },
                            'bw_state': {
                                'type': 'str',
                                },
                            'is_auth_passed': {
                                'type': 'str',
                                },
                            'level': {
                                'type': 'int',
                                },
                            'bl_reasoning_rcode': {
                                'type': 'str',
                                },
                            'bl_reasoning_timestamp': {
                                'type': 'str',
                                },
                            'current_connections': {
                                'type': 'str',
                                },
                            'is_connections_exceed': {
                                'type': 'int',
                                },
                            'connection_limit': {
                                'type': 'str',
                                },
                            'current_connection_rate': {
                                'type': 'str',
                                },
                            'is_connection_rate_exceed': {
                                'type': 'int',
                                },
                            'connection_rate_limit': {
                                'type': 'str',
                                },
                            'current_packet_rate': {
                                'type': 'str',
                                },
                            'is_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'packet_rate_limit': {
                                'type': 'str',
                                },
                            'current_kBit_rate': {
                                'type': 'str',
                                },
                            'is_kBit_rate_exceed': {
                                'type': 'int',
                                },
                            'kBit_rate_limit': {
                                'type': 'str',
                                },
                            'current_frag_packet_rate': {
                                'type': 'str',
                                },
                            'is_frag_packet_rate_exceed': {
                                'type': 'int',
                                },
                            'frag_packet_rate_limit': {
                                'type': 'str',
                                },
                            'current_app_stat1': {
                                'type': 'str',
                                },
                            'is_app_stat1_exceed': {
                                'type': 'int',
                                },
                            'app_stat1_limit': {
                                'type': 'str',
                                },
                            'current_app_stat2': {
                                'type': 'str',
                                },
                            'is_app_stat2_exceed': {
                                'type': 'int',
                                },
                            'app_stat2_limit': {
                                'type': 'str',
                                },
                            'current_app_stat3': {
                                'type': 'str',
                                },
                            'is_app_stat3_exceed': {
                                'type': 'int',
                                },
                            'app_stat3_limit': {
                                'type': 'str',
                                },
                            'current_app_stat4': {
                                'type': 'str',
                                },
                            'is_app_stat4_exceed': {
                                'type': 'int',
                                },
                            'app_stat4_limit': {
                                'type': 'str',
                                },
                            'current_app_stat5': {
                                'type': 'str',
                                },
                            'is_app_stat5_exceed': {
                                'type': 'int',
                                },
                            'app_stat5_limit': {
                                'type': 'str',
                                },
                            'current_app_stat6': {
                                'type': 'str',
                                },
                            'is_app_stat6_exceed': {
                                'type': 'int',
                                },
                            'app_stat6_limit': {
                                'type': 'str',
                                },
                            'current_app_stat7': {
                                'type': 'str',
                                },
                            'is_app_stat7_exceed': {
                                'type': 'int',
                                },
                            'app_stat7_limit': {
                                'type': 'str',
                                },
                            'current_app_stat8': {
                                'type': 'str',
                                },
                            'is_app_stat8_exceed': {
                                'type': 'int',
                                },
                            'app_stat8_limit': {
                                'type': 'str',
                                },
                            'age': {
                                'type': 'int',
                                },
                            'lockup_time': {
                                'type': 'int',
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
                                'type': 'int',
                                },
                            'http_filter_rates': {
                                'type': 'list',
                                'http_filter_rate_name': {
                                    'type': 'str',
                                    },
                                'is_http_filter_rate_limit_exceed': {
                                    'type': 'int',
                                    },
                                'current_http_filter_rate': {
                                    'type': 'str',
                                    },
                                'http_filter_rate_limit': {
                                    'type': 'str',
                                    }
                                },
                            'response_size_rates': {
                                'type': 'list',
                                'response_size_rate_name': {
                                    'type': 'str',
                                    },
                                'is_response_size_rate_limit_exceed': {
                                    'type': 'int',
                                    },
                                'current_response_size_rate': {
                                    'type': 'str',
                                    },
                                'response_size_rate_limit': {
                                    'type': 'str',
                                    }
                                },
                            'debug_str': {
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
                        'sources': {
                            'type': 'bool',
                            },
                        'overflow_policy': {
                            'type': 'bool',
                            },
                        'sources_all_entries': {
                            'type': 'bool',
                            },
                        'class_list': {
                            'type': 'str',
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
                        'exceeded': {
                            'type': 'bool',
                            },
                        'black_listed': {
                            'type': 'bool',
                            },
                        'white_listed': {
                            'type': 'bool',
                            },
                        'authenticated': {
                            'type': 'bool',
                            },
                        'level': {
                            'type': 'bool',
                            },
                        'app_stat': {
                            'type': 'bool',
                            },
                        'indicators': {
                            'type': 'bool',
                            },
                        'indicator_detail': {
                            'type': 'bool',
                            },
                        'l4_ext_rate': {
                            'type': 'bool',
                            },
                        'hw_blacklisted': {
                            'type': 'bool',
                            },
                        'suffix_request_rate': {
                            'type': 'bool',
                            },
                        'domain_name': {
                            'type': 'str',
                            }
                        }
                    }
                }
            }
        })
    # Parent keys
    rv.update(dict(zone_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/dst/zone/{zone_name}/port-range/{port_range_start}+{port_range_end}+{protocol}"

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
    if '/' in module.params["zone_name"]:
        f_dict["zone_name"] = module.params["zone_name"].replace("/", "%2F")
    else:
        f_dict["zone_name"] = module.params["zone_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/dst/zone/{zone_name}/port-range/+"

    f_dict = {}
    f_dict["port_range_start"] = ""
    f_dict["port_range_end"] = ""
    f_dict["protocol"] = ""
    f_dict["zone_name"] = module.params["zone_name"]

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
