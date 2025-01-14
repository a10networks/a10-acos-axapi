#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_zone_template_tcp
description:
    - TCP template Configuration
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
    name:
        description:
        - "Field name"
        type: str
        required: True
    age:
        description:
        - "Session age in minutes"
        type: int
        required: False
    age_second:
        description:
        - "Session age in seconds"
        type: int
        required: False
    age_out_reset_server:
        description:
        - "Send TCP reset to server if aging time has passed"
        type: bool
        required: False
    tcp_half_open_timeout:
        description:
        - "TCP half-open session age in seconds"
        type: int
        required: False
    tcp_half_open_timeout_reset_server:
        description:
        - "Send TCP reset to server if TCP half-open session timeout"
        type: bool
        required: False
    concurrent:
        description:
        - "Enable concurrent port access for non-matching ports (DST support only)"
        type: bool
        required: False
    syn_cookie:
        description:
        - "Enable SYN Cookie"
        type: bool
        required: False
    create_conn_on_syn_only:
        description:
        - "Enable connection establishment on SYN only"
        type: bool
        required: False
    filter_match_type:
        description:
        - "'default'= Stop matching on drop/blacklist action; 'stop-on-first-match'= Stop
          matching on first match;"
        type: str
        required: False
    out_of_seq_cfg:
        description:
        - "Field out_of_seq_cfg"
        type: dict
        required: False
        suboptions:
            out_of_seq:
                description:
                - "Take action if out-of-seq pkts exceed configured threshold"
                type: int
            out_of_seq_action_list_name:
                description:
                - "Configure action-list to take for out-of-seq exceed"
                type: str
            out_of_seq_action:
                description:
                - "'drop'= Drop packets for out-of-seq exceed (Default); 'blacklist-src'= help
          Blacklist-src for out-of-seq exceed; 'ignore'= help Ignore out-of-seq exceed;"
                type: str
    per_conn_out_of_seq_rate_cfg:
        description:
        - "Field per_conn_out_of_seq_rate_cfg"
        type: dict
        required: False
        suboptions:
            per_conn_out_of_seq_rate_limit:
                description:
                - "Take action if out-of-seq pkt rate exceed configured threshold"
                type: int
            per_conn_out_of_seq_rate_action_list_name:
                description:
                - "Configure action-list to take for out-of-seq rate exceed"
                type: str
            per_conn_out_of_seq_rate_action:
                description:
                - "'drop'= Drop packets for out-of-seq rate exceed (Default); 'blacklist-src'=
          help Blacklist-src for out-of-seq rate exceed; 'ignore'= help Ignore out-of-seq
          rate exceed;"
                type: str
    max_rexmit_syn_per_flow_cfg:
        description:
        - "Field max_rexmit_syn_per_flow_cfg"
        type: dict
        required: False
        suboptions:
            max_rexmit_syn_per_flow:
                description:
                - "Maximum number of re-transmit SYN per flow"
                type: int
            max_rexmit_syn_per_flow_action_list_name:
                description:
                - "Configure action-list to take for max-rexmit-syn-per-flow exceed"
                type: str
            max_rexmit_syn_per_flow_action:
                description:
                - "'drop'= Drop SYN packets for max-rexmit-syn-per-flow exceed (Default);
          'blacklist-src'= help Blacklist-src for max-rexmit-syn-per-flow exceed;"
                type: str
    retransmit_cfg:
        description:
        - "Field retransmit_cfg"
        type: dict
        required: False
        suboptions:
            retransmit:
                description:
                - "Take action if retransmit pkts exceed configured threshold"
                type: int
            retransmit_action_list_name:
                description:
                - "Configure action-list to take for retransmit exceed"
                type: str
            retransmit_action:
                description:
                - "'drop'= Drop packets for retrans exceed (Default); 'blacklist-src'= help
          Blacklist-src for retrans exceed; 'ignore'= help Ignore retrans exceed;"
                type: str
    per_conn_retransmit_rate_cfg:
        description:
        - "Field per_conn_retransmit_rate_cfg"
        type: dict
        required: False
        suboptions:
            per_conn_retransmit_rate_limit:
                description:
                - "Take action if retransmit pkt rate exceed configured threshold"
                type: int
            per_conn_retransmit_rate_action_list_name:
                description:
                - "Configure action-list to take for retransmit rate exceed"
                type: str
            per_conn_retransmit_rate_action:
                description:
                - "'drop'= Drop packets for retrans rate exceed (Default); 'blacklist-src'= help
          Blacklist-src for retrans rate exceed; 'ignore'= help Ignore retrans rate
          exceed;"
                type: str
    zero_win_cfg:
        description:
        - "Field zero_win_cfg"
        type: dict
        required: False
        suboptions:
            zero_win:
                description:
                - "Take action if zero window pkts exceed configured threshold"
                type: int
            zero_win_action_list_name:
                description:
                - "Configure action-list to take for zero window exceed"
                type: str
            zero_win_action:
                description:
                - "'drop'= Drop packets for zero-win exceed (Default); 'blacklist-src'= help
          Blacklist-src for zero-win exceed; 'ignore'= Ignore zero-win exceed;"
                type: str
    per_conn_zero_win_rate_cfg:
        description:
        - "Field per_conn_zero_win_rate_cfg"
        type: dict
        required: False
        suboptions:
            per_conn_zero_win_rate_limit:
                description:
                - "Take action if zero window pkt rate exceed configured threshold"
                type: int
            per_conn_zero_win_rate_action_list_name:
                description:
                - "Configure action-list to take for zero window rate exceed"
                type: str
            per_conn_zero_win_rate_action:
                description:
                - "'drop'= Drop packets for zero-win rate exceed (Default); 'blacklist-src'= help
          Blacklist-src for zero-win rate exceed; 'ignore'= Ignore zero-win rate exceed;"
                type: str
    per_conn_pkt_rate_cfg:
        description:
        - "Field per_conn_pkt_rate_cfg"
        type: dict
        required: False
        suboptions:
            per_conn_pkt_rate_limit:
                description:
                - "Packet rate limit per connection per rate-interval"
                type: int
            per_conn_pkt_rate_action_list_name:
                description:
                - "Configure action-list to take for per-conn-pkt-rate exceed"
                type: str
            per_conn_pkt_rate_action:
                description:
                - "'drop'= Drop packets for per-conn-pkt-rate exceed (Default); 'blacklist-src'=
          help Blacklist-src for per-conn-pkt-rate exceed; 'ignore'= Ignore per-conn-pkt-
          rate-exceed;"
                type: str
    per_conn_rate_interval:
        description:
        - "'100ms'= 100ms; '1sec'= 1sec; '10sec'= 10sec;"
        type: str
        required: False
    small_win_cfg:
        description:
        - "Field small_win_cfg"
        type: dict
        required: False
        suboptions:
            small_window:
                description:
                - "Smallest allowed window size"
                type: int
            small_window_threshold:
                description:
                - "Take action if small window pkts exceed configured threshold"
                type: int
            small_window_action_list_name:
                description:
                - "Configure action-list to take for small window exceed"
                type: str
            small_window_action:
                description:
                - "'drop'= Drop packets for small-window exceed (Default); 'blacklist-src'= help
          Blacklist-src for small-window exceed; 'ignore'= Ignore small-window exceed;"
                type: str
    dst:
        description:
        - "Field dst"
        type: dict
        required: False
        suboptions:
            rate_limit:
                description:
                - "Field rate_limit"
                type: dict
    src:
        description:
        - "Field src"
        type: dict
        required: False
        suboptions:
            rate_limit:
                description:
                - "Field rate_limit"
                type: dict
    allow_synack_skip_authentications:
        description:
        - "Allow create sessions on SYNACK without syn-auth and ack-auth (ASYM Mode only)"
        type: bool
        required: False
    synack_rate_limit:
        description:
        - "Config SYNACK rate limit"
        type: int
        required: False
    track_together_with_syn:
        description:
        - "SYNACK will be counted in Dst Syn-rate limit"
        type: bool
        required: False
    allow_syn_otherflags:
        description:
        - "Treat TCP SYN+PSH as a TCP SYN (DST tcp ports support only)"
        type: bool
        required: False
    allow_tcp_tfo:
        description:
        - "Allow TCP Fast Open"
        type: bool
        required: False
    conn_rate_limit_on_syn_only:
        description:
        - "Only count SYN-initiated connections towards connection-rate tracking"
        type: bool
        required: False
    action_on_syn_rto_retry_count:
        description:
        - "Take action if syn-auth RTO-authentication fail over retry time(default=5)"
        type: int
        required: False
    action_on_ack_rto_retry_count:
        description:
        - "Take action if ack-auth RTO-authentication fail over retry time(default=5)"
        type: int
        required: False
    ack_authentication_synack_reset:
        description:
        - "Reset client TCP SYN+ACK for authentication (DST support only)"
        type: bool
        required: False
    known_resp_src_port_cfg:
        description:
        - "Field known_resp_src_port_cfg"
        type: dict
        required: False
        suboptions:
            known_resp_src_port:
                description:
                - "Take action if src-port is less than 1024"
                type: bool
            known_resp_src_port_action_list_name:
                description:
                - "Configure action-list to take for well-known src-port"
                type: str
            known_resp_src_port_action:
                description:
                - "'drop'= Drop packets from well-known src-port(Default); 'blacklist-src'=
          Blacklist-src from well-known src-port; 'ignore'= Ignore well-known src-port;"
                type: str
            exclude_src_resp_port:
                description:
                - "Exclude src port equal to dst port"
                type: bool
    syn_authentication:
        description:
        - "Field syn_authentication"
        type: dict
        required: False
        suboptions:
            syn_auth_type:
                description:
                - "'send-rst'= Send reset to all concurrent client auth attempts after syn cookie
          check pass; 'force-rst-by-ack'= Send client a bad ack after syn cookie check
          pass; 'force-rst-by-synack'= Send client a bad synack after syn cookie check
          pass; 'send-rst-once'= Send RST to one client concurrent auth attempts;
          'hybrid'= Combining force-rst-by-synack and send-rst together;"
                type: str
            syn_auth_timeout:
                description:
                - "syn retransmit timeout in seconds(default timeout= 5 seconds)"
                type: int
            syn_auth_min_delay:
                description:
                - "Minimum delay (in 100ms intervals) between SYN retransmits for retransmit-check
          to pass"
                type: int
            syn_auth_rto:
                description:
                - "Estimate the RTO and apply the exponential back-off for authentication"
                type: bool
            syn_auth_pass_action_list_name:
                description:
                - "Configure action-list to take for passing the authentication"
                type: str
            syn_auth_pass_action:
                description:
                - "'authenticate-src'= authenticate-src (Default);"
                type: str
            syn_auth_fail_action_list_name:
                description:
                - "Configure action-list to take for failing the authentication."
                type: str
            syn_auth_fail_action:
                description:
                - "'drop'= Drop packets (Default); 'blacklist-src'= Blacklist-src; 'reset'= Send
          reset to client (Applicable to retransmit-check only);"
                type: str
    ack_authentication:
        description:
        - "Field ack_authentication"
        type: dict
        required: False
        suboptions:
            ack_auth_timeout:
                description:
                - "ack retransmit timeout in seconds(default timeout= 5 seconds)"
                type: int
            ack_auth_min_delay:
                description:
                - "Minimum delay (in 100ms intervals) between ACK retransmits for retransmit-check
          to pass"
                type: int
            ack_auth_only:
                description:
                - "Apply retransmit-check only once per source address for authentication purpose"
                type: bool
            ack_auth_rto:
                description:
                - "Estimate the RTO and apply the exponential back-off for authentication"
                type: bool
            ack_auth_pass_action_list_name:
                description:
                - "Configure action-list to take for passing the authentication"
                type: str
            ack_auth_pass_action:
                description:
                - "'authenticate-src'= authenticate-src (Default);"
                type: str
            ack_auth_fail_action_list_name:
                description:
                - "Configure action-list to take for failing the authentication."
                type: str
            ack_auth_fail_action:
                description:
                - "'drop'= Drop packets (Default); 'blacklist-src'= Blacklist-src; 'reset'= Send
          reset to client;"
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
    progression_tracking:
        description:
        - "Field progression_tracking"
        type: dict
        required: False
        suboptions:
            progression_tracking_enabled:
                description:
                - "'enable-check'= Enable Progression Tracking Check;"
                type: str
            ignore_TLS_handshake:
                description:
                - "Ignore TLS handshake, support SSL-L4 port only"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            mitigation:
                description:
                - "Field mitigation"
                type: dict
            profiling:
                description:
                - "Field profiling"
                type: dict
    filter_list:
        description:
        - "Field filter_list"
        type: list
        required: False
        suboptions:
            tcp_filter_name:
                description:
                - "Field tcp_filter_name"
                type: str
            tcp_filter_seq:
                description:
                - "Sequence number"
                type: int
            tcp_filter_regex:
                description:
                - "Regex Expression"
                type: str
            tcp_filter_inverse_match:
                description:
                - "Inverse the result of the matching"
                type: bool
            byte_offset_filter:
                description:
                - "Filter using Berkeley Packet Filter syntax"
                type: str
            tcp_filter_action_list_name:
                description:
                - "Configure action-list to take"
                type: str
            tcp_filter_action:
                description:
                - "'drop'= Drop packets (Default); 'ignore'= Take no action; 'blacklist-src'=
          Blacklist-src; 'authenticate-src'= Authenticate-src;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
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
AVAILABLE_PROPERTIES = [
    "ack_authentication", "ack_authentication_synack_reset", "action_on_ack_rto_retry_count", "action_on_syn_rto_retry_count", "age", "age_out_reset_server", "age_second", "allow_syn_otherflags", "allow_synack_skip_authentications", "allow_tcp_tfo", "concurrent", "conn_rate_limit_on_syn_only", "create_conn_on_syn_only", "dst", "filter_list",
    "filter_match_type", "known_resp_src_port_cfg", "max_rexmit_syn_per_flow_cfg", "name", "out_of_seq_cfg", "per_conn_out_of_seq_rate_cfg", "per_conn_pkt_rate_cfg", "per_conn_rate_interval", "per_conn_retransmit_rate_cfg", "per_conn_zero_win_rate_cfg", "progression_tracking", "retransmit_cfg", "small_win_cfg", "src", "syn_authentication",
    "syn_cookie", "synack_rate_limit", "tcp_half_open_timeout", "tcp_half_open_timeout_reset_server", "track_together_with_syn", "user_tag", "uuid", "zero_win_cfg",
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
        'name': {
            'type': 'str',
            'required': True,
            },
        'age': {
            'type': 'int',
            },
        'age_second': {
            'type': 'int',
            },
        'age_out_reset_server': {
            'type': 'bool',
            },
        'tcp_half_open_timeout': {
            'type': 'int',
            },
        'tcp_half_open_timeout_reset_server': {
            'type': 'bool',
            },
        'concurrent': {
            'type': 'bool',
            },
        'syn_cookie': {
            'type': 'bool',
            },
        'create_conn_on_syn_only': {
            'type': 'bool',
            },
        'filter_match_type': {
            'type': 'str',
            'choices': ['default', 'stop-on-first-match']
            },
        'out_of_seq_cfg': {
            'type': 'dict',
            'out_of_seq': {
                'type': 'int',
                },
            'out_of_seq_action_list_name': {
                'type': 'str',
                },
            'out_of_seq_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'ignore']
                }
            },
        'per_conn_out_of_seq_rate_cfg': {
            'type': 'dict',
            'per_conn_out_of_seq_rate_limit': {
                'type': 'int',
                },
            'per_conn_out_of_seq_rate_action_list_name': {
                'type': 'str',
                },
            'per_conn_out_of_seq_rate_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'ignore']
                }
            },
        'max_rexmit_syn_per_flow_cfg': {
            'type': 'dict',
            'max_rexmit_syn_per_flow': {
                'type': 'int',
                },
            'max_rexmit_syn_per_flow_action_list_name': {
                'type': 'str',
                },
            'max_rexmit_syn_per_flow_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src']
                }
            },
        'retransmit_cfg': {
            'type': 'dict',
            'retransmit': {
                'type': 'int',
                },
            'retransmit_action_list_name': {
                'type': 'str',
                },
            'retransmit_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'ignore']
                }
            },
        'per_conn_retransmit_rate_cfg': {
            'type': 'dict',
            'per_conn_retransmit_rate_limit': {
                'type': 'int',
                },
            'per_conn_retransmit_rate_action_list_name': {
                'type': 'str',
                },
            'per_conn_retransmit_rate_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'ignore']
                }
            },
        'zero_win_cfg': {
            'type': 'dict',
            'zero_win': {
                'type': 'int',
                },
            'zero_win_action_list_name': {
                'type': 'str',
                },
            'zero_win_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'ignore']
                }
            },
        'per_conn_zero_win_rate_cfg': {
            'type': 'dict',
            'per_conn_zero_win_rate_limit': {
                'type': 'int',
                },
            'per_conn_zero_win_rate_action_list_name': {
                'type': 'str',
                },
            'per_conn_zero_win_rate_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'ignore']
                }
            },
        'per_conn_pkt_rate_cfg': {
            'type': 'dict',
            'per_conn_pkt_rate_limit': {
                'type': 'int',
                },
            'per_conn_pkt_rate_action_list_name': {
                'type': 'str',
                },
            'per_conn_pkt_rate_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'ignore']
                }
            },
        'per_conn_rate_interval': {
            'type': 'str',
            'choices': ['100ms', '1sec', '10sec']
            },
        'small_win_cfg': {
            'type': 'dict',
            'small_window': {
                'type': 'int',
                },
            'small_window_threshold': {
                'type': 'int',
                },
            'small_window_action_list_name': {
                'type': 'str',
                },
            'small_window_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'ignore']
                }
            },
        'dst': {
            'type': 'dict',
            'rate_limit': {
                'type': 'dict',
                'syn_rate_limit': {
                    'type': 'dict',
                    'dst_syn_rate_limit': {
                        'type': 'int',
                        },
                    'dst_syn_rate_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore']
                        }
                    }
                }
            },
        'src': {
            'type': 'dict',
            'rate_limit': {
                'type': 'dict',
                'syn_rate_limit': {
                    'type': 'dict',
                    'src_syn_rate_limit': {
                        'type': 'int',
                        },
                    'src_syn_rate_action_list_name': {
                        'type': 'str',
                        },
                    'src_syn_rate_action': {
                        'type': 'str',
                        'choices': ['drop', 'blacklist-src', 'ignore']
                        }
                    }
                }
            },
        'allow_synack_skip_authentications': {
            'type': 'bool',
            },
        'synack_rate_limit': {
            'type': 'int',
            },
        'track_together_with_syn': {
            'type': 'bool',
            },
        'allow_syn_otherflags': {
            'type': 'bool',
            },
        'allow_tcp_tfo': {
            'type': 'bool',
            },
        'conn_rate_limit_on_syn_only': {
            'type': 'bool',
            },
        'action_on_syn_rto_retry_count': {
            'type': 'int',
            },
        'action_on_ack_rto_retry_count': {
            'type': 'int',
            },
        'ack_authentication_synack_reset': {
            'type': 'bool',
            },
        'known_resp_src_port_cfg': {
            'type': 'dict',
            'known_resp_src_port': {
                'type': 'bool',
                },
            'known_resp_src_port_action_list_name': {
                'type': 'str',
                },
            'known_resp_src_port_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'ignore']
                },
            'exclude_src_resp_port': {
                'type': 'bool',
                }
            },
        'syn_authentication': {
            'type': 'dict',
            'syn_auth_type': {
                'type': 'str',
                'choices': ['send-rst', 'force-rst-by-ack', 'force-rst-by-synack', 'send-rst-once', 'hybrid']
                },
            'syn_auth_timeout': {
                'type': 'int',
                },
            'syn_auth_min_delay': {
                'type': 'int',
                },
            'syn_auth_rto': {
                'type': 'bool',
                },
            'syn_auth_pass_action_list_name': {
                'type': 'str',
                },
            'syn_auth_pass_action': {
                'type': 'str',
                'choices': ['authenticate-src']
                },
            'syn_auth_fail_action_list_name': {
                'type': 'str',
                },
            'syn_auth_fail_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'reset']
                }
            },
        'ack_authentication': {
            'type': 'dict',
            'ack_auth_timeout': {
                'type': 'int',
                },
            'ack_auth_min_delay': {
                'type': 'int',
                },
            'ack_auth_only': {
                'type': 'bool',
                },
            'ack_auth_rto': {
                'type': 'bool',
                },
            'ack_auth_pass_action_list_name': {
                'type': 'str',
                },
            'ack_auth_pass_action': {
                'type': 'str',
                'choices': ['authenticate-src']
                },
            'ack_auth_fail_action_list_name': {
                'type': 'str',
                },
            'ack_auth_fail_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'reset']
                }
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'progression_tracking': {
            'type': 'dict',
            'progression_tracking_enabled': {
                'type': 'str',
                'choices': ['enable-check']
                },
            'ignore_TLS_handshake': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                },
            'mitigation': {
                'type': 'dict',
                'request_tracking': {
                    'type': 'dict',
                    'progression_tracking_req_enabled': {
                        'type': 'str',
                        'choices': ['enable-check']
                        },
                    'request_response_model': {
                        'type': 'str',
                        'choices': ['enable', 'disable']
                        },
                    'response_length_max': {
                        'type': 'int',
                        },
                    'response_length_min': {
                        'type': 'int',
                        },
                    'request_length_min': {
                        'type': 'int',
                        },
                    'request_length_max': {
                        'type': 'int',
                        },
                    'request_to_response_max_time': {
                        'type': 'int',
                        },
                    'response_to_request_max_time': {
                        'type': 'int',
                        },
                    'first_request_max_time': {
                        'type': 'int',
                        },
                    'progression_tracking_req_action_list_name': {
                        'type': 'str',
                        },
                    'violation': {
                        'type': 'int',
                        },
                    'progression_tracking_req_action': {
                        'type': 'str',
                        'choices': ['drop', 'blacklist-src']
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'connection_tracking': {
                    'type': 'dict',
                    'progression_tracking_conn_enabled': {
                        'type': 'str',
                        'choices': ['enable-check']
                        },
                    'conn_sent_max': {
                        'type': 'int',
                        },
                    'conn_sent_min': {
                        'type': 'int',
                        },
                    'conn_rcvd_max': {
                        'type': 'int',
                        },
                    'conn_rcvd_min': {
                        'type': 'int',
                        },
                    'conn_rcvd_sent_ratio_min': {
                        'type': 'int',
                        },
                    'conn_rcvd_sent_ratio_max': {
                        'type': 'int',
                        },
                    'conn_duration_max': {
                        'type': 'int',
                        },
                    'conn_duration_min': {
                        'type': 'int',
                        },
                    'conn_violation': {
                        'type': 'int',
                        },
                    'progression_tracking_conn_action_list_name': {
                        'type': 'str',
                        },
                    'progression_tracking_conn_action': {
                        'type': 'str',
                        'choices': ['drop', 'blacklist-src']
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'time_window_tracking': {
                    'type': 'dict',
                    'progression_tracking_win_enabled': {
                        'type': 'str',
                        'choices': ['enable-check']
                        },
                    'window_sent_max': {
                        'type': 'int',
                        },
                    'window_sent_min': {
                        'type': 'int',
                        },
                    'window_rcvd_max': {
                        'type': 'int',
                        },
                    'window_rcvd_min': {
                        'type': 'int',
                        },
                    'window_rcvd_sent_ratio_min': {
                        'type': 'int',
                        },
                    'window_rcvd_sent_ratio_max': {
                        'type': 'int',
                        },
                    'window_violation': {
                        'type': 'int',
                        },
                    'progression_tracking_windows_action_list_name': {
                        'type': 'str',
                        },
                    'progression_tracking_windows_action': {
                        'type': 'str',
                        'choices': ['drop', 'blacklist-src']
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'slow_attack': {
                    'type': 'dict',
                    'slow_attack': {
                        'type': 'str',
                        'choices': ['enable-check']
                        },
                    'response_pkt_rate_max': {
                        'type': 'int',
                        },
                    'init_response_max_time': {
                        'type': 'int',
                        },
                    'init_request_max_time': {
                        'type': 'int',
                        },
                    'progression_tracking_slow_action_list_name': {
                        'type': 'str',
                        },
                    'progression_tracking_slow_action': {
                        'type': 'str',
                        'choices': ['drop', 'reset', 'blacklist-src']
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'slow_attacker_identification': {
                        'type': 'dict',
                        'enable_identification': {
                            'type': 'bool',
                            },
                        'active_connection': {
                            'type': 'int',
                            },
                        'bad_connection': {
                            'type': 'int',
                            },
                        'uuid': {
                            'type': 'str',
                            }
                        }
                    }
                },
            'profiling': {
                'type': 'dict',
                'profiling_request_response_model': {
                    'type': 'bool',
                    },
                'profiling_connection_life_model': {
                    'type': 'bool',
                    },
                'profiling_time_window_model': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'filter_list': {
            'type': 'list',
            'tcp_filter_name': {
                'type': 'str',
                'required': True,
                },
            'tcp_filter_seq': {
                'type': 'int',
                },
            'tcp_filter_regex': {
                'type': 'str',
                },
            'tcp_filter_inverse_match': {
                'type': 'bool',
                },
            'byte_offset_filter': {
                'type': 'str',
                },
            'tcp_filter_action_list_name': {
                'type': 'str',
                },
            'tcp_filter_action': {
                'type': 'str',
                'choices': ['drop', 'ignore', 'blacklist-src', 'authenticate-src']
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/zone-template/tcp/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/zone-template/tcp"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["tcp"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["tcp"].get(k) != v:
            change_results["changed"] = True
            config_changes["tcp"][k] = v

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
    payload = utils.build_json("tcp", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["tcp"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["tcp-list"] if info != "NotFound" else info
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
