#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_template_tcp
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
    action_cfg:
        description:
        - "Field action_cfg"
        type: dict
        required: False
        suboptions:
            action_on_ack:
                description:
                - "Monitor tcp ack for age-out session"
                type: bool
            reset:
                description:
                - "Send RST to client"
                type: bool
            timeout:
                description:
                - "ACK retry timeout in sec"
                type: int
            min_retry_gap:
                description:
                - "Min gap between 2 ACKs for action-on-ack pass in 100ms interval"
                type: int
            authenticate_only:
                description:
                - "Apply action-on-ack once per source address for authentication purpose"
                type: bool
            rto_authentication:
                description:
                - "Estimate the RTO and apply the exponential back-off for authentication"
                type: bool
    action_on_syn_rto_retry_count:
        description:
        - "Take action if action-on-syn RTO-authentication fail over retry time(default=5)"
        type: int
        required: False
    action_on_ack_rto_retry_count:
        description:
        - "Take action if action-on-ack RTO-authentication fail over retry time(default=5)"
        type: int
        required: False
    age:
        description:
        - "Session age in minutes"
        type: int
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
    black_list_out_of_seq:
        description:
        - "Black list Src IP if out of seq pkts exceed configured threshold"
        type: int
        required: False
    black_list_retransmit:
        description:
        - "Black list Src IP if retransmit pkts exceed configured threshold"
        type: int
        required: False
    black_list_zero_win:
        description:
        - "Black list Src IP if zero window pkts exceed configured threshold"
        type: int
        required: False
    syn_auth:
        description:
        - "'send-rst'= Send RST to client upon client ACK; 'force-rst-by-ack'= Force
          client RST via the use of ACK; 'force-rst-by-synack'= Force client RST via the
          use of bad SYN|ACK; 'disable'= Disable TCP SYN Authentication;"
        type: str
        required: False
    conn_rate_limit_on_syn_only:
        description:
        - "Only count SYN-initiated connections towards connection-rate tracking"
        type: bool
        required: False
    per_conn_rate_interval:
        description:
        - "'100ms'= 100ms; '1sec'= 1sec; '10sec'= 10sec;"
        type: str
        required: False
    per_conn_pkt_rate_limit:
        description:
        - "Packet rate limit per connection per rate-interval"
        type: int
        required: False
    per_conn_pkt_rate_action:
        description:
        - "'drop'= Drop packets for per-conn-pkt-rate exceed (Default); 'blacklist-src'=
          help Blacklist-src for per-conn-pkt-rate exceed; 'ignore'= Ignore per-conn-pkt-
          rate-exceed;"
        type: str
        required: False
    per_conn_out_of_seq_rate_limit:
        description:
        - "Take action if out-of-seq pkt rate exceed configured threshold"
        type: int
        required: False
    per_conn_out_of_seq_rate_action:
        description:
        - "'drop'= Drop packets for out-of-seq rate exceed (Default); 'blacklist-src'=
          help Blacklist-src for out-of-seq rate exceed; 'ignore'= help Ignore out-of-seq
          rate exceed;"
        type: str
        required: False
    per_conn_retransmit_rate_limit:
        description:
        - "Take action if retransmit pkt rate exceed configured threshold"
        type: int
        required: False
    per_conn_retransmit_rate_action:
        description:
        - "'drop'= Drop packets for retransmit rate exceed (Default); 'blacklist-src'=
          help Blacklist-src for retransmit rate exceed; 'ignore'= help Ignore retransmit
          rate exceed;"
        type: str
        required: False
    per_conn_zero_win_rate_limit:
        description:
        - "Take action if zero window pkt rate exceed configured threshold"
        type: int
        required: False
    per_conn_zero_win_rate_action:
        description:
        - "'drop'= Drop packets for zero-win rate exceed (Default); 'blacklist-src'= help
          Blacklist-src for zero-win rate exceed; 'ignore'= help Ignore zero-win rate
          exceed;"
        type: str
        required: False
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
    action_syn_cfg:
        description:
        - "Field action_syn_cfg"
        type: dict
        required: False
        suboptions:
            action_on_syn:
                description:
                - "Monitor tcp syn for age-out session"
                type: bool
            action_on_syn_reset:
                description:
                - "Send RST to client"
                type: bool
            action_on_syn_timeout:
                description:
                - "SYN retry timeout in sec"
                type: int
            action_on_syn_gap:
                description:
                - "Min gap between 2 SYNs for action-on-syn pass in 100ms interval"
                type: int
            action_on_syn_rto:
                description:
                - "Estimate the RTO and apply the exponential back-off for authentication"
                type: bool
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
    ack_authentication_synack_reset:
        description:
        - "Enable Reset client TCP SYN+ACK for authentication (DST support only)"
        type: bool
        required: False
    drop_known_resp_src_port_cfg:
        description:
        - "Field drop_known_resp_src_port_cfg"
        type: dict
        required: False
        suboptions:
            drop_known_resp_src_port:
                description:
                - "Drop well-known if src-port is less than 1024"
                type: bool
            exclude_src_resp_port:
                description:
                - "excluding src port equal destination port"
                type: bool
    tunnel_encap:
        description:
        - "Field tunnel_encap"
        type: dict
        required: False
        suboptions:
            ip_cfg:
                description:
                - "Field ip_cfg"
                type: dict
            gre_cfg:
                description:
                - "Field gre_cfg"
                type: dict
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
            request_response_model:
                description:
                - "'enable'= Enable Request Response Model; 'disable'= Disable Request Response
          Model;"
                type: str
            violation:
                description:
                - "Set the violation threshold"
                type: int
            response_length_max:
                description:
                - "Set the maximum response length"
                type: int
            request_length_min:
                description:
                - "Set the minimum request length"
                type: int
            request_length_max:
                description:
                - "Set the maximum request length"
                type: int
            response_request_min_ratio:
                description:
                - "Set the minimum response to request ratio (in unit of 0.1% [1=1000])"
                type: int
            response_request_max_ratio:
                description:
                - "Set the maximum response to request ratio (in unit of 0.1% [1=1000])"
                type: int
            first_request_max_time:
                description:
                - "Set the maximum wait time from connection creation until the first data is
          transmitted over the connection (100 ms)"
                type: int
            request_to_response_max_time:
                description:
                - "Set the maximum request to response time (100 ms)"
                type: int
            response_to_request_max_time:
                description:
                - "Set the maximum response to request time (100 ms)"
                type: int
            profiling_request_response_model:
                description:
                - "Enable auto-config progression tracking learning for request response model"
                type: bool
            profiling_connection_life_model:
                description:
                - "Enable auto-config progression tracking learning for connection model"
                type: bool
            profiling_time_window_model:
                description:
                - "Enable auto-config progression tracking learning for time window model"
                type: bool
            progression_tracking_action_list_name:
                description:
                - "Configure action-list to take when progression tracking violation exceed"
                type: str
            progression_tracking_action:
                description:
                - "'drop'= Drop packets for progression tracking violation exceed (Default);
          'blacklist-src'= Blacklist-src for progression tracking violation exceed;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            connection_tracking:
                description:
                - "Field connection_tracking"
                type: dict
            time_window_tracking:
                description:
                - "Field time_window_tracking"
                type: dict
    filter_list:
        description:
        - "Field filter_list"
        type: list
        required: False
        suboptions:
            tcp_filter_seq:
                description:
                - "Sequence number"
                type: int
            tcp_filter_regex:
                description:
                - "Regex Expression"
                type: str
            byte_offset_filter:
                description:
                - "Filter Expression using Berkeley Packet Filter syntax"
                type: str
            tcp_filter_unmatched:
                description:
                - "action taken when it does not match"
                type: bool
            tcp_filter_action:
                description:
                - "'blacklist-src'= Also blacklist the source when action is taken; 'whitelist-
          src'= Whitelist the source after filter passes, packets are dropped until then;
          'count-only'= Take no action and continue processing the next filter;"
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
    "ack_authentication_synack_reset", "action_cfg", "action_on_ack_rto_retry_count", "action_on_syn_rto_retry_count", "action_syn_cfg", "age", "allow_syn_otherflags", "allow_synack_skip_authentications", "allow_tcp_tfo", "black_list_out_of_seq", "black_list_retransmit", "black_list_zero_win", "conn_rate_limit_on_syn_only",
    "create_conn_on_syn_only", "drop_known_resp_src_port_cfg", "dst", "filter_list", "name", "per_conn_out_of_seq_rate_action", "per_conn_out_of_seq_rate_limit", "per_conn_pkt_rate_action", "per_conn_pkt_rate_limit", "per_conn_rate_interval", "per_conn_retransmit_rate_action", "per_conn_retransmit_rate_limit", "per_conn_zero_win_rate_action",
    "per_conn_zero_win_rate_limit", "progression_tracking", "src", "syn_auth", "syn_cookie", "synack_rate_limit", "track_together_with_syn", "tunnel_encap", "user_tag", "uuid",
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
        'action_cfg': {
            'type': 'dict',
            'action_on_ack': {
                'type': 'bool',
                },
            'reset': {
                'type': 'bool',
                },
            'timeout': {
                'type': 'int',
                },
            'min_retry_gap': {
                'type': 'int',
                },
            'authenticate_only': {
                'type': 'bool',
                },
            'rto_authentication': {
                'type': 'bool',
                }
            },
        'action_on_syn_rto_retry_count': {
            'type': 'int',
            },
        'action_on_ack_rto_retry_count': {
            'type': 'int',
            },
        'age': {
            'type': 'int',
            },
        'syn_cookie': {
            'type': 'bool',
            },
        'create_conn_on_syn_only': {
            'type': 'bool',
            },
        'black_list_out_of_seq': {
            'type': 'int',
            },
        'black_list_retransmit': {
            'type': 'int',
            },
        'black_list_zero_win': {
            'type': 'int',
            },
        'syn_auth': {
            'type': 'str',
            'choices': ['send-rst', 'force-rst-by-ack', 'force-rst-by-synack', 'disable']
            },
        'conn_rate_limit_on_syn_only': {
            'type': 'bool',
            },
        'per_conn_rate_interval': {
            'type': 'str',
            'choices': ['100ms', '1sec', '10sec']
            },
        'per_conn_pkt_rate_limit': {
            'type': 'int',
            },
        'per_conn_pkt_rate_action': {
            'type': 'str',
            'choices': ['drop', 'blacklist-src', 'ignore']
            },
        'per_conn_out_of_seq_rate_limit': {
            'type': 'int',
            },
        'per_conn_out_of_seq_rate_action': {
            'type': 'str',
            'choices': ['drop', 'blacklist-src', 'ignore']
            },
        'per_conn_retransmit_rate_limit': {
            'type': 'int',
            },
        'per_conn_retransmit_rate_action': {
            'type': 'str',
            'choices': ['drop', 'blacklist-src', 'ignore']
            },
        'per_conn_zero_win_rate_limit': {
            'type': 'int',
            },
        'per_conn_zero_win_rate_action': {
            'type': 'str',
            'choices': ['drop', 'blacklist-src', 'ignore']
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
        'action_syn_cfg': {
            'type': 'dict',
            'action_on_syn': {
                'type': 'bool',
                },
            'action_on_syn_reset': {
                'type': 'bool',
                },
            'action_on_syn_timeout': {
                'type': 'int',
                },
            'action_on_syn_gap': {
                'type': 'int',
                },
            'action_on_syn_rto': {
                'type': 'bool',
                }
            },
        'allow_syn_otherflags': {
            'type': 'bool',
            },
        'allow_tcp_tfo': {
            'type': 'bool',
            },
        'ack_authentication_synack_reset': {
            'type': 'bool',
            },
        'drop_known_resp_src_port_cfg': {
            'type': 'dict',
            'drop_known_resp_src_port': {
                'type': 'bool',
                },
            'exclude_src_resp_port': {
                'type': 'bool',
                }
            },
        'tunnel_encap': {
            'type': 'dict',
            'ip_cfg': {
                'type': 'dict',
                'ip_encap': {
                    'type': 'bool',
                    },
                'always': {
                    'type': 'dict',
                    'ipv4_addr': {
                        'type': 'str',
                        },
                    'preserve_src_ipv4': {
                        'type': 'bool',
                        },
                    'ipv6_addr': {
                        'type': 'str',
                        },
                    'preserve_src_ipv6': {
                        'type': 'bool',
                        }
                    }
                },
            'gre_cfg': {
                'type': 'dict',
                'gre_encap': {
                    'type': 'bool',
                    },
                'gre_always': {
                    'type': 'dict',
                    'gre_ipv4': {
                        'type': 'str',
                        },
                    'key_ipv4': {
                        'type': 'str',
                        },
                    'preserve_src_ipv4_gre': {
                        'type': 'bool',
                        },
                    'gre_ipv6': {
                        'type': 'str',
                        },
                    'key_ipv6': {
                        'type': 'str',
                        },
                    'preserve_src_ipv6_gre': {
                        'type': 'bool',
                        }
                    }
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
            'request_response_model': {
                'type': 'str',
                'choices': ['enable', 'disable']
                },
            'violation': {
                'type': 'int',
                },
            'response_length_max': {
                'type': 'int',
                },
            'request_length_min': {
                'type': 'int',
                },
            'request_length_max': {
                'type': 'int',
                },
            'response_request_min_ratio': {
                'type': 'int',
                },
            'response_request_max_ratio': {
                'type': 'int',
                },
            'first_request_max_time': {
                'type': 'int',
                },
            'request_to_response_max_time': {
                'type': 'int',
                },
            'response_to_request_max_time': {
                'type': 'int',
                },
            'profiling_request_response_model': {
                'type': 'bool',
                },
            'profiling_connection_life_model': {
                'type': 'bool',
                },
            'profiling_time_window_model': {
                'type': 'bool',
                },
            'progression_tracking_action_list_name': {
                'type': 'str',
                },
            'progression_tracking_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src']
                },
            'uuid': {
                'type': 'str',
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
                }
            },
        'filter_list': {
            'type': 'list',
            'tcp_filter_seq': {
                'type': 'int',
                'required': True,
                },
            'tcp_filter_regex': {
                'type': 'str',
                },
            'byte_offset_filter': {
                'type': 'str',
                },
            'tcp_filter_unmatched': {
                'type': 'bool',
                },
            'tcp_filter_action': {
                'type': 'str',
                'choices': ['blacklist-src', 'whitelist-src', 'count-only']
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
    url_base = "/axapi/v3/ddos/template/tcp/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/template/tcp"

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


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
