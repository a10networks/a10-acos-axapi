#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_template_logging
description:
    - Logging Template
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
        - "Logging template name"
        type: str
        required: True
    resolution:
        description:
        - "'seconds'= Logging timestamp resolution in seconds (default);
          '10-milliseconds'= Logging timestamp resolution in 10s of milli-seconds;"
        type: str
        required: False
    log:
        description:
        - "Field log"
        type: dict
        required: False
        suboptions:
            fixed_nat:
                description:
                - "Field fixed_nat"
                type: dict
            one_to_one_nat:
                description:
                - "Field one_to_one_nat"
                type: dict
            map_dhcpv6:
                description:
                - "Field map_dhcpv6"
                type: dict
            http_requests:
                description:
                - "'host'= Log the HTTP Host Header; 'url'= Log the HTTP Request URL;"
                type: str
            port_mappings:
                description:
                - "'creation'= Log only creation of NAT mappings; 'disable'= Disable Log creation
          and deletion of NAT mappings; 'both'= Log creation and deletion of NAT
          mappings;"
                type: str
            port_overloading:
                description:
                - "Force logging of all port-overloading sessions"
                type: bool
            user_data:
                description:
                - "Log LSN Subscriber Information"
                type: bool
            sessions:
                description:
                - "Log all data sessions created using NAT"
                type: bool
            merged_style:
                description:
                - "Merge creation and deletion of session logs to one"
                type: bool
    include_destination:
        description:
        - "Include the destination IP and port in logs"
        type: bool
        required: False
    include_inside_user_mac:
        description:
        - "Include the inside user MAC address in logs"
        type: bool
        required: False
    include_partition_name:
        description:
        - "Include partition name in logging events"
        type: bool
        required: False
    include_session_byte_count:
        description:
        - "include byte count in session deletion logs"
        type: bool
        required: False
    include_port_block_account:
        description:
        - "include bytes accounting information in port-batch-v2 port-mapping and fixed-
          nat user-ports messages"
        type: bool
        required: False
    include_radius_attribute:
        description:
        - "Field include_radius_attribute"
        type: dict
        required: False
        suboptions:
            attr_cfg:
                description:
                - "Field attr_cfg"
                type: list
            no_quote:
                description:
                - "No quotation marks for RADIUS attributes in logs"
                type: bool
            insert_if_not_existing:
                description:
                - "Configure what string is to be inserted for custom RADIUS attributes"
                type: bool
            zero_in_custom_attr:
                description:
                - "Insert 0000 for standard and custom attributes in log string"
                type: bool
            framed_ipv6_prefix:
                description:
                - "Include radius attributes for the prefix"
                type: bool
            prefix_length:
                description:
                - "'32'= Prefix length 32; '48'= Prefix length 48; '64'= Prefix length 64; '80'=
          Prefix length 80; '96'= Prefix length 96; '112'= Prefix length 112;"
                type: str
    include_http:
        description:
        - "Field include_http"
        type: dict
        required: False
        suboptions:
            header_cfg:
                description:
                - "Field header_cfg"
                type: list
            l4_session_info:
                description:
                - "Log the L4 session information of the HTTP request"
                type: bool
            method:
                description:
                - "Log the HTTP Request Method"
                type: bool
            request_number:
                description:
                - "HTTP Request Number"
                type: bool
            file_extension:
                description:
                - "HTTP file extension"
                type: bool
    rule:
        description:
        - "Field rule"
        type: dict
        required: False
        suboptions:
            rule_http_requests:
                description:
                - "Field rule_http_requests"
                type: dict
            interim_update_interval:
                description:
                - "Log interim update of NAT mappings (Interim update interval in minutes(Interval
          is floored to a multiple of 5))"
                type: int
    facility:
        description:
        - "'kernel'= 0= Kernel; 'user'= 1= User-level; 'mail'= 2= Mail; 'daemon'= 3=
          System daemons; 'security-authorization'= 4= Security/authorization; 'syslog'=
          5= Syslog internal; 'line-printer'= 6= Line printer; 'news'= 7= Network news;
          'uucp'= 8= UUCP subsystem; 'cron'= 9= Time-related; 'security-authorization-
          private'= 10= Private security/authorization; 'ftp'= 11= FTP; 'ntp'= 12= NTP;
          'audit'= 13= Audit; 'alert'= 14= Alert; 'clock'= 15= Clock-related; 'local0'=
          16= Local use 0; 'local1'= 17= Local use 1; 'local2'= 18= Local use 2;
          'local3'= 19= Local use 3; 'local4'= 20= Local use 4; 'local5'= 21= Local use
          5; 'local6'= 22= Local use 6; 'local7'= 23= Local use 7;"
        type: str
        required: False
    severity:
        description:
        - "Field severity"
        type: dict
        required: False
        suboptions:
            severity_string:
                description:
                - "'emergency'= 0= Emergency; 'alert'= 1= Alert; 'critical'= 2= Critical; 'error'=
          3= Error; 'warning'= 4= Warning; 'notice'= 5= Notice; 'informational'= 6=
          Informational; 'debug'= 7= Debug;"
                type: str
            severity_val:
                description:
                - "Logging severity level"
                type: int
    format:
        description:
        - "'binary'= Binary logging format; 'compact'= Compact ASCII logging format (Hex
          format with compact representation); 'custom'= Arbitrary custom logging format;
          'default'= Default A10 logging format (ASCII); 'rfc5424'= RFC5424 compliant
          logging format; 'cef'= Common Event Format for logging;"
        type: str
        required: False
    batched_logging_disable:
        description:
        - "Disable multiple logs per packet"
        type: bool
        required: False
    log_receiver:
        description:
        - "Field log_receiver"
        type: dict
        required: False
        suboptions:
            radius:
                description:
                - "Use RADIUS server for NAT logging"
                type: bool
            secret_string:
                description:
                - "The RADIUS server's secret"
                type: str
            encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED secret string)"
                type: str
    service_group:
        description:
        - "Set NAT logging service-group"
        type: str
        required: False
    shared:
        description:
        - "Service group is in shared patition"
        type: bool
        required: False
    source_port:
        description:
        - "Field source_port"
        type: dict
        required: False
        suboptions:
            source_port_num:
                description:
                - "Set source port for sending NAT syslogs (default= 514)"
                type: int
            any:
                description:
                - "Use any source port"
                type: bool
    rfc_custom:
        description:
        - "Field rfc_custom"
        type: dict
        required: False
        suboptions:
            header:
                description:
                - "Field header"
                type: dict
            message:
                description:
                - "Field message"
                type: dict
    custom:
        description:
        - "Field custom"
        type: dict
        required: False
        suboptions:
            custom_header:
                description:
                - "'use-syslog-header'= Use syslog header as custom log header;"
                type: str
            custom_message:
                description:
                - "Field custom_message"
                type: dict
            custom_time_stamp_format:
                description:
                - "Customize the time stamp format (Customize the time-stamp format.
          Default=%Y%m%d%H%M%S)"
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
    source_address:
        description:
        - "Field source_address"
        type: dict
        required: False
        suboptions:
            ip:
                description:
                - "Specify source IP address"
                type: str
            ipv6:
                description:
                - "Specify source IPv6 address"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    disable_log_by_destination:
        description:
        - "Field disable_log_by_destination"
        type: dict
        required: False
        suboptions:
            tcp_list:
                description:
                - "Field tcp_list"
                type: list
            udp_list:
                description:
                - "Field udp_list"
                type: list
            icmp:
                description:
                - "Disable logging for icmp traffic"
                type: bool
            others:
                description:
                - "Disable logging for other L4 protocols"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            ip_list:
                description:
                - "Field ip_list"
                type: list
            ip6_list:
                description:
                - "Field ip6_list"
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
    "batched_logging_disable",
    "custom",
    "disable_log_by_destination",
    "facility",
    "format",
    "include_destination",
    "include_http",
    "include_inside_user_mac",
    "include_partition_name",
    "include_port_block_account",
    "include_radius_attribute",
    "include_session_byte_count",
    "log",
    "log_receiver",
    "name",
    "resolution",
    "rfc_custom",
    "rule",
    "service_group",
    "severity",
    "shared",
    "source_address",
    "source_port",
    "user_tag",
    "uuid",
]


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
            type='str',
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
        'resolution': {
            'type': 'str',
            'choices': ['seconds', '10-milliseconds']
        },
        'log': {
            'type': 'dict',
            'fixed_nat': {
                'type': 'dict',
                'fixed_nat_http_requests': {
                    'type': 'str',
                    'choices': ['host', 'url']
                },
                'fixed_nat_port_mappings': {
                    'type': 'str',
                    'choices': ['both', 'creation']
                },
                'fixed_nat_sessions': {
                    'type': 'bool',
                },
                'fixed_nat_merged_style': {
                    'type': 'bool',
                },
                'user_ports': {
                    'type': 'dict',
                    'user_ports': {
                        'type': 'bool',
                    },
                    'days': {
                        'type': 'int',
                    },
                    'start_time': {
                        'type': 'str',
                    }
                }
            },
            'one_to_one_nat': {
                'type': 'dict',
                'one_to_one_nat_sessions': {
                    'type': 'bool',
                },
                'one_to_one_merged_style': {
                    'type': 'bool',
                }
            },
            'map_dhcpv6': {
                'type': 'dict',
                'map_dhcpv6_prefix_all': {
                    'type': 'bool',
                },
                'map_dhcpv6_msg_type': {
                    'type': 'list',
                    'map_dhcpv6_msg_type': {
                        'type':
                        'str',
                        'choices': [
                            'prefix-assignment', 'prefix-renewal',
                            'prefix-release'
                        ]
                    }
                }
            },
            'http_requests': {
                'type': 'str',
                'choices': ['host', 'url']
            },
            'port_mappings': {
                'type': 'str',
                'choices': ['creation', 'disable', 'both']
            },
            'port_overloading': {
                'type': 'bool',
            },
            'user_data': {
                'type': 'bool',
            },
            'sessions': {
                'type': 'bool',
            },
            'merged_style': {
                'type': 'bool',
            }
        },
        'include_destination': {
            'type': 'bool',
        },
        'include_inside_user_mac': {
            'type': 'bool',
        },
        'include_partition_name': {
            'type': 'bool',
        },
        'include_session_byte_count': {
            'type': 'bool',
        },
        'include_port_block_account': {
            'type': 'bool',
        },
        'include_radius_attribute': {
            'type': 'dict',
            'attr_cfg': {
                'type': 'list',
                'attr': {
                    'type':
                    'str',
                    'choices': [
                        'imei', 'imsi', 'msisdn', 'custom1', 'custom2',
                        'custom3', 'custom4', 'custom5', 'custom6'
                    ]
                },
                'attr_event': {
                    'type':
                    'str',
                    'choices': [
                        'http-requests', 'port-mappings', 'sessions',
                        'user-data'
                    ]
                }
            },
            'no_quote': {
                'type': 'bool',
            },
            'insert_if_not_existing': {
                'type': 'bool',
            },
            'zero_in_custom_attr': {
                'type': 'bool',
            },
            'framed_ipv6_prefix': {
                'type': 'bool',
            },
            'prefix_length': {
                'type': 'str',
                'choices': ['32', '48', '64', '80', '96', '112']
            }
        },
        'include_http': {
            'type': 'dict',
            'header_cfg': {
                'type': 'list',
                'http_header': {
                    'type':
                    'str',
                    'choices': [
                        'cookie', 'referer', 'user-agent', 'header1',
                        'header2', 'header3'
                    ]
                },
                'max_length': {
                    'type': 'int',
                },
                'custom_header_name': {
                    'type': 'str',
                },
                'custom_max_length': {
                    'type': 'int',
                }
            },
            'l4_session_info': {
                'type': 'bool',
            },
            'method': {
                'type': 'bool',
            },
            'request_number': {
                'type': 'bool',
            },
            'file_extension': {
                'type': 'bool',
            }
        },
        'rule': {
            'type': 'dict',
            'rule_http_requests': {
                'type': 'dict',
                'dest_port': {
                    'type': 'list',
                    'dest_port_number': {
                        'type': 'int',
                    },
                    'include_byte_count': {
                        'type': 'bool',
                    }
                },
                'log_every_http_request': {
                    'type': 'bool',
                },
                'max_url_len': {
                    'type': 'int',
                },
                'include_all_headers': {
                    'type': 'bool',
                },
                'disable_sequence_check': {
                    'type': 'bool',
                }
            },
            'interim_update_interval': {
                'type': 'int',
            }
        },
        'facility': {
            'type':
            'str',
            'choices': [
                'kernel', 'user', 'mail', 'daemon', 'security-authorization',
                'syslog', 'line-printer', 'news', 'uucp', 'cron',
                'security-authorization-private', 'ftp', 'ntp', 'audit',
                'alert', 'clock', 'local0', 'local1', 'local2', 'local3',
                'local4', 'local5', 'local6', 'local7'
            ]
        },
        'severity': {
            'type': 'dict',
            'severity_string': {
                'type':
                'str',
                'choices': [
                    'emergency', 'alert', 'critical', 'error', 'warning',
                    'notice', 'informational', 'debug'
                ]
            },
            'severity_val': {
                'type': 'int',
            }
        },
        'format': {
            'type': 'str',
            'choices':
            ['binary', 'compact', 'custom', 'default', 'rfc5424', 'cef']
        },
        'batched_logging_disable': {
            'type': 'bool',
        },
        'log_receiver': {
            'type': 'dict',
            'radius': {
                'type': 'bool',
            },
            'secret_string': {
                'type': 'str',
            },
            'encrypted': {
                'type': 'str',
            }
        },
        'service_group': {
            'type': 'str',
        },
        'shared': {
            'type': 'bool',
        },
        'source_port': {
            'type': 'dict',
            'source_port_num': {
                'type': 'int',
            },
            'any': {
                'type': 'bool',
            }
        },
        'rfc_custom': {
            'type': 'dict',
            'header': {
                'type': 'dict',
                'use_alternate_timestamp': {
                    'type': 'bool',
                }
            },
            'message': {
                'type': 'dict',
                'ipv6_tech': {
                    'type': 'list',
                    'tech_type': {
                        'type': 'str',
                        'choices': ['lsn', 'nat64', 'ds-lite', 'sixrd-nat64']
                    },
                    'fixed_nat_allocated': {
                        'type': 'str',
                    },
                    'fixed_nat_freed': {
                        'type': 'str',
                    },
                    'port_allocated': {
                        'type': 'str',
                    },
                    'port_freed': {
                        'type': 'str',
                    },
                    'port_batch_allocated': {
                        'type': 'str',
                    },
                    'port_batch_freed': {
                        'type': 'str',
                    },
                    'port_batch_v2_allocated': {
                        'type': 'str',
                    },
                    'port_batch_v2_freed': {
                        'type': 'str',
                    }
                },
                'dhcpv6_map_prefix_assigned': {
                    'type': 'str',
                },
                'dhcpv6_map_prefix_released': {
                    'type': 'str',
                },
                'dhcpv6_map_prefix_renewed': {
                    'type': 'str',
                },
                'http_request_got': {
                    'type': 'str',
                },
                'session_created': {
                    'type': 'str',
                },
                'session_deleted': {
                    'type': 'str',
                }
            }
        },
        'custom': {
            'type': 'dict',
            'custom_header': {
                'type': 'str',
                'choices': ['use-syslog-header']
            },
            'custom_message': {
                'type': 'dict',
                'custom_dhcpv6_map_prefix_assigned': {
                    'type': 'str',
                },
                'custom_dhcpv6_map_prefix_released': {
                    'type': 'str',
                },
                'custom_dhcpv6_map_prefix_renewed': {
                    'type': 'str',
                },
                'custom_fixed_nat_allocated': {
                    'type': 'str',
                },
                'custom_fixed_nat_interim_update': {
                    'type': 'str',
                },
                'custom_fixed_nat_freed': {
                    'type': 'str',
                },
                'custom_http_request_got': {
                    'type': 'str',
                },
                'custom_port_allocated': {
                    'type': 'str',
                },
                'custom_port_batch_allocated': {
                    'type': 'str',
                },
                'custom_port_batch_freed': {
                    'type': 'str',
                },
                'custom_port_batch_v2_allocated': {
                    'type': 'str',
                },
                'custom_port_batch_v2_freed': {
                    'type': 'str',
                },
                'custom_port_batch_v2_interim_update': {
                    'type': 'str',
                },
                'custom_port_freed': {
                    'type': 'str',
                },
                'custom_session_created': {
                    'type': 'str',
                },
                'custom_session_deleted': {
                    'type': 'str',
                }
            },
            'custom_time_stamp_format': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'source_address': {
            'type': 'dict',
            'ip': {
                'type': 'str',
            },
            'ipv6': {
                'type': 'str',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'disable_log_by_destination': {
            'type': 'dict',
            'tcp_list': {
                'type': 'list',
                'tcp_port_start': {
                    'type': 'int',
                },
                'tcp_port_end': {
                    'type': 'int',
                }
            },
            'udp_list': {
                'type': 'list',
                'udp_port_start': {
                    'type': 'int',
                },
                'udp_port_end': {
                    'type': 'int',
                }
            },
            'icmp': {
                'type': 'bool',
            },
            'others': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            },
            'ip_list': {
                'type': 'list',
                'ipv4_addr': {
                    'type': 'str',
                    'required': True,
                },
                'tcp_list': {
                    'type': 'list',
                    'tcp_port_start': {
                        'type': 'int',
                    },
                    'tcp_port_end': {
                        'type': 'int',
                    }
                },
                'udp_list': {
                    'type': 'list',
                    'udp_port_start': {
                        'type': 'int',
                    },
                    'udp_port_end': {
                        'type': 'int',
                    }
                },
                'icmp': {
                    'type': 'bool',
                },
                'others': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                },
                'user_tag': {
                    'type': 'str',
                }
            },
            'ip6_list': {
                'type': 'list',
                'ipv6_addr': {
                    'type': 'str',
                    'required': True,
                },
                'tcp_list': {
                    'type': 'list',
                    'tcp_port_start': {
                        'type': 'int',
                    },
                    'tcp_port_end': {
                        'type': 'int',
                    }
                },
                'udp_list': {
                    'type': 'list',
                    'udp_port_start': {
                        'type': 'int',
                    },
                    'udp_port_end': {
                        'type': 'int',
                    }
                },
                'icmp': {
                    'type': 'bool',
                },
                'others': {
                    'type': 'bool',
                },
                'uuid': {
                    'type': 'str',
                },
                'user_tag': {
                    'type': 'str',
                }
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/template/logging/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/template/logging/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["logging"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["logging"].get(k) != v:
            change_results["changed"] = True
            config_changes["logging"][k] = v

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
    payload = utils.build_json("logging", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[],
                  ansible_facts={},
                  acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params,
                                                  requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(
                api_client.switch_device_context(module.client,
                                                 a10_device_context_id))

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
                get_result = api_client.get(module.client,
                                            existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info[
                    "logging"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client,
                                                      existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info[
                    "logging-list"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
