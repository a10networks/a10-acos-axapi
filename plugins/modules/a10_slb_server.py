#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_server
description:
    - Server
short_description: Configures A10 slb.server
author: A10 Networks 2018
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            srv_gateway_arp:
                description:
                - "Field srv_gateway_arp"
            port_list:
                description:
                - "Field port_list"
            name:
                description:
                - "Server Name"
            dns_update_time:
                description:
                - "Field dns_update_time"
            state:
                description:
                - "Field state"
            creation_type:
                description:
                - "Field creation_type"
            server_ttl:
                description:
                - "Field server_ttl"
            curr_observe_rate:
                description:
                - "Field curr_observe_rate"
            curr_conn_rate:
                description:
                - "Field curr_conn_rate"
            conn_rate_unit:
                description:
                - "Field conn_rate_unit"
            disable:
                description:
                - "Field disable"
            slow_start_conn_limit:
                description:
                - "Field slow_start_conn_limit"
            is_autocreate:
                description:
                - "Field is_autocreate"
            drs_list:
                description:
                - "Field drs_list"
    health_check_disable:
        description:
        - "Disable configured health check configuration"
        required: False
    port_list:
        description:
        - "Field port_list"
        required: False
        suboptions:
            health_check_disable:
                description:
                - "Disable health check"
            protocol:
                description:
                - "'tcp'= TCP Port; 'udp'= UDP Port;"
            weight:
                description:
                - "Port Weight (Connection Weight)"
            shared_rport_health_check:
                description:
                - "Reference a health-check from shared partition"
            stats_data_action:
                description:
                - "'stats-data-enable'= Enable statistical data collection for real server port;
          'stats-data-disable'= Disable statistical data collection for real server port;"
            health_check_follow_port:
                description:
                - "Specify which port to follow for health status (Port Number)"
            template_port:
                description:
                - "Port template (Port template name)"
            conn_limit:
                description:
                - "Connection Limit"
            uuid:
                description:
                - "uuid of the object"
            support_http2:
                description:
                - "Starting HTTP/2 with Prior Knowledge"
            sampling_enable:
                description:
                - "Field sampling_enable"
            no_ssl:
                description:
                - "No SSL"
            follow_port_protocol:
                description:
                - "'tcp'= TCP Port; 'udp'= UDP Port;"
            template_server_ssl:
                description:
                - "Server side SSL template (Server side SSL Name)"
            alternate_port:
                description:
                - "Field alternate_port"
            port_number:
                description:
                - "Port Number"
            extended_stats:
                description:
                - "Enable extended statistics on real server port"
            rport_health_check_shared:
                description:
                - "Health Check (Monitor Name)"
            conn_resume:
                description:
                - "Connection Resume"
            user_tag:
                description:
                - "Customized tag"
            range:
                description:
                - "Port range (Port range value - used for vip-to-rport-mapping and vport-rport
          range mapping)"
            auth_cfg:
                description:
                - "Field auth_cfg"
            action:
                description:
                - "'enable'= enable; 'disable'= disable; 'disable-with-health-check'= disable
          port, but health check work;"
            health_check:
                description:
                - "Health Check (Monitor Name)"
            no_logging:
                description:
                - "Do not log connection over limit event"
    stats_data_action:
        description:
        - "'stats-data-enable'= Enable statistical data collection for real server;
          'stats-data-disable'= Disable statistical data collection for real server;"
        required: False
    slow_start:
        description:
        - "Slowly ramp up the connection number after server is up (start from 128, then
          double every 10 sec till 4096)"
        required: False
    weight:
        description:
        - "Weight for this Real Server (Connection Weight)"
        required: False
    spoofing_cache:
        description:
        - "This server is a spoofing cache"
        required: False
    resolve_as:
        description:
        - "'resolve-to-ipv4'= Use A Query only to resolve FQDN; 'resolve-to-ipv6'= Use
          AAAA Query only to resolve FQDN; 'resolve-to-ipv4-and-ipv6'= Use A as well as
          AAAA Query to resolve FQDN;"
        required: False
    conn_limit:
        description:
        - "Connection Limit"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            curr_conn:
                description:
                - "Current established connections"
            peak_conn:
                description:
                - "Peak number of established connections"
            rev_pkt:
                description:
                - "Reverse Packets Processed"
            total_rev_pkts:
                description:
                - "Packets processed in reverse direction"
            name:
                description:
                - "Server Name"
            total_ssl_conn:
                description:
                - "Total SSL connections established"
            total_fwd_pkts:
                description:
                - "Packets processed in forward direction"
            total_req:
                description:
                - "Total Requests processed"
            total_conn:
                description:
                - "Total established connections"
            curr_ssl_conn:
                description:
                - "Current SSL connections established"
            total_req_succ:
                description:
                - "Total Requests succeeded"
            port_list:
                description:
                - "Field port_list"
            fwd_pkt:
                description:
                - "Forward Packets Processed"
            total_fwd_bytes:
                description:
                - "Bytes processed in forward direction"
            total_rev_bytes:
                description:
                - "Bytes processed in reverse direction"
    uuid:
        description:
        - "uuid of the object"
        required: False
    fqdn_name:
        description:
        - "Server hostname"
        required: False
    external_ip:
        description:
        - "External IP address for NAT of GSLB"
        required: False
    health_check_shared:
        description:
        - "Health Check Monitor (Health monitor name)"
        required: False
    ipv6:
        description:
        - "IPv6 address Mapping of GSLB"
        required: False
    template_server:
        description:
        - "Server template (Server template name)"
        required: False
    server_ipv6_addr:
        description:
        - "IPV6 address"
        required: False
    alternate_server:
        description:
        - "Field alternate_server"
        required: False
        suboptions:
            alternate_name:
                description:
                - "Alternate Name"
            alternate:
                description:
                - "Alternate Server (Alternate Server Number)"
    shared_partition_health_check:
        description:
        - "Reference a health-check from shared partition"
        required: False
    host:
        description:
        - "IP Address"
        required: False
    extended_stats:
        description:
        - "Enable extended statistics on real server"
        required: False
    conn_resume:
        description:
        - "Connection Resume (Connection Resume (min active conn before resume taking new
          conn))"
        required: False
    name:
        description:
        - "Server Name"
        required: True
    user_tag:
        description:
        - "Customized tag"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'total-conn'= Total established connections; 'fwd-pkt'= Forward
          Packets Processed; 'rev-pkt'= Reverse Packets Processed; 'peak-conn'= Peak
          number of established connections; 'total_req'= Total Requests processed;
          'total_req_succ'= Total Requests succeeded; 'curr_ssl_conn'= Current SSL
          connections established; 'total_ssl_conn'= Total SSL connections established;
          'total_fwd_bytes'= Bytes processed in forward direction; 'total_rev_bytes'=
          Bytes processed in reverse direction; 'total_fwd_pkts'= Packets processed in
          forward direction; 'total_rev_pkts'= Packets processed in reverse direction;"
    action:
        description:
        - "'enable'= Enable this Real Server; 'disable'= Disable this Real Server;
          'disable-with-health-check'= disable real server, but health check work;"
        required: False
    health_check:
        description:
        - "Health Check Monitor (Health monitor name)"
        required: False
    no_logging:
        description:
        - "Do not log connection over limit event"
        required: False


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
    "action",
    "alternate_server",
    "conn_limit",
    "conn_resume",
    "extended_stats",
    "external_ip",
    "fqdn_name",
    "health_check",
    "health_check_disable",
    "health_check_shared",
    "host",
    "ipv6",
    "name",
    "no_logging",
    "oper",
    "port_list",
    "resolve_as",
    "sampling_enable",
    "server_ipv6_addr",
    "shared_partition_health_check",
    "slow_start",
    "spoofing_cache",
    "stats",
    "stats_data_action",
    "template_server",
    "user_tag",
    "uuid",
    "weight",
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
        'oper': {
            'type': 'dict',
            'srv_gateway_arp': {
                'type': 'str',
            },
            'port_list': {
                'type': 'list',
                'oper': {
                    'type': 'dict',
                    'down_grace_period_allowed': {
                        'type': 'int',
                    },
                    'ip': {
                        'type': 'str',
                    },
                    'ports_freed_total': {
                        'type': 'int',
                    },
                    'ports_consumed_total': {
                        'type': 'int',
                    },
                    'aflow_queue_size': {
                        'type': 'int',
                    },
                    'current_time': {
                        'type': 'int',
                    },
                    'alloc_failed': {
                        'type': 'int',
                    },
                    'vrid': {
                        'type': 'int',
                    },
                    'state': {
                        'type':
                        'str',
                        'choices': [
                            'Up', 'Down', 'Disabled', 'Maintenance', 'Unknown',
                            'DIS-UP', 'DIS-DOWN', 'DIS-MAINTENANCE',
                            'DIS-EXCEED-RATE', 'DIS-DAMP'
                        ]
                    },
                    'ipv6': {
                        'type': 'str',
                    },
                    'slow_start_conn_limit': {
                        'type': 'int',
                    },
                    'resv_conn': {
                        'type': 'int',
                    },
                    'hm_index': {
                        'type': 'int',
                    },
                    'down_time_grace_period': {
                        'type': 'int',
                    },
                    'inband_hm_reassign_num': {
                        'type': 'int',
                    },
                    'ports_consumed': {
                        'type': 'int',
                    },
                    'curr_observe_rate': {
                        'type': 'int',
                    },
                    'curr_conn_rate': {
                        'type': 'int',
                    },
                    'disable': {
                        'type': 'int',
                    },
                    'aflow_conn_limit': {
                        'type': 'int',
                    },
                    'diameter_enabled': {
                        'type': 'int',
                    },
                    'soft_down_time': {
                        'type': 'int',
                    },
                    'ha_group_id': {
                        'type': 'int',
                    },
                    'hm_key': {
                        'type': 'int',
                    },
                    'es_resp_time': {
                        'type': 'int',
                    },
                    'conn_rate_unit': {
                        'type': 'str',
                    }
                },
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['tcp', 'udp']
                },
                'port_number': {
                    'type': 'int',
                    'required': True,
                }
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'dns_update_time': {
                'type': 'str',
            },
            'state': {
                'type':
                'str',
                'choices': [
                    'Up', 'Down', 'Disabled', 'Maintenance', 'Unknown',
                    'Functional Up', 'DIS-UP', 'DIS-DOWN', 'DIS-MAINTENANCE',
                    'DIS-EXCEED-RATE', 'DIS-UNKNOWN'
                ]
            },
            'creation_type': {
                'type': 'str',
            },
            'server_ttl': {
                'type': 'int',
            },
            'curr_observe_rate': {
                'type': 'int',
            },
            'curr_conn_rate': {
                'type': 'int',
            },
            'conn_rate_unit': {
                'type': 'str',
            },
            'disable': {
                'type': 'int',
            },
            'slow_start_conn_limit': {
                'type': 'int',
            },
            'is_autocreate': {
                'type': 'int',
            },
            'drs_list': {
                'type': 'list',
                'drs_server_ipv6_addr': {
                    'type': 'str',
                },
                'drs_srv_gateway_arp': {
                    'type': 'str',
                },
                'drs_creation_type': {
                    'type': 'str',
                },
                'drs_dns_update_time': {
                    'type': 'str',
                },
                'drs_tot_req_suc': {
                    'type': 'int',
                },
                'drs_curr_conn': {
                    'type': 'int',
                },
                'drs_tot_rev_pkts': {
                    'type': 'int',
                },
                'drs_tot_rev_bytes': {
                    'type': 'int',
                },
                'drs_name': {
                    'type': 'str',
                },
                'drs_server_ttl': {
                    'type': 'int',
                },
                'drs_state': {
                    'type':
                    'str',
                    'choices': [
                        'Up', 'Down', 'Disabled', 'Maintenance', 'Unknown',
                        'Functional Up', 'DIS-UP', 'DIS-DOWN',
                        'DIS-MAINTENANCE', 'DIS-EXCEED-RATE', 'DIS-UNKNOWN'
                    ]
                },
                'drs_disable': {
                    'type': 'int',
                },
                'drs_tot_fwd_bytes': {
                    'type': 'int',
                },
                'drs_curr_observe_rate': {
                    'type': 'int',
                },
                'drs_host': {
                    'type': 'str',
                },
                'drs_tot_conn': {
                    'type': 'int',
                },
                'drs_curr_conn_rate': {
                    'type': 'int',
                },
                'drs_tot_req': {
                    'type': 'int',
                },
                'drs_conn_rate_unit': {
                    'type': 'str',
                },
                'drs_peak_conn': {
                    'type': 'int',
                },
                'drs_slow_start_conn_limit': {
                    'type': 'int',
                },
                'drs_tot_fwd_pkts': {
                    'type': 'int',
                },
                'drs_curr_req': {
                    'type': 'int',
                },
                'drs_is_autocreate': {
                    'type': 'int',
                }
            }
        },
        'health_check_disable': {
            'type': 'bool',
        },
        'port_list': {
            'type': 'list',
            'health_check_disable': {
                'type': 'bool',
            },
            'protocol': {
                'type': 'str',
                'required': True,
                'choices': ['tcp', 'udp']
            },
            'weight': {
                'type': 'int',
            },
            'shared_rport_health_check': {
                'type': 'bool',
            },
            'stats_data_action': {
                'type': 'str',
                'choices': ['stats-data-enable', 'stats-data-disable']
            },
            'health_check_follow_port': {
                'type': 'int',
            },
            'template_port': {
                'type': 'str',
            },
            'conn_limit': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            },
            'support_http2': {
                'type': 'bool',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'curr_req', 'total_req', 'total_req_succ',
                        'total_fwd_bytes', 'total_fwd_pkts', 'total_rev_bytes',
                        'total_rev_pkts', 'total_conn', 'last_total_conn',
                        'peak_conn', 'es_resp_200', 'es_resp_300',
                        'es_resp_400', 'es_resp_500', 'es_resp_other',
                        'es_req_count', 'es_resp_count',
                        'es_resp_invalid_http', 'total_rev_pkts_inspected',
                        'total_rev_pkts_inspected_good_status_code',
                        'response_time', 'fastest_rsp_time',
                        'slowest_rsp_time', 'curr_ssl_conn', 'total_ssl_conn',
                        'resp-count', 'resp-1xx', 'resp-2xx', 'resp-3xx',
                        'resp-4xx', 'resp-5xx', 'resp-other', 'resp-latency',
                        'curr_pconn'
                    ]
                }
            },
            'no_ssl': {
                'type': 'bool',
            },
            'follow_port_protocol': {
                'type': 'str',
                'choices': ['tcp', 'udp']
            },
            'template_server_ssl': {
                'type': 'str',
            },
            'alternate_port': {
                'type': 'list',
                'alternate_name': {
                    'type': 'str',
                },
                'alternate': {
                    'type': 'int',
                },
                'alternate_server_port': {
                    'type': 'int',
                }
            },
            'port_number': {
                'type': 'int',
                'required': True,
            },
            'extended_stats': {
                'type': 'bool',
            },
            'rport_health_check_shared': {
                'type': 'str',
            },
            'conn_resume': {
                'type': 'int',
            },
            'user_tag': {
                'type': 'str',
            },
            'range': {
                'type': 'int',
            },
            'auth_cfg': {
                'type': 'dict',
                'service_principal_name': {
                    'type': 'str',
                }
            },
            'action': {
                'type': 'str',
                'choices': ['enable', 'disable', 'disable-with-health-check']
            },
            'health_check': {
                'type': 'str',
            },
            'no_logging': {
                'type': 'bool',
            }
        },
        'stats_data_action': {
            'type': 'str',
            'choices': ['stats-data-enable', 'stats-data-disable']
        },
        'slow_start': {
            'type': 'bool',
        },
        'weight': {
            'type': 'int',
        },
        'spoofing_cache': {
            'type': 'bool',
        },
        'resolve_as': {
            'type':
            'str',
            'choices':
            ['resolve-to-ipv4', 'resolve-to-ipv6', 'resolve-to-ipv4-and-ipv6']
        },
        'conn_limit': {
            'type': 'int',
        },
        'stats': {
            'type': 'dict',
            'curr_conn': {
                'type': 'str',
            },
            'peak_conn': {
                'type': 'str',
            },
            'rev_pkt': {
                'type': 'str',
            },
            'total_rev_pkts': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'total_ssl_conn': {
                'type': 'str',
            },
            'total_fwd_pkts': {
                'type': 'str',
            },
            'total_req': {
                'type': 'str',
            },
            'total_conn': {
                'type': 'str',
            },
            'curr_ssl_conn': {
                'type': 'str',
            },
            'total_req_succ': {
                'type': 'str',
            },
            'port_list': {
                'type': 'list',
                'protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['tcp', 'udp']
                },
                'stats': {
                    'type': 'dict',
                    'es_resp_invalid_http': {
                        'type': 'str',
                    },
                    'curr_req': {
                        'type': 'str',
                    },
                    'total_rev_pkts_inspected_good_status_code': {
                        'type': 'str',
                    },
                    'resp_1xx': {
                        'type': 'str',
                    },
                    'curr_ssl_conn': {
                        'type': 'str',
                    },
                    'resp_2xx': {
                        'type': 'str',
                    },
                    'es_resp_count': {
                        'type': 'str',
                    },
                    'total_fwd_bytes': {
                        'type': 'str',
                    },
                    'es_resp_other': {
                        'type': 'str',
                    },
                    'fastest_rsp_time': {
                        'type': 'str',
                    },
                    'total_fwd_pkts': {
                        'type': 'str',
                    },
                    'resp_3xx': {
                        'type': 'str',
                    },
                    'resp_latency': {
                        'type': 'str',
                    },
                    'resp_count': {
                        'type': 'str',
                    },
                    'es_req_count': {
                        'type': 'str',
                    },
                    'resp_other': {
                        'type': 'str',
                    },
                    'es_resp_500': {
                        'type': 'str',
                    },
                    'peak_conn': {
                        'type': 'str',
                    },
                    'total_req': {
                        'type': 'str',
                    },
                    'es_resp_400': {
                        'type': 'str',
                    },
                    'es_resp_300': {
                        'type': 'str',
                    },
                    'curr_pconn': {
                        'type': 'str',
                    },
                    'curr_conn': {
                        'type': 'str',
                    },
                    'es_resp_200': {
                        'type': 'str',
                    },
                    'total_rev_bytes': {
                        'type': 'str',
                    },
                    'response_time': {
                        'type': 'str',
                    },
                    'resp_4xx': {
                        'type': 'str',
                    },
                    'total_ssl_conn': {
                        'type': 'str',
                    },
                    'total_conn': {
                        'type': 'str',
                    },
                    'total_rev_pkts': {
                        'type': 'str',
                    },
                    'total_req_succ': {
                        'type': 'str',
                    },
                    'last_total_conn': {
                        'type': 'str',
                    },
                    'total_rev_pkts_inspected': {
                        'type': 'str',
                    },
                    'resp_5xx': {
                        'type': 'str',
                    },
                    'slowest_rsp_time': {
                        'type': 'str',
                    }
                },
                'port_number': {
                    'type': 'int',
                    'required': True,
                }
            },
            'fwd_pkt': {
                'type': 'str',
            },
            'total_fwd_bytes': {
                'type': 'str',
            },
            'total_rev_bytes': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'fqdn_name': {
            'type': 'str',
        },
        'external_ip': {
            'type': 'str',
        },
        'health_check_shared': {
            'type': 'str',
        },
        'ipv6': {
            'type': 'str',
        },
        'template_server': {
            'type': 'str',
        },
        'server_ipv6_addr': {
            'type': 'str',
        },
        'alternate_server': {
            'type': 'list',
            'alternate_name': {
                'type': 'str',
            },
            'alternate': {
                'type': 'int',
            }
        },
        'shared_partition_health_check': {
            'type': 'bool',
        },
        'host': {
            'type': 'str',
        },
        'extended_stats': {
            'type': 'bool',
        },
        'conn_resume': {
            'type': 'int',
        },
        'name': {
            'type': 'str',
            'required': True,
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
                    'all', 'total-conn', 'fwd-pkt', 'rev-pkt', 'peak-conn',
                    'total_req', 'total_req_succ', 'curr_ssl_conn',
                    'total_ssl_conn', 'total_fwd_bytes', 'total_rev_bytes',
                    'total_fwd_pkts', 'total_rev_pkts'
                ]
            }
        },
        'action': {
            'type': 'str',
            'choices': ['enable', 'disable', 'disable-with-health-check']
        },
        'health_check': {
            'type': 'str',
        },
        'no_logging': {
            'type': 'bool',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/server/{name}"

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
    url_base = "/axapi/v3/slb/server/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted(['host', 'fqdn_name', 'server_ipv6_addr'])
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
        for k, v in payload["server"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["server"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["server"][k] = v
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
    payload = build_json("server", module)
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
