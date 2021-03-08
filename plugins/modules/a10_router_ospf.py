#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_router_ospf
description:
    - Open Shortest Path First (OSPF)
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
    process_id:
        description:
        - "OSPF process ID"
        type: int
        required: True
    auto_cost_reference_bandwidth:
        description:
        - "Use reference bandwidth method to assign OSPF cost (The reference bandwidth in
          terms of Mbits per second)"
        type: int
        required: False
    bfd_all_interfaces:
        description:
        - "Enable BFD on all interfaces"
        type: bool
        required: False
    rfc1583_compatible:
        description:
        - "Compatible with RFC 1583"
        type: bool
        required: False
    default_metric:
        description:
        - "Set metric of redistributed routes (Default metric)"
        type: int
        required: False
    distance:
        description:
        - "Field distance"
        type: dict
        required: False
        suboptions:
            distance_value:
                description:
                - "OSPF Administrative distance"
                type: int
            distance_ospf:
                description:
                - "Field distance_ospf"
                type: dict
    distribute_internal_list:
        description:
        - "Field distribute_internal_list"
        type: list
        required: False
        suboptions:
            di_type:
                description:
                - "'lw4o6'= LW4O6 Prefix; 'floating-ip'= Floating IP; 'ip-nat'= IP NAT; 'ip-nat-
          list'= IP NAT list; 'static-nat'= Static NAT; 'vip'= Only not flagged Virtual
          IP (VIP); 'vip-only-flagged'= Selected Virtual IP (VIP);"
                type: str
            di_area_ipv4:
                description:
                - "OSPF area ID as a IP address format"
                type: str
            di_area_num:
                description:
                - "OSPF area ID as a decimal value"
                type: int
            di_cost:
                description:
                - "Cost of route"
                type: int
    distribute_lists:
        description:
        - "Field distribute_lists"
        type: list
        required: False
        suboptions:
            value:
                description:
                - "Access-list name"
                type: str
            direction:
                description:
                - "'in'= Filter incoming routing updates; 'out'= Filter outgoing routing updates;"
                type: str
            protocol:
                description:
                - "'bgp'= Border Gateway Protocol (BGP); 'connected'= Connected; 'floating-ip'=
          Floating IP; 'lw4o6'= LW4O6 Prefix; 'ip-nat'= IP NAT; 'ip-nat-list'= IP NAT
          list; 'static-nat'= Static NAT; 'isis'= ISO IS-IS; 'ospf'= Open Shortest Path
          First (OSPF); 'rip'= Routing Information Protocol (RIP); 'static'= Static
          routes;"
                type: str
            ospf_id:
                description:
                - "OSPF process ID"
                type: int
            option:
                description:
                - "'only-flagged'= Selected Virtual IP (VIP); 'only-not-flagged'= Only not
          flagged;"
                type: str
    ha_standby_extra_cost:
        description:
        - "Field ha_standby_extra_cost"
        type: list
        required: False
        suboptions:
            extra_cost:
                description:
                - "The extra cost value"
                type: int
            group:
                description:
                - "Group (Group ID)"
                type: int
    host_list:
        description:
        - "Field host_list"
        type: list
        required: False
        suboptions:
            host_address:
                description:
                - "Host address"
                type: str
            area_cfg:
                description:
                - "Field area_cfg"
                type: dict
    log_adjacency_changes_cfg:
        description:
        - "Field log_adjacency_changes_cfg"
        type: dict
        required: False
        suboptions:
            state:
                description:
                - "'detail'= Log changes in adjacency state; 'disable'= Disable logging;"
                type: str
    max_concurrent_dd:
        description:
        - "Maximum number allowed to process DD concurrently (Number of DD process)"
        type: int
        required: False
    maximum_area:
        description:
        - "Maximum number of non-backbone areas (OSPF area limit)"
        type: int
        required: False
    neighbor_list:
        description:
        - "Field neighbor_list"
        type: list
        required: False
        suboptions:
            address:
                description:
                - "Neighbor address"
                type: str
            cost:
                description:
                - "OSPF cost for point-to-multipoint neighbor (Metric)"
                type: int
            poll_interval:
                description:
                - "OSPF dead-router polling interval (Seconds)"
                type: int
            priority:
                description:
                - "OSPF priority of non-broadcast neighbor"
                type: int
    network_list:
        description:
        - "Field network_list"
        type: list
        required: False
        suboptions:
            network_ipv4:
                description:
                - "Network number"
                type: str
            network_ipv4_mask:
                description:
                - "OSPF wild card bits"
                type: str
            network_ipv4_cidr:
                description:
                - "OSPF network prefix"
                type: str
            network_area:
                description:
                - "Field network_area"
                type: dict
    ospf_1:
        description:
        - "Field ospf_1"
        type: dict
        required: False
        suboptions:
            abr_type:
                description:
                - "Field abr_type"
                type: dict
    router_id:
        description:
        - "Field router_id"
        type: dict
        required: False
        suboptions:
            value:
                description:
                - "OSPF router-id in IPv4 address format"
                type: str
    overflow:
        description:
        - "Field overflow"
        type: dict
        required: False
        suboptions:
            database:
                description:
                - "Field database"
                type: dict
    passive_interface:
        description:
        - "Field passive_interface"
        type: dict
        required: False
        suboptions:
            loopback_cfg:
                description:
                - "Field loopback_cfg"
                type: list
            trunk_cfg:
                description:
                - "Field trunk_cfg"
                type: list
            ve_cfg:
                description:
                - "Field ve_cfg"
                type: list
            tunnel_cfg:
                description:
                - "Field tunnel_cfg"
                type: list
            lif_cfg:
                description:
                - "Field lif_cfg"
                type: list
            eth_cfg:
                description:
                - "Field eth_cfg"
                type: list
    summary_address_list:
        description:
        - "Field summary_address_list"
        type: list
        required: False
        suboptions:
            summary_address:
                description:
                - "Configure IP address summaries (Summary prefix)"
                type: str
            not_advertise:
                description:
                - "Suppress routes that match the prefix"
                type: bool
            tag:
                description:
                - "Set tag (32-bit tag value)"
                type: int
    timers:
        description:
        - "Field timers"
        type: dict
        required: False
        suboptions:
            spf:
                description:
                - "Field spf"
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
    default_information:
        description:
        - "Field default_information"
        type: dict
        required: False
        suboptions:
            originate:
                description:
                - "Distribute a default route"
                type: bool
            always:
                description:
                - "Always advertise default route"
                type: bool
            metric:
                description:
                - "OSPF default metric (OSPF metric)"
                type: int
            metric_type:
                description:
                - "OSPF metric type for default routes"
                type: int
            route_map:
                description:
                - "Route map reference (Pointer to route-map entries)"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    area_list:
        description:
        - "Field area_list"
        type: list
        required: False
        suboptions:
            area_ipv4:
                description:
                - "OSPF area ID in IP address format"
                type: str
            area_num:
                description:
                - "OSPF area ID as a decimal value"
                type: int
            auth_cfg:
                description:
                - "Field auth_cfg"
                type: dict
            filter_lists:
                description:
                - "Field filter_lists"
                type: list
            nssa_cfg:
                description:
                - "Field nssa_cfg"
                type: dict
            default_cost:
                description:
                - "Set the summary-default cost of a NSSA or stub area (Stub's advertised default
          summary cost)"
                type: int
            range_list:
                description:
                - "Field range_list"
                type: list
            shortcut:
                description:
                - "'default'= Set default shortcutting behavior; 'disable'= Disable shortcutting
          through the area; 'enable'= Enable shortcutting through the area;"
                type: str
            stub_cfg:
                description:
                - "Field stub_cfg"
                type: dict
            virtual_link_list:
                description:
                - "Field virtual_link_list"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
    redistribute:
        description:
        - "Field redistribute"
        type: dict
        required: False
        suboptions:
            redist_list:
                description:
                - "Field redist_list"
                type: list
            ospf_list:
                description:
                - "Field ospf_list"
                type: list
            ip_nat:
                description:
                - "IP-NAT"
                type: bool
            metric_ip_nat:
                description:
                - "OSPF default metric (OSPF metric)"
                type: int
            metric_type_ip_nat:
                description:
                - "'1'= Set OSPF External Type 1 metrics; '2'= Set OSPF External Type 2 metrics;"
                type: str
            route_map_ip_nat:
                description:
                - "Route map reference (Pointer to route-map entries)"
                type: str
            tag_ip_nat:
                description:
                - "Set tag for routes redistributed into OSPF (32-bit tag value)"
                type: int
            ip_nat_floating_list:
                description:
                - "Field ip_nat_floating_list"
                type: list
            vip_list:
                description:
                - "Field vip_list"
                type: list
            vip_floating_list:
                description:
                - "Field vip_floating_list"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str

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
    "area_list",
    "auto_cost_reference_bandwidth",
    "bfd_all_interfaces",
    "default_information",
    "default_metric",
    "distance",
    "distribute_internal_list",
    "distribute_lists",
    "ha_standby_extra_cost",
    "host_list",
    "log_adjacency_changes_cfg",
    "max_concurrent_dd",
    "maximum_area",
    "neighbor_list",
    "network_list",
    "ospf_1",
    "overflow",
    "passive_interface",
    "process_id",
    "redistribute",
    "rfc1583_compatible",
    "router_id",
    "summary_address_list",
    "timers",
    "user_tag",
    "uuid",
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
        'process_id': {
            'type': 'int',
            'required': True,
        },
        'auto_cost_reference_bandwidth': {
            'type': 'int',
        },
        'bfd_all_interfaces': {
            'type': 'bool',
        },
        'rfc1583_compatible': {
            'type': 'bool',
        },
        'default_metric': {
            'type': 'int',
        },
        'distance': {
            'type': 'dict',
            'distance_value': {
                'type': 'int',
            },
            'distance_ospf': {
                'type': 'dict',
                'distance_external': {
                    'type': 'int',
                },
                'distance_inter_area': {
                    'type': 'int',
                },
                'distance_intra_area': {
                    'type': 'int',
                }
            }
        },
        'distribute_internal_list': {
            'type': 'list',
            'di_type': {
                'type':
                'str',
                'choices': [
                    'lw4o6', 'floating-ip', 'ip-nat', 'ip-nat-list',
                    'static-nat', 'vip', 'vip-only-flagged'
                ]
            },
            'di_area_ipv4': {
                'type': 'str',
            },
            'di_area_num': {
                'type': 'int',
            },
            'di_cost': {
                'type': 'int',
            }
        },
        'distribute_lists': {
            'type': 'list',
            'value': {
                'type': 'str',
            },
            'direction': {
                'type': 'str',
                'choices': ['in', 'out']
            },
            'protocol': {
                'type':
                'str',
                'choices': [
                    'bgp', 'connected', 'floating-ip', 'lw4o6', 'ip-nat',
                    'ip-nat-list', 'static-nat', 'isis', 'ospf', 'rip',
                    'static'
                ]
            },
            'ospf_id': {
                'type': 'int',
            },
            'option': {
                'type': 'str',
                'choices': ['only-flagged', 'only-not-flagged']
            }
        },
        'ha_standby_extra_cost': {
            'type': 'list',
            'extra_cost': {
                'type': 'int',
            },
            'group': {
                'type': 'int',
            }
        },
        'host_list': {
            'type': 'list',
            'host_address': {
                'type': 'str',
            },
            'area_cfg': {
                'type': 'dict',
                'area_ipv4': {
                    'type': 'str',
                },
                'area_num': {
                    'type': 'int',
                },
                'cost': {
                    'type': 'int',
                }
            }
        },
        'log_adjacency_changes_cfg': {
            'type': 'dict',
            'state': {
                'type': 'str',
                'choices': ['detail', 'disable']
            }
        },
        'max_concurrent_dd': {
            'type': 'int',
        },
        'maximum_area': {
            'type': 'int',
        },
        'neighbor_list': {
            'type': 'list',
            'address': {
                'type': 'str',
            },
            'cost': {
                'type': 'int',
            },
            'poll_interval': {
                'type': 'int',
            },
            'priority': {
                'type': 'int',
            }
        },
        'network_list': {
            'type': 'list',
            'network_ipv4': {
                'type': 'str',
            },
            'network_ipv4_mask': {
                'type': 'str',
            },
            'network_ipv4_cidr': {
                'type': 'str',
            },
            'network_area': {
                'type': 'dict',
                'network_area_ipv4': {
                    'type': 'str',
                },
                'network_area_num': {
                    'type': 'int',
                },
                'instance_value': {
                    'type': 'int',
                }
            }
        },
        'ospf_1': {
            'type': 'dict',
            'abr_type': {
                'type': 'dict',
                'option': {
                    'type': 'str',
                    'choices': ['cisco', 'ibm', 'shortcut', 'standard']
                }
            }
        },
        'router_id': {
            'type': 'dict',
            'value': {
                'type': 'str',
            }
        },
        'overflow': {
            'type': 'dict',
            'database': {
                'type': 'dict',
                'count': {
                    'type': 'int',
                },
                'limit': {
                    'type': 'str',
                    'choices': ['hard', 'soft']
                },
                'db_external': {
                    'type': 'int',
                },
                'recovery_time': {
                    'type': 'int',
                }
            }
        },
        'passive_interface': {
            'type': 'dict',
            'loopback_cfg': {
                'type': 'list',
                'loopback': {
                    'type': 'str',
                },
                'loopback_address': {
                    'type': 'str',
                }
            },
            'trunk_cfg': {
                'type': 'list',
                'trunk': {
                    'type': 'str',
                },
                'trunk_address': {
                    'type': 'str',
                }
            },
            've_cfg': {
                'type': 'list',
                've': {
                    'type': 'str',
                },
                've_address': {
                    'type': 'str',
                }
            },
            'tunnel_cfg': {
                'type': 'list',
                'tunnel': {
                    'type': 'str',
                },
                'tunnel_address': {
                    'type': 'str',
                }
            },
            'lif_cfg': {
                'type': 'list',
                'lif': {
                    'type': 'str',
                },
                'lif_address': {
                    'type': 'str',
                }
            },
            'eth_cfg': {
                'type': 'list',
                'ethernet': {
                    'type': 'str',
                },
                'eth_address': {
                    'type': 'str',
                }
            }
        },
        'summary_address_list': {
            'type': 'list',
            'summary_address': {
                'type': 'str',
            },
            'not_advertise': {
                'type': 'bool',
            },
            'tag': {
                'type': 'int',
            }
        },
        'timers': {
            'type': 'dict',
            'spf': {
                'type': 'dict',
                'exp': {
                    'type': 'dict',
                    'min_delay': {
                        'type': 'int',
                    },
                    'max_delay': {
                        'type': 'int',
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
        'default_information': {
            'type': 'dict',
            'originate': {
                'type': 'bool',
            },
            'always': {
                'type': 'bool',
            },
            'metric': {
                'type': 'int',
            },
            'metric_type': {
                'type': 'int',
            },
            'route_map': {
                'type': 'str',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'area_list': {
            'type': 'list',
            'area_ipv4': {
                'type': 'str',
                'required': True,
            },
            'area_num': {
                'type': 'int',
                'required': True,
            },
            'auth_cfg': {
                'type': 'dict',
                'authentication': {
                    'type': 'bool',
                },
                'message_digest': {
                    'type': 'bool',
                }
            },
            'filter_lists': {
                'type': 'list',
                'filter_list': {
                    'type': 'bool',
                },
                'acl_name': {
                    'type': 'str',
                },
                'acl_direction': {
                    'type': 'str',
                    'choices': ['in', 'out']
                },
                'plist_name': {
                    'type': 'str',
                },
                'plist_direction': {
                    'type': 'str',
                    'choices': ['in', 'out']
                }
            },
            'nssa_cfg': {
                'type': 'dict',
                'nssa': {
                    'type': 'bool',
                },
                'no_redistribution': {
                    'type': 'bool',
                },
                'no_summary': {
                    'type': 'bool',
                },
                'translator_role': {
                    'type': 'str',
                    'choices': ['always', 'candidate', 'never']
                },
                'default_information_originate': {
                    'type': 'bool',
                },
                'metric': {
                    'type': 'int',
                },
                'metric_type': {
                    'type': 'int',
                }
            },
            'default_cost': {
                'type': 'int',
            },
            'range_list': {
                'type': 'list',
                'area_range_prefix': {
                    'type': 'str',
                },
                'option': {
                    'type': 'str',
                    'choices': ['advertise', 'not-advertise']
                }
            },
            'shortcut': {
                'type': 'str',
                'choices': ['default', 'disable', 'enable']
            },
            'stub_cfg': {
                'type': 'dict',
                'stub': {
                    'type': 'bool',
                },
                'no_summary': {
                    'type': 'bool',
                }
            },
            'virtual_link_list': {
                'type': 'list',
                'virtual_link_ip_addr': {
                    'type': 'str',
                },
                'bfd': {
                    'type': 'bool',
                },
                'hello_interval': {
                    'type': 'int',
                },
                'dead_interval': {
                    'type': 'int',
                },
                'retransmit_interval': {
                    'type': 'int',
                },
                'transmit_delay': {
                    'type': 'int',
                },
                'virtual_link_authentication': {
                    'type': 'bool',
                },
                'virtual_link_auth_type': {
                    'type': 'str',
                    'choices': ['message-digest', 'null']
                },
                'authentication_key': {
                    'type': 'str',
                },
                'message_digest_key': {
                    'type': 'int',
                },
                'md5': {
                    'type': 'str',
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'redistribute': {
            'type': 'dict',
            'redist_list': {
                'type': 'list',
                'ntype': {
                    'type':
                    'str',
                    'choices': [
                        'bgp', 'connected', 'floating-ip', 'ip-nat-list',
                        'lw4o6', 'nat-map', 'static-nat', 'isis', 'rip',
                        'static'
                    ]
                },
                'metric': {
                    'type': 'int',
                },
                'metric_type': {
                    'type': 'str',
                    'choices': ['1', '2']
                },
                'route_map': {
                    'type': 'str',
                },
                'tag': {
                    'type': 'int',
                }
            },
            'ospf_list': {
                'type': 'list',
                'ospf': {
                    'type': 'bool',
                },
                'process_id': {
                    'type': 'int',
                },
                'metric_ospf': {
                    'type': 'int',
                },
                'metric_type_ospf': {
                    'type': 'str',
                    'choices': ['1', '2']
                },
                'route_map_ospf': {
                    'type': 'str',
                },
                'tag_ospf': {
                    'type': 'int',
                }
            },
            'ip_nat': {
                'type': 'bool',
            },
            'metric_ip_nat': {
                'type': 'int',
            },
            'metric_type_ip_nat': {
                'type': 'str',
                'choices': ['1', '2']
            },
            'route_map_ip_nat': {
                'type': 'str',
            },
            'tag_ip_nat': {
                'type': 'int',
            },
            'ip_nat_floating_list': {
                'type': 'list',
                'ip_nat_prefix': {
                    'type': 'str',
                },
                'ip_nat_floating_IP_forward': {
                    'type': 'str',
                }
            },
            'vip_list': {
                'type': 'list',
                'type_vip': {
                    'type': 'str',
                    'choices': ['only-flagged', 'only-not-flagged']
                },
                'metric_vip': {
                    'type': 'int',
                },
                'metric_type_vip': {
                    'type': 'str',
                    'choices': ['1', '2']
                },
                'route_map_vip': {
                    'type': 'str',
                },
                'tag_vip': {
                    'type': 'int',
                }
            },
            'vip_floating_list': {
                'type': 'list',
                'vip_address': {
                    'type': 'str',
                },
                'vip_floating_IP_forward': {
                    'type': 'str',
                }
            },
            'uuid': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/ospf/{process-id}"

    f_dict = {}
    f_dict["process-id"] = module.params["process_id"]

    return url_base.format(**f_dict)


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


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
    url_base = "/axapi/v3/router/ospf/{process-id}"

    f_dict = {}
    f_dict["process-id"] = ""

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
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
        for k, v in payload["ospf"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["ospf"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["ospf"][k] = v
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
    payload = build_json("ospf", module)
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
