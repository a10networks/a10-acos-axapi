#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_interface_ve
description:
    - Virtual ethernet interface
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
    ifnum:
        description:
        - "Virtual ethernet interface number"
        type: int
        required: True
    name:
        description:
        - "Name for the interface"
        type: str
        required: False
    l3_vlan_fwd_disable:
        description:
        - "Disable L3 forwarding between VLANs for incoming packets on this interface"
        type: bool
        required: False
    mtu:
        description:
        - "Interface mtu (Interface MTU, default 1 (min MTU is 1280 for IPv6))"
        type: int
        required: False
    trap_source:
        description:
        - "The trap source"
        type: bool
        required: False
    action:
        description:
        - "'enable'= Enable; 'disable'= Disable;"
        type: str
        required: False
    icmp_rate_limit:
        description:
        - "Field icmp_rate_limit"
        type: dict
        required: False
        suboptions:
            normal:
                description:
                - "Normal rate limit. If exceeds this limit, drop the ICMP packet that goes over
          the limit"
                type: int
            lockup:
                description:
                - "Enter lockup state when ICMP rate exceeds lockup rate limit (Maximum rate
          limit. If exceeds this limit, drop all ICMP packet for a time period)"
                type: int
            lockup_period:
                description:
                - "Lockup period (second)"
                type: int
    icmpv6_rate_limit:
        description:
        - "Field icmpv6_rate_limit"
        type: dict
        required: False
        suboptions:
            normal_v6:
                description:
                - "Normal rate limit. If exceeds this limit, drop the ICMP packet that goes over
          the limit"
                type: int
            lockup_v6:
                description:
                - "Enter lockup state when ICMP rate exceeds lockup rate limit (Maximum rate
          limit. If exceeds this limit, drop all ICMP packet for a time period)"
                type: int
            lockup_period_v6:
                description:
                - "Lockup period (second)"
                type: int
    access_list:
        description:
        - "Field access_list"
        type: dict
        required: False
        suboptions:
            acl_id:
                description:
                - "ACL id"
                type: int
            acl_name:
                description:
                - "Named Access List"
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
                - "'all'= all; 'num_pkts'= Input packets; 'num_total_bytes'= Input bytes;
          'num_unicast_pkts'= Received unicasts; 'num_broadcast_pkts'= Received
          broadcasts; 'num_multicast_pkts'= Received multicasts; 'num_tx_pkts'=
          Transmitted packets; 'num_total_tx_bytes'= Transmitted bytes;
          'num_unicast_tx_pkts'= Transmitted unicasts; 'num_broadcast_tx_pkts'=
          Transmitted broadcasts; 'num_multicast_tx_pkts'= Transmitted multicasts;
          'rate_pkt_sent'= Packet sent rate packets/sec; 'rate_byte_sent'= Byte sent rate
          bits/sec; 'rate_pkt_rcvd'= Packet received rate packets/sec; 'rate_byte_rcvd'=
          Byte received rate bits/sec; 'load_interval'= Load Interval;"
                type: str
    ip:
        description:
        - "Field ip"
        type: dict
        required: False
        suboptions:
            dhcp:
                description:
                - "Use DHCP to configure IP address"
                type: bool
            address_list:
                description:
                - "Field address_list"
                type: list
            allow_promiscuous_vip:
                description:
                - "Allow traffic to be associated with promiscuous VIP"
                type: bool
            client:
                description:
                - "Client facing interface for IPv4/v6 traffic"
                type: bool
            server:
                description:
                - "Server facing interface for IPv4/v6 traffic"
                type: bool
            helper_address_list:
                description:
                - "Field helper_address_list"
                type: list
            inside:
                description:
                - "Configure interface as inside"
                type: bool
            outside:
                description:
                - "Configure interface as outside"
                type: bool
            ttl_ignore:
                description:
                - "Ignore TTL decrement for a received packet"
                type: bool
            slb_partition_redirect:
                description:
                - "Redirect SLB traffic across partition"
                type: bool
            generate_membership_query:
                description:
                - "Enable Membership Query"
                type: bool
            query_interval:
                description:
                - "1 - 255 (Default is 125)"
                type: int
            max_resp_time:
                description:
                - "Maximum Response Time (Max Response Time (Default is 100))"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            stateful_firewall:
                description:
                - "Field stateful_firewall"
                type: dict
            router:
                description:
                - "Field router"
                type: dict
            rip:
                description:
                - "Field rip"
                type: dict
            ospf:
                description:
                - "Field ospf"
                type: dict
    ipv6:
        description:
        - "Field ipv6"
        type: dict
        required: False
        suboptions:
            address_list:
                description:
                - "Field address_list"
                type: list
            ipv6_enable:
                description:
                - "Enable IPv6 processing"
                type: bool
            v6_acl_name:
                description:
                - "Apply ACL rules to incoming packets on this interface (Named Access List)"
                type: str
            inbound:
                description:
                - "ACL applied on incoming packets to this interface"
                type: bool
            inside:
                description:
                - "Configure interface as NAT inside"
                type: bool
            outside:
                description:
                - "Configure interface as NAT outside"
                type: bool
            ttl_ignore:
                description:
                - "Ignore TTL decrement for a received packet"
                type: bool
            router_adver:
                description:
                - "Field router_adver"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
            stateful_firewall:
                description:
                - "Field stateful_firewall"
                type: dict
            router:
                description:
                - "Field router"
                type: dict
            rip:
                description:
                - "Field rip"
                type: dict
            ospf:
                description:
                - "Field ospf"
                type: dict
    ddos:
        description:
        - "Field ddos"
        type: dict
        required: False
        suboptions:
            outside:
                description:
                - "DDoS inside (trusted) or outside (untrusted) interface"
                type: bool
            inside:
                description:
                - "DDoS inside (trusted) or outside (untrusted) interface"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    nptv6:
        description:
        - "Field nptv6"
        type: dict
        required: False
        suboptions:
            domain_list:
                description:
                - "Field domain_list"
                type: list
    map:
        description:
        - "Field map"
        type: dict
        required: False
        suboptions:
            inside:
                description:
                - "Configure MAP inside interface (connected to MAP domains)"
                type: bool
            outside:
                description:
                - "Configure MAP outside interface"
                type: bool
            map_t_inside:
                description:
                - "Configure MAP inside interface (connected to MAP domains)"
                type: bool
            map_t_outside:
                description:
                - "Configure MAP outside interface"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    lw_4o6:
        description:
        - "Field lw_4o6"
        type: dict
        required: False
        suboptions:
            outside:
                description:
                - "Configure LW-4over6 inside interface"
                type: bool
            inside:
                description:
                - "Configure LW-4over6 outside interface"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    bfd:
        description:
        - "Field bfd"
        type: dict
        required: False
        suboptions:
            authentication:
                description:
                - "Field authentication"
                type: dict
            echo:
                description:
                - "Enable BFD Echo"
                type: bool
            demand:
                description:
                - "Demand mode"
                type: bool
            interval_cfg:
                description:
                - "Field interval_cfg"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
    isis:
        description:
        - "Field isis"
        type: dict
        required: False
        suboptions:
            authentication:
                description:
                - "Field authentication"
                type: dict
            bfd_cfg:
                description:
                - "Field bfd_cfg"
                type: dict
            circuit_type:
                description:
                - "'level-1'= Level-1 only adjacencies are formed; 'level-1-2'= Level-1-2
          adjacencies are formed; 'level-2-only'= Level-2 only adjacencies are formed;"
                type: str
            csnp_interval_list:
                description:
                - "Field csnp_interval_list"
                type: list
            padding:
                description:
                - "Add padding to IS-IS hello packets"
                type: bool
            hello_interval_list:
                description:
                - "Field hello_interval_list"
                type: list
            hello_interval_minimal_list:
                description:
                - "Field hello_interval_minimal_list"
                type: list
            hello_multiplier_list:
                description:
                - "Field hello_multiplier_list"
                type: list
            lsp_interval:
                description:
                - "Set LSP transmission interval (LSP transmission interval (milliseconds))"
                type: int
            mesh_group:
                description:
                - "Field mesh_group"
                type: dict
            metric_list:
                description:
                - "Field metric_list"
                type: list
            network:
                description:
                - "'broadcast'= Specify IS-IS broadcast multi-access network; 'point-to-point'=
          Specify IS-IS point-to-point network;"
                type: str
            password_list:
                description:
                - "Field password_list"
                type: list
            priority_list:
                description:
                - "Field priority_list"
                type: list
            retransmit_interval:
                description:
                - "Set per-LSP retransmission interval (Interval between retransmissions of the
          same LSP (seconds))"
                type: int
            wide_metric_list:
                description:
                - "Field wide_metric_list"
                type: list
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
            state:
                description:
                - "Field state"
                type: str
            line_protocol:
                description:
                - "Field line_protocol"
                type: str
            link_type:
                description:
                - "Field link_type"
                type: str
            mac:
                description:
                - "Field mac"
                type: str
            ipv4_address:
                description:
                - "IP address"
                type: str
            ipv4_netmask:
                description:
                - "IP subnet mask"
                type: str
            ipv6_link_local:
                description:
                - "Field ipv6_link_local"
                type: str
            ipv6_link_local_prefix:
                description:
                - "Field ipv6_link_local_prefix"
                type: str
            ipv6_link_local_type:
                description:
                - "Field ipv6_link_local_type"
                type: str
            ipv6_link_local_scope:
                description:
                - "Field ipv6_link_local_scope"
                type: str
            ipv4_addr_count:
                description:
                - "Field ipv4_addr_count"
                type: int
            ipv4_list:
                description:
                - "Field ipv4_list"
                type: list
            ipv6_addr_count:
                description:
                - "Field ipv6_addr_count"
                type: int
            ipv6_list:
                description:
                - "Field ipv6_list"
                type: list
            igmp_query_sent:
                description:
                - "Field igmp_query_sent"
                type: int
            icmp_rate_limit_current:
                description:
                - "Field icmp_rate_limit_current"
                type: int
            icmp_rate_over_limit_drop:
                description:
                - "Field icmp_rate_over_limit_drop"
                type: int
            icmp6_rate_limit_current:
                description:
                - "Field icmp6_rate_limit_current"
                type: int
            icmp6_rate_over_limit_drop:
                description:
                - "Field icmp6_rate_over_limit_drop"
                type: int
            user_trunk_id:
                description:
                - "Field user_trunk_id"
                type: int
            ifnum:
                description:
                - "Virtual ethernet interface number"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            num_pkts:
                description:
                - "Input packets"
                type: str
            num_total_bytes:
                description:
                - "Input bytes"
                type: str
            num_unicast_pkts:
                description:
                - "Received unicasts"
                type: str
            num_broadcast_pkts:
                description:
                - "Received broadcasts"
                type: str
            num_multicast_pkts:
                description:
                - "Received multicasts"
                type: str
            num_tx_pkts:
                description:
                - "Transmitted packets"
                type: str
            num_total_tx_bytes:
                description:
                - "Transmitted bytes"
                type: str
            num_unicast_tx_pkts:
                description:
                - "Transmitted unicasts"
                type: str
            num_broadcast_tx_pkts:
                description:
                - "Transmitted broadcasts"
                type: str
            num_multicast_tx_pkts:
                description:
                - "Transmitted multicasts"
                type: str
            rate_pkt_sent:
                description:
                - "Packet sent rate packets/sec"
                type: str
            rate_byte_sent:
                description:
                - "Byte sent rate bits/sec"
                type: str
            rate_pkt_rcvd:
                description:
                - "Packet received rate packets/sec"
                type: str
            rate_byte_rcvd:
                description:
                - "Byte received rate bits/sec"
                type: str
            load_interval:
                description:
                - "Load Interval"
                type: str
            ifnum:
                description:
                - "Virtual ethernet interface number"
                type: int

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
    "access_list",
    "action",
    "bfd",
    "ddos",
    "icmp_rate_limit",
    "icmpv6_rate_limit",
    "ifnum",
    "ip",
    "ipv6",
    "isis",
    "l3_vlan_fwd_disable",
    "lw_4o6",
    "map",
    "mtu",
    "name",
    "nptv6",
    "oper",
    "sampling_enable",
    "stats",
    "trap_source",
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
        'ifnum': {
            'type': 'int',
            'required': True,
        },
        'name': {
            'type': 'str',
        },
        'l3_vlan_fwd_disable': {
            'type': 'bool',
        },
        'mtu': {
            'type': 'int',
        },
        'trap_source': {
            'type': 'bool',
        },
        'action': {
            'type': 'str',
            'choices': ['enable', 'disable']
        },
        'icmp_rate_limit': {
            'type': 'dict',
            'normal': {
                'type': 'int',
            },
            'lockup': {
                'type': 'int',
            },
            'lockup_period': {
                'type': 'int',
            }
        },
        'icmpv6_rate_limit': {
            'type': 'dict',
            'normal_v6': {
                'type': 'int',
            },
            'lockup_v6': {
                'type': 'int',
            },
            'lockup_period_v6': {
                'type': 'int',
            }
        },
        'access_list': {
            'type': 'dict',
            'acl_id': {
                'type': 'int',
            },
            'acl_name': {
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
                'type':
                'str',
                'choices': [
                    'all', 'num_pkts', 'num_total_bytes', 'num_unicast_pkts',
                    'num_broadcast_pkts', 'num_multicast_pkts', 'num_tx_pkts',
                    'num_total_tx_bytes', 'num_unicast_tx_pkts',
                    'num_broadcast_tx_pkts', 'num_multicast_tx_pkts',
                    'rate_pkt_sent', 'rate_byte_sent', 'rate_pkt_rcvd',
                    'rate_byte_rcvd', 'load_interval'
                ]
            }
        },
        'ip': {
            'type': 'dict',
            'dhcp': {
                'type': 'bool',
            },
            'address_list': {
                'type': 'list',
                'ipv4_address': {
                    'type': 'str',
                },
                'ipv4_netmask': {
                    'type': 'str',
                }
            },
            'allow_promiscuous_vip': {
                'type': 'bool',
            },
            'client': {
                'type': 'bool',
            },
            'server': {
                'type': 'bool',
            },
            'helper_address_list': {
                'type': 'list',
                'helper_address': {
                    'type': 'str',
                }
            },
            'inside': {
                'type': 'bool',
            },
            'outside': {
                'type': 'bool',
            },
            'ttl_ignore': {
                'type': 'bool',
            },
            'slb_partition_redirect': {
                'type': 'bool',
            },
            'generate_membership_query': {
                'type': 'bool',
            },
            'query_interval': {
                'type': 'int',
            },
            'max_resp_time': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            },
            'stateful_firewall': {
                'type': 'dict',
                'inside': {
                    'type': 'bool',
                },
                'class_list': {
                    'type': 'str',
                },
                'outside': {
                    'type': 'bool',
                },
                'access_list': {
                    'type': 'bool',
                },
                'acl_id': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'router': {
                'type': 'dict',
                'isis': {
                    'type': 'dict',
                    'tag': {
                        'type': 'str',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                }
            },
            'rip': {
                'type': 'dict',
                'authentication': {
                    'type': 'dict',
                    'str': {
                        'type': 'dict',
                        'string': {
                            'type': 'str',
                        }
                    },
                    'mode': {
                        'type': 'dict',
                        'mode': {
                            'type': 'str',
                            'choices': ['md5', 'text']
                        }
                    },
                    'key_chain': {
                        'type': 'dict',
                        'key_chain': {
                            'type': 'str',
                        }
                    }
                },
                'send_packet': {
                    'type': 'bool',
                },
                'receive_packet': {
                    'type': 'bool',
                },
                'send_cfg': {
                    'type': 'dict',
                    'send': {
                        'type': 'bool',
                    },
                    'version': {
                        'type': 'str',
                        'choices': ['1', '2', '1-compatible', '1-2']
                    }
                },
                'receive_cfg': {
                    'type': 'dict',
                    'receive': {
                        'type': 'bool',
                    },
                    'version': {
                        'type': 'str',
                        'choices': ['1', '2', '1-2']
                    }
                },
                'split_horizon_cfg': {
                    'type': 'dict',
                    'state': {
                        'type': 'str',
                        'choices': ['poisoned', 'disable', 'enable']
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'ospf': {
                'type': 'dict',
                'ospf_global': {
                    'type': 'dict',
                    'authentication_cfg': {
                        'type': 'dict',
                        'authentication': {
                            'type': 'bool',
                        },
                        'value': {
                            'type': 'str',
                            'choices': ['message-digest', 'null']
                        }
                    },
                    'authentication_key': {
                        'type': 'str',
                    },
                    'bfd_cfg': {
                        'type': 'dict',
                        'bfd': {
                            'type': 'bool',
                        },
                        'disable': {
                            'type': 'bool',
                        }
                    },
                    'cost': {
                        'type': 'int',
                    },
                    'database_filter_cfg': {
                        'type': 'dict',
                        'database_filter': {
                            'type': 'str',
                            'choices': ['all']
                        },
                        'out': {
                            'type': 'bool',
                        }
                    },
                    'dead_interval': {
                        'type': 'int',
                    },
                    'disable': {
                        'type': 'str',
                        'choices': ['all']
                    },
                    'hello_interval': {
                        'type': 'int',
                    },
                    'message_digest_cfg': {
                        'type': 'list',
                        'message_digest_key': {
                            'type': 'int',
                        },
                        'md5': {
                            'type': 'dict',
                            'md5_value': {
                                'type': 'str',
                            },
                            'encrypted': {
                                'type': 'str',
                            }
                        }
                    },
                    'mtu': {
                        'type': 'int',
                    },
                    'mtu_ignore': {
                        'type': 'bool',
                    },
                    'network': {
                        'type': 'dict',
                        'broadcast': {
                            'type': 'bool',
                        },
                        'non_broadcast': {
                            'type': 'bool',
                        },
                        'point_to_point': {
                            'type': 'bool',
                        },
                        'point_to_multipoint': {
                            'type': 'bool',
                        },
                        'p2mp_nbma': {
                            'type': 'bool',
                        }
                    },
                    'priority': {
                        'type': 'int',
                    },
                    'retransmit_interval': {
                        'type': 'int',
                    },
                    'transmit_delay': {
                        'type': 'int',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                },
                'ospf_ip_list': {
                    'type': 'list',
                    'ip_addr': {
                        'type': 'str',
                        'required': True,
                    },
                    'authentication': {
                        'type': 'bool',
                    },
                    'value': {
                        'type': 'str',
                        'choices': ['message-digest', 'null']
                    },
                    'authentication_key': {
                        'type': 'str',
                    },
                    'cost': {
                        'type': 'int',
                    },
                    'database_filter': {
                        'type': 'str',
                        'choices': ['all']
                    },
                    'out': {
                        'type': 'bool',
                    },
                    'dead_interval': {
                        'type': 'int',
                    },
                    'hello_interval': {
                        'type': 'int',
                    },
                    'message_digest_cfg': {
                        'type': 'list',
                        'message_digest_key': {
                            'type': 'int',
                        },
                        'md5_value': {
                            'type': 'str',
                        },
                        'encrypted': {
                            'type': 'str',
                        }
                    },
                    'mtu_ignore': {
                        'type': 'bool',
                    },
                    'priority': {
                        'type': 'int',
                    },
                    'retransmit_interval': {
                        'type': 'int',
                    },
                    'transmit_delay': {
                        'type': 'int',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                }
            }
        },
        'ipv6': {
            'type': 'dict',
            'address_list': {
                'type': 'list',
                'ipv6_addr': {
                    'type': 'str',
                },
                'address_type': {
                    'type': 'str',
                    'choices': ['anycast', 'link-local']
                }
            },
            'ipv6_enable': {
                'type': 'bool',
            },
            'v6_acl_name': {
                'type': 'str',
            },
            'inbound': {
                'type': 'bool',
            },
            'inside': {
                'type': 'bool',
            },
            'outside': {
                'type': 'bool',
            },
            'ttl_ignore': {
                'type': 'bool',
            },
            'router_adver': {
                'type': 'dict',
                'action': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                },
                'default_lifetime': {
                    'type': 'int',
                },
                'hop_limit': {
                    'type': 'int',
                },
                'max_interval': {
                    'type': 'int',
                },
                'min_interval': {
                    'type': 'int',
                },
                'rate_limit': {
                    'type': 'int',
                },
                'reachable_time': {
                    'type': 'int',
                },
                'retransmit_timer': {
                    'type': 'int',
                },
                'adver_mtu_disable': {
                    'type': 'bool',
                },
                'adver_mtu': {
                    'type': 'int',
                },
                'prefix_list': {
                    'type': 'list',
                    'prefix': {
                        'type': 'str',
                    },
                    'not_autonomous': {
                        'type': 'bool',
                    },
                    'not_on_link': {
                        'type': 'bool',
                    },
                    'preferred_lifetime': {
                        'type': 'int',
                    },
                    'valid_lifetime': {
                        'type': 'int',
                    }
                },
                'managed_config_action': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                },
                'other_config_action': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                },
                'adver_vrid': {
                    'type': 'int',
                },
                'use_floating_ip': {
                    'type': 'bool',
                },
                'floating_ip': {
                    'type': 'str',
                },
                'adver_vrid_default': {
                    'type': 'bool',
                },
                'use_floating_ip_default_vrid': {
                    'type': 'bool',
                },
                'floating_ip_default_vrid': {
                    'type': 'str',
                }
            },
            'uuid': {
                'type': 'str',
            },
            'stateful_firewall': {
                'type': 'dict',
                'inside': {
                    'type': 'bool',
                },
                'class_list': {
                    'type': 'str',
                },
                'outside': {
                    'type': 'bool',
                },
                'access_list': {
                    'type': 'bool',
                },
                'acl_name': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'router': {
                'type': 'dict',
                'ripng': {
                    'type': 'dict',
                    'rip': {
                        'type': 'bool',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                },
                'ospf': {
                    'type': 'dict',
                    'area_list': {
                        'type': 'list',
                        'area_id_num': {
                            'type': 'int',
                        },
                        'area_id_addr': {
                            'type': 'str',
                        },
                        'tag': {
                            'type': 'str',
                        },
                        'instance_id': {
                            'type': 'int',
                        }
                    },
                    'uuid': {
                        'type': 'str',
                    }
                },
                'isis': {
                    'type': 'dict',
                    'tag': {
                        'type': 'str',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                }
            },
            'rip': {
                'type': 'dict',
                'split_horizon_cfg': {
                    'type': 'dict',
                    'state': {
                        'type': 'str',
                        'choices': ['poisoned', 'disable', 'enable']
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'ospf': {
                'type': 'dict',
                'network_list': {
                    'type': 'list',
                    'broadcast_type': {
                        'type':
                        'str',
                        'choices': [
                            'broadcast', 'non-broadcast', 'point-to-point',
                            'point-to-multipoint'
                        ]
                    },
                    'p2mp_nbma': {
                        'type': 'bool',
                    },
                    'network_instance_id': {
                        'type': 'int',
                    }
                },
                'bfd': {
                    'type': 'bool',
                },
                'disable': {
                    'type': 'bool',
                },
                'cost_cfg': {
                    'type': 'list',
                    'cost': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'dead_interval_cfg': {
                    'type': 'list',
                    'dead_interval': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'hello_interval_cfg': {
                    'type': 'list',
                    'hello_interval': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'mtu_ignore_cfg': {
                    'type': 'list',
                    'mtu_ignore': {
                        'type': 'bool',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'neighbor_cfg': {
                    'type': 'list',
                    'neighbor': {
                        'type': 'str',
                    },
                    'neig_inst': {
                        'type': 'int',
                    },
                    'neighbor_cost': {
                        'type': 'int',
                    },
                    'neighbor_poll_interval': {
                        'type': 'int',
                    },
                    'neighbor_priority': {
                        'type': 'int',
                    }
                },
                'priority_cfg': {
                    'type': 'list',
                    'priority': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'retransmit_interval_cfg': {
                    'type': 'list',
                    'retransmit_interval': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'transmit_delay_cfg': {
                    'type': 'list',
                    'transmit_delay': {
                        'type': 'int',
                    },
                    'instance_id': {
                        'type': 'int',
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            }
        },
        'ddos': {
            'type': 'dict',
            'outside': {
                'type': 'bool',
            },
            'inside': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'nptv6': {
            'type': 'dict',
            'domain_list': {
                'type': 'list',
                'domain_name': {
                    'type': 'str',
                    'required': True,
                },
                'bind_type': {
                    'type': 'str',
                    'required': True,
                    'choices': ['inside', 'outside']
                },
                'uuid': {
                    'type': 'str',
                }
            }
        },
        'map': {
            'type': 'dict',
            'inside': {
                'type': 'bool',
            },
            'outside': {
                'type': 'bool',
            },
            'map_t_inside': {
                'type': 'bool',
            },
            'map_t_outside': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'lw_4o6': {
            'type': 'dict',
            'outside': {
                'type': 'bool',
            },
            'inside': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'bfd': {
            'type': 'dict',
            'authentication': {
                'type': 'dict',
                'key_id': {
                    'type': 'int',
                },
                'method': {
                    'type':
                    'str',
                    'choices': [
                        'md5', 'meticulous-md5', 'meticulous-sha1', 'sha1',
                        'simple'
                    ]
                },
                'password': {
                    'type': 'str',
                },
                'encrypted': {
                    'type': 'str',
                }
            },
            'echo': {
                'type': 'bool',
            },
            'demand': {
                'type': 'bool',
            },
            'interval_cfg': {
                'type': 'dict',
                'interval': {
                    'type': 'int',
                },
                'min_rx': {
                    'type': 'int',
                },
                'multiplier': {
                    'type': 'int',
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'isis': {
            'type': 'dict',
            'authentication': {
                'type': 'dict',
                'send_only_list': {
                    'type': 'list',
                    'send_only': {
                        'type': 'bool',
                    },
                    'level': {
                        'type': 'str',
                        'choices': ['level-1', 'level-2']
                    }
                },
                'mode_list': {
                    'type': 'list',
                    'mode': {
                        'type': 'str',
                        'choices': ['md5']
                    },
                    'level': {
                        'type': 'str',
                        'choices': ['level-1', 'level-2']
                    }
                },
                'key_chain_list': {
                    'type': 'list',
                    'key_chain': {
                        'type': 'str',
                    },
                    'level': {
                        'type': 'str',
                        'choices': ['level-1', 'level-2']
                    }
                }
            },
            'bfd_cfg': {
                'type': 'dict',
                'bfd': {
                    'type': 'bool',
                },
                'disable': {
                    'type': 'bool',
                }
            },
            'circuit_type': {
                'type': 'str',
                'choices': ['level-1', 'level-1-2', 'level-2-only']
            },
            'csnp_interval_list': {
                'type': 'list',
                'csnp_interval': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'padding': {
                'type': 'bool',
            },
            'hello_interval_list': {
                'type': 'list',
                'hello_interval': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'hello_interval_minimal_list': {
                'type': 'list',
                'hello_interval_minimal': {
                    'type': 'bool',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'hello_multiplier_list': {
                'type': 'list',
                'hello_multiplier': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'lsp_interval': {
                'type': 'int',
            },
            'mesh_group': {
                'type': 'dict',
                'value': {
                    'type': 'int',
                },
                'blocked': {
                    'type': 'bool',
                }
            },
            'metric_list': {
                'type': 'list',
                'metric': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'network': {
                'type': 'str',
                'choices': ['broadcast', 'point-to-point']
            },
            'password_list': {
                'type': 'list',
                'password': {
                    'type': 'str',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'priority_list': {
                'type': 'list',
                'priority': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'retransmit_interval': {
                'type': 'int',
            },
            'wide_metric_list': {
                'type': 'list',
                'wide_metric': {
                    'type': 'int',
                },
                'level': {
                    'type': 'str',
                    'choices': ['level-1', 'level-2']
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'oper': {
            'type': 'dict',
            'state': {
                'type': 'str',
                'choices': ['up', 'disabled', 'down']
            },
            'line_protocol': {
                'type': 'str',
                'choices': ['up', 'down']
            },
            'link_type': {
                'type': 'str',
            },
            'mac': {
                'type': 'str',
            },
            'ipv4_address': {
                'type': 'str',
            },
            'ipv4_netmask': {
                'type': 'str',
            },
            'ipv6_link_local': {
                'type': 'str',
            },
            'ipv6_link_local_prefix': {
                'type': 'str',
            },
            'ipv6_link_local_type': {
                'type': 'str',
            },
            'ipv6_link_local_scope': {
                'type': 'str',
            },
            'ipv4_addr_count': {
                'type': 'int',
            },
            'ipv4_list': {
                'type': 'list',
                'addr': {
                    'type': 'str',
                },
                'mask': {
                    'type': 'str',
                }
            },
            'ipv6_addr_count': {
                'type': 'int',
            },
            'ipv6_list': {
                'type': 'list',
                'addr': {
                    'type': 'str',
                },
                'prefix': {
                    'type': 'str',
                },
                'is_anycast': {
                    'type': 'int',
                }
            },
            'igmp_query_sent': {
                'type': 'int',
            },
            'icmp_rate_limit_current': {
                'type': 'int',
            },
            'icmp_rate_over_limit_drop': {
                'type': 'int',
            },
            'icmp6_rate_limit_current': {
                'type': 'int',
            },
            'icmp6_rate_over_limit_drop': {
                'type': 'int',
            },
            'user_trunk_id': {
                'type': 'int',
            },
            'ifnum': {
                'type': 'int',
                'required': True,
            }
        },
        'stats': {
            'type': 'dict',
            'num_pkts': {
                'type': 'str',
            },
            'num_total_bytes': {
                'type': 'str',
            },
            'num_unicast_pkts': {
                'type': 'str',
            },
            'num_broadcast_pkts': {
                'type': 'str',
            },
            'num_multicast_pkts': {
                'type': 'str',
            },
            'num_tx_pkts': {
                'type': 'str',
            },
            'num_total_tx_bytes': {
                'type': 'str',
            },
            'num_unicast_tx_pkts': {
                'type': 'str',
            },
            'num_broadcast_tx_pkts': {
                'type': 'str',
            },
            'num_multicast_tx_pkts': {
                'type': 'str',
            },
            'rate_pkt_sent': {
                'type': 'str',
            },
            'rate_byte_sent': {
                'type': 'str',
            },
            'rate_pkt_rcvd': {
                'type': 'str',
            },
            'rate_byte_rcvd': {
                'type': 'str',
            },
            'load_interval': {
                'type': 'str',
            },
            'ifnum': {
                'type': 'int',
                'required': True,
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/ve/{ifnum}"

    f_dict = {}
    f_dict["ifnum"] = module.params["ifnum"]

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
    url_base = "/axapi/v3/interface/ve/{ifnum}"

    f_dict = {}
    f_dict["ifnum"] = ""

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
        for k, v in payload["ve"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["ve"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["ve"][k] = v
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
    payload = build_json("ve", module)
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
