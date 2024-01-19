#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_interface_tunnel
description:
    - Tunnel interface
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
    ifnum:
        description:
        - "Tunnel interface number"
        type: int
        required: True
    name:
        description:
        - "Name for the interface"
        type: str
        required: False
    mtu:
        description:
        - "Interface mtu (Interface MTU, default 1 (min MTU is 1280 for IPv6))"
        type: int
        required: False
    action:
        description:
        - "'enable'= Enable; 'disable'= Disable;"
        type: str
        required: False
    speed:
        description:
        - "Speed in Gbit/Sec (Default 10 Gbps)"
        type: int
        required: False
    load_interval:
        description:
        - "Configure Load Interval (Seconds (5-300, Multiple of 5), default 300)"
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'num-rx-pkts'= received packets; 'num-total-rx-bytes'= received
          bytes; 'num-tx-pkts'= sent packets; 'num-total-tx-bytes'= sent bytes; 'num-rx-
          err-pkts'= received error packets; 'num-tx-err-pkts'= sent error packets;
          'rate_pkt_sent'= Packet sent rate packets/sec; 'rate_byte_sent'= Byte sent rate
          bits/sec; 'rate_pkt_rcvd'= Packet received rate packets/sec; 'rate_byte_rcvd'=
          Byte received rate bits/sec;"
                type: str
    packet_capture_template:
        description:
        - "Name of the packet capture template to be bind with this object"
        type: str
        required: False
    ip:
        description:
        - "Field ip"
        type: dict
        required: False
        suboptions:
            address:
                description:
                - "Field address"
                type: dict
            generate_membership_query:
                description:
                - "Enable Membership Query"
                type: bool
            generate_membership_query_val:
                description:
                - "1 - 255 (Default is 125)"
                type: int
            max_resp_time:
                description:
                - "Max Response Time (Default is 100)"
                type: int
            inside:
                description:
                - "Configure interface as inside"
                type: bool
            outside:
                description:
                - "Configure interface as outside"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
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
            address_cfg:
                description:
                - "Field address_cfg"
                type: list
            ipv6_enable:
                description:
                - "Enable IPv6 processing"
                type: bool
            inside:
                description:
                - "Configure interface as inside"
                type: bool
            outside:
                description:
                - "Configure interface as outside"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            router:
                description:
                - "Field router"
                type: dict
            ospf:
                description:
                - "Field ospf"
                type: dict
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
            config_speed:
                description:
                - "Field config_speed"
                type: int
            ipv4_address:
                description:
                - "IPv4 address"
                type: str
            ipv4_netmask:
                description:
                - "IPv4 subnet mask"
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
            ifnum:
                description:
                - "Tunnel interface number"
                type: int
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            num_rx_pkts:
                description:
                - "received packets"
                type: str
            num_total_rx_bytes:
                description:
                - "received bytes"
                type: str
            num_tx_pkts:
                description:
                - "sent packets"
                type: str
            num_total_tx_bytes:
                description:
                - "sent bytes"
                type: str
            num_rx_err_pkts:
                description:
                - "received error packets"
                type: str
            num_tx_err_pkts:
                description:
                - "sent error packets"
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
            ifnum:
                description:
                - "Tunnel interface number"
                type: int

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
AVAILABLE_PROPERTIES = ["action", "ifnum", "ip", "ipv6", "load_interval", "lw_4o6", "map", "mtu", "name", "oper", "packet_capture_template", "sampling_enable", "speed", "stats", "user_tag", "uuid", ]


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
        'ifnum': {
            'type': 'int',
            'required': True,
            },
        'name': {
            'type': 'str',
            },
        'mtu': {
            'type': 'int',
            },
        'action': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'speed': {
            'type': 'int',
            },
        'load_interval': {
            'type': 'int',
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
                'choices': ['all', 'num-rx-pkts', 'num-total-rx-bytes', 'num-tx-pkts', 'num-total-tx-bytes', 'num-rx-err-pkts', 'num-tx-err-pkts', 'rate_pkt_sent', 'rate_byte_sent', 'rate_pkt_rcvd', 'rate_byte_rcvd']
                }
            },
        'packet_capture_template': {
            'type': 'str',
            },
        'ip': {
            'type': 'dict',
            'address': {
                'type': 'dict',
                'dhcp': {
                    'type': 'bool',
                    },
                'ip_cfg': {
                    'type': 'list',
                    'ipv4_address': {
                        'type': 'str',
                        },
                    'ipv4_netmask': {
                        'type': 'str',
                        }
                    }
                },
            'generate_membership_query': {
                'type': 'bool',
                },
            'generate_membership_query_val': {
                'type': 'int',
                },
            'max_resp_time': {
                'type': 'int',
                },
            'inside': {
                'type': 'bool',
                },
            'outside': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
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
                        'choices': ['2']
                        }
                    },
                'receive_cfg': {
                    'type': 'dict',
                    'receive': {
                        'type': 'bool',
                        },
                    'version': {
                        'type': 'str',
                        'choices': ['2']
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
            'address_cfg': {
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
            'inside': {
                'type': 'bool',
                },
            'outside': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
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
                    }
                },
            'ospf': {
                'type': 'dict',
                'network_list': {
                    'type': 'list',
                    'broadcast_type': {
                        'type': 'str',
                        'choices': ['broadcast', 'non-broadcast', 'point-to-point', 'point-to-multipoint']
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
            'config_speed': {
                'type': 'int',
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
            'ifnum': {
                'type': 'int',
                'required': True,
                }
            },
        'stats': {
            'type': 'dict',
            'num_rx_pkts': {
                'type': 'str',
                },
            'num_total_rx_bytes': {
                'type': 'str',
                },
            'num_tx_pkts': {
                'type': 'str',
                },
            'num_total_tx_bytes': {
                'type': 'str',
                },
            'num_rx_err_pkts': {
                'type': 'str',
                },
            'num_tx_err_pkts': {
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
    url_base = "/axapi/v3/interface/tunnel/{ifnum}"

    f_dict = {}
    if '/' in str(module.params["ifnum"]):
        f_dict["ifnum"] = module.params["ifnum"].replace("/", "%2F")
    else:
        f_dict["ifnum"] = module.params["ifnum"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/interface/tunnel"

    f_dict = {}
    f_dict["ifnum"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["tunnel"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["tunnel"].get(k) != v:
            change_results["changed"] = True
            config_changes["tunnel"][k] = v

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
    payload = utils.build_json("tunnel", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["tunnel"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["tunnel-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["tunnel"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["tunnel"]["stats"] if info != "NotFound" else info
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
