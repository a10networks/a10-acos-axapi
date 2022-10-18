#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_router_bgp
description:
    - Border Gateway Protocol (BGP)
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
    as_number:
        description:
        - "AS number"
        type: int
        required: True
    aggregate_address_list:
        description:
        - "Field aggregate_address_list"
        type: list
        required: False
        suboptions:
            aggregate_address:
                description:
                - "Configure BGP aggregate entries (Aggregate prefix)"
                type: str
            as_set:
                description:
                - "Generate AS set path information"
                type: bool
            summary_only:
                description:
                - "Filter more specific routes from updates"
                type: bool
    bgp:
        description:
        - "Field bgp"
        type: dict
        required: False
        suboptions:
            always_compare_med:
                description:
                - "Allow comparing MED from different neighbors"
                type: bool
            bestpath_cfg:
                description:
                - "Field bestpath_cfg"
                type: dict
            dampening_cfg:
                description:
                - "Field dampening_cfg"
                type: dict
            local_preference_value:
                description:
                - "Configure default local preference value"
                type: int
            deterministic_med:
                description:
                - "Pick the best-MED path among paths advertised from the neighboring AS"
                type: bool
            enforce_first_as:
                description:
                - "Enforce the first AS for EBGP routes"
                type: bool
            fast_external_failover:
                description:
                - "Immediately reset session if a link to a directly connected external peer goes
          down"
                type: bool
            log_neighbor_changes:
                description:
                - "Log neighbor up/down and reset reason"
                type: bool
            nexthop_trigger_count:
                description:
                - "BGP nexthop-tracking status (count)"
                type: int
            router_id:
                description:
                - "Override current router identifier (peers will reset) (Manually configured
          router identifier)"
                type: str
            override_validation:
                description:
                - "override router-id validation"
                type: bool
            scan_time:
                description:
                - "Configure background scan interval (Scan interval (sec) [Default=60 Disable=0])"
                type: int
            graceful_restart:
                description:
                - "Configure BGP BGP Graceful Restart"
                type: bool
            bgp_restart_time:
                description:
                - "BGP Peer Graceful Restart time in seconds (default 90)"
                type: int
            bgp_stalepath_time:
                description:
                - "BGP Graceful Restart Stalepath retention time in seconds (default 360)"
                type: int
    distance_list:
        description:
        - "Field distance_list"
        type: list
        required: False
        suboptions:
            admin_distance:
                description:
                - "Define an administrative distance"
                type: int
            src_prefix:
                description:
                - "IP source prefix"
                type: str
            acl_str:
                description:
                - "Access list name"
                type: str
            ext_routes_dist:
                description:
                - "Distance for routes external to the AS"
                type: int
            int_routes_dist:
                description:
                - "Distance for routes internal to the AS"
                type: int
            local_routes_dist:
                description:
                - "Distance for local routes"
                type: int
    maximum_paths_value:
        description:
        - "Supported BGP multipath numbers"
        type: int
        required: False
    originate:
        description:
        - "Distribute a default route"
        type: bool
        required: False
    timers:
        description:
        - "Field timers"
        type: dict
        required: False
        suboptions:
            bgp_keepalive:
                description:
                - "Keepalive interval"
                type: int
            bgp_holdtime:
                description:
                - "Holdtime"
                type: int
    synchronization:
        description:
        - "Perform IGP synchronization"
        type: bool
        required: False
    auto_summary:
        description:
        - "Enable automatic network number summarization"
        type: bool
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
    network:
        description:
        - "Field network"
        type: dict
        required: False
        suboptions:
            synchronization:
                description:
                - "Field synchronization"
                type: dict
            ip_cidr_list:
                description:
                - "Field ip_cidr_list"
                type: list
    neighbor:
        description:
        - "Field neighbor"
        type: dict
        required: False
        suboptions:
            peer_group_neighbor_list:
                description:
                - "Field peer_group_neighbor_list"
                type: list
            ipv4_neighbor_list:
                description:
                - "Field ipv4_neighbor_list"
                type: list
            ipv6_neighbor_list:
                description:
                - "Field ipv6_neighbor_list"
                type: list
            ethernet_neighbor_list:
                description:
                - "Field ethernet_neighbor_list"
                type: list
            ve_neighbor_list:
                description:
                - "Field ve_neighbor_list"
                type: list
            trunk_neighbor_list:
                description:
                - "Field trunk_neighbor_list"
                type: list
    redistribute:
        description:
        - "Field redistribute"
        type: dict
        required: False
        suboptions:
            connected_cfg:
                description:
                - "Field connected_cfg"
                type: dict
            floating_ip_cfg:
                description:
                - "Field floating_ip_cfg"
                type: dict
            lw4o6_cfg:
                description:
                - "Field lw4o6_cfg"
                type: dict
            static_nat_cfg:
                description:
                - "Field static_nat_cfg"
                type: dict
            ip_nat_cfg:
                description:
                - "Field ip_nat_cfg"
                type: dict
            ip_nat_list_cfg:
                description:
                - "Field ip_nat_list_cfg"
                type: dict
            isis_cfg:
                description:
                - "Field isis_cfg"
                type: dict
            ospf_cfg:
                description:
                - "Field ospf_cfg"
                type: dict
            rip_cfg:
                description:
                - "Field rip_cfg"
                type: dict
            static_cfg:
                description:
                - "Field static_cfg"
                type: dict
            nat_map_cfg:
                description:
                - "Field nat_map_cfg"
                type: dict
            vip:
                description:
                - "Field vip"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
    address_family:
        description:
        - "Field address_family"
        type: dict
        required: False
        suboptions:
            ipv6:
                description:
                - "Field ipv6"
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
AVAILABLE_PROPERTIES = ["address_family", "aggregate_address_list", "as_number", "auto_summary", "bgp", "distance_list", "maximum_paths_value", "neighbor", "network", "originate", "redistribute", "synchronization", "timers", "user_tag", "uuid", ]


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
        'as_number': {
            'type': 'int',
            'required': True,
            },
        'aggregate_address_list': {
            'type': 'list',
            'aggregate_address': {
                'type': 'str',
                },
            'as_set': {
                'type': 'bool',
                },
            'summary_only': {
                'type': 'bool',
                }
            },
        'bgp': {
            'type': 'dict',
            'always_compare_med': {
                'type': 'bool',
                },
            'bestpath_cfg': {
                'type': 'dict',
                'ignore': {
                    'type': 'bool',
                    },
                'compare_routerid': {
                    'type': 'bool',
                    },
                'remove_recv_med': {
                    'type': 'bool',
                    },
                'remove_send_med': {
                    'type': 'bool',
                    },
                'missing_as_worst': {
                    'type': 'bool',
                    }
                },
            'dampening_cfg': {
                'type': 'dict',
                'dampening': {
                    'type': 'bool',
                    },
                'dampening_half_time': {
                    'type': 'int',
                    },
                'dampening_reuse': {
                    'type': 'int',
                    },
                'dampening_supress': {
                    'type': 'int',
                    },
                'dampening_max_supress': {
                    'type': 'int',
                    },
                'dampening_penalty': {
                    'type': 'int',
                    },
                'route_map': {
                    'type': 'str',
                    }
                },
            'local_preference_value': {
                'type': 'int',
                },
            'deterministic_med': {
                'type': 'bool',
                },
            'enforce_first_as': {
                'type': 'bool',
                },
            'fast_external_failover': {
                'type': 'bool',
                },
            'log_neighbor_changes': {
                'type': 'bool',
                },
            'nexthop_trigger_count': {
                'type': 'int',
                },
            'router_id': {
                'type': 'str',
                },
            'override_validation': {
                'type': 'bool',
                },
            'scan_time': {
                'type': 'int',
                },
            'graceful_restart': {
                'type': 'bool',
                },
            'bgp_restart_time': {
                'type': 'int',
                },
            'bgp_stalepath_time': {
                'type': 'int',
                }
            },
        'distance_list': {
            'type': 'list',
            'admin_distance': {
                'type': 'int',
                },
            'src_prefix': {
                'type': 'str',
                },
            'acl_str': {
                'type': 'str',
                },
            'ext_routes_dist': {
                'type': 'int',
                },
            'int_routes_dist': {
                'type': 'int',
                },
            'local_routes_dist': {
                'type': 'int',
                }
            },
        'maximum_paths_value': {
            'type': 'int',
            },
        'originate': {
            'type': 'bool',
            },
        'timers': {
            'type': 'dict',
            'bgp_keepalive': {
                'type': 'int',
                },
            'bgp_holdtime': {
                'type': 'int',
                }
            },
        'synchronization': {
            'type': 'bool',
            },
        'auto_summary': {
            'type': 'bool',
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'network': {
            'type': 'dict',
            'synchronization': {
                'type': 'dict',
                'network_synchronization': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'ip_cidr_list': {
                'type': 'list',
                'network_ipv4_cidr': {
                    'type': 'str',
                    'required': True,
                    },
                'route_map': {
                    'type': 'str',
                    },
                'backdoor': {
                    'type': 'bool',
                    },
                'description': {
                    'type': 'str',
                    },
                'comm_value': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'neighbor': {
            'type': 'dict',
            'peer_group_neighbor_list': {
                'type': 'list',
                'peer_group': {
                    'type': 'str',
                    'required': True,
                    },
                'peer_group_key': {
                    'type': 'bool',
                    },
                'peer_group_remote_as': {
                    'type': 'int',
                    },
                'activate': {
                    'type': 'bool',
                    },
                'advertisement_interval': {
                    'type': 'int',
                    },
                'allowas_in': {
                    'type': 'bool',
                    },
                'allowas_in_count': {
                    'type': 'int',
                    },
                'as_origination_interval': {
                    'type': 'int',
                    },
                'dynamic': {
                    'type': 'bool',
                    },
                'prefix_list_direction': {
                    'type': 'str',
                    'choices': ['both', 'receive', 'send']
                    },
                'route_refresh': {
                    'type': 'bool',
                    },
                'extended_nexthop': {
                    'type': 'bool',
                    },
                'collide_established': {
                    'type': 'bool',
                    },
                'default_originate': {
                    'type': 'bool',
                    },
                'route_map': {
                    'type': 'str',
                    },
                'description': {
                    'type': 'str',
                    },
                'disallow_infinite_holdtime': {
                    'type': 'bool',
                    },
                'distribute_lists': {
                    'type': 'list',
                    'distribute_list': {
                        'type': 'str',
                        },
                    'distribute_list_direction': {
                        'type': 'str',
                        'choices': ['in', 'out']
                        }
                    },
                'dont_capability_negotiate': {
                    'type': 'bool',
                    },
                'ebgp_multihop': {
                    'type': 'bool',
                    },
                'ebgp_multihop_hop_count': {
                    'type': 'int',
                    },
                'enforce_multihop': {
                    'type': 'bool',
                    },
                'bfd': {
                    'type': 'bool',
                    },
                'multihop': {
                    'type': 'bool',
                    },
                'neighbor_filter_lists': {
                    'type': 'list',
                    'filter_list': {
                        'type': 'str',
                        },
                    'filter_list_direction': {
                        'type': 'str',
                        'choices': ['in', 'out']
                        }
                    },
                'maximum_prefix': {
                    'type': 'int',
                    },
                'maximum_prefix_thres': {
                    'type': 'int',
                    },
                'next_hop_self': {
                    'type': 'bool',
                    },
                'override_capability': {
                    'type': 'bool',
                    },
                'pass_value': {
                    'type': 'str',
                    },
                'pass_encrypted': {
                    'type': 'str',
                    },
                'passive': {
                    'type': 'bool',
                    },
                'neighbor_prefix_lists': {
                    'type': 'list',
                    'nbr_prefix_list': {
                        'type': 'str',
                        },
                    'nbr_prefix_list_direction': {
                        'type': 'str',
                        'choices': ['in', 'out']
                        }
                    },
                'remove_private_as': {
                    'type': 'bool',
                    },
                'neighbor_route_map_lists': {
                    'type': 'list',
                    'nbr_route_map': {
                        'type': 'str',
                        },
                    'nbr_rmap_direction': {
                        'type': 'str',
                        'choices': ['in', 'out']
                        }
                    },
                'send_community_val': {
                    'type': 'str',
                    'choices': ['both', 'none', 'standard', 'extended']
                    },
                'inbound': {
                    'type': 'bool',
                    },
                'shutdown': {
                    'type': 'bool',
                    },
                'strict_capability_match': {
                    'type': 'bool',
                    },
                'timers_keepalive': {
                    'type': 'int',
                    },
                'timers_holdtime': {
                    'type': 'int',
                    },
                'connect': {
                    'type': 'int',
                    },
                'unsuppress_map': {
                    'type': 'str',
                    },
                'update_source_ip': {
                    'type': 'str',
                    },
                'update_source_ipv6': {
                    'type': 'str',
                    },
                'ethernet': {
                    'type': 'str',
                    },
                'loopback': {
                    'type': 'str',
                    },
                've': {
                    'type': 'str',
                    },
                'trunk': {
                    'type': 'str',
                    },
                'lif': {
                    'type': 'str',
                    },
                'tunnel': {
                    'type': 'str',
                    },
                'weight': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'ipv4_neighbor_list': {
                'type': 'list',
                'neighbor_ipv4': {
                    'type': 'str',
                    'required': True,
                    },
                'nbr_remote_as': {
                    'type': 'int',
                    },
                'peer_group_name': {
                    'type': 'str',
                    },
                'activate': {
                    'type': 'bool',
                    },
                'advertisement_interval': {
                    'type': 'int',
                    },
                'allowas_in': {
                    'type': 'bool',
                    },
                'allowas_in_count': {
                    'type': 'int',
                    },
                'as_origination_interval': {
                    'type': 'int',
                    },
                'dynamic': {
                    'type': 'bool',
                    },
                'prefix_list_direction': {
                    'type': 'str',
                    'choices': ['both', 'receive', 'send']
                    },
                'route_refresh': {
                    'type': 'bool',
                    },
                'graceful_restart': {
                    'type': 'bool',
                    },
                'collide_established': {
                    'type': 'bool',
                    },
                'default_originate': {
                    'type': 'bool',
                    },
                'route_map': {
                    'type': 'str',
                    },
                'description': {
                    'type': 'str',
                    },
                'disallow_infinite_holdtime': {
                    'type': 'bool',
                    },
                'distribute_lists': {
                    'type': 'list',
                    'distribute_list': {
                        'type': 'str',
                        },
                    'distribute_list_direction': {
                        'type': 'str',
                        'choices': ['in', 'out']
                        }
                    },
                'acos_application_only': {
                    'type': 'bool',
                    },
                'dont_capability_negotiate': {
                    'type': 'bool',
                    },
                'ebgp_multihop': {
                    'type': 'bool',
                    },
                'ebgp_multihop_hop_count': {
                    'type': 'int',
                    },
                'enforce_multihop': {
                    'type': 'bool',
                    },
                'bfd': {
                    'type': 'bool',
                    },
                'multihop': {
                    'type': 'bool',
                    },
                'key_id': {
                    'type': 'int',
                    },
                'key_type': {
                    'type': 'str',
                    'choices': ['md5', 'meticulous-md5', 'meticulous-sha1', 'sha1', 'simple']
                    },
                'bfd_value': {
                    'type': 'str',
                    },
                'bfd_encrypted': {
                    'type': 'str',
                    },
                'neighbor_filter_lists': {
                    'type': 'list',
                    'filter_list': {
                        'type': 'str',
                        },
                    'filter_list_direction': {
                        'type': 'str',
                        'choices': ['in', 'out']
                        }
                    },
                'maximum_prefix': {
                    'type': 'int',
                    },
                'maximum_prefix_thres': {
                    'type': 'int',
                    },
                'restart_min': {
                    'type': 'int',
                    },
                'next_hop_self': {
                    'type': 'bool',
                    },
                'override_capability': {
                    'type': 'bool',
                    },
                'pass_value': {
                    'type': 'str',
                    },
                'pass_encrypted': {
                    'type': 'str',
                    },
                'passive': {
                    'type': 'bool',
                    },
                'neighbor_prefix_lists': {
                    'type': 'list',
                    'nbr_prefix_list': {
                        'type': 'str',
                        },
                    'nbr_prefix_list_direction': {
                        'type': 'str',
                        'choices': ['in', 'out']
                        }
                    },
                'remove_private_as': {
                    'type': 'bool',
                    },
                'neighbor_route_map_lists': {
                    'type': 'list',
                    'nbr_route_map': {
                        'type': 'str',
                        },
                    'nbr_rmap_direction': {
                        'type': 'str',
                        'choices': ['in', 'out']
                        }
                    },
                'send_community_val': {
                    'type': 'str',
                    'choices': ['both', 'none', 'standard', 'extended']
                    },
                'inbound': {
                    'type': 'bool',
                    },
                'shutdown': {
                    'type': 'bool',
                    },
                'strict_capability_match': {
                    'type': 'bool',
                    },
                'timers_keepalive': {
                    'type': 'int',
                    },
                'timers_holdtime': {
                    'type': 'int',
                    },
                'connect': {
                    'type': 'int',
                    },
                'unsuppress_map': {
                    'type': 'str',
                    },
                'update_source_ip': {
                    'type': 'str',
                    },
                'update_source_ipv6': {
                    'type': 'str',
                    },
                'ethernet': {
                    'type': 'str',
                    },
                'loopback': {
                    'type': 'str',
                    },
                've': {
                    'type': 'str',
                    },
                'trunk': {
                    'type': 'str',
                    },
                'lif': {
                    'type': 'str',
                    },
                'tunnel': {
                    'type': 'str',
                    },
                'weight': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'ipv6_neighbor_list': {
                'type': 'list',
                'neighbor_ipv6': {
                    'type': 'str',
                    'required': True,
                    },
                'nbr_remote_as': {
                    'type': 'int',
                    },
                'peer_group_name': {
                    'type': 'str',
                    },
                'activate': {
                    'type': 'bool',
                    },
                'advertisement_interval': {
                    'type': 'int',
                    },
                'allowas_in': {
                    'type': 'bool',
                    },
                'allowas_in_count': {
                    'type': 'int',
                    },
                'as_origination_interval': {
                    'type': 'int',
                    },
                'dynamic': {
                    'type': 'bool',
                    },
                'prefix_list_direction': {
                    'type': 'str',
                    'choices': ['both', 'receive', 'send']
                    },
                'route_refresh': {
                    'type': 'bool',
                    },
                'graceful_restart': {
                    'type': 'bool',
                    },
                'extended_nexthop': {
                    'type': 'bool',
                    },
                'collide_established': {
                    'type': 'bool',
                    },
                'default_originate': {
                    'type': 'bool',
                    },
                'route_map': {
                    'type': 'str',
                    },
                'description': {
                    'type': 'str',
                    },
                'disallow_infinite_holdtime': {
                    'type': 'bool',
                    },
                'distribute_lists': {
                    'type': 'list',
                    'distribute_list': {
                        'type': 'str',
                        },
                    'distribute_list_direction': {
                        'type': 'str',
                        'choices': ['in', 'out']
                        }
                    },
                'acos_application_only': {
                    'type': 'bool',
                    },
                'dont_capability_negotiate': {
                    'type': 'bool',
                    },
                'ebgp_multihop': {
                    'type': 'bool',
                    },
                'ebgp_multihop_hop_count': {
                    'type': 'int',
                    },
                'enforce_multihop': {
                    'type': 'bool',
                    },
                'bfd': {
                    'type': 'bool',
                    },
                'multihop': {
                    'type': 'bool',
                    },
                'key_id': {
                    'type': 'int',
                    },
                'key_type': {
                    'type': 'str',
                    'choices': ['md5', 'meticulous-md5', 'meticulous-sha1', 'sha1', 'simple']
                    },
                'bfd_value': {
                    'type': 'str',
                    },
                'bfd_encrypted': {
                    'type': 'str',
                    },
                'neighbor_filter_lists': {
                    'type': 'list',
                    'filter_list': {
                        'type': 'str',
                        },
                    'filter_list_direction': {
                        'type': 'str',
                        'choices': ['in', 'out']
                        }
                    },
                'maximum_prefix': {
                    'type': 'int',
                    },
                'maximum_prefix_thres': {
                    'type': 'int',
                    },
                'restart_min': {
                    'type': 'int',
                    },
                'next_hop_self': {
                    'type': 'bool',
                    },
                'override_capability': {
                    'type': 'bool',
                    },
                'pass_value': {
                    'type': 'str',
                    },
                'pass_encrypted': {
                    'type': 'str',
                    },
                'passive': {
                    'type': 'bool',
                    },
                'neighbor_prefix_lists': {
                    'type': 'list',
                    'nbr_prefix_list': {
                        'type': 'str',
                        },
                    'nbr_prefix_list_direction': {
                        'type': 'str',
                        'choices': ['in', 'out']
                        }
                    },
                'remove_private_as': {
                    'type': 'bool',
                    },
                'neighbor_route_map_lists': {
                    'type': 'list',
                    'nbr_route_map': {
                        'type': 'str',
                        },
                    'nbr_rmap_direction': {
                        'type': 'str',
                        'choices': ['in', 'out']
                        }
                    },
                'send_community_val': {
                    'type': 'str',
                    'choices': ['both', 'none', 'standard', 'extended']
                    },
                'inbound': {
                    'type': 'bool',
                    },
                'shutdown': {
                    'type': 'bool',
                    },
                'strict_capability_match': {
                    'type': 'bool',
                    },
                'timers_keepalive': {
                    'type': 'int',
                    },
                'timers_holdtime': {
                    'type': 'int',
                    },
                'connect': {
                    'type': 'int',
                    },
                'unsuppress_map': {
                    'type': 'str',
                    },
                'update_source_ip': {
                    'type': 'str',
                    },
                'update_source_ipv6': {
                    'type': 'str',
                    },
                'ethernet': {
                    'type': 'str',
                    },
                'loopback': {
                    'type': 'str',
                    },
                've': {
                    'type': 'str',
                    },
                'trunk': {
                    'type': 'str',
                    },
                'lif': {
                    'type': 'str',
                    },
                'tunnel': {
                    'type': 'str',
                    },
                'weight': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'ethernet_neighbor_list': {
                'type': 'list',
                'ethernet': {
                    'type': 'str',
                    'required': True,
                    },
                'unnumbered': {
                    'type': 'bool',
                    },
                'peer_group_name': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            've_neighbor_list': {
                'type': 'list',
                've': {
                    'type': 'str',
                    'required': True,
                    },
                'unnumbered': {
                    'type': 'bool',
                    },
                'peer_group_name': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'trunk_neighbor_list': {
                'type': 'list',
                'trunk': {
                    'type': 'str',
                    'required': True,
                    },
                'unnumbered': {
                    'type': 'bool',
                    },
                'peer_group_name': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'redistribute': {
            'type': 'dict',
            'connected_cfg': {
                'type': 'dict',
                'connected': {
                    'type': 'bool',
                    },
                'route_map': {
                    'type': 'str',
                    }
                },
            'floating_ip_cfg': {
                'type': 'dict',
                'floating_ip': {
                    'type': 'bool',
                    },
                'route_map': {
                    'type': 'str',
                    }
                },
            'lw4o6_cfg': {
                'type': 'dict',
                'lw4o6': {
                    'type': 'bool',
                    },
                'route_map': {
                    'type': 'str',
                    }
                },
            'static_nat_cfg': {
                'type': 'dict',
                'static_nat': {
                    'type': 'bool',
                    },
                'route_map': {
                    'type': 'str',
                    }
                },
            'ip_nat_cfg': {
                'type': 'dict',
                'ip_nat': {
                    'type': 'bool',
                    },
                'route_map': {
                    'type': 'str',
                    }
                },
            'ip_nat_list_cfg': {
                'type': 'dict',
                'ip_nat_list': {
                    'type': 'bool',
                    },
                'route_map': {
                    'type': 'str',
                    }
                },
            'isis_cfg': {
                'type': 'dict',
                'isis': {
                    'type': 'bool',
                    },
                'route_map': {
                    'type': 'str',
                    }
                },
            'ospf_cfg': {
                'type': 'dict',
                'ospf': {
                    'type': 'bool',
                    },
                'route_map': {
                    'type': 'str',
                    }
                },
            'rip_cfg': {
                'type': 'dict',
                'rip': {
                    'type': 'bool',
                    },
                'route_map': {
                    'type': 'str',
                    }
                },
            'static_cfg': {
                'type': 'dict',
                'static': {
                    'type': 'bool',
                    },
                'route_map': {
                    'type': 'str',
                    }
                },
            'nat_map_cfg': {
                'type': 'dict',
                'nat_map': {
                    'type': 'bool',
                    },
                'route_map': {
                    'type': 'str',
                    }
                },
            'vip': {
                'type': 'dict',
                'only_flagged_cfg': {
                    'type': 'dict',
                    'only_flagged': {
                        'type': 'bool',
                        },
                    'route_map': {
                        'type': 'str',
                        }
                    },
                'only_not_flagged_cfg': {
                    'type': 'dict',
                    'only_not_flagged': {
                        'type': 'bool',
                        },
                    'route_map': {
                        'type': 'str',
                        }
                    }
                },
            'uuid': {
                'type': 'str',
                }
            },
        'address_family': {
            'type': 'dict',
            'ipv6': {
                'type': 'dict',
                'bgp': {
                    'type': 'dict',
                    'dampening': {
                        'type': 'bool',
                        },
                    'dampening_half': {
                        'type': 'int',
                        },
                    'dampening_start_reuse': {
                        'type': 'int',
                        },
                    'dampening_start_supress': {
                        'type': 'int',
                        },
                    'dampening_max_supress': {
                        'type': 'int',
                        },
                    'dampening_unreachability': {
                        'type': 'int',
                        },
                    'route_map': {
                        'type': 'str',
                        }
                    },
                'distance': {
                    'type': 'dict',
                    'distance_ext': {
                        'type': 'int',
                        },
                    'distance_int': {
                        'type': 'int',
                        },
                    'distance_local': {
                        'type': 'int',
                        }
                    },
                'maximum_paths_value': {
                    'type': 'int',
                    },
                'originate': {
                    'type': 'bool',
                    },
                'aggregate_address_list': {
                    'type': 'list',
                    'aggregate_address': {
                        'type': 'str',
                        },
                    'as_set': {
                        'type': 'bool',
                        },
                    'summary_only': {
                        'type': 'bool',
                        }
                    },
                'auto_summary': {
                    'type': 'bool',
                    },
                'synchronization': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'network': {
                    'type': 'dict',
                    'synchronization': {
                        'type': 'dict',
                        'network_synchronization': {
                            'type': 'bool',
                            },
                        'uuid': {
                            'type': 'str',
                            }
                        },
                    'ipv6_network_list': {
                        'type': 'list',
                        'network_ipv6': {
                            'type': 'str',
                            'required': True,
                            },
                        'route_map': {
                            'type': 'str',
                            },
                        'backdoor': {
                            'type': 'bool',
                            },
                        'description': {
                            'type': 'str',
                            },
                        'comm_value': {
                            'type': 'str',
                            },
                        'uuid': {
                            'type': 'str',
                            }
                        }
                    },
                'neighbor': {
                    'type': 'dict',
                    'peer_group_neighbor_list': {
                        'type': 'list',
                        'peer_group': {
                            'type': 'str',
                            'required': True,
                            },
                        'activate': {
                            'type': 'bool',
                            },
                        'allowas_in': {
                            'type': 'bool',
                            },
                        'allowas_in_count': {
                            'type': 'int',
                            },
                        'prefix_list_direction': {
                            'type': 'str',
                            'choices': ['both', 'receive', 'send']
                            },
                        'default_originate': {
                            'type': 'bool',
                            },
                        'route_map': {
                            'type': 'str',
                            },
                        'distribute_lists': {
                            'type': 'list',
                            'distribute_list': {
                                'type': 'str',
                                },
                            'distribute_list_direction': {
                                'type': 'str',
                                'choices': ['in', 'out']
                                }
                            },
                        'neighbor_filter_lists': {
                            'type': 'list',
                            'filter_list': {
                                'type': 'str',
                                },
                            'filter_list_direction': {
                                'type': 'str',
                                'choices': ['in', 'out']
                                }
                            },
                        'maximum_prefix': {
                            'type': 'int',
                            },
                        'maximum_prefix_thres': {
                            'type': 'int',
                            },
                        'next_hop_self': {
                            'type': 'bool',
                            },
                        'neighbor_prefix_lists': {
                            'type': 'list',
                            'nbr_prefix_list': {
                                'type': 'str',
                                },
                            'nbr_prefix_list_direction': {
                                'type': 'str',
                                'choices': ['in', 'out']
                                }
                            },
                        'remove_private_as': {
                            'type': 'bool',
                            },
                        'neighbor_route_map_lists': {
                            'type': 'list',
                            'nbr_route_map': {
                                'type': 'str',
                                },
                            'nbr_rmap_direction': {
                                'type': 'str',
                                'choices': ['in', 'out']
                                }
                            },
                        'send_community_val': {
                            'type': 'str',
                            'choices': ['both', 'none', 'standard', 'extended']
                            },
                        'inbound': {
                            'type': 'bool',
                            },
                        'unsuppress_map': {
                            'type': 'str',
                            },
                        'weight': {
                            'type': 'int',
                            },
                        'uuid': {
                            'type': 'str',
                            }
                        },
                    'ipv4_neighbor_list': {
                        'type': 'list',
                        'neighbor_ipv4': {
                            'type': 'str',
                            'required': True,
                            },
                        'peer_group_name': {
                            'type': 'str',
                            },
                        'activate': {
                            'type': 'bool',
                            },
                        'allowas_in': {
                            'type': 'bool',
                            },
                        'allowas_in_count': {
                            'type': 'int',
                            },
                        'prefix_list_direction': {
                            'type': 'str',
                            'choices': ['both', 'receive', 'send']
                            },
                        'graceful_restart': {
                            'type': 'bool',
                            },
                        'default_originate': {
                            'type': 'bool',
                            },
                        'route_map': {
                            'type': 'str',
                            },
                        'distribute_lists': {
                            'type': 'list',
                            'distribute_list': {
                                'type': 'str',
                                },
                            'distribute_list_direction': {
                                'type': 'str',
                                'choices': ['in', 'out']
                                }
                            },
                        'neighbor_filter_lists': {
                            'type': 'list',
                            'filter_list': {
                                'type': 'str',
                                },
                            'filter_list_direction': {
                                'type': 'str',
                                'choices': ['in', 'out']
                                }
                            },
                        'maximum_prefix': {
                            'type': 'int',
                            },
                        'maximum_prefix_thres': {
                            'type': 'int',
                            },
                        'restart_min': {
                            'type': 'int',
                            },
                        'next_hop_self': {
                            'type': 'bool',
                            },
                        'neighbor_prefix_lists': {
                            'type': 'list',
                            'nbr_prefix_list': {
                                'type': 'str',
                                },
                            'nbr_prefix_list_direction': {
                                'type': 'str',
                                'choices': ['in', 'out']
                                }
                            },
                        'remove_private_as': {
                            'type': 'bool',
                            },
                        'neighbor_route_map_lists': {
                            'type': 'list',
                            'nbr_route_map': {
                                'type': 'str',
                                },
                            'nbr_rmap_direction': {
                                'type': 'str',
                                'choices': ['in', 'out']
                                }
                            },
                        'send_community_val': {
                            'type': 'str',
                            'choices': ['both', 'none', 'standard', 'extended']
                            },
                        'inbound': {
                            'type': 'bool',
                            },
                        'unsuppress_map': {
                            'type': 'str',
                            },
                        'weight': {
                            'type': 'int',
                            },
                        'uuid': {
                            'type': 'str',
                            }
                        },
                    'ipv6_neighbor_list': {
                        'type': 'list',
                        'neighbor_ipv6': {
                            'type': 'str',
                            'required': True,
                            },
                        'peer_group_name': {
                            'type': 'str',
                            },
                        'activate': {
                            'type': 'bool',
                            },
                        'allowas_in': {
                            'type': 'bool',
                            },
                        'allowas_in_count': {
                            'type': 'int',
                            },
                        'prefix_list_direction': {
                            'type': 'str',
                            'choices': ['both', 'receive', 'send']
                            },
                        'graceful_restart': {
                            'type': 'bool',
                            },
                        'default_originate': {
                            'type': 'bool',
                            },
                        'route_map': {
                            'type': 'str',
                            },
                        'distribute_lists': {
                            'type': 'list',
                            'distribute_list': {
                                'type': 'str',
                                },
                            'distribute_list_direction': {
                                'type': 'str',
                                'choices': ['in', 'out']
                                }
                            },
                        'neighbor_filter_lists': {
                            'type': 'list',
                            'filter_list': {
                                'type': 'str',
                                },
                            'filter_list_direction': {
                                'type': 'str',
                                'choices': ['in', 'out']
                                }
                            },
                        'maximum_prefix': {
                            'type': 'int',
                            },
                        'maximum_prefix_thres': {
                            'type': 'int',
                            },
                        'restart_min': {
                            'type': 'int',
                            },
                        'next_hop_self': {
                            'type': 'bool',
                            },
                        'neighbor_prefix_lists': {
                            'type': 'list',
                            'nbr_prefix_list': {
                                'type': 'str',
                                },
                            'nbr_prefix_list_direction': {
                                'type': 'str',
                                'choices': ['in', 'out']
                                }
                            },
                        'remove_private_as': {
                            'type': 'bool',
                            },
                        'neighbor_route_map_lists': {
                            'type': 'list',
                            'nbr_route_map': {
                                'type': 'str',
                                },
                            'nbr_rmap_direction': {
                                'type': 'str',
                                'choices': ['in', 'out']
                                }
                            },
                        'send_community_val': {
                            'type': 'str',
                            'choices': ['both', 'none', 'standard', 'extended']
                            },
                        'inbound': {
                            'type': 'bool',
                            },
                        'unsuppress_map': {
                            'type': 'str',
                            },
                        'weight': {
                            'type': 'int',
                            },
                        'uuid': {
                            'type': 'str',
                            }
                        },
                    'ethernet_neighbor_ipv6_list': {
                        'type': 'list',
                        'ethernet': {
                            'type': 'str',
                            'required': True,
                            },
                        'peer_group_name': {
                            'type': 'str',
                            },
                        'uuid': {
                            'type': 'str',
                            }
                        },
                    've_neighbor_ipv6_list': {
                        'type': 'list',
                        've': {
                            'type': 'str',
                            'required': True,
                            },
                        'peer_group_name': {
                            'type': 'str',
                            },
                        'uuid': {
                            'type': 'str',
                            }
                        },
                    'trunk_neighbor_ipv6_list': {
                        'type': 'list',
                        'trunk': {
                            'type': 'str',
                            'required': True,
                            },
                        'peer_group_name': {
                            'type': 'str',
                            },
                        'uuid': {
                            'type': 'str',
                            }
                        }
                    },
                'redistribute': {
                    'type': 'dict',
                    'connected_cfg': {
                        'type': 'dict',
                        'connected': {
                            'type': 'bool',
                            },
                        'route_map': {
                            'type': 'str',
                            }
                        },
                    'floating_ip_cfg': {
                        'type': 'dict',
                        'floating_ip': {
                            'type': 'bool',
                            },
                        'route_map': {
                            'type': 'str',
                            }
                        },
                    'nat64_cfg': {
                        'type': 'dict',
                        'nat64': {
                            'type': 'bool',
                            },
                        'route_map': {
                            'type': 'str',
                            }
                        },
                    'nat_map_cfg': {
                        'type': 'dict',
                        'nat_map': {
                            'type': 'bool',
                            },
                        'route_map': {
                            'type': 'str',
                            }
                        },
                    'lw4o6_cfg': {
                        'type': 'dict',
                        'lw4o6': {
                            'type': 'bool',
                            },
                        'route_map': {
                            'type': 'str',
                            }
                        },
                    'static_nat_cfg': {
                        'type': 'dict',
                        'static_nat': {
                            'type': 'bool',
                            },
                        'route_map': {
                            'type': 'str',
                            }
                        },
                    'ip_nat_cfg': {
                        'type': 'dict',
                        'ip_nat': {
                            'type': 'bool',
                            },
                        'route_map': {
                            'type': 'str',
                            }
                        },
                    'ip_nat_list_cfg': {
                        'type': 'dict',
                        'ip_nat_list': {
                            'type': 'bool',
                            },
                        'route_map': {
                            'type': 'str',
                            }
                        },
                    'isis_cfg': {
                        'type': 'dict',
                        'isis': {
                            'type': 'bool',
                            },
                        'route_map': {
                            'type': 'str',
                            }
                        },
                    'ospf_cfg': {
                        'type': 'dict',
                        'ospf': {
                            'type': 'bool',
                            },
                        'route_map': {
                            'type': 'str',
                            }
                        },
                    'rip_cfg': {
                        'type': 'dict',
                        'rip': {
                            'type': 'bool',
                            },
                        'route_map': {
                            'type': 'str',
                            }
                        },
                    'static_cfg': {
                        'type': 'dict',
                        'static': {
                            'type': 'bool',
                            },
                        'route_map': {
                            'type': 'str',
                            }
                        },
                    'vip': {
                        'type': 'dict',
                        'only_flagged_cfg': {
                            'type': 'dict',
                            'only_flagged': {
                                'type': 'bool',
                                },
                            'route_map': {
                                'type': 'str',
                                }
                            },
                        'only_not_flagged_cfg': {
                            'type': 'dict',
                            'only_not_flagged': {
                                'type': 'bool',
                                },
                            'route_map': {
                                'type': 'str',
                                }
                            }
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/bgp/{as_number}"

    f_dict = {}
    if '/' in str(module.params["as_number"]):
        f_dict["as_number"] = module.params["as_number"].replace("/", "%2F")
    else:
        f_dict["as_number"] = module.params["as_number"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/router/bgp/{as_number}"

    f_dict = {}
    f_dict["as_number"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["bgp"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["bgp"].get(k) != v:
            change_results["changed"] = True
            config_changes["bgp"][k] = v

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
    payload = utils.build_json("bgp", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["bgp"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["bgp-list"] if info != "NotFound" else info
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
