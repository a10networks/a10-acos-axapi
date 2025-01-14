#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_rule_set
description:
    - Configure Security policy Rule Set
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
        - "Rule set name"
        type: str
        required: True
    session_statistic:
        description:
        - "'enable'= Enable session based statistic (Default); 'disable'= Disable session
          based statistic;"
        type: str
        required: False
    remark:
        description:
        - "Rule set entry comment (Notes for this rule set)"
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'unmatched-drops'= Unmatched drops counter; 'permit'= Permitted
          counter; 'deny'= Denied counter; 'reset'= Reset counter;"
                type: str
    packet_capture_template:
        description:
        - "Name of the packet capture template to be bind with this object"
        type: str
        required: False
    rule_list:
        description:
        - "Field rule_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Rule name"
                type: str
            remark:
                description:
                - "Rule entry comment (Notes for this rule)"
                type: str
            status:
                description:
                - "'enable'= Enable rule; 'disable'= Disable rule;"
                type: str
            ip_version:
                description:
                - "'v4'= IPv4 rule; 'v6'= IPv6 rule;"
                type: str
            action:
                description:
                - "'permit'= permit; 'deny'= deny; 'reset'= reset;"
                type: str
            log:
                description:
                - "Enable logging"
                type: bool
            reset_lid:
                description:
                - "Apply a Template LID"
                type: int
            listen_on_port:
                description:
                - "Listen on port"
                type: bool
            policy:
                description:
                - "'cgnv6'= Apply CGNv6 policy; 'forward'= Forward packet; 'ipsec'= Apply IPsec
          encapsulation; 'ipsec-group'= Apply IPsec encapsulation from a group;"
                type: str
            vpn_ipsec_name:
                description:
                - "VPN IPsec name"
                type: str
            vpn_ipsec_group_name:
                description:
                - "VPN IPsec Group name"
                type: str
            forward_listen_on_port:
                description:
                - "Listen on port"
                type: bool
            lid:
                description:
                - "Apply a Template LID"
                type: int
            listen_on_port_lid:
                description:
                - "Apply a Template LID"
                type: int
            fw_log:
                description:
                - "Enable logging"
                type: bool
            fwlog:
                description:
                - "Enable logging"
                type: bool
            cgnv6_log:
                description:
                - "Enable logging"
                type: bool
            forward_log:
                description:
                - "Enable logging"
                type: bool
            lidlog:
                description:
                - "Enable logging"
                type: bool
            reset_lidlog:
                description:
                - "Enable logging"
                type: bool
            listen_on_port_lidlog:
                description:
                - "Enable logging"
                type: bool
            cgnv6_policy:
                description:
                - "'lsn-lid'= Apply specified CGNv6 LSN LID; 'fixed-nat'= Apply CGNv6 Fixed NAT;
          'ds-lite'= Apply CGNv6 DS-Lite;"
                type: str
            cgnv6_fixed_nat_log:
                description:
                - "Enable logging"
                type: bool
            cgnv6_lsn_lid:
                description:
                - "LSN LID"
                type: int
            cgnv6_ds_lite:
                description:
                - "'lsn-lid'= Apply specified CGNv6 LSN LID;"
                type: str
            cgnv6_ds_lite_lsn_lid:
                description:
                - "LSN LID"
                type: int
            inspect_payload:
                description:
                - "Enable DS-Lite tunnel inspection"
                type: bool
            cgnv6_ds_lite_log:
                description:
                - "Enable logging"
                type: bool
            cgnv6_lsn_log:
                description:
                - "Enable logging"
                type: bool
            gtp_template:
                description:
                - "Configure GTP Policy Template (GTP Template Policy Name)"
                type: str
            src_geoloc_name:
                description:
                - "Single geolocation name"
                type: str
            src_geoloc_list:
                description:
                - "Geolocation name list"
                type: str
            src_geoloc_list_shared:
                description:
                - "Use Geolocation list from shared partition"
                type: bool
            src_ipv4_any:
                description:
                - "'any'= Any IPv4 address;"
                type: str
            src_ipv6_any:
                description:
                - "'any'= Any IPv6 address;"
                type: str
            src_class_list:
                description:
                - "Match source IP against class-list"
                type: str
            source_list:
                description:
                - "Field source_list"
                type: list
            src_zone:
                description:
                - "Zone name"
                type: str
            src_zone_any:
                description:
                - "'any'= any;"
                type: str
            src_threat_list:
                description:
                - "Bind threat-list for source IP based filtering"
                type: str
            dst_geoloc_name:
                description:
                - "Single geolocation name"
                type: str
            dst_geoloc_list:
                description:
                - "Geolocation name list"
                type: str
            dst_geoloc_list_shared:
                description:
                - "Use Geolocation list from shared partition"
                type: bool
            dst_ipv4_any:
                description:
                - "'any'= Any IPv4 address;"
                type: str
            dst_ipv6_any:
                description:
                - "'any'= Any IPv6 address;"
                type: str
            dst_class_list:
                description:
                - "Match destination IP against class-list"
                type: str
            dest_list:
                description:
                - "Field dest_list"
                type: list
            dst_domain_list:
                description:
                - "Match destination IP against domain-list"
                type: str
            dst_zone:
                description:
                - "Zone name"
                type: str
            dst_zone_any:
                description:
                - "'any'= any;"
                type: str
            dst_threat_list:
                description:
                - "Bind threat-list for destination IP based filtering"
                type: str
            service_any:
                description:
                - "'any'= any;"
                type: str
            service_list:
                description:
                - "Field service_list"
                type: list
            idle_timeout:
                description:
                - "TCP/UDP idle-timeout"
                type: int
            dscp_list:
                description:
                - "Field dscp_list"
                type: list
            application_any:
                description:
                - "'any'= any;"
                type: str
            app_list:
                description:
                - "Field app_list"
                type: list
            track_application:
                description:
                - "Enable application statistic (functional only in action permit)"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
            packet_capture_template:
                description:
                - "Name of the packet capture template to be bind with this object"
                type: str
            action_group:
                description:
                - "Field action_group"
                type: dict
            move_rule:
                description:
                - "Field move_rule"
                type: dict
    rules_by_zone:
        description:
        - "Field rules_by_zone"
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
    application:
        description:
        - "Field application"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    track_app_rule_list:
        description:
        - "Field track_app_rule_list"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    app:
        description:
        - "Field app"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    tag:
        description:
        - "Field tag"
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
            policy_status:
                description:
                - "Field policy_status"
                type: str
            policy_unmatched_drop:
                description:
                - "Field policy_unmatched_drop"
                type: int
            policy_permit:
                description:
                - "Field policy_permit"
                type: int
            policy_deny:
                description:
                - "Field policy_deny"
                type: int
            policy_reset:
                description:
                - "Field policy_reset"
                type: int
            policy_rule_count:
                description:
                - "Field policy_rule_count"
                type: int
            rule_stats:
                description:
                - "Field rule_stats"
                type: list
            total_hit:
                description:
                - "Field total_hit"
                type: int
            total_permit_bytes:
                description:
                - "Field total_permit_bytes"
                type: int
            total_deny_bytes:
                description:
                - "Field total_deny_bytes"
                type: int
            total_reset_bytes:
                description:
                - "Field total_reset_bytes"
                type: int
            total_bytes:
                description:
                - "Field total_bytes"
                type: int
            total_permit_packets:
                description:
                - "Field total_permit_packets"
                type: int
            total_deny_packets:
                description:
                - "Field total_deny_packets"
                type: int
            total_reset_packets:
                description:
                - "Field total_reset_packets"
                type: int
            total_packets:
                description:
                - "Field total_packets"
                type: int
            total_active_tcp:
                description:
                - "Field total_active_tcp"
                type: int
            total_active_udp:
                description:
                - "Field total_active_udp"
                type: int
            total_active_icmp:
                description:
                - "Field total_active_icmp"
                type: int
            total_active_others:
                description:
                - "Field total_active_others"
                type: int
            show_total_stats:
                description:
                - "Field show_total_stats"
                type: str
            topn_rules:
                description:
                - "Field topn_rules"
                type: str
            name:
                description:
                - "Rule set name"
                type: str
            rule_list:
                description:
                - "Field rule_list"
                type: list
            rules_by_zone:
                description:
                - "Field rules_by_zone"
                type: dict
            application:
                description:
                - "Field application"
                type: dict
            track_app_rule_list:
                description:
                - "Field track_app_rule_list"
                type: dict
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            unmatched_drops:
                description:
                - "Unmatched drops counter"
                type: str
            permit:
                description:
                - "Permitted counter"
                type: str
            deny:
                description:
                - "Denied counter"
                type: str
            reset:
                description:
                - "Reset counter"
                type: str
            name:
                description:
                - "Rule set name"
                type: str
            rule_list:
                description:
                - "Field rule_list"
                type: list
            rules_by_zone:
                description:
                - "Field rules_by_zone"
                type: dict
            track_app_rule_list:
                description:
                - "Field track_app_rule_list"
                type: dict
            app:
                description:
                - "Field app"
                type: dict
            tag:
                description:
                - "Field tag"
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
AVAILABLE_PROPERTIES = ["app", "application", "name", "oper", "packet_capture_template", "remark", "rule_list", "rules_by_zone", "sampling_enable", "session_statistic", "stats", "tag", "track_app_rule_list", "user_tag", "uuid", ]


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
        'session_statistic': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'remark': {
            'type': 'str',
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
                'choices': ['all', 'unmatched-drops', 'permit', 'deny', 'reset']
                }
            },
        'packet_capture_template': {
            'type': 'str',
            },
        'rule_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'remark': {
                'type': 'str',
                },
            'status': {
                'type': 'str',
                'choices': ['enable', 'disable']
                },
            'ip_version': {
                'type': 'str',
                'choices': ['v4', 'v6']
                },
            'action': {
                'type': 'str',
                'choices': ['permit', 'deny', 'reset']
                },
            'log': {
                'type': 'bool',
                },
            'reset_lid': {
                'type': 'int',
                },
            'listen_on_port': {
                'type': 'bool',
                },
            'policy': {
                'type': 'str',
                'choices': ['cgnv6', 'forward', 'ipsec', 'ipsec-group']
                },
            'vpn_ipsec_name': {
                'type': 'str',
                },
            'vpn_ipsec_group_name': {
                'type': 'str',
                },
            'forward_listen_on_port': {
                'type': 'bool',
                },
            'lid': {
                'type': 'int',
                },
            'listen_on_port_lid': {
                'type': 'int',
                },
            'fw_log': {
                'type': 'bool',
                },
            'fwlog': {
                'type': 'bool',
                },
            'cgnv6_log': {
                'type': 'bool',
                },
            'forward_log': {
                'type': 'bool',
                },
            'lidlog': {
                'type': 'bool',
                },
            'reset_lidlog': {
                'type': 'bool',
                },
            'listen_on_port_lidlog': {
                'type': 'bool',
                },
            'cgnv6_policy': {
                'type': 'str',
                'choices': ['lsn-lid', 'fixed-nat', 'ds-lite']
                },
            'cgnv6_fixed_nat_log': {
                'type': 'bool',
                },
            'cgnv6_lsn_lid': {
                'type': 'int',
                },
            'cgnv6_ds_lite': {
                'type': 'str',
                'choices': ['lsn-lid']
                },
            'cgnv6_ds_lite_lsn_lid': {
                'type': 'int',
                },
            'inspect_payload': {
                'type': 'bool',
                },
            'cgnv6_ds_lite_log': {
                'type': 'bool',
                },
            'cgnv6_lsn_log': {
                'type': 'bool',
                },
            'gtp_template': {
                'type': 'str',
                },
            'src_geoloc_name': {
                'type': 'str',
                },
            'src_geoloc_list': {
                'type': 'str',
                },
            'src_geoloc_list_shared': {
                'type': 'bool',
                },
            'src_ipv4_any': {
                'type': 'str',
                'choices': ['any']
                },
            'src_ipv6_any': {
                'type': 'str',
                'choices': ['any']
                },
            'src_class_list': {
                'type': 'str',
                },
            'source_list': {
                'type': 'list',
                'src_ip_subnet': {
                    'type': 'str',
                    },
                'src_ipv6_subnet': {
                    'type': 'str',
                    },
                'src_obj_network': {
                    'type': 'str',
                    },
                'src_obj_grp_network': {
                    'type': 'str',
                    },
                'src_slb_server': {
                    'type': 'str',
                    }
                },
            'src_zone': {
                'type': 'str',
                },
            'src_zone_any': {
                'type': 'str',
                'choices': ['any']
                },
            'src_threat_list': {
                'type': 'str',
                },
            'dst_geoloc_name': {
                'type': 'str',
                },
            'dst_geoloc_list': {
                'type': 'str',
                },
            'dst_geoloc_list_shared': {
                'type': 'bool',
                },
            'dst_ipv4_any': {
                'type': 'str',
                'choices': ['any']
                },
            'dst_ipv6_any': {
                'type': 'str',
                'choices': ['any']
                },
            'dst_class_list': {
                'type': 'str',
                },
            'dest_list': {
                'type': 'list',
                'dst_ip_subnet': {
                    'type': 'str',
                    },
                'dst_ipv6_subnet': {
                    'type': 'str',
                    },
                'dst_obj_network': {
                    'type': 'str',
                    },
                'dst_obj_grp_network': {
                    'type': 'str',
                    },
                'dst_slb_server': {
                    'type': 'str',
                    },
                'dst_slb_vserver': {
                    'type': 'str',
                    }
                },
            'dst_domain_list': {
                'type': 'str',
                },
            'dst_zone': {
                'type': 'str',
                },
            'dst_zone_any': {
                'type': 'str',
                'choices': ['any']
                },
            'dst_threat_list': {
                'type': 'str',
                },
            'service_any': {
                'type': 'str',
                'choices': ['any']
                },
            'service_list': {
                'type': 'list',
                'protocols': {
                    'type': 'str',
                    'choices': ['tcp', 'udp', 'sctp']
                    },
                'proto_id': {
                    'type': 'int',
                    },
                'obj_grp_service': {
                    'type': 'str',
                    },
                'icmp': {
                    'type': 'bool',
                    },
                'icmpv6': {
                    'type': 'bool',
                    },
                'icmp_type': {
                    'type': 'int',
                    },
                'special_type': {
                    'type': 'str',
                    'choices': ['any-type', 'echo-reply', 'echo-request', 'info-reply', 'info-request', 'mask-reply', 'mask-request', 'parameter-problem', 'redirect', 'source-quench', 'time-exceeded', 'timestamp', 'timestamp-reply', 'dest-unreachable']
                    },
                'icmp_code': {
                    'type': 'int',
                    },
                'special_code': {
                    'type': 'str',
                    'choices': ['any-code', 'frag-required', 'host-unreachable', 'network-unreachable', 'port-unreachable', 'proto-unreachable', 'route-failed']
                    },
                'icmpv6_type': {
                    'type': 'int',
                    },
                'special_v6_type': {
                    'type': 'str',
                    'choices': ['any-type', 'dest-unreachable', 'echo-reply', 'echo-request', 'packet-too-big', 'param-prob', 'time-exceeded']
                    },
                'icmpv6_code': {
                    'type': 'int',
                    },
                'special_v6_code': {
                    'type': 'str',
                    'choices': ['any-code', 'addr-unreachable', 'admin-prohibited', 'no-route', 'not-neighbour', 'port-unreachable']
                    },
                'eq_src_port': {
                    'type': 'int',
                    },
                'gt_src_port': {
                    'type': 'int',
                    },
                'lt_src_port': {
                    'type': 'int',
                    },
                'range_src_port': {
                    'type': 'int',
                    },
                'port_num_end_src': {
                    'type': 'int',
                    },
                'eq_dst_port': {
                    'type': 'int',
                    },
                'gt_dst_port': {
                    'type': 'int',
                    },
                'lt_dst_port': {
                    'type': 'int',
                    },
                'range_dst_port': {
                    'type': 'int',
                    },
                'port_num_end_dst': {
                    'type': 'int',
                    },
                'sctp_template': {
                    'type': 'str',
                    },
                'alg': {
                    'type': 'str',
                    'choices': ['FTP', 'TFTP', 'SIP', 'DNS', 'PPTP', 'RTSP', 'ESP']
                    }
                },
            'idle_timeout': {
                'type': 'int',
                },
            'dscp_list': {
                'type': 'list',
                'dscp_value': {
                    'type': 'str',
                    'choices': ['default', 'af11', 'af12', 'af13', 'af21', 'af22', 'af23', 'af31', 'af32', 'af33', 'af41', 'af42', 'af43', 'cs1', 'cs2', 'cs3', 'cs4', 'cs5', 'cs6', 'cs7', 'ef']
                    },
                'dscp_range_start': {
                    'type': 'int',
                    },
                'dscp_range_end': {
                    'type': 'int',
                    }
                },
            'application_any': {
                'type': 'str',
                'choices': ['any']
                },
            'app_list': {
                'type': 'list',
                'obj_grp_application': {
                    'type': 'str',
                    },
                'protocol': {
                    'type': 'str',
                    },
                'protocol_tag': {
                    'type':
                    'str',
                    'choices': [
                        'aaa', 'adult-content', 'advertising', 'application-enforcing-tls', 'analytics-and-statistics', 'anonymizers-and-proxies', 'audio-chat', 'basic', 'blog', 'cdn', 'certification-authority', 'chat', 'classified-ads', 'cloud-based-services', 'crowdfunding', 'cryptocurrency', 'database', 'disposable-email', 'ebook-reader',
                        'education', 'email', 'enterprise', 'file-management', 'file-transfer', 'forum', 'gaming', 'healthcare', 'instant-messaging-and-multimedia-conferencing', 'internet-of-things', 'map-service', 'mobile', 'multimedia-streaming', 'networking', 'news-portal', 'payment-service', 'peer-to-peer', 'remote-access', 'scada',
                        'social-networks', 'software-update', 'speedtest', 'standards-based', 'transportation', 'video-chat', 'voip', 'vpn-tunnels', 'web', 'web-e-commerce', 'web-search-engines', 'web-websites', 'webmails', 'web-ext-adult', 'web-ext-auctions', 'web-ext-blogs', 'web-ext-business-and-economy', 'web-ext-cdns', 'web-ext-collaboration',
                        'web-ext-computer-and-internet-info', 'web-ext-computer-and-internet-security', 'web-ext-dating', 'web-ext-educational-institutions', 'web-ext-entertainment-and-arts', 'web-ext-fashion-and-beauty', 'web-ext-file-share', 'web-ext-financial-services', 'web-ext-gambling', 'web-ext-games', 'web-ext-government',
                        'web-ext-health-and-medicine', 'web-ext-individual-stock-advice-and-tools', 'web-ext-internet-portals', 'web-ext-job-search', 'web-ext-local-information', 'web-ext-malware', 'web-ext-motor-vehicles', 'web-ext-music', 'web-ext-news', 'web-ext-p2p', 'web-ext-parked-sites', 'web-ext-proxy-avoid-and-anonymizers',
                        'web-ext-real-estate', 'web-ext-reference-and-research', 'web-ext-search-engines', 'web-ext-shopping', 'web-ext-social-network', 'web-ext-society', 'web-ext-software', 'web-ext-sports', 'web-ext-streaming-media', 'web-ext-training-and-tools', 'web-ext-translation', 'web-ext-travel', 'web-ext-web-advertisements',
                        'web-ext-web-based-email', 'web-ext-web-hosting', 'web-ext-web-service'
                        ]
                    }
                },
            'track_application': {
                'type': 'bool',
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
                        'all', 'hit-count', 'permit-bytes', 'deny-bytes', 'reset-bytes', 'permit-packets', 'deny-packets', 'reset-packets', 'active-session-tcp', 'active-session-udp', 'active-session-icmp', 'active-session-other', 'session-tcp', 'session-udp', 'session-icmp', 'session-other', 'active-session-sctp', 'session-sctp',
                        'hitcount-timestamp', 'rate-limit-drops', 'syn-cookie-syn-ack-sent', 'syn-cookie-verification-passed', 'syn-cookie-verification-failed', 'syn-cookie-conn-setup-failed', 'tcp-half-open-count'
                        ]
                    }
                },
            'packet_capture_template': {
                'type': 'str',
                },
            'action_group': {
                'type': 'dict',
                'ntype': {
                    'type': 'str',
                    'choices': ['permit', 'deny', 'reset']
                    },
                'permit_log': {
                    'type': 'bool',
                    },
                'reset_log': {
                    'type': 'bool',
                    },
                'deny_log': {
                    'type': 'bool',
                    },
                'logging_template_list': {
                    'type': 'list',
                    'permit_log_template_type': {
                        'type': 'str',
                        'choices': ['fw-logging-template', 'cgnv6-logging-template', 'netflow-monitor']
                        },
                    'permit_fw_log': {
                        'type': 'str',
                        },
                    'permit_cgnv6_log': {
                        'type': 'str',
                        },
                    'permit_netflow_log': {
                        'type': 'str',
                        }
                    },
                'reset_log_template_type': {
                    'type': 'str',
                    'choices': ['fw-logging-template']
                    },
                'reset_fw_log': {
                    'type': 'str',
                    },
                'deny_log_template_type': {
                    'type': 'str',
                    'choices': ['fw-logging-template']
                    },
                'deny_fw_log': {
                    'type': 'str',
                    },
                'listen_on_port': {
                    'type': 'bool',
                    },
                'forward': {
                    'type': 'bool',
                    },
                'ipsec': {
                    'type': 'bool',
                    },
                'ipsec_group': {
                    'type': 'bool',
                    },
                'vpn_ipsec_name': {
                    'type': 'str',
                    },
                'vpn_ipsec_group_name': {
                    'type': 'str',
                    },
                'cgnv6': {
                    'type': 'bool',
                    },
                'cgnv6_policy': {
                    'type': 'str',
                    'choices': ['lsn-lid', 'fixed-nat', 'ds-lite']
                    },
                'cgnv6_lsn_lid': {
                    'type': 'int',
                    },
                'cgnv6_ds_lite': {
                    'type': 'str',
                    'choices': ['lsn-lid']
                    },
                'cgnv6_ds_lite_lsn_lid': {
                    'type': 'int',
                    },
                'inspect_payload': {
                    'type': 'bool',
                    },
                'permit_limit_policy': {
                    'type': 'int',
                    },
                'deny_reset_limit_policy': {
                    'type': 'int',
                    },
                'permit_respond_to_user_mac': {
                    'type': 'bool',
                    },
                'reset_respond_to_user_mac': {
                    'type': 'bool',
                    },
                'set_dscp': {
                    'type': 'bool',
                    },
                'dscp_value': {
                    'type': 'str',
                    'choices': ['default', 'af11', 'af12', 'af13', 'af21', 'af22', 'af23', 'af31', 'af32', 'af33', 'af41', 'af42', 'af43', 'cs1', 'cs2', 'cs3', 'cs4', 'cs5', 'cs6', 'cs7', 'ef']
                    },
                'dscp_number': {
                    'type': 'int',
                    },
                'tcp': {
                    'type': 'bool',
                    },
                'syn_cookie': {
                    'type': 'bool',
                    },
                'syn_cookie_enable': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                    },
                'threshold_val': {
                    'type': 'int',
                    },
                'on_timeout': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'move_rule': {
                'type': 'dict',
                'location': {
                    'type': 'str',
                    'choices': ['top', 'before', 'after', 'bottom']
                    },
                'target_rule': {
                    'type': 'str',
                    }
                }
            },
        'rules_by_zone': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type': 'str',
                    'choices': ['all', 'dummy']
                    }
                }
            },
        'application': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'track_app_rule_list': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'app': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'tag': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'policy_status': {
                'type': 'str',
                },
            'policy_unmatched_drop': {
                'type': 'int',
                },
            'policy_permit': {
                'type': 'int',
                },
            'policy_deny': {
                'type': 'int',
                },
            'policy_reset': {
                'type': 'int',
                },
            'policy_rule_count': {
                'type': 'int',
                },
            'rule_stats': {
                'type': 'list',
                'rule_name': {
                    'type': 'str',
                    },
                'rule_hitcount': {
                    'type': 'int',
                    },
                'rule_action': {
                    'type': 'str',
                    },
                'rule_status': {
                    'type': 'str',
                    }
                },
            'total_hit': {
                'type': 'int',
                },
            'total_permit_bytes': {
                'type': 'int',
                },
            'total_deny_bytes': {
                'type': 'int',
                },
            'total_reset_bytes': {
                'type': 'int',
                },
            'total_bytes': {
                'type': 'int',
                },
            'total_permit_packets': {
                'type': 'int',
                },
            'total_deny_packets': {
                'type': 'int',
                },
            'total_reset_packets': {
                'type': 'int',
                },
            'total_packets': {
                'type': 'int',
                },
            'total_active_tcp': {
                'type': 'int',
                },
            'total_active_udp': {
                'type': 'int',
                },
            'total_active_icmp': {
                'type': 'int',
                },
            'total_active_others': {
                'type': 'int',
                },
            'show_total_stats': {
                'type': 'str',
                },
            'topn_rules': {
                'type': 'str',
                },
            'name': {
                'type': 'str',
                'required': True,
                },
            'rule_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'oper': {
                    'type': 'dict',
                    'hitcount': {
                        'type': 'int',
                        },
                    'last_hitcount_time': {
                        'type': 'str',
                        },
                    'action': {
                        'type': 'str',
                        },
                    'status': {
                        'type': 'str',
                        },
                    'permitbytes': {
                        'type': 'int',
                        },
                    'denybytes': {
                        'type': 'int',
                        },
                    'resetbytes': {
                        'type': 'int',
                        },
                    'totalbytes': {
                        'type': 'int',
                        },
                    'permitpackets': {
                        'type': 'int',
                        },
                    'denypackets': {
                        'type': 'int',
                        },
                    'resetpackets': {
                        'type': 'int',
                        },
                    'totalpackets': {
                        'type': 'int',
                        },
                    'activesessiontcp': {
                        'type': 'int',
                        },
                    'activesessionudp': {
                        'type': 'int',
                        },
                    'activesessionicmp': {
                        'type': 'int',
                        },
                    'activesessionsctp': {
                        'type': 'int',
                        },
                    'activesessionother': {
                        'type': 'int',
                        },
                    'activesessiontotal': {
                        'type': 'int',
                        },
                    'sessiontcp': {
                        'type': 'int',
                        },
                    'sessionudp': {
                        'type': 'int',
                        },
                    'sessionicmp': {
                        'type': 'int',
                        },
                    'sessionsctp': {
                        'type': 'int',
                        },
                    'sessionother': {
                        'type': 'int',
                        },
                    'sessiontotal': {
                        'type': 'int',
                        },
                    'ratelimitdrops': {
                        'type': 'int',
                        },
                    'syncookieon': {
                        'type': 'int',
                        },
                    'synacksent': {
                        'type': 'int',
                        },
                    'verificationpassed': {
                        'type': 'int',
                        },
                    'verificationfailed': {
                        'type': 'int',
                        },
                    'tcphalfopencount': {
                        'type': 'int',
                        }
                    }
                },
            'rules_by_zone': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'group_list': {
                        'type': 'list',
                        'from': {
                            'type': 'str',
                            },
                        'to': {
                            'type': 'str',
                            },
                        'rule_list': {
                            'type': 'list',
                            'name': {
                                'type': 'str',
                                },
                            'action': {
                                'type': 'str',
                                },
                            'source_list': {
                                'type': 'list',
                                'source': {
                                    'type': 'str',
                                    }
                                },
                            'dest_list': {
                                'type': 'list',
                                'dest': {
                                    'type': 'str',
                                    }
                                },
                            'service_list': {
                                'type': 'list',
                                'service': {
                                    'type': 'str',
                                    }
                                },
                            'dscp_list': {
                                'type': 'list',
                                'dscp': {
                                    'type': 'str',
                                    }
                                }
                            }
                        }
                    }
                },
            'application': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'category_stat': {
                        'type': 'str',
                        },
                    'app_stat': {
                        'type': 'str',
                        },
                    'protocol': {
                        'type': 'int',
                        },
                    'rule': {
                        'type': 'str',
                        },
                    'rule_set_only': {
                        'type': 'int',
                        },
                    'rule_list': {
                        'type': 'list',
                        'name': {
                            'type': 'str',
                            },
                        'stat_list': {
                            'type': 'list',
                            'name': {
                                'type': 'str',
                                },
                            'category': {
                                'type': 'str',
                                },
                            'ntype': {
                                'type': 'str',
                                },
                            'conns': {
                                'type': 'int',
                                },
                            'bytes': {
                                'type': 'int',
                                }
                            }
                        }
                    }
                },
            'track_app_rule_list': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'rule_list': {
                        'type': 'list',
                        'name': {
                            'type': 'str',
                            }
                        }
                    }
                }
            },
        'stats': {
            'type': 'dict',
            'unmatched_drops': {
                'type': 'str',
                },
            'permit': {
                'type': 'str',
                },
            'deny': {
                'type': 'str',
                },
            'reset': {
                'type': 'str',
                },
            'name': {
                'type': 'str',
                'required': True,
                },
            'rule_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'stats': {
                    'type': 'dict',
                    'hit_count': {
                        'type': 'str',
                        },
                    'permit_bytes': {
                        'type': 'str',
                        },
                    'deny_bytes': {
                        'type': 'str',
                        },
                    'reset_bytes': {
                        'type': 'str',
                        },
                    'permit_packets': {
                        'type': 'str',
                        },
                    'deny_packets': {
                        'type': 'str',
                        },
                    'reset_packets': {
                        'type': 'str',
                        },
                    'active_session_tcp': {
                        'type': 'str',
                        },
                    'active_session_udp': {
                        'type': 'str',
                        },
                    'active_session_icmp': {
                        'type': 'str',
                        },
                    'active_session_other': {
                        'type': 'str',
                        },
                    'session_tcp': {
                        'type': 'str',
                        },
                    'session_udp': {
                        'type': 'str',
                        },
                    'session_icmp': {
                        'type': 'str',
                        },
                    'session_other': {
                        'type': 'str',
                        },
                    'active_session_sctp': {
                        'type': 'str',
                        },
                    'session_sctp': {
                        'type': 'str',
                        },
                    'hitcount_timestamp': {
                        'type': 'str',
                        },
                    'rate_limit_drops': {
                        'type': 'str',
                        },
                    'syn_cookie_syn_ack_sent': {
                        'type': 'str',
                        },
                    'syn_cookie_verification_passed': {
                        'type': 'str',
                        },
                    'syn_cookie_verification_failed': {
                        'type': 'str',
                        },
                    'tcp_half_open_count': {
                        'type': 'str',
                        }
                    }
                },
            'rules_by_zone': {
                'type': 'dict',
                'stats': {
                    'type': 'dict',
                    'dummy': {
                        'type': 'str',
                        }
                    }
                },
            'track_app_rule_list': {
                'type': 'dict',
                'stats': {
                    'type': 'dict',
                    'dummy': {
                        'type': 'str',
                        }
                    }
                },
            'app': {
                'type': 'dict',
                'stats': {
                    'type': 'dict',
                    'appstat1': {
                        'type': 'str',
                        },
                    'appstat2': {
                        'type': 'str',
                        },
                    'appstat3': {
                        'type': 'str',
                        },
                    'appstat4': {
                        'type': 'str',
                        },
                    'appstat5': {
                        'type': 'str',
                        },
                    'appstat6': {
                        'type': 'str',
                        },
                    'appstat7': {
                        'type': 'str',
                        },
                    'appstat8': {
                        'type': 'str',
                        },
                    'appstat9': {
                        'type': 'str',
                        },
                    'appstat10': {
                        'type': 'str',
                        },
                    'appstat11': {
                        'type': 'str',
                        },
                    'appstat12': {
                        'type': 'str',
                        },
                    'appstat13': {
                        'type': 'str',
                        },
                    'appstat14': {
                        'type': 'str',
                        },
                    'appstat15': {
                        'type': 'str',
                        },
                    'appstat16': {
                        'type': 'str',
                        },
                    'appstat17': {
                        'type': 'str',
                        },
                    'appstat18': {
                        'type': 'str',
                        },
                    'appstat19': {
                        'type': 'str',
                        },
                    'appstat20': {
                        'type': 'str',
                        },
                    'appstat21': {
                        'type': 'str',
                        },
                    'appstat22': {
                        'type': 'str',
                        },
                    'appstat23': {
                        'type': 'str',
                        },
                    'appstat24': {
                        'type': 'str',
                        },
                    'appstat25': {
                        'type': 'str',
                        },
                    'appstat26': {
                        'type': 'str',
                        },
                    'appstat27': {
                        'type': 'str',
                        },
                    'appstat28': {
                        'type': 'str',
                        },
                    'appstat29': {
                        'type': 'str',
                        },
                    'appstat30': {
                        'type': 'str',
                        },
                    'appstat31': {
                        'type': 'str',
                        },
                    'appstat32': {
                        'type': 'str',
                        },
                    'appstat33': {
                        'type': 'str',
                        },
                    'appstat34': {
                        'type': 'str',
                        },
                    'appstat35': {
                        'type': 'str',
                        },
                    'appstat36': {
                        'type': 'str',
                        },
                    'appstat37': {
                        'type': 'str',
                        },
                    'appstat38': {
                        'type': 'str',
                        },
                    'appstat39': {
                        'type': 'str',
                        },
                    'appstat40': {
                        'type': 'str',
                        },
                    'appstat41': {
                        'type': 'str',
                        },
                    'appstat42': {
                        'type': 'str',
                        },
                    'appstat43': {
                        'type': 'str',
                        },
                    'appstat44': {
                        'type': 'str',
                        },
                    'appstat45': {
                        'type': 'str',
                        },
                    'appstat46': {
                        'type': 'str',
                        },
                    'appstat47': {
                        'type': 'str',
                        },
                    'appstat48': {
                        'type': 'str',
                        },
                    'appstat49': {
                        'type': 'str',
                        },
                    'appstat50': {
                        'type': 'str',
                        },
                    'appstat51': {
                        'type': 'str',
                        },
                    'appstat52': {
                        'type': 'str',
                        },
                    'appstat53': {
                        'type': 'str',
                        },
                    'appstat54': {
                        'type': 'str',
                        },
                    'appstat55': {
                        'type': 'str',
                        },
                    'appstat56': {
                        'type': 'str',
                        },
                    'appstat57': {
                        'type': 'str',
                        },
                    'appstat58': {
                        'type': 'str',
                        },
                    'appstat59': {
                        'type': 'str',
                        },
                    'appstat60': {
                        'type': 'str',
                        },
                    'appstat61': {
                        'type': 'str',
                        },
                    'appstat62': {
                        'type': 'str',
                        },
                    'appstat63': {
                        'type': 'str',
                        },
                    'appstat64': {
                        'type': 'str',
                        },
                    'appstat65': {
                        'type': 'str',
                        },
                    'appstat66': {
                        'type': 'str',
                        },
                    'appstat67': {
                        'type': 'str',
                        },
                    'appstat68': {
                        'type': 'str',
                        },
                    'appstat69': {
                        'type': 'str',
                        },
                    'appstat70': {
                        'type': 'str',
                        },
                    'appstat71': {
                        'type': 'str',
                        },
                    'appstat72': {
                        'type': 'str',
                        },
                    'appstat73': {
                        'type': 'str',
                        },
                    'appstat74': {
                        'type': 'str',
                        },
                    'appstat75': {
                        'type': 'str',
                        },
                    'appstat76': {
                        'type': 'str',
                        },
                    'appstat77': {
                        'type': 'str',
                        },
                    'appstat78': {
                        'type': 'str',
                        },
                    'appstat79': {
                        'type': 'str',
                        },
                    'appstat80': {
                        'type': 'str',
                        },
                    'appstat81': {
                        'type': 'str',
                        },
                    'appstat82': {
                        'type': 'str',
                        },
                    'appstat83': {
                        'type': 'str',
                        },
                    'appstat84': {
                        'type': 'str',
                        },
                    'appstat85': {
                        'type': 'str',
                        },
                    'appstat86': {
                        'type': 'str',
                        },
                    'appstat87': {
                        'type': 'str',
                        },
                    'appstat88': {
                        'type': 'str',
                        },
                    'appstat89': {
                        'type': 'str',
                        },
                    'appstat90': {
                        'type': 'str',
                        },
                    'appstat91': {
                        'type': 'str',
                        },
                    'appstat92': {
                        'type': 'str',
                        },
                    'appstat93': {
                        'type': 'str',
                        },
                    'appstat94': {
                        'type': 'str',
                        },
                    'appstat95': {
                        'type': 'str',
                        },
                    'appstat96': {
                        'type': 'str',
                        },
                    'appstat97': {
                        'type': 'str',
                        },
                    'appstat98': {
                        'type': 'str',
                        },
                    'appstat99': {
                        'type': 'str',
                        },
                    'appstat100': {
                        'type': 'str',
                        },
                    'appstat101': {
                        'type': 'str',
                        },
                    'appstat102': {
                        'type': 'str',
                        },
                    'appstat103': {
                        'type': 'str',
                        },
                    'appstat104': {
                        'type': 'str',
                        },
                    'appstat105': {
                        'type': 'str',
                        },
                    'appstat106': {
                        'type': 'str',
                        },
                    'appstat107': {
                        'type': 'str',
                        },
                    'appstat108': {
                        'type': 'str',
                        },
                    'appstat109': {
                        'type': 'str',
                        },
                    'appstat110': {
                        'type': 'str',
                        },
                    'appstat111': {
                        'type': 'str',
                        },
                    'appstat112': {
                        'type': 'str',
                        },
                    'appstat113': {
                        'type': 'str',
                        },
                    'appstat114': {
                        'type': 'str',
                        },
                    'appstat115': {
                        'type': 'str',
                        },
                    'appstat116': {
                        'type': 'str',
                        },
                    'appstat117': {
                        'type': 'str',
                        },
                    'appstat118': {
                        'type': 'str',
                        },
                    'appstat119': {
                        'type': 'str',
                        },
                    'appstat120': {
                        'type': 'str',
                        },
                    'appstat121': {
                        'type': 'str',
                        },
                    'appstat122': {
                        'type': 'str',
                        },
                    'appstat123': {
                        'type': 'str',
                        },
                    'appstat124': {
                        'type': 'str',
                        },
                    'appstat125': {
                        'type': 'str',
                        },
                    'appstat126': {
                        'type': 'str',
                        },
                    'appstat127': {
                        'type': 'str',
                        },
                    'appstat128': {
                        'type': 'str',
                        },
                    'appstat129': {
                        'type': 'str',
                        },
                    'appstat130': {
                        'type': 'str',
                        },
                    'appstat131': {
                        'type': 'str',
                        },
                    'appstat132': {
                        'type': 'str',
                        },
                    'appstat133': {
                        'type': 'str',
                        },
                    'appstat134': {
                        'type': 'str',
                        },
                    'appstat135': {
                        'type': 'str',
                        },
                    'appstat136': {
                        'type': 'str',
                        },
                    'appstat137': {
                        'type': 'str',
                        },
                    'appstat138': {
                        'type': 'str',
                        },
                    'appstat139': {
                        'type': 'str',
                        },
                    'appstat140': {
                        'type': 'str',
                        },
                    'appstat141': {
                        'type': 'str',
                        },
                    'appstat142': {
                        'type': 'str',
                        },
                    'appstat143': {
                        'type': 'str',
                        },
                    'appstat144': {
                        'type': 'str',
                        },
                    'appstat145': {
                        'type': 'str',
                        },
                    'appstat146': {
                        'type': 'str',
                        },
                    'appstat147': {
                        'type': 'str',
                        },
                    'appstat148': {
                        'type': 'str',
                        },
                    'appstat149': {
                        'type': 'str',
                        },
                    'appstat150': {
                        'type': 'str',
                        },
                    'appstat151': {
                        'type': 'str',
                        },
                    'appstat152': {
                        'type': 'str',
                        },
                    'appstat153': {
                        'type': 'str',
                        },
                    'appstat154': {
                        'type': 'str',
                        },
                    'appstat155': {
                        'type': 'str',
                        },
                    'appstat156': {
                        'type': 'str',
                        },
                    'appstat157': {
                        'type': 'str',
                        },
                    'appstat158': {
                        'type': 'str',
                        },
                    'appstat159': {
                        'type': 'str',
                        },
                    'appstat160': {
                        'type': 'str',
                        },
                    'appstat161': {
                        'type': 'str',
                        },
                    'appstat162': {
                        'type': 'str',
                        },
                    'appstat163': {
                        'type': 'str',
                        },
                    'appstat164': {
                        'type': 'str',
                        },
                    'appstat165': {
                        'type': 'str',
                        },
                    'appstat166': {
                        'type': 'str',
                        },
                    'appstat167': {
                        'type': 'str',
                        },
                    'appstat168': {
                        'type': 'str',
                        },
                    'appstat169': {
                        'type': 'str',
                        },
                    'appstat170': {
                        'type': 'str',
                        },
                    'appstat171': {
                        'type': 'str',
                        },
                    'appstat172': {
                        'type': 'str',
                        },
                    'appstat173': {
                        'type': 'str',
                        },
                    'appstat174': {
                        'type': 'str',
                        },
                    'appstat175': {
                        'type': 'str',
                        },
                    'appstat176': {
                        'type': 'str',
                        },
                    'appstat177': {
                        'type': 'str',
                        },
                    'appstat178': {
                        'type': 'str',
                        },
                    'appstat179': {
                        'type': 'str',
                        },
                    'appstat180': {
                        'type': 'str',
                        },
                    'appstat181': {
                        'type': 'str',
                        },
                    'appstat182': {
                        'type': 'str',
                        },
                    'appstat183': {
                        'type': 'str',
                        },
                    'appstat184': {
                        'type': 'str',
                        },
                    'appstat185': {
                        'type': 'str',
                        },
                    'appstat186': {
                        'type': 'str',
                        },
                    'appstat187': {
                        'type': 'str',
                        },
                    'appstat188': {
                        'type': 'str',
                        },
                    'appstat189': {
                        'type': 'str',
                        },
                    'appstat190': {
                        'type': 'str',
                        },
                    'appstat191': {
                        'type': 'str',
                        },
                    'appstat192': {
                        'type': 'str',
                        },
                    'appstat193': {
                        'type': 'str',
                        },
                    'appstat194': {
                        'type': 'str',
                        },
                    'appstat195': {
                        'type': 'str',
                        },
                    'appstat196': {
                        'type': 'str',
                        },
                    'appstat197': {
                        'type': 'str',
                        },
                    'appstat198': {
                        'type': 'str',
                        },
                    'appstat199': {
                        'type': 'str',
                        },
                    'appstat200': {
                        'type': 'str',
                        },
                    'appstat201': {
                        'type': 'str',
                        },
                    'appstat202': {
                        'type': 'str',
                        },
                    'appstat203': {
                        'type': 'str',
                        },
                    'appstat204': {
                        'type': 'str',
                        },
                    'appstat205': {
                        'type': 'str',
                        },
                    'appstat206': {
                        'type': 'str',
                        },
                    'appstat207': {
                        'type': 'str',
                        },
                    'appstat208': {
                        'type': 'str',
                        },
                    'appstat209': {
                        'type': 'str',
                        },
                    'appstat210': {
                        'type': 'str',
                        },
                    'appstat211': {
                        'type': 'str',
                        },
                    'appstat212': {
                        'type': 'str',
                        },
                    'appstat213': {
                        'type': 'str',
                        },
                    'appstat214': {
                        'type': 'str',
                        },
                    'appstat215': {
                        'type': 'str',
                        },
                    'appstat216': {
                        'type': 'str',
                        },
                    'appstat217': {
                        'type': 'str',
                        },
                    'appstat218': {
                        'type': 'str',
                        },
                    'appstat219': {
                        'type': 'str',
                        },
                    'appstat220': {
                        'type': 'str',
                        },
                    'appstat221': {
                        'type': 'str',
                        },
                    'appstat222': {
                        'type': 'str',
                        },
                    'appstat223': {
                        'type': 'str',
                        },
                    'appstat224': {
                        'type': 'str',
                        },
                    'appstat225': {
                        'type': 'str',
                        },
                    'appstat226': {
                        'type': 'str',
                        },
                    'appstat227': {
                        'type': 'str',
                        },
                    'appstat228': {
                        'type': 'str',
                        },
                    'appstat229': {
                        'type': 'str',
                        },
                    'appstat230': {
                        'type': 'str',
                        },
                    'appstat231': {
                        'type': 'str',
                        },
                    'appstat232': {
                        'type': 'str',
                        },
                    'appstat233': {
                        'type': 'str',
                        },
                    'appstat234': {
                        'type': 'str',
                        },
                    'appstat235': {
                        'type': 'str',
                        },
                    'appstat236': {
                        'type': 'str',
                        },
                    'appstat237': {
                        'type': 'str',
                        },
                    'appstat238': {
                        'type': 'str',
                        },
                    'appstat239': {
                        'type': 'str',
                        },
                    'appstat240': {
                        'type': 'str',
                        },
                    'appstat241': {
                        'type': 'str',
                        },
                    'appstat242': {
                        'type': 'str',
                        },
                    'appstat243': {
                        'type': 'str',
                        },
                    'appstat244': {
                        'type': 'str',
                        },
                    'appstat245': {
                        'type': 'str',
                        },
                    'appstat246': {
                        'type': 'str',
                        },
                    'appstat247': {
                        'type': 'str',
                        },
                    'appstat248': {
                        'type': 'str',
                        },
                    'appstat249': {
                        'type': 'str',
                        },
                    'appstat250': {
                        'type': 'str',
                        },
                    'appstat251': {
                        'type': 'str',
                        },
                    'appstat252': {
                        'type': 'str',
                        },
                    'appstat253': {
                        'type': 'str',
                        },
                    'appstat254': {
                        'type': 'str',
                        },
                    'appstat255': {
                        'type': 'str',
                        },
                    'appstat256': {
                        'type': 'str',
                        },
                    'appstat257': {
                        'type': 'str',
                        },
                    'appstat258': {
                        'type': 'str',
                        },
                    'appstat259': {
                        'type': 'str',
                        },
                    'appstat260': {
                        'type': 'str',
                        },
                    'appstat261': {
                        'type': 'str',
                        },
                    'appstat262': {
                        'type': 'str',
                        },
                    'appstat263': {
                        'type': 'str',
                        },
                    'appstat264': {
                        'type': 'str',
                        },
                    'appstat265': {
                        'type': 'str',
                        },
                    'appstat266': {
                        'type': 'str',
                        },
                    'appstat267': {
                        'type': 'str',
                        },
                    'appstat268': {
                        'type': 'str',
                        },
                    'appstat269': {
                        'type': 'str',
                        },
                    'appstat270': {
                        'type': 'str',
                        },
                    'appstat271': {
                        'type': 'str',
                        },
                    'appstat272': {
                        'type': 'str',
                        },
                    'appstat273': {
                        'type': 'str',
                        },
                    'appstat274': {
                        'type': 'str',
                        },
                    'appstat275': {
                        'type': 'str',
                        },
                    'appstat276': {
                        'type': 'str',
                        },
                    'appstat277': {
                        'type': 'str',
                        },
                    'appstat278': {
                        'type': 'str',
                        },
                    'appstat279': {
                        'type': 'str',
                        },
                    'appstat280': {
                        'type': 'str',
                        },
                    'appstat281': {
                        'type': 'str',
                        },
                    'appstat282': {
                        'type': 'str',
                        },
                    'appstat283': {
                        'type': 'str',
                        },
                    'appstat284': {
                        'type': 'str',
                        },
                    'appstat285': {
                        'type': 'str',
                        },
                    'appstat286': {
                        'type': 'str',
                        },
                    'appstat287': {
                        'type': 'str',
                        },
                    'appstat288': {
                        'type': 'str',
                        },
                    'appstat289': {
                        'type': 'str',
                        },
                    'appstat290': {
                        'type': 'str',
                        },
                    'appstat291': {
                        'type': 'str',
                        },
                    'appstat292': {
                        'type': 'str',
                        },
                    'appstat293': {
                        'type': 'str',
                        },
                    'appstat294': {
                        'type': 'str',
                        },
                    'appstat295': {
                        'type': 'str',
                        },
                    'appstat296': {
                        'type': 'str',
                        },
                    'appstat297': {
                        'type': 'str',
                        },
                    'appstat298': {
                        'type': 'str',
                        },
                    'appstat299': {
                        'type': 'str',
                        },
                    'appstat300': {
                        'type': 'str',
                        },
                    'appstat301': {
                        'type': 'str',
                        },
                    'appstat302': {
                        'type': 'str',
                        },
                    'appstat303': {
                        'type': 'str',
                        },
                    'appstat304': {
                        'type': 'str',
                        },
                    'appstat305': {
                        'type': 'str',
                        },
                    'appstat306': {
                        'type': 'str',
                        },
                    'appstat307': {
                        'type': 'str',
                        },
                    'appstat308': {
                        'type': 'str',
                        },
                    'appstat309': {
                        'type': 'str',
                        },
                    'appstat310': {
                        'type': 'str',
                        },
                    'appstat311': {
                        'type': 'str',
                        },
                    'appstat312': {
                        'type': 'str',
                        },
                    'appstat313': {
                        'type': 'str',
                        },
                    'appstat314': {
                        'type': 'str',
                        },
                    'appstat315': {
                        'type': 'str',
                        },
                    'appstat316': {
                        'type': 'str',
                        },
                    'appstat317': {
                        'type': 'str',
                        },
                    'appstat318': {
                        'type': 'str',
                        },
                    'appstat319': {
                        'type': 'str',
                        },
                    'appstat320': {
                        'type': 'str',
                        },
                    'appstat321': {
                        'type': 'str',
                        },
                    'appstat322': {
                        'type': 'str',
                        },
                    'appstat323': {
                        'type': 'str',
                        },
                    'appstat324': {
                        'type': 'str',
                        },
                    'appstat325': {
                        'type': 'str',
                        },
                    'appstat326': {
                        'type': 'str',
                        },
                    'appstat327': {
                        'type': 'str',
                        },
                    'appstat328': {
                        'type': 'str',
                        },
                    'appstat329': {
                        'type': 'str',
                        },
                    'appstat330': {
                        'type': 'str',
                        },
                    'appstat331': {
                        'type': 'str',
                        },
                    'appstat332': {
                        'type': 'str',
                        },
                    'appstat333': {
                        'type': 'str',
                        },
                    'appstat334': {
                        'type': 'str',
                        },
                    'appstat335': {
                        'type': 'str',
                        },
                    'appstat336': {
                        'type': 'str',
                        },
                    'appstat337': {
                        'type': 'str',
                        },
                    'appstat338': {
                        'type': 'str',
                        },
                    'appstat339': {
                        'type': 'str',
                        },
                    'appstat340': {
                        'type': 'str',
                        },
                    'appstat341': {
                        'type': 'str',
                        },
                    'appstat342': {
                        'type': 'str',
                        },
                    'appstat343': {
                        'type': 'str',
                        },
                    'appstat344': {
                        'type': 'str',
                        },
                    'appstat345': {
                        'type': 'str',
                        },
                    'appstat346': {
                        'type': 'str',
                        },
                    'appstat347': {
                        'type': 'str',
                        },
                    'appstat348': {
                        'type': 'str',
                        },
                    'appstat349': {
                        'type': 'str',
                        },
                    'appstat350': {
                        'type': 'str',
                        },
                    'appstat351': {
                        'type': 'str',
                        },
                    'appstat352': {
                        'type': 'str',
                        },
                    'appstat353': {
                        'type': 'str',
                        },
                    'appstat354': {
                        'type': 'str',
                        },
                    'appstat355': {
                        'type': 'str',
                        },
                    'appstat356': {
                        'type': 'str',
                        },
                    'appstat357': {
                        'type': 'str',
                        },
                    'appstat358': {
                        'type': 'str',
                        },
                    'appstat359': {
                        'type': 'str',
                        },
                    'appstat360': {
                        'type': 'str',
                        },
                    'appstat361': {
                        'type': 'str',
                        },
                    'appstat362': {
                        'type': 'str',
                        },
                    'appstat363': {
                        'type': 'str',
                        },
                    'appstat364': {
                        'type': 'str',
                        },
                    'appstat365': {
                        'type': 'str',
                        },
                    'appstat366': {
                        'type': 'str',
                        },
                    'appstat367': {
                        'type': 'str',
                        },
                    'appstat368': {
                        'type': 'str',
                        },
                    'appstat369': {
                        'type': 'str',
                        },
                    'appstat370': {
                        'type': 'str',
                        },
                    'appstat371': {
                        'type': 'str',
                        },
                    'appstat372': {
                        'type': 'str',
                        },
                    'appstat373': {
                        'type': 'str',
                        },
                    'appstat374': {
                        'type': 'str',
                        },
                    'appstat375': {
                        'type': 'str',
                        },
                    'appstat376': {
                        'type': 'str',
                        },
                    'appstat377': {
                        'type': 'str',
                        },
                    'appstat378': {
                        'type': 'str',
                        },
                    'appstat379': {
                        'type': 'str',
                        },
                    'appstat380': {
                        'type': 'str',
                        },
                    'appstat381': {
                        'type': 'str',
                        },
                    'appstat382': {
                        'type': 'str',
                        },
                    'appstat383': {
                        'type': 'str',
                        },
                    'appstat384': {
                        'type': 'str',
                        },
                    'appstat385': {
                        'type': 'str',
                        },
                    'appstat386': {
                        'type': 'str',
                        },
                    'appstat387': {
                        'type': 'str',
                        },
                    'appstat388': {
                        'type': 'str',
                        },
                    'appstat389': {
                        'type': 'str',
                        },
                    'appstat390': {
                        'type': 'str',
                        },
                    'appstat391': {
                        'type': 'str',
                        },
                    'appstat392': {
                        'type': 'str',
                        },
                    'appstat393': {
                        'type': 'str',
                        },
                    'appstat394': {
                        'type': 'str',
                        },
                    'appstat395': {
                        'type': 'str',
                        },
                    'appstat396': {
                        'type': 'str',
                        },
                    'appstat397': {
                        'type': 'str',
                        },
                    'appstat398': {
                        'type': 'str',
                        },
                    'appstat399': {
                        'type': 'str',
                        },
                    'appstat400': {
                        'type': 'str',
                        },
                    'appstat401': {
                        'type': 'str',
                        },
                    'appstat402': {
                        'type': 'str',
                        },
                    'appstat403': {
                        'type': 'str',
                        },
                    'appstat404': {
                        'type': 'str',
                        },
                    'appstat405': {
                        'type': 'str',
                        },
                    'appstat406': {
                        'type': 'str',
                        },
                    'appstat407': {
                        'type': 'str',
                        },
                    'appstat408': {
                        'type': 'str',
                        },
                    'appstat409': {
                        'type': 'str',
                        },
                    'appstat410': {
                        'type': 'str',
                        },
                    'appstat411': {
                        'type': 'str',
                        },
                    'appstat412': {
                        'type': 'str',
                        },
                    'appstat413': {
                        'type': 'str',
                        },
                    'appstat414': {
                        'type': 'str',
                        },
                    'appstat415': {
                        'type': 'str',
                        },
                    'appstat416': {
                        'type': 'str',
                        },
                    'appstat417': {
                        'type': 'str',
                        },
                    'appstat418': {
                        'type': 'str',
                        },
                    'appstat419': {
                        'type': 'str',
                        },
                    'appstat420': {
                        'type': 'str',
                        },
                    'appstat421': {
                        'type': 'str',
                        },
                    'appstat422': {
                        'type': 'str',
                        },
                    'appstat423': {
                        'type': 'str',
                        },
                    'appstat424': {
                        'type': 'str',
                        },
                    'appstat425': {
                        'type': 'str',
                        },
                    'appstat426': {
                        'type': 'str',
                        },
                    'appstat427': {
                        'type': 'str',
                        },
                    'appstat428': {
                        'type': 'str',
                        },
                    'appstat429': {
                        'type': 'str',
                        },
                    'appstat430': {
                        'type': 'str',
                        },
                    'appstat431': {
                        'type': 'str',
                        },
                    'appstat432': {
                        'type': 'str',
                        },
                    'appstat433': {
                        'type': 'str',
                        },
                    'appstat434': {
                        'type': 'str',
                        },
                    'appstat435': {
                        'type': 'str',
                        },
                    'appstat436': {
                        'type': 'str',
                        },
                    'appstat437': {
                        'type': 'str',
                        },
                    'appstat438': {
                        'type': 'str',
                        },
                    'appstat439': {
                        'type': 'str',
                        },
                    'appstat440': {
                        'type': 'str',
                        },
                    'appstat441': {
                        'type': 'str',
                        },
                    'appstat442': {
                        'type': 'str',
                        },
                    'appstat443': {
                        'type': 'str',
                        },
                    'appstat444': {
                        'type': 'str',
                        },
                    'appstat445': {
                        'type': 'str',
                        },
                    'appstat446': {
                        'type': 'str',
                        },
                    'appstat447': {
                        'type': 'str',
                        },
                    'appstat448': {
                        'type': 'str',
                        },
                    'appstat449': {
                        'type': 'str',
                        },
                    'appstat450': {
                        'type': 'str',
                        },
                    'appstat451': {
                        'type': 'str',
                        },
                    'appstat452': {
                        'type': 'str',
                        },
                    'appstat453': {
                        'type': 'str',
                        },
                    'appstat454': {
                        'type': 'str',
                        },
                    'appstat455': {
                        'type': 'str',
                        },
                    'appstat456': {
                        'type': 'str',
                        },
                    'appstat457': {
                        'type': 'str',
                        },
                    'appstat458': {
                        'type': 'str',
                        },
                    'appstat459': {
                        'type': 'str',
                        },
                    'appstat460': {
                        'type': 'str',
                        },
                    'appstat461': {
                        'type': 'str',
                        },
                    'appstat462': {
                        'type': 'str',
                        },
                    'appstat463': {
                        'type': 'str',
                        },
                    'appstat464': {
                        'type': 'str',
                        },
                    'appstat465': {
                        'type': 'str',
                        },
                    'appstat466': {
                        'type': 'str',
                        },
                    'appstat467': {
                        'type': 'str',
                        },
                    'appstat468': {
                        'type': 'str',
                        },
                    'appstat469': {
                        'type': 'str',
                        },
                    'appstat470': {
                        'type': 'str',
                        },
                    'appstat471': {
                        'type': 'str',
                        },
                    'appstat472': {
                        'type': 'str',
                        },
                    'appstat473': {
                        'type': 'str',
                        },
                    'appstat474': {
                        'type': 'str',
                        },
                    'appstat475': {
                        'type': 'str',
                        },
                    'appstat476': {
                        'type': 'str',
                        },
                    'appstat477': {
                        'type': 'str',
                        },
                    'appstat478': {
                        'type': 'str',
                        },
                    'appstat479': {
                        'type': 'str',
                        },
                    'appstat480': {
                        'type': 'str',
                        },
                    'appstat481': {
                        'type': 'str',
                        },
                    'appstat482': {
                        'type': 'str',
                        },
                    'appstat483': {
                        'type': 'str',
                        },
                    'appstat484': {
                        'type': 'str',
                        },
                    'appstat485': {
                        'type': 'str',
                        },
                    'appstat486': {
                        'type': 'str',
                        },
                    'appstat487': {
                        'type': 'str',
                        },
                    'appstat488': {
                        'type': 'str',
                        },
                    'appstat489': {
                        'type': 'str',
                        },
                    'appstat490': {
                        'type': 'str',
                        },
                    'appstat491': {
                        'type': 'str',
                        },
                    'appstat492': {
                        'type': 'str',
                        },
                    'appstat493': {
                        'type': 'str',
                        },
                    'appstat494': {
                        'type': 'str',
                        },
                    'appstat495': {
                        'type': 'str',
                        },
                    'appstat496': {
                        'type': 'str',
                        },
                    'appstat497': {
                        'type': 'str',
                        },
                    'appstat498': {
                        'type': 'str',
                        },
                    'appstat499': {
                        'type': 'str',
                        },
                    'appstat500': {
                        'type': 'str',
                        },
                    'appstat501': {
                        'type': 'str',
                        },
                    'appstat502': {
                        'type': 'str',
                        },
                    'appstat503': {
                        'type': 'str',
                        },
                    'appstat504': {
                        'type': 'str',
                        },
                    'appstat505': {
                        'type': 'str',
                        },
                    'appstat506': {
                        'type': 'str',
                        },
                    'appstat507': {
                        'type': 'str',
                        },
                    'appstat508': {
                        'type': 'str',
                        },
                    'appstat509': {
                        'type': 'str',
                        },
                    'appstat510': {
                        'type': 'str',
                        },
                    'appstat511': {
                        'type': 'str',
                        }
                    }
                },
            'tag': {
                'type': 'dict',
                'stats': {
                    'type': 'dict',
                    'categorystat1': {
                        'type': 'str',
                        },
                    'categorystat2': {
                        'type': 'str',
                        },
                    'categorystat3': {
                        'type': 'str',
                        },
                    'categorystat4': {
                        'type': 'str',
                        },
                    'categorystat5': {
                        'type': 'str',
                        },
                    'categorystat6': {
                        'type': 'str',
                        },
                    'categorystat7': {
                        'type': 'str',
                        },
                    'categorystat8': {
                        'type': 'str',
                        },
                    'categorystat9': {
                        'type': 'str',
                        },
                    'categorystat10': {
                        'type': 'str',
                        },
                    'categorystat11': {
                        'type': 'str',
                        },
                    'categorystat12': {
                        'type': 'str',
                        },
                    'categorystat13': {
                        'type': 'str',
                        },
                    'categorystat14': {
                        'type': 'str',
                        },
                    'categorystat15': {
                        'type': 'str',
                        },
                    'categorystat16': {
                        'type': 'str',
                        },
                    'categorystat17': {
                        'type': 'str',
                        },
                    'categorystat18': {
                        'type': 'str',
                        },
                    'categorystat19': {
                        'type': 'str',
                        },
                    'categorystat20': {
                        'type': 'str',
                        },
                    'categorystat21': {
                        'type': 'str',
                        },
                    'categorystat22': {
                        'type': 'str',
                        },
                    'categorystat23': {
                        'type': 'str',
                        },
                    'categorystat24': {
                        'type': 'str',
                        },
                    'categorystat25': {
                        'type': 'str',
                        },
                    'categorystat26': {
                        'type': 'str',
                        },
                    'categorystat27': {
                        'type': 'str',
                        },
                    'categorystat28': {
                        'type': 'str',
                        },
                    'categorystat29': {
                        'type': 'str',
                        },
                    'categorystat30': {
                        'type': 'str',
                        },
                    'categorystat31': {
                        'type': 'str',
                        },
                    'categorystat32': {
                        'type': 'str',
                        },
                    'categorystat33': {
                        'type': 'str',
                        },
                    'categorystat34': {
                        'type': 'str',
                        },
                    'categorystat35': {
                        'type': 'str',
                        },
                    'categorystat36': {
                        'type': 'str',
                        },
                    'categorystat37': {
                        'type': 'str',
                        },
                    'categorystat38': {
                        'type': 'str',
                        },
                    'categorystat39': {
                        'type': 'str',
                        },
                    'categorystat40': {
                        'type': 'str',
                        },
                    'categorystat41': {
                        'type': 'str',
                        },
                    'categorystat42': {
                        'type': 'str',
                        },
                    'categorystat43': {
                        'type': 'str',
                        },
                    'categorystat44': {
                        'type': 'str',
                        },
                    'categorystat45': {
                        'type': 'str',
                        },
                    'categorystat46': {
                        'type': 'str',
                        },
                    'categorystat47': {
                        'type': 'str',
                        },
                    'categorystat48': {
                        'type': 'str',
                        },
                    'categorystat49': {
                        'type': 'str',
                        },
                    'categorystat50': {
                        'type': 'str',
                        },
                    'categorystat51': {
                        'type': 'str',
                        },
                    'categorystat52': {
                        'type': 'str',
                        },
                    'categorystat53': {
                        'type': 'str',
                        },
                    'categorystat54': {
                        'type': 'str',
                        },
                    'categorystat55': {
                        'type': 'str',
                        },
                    'categorystat56': {
                        'type': 'str',
                        },
                    'categorystat57': {
                        'type': 'str',
                        },
                    'categorystat58': {
                        'type': 'str',
                        },
                    'categorystat59': {
                        'type': 'str',
                        },
                    'categorystat60': {
                        'type': 'str',
                        },
                    'categorystat61': {
                        'type': 'str',
                        },
                    'categorystat62': {
                        'type': 'str',
                        },
                    'categorystat63': {
                        'type': 'str',
                        },
                    'categorystat64': {
                        'type': 'str',
                        },
                    'categorystat65': {
                        'type': 'str',
                        },
                    'categorystat66': {
                        'type': 'str',
                        },
                    'categorystat67': {
                        'type': 'str',
                        },
                    'categorystat68': {
                        'type': 'str',
                        },
                    'categorystat69': {
                        'type': 'str',
                        },
                    'categorystat70': {
                        'type': 'str',
                        },
                    'categorystat71': {
                        'type': 'str',
                        },
                    'categorystat72': {
                        'type': 'str',
                        },
                    'categorystat73': {
                        'type': 'str',
                        },
                    'categorystat74': {
                        'type': 'str',
                        },
                    'categorystat75': {
                        'type': 'str',
                        },
                    'categorystat76': {
                        'type': 'str',
                        },
                    'categorystat77': {
                        'type': 'str',
                        },
                    'categorystat78': {
                        'type': 'str',
                        },
                    'categorystat79': {
                        'type': 'str',
                        },
                    'categorystat80': {
                        'type': 'str',
                        },
                    'categorystat81': {
                        'type': 'str',
                        },
                    'categorystat82': {
                        'type': 'str',
                        },
                    'categorystat83': {
                        'type': 'str',
                        },
                    'categorystat84': {
                        'type': 'str',
                        },
                    'categorystat85': {
                        'type': 'str',
                        },
                    'categorystat86': {
                        'type': 'str',
                        },
                    'categorystat87': {
                        'type': 'str',
                        },
                    'categorystat88': {
                        'type': 'str',
                        },
                    'categorystat89': {
                        'type': 'str',
                        },
                    'categorystat90': {
                        'type': 'str',
                        },
                    'categorystat91': {
                        'type': 'str',
                        },
                    'categorystat92': {
                        'type': 'str',
                        },
                    'categorystat93': {
                        'type': 'str',
                        },
                    'categorystat94': {
                        'type': 'str',
                        },
                    'categorystat95': {
                        'type': 'str',
                        },
                    'categorystat96': {
                        'type': 'str',
                        },
                    'categorystat97': {
                        'type': 'str',
                        },
                    'categorystat98': {
                        'type': 'str',
                        },
                    'categorystat99': {
                        'type': 'str',
                        },
                    'categorystat100': {
                        'type': 'str',
                        },
                    'categorystat101': {
                        'type': 'str',
                        },
                    'categorystat102': {
                        'type': 'str',
                        },
                    'categorystat103': {
                        'type': 'str',
                        },
                    'categorystat104': {
                        'type': 'str',
                        },
                    'categorystat105': {
                        'type': 'str',
                        },
                    'categorystat106': {
                        'type': 'str',
                        },
                    'categorystat107': {
                        'type': 'str',
                        },
                    'categorystat108': {
                        'type': 'str',
                        },
                    'categorystat109': {
                        'type': 'str',
                        },
                    'categorystat110': {
                        'type': 'str',
                        },
                    'categorystat111': {
                        'type': 'str',
                        },
                    'categorystat112': {
                        'type': 'str',
                        },
                    'categorystat113': {
                        'type': 'str',
                        },
                    'categorystat114': {
                        'type': 'str',
                        },
                    'categorystat115': {
                        'type': 'str',
                        },
                    'categorystat116': {
                        'type': 'str',
                        },
                    'categorystat117': {
                        'type': 'str',
                        },
                    'categorystat118': {
                        'type': 'str',
                        },
                    'categorystat119': {
                        'type': 'str',
                        },
                    'categorystat120': {
                        'type': 'str',
                        },
                    'categorystat121': {
                        'type': 'str',
                        },
                    'categorystat122': {
                        'type': 'str',
                        },
                    'categorystat123': {
                        'type': 'str',
                        },
                    'categorystat124': {
                        'type': 'str',
                        },
                    'categorystat125': {
                        'type': 'str',
                        },
                    'categorystat126': {
                        'type': 'str',
                        },
                    'categorystat127': {
                        'type': 'str',
                        },
                    'categorystat128': {
                        'type': 'str',
                        },
                    'categorystat129': {
                        'type': 'str',
                        },
                    'categorystat130': {
                        'type': 'str',
                        },
                    'categorystat131': {
                        'type': 'str',
                        },
                    'categorystat132': {
                        'type': 'str',
                        },
                    'categorystat133': {
                        'type': 'str',
                        },
                    'categorystat134': {
                        'type': 'str',
                        },
                    'categorystat135': {
                        'type': 'str',
                        },
                    'categorystat136': {
                        'type': 'str',
                        },
                    'categorystat137': {
                        'type': 'str',
                        },
                    'categorystat138': {
                        'type': 'str',
                        },
                    'categorystat139': {
                        'type': 'str',
                        },
                    'categorystat140': {
                        'type': 'str',
                        },
                    'categorystat141': {
                        'type': 'str',
                        },
                    'categorystat142': {
                        'type': 'str',
                        },
                    'categorystat143': {
                        'type': 'str',
                        },
                    'categorystat144': {
                        'type': 'str',
                        },
                    'categorystat145': {
                        'type': 'str',
                        },
                    'categorystat146': {
                        'type': 'str',
                        },
                    'categorystat147': {
                        'type': 'str',
                        },
                    'categorystat148': {
                        'type': 'str',
                        },
                    'categorystat149': {
                        'type': 'str',
                        },
                    'categorystat150': {
                        'type': 'str',
                        },
                    'categorystat151': {
                        'type': 'str',
                        },
                    'categorystat152': {
                        'type': 'str',
                        },
                    'categorystat153': {
                        'type': 'str',
                        },
                    'categorystat154': {
                        'type': 'str',
                        },
                    'categorystat155': {
                        'type': 'str',
                        },
                    'categorystat156': {
                        'type': 'str',
                        },
                    'categorystat157': {
                        'type': 'str',
                        },
                    'categorystat158': {
                        'type': 'str',
                        },
                    'categorystat159': {
                        'type': 'str',
                        },
                    'categorystat160': {
                        'type': 'str',
                        },
                    'categorystat161': {
                        'type': 'str',
                        },
                    'categorystat162': {
                        'type': 'str',
                        },
                    'categorystat163': {
                        'type': 'str',
                        },
                    'categorystat164': {
                        'type': 'str',
                        },
                    'categorystat165': {
                        'type': 'str',
                        },
                    'categorystat166': {
                        'type': 'str',
                        },
                    'categorystat167': {
                        'type': 'str',
                        },
                    'categorystat168': {
                        'type': 'str',
                        },
                    'categorystat169': {
                        'type': 'str',
                        },
                    'categorystat170': {
                        'type': 'str',
                        },
                    'categorystat171': {
                        'type': 'str',
                        },
                    'categorystat172': {
                        'type': 'str',
                        },
                    'categorystat173': {
                        'type': 'str',
                        },
                    'categorystat174': {
                        'type': 'str',
                        },
                    'categorystat175': {
                        'type': 'str',
                        },
                    'categorystat176': {
                        'type': 'str',
                        },
                    'categorystat177': {
                        'type': 'str',
                        },
                    'categorystat178': {
                        'type': 'str',
                        },
                    'categorystat179': {
                        'type': 'str',
                        },
                    'categorystat180': {
                        'type': 'str',
                        },
                    'categorystat181': {
                        'type': 'str',
                        },
                    'categorystat182': {
                        'type': 'str',
                        },
                    'categorystat183': {
                        'type': 'str',
                        },
                    'categorystat184': {
                        'type': 'str',
                        },
                    'categorystat185': {
                        'type': 'str',
                        },
                    'categorystat186': {
                        'type': 'str',
                        },
                    'categorystat187': {
                        'type': 'str',
                        },
                    'categorystat188': {
                        'type': 'str',
                        },
                    'categorystat189': {
                        'type': 'str',
                        },
                    'categorystat190': {
                        'type': 'str',
                        },
                    'categorystat191': {
                        'type': 'str',
                        },
                    'categorystat192': {
                        'type': 'str',
                        },
                    'categorystat193': {
                        'type': 'str',
                        },
                    'categorystat194': {
                        'type': 'str',
                        },
                    'categorystat195': {
                        'type': 'str',
                        },
                    'categorystat196': {
                        'type': 'str',
                        },
                    'categorystat197': {
                        'type': 'str',
                        },
                    'categorystat198': {
                        'type': 'str',
                        },
                    'categorystat199': {
                        'type': 'str',
                        },
                    'categorystat200': {
                        'type': 'str',
                        },
                    'categorystat201': {
                        'type': 'str',
                        },
                    'categorystat202': {
                        'type': 'str',
                        },
                    'categorystat203': {
                        'type': 'str',
                        },
                    'categorystat204': {
                        'type': 'str',
                        },
                    'categorystat205': {
                        'type': 'str',
                        },
                    'categorystat206': {
                        'type': 'str',
                        },
                    'categorystat207': {
                        'type': 'str',
                        },
                    'categorystat208': {
                        'type': 'str',
                        },
                    'categorystat209': {
                        'type': 'str',
                        },
                    'categorystat210': {
                        'type': 'str',
                        },
                    'categorystat211': {
                        'type': 'str',
                        },
                    'categorystat212': {
                        'type': 'str',
                        },
                    'categorystat213': {
                        'type': 'str',
                        },
                    'categorystat214': {
                        'type': 'str',
                        },
                    'categorystat215': {
                        'type': 'str',
                        },
                    'categorystat216': {
                        'type': 'str',
                        },
                    'categorystat217': {
                        'type': 'str',
                        },
                    'categorystat218': {
                        'type': 'str',
                        },
                    'categorystat219': {
                        'type': 'str',
                        },
                    'categorystat220': {
                        'type': 'str',
                        },
                    'categorystat221': {
                        'type': 'str',
                        },
                    'categorystat222': {
                        'type': 'str',
                        },
                    'categorystat223': {
                        'type': 'str',
                        },
                    'categorystat224': {
                        'type': 'str',
                        },
                    'categorystat225': {
                        'type': 'str',
                        },
                    'categorystat226': {
                        'type': 'str',
                        },
                    'categorystat227': {
                        'type': 'str',
                        },
                    'categorystat228': {
                        'type': 'str',
                        },
                    'categorystat229': {
                        'type': 'str',
                        },
                    'categorystat230': {
                        'type': 'str',
                        },
                    'categorystat231': {
                        'type': 'str',
                        },
                    'categorystat232': {
                        'type': 'str',
                        },
                    'categorystat233': {
                        'type': 'str',
                        },
                    'categorystat234': {
                        'type': 'str',
                        },
                    'categorystat235': {
                        'type': 'str',
                        },
                    'categorystat236': {
                        'type': 'str',
                        },
                    'categorystat237': {
                        'type': 'str',
                        },
                    'categorystat238': {
                        'type': 'str',
                        },
                    'categorystat239': {
                        'type': 'str',
                        },
                    'categorystat240': {
                        'type': 'str',
                        },
                    'categorystat241': {
                        'type': 'str',
                        },
                    'categorystat242': {
                        'type': 'str',
                        },
                    'categorystat243': {
                        'type': 'str',
                        },
                    'categorystat244': {
                        'type': 'str',
                        },
                    'categorystat245': {
                        'type': 'str',
                        },
                    'categorystat246': {
                        'type': 'str',
                        },
                    'categorystat247': {
                        'type': 'str',
                        },
                    'categorystat248': {
                        'type': 'str',
                        },
                    'categorystat249': {
                        'type': 'str',
                        },
                    'categorystat250': {
                        'type': 'str',
                        },
                    'categorystat251': {
                        'type': 'str',
                        },
                    'categorystat252': {
                        'type': 'str',
                        },
                    'categorystat253': {
                        'type': 'str',
                        },
                    'categorystat254': {
                        'type': 'str',
                        },
                    'categorystat255': {
                        'type': 'str',
                        },
                    'categorystat256': {
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
    url_base = "/axapi/v3/rule-set/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/rule-set"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["rule-set"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["rule-set"].get(k) != v:
            change_results["changed"] = True
            config_changes["rule-set"][k] = v

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
    payload = utils.build_json("rule-set", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["rule-set"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["rule-set-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["rule-set"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["rule-set"]["stats"] if info != "NotFound" else info
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
