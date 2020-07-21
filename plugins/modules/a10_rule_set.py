#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_rule_set
description:
    - Configure Security policy Rule Set
short_description: Configures A10 rule-set
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
            total_active_icmp:
                description:
                - "Field total_active_icmp"
            policy_deny:
                description:
                - "Field policy_deny"
            total_deny_bytes:
                description:
                - "Field total_deny_bytes"
            total_hit:
                description:
                - "Field total_hit"
            policy_status:
                description:
                - "Field policy_status"
            total_packets:
                description:
                - "Field total_packets"
            total_deny_packets:
                description:
                - "Field total_deny_packets"
            total_permit_bytes:
                description:
                - "Field total_permit_bytes"
            rule_list:
                description:
                - "Field rule_list"
            total_active_tcp:
                description:
                - "Field total_active_tcp"
            application:
                description:
                - "Field application"
            total_active_others:
                description:
                - "Field total_active_others"
            total_permit_packets:
                description:
                - "Field total_permit_packets"
            rule_stats:
                description:
                - "Field rule_stats"
            total_active_udp:
                description:
                - "Field total_active_udp"
            policy_rule_count:
                description:
                - "Field policy_rule_count"
            policy_reset:
                description:
                - "Field policy_reset"
            total_reset_packets:
                description:
                - "Field total_reset_packets"
            total_reset_bytes:
                description:
                - "Field total_reset_bytes"
            rules_by_zone:
                description:
                - "Field rules_by_zone"
            name:
                description:
                - "Rule set name"
            total_bytes:
                description:
                - "Field total_bytes"
            topn_rules:
                description:
                - "Field topn_rules"
            track_app_rule_list:
                description:
                - "Field track_app_rule_list"
            policy_unmatched_drop:
                description:
                - "Field policy_unmatched_drop"
            show_total_stats:
                description:
                - "Field show_total_stats"
            policy_permit:
                description:
                - "Field policy_permit"
    remark:
        description:
        - "Rule set entry comment (Notes for this rule set)"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            reset:
                description:
                - "Reset counter"
            deny:
                description:
                - "Denied counter"
            name:
                description:
                - "Rule set name"
            app:
                description:
                - "Field app"
            track_app_rule_list:
                description:
                - "Field track_app_rule_list"
            rule_list:
                description:
                - "Field rule_list"
            tag:
                description:
                - "Field tag"
            permit:
                description:
                - "Permitted counter"
            unmatched_drops:
                description:
                - "Unmatched drops counter"
            rules_by_zone:
                description:
                - "Field rules_by_zone"
    name:
        description:
        - "Rule set name"
        required: True
    app:
        description:
        - "Field app"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    track_app_rule_list:
        description:
        - "Field track_app_rule_list"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    user_tag:
        description:
        - "Customized tag"
        required: False
    application:
        description:
        - "Field application"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'unmatched-drops'= Unmatched drops counter; 'permit'= Permitted
          counter; 'deny'= Denied counter; 'reset'= Reset counter;"
    tag:
        description:
        - "Field tag"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    rule_list:
        description:
        - "Field rule_list"
        required: False
        suboptions:
            cgnv6_fixed_nat_log:
                description:
                - "Enable logging"
            dst_geoloc_list_shared:
                description:
                - "Use Geolocation list from shared partition"
            sampling_enable:
                description:
                - "Field sampling_enable"
            forward_listen_on_port:
                description:
                - "Listen on port"
            reset_lidlog:
                description:
                - "Enable logging"
            listen_on_port_lid:
                description:
                - "Apply a Template LID"
            app_list:
                description:
                - "Field app_list"
            src_threat_list:
                description:
                - "Bind threat-list for source IP based filtering"
            cgnv6_policy:
                description:
                - "'lsn-lid'= Apply specified CGNv6 LSN LID; 'fixed-nat'= Apply CGNv6 Fixed NAT;"
            src_geoloc_name:
                description:
                - "Single geolocation name"
            cgnv6_log:
                description:
                - "Enable logging"
            forward_log:
                description:
                - "Enable logging"
            lid:
                description:
                - "Apply a Template LID"
            listen_on_port:
                description:
                - "Listen on port"
            move_rule:
                description:
                - "Field move_rule"
            log:
                description:
                - "Enable logging"
            dst_geoloc_name:
                description:
                - "Single geolocation name"
            idle_timeout:
                description:
                - "TCP/UDP idle-timeout"
            listen_on_port_lidlog:
                description:
                - "Enable logging"
            src_zone_any:
                description:
                - "'any'= any;"
            ip_version:
                description:
                - "'v4'= IPv4 rule; 'v6'= IPv6 rule;"
            application_any:
                description:
                - "'any'= any;"
            src_zone:
                description:
                - "Zone name"
            src_geoloc_list_shared:
                description:
                - "Use Geolocation list from shared partition"
            policy:
                description:
                - "'cgnv6'= Apply CGNv6 policy; 'forward'= Forward packet;"
            source_list:
                description:
                - "Field source_list"
            dst_zone_any:
                description:
                - "'any'= any;"
            status:
                description:
                - "'enable'= Enable rule; 'disable'= Disable rule;"
            lidlog:
                description:
                - "Enable logging"
            dst_ipv4_any:
                description:
                - "'any'= Any IPv4 address;"
            cgnv6_lsn_lid:
                description:
                - "LSN LID"
            src_geoloc_list:
                description:
                - "Geolocation name list"
            src_ipv4_any:
                description:
                - "'any'= Any IPv4 address;"
            fwlog:
                description:
                - "Enable logging"
            dst_zone:
                description:
                - "Zone name"
            dst_class_list:
                description:
                - "Match destination IP against class-list"
            uuid:
                description:
                - "uuid of the object"
            dst_threat_list:
                description:
                - "Bind threat-list for destination IP based filtering"
            remark:
                description:
                - "Rule entry comment (Notes for this rule)"
            src_class_list:
                description:
                - "Match source IP against class-list"
            name:
                description:
                - "Rule name"
            src_ipv6_any:
                description:
                - "'any'= Any IPv6 address;"
            reset_lid:
                description:
                - "Apply a Template LID"
            dst_geoloc_list:
                description:
                - "Geolocation name list"
            track_application:
                description:
                - "Enable application statistic"
            user_tag:
                description:
                - "Customized tag"
            cgnv6_lsn_log:
                description:
                - "Enable logging"
            dst_ipv6_any:
                description:
                - "'any'= Any IPv6 address;"
            service_any:
                description:
                - "'any'= any;"
            service_list:
                description:
                - "Field service_list"
            dst_domain_list:
                description:
                - "Match destination IP against domain-list"
            dest_list:
                description:
                - "Field dest_list"
            action:
                description:
                - "'permit'= permit; 'deny'= deny; 'reset'= reset;"
            fw_log:
                description:
                - "Enable logging"
    session_statistic:
        description:
        - "'enable'= Enable session based statistic (Default); 'disable'= Disable session
          based statistic;"
        required: False
    rules_by_zone:
        description:
        - "Field rules_by_zone"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    uuid:
        description:
        - "uuid of the object"
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
    "app",
    "application",
    "name",
    "oper",
    "remark",
    "rule_list",
    "rules_by_zone",
    "sampling_enable",
    "session_statistic",
    "stats",
    "tag",
    "track_app_rule_list",
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
        'oper': {
            'type': 'dict',
            'total_active_icmp': {
                'type': 'int',
            },
            'policy_deny': {
                'type': 'int',
            },
            'total_deny_bytes': {
                'type': 'int',
            },
            'total_hit': {
                'type': 'int',
            },
            'policy_status': {
                'type': 'str',
            },
            'total_packets': {
                'type': 'int',
            },
            'total_deny_packets': {
                'type': 'int',
            },
            'total_permit_bytes': {
                'type': 'int',
            },
            'rule_list': {
                'type': 'list',
                'oper': {
                    'type': 'dict',
                    'denybytes': {
                        'type': 'int',
                    },
                    'activesessiontcp': {
                        'type': 'int',
                    },
                    'permitbytes': {
                        'type': 'int',
                    },
                    'sessiontcp': {
                        'type': 'int',
                    },
                    'resetpackets': {
                        'type': 'int',
                    },
                    'sessionsctp': {
                        'type': 'int',
                    },
                    'sessionother': {
                        'type': 'int',
                    },
                    'totalbytes': {
                        'type': 'int',
                    },
                    'activesessionicmp': {
                        'type': 'int',
                    },
                    'denypackets': {
                        'type': 'int',
                    },
                    'hitcount': {
                        'type': 'int',
                    },
                    'status': {
                        'type': 'str',
                    },
                    'activesessionother': {
                        'type': 'int',
                    },
                    'sessionudp': {
                        'type': 'int',
                    },
                    'sessionicmp': {
                        'type': 'int',
                    },
                    'sessiontotal': {
                        'type': 'int',
                    },
                    'totalpackets': {
                        'type': 'int',
                    },
                    'activesessionudp': {
                        'type': 'int',
                    },
                    'permitpackets': {
                        'type': 'int',
                    },
                    'last_hitcount_time': {
                        'type': 'str',
                    },
                    'activesessiontotal': {
                        'type': 'int',
                    },
                    'resetbytes': {
                        'type': 'int',
                    },
                    'action': {
                        'type': 'str',
                    },
                    'activesessionsctp': {
                        'type': 'int',
                    }
                },
                'name': {
                    'type': 'str',
                    'required': True,
                }
            },
            'total_active_tcp': {
                'type': 'int',
            },
            'application': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'app_stat': {
                        'type': 'str',
                    },
                    'category_stat': {
                        'type': 'str',
                    },
                    'rule': {
                        'type': 'str',
                    },
                    'rule_list': {
                        'type': 'list',
                        'stat_list': {
                            'type': 'list',
                            'category': {
                                'type': 'str',
                            },
                            'conns': {
                                'type': 'int',
                            },
                            'bytes': {
                                'type': 'int',
                            },
                            'name': {
                                'type': 'str',
                            },
                            'ntype': {
                                'type': 'str',
                            }
                        },
                        'name': {
                            'type': 'str',
                        }
                    }
                }
            },
            'total_active_others': {
                'type': 'int',
            },
            'total_permit_packets': {
                'type': 'int',
            },
            'rule_stats': {
                'type': 'list',
                'rule_hitcount': {
                    'type': 'int',
                },
                'rule_action': {
                    'type': 'str',
                },
                'rule_status': {
                    'type': 'str',
                },
                'rule_name': {
                    'type': 'str',
                }
            },
            'total_active_udp': {
                'type': 'int',
            },
            'policy_rule_count': {
                'type': 'int',
            },
            'policy_reset': {
                'type': 'int',
            },
            'total_reset_packets': {
                'type': 'int',
            },
            'total_reset_bytes': {
                'type': 'int',
            },
            'rules_by_zone': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'group_list': {
                        'type': 'list',
                        'to': {
                            'type': 'str',
                        },
                        'from': {
                            'type': 'str',
                        },
                        'rule_list': {
                            'type': 'list',
                            'dest_list': {
                                'type': 'list',
                                'dest': {
                                    'type': 'str',
                                }
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
                            'name': {
                                'type': 'str',
                            },
                            'service_list': {
                                'type': 'list',
                                'service': {
                                    'type': 'str',
                                }
                            }
                        }
                    }
                }
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'total_bytes': {
                'type': 'int',
            },
            'topn_rules': {
                'type': 'str',
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
            },
            'policy_unmatched_drop': {
                'type': 'int',
            },
            'show_total_stats': {
                'type': 'str',
            },
            'policy_permit': {
                'type': 'int',
            }
        },
        'remark': {
            'type': 'str',
        },
        'stats': {
            'type': 'dict',
            'reset': {
                'type': 'str',
            },
            'deny': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'app': {
                'type': 'dict',
                'stats': {
                    'type': 'dict',
                    'appstat249': {
                        'type': 'str',
                    },
                    'appstat248': {
                        'type': 'str',
                    },
                    'appstat245': {
                        'type': 'str',
                    },
                    'appstat244': {
                        'type': 'str',
                    },
                    'appstat247': {
                        'type': 'str',
                    },
                    'appstat246': {
                        'type': 'str',
                    },
                    'appstat241': {
                        'type': 'str',
                    },
                    'appstat240': {
                        'type': 'str',
                    },
                    'appstat243': {
                        'type': 'str',
                    },
                    'appstat242': {
                        'type': 'str',
                    },
                    'appstat489': {
                        'type': 'str',
                    },
                    'appstat488': {
                        'type': 'str',
                    },
                    'appstat487': {
                        'type': 'str',
                    },
                    'appstat486': {
                        'type': 'str',
                    },
                    'appstat485': {
                        'type': 'str',
                    },
                    'appstat484': {
                        'type': 'str',
                    },
                    'appstat483': {
                        'type': 'str',
                    },
                    'appstat482': {
                        'type': 'str',
                    },
                    'appstat481': {
                        'type': 'str',
                    },
                    'appstat480': {
                        'type': 'str',
                    },
                    'appstat91': {
                        'type': 'str',
                    },
                    'appstat90': {
                        'type': 'str',
                    },
                    'appstat93': {
                        'type': 'str',
                    },
                    'appstat92': {
                        'type': 'str',
                    },
                    'appstat95': {
                        'type': 'str',
                    },
                    'appstat94': {
                        'type': 'str',
                    },
                    'appstat97': {
                        'type': 'str',
                    },
                    'appstat96': {
                        'type': 'str',
                    },
                    'appstat99': {
                        'type': 'str',
                    },
                    'appstat98': {
                        'type': 'str',
                    },
                    'appstat182': {
                        'type': 'str',
                    },
                    'appstat183': {
                        'type': 'str',
                    },
                    'appstat180': {
                        'type': 'str',
                    },
                    'appstat181': {
                        'type': 'str',
                    },
                    'appstat186': {
                        'type': 'str',
                    },
                    'appstat187': {
                        'type': 'str',
                    },
                    'appstat184': {
                        'type': 'str',
                    },
                    'appstat185': {
                        'type': 'str',
                    },
                    'appstat188': {
                        'type': 'str',
                    },
                    'appstat189': {
                        'type': 'str',
                    },
                    'appstat348': {
                        'type': 'str',
                    },
                    'appstat349': {
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
                    'appstat119': {
                        'type': 'str',
                    },
                    'appstat118': {
                        'type': 'str',
                    },
                    'appstat111': {
                        'type': 'str',
                    },
                    'appstat110': {
                        'type': 'str',
                    },
                    'appstat113': {
                        'type': 'str',
                    },
                    'appstat112': {
                        'type': 'str',
                    },
                    'appstat115': {
                        'type': 'str',
                    },
                    'appstat114': {
                        'type': 'str',
                    },
                    'appstat117': {
                        'type': 'str',
                    },
                    'appstat116': {
                        'type': 'str',
                    },
                    'appstat449': {
                        'type': 'str',
                    },
                    'appstat448': {
                        'type': 'str',
                    },
                    'appstat443': {
                        'type': 'str',
                    },
                    'appstat442': {
                        'type': 'str',
                    },
                    'appstat441': {
                        'type': 'str',
                    },
                    'appstat440': {
                        'type': 'str',
                    },
                    'appstat447': {
                        'type': 'str',
                    },
                    'appstat446': {
                        'type': 'str',
                    },
                    'appstat445': {
                        'type': 'str',
                    },
                    'appstat444': {
                        'type': 'str',
                    },
                    'appstat298': {
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
                    'appstat299': {
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
                    'appstat238': {
                        'type': 'str',
                    },
                    'appstat239': {
                        'type': 'str',
                    },
                    'appstat46': {
                        'type': 'str',
                    },
                    'appstat47': {
                        'type': 'str',
                    },
                    'appstat44': {
                        'type': 'str',
                    },
                    'appstat45': {
                        'type': 'str',
                    },
                    'appstat42': {
                        'type': 'str',
                    },
                    'appstat43': {
                        'type': 'str',
                    },
                    'appstat40': {
                        'type': 'str',
                    },
                    'appstat41': {
                        'type': 'str',
                    },
                    'appstat290': {
                        'type': 'str',
                    },
                    'appstat48': {
                        'type': 'str',
                    },
                    'appstat49': {
                        'type': 'str',
                    },
                    'appstat358': {
                        'type': 'str',
                    },
                    'appstat308': {
                        'type': 'str',
                    },
                    'appstat309': {
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
                    'appstat155': {
                        'type': 'str',
                    },
                    'appstat154': {
                        'type': 'str',
                    },
                    'appstat157': {
                        'type': 'str',
                    },
                    'appstat156': {
                        'type': 'str',
                    },
                    'appstat151': {
                        'type': 'str',
                    },
                    'appstat150': {
                        'type': 'str',
                    },
                    'appstat153': {
                        'type': 'str',
                    },
                    'appstat152': {
                        'type': 'str',
                    },
                    'appstat159': {
                        'type': 'str',
                    },
                    'appstat158': {
                        'type': 'str',
                    },
                    'appstat9': {
                        'type': 'str',
                    },
                    'appstat8': {
                        'type': 'str',
                    },
                    'appstat405': {
                        'type': 'str',
                    },
                    'appstat404': {
                        'type': 'str',
                    },
                    'appstat403': {
                        'type': 'str',
                    },
                    'appstat402': {
                        'type': 'str',
                    },
                    'appstat401': {
                        'type': 'str',
                    },
                    'appstat400': {
                        'type': 'str',
                    },
                    'appstat1': {
                        'type': 'str',
                    },
                    'appstat3': {
                        'type': 'str',
                    },
                    'appstat2': {
                        'type': 'str',
                    },
                    'appstat5': {
                        'type': 'str',
                    },
                    'appstat4': {
                        'type': 'str',
                    },
                    'appstat7': {
                        'type': 'str',
                    },
                    'appstat6': {
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
                    'appstat472': {
                        'type': 'str',
                    },
                    'appstat473': {
                        'type': 'str',
                    },
                    'appstat470': {
                        'type': 'str',
                    },
                    'appstat471': {
                        'type': 'str',
                    },
                    'appstat476': {
                        'type': 'str',
                    },
                    'appstat477': {
                        'type': 'str',
                    },
                    'appstat474': {
                        'type': 'str',
                    },
                    'appstat475': {
                        'type': 'str',
                    },
                    'appstat478': {
                        'type': 'str',
                    },
                    'appstat479': {
                        'type': 'str',
                    },
                    'appstat82': {
                        'type': 'str',
                    },
                    'appstat83': {
                        'type': 'str',
                    },
                    'appstat80': {
                        'type': 'str',
                    },
                    'appstat81': {
                        'type': 'str',
                    },
                    'appstat86': {
                        'type': 'str',
                    },
                    'appstat87': {
                        'type': 'str',
                    },
                    'appstat84': {
                        'type': 'str',
                    },
                    'appstat85': {
                        'type': 'str',
                    },
                    'appstat88': {
                        'type': 'str',
                    },
                    'appstat89': {
                        'type': 'str',
                    },
                    'appstat204': {
                        'type': 'str',
                    },
                    'appstat258': {
                        'type': 'str',
                    },
                    'appstat259': {
                        'type': 'str',
                    },
                    'appstat39': {
                        'type': 'str',
                    },
                    'appstat38': {
                        'type': 'str',
                    },
                    'appstat37': {
                        'type': 'str',
                    },
                    'appstat36': {
                        'type': 'str',
                    },
                    'appstat35': {
                        'type': 'str',
                    },
                    'appstat34': {
                        'type': 'str',
                    },
                    'appstat33': {
                        'type': 'str',
                    },
                    'appstat32': {
                        'type': 'str',
                    },
                    'appstat31': {
                        'type': 'str',
                    },
                    'appstat30': {
                        'type': 'str',
                    },
                    'appstat191': {
                        'type': 'str',
                    },
                    'appstat190': {
                        'type': 'str',
                    },
                    'appstat193': {
                        'type': 'str',
                    },
                    'appstat192': {
                        'type': 'str',
                    },
                    'appstat195': {
                        'type': 'str',
                    },
                    'appstat194': {
                        'type': 'str',
                    },
                    'appstat197': {
                        'type': 'str',
                    },
                    'appstat196': {
                        'type': 'str',
                    },
                    'appstat199': {
                        'type': 'str',
                    },
                    'appstat198': {
                        'type': 'str',
                    },
                    'appstat251': {
                        'type': 'str',
                    },
                    'appstat353': {
                        'type': 'str',
                    },
                    'appstat352': {
                        'type': 'str',
                    },
                    'appstat351': {
                        'type': 'str',
                    },
                    'appstat350': {
                        'type': 'str',
                    },
                    'appstat357': {
                        'type': 'str',
                    },
                    'appstat356': {
                        'type': 'str',
                    },
                    'appstat355': {
                        'type': 'str',
                    },
                    'appstat354': {
                        'type': 'str',
                    },
                    'appstat292': {
                        'type': 'str',
                    },
                    'appstat293': {
                        'type': 'str',
                    },
                    'appstat359': {
                        'type': 'str',
                    },
                    'appstat291': {
                        'type': 'str',
                    },
                    'appstat296': {
                        'type': 'str',
                    },
                    'appstat297': {
                        'type': 'str',
                    },
                    'appstat294': {
                        'type': 'str',
                    },
                    'appstat295': {
                        'type': 'str',
                    },
                    'appstat128': {
                        'type': 'str',
                    },
                    'appstat129': {
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
                    'appstat438': {
                        'type': 'str',
                    },
                    'appstat439': {
                        'type': 'str',
                    },
                    'appstat436': {
                        'type': 'str',
                    },
                    'appstat437': {
                        'type': 'str',
                    },
                    'appstat434': {
                        'type': 'str',
                    },
                    'appstat435': {
                        'type': 'str',
                    },
                    'appstat432': {
                        'type': 'str',
                    },
                    'appstat433': {
                        'type': 'str',
                    },
                    'appstat430': {
                        'type': 'str',
                    },
                    'appstat431': {
                        'type': 'str',
                    },
                    'appstat500': {
                        'type': 'str',
                    },
                    'appstat501': {
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
                    'appstat228': {
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
                    'appstat223': {
                        'type': 'str',
                    },
                    'appstat222': {
                        'type': 'str',
                    },
                    'appstat221': {
                        'type': 'str',
                    },
                    'appstat220': {
                        'type': 'str',
                    },
                    'appstat227': {
                        'type': 'str',
                    },
                    'appstat226': {
                        'type': 'str',
                    },
                    'appstat225': {
                        'type': 'str',
                    },
                    'appstat224': {
                        'type': 'str',
                    },
                    'appstat79': {
                        'type': 'str',
                    },
                    'appstat78': {
                        'type': 'str',
                    },
                    'appstat73': {
                        'type': 'str',
                    },
                    'appstat72': {
                        'type': 'str',
                    },
                    'appstat71': {
                        'type': 'str',
                    },
                    'appstat70': {
                        'type': 'str',
                    },
                    'appstat77': {
                        'type': 'str',
                    },
                    'appstat76': {
                        'type': 'str',
                    },
                    'appstat75': {
                        'type': 'str',
                    },
                    'appstat74': {
                        'type': 'str',
                    },
                    'appstat319': {
                        'type': 'str',
                    },
                    'appstat318': {
                        'type': 'str',
                    },
                    'appstat317': {
                        'type': 'str',
                    },
                    'appstat316': {
                        'type': 'str',
                    },
                    'appstat315': {
                        'type': 'str',
                    },
                    'appstat314': {
                        'type': 'str',
                    },
                    'appstat313': {
                        'type': 'str',
                    },
                    'appstat312': {
                        'type': 'str',
                    },
                    'appstat311': {
                        'type': 'str',
                    },
                    'appstat310': {
                        'type': 'str',
                    },
                    'appstat407': {
                        'type': 'str',
                    },
                    'appstat406': {
                        'type': 'str',
                    },
                    'appstat168': {
                        'type': 'str',
                    },
                    'appstat169': {
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
                    'appstat368': {
                        'type': 'str',
                    },
                    'appstat369': {
                        'type': 'str',
                    },
                    'appstat362': {
                        'type': 'str',
                    },
                    'appstat363': {
                        'type': 'str',
                    },
                    'appstat360': {
                        'type': 'str',
                    },
                    'appstat361': {
                        'type': 'str',
                    },
                    'appstat366': {
                        'type': 'str',
                    },
                    'appstat367': {
                        'type': 'str',
                    },
                    'appstat364': {
                        'type': 'str',
                    },
                    'appstat365': {
                        'type': 'str',
                    },
                    'appstat409': {
                        'type': 'str',
                    },
                    'appstat408': {
                        'type': 'str',
                    },
                    'appstat267': {
                        'type': 'str',
                    },
                    'appstat266': {
                        'type': 'str',
                    },
                    'appstat265': {
                        'type': 'str',
                    },
                    'appstat264': {
                        'type': 'str',
                    },
                    'appstat263': {
                        'type': 'str',
                    },
                    'appstat262': {
                        'type': 'str',
                    },
                    'appstat261': {
                        'type': 'str',
                    },
                    'appstat260': {
                        'type': 'str',
                    },
                    'appstat506': {
                        'type': 'str',
                    },
                    'appstat507': {
                        'type': 'str',
                    },
                    'appstat504': {
                        'type': 'str',
                    },
                    'appstat505': {
                        'type': 'str',
                    },
                    'appstat502': {
                        'type': 'str',
                    },
                    'appstat503': {
                        'type': 'str',
                    },
                    'appstat269': {
                        'type': 'str',
                    },
                    'appstat268': {
                        'type': 'str',
                    },
                    'appstat461': {
                        'type': 'str',
                    },
                    'appstat460': {
                        'type': 'str',
                    },
                    'appstat463': {
                        'type': 'str',
                    },
                    'appstat462': {
                        'type': 'str',
                    },
                    'appstat465': {
                        'type': 'str',
                    },
                    'appstat464': {
                        'type': 'str',
                    },
                    'appstat467': {
                        'type': 'str',
                    },
                    'appstat466': {
                        'type': 'str',
                    },
                    'appstat469': {
                        'type': 'str',
                    },
                    'appstat468': {
                        'type': 'str',
                    },
                    'appstat212': {
                        'type': 'str',
                    },
                    'appstat213': {
                        'type': 'str',
                    },
                    'appstat210': {
                        'type': 'str',
                    },
                    'appstat211': {
                        'type': 'str',
                    },
                    'appstat216': {
                        'type': 'str',
                    },
                    'appstat217': {
                        'type': 'str',
                    },
                    'appstat214': {
                        'type': 'str',
                    },
                    'appstat215': {
                        'type': 'str',
                    },
                    'appstat218': {
                        'type': 'str',
                    },
                    'appstat219': {
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
                    'appstat229': {
                        'type': 'str',
                    },
                    'appstat383': {
                        'type': 'str',
                    },
                    'appstat326': {
                        'type': 'str',
                    },
                    'appstat327': {
                        'type': 'str',
                    },
                    'appstat324': {
                        'type': 'str',
                    },
                    'appstat325': {
                        'type': 'str',
                    },
                    'appstat322': {
                        'type': 'str',
                    },
                    'appstat323': {
                        'type': 'str',
                    },
                    'appstat320': {
                        'type': 'str',
                    },
                    'appstat321': {
                        'type': 'str',
                    },
                    'appstat281': {
                        'type': 'str',
                    },
                    'appstat280': {
                        'type': 'str',
                    },
                    'appstat283': {
                        'type': 'str',
                    },
                    'appstat282': {
                        'type': 'str',
                    },
                    'appstat285': {
                        'type': 'str',
                    },
                    'appstat284': {
                        'type': 'str',
                    },
                    'appstat287': {
                        'type': 'str',
                    },
                    'appstat329': {
                        'type': 'str',
                    },
                    'appstat388': {
                        'type': 'str',
                    },
                    'appstat389': {
                        'type': 'str',
                    },
                    'appstat250': {
                        'type': 'str',
                    },
                    'appstat133': {
                        'type': 'str',
                    },
                    'appstat132': {
                        'type': 'str',
                    },
                    'appstat131': {
                        'type': 'str',
                    },
                    'appstat130': {
                        'type': 'str',
                    },
                    'appstat137': {
                        'type': 'str',
                    },
                    'appstat136': {
                        'type': 'str',
                    },
                    'appstat135': {
                        'type': 'str',
                    },
                    'appstat134': {
                        'type': 'str',
                    },
                    'appstat139': {
                        'type': 'str',
                    },
                    'appstat138': {
                        'type': 'str',
                    },
                    'appstat429': {
                        'type': 'str',
                    },
                    'appstat428': {
                        'type': 'str',
                    },
                    'appstat425': {
                        'type': 'str',
                    },
                    'appstat424': {
                        'type': 'str',
                    },
                    'appstat427': {
                        'type': 'str',
                    },
                    'appstat426': {
                        'type': 'str',
                    },
                    'appstat421': {
                        'type': 'str',
                    },
                    'appstat420': {
                        'type': 'str',
                    },
                    'appstat423': {
                        'type': 'str',
                    },
                    'appstat422': {
                        'type': 'str',
                    },
                    'appstat508': {
                        'type': 'str',
                    },
                    'appstat509': {
                        'type': 'str',
                    },
                    'appstat397': {
                        'type': 'str',
                    },
                    'appstat396': {
                        'type': 'str',
                    },
                    'appstat395': {
                        'type': 'str',
                    },
                    'appstat394': {
                        'type': 'str',
                    },
                    'appstat393': {
                        'type': 'str',
                    },
                    'appstat392': {
                        'type': 'str',
                    },
                    'appstat391': {
                        'type': 'str',
                    },
                    'appstat390': {
                        'type': 'str',
                    },
                    'appstat256': {
                        'type': 'str',
                    },
                    'appstat257': {
                        'type': 'str',
                    },
                    'appstat254': {
                        'type': 'str',
                    },
                    'appstat255': {
                        'type': 'str',
                    },
                    'appstat252': {
                        'type': 'str',
                    },
                    'appstat253': {
                        'type': 'str',
                    },
                    'appstat399': {
                        'type': 'str',
                    },
                    'appstat398': {
                        'type': 'str',
                    },
                    'appstat498': {
                        'type': 'str',
                    },
                    'appstat499': {
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
                    'appstat68': {
                        'type': 'str',
                    },
                    'appstat69': {
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
                    'appstat19': {
                        'type': 'str',
                    },
                    'appstat18': {
                        'type': 'str',
                    },
                    'appstat11': {
                        'type': 'str',
                    },
                    'appstat10': {
                        'type': 'str',
                    },
                    'appstat13': {
                        'type': 'str',
                    },
                    'appstat12': {
                        'type': 'str',
                    },
                    'appstat15': {
                        'type': 'str',
                    },
                    'appstat14': {
                        'type': 'str',
                    },
                    'appstat17': {
                        'type': 'str',
                    },
                    'appstat16': {
                        'type': 'str',
                    },
                    'appstat179': {
                        'type': 'str',
                    },
                    'appstat178': {
                        'type': 'str',
                    },
                    'appstat177': {
                        'type': 'str',
                    },
                    'appstat176': {
                        'type': 'str',
                    },
                    'appstat175': {
                        'type': 'str',
                    },
                    'appstat174': {
                        'type': 'str',
                    },
                    'appstat173': {
                        'type': 'str',
                    },
                    'appstat172': {
                        'type': 'str',
                    },
                    'appstat171': {
                        'type': 'str',
                    },
                    'appstat170': {
                        'type': 'str',
                    },
                    'appstat379': {
                        'type': 'str',
                    },
                    'appstat378': {
                        'type': 'str',
                    },
                    'appstat371': {
                        'type': 'str',
                    },
                    'appstat370': {
                        'type': 'str',
                    },
                    'appstat373': {
                        'type': 'str',
                    },
                    'appstat372': {
                        'type': 'str',
                    },
                    'appstat375': {
                        'type': 'str',
                    },
                    'appstat374': {
                        'type': 'str',
                    },
                    'appstat377': {
                        'type': 'str',
                    },
                    'appstat376': {
                        'type': 'str',
                    },
                    'appstat108': {
                        'type': 'str',
                    },
                    'appstat109': {
                        'type': 'str',
                    },
                    'appstat102': {
                        'type': 'str',
                    },
                    'appstat103': {
                        'type': 'str',
                    },
                    'appstat100': {
                        'type': 'str',
                    },
                    'appstat101': {
                        'type': 'str',
                    },
                    'appstat106': {
                        'type': 'str',
                    },
                    'appstat107': {
                        'type': 'str',
                    },
                    'appstat104': {
                        'type': 'str',
                    },
                    'appstat105': {
                        'type': 'str',
                    },
                    'appstat289': {
                        'type': 'str',
                    },
                    'appstat288': {
                        'type': 'str',
                    },
                    'appstat511': {
                        'type': 'str',
                    },
                    'appstat510': {
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
                    'appstat458': {
                        'type': 'str',
                    },
                    'appstat459': {
                        'type': 'str',
                    },
                    'appstat201': {
                        'type': 'str',
                    },
                    'appstat200': {
                        'type': 'str',
                    },
                    'appstat203': {
                        'type': 'str',
                    },
                    'appstat202': {
                        'type': 'str',
                    },
                    'appstat205': {
                        'type': 'str',
                    },
                    'appstat328': {
                        'type': 'str',
                    },
                    'appstat207': {
                        'type': 'str',
                    },
                    'appstat206': {
                        'type': 'str',
                    },
                    'appstat209': {
                        'type': 'str',
                    },
                    'appstat208': {
                        'type': 'str',
                    },
                    'appstat286': {
                        'type': 'str',
                    },
                    'appstat55': {
                        'type': 'str',
                    },
                    'appstat54': {
                        'type': 'str',
                    },
                    'appstat57': {
                        'type': 'str',
                    },
                    'appstat56': {
                        'type': 'str',
                    },
                    'appstat51': {
                        'type': 'str',
                    },
                    'appstat50': {
                        'type': 'str',
                    },
                    'appstat53': {
                        'type': 'str',
                    },
                    'appstat52': {
                        'type': 'str',
                    },
                    'appstat59': {
                        'type': 'str',
                    },
                    'appstat58': {
                        'type': 'str',
                    },
                    'appstat335': {
                        'type': 'str',
                    },
                    'appstat334': {
                        'type': 'str',
                    },
                    'appstat337': {
                        'type': 'str',
                    },
                    'appstat336': {
                        'type': 'str',
                    },
                    'appstat331': {
                        'type': 'str',
                    },
                    'appstat330': {
                        'type': 'str',
                    },
                    'appstat333': {
                        'type': 'str',
                    },
                    'appstat332': {
                        'type': 'str',
                    },
                    'appstat339': {
                        'type': 'str',
                    },
                    'appstat338': {
                        'type': 'str',
                    },
                    'appstat146': {
                        'type': 'str',
                    },
                    'appstat147': {
                        'type': 'str',
                    },
                    'appstat144': {
                        'type': 'str',
                    },
                    'appstat145': {
                        'type': 'str',
                    },
                    'appstat142': {
                        'type': 'str',
                    },
                    'appstat143': {
                        'type': 'str',
                    },
                    'appstat140': {
                        'type': 'str',
                    },
                    'appstat141': {
                        'type': 'str',
                    },
                    'appstat148': {
                        'type': 'str',
                    },
                    'appstat149': {
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
                    'appstat237': {
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
            'rule_list': {
                'type': 'list',
                'stats': {
                    'type': 'dict',
                    'active_session_other': {
                        'type': 'str',
                    },
                    'session_icmp': {
                        'type': 'str',
                    },
                    'hit_count': {
                        'type': 'str',
                    },
                    'active_session_tcp': {
                        'type': 'str',
                    },
                    'deny_packets': {
                        'type': 'str',
                    },
                    'session_other': {
                        'type': 'str',
                    },
                    'session_sctp': {
                        'type': 'str',
                    },
                    'active_session_icmp': {
                        'type': 'str',
                    },
                    'permit_bytes': {
                        'type': 'str',
                    },
                    'reset_packets': {
                        'type': 'str',
                    },
                    'hitcount_timestamp': {
                        'type': 'str',
                    },
                    'reset_bytes': {
                        'type': 'str',
                    },
                    'session_tcp': {
                        'type': 'str',
                    },
                    'session_udp': {
                        'type': 'str',
                    },
                    'active_session_sctp': {
                        'type': 'str',
                    },
                    'active_session_udp': {
                        'type': 'str',
                    },
                    'deny_bytes': {
                        'type': 'str',
                    },
                    'permit_packets': {
                        'type': 'str',
                    }
                },
                'name': {
                    'type': 'str',
                    'required': True,
                }
            },
            'tag': {
                'type': 'dict',
                'stats': {
                    'type': 'dict',
                    'categorystat54': {
                        'type': 'str',
                    },
                    'categorystat84': {
                        'type': 'str',
                    },
                    'categorystat85': {
                        'type': 'str',
                    },
                    'categorystat26': {
                        'type': 'str',
                    },
                    'categorystat27': {
                        'type': 'str',
                    },
                    'categorystat24': {
                        'type': 'str',
                    },
                    'categorystat25': {
                        'type': 'str',
                    },
                    'categorystat22': {
                        'type': 'str',
                    },
                    'categorystat23': {
                        'type': 'str',
                    },
                    'categorystat20': {
                        'type': 'str',
                    },
                    'categorystat21': {
                        'type': 'str',
                    },
                    'categorystat28': {
                        'type': 'str',
                    },
                    'categorystat29': {
                        'type': 'str',
                    },
                    'categorystat7': {
                        'type': 'str',
                    },
                    'categorystat168': {
                        'type': 'str',
                    },
                    'categorystat169': {
                        'type': 'str',
                    },
                    'categorystat6': {
                        'type': 'str',
                    },
                    'categorystat162': {
                        'type': 'str',
                    },
                    'categorystat163': {
                        'type': 'str',
                    },
                    'categorystat160': {
                        'type': 'str',
                    },
                    'categorystat161': {
                        'type': 'str',
                    },
                    'categorystat166': {
                        'type': 'str',
                    },
                    'categorystat167': {
                        'type': 'str',
                    },
                    'categorystat164': {
                        'type': 'str',
                    },
                    'categorystat165': {
                        'type': 'str',
                    },
                    'categorystat4': {
                        'type': 'str',
                    },
                    'categorystat210': {
                        'type': 'str',
                    },
                    'categorystat3': {
                        'type': 'str',
                    },
                    'categorystat109': {
                        'type': 'str',
                    },
                    'categorystat1': {
                        'type': 'str',
                    },
                    'categorystat35': {
                        'type': 'str',
                    },
                    'categorystat34': {
                        'type': 'str',
                    },
                    'categorystat37': {
                        'type': 'str',
                    },
                    'categorystat36': {
                        'type': 'str',
                    },
                    'categorystat31': {
                        'type': 'str',
                    },
                    'categorystat30': {
                        'type': 'str',
                    },
                    'categorystat33': {
                        'type': 'str',
                    },
                    'categorystat32': {
                        'type': 'str',
                    },
                    'categorystat39': {
                        'type': 'str',
                    },
                    'categorystat38': {
                        'type': 'str',
                    },
                    'categorystat197': {
                        'type': 'str',
                    },
                    'categorystat196': {
                        'type': 'str',
                    },
                    'categorystat195': {
                        'type': 'str',
                    },
                    'categorystat194': {
                        'type': 'str',
                    },
                    'categorystat193': {
                        'type': 'str',
                    },
                    'categorystat192': {
                        'type': 'str',
                    },
                    'categorystat191': {
                        'type': 'str',
                    },
                    'categorystat190': {
                        'type': 'str',
                    },
                    'categorystat100': {
                        'type': 'str',
                    },
                    'categorystat199': {
                        'type': 'str',
                    },
                    'categorystat198': {
                        'type': 'str',
                    },
                    'categorystat207': {
                        'type': 'str',
                    },
                    'categorystat206': {
                        'type': 'str',
                    },
                    'categorystat205': {
                        'type': 'str',
                    },
                    'categorystat204': {
                        'type': 'str',
                    },
                    'categorystat203': {
                        'type': 'str',
                    },
                    'categorystat9': {
                        'type': 'str',
                    },
                    'categorystat119': {
                        'type': 'str',
                    },
                    'categorystat118': {
                        'type': 'str',
                    },
                    'categorystat117': {
                        'type': 'str',
                    },
                    'categorystat116': {
                        'type': 'str',
                    },
                    'categorystat115': {
                        'type': 'str',
                    },
                    'categorystat114': {
                        'type': 'str',
                    },
                    'categorystat113': {
                        'type': 'str',
                    },
                    'categorystat112': {
                        'type': 'str',
                    },
                    'categorystat111': {
                        'type': 'str',
                    },
                    'categorystat110': {
                        'type': 'str',
                    },
                    'categorystat52': {
                        'type': 'str',
                    },
                    'categorystat202': {
                        'type': 'str',
                    },
                    'categorystat184': {
                        'type': 'str',
                    },
                    'categorystat88': {
                        'type': 'str',
                    },
                    'categorystat89': {
                        'type': 'str',
                    },
                    'categorystat186': {
                        'type': 'str',
                    },
                    'categorystat187': {
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
                    'categorystat188': {
                        'type': 'str',
                    },
                    'categorystat189': {
                        'type': 'str',
                    },
                    'categorystat86': {
                        'type': 'str',
                    },
                    'categorystat87': {
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
                    'categorystat108': {
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
                    'categorystat218': {
                        'type': 'str',
                    },
                    'categorystat219': {
                        'type': 'str',
                    },
                    'categorystat102': {
                        'type': 'str',
                    },
                    'categorystat103': {
                        'type': 'str',
                    },
                    'categorystat201': {
                        'type': 'str',
                    },
                    'categorystat19': {
                        'type': 'str',
                    },
                    'categorystat18': {
                        'type': 'str',
                    },
                    'categorystat17': {
                        'type': 'str',
                    },
                    'categorystat16': {
                        'type': 'str',
                    },
                    'categorystat15': {
                        'type': 'str',
                    },
                    'categorystat14': {
                        'type': 'str',
                    },
                    'categorystat13': {
                        'type': 'str',
                    },
                    'categorystat12': {
                        'type': 'str',
                    },
                    'categorystat11': {
                        'type': 'str',
                    },
                    'categorystat10': {
                        'type': 'str',
                    },
                    'categorystat97': {
                        'type': 'str',
                    },
                    'categorystat96': {
                        'type': 'str',
                    },
                    'categorystat95': {
                        'type': 'str',
                    },
                    'categorystat94': {
                        'type': 'str',
                    },
                    'categorystat93': {
                        'type': 'str',
                    },
                    'categorystat92': {
                        'type': 'str',
                    },
                    'categorystat91': {
                        'type': 'str',
                    },
                    'categorystat90': {
                        'type': 'str',
                    },
                    'categorystat8': {
                        'type': 'str',
                    },
                    'categorystat99': {
                        'type': 'str',
                    },
                    'categorystat98': {
                        'type': 'str',
                    },
                    'categorystat139': {
                        'type': 'str',
                    },
                    'categorystat138': {
                        'type': 'str',
                    },
                    'categorystat223': {
                        'type': 'str',
                    },
                    'categorystat222': {
                        'type': 'str',
                    },
                    'categorystat225': {
                        'type': 'str',
                    },
                    'categorystat209': {
                        'type': 'str',
                    },
                    'categorystat227': {
                        'type': 'str',
                    },
                    'categorystat226': {
                        'type': 'str',
                    },
                    'categorystat131': {
                        'type': 'str',
                    },
                    'categorystat228': {
                        'type': 'str',
                    },
                    'categorystat133': {
                        'type': 'str',
                    },
                    'categorystat208': {
                        'type': 'str',
                    },
                    'categorystat135': {
                        'type': 'str',
                    },
                    'categorystat134': {
                        'type': 'str',
                    },
                    'categorystat137': {
                        'type': 'str',
                    },
                    'categorystat136': {
                        'type': 'str',
                    },
                    'categorystat68': {
                        'type': 'str',
                    },
                    'categorystat69': {
                        'type': 'str',
                    },
                    'categorystat62': {
                        'type': 'str',
                    },
                    'categorystat63': {
                        'type': 'str',
                    },
                    'categorystat60': {
                        'type': 'str',
                    },
                    'categorystat61': {
                        'type': 'str',
                    },
                    'categorystat66': {
                        'type': 'str',
                    },
                    'categorystat67': {
                        'type': 'str',
                    },
                    'categorystat64': {
                        'type': 'str',
                    },
                    'categorystat65': {
                        'type': 'str',
                    },
                    'categorystat238': {
                        'type': 'str',
                    },
                    'categorystat239': {
                        'type': 'str',
                    },
                    'categorystat236': {
                        'type': 'str',
                    },
                    'categorystat237': {
                        'type': 'str',
                    },
                    'categorystat234': {
                        'type': 'str',
                    },
                    'categorystat200': {
                        'type': 'str',
                    },
                    'categorystat232': {
                        'type': 'str',
                    },
                    'categorystat233': {
                        'type': 'str',
                    },
                    'categorystat230': {
                        'type': 'str',
                    },
                    'categorystat231': {
                        'type': 'str',
                    },
                    'categorystat126': {
                        'type': 'str',
                    },
                    'categorystat127': {
                        'type': 'str',
                    },
                    'categorystat124': {
                        'type': 'str',
                    },
                    'categorystat125': {
                        'type': 'str',
                    },
                    'categorystat122': {
                        'type': 'str',
                    },
                    'categorystat123': {
                        'type': 'str',
                    },
                    'categorystat120': {
                        'type': 'str',
                    },
                    'categorystat121': {
                        'type': 'str',
                    },
                    'categorystat128': {
                        'type': 'str',
                    },
                    'categorystat129': {
                        'type': 'str',
                    },
                    'categorystat79': {
                        'type': 'str',
                    },
                    'categorystat78': {
                        'type': 'str',
                    },
                    'categorystat71': {
                        'type': 'str',
                    },
                    'categorystat70': {
                        'type': 'str',
                    },
                    'categorystat73': {
                        'type': 'str',
                    },
                    'categorystat72': {
                        'type': 'str',
                    },
                    'categorystat75': {
                        'type': 'str',
                    },
                    'categorystat74': {
                        'type': 'str',
                    },
                    'categorystat77': {
                        'type': 'str',
                    },
                    'categorystat76': {
                        'type': 'str',
                    },
                    'categorystat249': {
                        'type': 'str',
                    },
                    'categorystat248': {
                        'type': 'str',
                    },
                    'categorystat5': {
                        'type': 'str',
                    },
                    'categorystat243': {
                        'type': 'str',
                    },
                    'categorystat242': {
                        'type': 'str',
                    },
                    'categorystat241': {
                        'type': 'str',
                    },
                    'categorystat240': {
                        'type': 'str',
                    },
                    'categorystat247': {
                        'type': 'str',
                    },
                    'categorystat246': {
                        'type': 'str',
                    },
                    'categorystat245': {
                        'type': 'str',
                    },
                    'categorystat244': {
                        'type': 'str',
                    },
                    'categorystat153': {
                        'type': 'str',
                    },
                    'categorystat152': {
                        'type': 'str',
                    },
                    'categorystat151': {
                        'type': 'str',
                    },
                    'categorystat150': {
                        'type': 'str',
                    },
                    'categorystat157': {
                        'type': 'str',
                    },
                    'categorystat156': {
                        'type': 'str',
                    },
                    'categorystat155': {
                        'type': 'str',
                    },
                    'categorystat154': {
                        'type': 'str',
                    },
                    'categorystat235': {
                        'type': 'str',
                    },
                    'categorystat159': {
                        'type': 'str',
                    },
                    'categorystat158': {
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
                    'categorystat48': {
                        'type': 'str',
                    },
                    'categorystat49': {
                        'type': 'str',
                    },
                    'categorystat221': {
                        'type': 'str',
                    },
                    'categorystat220': {
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
                    'categorystat224': {
                        'type': 'str',
                    },
                    'categorystat53': {
                        'type': 'str',
                    },
                    'categorystat2': {
                        'type': 'str',
                    },
                    'categorystat51': {
                        'type': 'str',
                    },
                    'categorystat50': {
                        'type': 'str',
                    },
                    'categorystat57': {
                        'type': 'str',
                    },
                    'categorystat56': {
                        'type': 'str',
                    },
                    'categorystat55': {
                        'type': 'str',
                    },
                    'categorystat185': {
                        'type': 'str',
                    },
                    'categorystat59': {
                        'type': 'str',
                    },
                    'categorystat58': {
                        'type': 'str',
                    },
                    'categorystat229': {
                        'type': 'str',
                    },
                    'categorystat130': {
                        'type': 'str',
                    },
                    'categorystat101': {
                        'type': 'str',
                    },
                    'categorystat132': {
                        'type': 'str',
                    },
                    'categorystat179': {
                        'type': 'str',
                    },
                    'categorystat178': {
                        'type': 'str',
                    },
                    'categorystat175': {
                        'type': 'str',
                    },
                    'categorystat174': {
                        'type': 'str',
                    },
                    'categorystat177': {
                        'type': 'str',
                    },
                    'categorystat176': {
                        'type': 'str',
                    },
                    'categorystat171': {
                        'type': 'str',
                    },
                    'categorystat170': {
                        'type': 'str',
                    },
                    'categorystat173': {
                        'type': 'str',
                    },
                    'categorystat172': {
                        'type': 'str',
                    }
                }
            },
            'permit': {
                'type': 'str',
            },
            'unmatched_drops': {
                'type': 'str',
            },
            'rules_by_zone': {
                'type': 'dict',
                'stats': {
                    'type': 'dict',
                    'dummy': {
                        'type': 'str',
                    }
                }
            }
        },
        'name': {
            'type': 'str',
            'required': True,
        },
        'app': {
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
        'user_tag': {
            'type': 'str',
        },
        'application': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type': 'str',
                'choices':
                ['all', 'unmatched-drops', 'permit', 'deny', 'reset']
            }
        },
        'tag': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
            }
        },
        'rule_list': {
            'type': 'list',
            'cgnv6_fixed_nat_log': {
                'type': 'bool',
            },
            'dst_geoloc_list_shared': {
                'type': 'bool',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'hit-count', 'permit-bytes', 'deny-bytes',
                        'reset-bytes', 'permit-packets', 'deny-packets',
                        'reset-packets', 'active-session-tcp',
                        'active-session-udp', 'active-session-icmp',
                        'active-session-other', 'session-tcp', 'session-udp',
                        'session-icmp', 'session-other', 'active-session-sctp',
                        'session-sctp', 'hitcount-timestamp'
                    ]
                }
            },
            'forward_listen_on_port': {
                'type': 'bool',
            },
            'reset_lidlog': {
                'type': 'bool',
            },
            'listen_on_port_lid': {
                'type': 'int',
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
                        'aaa', 'adult-content', 'advertising',
                        'analytics-and-statistics', 'anonymizers-and-proxies',
                        'audio-chat', 'basic', 'blog', 'cdn', 'chat',
                        'classified-ads', 'cloud-based-services',
                        'cryptocurrency', 'database', 'disposable-email',
                        'email', 'enterprise', 'file-management',
                        'file-transfer', 'forum', 'gaming',
                        'instant-messaging-and-multimedia-conferencing',
                        'internet-of-things', 'mobile', 'multimedia-streaming',
                        'networking', 'news-portal', 'peer-to-peer',
                        'remote-access', 'scada', 'social-networks',
                        'software-update', 'standards-based', 'transportation',
                        'video-chat', 'voip', 'vpn-tunnels', 'web',
                        'web-e-commerce', 'web-search-engines', 'web-websites',
                        'webmails', 'web-ext-adult', 'web-ext-auctions',
                        'web-ext-blogs', 'web-ext-business-and-economy',
                        'web-ext-cdns', 'web-ext-collaboration',
                        'web-ext-computer-and-internet-info',
                        'web-ext-computer-and-internet-security',
                        'web-ext-dating', 'web-ext-educational-institutions',
                        'web-ext-entertainment-and-arts',
                        'web-ext-fashion-and-beauty', 'web-ext-file-share',
                        'web-ext-financial-services', 'web-ext-gambling',
                        'web-ext-games', 'web-ext-government',
                        'web-ext-health-and-medicine',
                        'web-ext-individual-stock-advice-and-tools',
                        'web-ext-internet-portals', 'web-ext-job-search',
                        'web-ext-local-information', 'web-ext-malware',
                        'web-ext-motor-vehicles', 'web-ext-music',
                        'web-ext-news', 'web-ext-p2p', 'web-ext-parked-sites',
                        'web-ext-proxy-avoid-and-anonymizers',
                        'web-ext-real-estate',
                        'web-ext-reference-and-research',
                        'web-ext-search-engines', 'web-ext-shopping',
                        'web-ext-social-network', 'web-ext-society',
                        'web-ext-software', 'web-ext-sports',
                        'web-ext-streaming-media',
                        'web-ext-training-and-tools', 'web-ext-translation',
                        'web-ext-travel', 'web-ext-web-advertisements',
                        'web-ext-web-based-email', 'web-ext-web-hosting',
                        'web-ext-web-service'
                    ]
                }
            },
            'src_threat_list': {
                'type': 'str',
            },
            'cgnv6_policy': {
                'type': 'str',
                'choices': ['lsn-lid', 'fixed-nat']
            },
            'src_geoloc_name': {
                'type': 'str',
            },
            'cgnv6_log': {
                'type': 'bool',
            },
            'forward_log': {
                'type': 'bool',
            },
            'lid': {
                'type': 'int',
            },
            'listen_on_port': {
                'type': 'bool',
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
            },
            'log': {
                'type': 'bool',
            },
            'dst_geoloc_name': {
                'type': 'str',
            },
            'idle_timeout': {
                'type': 'int',
            },
            'listen_on_port_lidlog': {
                'type': 'bool',
            },
            'src_zone_any': {
                'type': 'str',
                'choices': ['any']
            },
            'ip_version': {
                'type': 'str',
                'choices': ['v4', 'v6']
            },
            'application_any': {
                'type': 'str',
                'choices': ['any']
            },
            'src_zone': {
                'type': 'str',
            },
            'src_geoloc_list_shared': {
                'type': 'bool',
            },
            'policy': {
                'type': 'str',
                'choices': ['cgnv6', 'forward']
            },
            'source_list': {
                'type': 'list',
                'src_ipv6_subnet': {
                    'type': 'str',
                },
                'src_obj_network': {
                    'type': 'str',
                },
                'src_slb_server': {
                    'type': 'str',
                },
                'src_obj_grp_network': {
                    'type': 'str',
                },
                'src_ip_subnet': {
                    'type': 'str',
                }
            },
            'dst_zone_any': {
                'type': 'str',
                'choices': ['any']
            },
            'status': {
                'type': 'str',
                'choices': ['enable', 'disable']
            },
            'lidlog': {
                'type': 'bool',
            },
            'dst_ipv4_any': {
                'type': 'str',
                'choices': ['any']
            },
            'cgnv6_lsn_lid': {
                'type': 'int',
            },
            'src_geoloc_list': {
                'type': 'str',
            },
            'src_ipv4_any': {
                'type': 'str',
                'choices': ['any']
            },
            'fwlog': {
                'type': 'bool',
            },
            'dst_zone': {
                'type': 'str',
            },
            'dst_class_list': {
                'type': 'str',
            },
            'uuid': {
                'type': 'str',
            },
            'dst_threat_list': {
                'type': 'str',
            },
            'remark': {
                'type': 'str',
            },
            'src_class_list': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'src_ipv6_any': {
                'type': 'str',
                'choices': ['any']
            },
            'reset_lid': {
                'type': 'int',
            },
            'dst_geoloc_list': {
                'type': 'str',
            },
            'track_application': {
                'type': 'bool',
            },
            'user_tag': {
                'type': 'str',
            },
            'cgnv6_lsn_log': {
                'type': 'bool',
            },
            'dst_ipv6_any': {
                'type': 'str',
                'choices': ['any']
            },
            'service_any': {
                'type': 'str',
                'choices': ['any']
            },
            'service_list': {
                'type': 'list',
                'gtp_template': {
                    'type': 'str',
                },
                'icmp_type': {
                    'type': 'int',
                },
                'range_dst_port': {
                    'type': 'int',
                },
                'icmpv6_code': {
                    'type': 'int',
                },
                'gt_src_port': {
                    'type': 'int',
                },
                'lt_src_port': {
                    'type': 'int',
                },
                'proto_id': {
                    'type': 'int',
                },
                'lt_dst_port': {
                    'type': 'int',
                },
                'alg': {
                    'type': 'str',
                    'choices': ['FTP', 'TFTP', 'SIP', 'DNS', 'PPTP', 'RTSP']
                },
                'obj_grp_service': {
                    'type': 'str',
                },
                'icmpv6_type': {
                    'type': 'int',
                },
                'icmp_code': {
                    'type': 'int',
                },
                'range_src_port': {
                    'type': 'int',
                },
                'eq_dst_port': {
                    'type': 'int',
                },
                'sctp_template': {
                    'type': 'str',
                },
                'icmp': {
                    'type': 'bool',
                },
                'protocols': {
                    'type': 'str',
                    'choices': ['tcp', 'udp', 'sctp']
                },
                'gt_dst_port': {
                    'type': 'int',
                },
                'port_num_end_src': {
                    'type': 'int',
                },
                'special_v6_type': {
                    'type':
                    'str',
                    'choices': [
                        'any-type', 'dest-unreachable', 'echo-reply',
                        'echo-request', 'packet-too-big', 'param-prob',
                        'time-exceeded'
                    ]
                },
                'eq_src_port': {
                    'type': 'int',
                },
                'special_v6_code': {
                    'type':
                    'str',
                    'choices': [
                        'any-code', 'addr-unreachable', 'admin-prohibited',
                        'no-route', 'not-neighbour', 'port-unreachable'
                    ]
                },
                'icmpv6': {
                    'type': 'bool',
                },
                'port_num_end_dst': {
                    'type': 'int',
                },
                'special_code': {
                    'type':
                    'str',
                    'choices': [
                        'any-code', 'frag-required', 'host-unreachable',
                        'network-unreachable', 'port-unreachable',
                        'proto-unreachable', 'route-failed'
                    ]
                },
                'special_type': {
                    'type':
                    'str',
                    'choices': [
                        'any-type', 'echo-reply', 'echo-request', 'info-reply',
                        'info-request', 'mask-reply', 'mask-request',
                        'parameter-problem', 'redirect', 'source-quench',
                        'time-exceeded', 'timestamp', 'timestamp-reply',
                        'dest-unreachable'
                    ]
                }
            },
            'dst_domain_list': {
                'type': 'str',
            },
            'dest_list': {
                'type': 'list',
                'dst_obj_network': {
                    'type': 'str',
                },
                'dst_obj_grp_network': {
                    'type': 'str',
                },
                'dst_slb_vserver': {
                    'type': 'str',
                },
                'dst_ip_subnet': {
                    'type': 'str',
                },
                'dst_ipv6_subnet': {
                    'type': 'str',
                },
                'dst_slb_server': {
                    'type': 'str',
                }
            },
            'action': {
                'type': 'str',
                'choices': ['permit', 'deny', 'reset']
            },
            'fw_log': {
                'type': 'bool',
            }
        },
        'session_statistic': {
            'type': 'str',
            'choices': ['enable', 'disable']
        },
        'rules_by_zone': {
            'type': 'dict',
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type': 'str',
                    'choices': ['all', 'dummy']
                }
            },
            'uuid': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/rule-set/{name}"

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
    url_base = "/axapi/v3/rule-set/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
        for k, v in payload["rule-set"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["rule-set"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["rule-set"][k] = v
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
    payload = build_json("rule-set", module)
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
