#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_gslb_zone_service
description:
    - Service information for the GSLB zone
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
    zone_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    service_port:
        description:
        - "Port number of the service"
        type: int
        required: True
    service_name:
        description:
        - "Specify the service name for the zone, * for wildcard"
        type: str
        required: True
    action:
        description:
        - "'drop'= Drop query; 'forward'= Forward packet; 'ignore'= Send empty response;
          'reject'= Send refuse response;"
        type: str
        required: False
    forward_type:
        description:
        - "'both'= Forward both query and response; 'query'= Forward query; 'response'=
          Forward response;"
        type: str
        required: False
    disable:
        description:
        - "Disable"
        type: bool
        required: False
    health_check_gateway:
        description:
        - "'enable'= Enable Gateway Status Check; 'disable'= Disable Gateway Status Check;"
        type: str
        required: False
    health_check_port:
        description:
        - "Field health_check_port"
        type: list
        required: False
        suboptions:
            health_check_port:
                description:
                - "Check Related Port Status (Port Number)"
                type: int
    policy:
        description:
        - "Specify policy for this service (Specify policy name)"
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
                - "'all'= all; 'received-query'= Number of DNS queries received for the service;
          'sent-response'= Number of DNS replies sent to clients for the service; 'proxy-
          mode-response'= Number of DNS replies sent to clients by the ACOS device as a
          DNS proxy for the service; 'cache-mode-response'= Number of cached DNS replies
          sent to clients by the ACOS device for the service. (This statistic applies
          only if the DNS cache; 'server-mode-response'= Number of DNS replies sent to
          clients by the ACOS device as a DNS server for the service. (This statistic
          applies only if the D; 'sticky-mode-response'= Number of DNS replies sent to
          clients by the ACOS device to keep the clients on the same site. (This
          statistic applies only if; 'backup-mode-response'= help Number of DNS replies
          sent to clients by the ACOS device in backup mode;"
                type: str
    dns_a_record:
        description:
        - "Field dns_a_record"
        type: dict
        required: False
        suboptions:
            dns_a_record_srv_list:
                description:
                - "Field dns_a_record_srv_list"
                type: list
            dns_a_record_ipv4_list:
                description:
                - "Field dns_a_record_ipv4_list"
                type: list
            dns_a_record_ipv6_list:
                description:
                - "Field dns_a_record_ipv6_list"
                type: list
    dns_cname_record_list:
        description:
        - "Field dns_cname_record_list"
        type: list
        required: False
        suboptions:
            alias_name:
                description:
                - "Specify the alias name"
                type: str
            admin_preference:
                description:
                - "Specify Administrative Preference, default is 100"
                type: int
            weight:
                description:
                - "Specify Weight, default is 1"
                type: int
            as_backup:
                description:
                - "As backup when fail"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    dns_mx_record_list:
        description:
        - "Field dns_mx_record_list"
        type: list
        required: False
        suboptions:
            mx_name:
                description:
                - "Specify Domain Name"
                type: str
            priority:
                description:
                - "Specify Priority"
                type: int
            ttl:
                description:
                - "Specify TTL"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    dns_ns_record_list:
        description:
        - "Field dns_ns_record_list"
        type: list
        required: False
        suboptions:
            ns_name:
                description:
                - "Specify Domain Name"
                type: str
            ttl:
                description:
                - "Specify TTL"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    dns_ptr_record_list:
        description:
        - "Field dns_ptr_record_list"
        type: list
        required: False
        suboptions:
            ptr_name:
                description:
                - "Specify Domain Name"
                type: str
            ttl:
                description:
                - "Specify TTL"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    dns_srv_record_list:
        description:
        - "Field dns_srv_record_list"
        type: list
        required: False
        suboptions:
            srv_name:
                description:
                - "Specify Domain Name"
                type: str
            port:
                description:
                - "Specify Port (Port Number)"
                type: int
            priority:
                description:
                - "Specify Priority"
                type: int
            weight:
                description:
                - "Specify Weight, default is 10"
                type: int
            ttl:
                description:
                - "Specify TTL"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    dns_naptr_record_list:
        description:
        - "Field dns_naptr_record_list"
        type: list
        required: False
        suboptions:
            naptr_target:
                description:
                - "Specify the replacement or regular expression"
                type: str
            service_proto:
                description:
                - "Specify Service and Protocol"
                type: str
            flag:
                description:
                - "Specify the flag (e.g., a, s). Default is empty flag"
                type: str
            order:
                description:
                - "Specify Order"
                type: int
            preference:
                description:
                - "Specify Preference"
                type: int
            regexp:
                description:
                - "Return the regular expression"
                type: bool
            ttl:
                description:
                - "Specify TTL"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    dns_txt_record_list:
        description:
        - "Field dns_txt_record_list"
        type: list
        required: False
        suboptions:
            record_name:
                description:
                - "Specify the Object Name for TXT Data"
                type: str
            txt_data:
                description:
                - "Specify TXT Data"
                type: str
            ttl:
                description:
                - "Specify TTL"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
    dns_record_list:
        description:
        - "Field dns_record_list"
        type: list
        required: False
        suboptions:
            ntype:
                description:
                - "Specify DNS Type"
                type: int
            data:
                description:
                - "Specify DNS Data"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    geo_location_list:
        description:
        - "Field geo_location_list"
        type: list
        required: False
        suboptions:
            geo_name:
                description:
                - "Specify the geo-location"
                type: str
            alias:
                description:
                - "Field alias"
                type: list
            action:
                description:
                - "Action for this geo-location"
                type: bool
            action_type:
                description:
                - "'allow'= Allow query from this geo-location; 'drop'= Drop query from this geo-
          location; 'forward'= Forward packet for this geo-location; 'ignore'= Send empty
          response to this geo-location; 'reject'= Send refuse response to this geo-
          location;"
                type: str
            forward_type:
                description:
                - "'both'= Forward both query and response; 'query'= Forward query from this geo-
          location; 'response'= Forward response to this geo-location;"
                type: str
            policy:
                description:
                - "Policy for this geo-location (Specify the policy name)"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
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
            cache_list:
                description:
                - "Field cache_list"
                type: list
            session_list:
                description:
                - "Field session_list"
                type: list
            matched:
                description:
                - "Field matched"
                type: int
            total_sessions:
                description:
                - "Field total_sessions"
                type: int
            service_port:
                description:
                - "Port number of the service"
                type: int
            service_name:
                description:
                - "Specify the service name for the zone, * for wildcard"
                type: str
            dns_mx_record_list:
                description:
                - "Field dns_mx_record_list"
                type: list
            dns_ns_record_list:
                description:
                - "Field dns_ns_record_list"
                type: list
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            received_query:
                description:
                - "Number of DNS queries received for the service"
                type: str
            sent_response:
                description:
                - "Number of DNS replies sent to clients for the service"
                type: str
            proxy_mode_response:
                description:
                - "Number of DNS replies sent to clients by the ACOS device as a DNS proxy for the
          service"
                type: str
            cache_mode_response:
                description:
                - "Number of cached DNS replies sent to clients by the ACOS device for the
          service. (This statistic applies only if the DNS cache"
                type: str
            server_mode_response:
                description:
                - "Number of DNS replies sent to clients by the ACOS device as a DNS server for
          the service. (This statistic applies only if the D"
                type: str
            sticky_mode_response:
                description:
                - "Number of DNS replies sent to clients by the ACOS device to keep the clients on
          the same site. (This statistic applies only if"
                type: str
            backup_mode_response:
                description:
                - "help Number of DNS replies sent to clients by the ACOS device in backup mode"
                type: str
            service_port:
                description:
                - "Port number of the service"
                type: int
            service_name:
                description:
                - "Specify the service name for the zone, * for wildcard"
                type: str
            dns_a_record:
                description:
                - "Field dns_a_record"
                type: dict
            dns_cname_record_list:
                description:
                - "Field dns_cname_record_list"
                type: list
            dns_mx_record_list:
                description:
                - "Field dns_mx_record_list"
                type: list
            dns_ns_record_list:
                description:
                - "Field dns_ns_record_list"
                type: list
            dns_ptr_record_list:
                description:
                - "Field dns_ptr_record_list"
                type: list
            dns_srv_record_list:
                description:
                - "Field dns_srv_record_list"
                type: list
            dns_naptr_record_list:
                description:
                - "Field dns_naptr_record_list"
                type: list
            dns_txt_record_list:
                description:
                - "Field dns_txt_record_list"
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
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "action",
    "disable",
    "dns_a_record",
    "dns_cname_record_list",
    "dns_mx_record_list",
    "dns_naptr_record_list",
    "dns_ns_record_list",
    "dns_ptr_record_list",
    "dns_record_list",
    "dns_srv_record_list",
    "dns_txt_record_list",
    "forward_type",
    "geo_location_list",
    "health_check_gateway",
    "health_check_port",
    "oper",
    "policy",
    "sampling_enable",
    "service_name",
    "service_port",
    "stats",
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
        'service_port': {
            'type': 'int',
            'required': True,
        },
        'service_name': {
            'type': 'str',
            'required': True,
        },
        'action': {
            'type': 'str',
            'choices': ['drop', 'forward', 'ignore', 'reject']
        },
        'forward_type': {
            'type': 'str',
            'choices': ['both', 'query', 'response']
        },
        'disable': {
            'type': 'bool',
        },
        'health_check_gateway': {
            'type': 'str',
            'choices': ['enable', 'disable']
        },
        'health_check_port': {
            'type': 'list',
            'health_check_port': {
                'type': 'int',
            }
        },
        'policy': {
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
                'type':
                'str',
                'choices': [
                    'all', 'received-query', 'sent-response',
                    'proxy-mode-response', 'cache-mode-response',
                    'server-mode-response', 'sticky-mode-response',
                    'backup-mode-response'
                ]
            }
        },
        'dns_a_record': {
            'type': 'dict',
            'dns_a_record_srv_list': {
                'type': 'list',
                'svrname': {
                    'type': 'str',
                    'required': True,
                },
                'no_resp': {
                    'type': 'bool',
                },
                'as_backup': {
                    'type': 'bool',
                },
                'weight': {
                    'type': 'int',
                },
                'ttl': {
                    'type': 'int',
                },
                'as_replace': {
                    'type': 'bool',
                },
                'disable': {
                    'type': 'bool',
                },
                'static': {
                    'type': 'bool',
                },
                'admin_ip': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                },
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type': 'str',
                        'choices': ['all', 'hits']
                    }
                }
            },
            'dns_a_record_ipv4_list': {
                'type': 'list',
                'dns_a_record_ip': {
                    'type': 'str',
                    'required': True,
                },
                'no_resp': {
                    'type': 'bool',
                },
                'as_backup': {
                    'type': 'bool',
                },
                'weight': {
                    'type': 'int',
                },
                'ttl': {
                    'type': 'int',
                },
                'as_replace': {
                    'type': 'bool',
                },
                'disable': {
                    'type': 'bool',
                },
                'static': {
                    'type': 'bool',
                },
                'admin_ip': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                },
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type': 'str',
                        'choices': ['all', 'hits']
                    }
                }
            },
            'dns_a_record_ipv6_list': {
                'type': 'list',
                'dns_a_record_ipv6': {
                    'type': 'str',
                    'required': True,
                },
                'no_resp': {
                    'type': 'bool',
                },
                'as_backup': {
                    'type': 'bool',
                },
                'weight': {
                    'type': 'int',
                },
                'ttl': {
                    'type': 'int',
                },
                'as_replace': {
                    'type': 'bool',
                },
                'disable': {
                    'type': 'bool',
                },
                'static': {
                    'type': 'bool',
                },
                'admin_ip': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                },
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type': 'str',
                        'choices': ['all', 'hits']
                    }
                }
            }
        },
        'dns_cname_record_list': {
            'type': 'list',
            'alias_name': {
                'type': 'str',
                'required': True,
            },
            'admin_preference': {
                'type': 'int',
            },
            'weight': {
                'type': 'int',
            },
            'as_backup': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type': 'str',
                    'choices': ['all', 'cname-hits']
                }
            }
        },
        'dns_mx_record_list': {
            'type': 'list',
            'mx_name': {
                'type': 'str',
                'required': True,
            },
            'priority': {
                'type': 'int',
            },
            'ttl': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type': 'str',
                    'choices': ['all', 'hits']
                }
            }
        },
        'dns_ns_record_list': {
            'type': 'list',
            'ns_name': {
                'type': 'str',
                'required': True,
            },
            'ttl': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type': 'str',
                    'choices': ['all', 'hits']
                }
            }
        },
        'dns_ptr_record_list': {
            'type': 'list',
            'ptr_name': {
                'type': 'str',
                'required': True,
            },
            'ttl': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type': 'str',
                    'choices': ['all', 'hits']
                }
            }
        },
        'dns_srv_record_list': {
            'type': 'list',
            'srv_name': {
                'type': 'str',
                'required': True,
            },
            'port': {
                'type': 'int',
                'required': True,
            },
            'priority': {
                'type': 'int',
            },
            'weight': {
                'type': 'int',
            },
            'ttl': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type': 'str',
                    'choices': ['all', 'hits']
                }
            }
        },
        'dns_naptr_record_list': {
            'type': 'list',
            'naptr_target': {
                'type': 'str',
                'required': True,
            },
            'service_proto': {
                'type': 'str',
                'required': True,
            },
            'flag': {
                'type': 'str',
                'required': True,
            },
            'order': {
                'type': 'int',
            },
            'preference': {
                'type': 'int',
            },
            'regexp': {
                'type': 'bool',
            },
            'ttl': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type': 'str',
                    'choices': ['all', 'naptr-hits']
                }
            }
        },
        'dns_txt_record_list': {
            'type': 'list',
            'record_name': {
                'type': 'str',
                'required': True,
            },
            'txt_data': {
                'type': 'str',
            },
            'ttl': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type': 'str',
                    'choices': ['all', 'hits']
                }
            }
        },
        'dns_record_list': {
            'type': 'list',
            'ntype': {
                'type': 'int',
                'required': True,
            },
            'data': {
                'type': 'str',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'geo_location_list': {
            'type': 'list',
            'geo_name': {
                'type': 'str',
                'required': True,
            },
            'alias': {
                'type': 'list',
                'alias': {
                    'type': 'str',
                }
            },
            'action': {
                'type': 'bool',
            },
            'action_type': {
                'type': 'str',
                'choices': ['allow', 'drop', 'forward', 'ignore', 'reject']
            },
            'forward_type': {
                'type': 'str',
                'choices': ['both', 'query', 'response']
            },
            'policy': {
                'type': 'str',
            },
            'uuid': {
                'type': 'str',
            },
            'user_tag': {
                'type': 'str',
            }
        },
        'oper': {
            'type': 'dict',
            'state': {
                'type': 'str',
            },
            'cache_list': {
                'type': 'list',
                'alias': {
                    'type': 'str',
                },
                'cache_length': {
                    'type': 'int',
                },
                'cache_ttl': {
                    'type': 'int',
                },
                'cache_dns_flag': {
                    'type': 'str',
                },
                'question_records': {
                    'type': 'int',
                },
                'answer_records': {
                    'type': 'int',
                },
                'authority_records': {
                    'type': 'int',
                },
                'additional_records': {
                    'type': 'int',
                }
            },
            'session_list': {
                'type': 'list',
                'client': {
                    'type': 'str',
                },
                'best': {
                    'type': 'str',
                },
                'mode': {
                    'type': 'str',
                },
                'hits': {
                    'type': 'int',
                },
                'last_second_hits': {
                    'type': 'int',
                },
                'ttl': {
                    'type': 'str',
                },
                'update': {
                    'type': 'int',
                },
                'aging': {
                    'type': 'int',
                }
            },
            'matched': {
                'type': 'int',
            },
            'total_sessions': {
                'type': 'int',
            },
            'service_port': {
                'type': 'int',
                'required': True,
            },
            'service_name': {
                'type': 'str',
                'required': True,
            },
            'dns_mx_record_list': {
                'type': 'list',
                'mx_name': {
                    'type': 'str',
                    'required': True,
                },
                'oper': {
                    'type': 'dict',
                    'last_server': {
                        'type': 'str',
                    }
                }
            },
            'dns_ns_record_list': {
                'type': 'list',
                'ns_name': {
                    'type': 'str',
                    'required': True,
                },
                'oper': {
                    'type': 'dict',
                    'last_server': {
                        'type': 'str',
                    }
                }
            }
        },
        'stats': {
            'type': 'dict',
            'received_query': {
                'type': 'str',
            },
            'sent_response': {
                'type': 'str',
            },
            'proxy_mode_response': {
                'type': 'str',
            },
            'cache_mode_response': {
                'type': 'str',
            },
            'server_mode_response': {
                'type': 'str',
            },
            'sticky_mode_response': {
                'type': 'str',
            },
            'backup_mode_response': {
                'type': 'str',
            },
            'service_port': {
                'type': 'int',
                'required': True,
            },
            'service_name': {
                'type': 'str',
                'required': True,
            },
            'dns_a_record': {
                'type': 'dict',
            },
            'dns_cname_record_list': {
                'type': 'list',
                'alias_name': {
                    'type': 'str',
                    'required': True,
                },
                'stats': {
                    'type': 'dict',
                    'cname_hits': {
                        'type': 'str',
                    }
                }
            },
            'dns_mx_record_list': {
                'type': 'list',
                'mx_name': {
                    'type': 'str',
                    'required': True,
                },
                'stats': {
                    'type': 'dict',
                    'hits': {
                        'type': 'str',
                    }
                }
            },
            'dns_ns_record_list': {
                'type': 'list',
                'ns_name': {
                    'type': 'str',
                    'required': True,
                },
                'stats': {
                    'type': 'dict',
                    'hits': {
                        'type': 'str',
                    }
                }
            },
            'dns_ptr_record_list': {
                'type': 'list',
                'ptr_name': {
                    'type': 'str',
                    'required': True,
                },
                'stats': {
                    'type': 'dict',
                    'hits': {
                        'type': 'str',
                    }
                }
            },
            'dns_srv_record_list': {
                'type': 'list',
                'srv_name': {
                    'type': 'str',
                    'required': True,
                },
                'port': {
                    'type': 'int',
                    'required': True,
                },
                'stats': {
                    'type': 'dict',
                    'hits': {
                        'type': 'str',
                    }
                }
            },
            'dns_naptr_record_list': {
                'type': 'list',
                'naptr_target': {
                    'type': 'str',
                    'required': True,
                },
                'service_proto': {
                    'type': 'str',
                    'required': True,
                },
                'flag': {
                    'type': 'str',
                    'required': True,
                },
                'stats': {
                    'type': 'dict',
                    'naptr_hits': {
                        'type': 'str',
                    }
                }
            },
            'dns_txt_record_list': {
                'type': 'list',
                'record_name': {
                    'type': 'str',
                    'required': True,
                },
                'stats': {
                    'type': 'dict',
                    'hits': {
                        'type': 'str',
                    }
                }
            }
        }
    })
    # Parent keys
    rv.update(dict(zone_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/zone/{zone_name}/service/{service-port}+{service-name}"

    f_dict = {}
    f_dict["service-port"] = module.params["service_port"]
    f_dict["service-name"] = module.params["service_name"]
    f_dict["zone_name"] = module.params["zone_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/zone/{zone_name}/service/{service-port}+{service-name}"

    f_dict = {}
    f_dict["service-port"] = ""
    f_dict["service-name"] = ""
    f_dict["zone_name"] = module.params["zone_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["service"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["service"].get(k) != v:
            change_results["changed"] = True
            config_changes["service"][k] = v

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
    payload = utils.build_json("service", module.params, AVAILABLE_PROPERTIES)
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
                  axapi_calls=[])

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
        if existing_config['response_body'] != 'Not Found':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                result["axapi_calls"].append(
                    api_client.get(module.client, existing_url(module)))
            elif module.params.get("get_type") == "list":
                result["axapi_calls"].append(
                    api_client.get_list(module.client, existing_url(module)))
            elif module.params.get("get_type") == "oper":
                result["axapi_calls"].append(
                    api_client.get_oper(module.client, existing_url(module)))
            elif module.params.get("get_type") == "stats":
                result["axapi_calls"].append(
                    api_client.get_stats(module.client, existing_url(module)))
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.session.session_id:
            module.client.session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
