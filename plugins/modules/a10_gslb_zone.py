#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_gslb_zone
description:
    - Specify the DNS zone name for which global SLB is provided
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
        - "Specify the name for the DNS zone"
        type: str
        required: True
    disable:
        description:
        - "Disable all services in the GSLB zone"
        type: bool
        required: False
    policy:
        description:
        - "Specify the policy for this zone (Specify policy name)"
        type: str
        required: False
    template:
        description:
        - "Field template"
        type: dict
        required: False
        suboptions:
            dnssec:
                description:
                - "Specify DNSSEC template (Specify template name)"
                type: str
    ttl:
        description:
        - "Specify the zone ttl value (TTL value, unit= second, default is 10)"
        type: int
        required: False
    use_server_ttl:
        description:
        - "Use DNS Server Response TTL value in GSLB Proxy mode"
        type: bool
        required: False
    dns_soa_record:
        description:
        - "Field dns_soa_record"
        type: dict
        required: False
        suboptions:
            soa_name:
                description:
                - "DNS Server Name"
                type: str
            mail:
                description:
                - "Mailbox"
                type: str
            expire:
                description:
                - "Specify Expire Time Interval, default is 1209600"
                type: int
            refresh:
                description:
                - "Specify Refresh Time Interval, default is 3600"
                type: int
            retry:
                description:
                - "Specify Retry Time Interval, default is 900"
                type: int
            serial:
                description:
                - "Specify Serial Number, default is Current Time (Time Interval)"
                type: int
            soa_ttl:
                description:
                - "Specify Negative caching TTL, default is Zone TTL"
                type: int
            external:
                description:
                - "Specify External SOA Record (DNS Server Name)"
                type: str
            ex_mail:
                description:
                - "Mailbox"
                type: str
            ex_expire:
                description:
                - "Specify Expire Time Interval, default is 1209600"
                type: int
            ex_refresh:
                description:
                - "Specify Refresh Time Interval, default is 3600"
                type: int
            ex_retry:
                description:
                - "Specify Retry Time Interval, default is 900"
                type: int
            ex_serial:
                description:
                - "Specify Serial Number, default is Current Time (Time Interval)"
                type: int
            ex_soa_ttl:
                description:
                - "Specify Negative caching TTL, default is Zone TTL"
                type: int
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
                - "'all'= all; 'received-query'= Total Number of DNS queries received for the
          zone; 'sent-response'= Total Number of DNS replies sent to clients for the
          zone; 'proxy-mode-response'= Total Number of DNS replies sent to clients by the
          ACOS device as a DNS proxy for the zone; 'cache-mode-response'= Total Number of
          cached DNS replies sent to clients by the ACOS device for the zone. (This
          statistic applies only if the DNS cac; 'server-mode-response'= Total Number of
          DNS replies sent to clients by the ACOS device as a DNS server for the zone.
          (This statistic applies only if th; 'sticky-mode-response'= Total Number of DNS
          replies sent to clients by the ACOS device to keep the clients on the same
          site. (This statistic applies on; 'backup-mode-response'= Total Number of DNS
          replies sent to clients by the ACOS device in backup mode;"
                type: str
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
    service_list:
        description:
        - "Field service_list"
        type: list
        required: False
        suboptions:
            service_port:
                description:
                - "Port number of the service"
                type: int
            service_name:
                description:
                - "Specify the service name for the zone, * for wildcard"
                type: str
            action:
                description:
                - "'drop'= Drop query; 'forward'= Forward packet; 'ignore'= Send empty response;
          'reject'= Send refuse response;"
                type: str
            forward_type:
                description:
                - "'both'= Forward both query and response; 'query'= Forward query; 'response'=
          Forward response;"
                type: str
            disable:
                description:
                - "Disable"
                type: bool
            health_check_gateway:
                description:
                - "'enable'= Enable Gateway Status Check; 'disable'= Disable Gateway Status Check;"
                type: str
            health_check_port:
                description:
                - "Field health_check_port"
                type: list
            policy:
                description:
                - "Specify policy for this service (Specify policy name)"
                type: str
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
            dns_record_list:
                description:
                - "Field dns_record_list"
                type: list
            geo_location_list:
                description:
                - "Field geo_location_list"
                type: list
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
            name:
                description:
                - "Specify the name for the DNS zone"
                type: str
            dns_mx_record_list:
                description:
                - "Field dns_mx_record_list"
                type: list
            dns_ns_record_list:
                description:
                - "Field dns_ns_record_list"
                type: list
            service_list:
                description:
                - "Field service_list"
                type: list
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            received_query:
                description:
                - "Total Number of DNS queries received for the zone"
                type: str
            sent_response:
                description:
                - "Total Number of DNS replies sent to clients for the zone"
                type: str
            proxy_mode_response:
                description:
                - "Total Number of DNS replies sent to clients by the ACOS device as a DNS proxy
          for the zone"
                type: str
            cache_mode_response:
                description:
                - "Total Number of cached DNS replies sent to clients by the ACOS device for the
          zone. (This statistic applies only if the DNS cac"
                type: str
            server_mode_response:
                description:
                - "Total Number of DNS replies sent to clients by the ACOS device as a DNS server
          for the zone. (This statistic applies only if th"
                type: str
            sticky_mode_response:
                description:
                - "Total Number of DNS replies sent to clients by the ACOS device to keep the
          clients on the same site. (This statistic applies on"
                type: str
            backup_mode_response:
                description:
                - "Total Number of DNS replies sent to clients by the ACOS device in backup mode"
                type: str
            name:
                description:
                - "Specify the name for the DNS zone"
                type: str
            dns_mx_record_list:
                description:
                - "Field dns_mx_record_list"
                type: list
            dns_ns_record_list:
                description:
                - "Field dns_ns_record_list"
                type: list
            service_list:
                description:
                - "Field service_list"
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

# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "disable",
    "dns_mx_record_list",
    "dns_ns_record_list",
    "dns_soa_record",
    "name",
    "oper",
    "policy",
    "sampling_enable",
    "service_list",
    "stats",
    "template",
    "ttl",
    "use_server_ttl",
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
        'disable': {
            'type': 'bool',
        },
        'policy': {
            'type': 'str',
        },
        'template': {
            'type': 'dict',
            'dnssec': {
                'type': 'str',
            }
        },
        'ttl': {
            'type': 'int',
        },
        'use_server_ttl': {
            'type': 'bool',
        },
        'dns_soa_record': {
            'type': 'dict',
            'soa_name': {
                'type': 'str',
            },
            'mail': {
                'type': 'str',
            },
            'expire': {
                'type': 'int',
            },
            'refresh': {
                'type': 'int',
            },
            'retry': {
                'type': 'int',
            },
            'serial': {
                'type': 'int',
            },
            'soa_ttl': {
                'type': 'int',
            },
            'external': {
                'type': 'str',
            },
            'ex_mail': {
                'type': 'str',
            },
            'ex_expire': {
                'type': 'int',
            },
            'ex_refresh': {
                'type': 'int',
            },
            'ex_retry': {
                'type': 'int',
            },
            'ex_serial': {
                'type': 'int',
            },
            'ex_soa_ttl': {
                'type': 'int',
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
                    'all', 'received-query', 'sent-response',
                    'proxy-mode-response', 'cache-mode-response',
                    'server-mode-response', 'sticky-mode-response',
                    'backup-mode-response'
                ]
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
        'service_list': {
            'type': 'list',
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
                    'choices':
                    ['allow', 'drop', 'forward', 'ignore', 'reject']
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
            }
        },
        'oper': {
            'type': 'dict',
            'state': {
                'type': 'str',
            },
            'name': {
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
            },
            'service_list': {
                'type': 'list',
                'service_port': {
                    'type': 'int',
                    'required': True,
                },
                'service_name': {
                    'type': 'str',
                    'required': True,
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
                    }
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
            'name': {
                'type': 'str',
                'required': True,
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
            'service_list': {
                'type': 'list',
                'service_port': {
                    'type': 'int',
                    'required': True,
                },
                'service_name': {
                    'type': 'str',
                    'required': True,
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
                    }
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
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/zone/{name}"

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


def _get(module, url, params={}):

    resp = None
    try:
        resp = module.client.get(url, params=params)
    except a10_ex.NotFound:
        resp = "Not Found"

    call_result = {
        "endpoint": url,
        "http_method": "GET",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _post(module, url, params={}, file_content=None, file_name=None):
    resp = module.client.post(url, params=params)
    resp = resp if resp else {}
    call_result = {
        "endpoint": url,
        "http_method": "POST",
        "request_body": params,
        "response_body": resp,
    }
    return call_result


def _delete(module, url):
    call_result = {
        "endpoint": url,
        "http_method": "DELETE",
        "request_body": {},
        "response_body": module.client.delete(url),
    }
    return call_result


def _switch_device_context(module, device_id):
    call_result = {
        "endpoint": "/axapi/v3/device-context",
        "http_method": "POST",
        "request_body": {
            "device-id": device_id
        },
        "response_body": module.client.change_context(device_id)
    }
    return call_result


def _active_partition(module, a10_partition):
    call_result = {
        "endpoint": "/axapi/v3/active-partition",
        "http_method": "POST",
        "request_body": {
            "curr_part_name": a10_partition
        },
        "response_body": module.client.activate_partition(a10_partition)
    }
    return call_result


def get(module):
    return _get(module, existing_url(module))


def get_list(module):
    return _get(module, list_url(module))


def get_oper(module):
    query_params = {}
    if module.params.get("oper"):
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, oper_url(module), params=query_params)


def get_stats(module):
    query_params = {}
    if module.params.get("stats"):
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
    return _get(module, stats_url(module), params=query_params)


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
    url_base = "/axapi/v3/gslb/zone/{name}"

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
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["zone"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["zone"].get(k) != v:
            change_results["changed"] = True
            config_changes["zone"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload):
    try:
        call_result = _post(module, new_url(module), payload)
        result["axapi_calls"].append(call_result)
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        module.client.session.close()
    return result


def update(module, result, existing_config, payload):
    try:
        call_result = _post(module, existing_url(module), payload)
        result["axapi_calls"].append(call_result)
        if call_result["response_body"] == existing_config:
            result["changed"] = False
        else:
            result["modified_values"].update(**call_result["response_body"])
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        module.client.session.close()
    return result


def present(module, result, existing_config):
    payload = build_json("zone", module)
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
        call_result = _delete(module, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        module.client.session.close()
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

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
    finally:
        module.client.session.close()
    return result


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

    valid = True

    run_errors = []
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
        result["axapi_calls"].append(_active_partition(module, a10_partition))

    if a10_device_context_id:
        result["axapi_calls"].append(
            _switch_device_context(module, a10_device_context_id))

    existing_config = get(module)
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
            result["axapi_calls"].append(get(module))
        elif module.params.get("get_type") == "list":
            result["axapi_calls"].append(get_list(module))
        elif module.params.get("get_type") == "oper":
            result["axapi_calls"].append(get_oper(module))
        elif module.params.get("get_type") == "stats":
            result["axapi_calls"].append(get_stats(module))

    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
