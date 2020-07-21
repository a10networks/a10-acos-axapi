#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_gslb_zone
description:
    - Specify the DNS zone name for which global SLB is provided
short_description: Configures A10 gslb.zone
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
            service_list:
                description:
                - "Field service_list"
            state:
                description:
                - "Field state"
            dns_mx_record_list:
                description:
                - "Field dns_mx_record_list"
            name:
                description:
                - "Specify the name for the DNS zone"
            dns_ns_record_list:
                description:
                - "Field dns_ns_record_list"
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            received_query:
                description:
                - "Total Number of DNS queries received for the zone"
            name:
                description:
                - "Specify the name for the DNS zone"
            dns_ns_record_list:
                description:
                - "Field dns_ns_record_list"
            sent_response:
                description:
                - "Total Number of DNS replies sent to clients for the zone"
            dns_mx_record_list:
                description:
                - "Field dns_mx_record_list"
            sticky_mode_response:
                description:
                - "Total Number of DNS replies sent to clients by the ACOS device to keep the
          clients on the same site. (This statistic applies on"
            server_mode_response:
                description:
                - "Total Number of DNS replies sent to clients by the ACOS device as a DNS server
          for the zone. (This statistic applies only if th"
            cache_mode_response:
                description:
                - "Total Number of cached DNS replies sent to clients by the ACOS device for the
          zone. (This statistic applies only if the DNS cac"
            backup_mode_response:
                description:
                - "Total Number of DNS replies sent to clients by the ACOS device in backup mode"
            service_list:
                description:
                - "Field service_list"
            proxy_mode_response:
                description:
                - "Total Number of DNS replies sent to clients by the ACOS device as a DNS proxy
          for the zone"
    name:
        description:
        - "Specify the name for the DNS zone"
        required: True
    dns_ns_record_list:
        description:
        - "Field dns_ns_record_list"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            ns_name:
                description:
                - "Specify Domain Name"
            uuid:
                description:
                - "uuid of the object"
            ttl:
                description:
                - "Specify TTL"
    dns_mx_record_list:
        description:
        - "Field dns_mx_record_list"
        required: False
        suboptions:
            priority:
                description:
                - "Specify Priority"
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
            mx_name:
                description:
                - "Specify Domain Name"
            ttl:
                description:
                - "Specify TTL"
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
    disable:
        description:
        - "Disable all services in the GSLB zone"
        required: False
    template:
        description:
        - "Field template"
        required: False
        suboptions:
            dnssec:
                description:
                - "Specify DNSSEC template (Specify template name)"
    ttl:
        description:
        - "Specify the zone ttl value (TTL value, unit= second, default is 10)"
        required: False
    policy:
        description:
        - "Specify the policy for this zone (Specify policy name)"
        required: False
    use_server_ttl:
        description:
        - "Use DNS Server Response TTL value in GSLB Proxy mode"
        required: False
    dns_soa_record:
        description:
        - "Field dns_soa_record"
        required: False
        suboptions:
            retry:
                description:
                - "Specify Retry Time Interval, default is 900"
            soa_name:
                description:
                - "DNS Server Name"
            ex_retry:
                description:
                - "Specify Retry Time Interval, default is 900"
            ex_soa_ttl:
                description:
                - "Specify Negative caching TTL, default is Zone TTL"
            ex_serial:
                description:
                - "Specify Serial Number, default is Current Time (Time Interval)"
            refresh:
                description:
                - "Specify Refresh Time Interval, default is 3600"
            ex_mail:
                description:
                - "Mailbox"
            expire:
                description:
                - "Specify Expire Time Interval, default is 1209600"
            ex_expire:
                description:
                - "Specify Expire Time Interval, default is 1209600"
            external:
                description:
                - "Specify External SOA Record (DNS Server Name)"
            mail:
                description:
                - "Mailbox"
            serial:
                description:
                - "Specify Serial Number, default is Current Time (Time Interval)"
            ex_refresh:
                description:
                - "Specify Refresh Time Interval, default is 3600"
            soa_ttl:
                description:
                - "Specify Negative caching TTL, default is Zone TTL"
    service_list:
        description:
        - "Field service_list"
        required: False
        suboptions:
            dns_a_record:
                description:
                - "Field dns_a_record"
            forward_type:
                description:
                - "'both'= Forward both query and response; 'query'= Forward query; 'response'=
          Forward response;"
            uuid:
                description:
                - "uuid of the object"
            health_check_port:
                description:
                - "Field health_check_port"
            dns_txt_record_list:
                description:
                - "Field dns_txt_record_list"
            service_port:
                description:
                - "Port number of the service"
            dns_mx_record_list:
                description:
                - "Field dns_mx_record_list"
            dns_record_list:
                description:
                - "Field dns_record_list"
            user_tag:
                description:
                - "Customized tag"
            dns_ns_record_list:
                description:
                - "Field dns_ns_record_list"
            health_check_gateway:
                description:
                - "'enable'= Enable Gateway Status Check; 'disable'= Disable Gateway Status Check;"
            sampling_enable:
                description:
                - "Field sampling_enable"
            disable:
                description:
                - "Disable"
            dns_srv_record_list:
                description:
                - "Field dns_srv_record_list"
            service_name:
                description:
                - "Specify the service name for the zone, * for wildcard"
            policy:
                description:
                - "Specify policy for this service (Specify policy name)"
            dns_ptr_record_list:
                description:
                - "Field dns_ptr_record_list"
            dns_cname_record_list:
                description:
                - "Field dns_cname_record_list"
            action:
                description:
                - "'drop'= Drop query; 'forward'= Forward packet; 'ignore'= Send empty response;
          'reject'= Send refuse response;"
            geo_location_list:
                description:
                - "Field geo_location_list"
            dns_naptr_record_list:
                description:
                - "Field dns_naptr_record_list"
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
            'service_list': {
                'type': 'list',
                'oper': {
                    'type': 'dict',
                    'cache_list': {
                        'type': 'list',
                        'cache_ttl': {
                            'type': 'int',
                        },
                        'additional_records': {
                            'type': 'int',
                        },
                        'answer_records': {
                            'type': 'int',
                        },
                        'cache_dns_flag': {
                            'type': 'str',
                        },
                        'question_records': {
                            'type': 'int',
                        },
                        'alias': {
                            'type': 'str',
                        },
                        'cache_length': {
                            'type': 'int',
                        },
                        'authority_records': {
                            'type': 'int',
                        }
                    },
                    'total_sessions': {
                        'type': 'int',
                    },
                    'matched': {
                        'type': 'int',
                    },
                    'state': {
                        'type': 'str',
                    },
                    'session_list': {
                        'type': 'list',
                        'aging': {
                            'type': 'int',
                        },
                        'hits': {
                            'type': 'int',
                        },
                        'update': {
                            'type': 'int',
                        },
                        'client': {
                            'type': 'str',
                        },
                        'last_second_hits': {
                            'type': 'int',
                        },
                        'mode': {
                            'type': 'str',
                        },
                        'ttl': {
                            'type': 'str',
                        },
                        'best': {
                            'type': 'str',
                        }
                    }
                },
                'service_port': {
                    'type': 'int',
                    'required': True,
                },
                'dns_mx_record_list': {
                    'type': 'list',
                    'oper': {
                        'type': 'dict',
                        'last_server': {
                            'type': 'str',
                        }
                    },
                    'mx_name': {
                        'type': 'str',
                        'required': True,
                    }
                },
                'dns_ns_record_list': {
                    'type': 'list',
                    'oper': {
                        'type': 'dict',
                        'last_server': {
                            'type': 'str',
                        }
                    },
                    'ns_name': {
                        'type': 'str',
                        'required': True,
                    }
                },
                'service_name': {
                    'type': 'str',
                    'required': True,
                }
            },
            'state': {
                'type': 'str',
            },
            'dns_mx_record_list': {
                'type': 'list',
                'oper': {
                    'type': 'dict',
                    'last_server': {
                        'type': 'str',
                    }
                },
                'mx_name': {
                    'type': 'str',
                    'required': True,
                }
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'dns_ns_record_list': {
                'type': 'list',
                'oper': {
                    'type': 'dict',
                    'last_server': {
                        'type': 'str',
                    }
                },
                'ns_name': {
                    'type': 'str',
                    'required': True,
                }
            }
        },
        'stats': {
            'type': 'dict',
            'received_query': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
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
            'sent_response': {
                'type': 'str',
            },
            'dns_mx_record_list': {
                'type': 'list',
                'stats': {
                    'type': 'dict',
                    'hits': {
                        'type': 'str',
                    }
                },
                'mx_name': {
                    'type': 'str',
                    'required': True,
                }
            },
            'sticky_mode_response': {
                'type': 'str',
            },
            'server_mode_response': {
                'type': 'str',
            },
            'cache_mode_response': {
                'type': 'str',
            },
            'backup_mode_response': {
                'type': 'str',
            },
            'service_list': {
                'type': 'list',
                'dns_a_record': {
                    'type': 'dict',
                },
                'stats': {
                    'type': 'dict',
                    'received_query': {
                        'type': 'str',
                    },
                    'sent_response': {
                        'type': 'str',
                    },
                    'sticky_mode_response': {
                        'type': 'str',
                    },
                    'server_mode_response': {
                        'type': 'str',
                    },
                    'cache_mode_response': {
                        'type': 'str',
                    },
                    'backup_mode_response': {
                        'type': 'str',
                    },
                    'proxy_mode_response': {
                        'type': 'str',
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
                },
                'service_port': {
                    'type': 'int',
                    'required': True,
                },
                'dns_mx_record_list': {
                    'type': 'list',
                    'stats': {
                        'type': 'dict',
                        'hits': {
                            'type': 'str',
                        }
                    },
                    'mx_name': {
                        'type': 'str',
                        'required': True,
                    }
                },
                'dns_srv_record_list': {
                    'type': 'list',
                    'srv_name': {
                        'type': 'str',
                        'required': True,
                    },
                    'stats': {
                        'type': 'dict',
                        'hits': {
                            'type': 'str',
                        }
                    },
                    'port': {
                        'type': 'int',
                        'required': True,
                    }
                },
                'service_name': {
                    'type': 'str',
                    'required': True,
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
                'dns_naptr_record_list': {
                    'type': 'list',
                    'flag': {
                        'type': 'str',
                        'required': True,
                    },
                    'stats': {
                        'type': 'dict',
                        'naptr_hits': {
                            'type': 'str',
                        }
                    },
                    'service_proto': {
                        'type': 'str',
                        'required': True,
                    },
                    'naptr_target': {
                        'type': 'str',
                        'required': True,
                    }
                }
            },
            'proxy_mode_response': {
                'type': 'str',
            }
        },
        'name': {
            'type': 'str',
            'required': True,
        },
        'dns_ns_record_list': {
            'type': 'list',
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type': 'str',
                    'choices': ['all', 'hits']
                }
            },
            'ns_name': {
                'type': 'str',
                'required': True,
            },
            'uuid': {
                'type': 'str',
            },
            'ttl': {
                'type': 'int',
            }
        },
        'dns_mx_record_list': {
            'type': 'list',
            'priority': {
                'type': 'int',
            },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type': 'str',
                    'choices': ['all', 'hits']
                }
            },
            'uuid': {
                'type': 'str',
            },
            'mx_name': {
                'type': 'str',
                'required': True,
            },
            'ttl': {
                'type': 'int',
            }
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
        'disable': {
            'type': 'bool',
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
        'policy': {
            'type': 'str',
        },
        'use_server_ttl': {
            'type': 'bool',
        },
        'dns_soa_record': {
            'type': 'dict',
            'retry': {
                'type': 'int',
            },
            'soa_name': {
                'type': 'str',
            },
            'ex_retry': {
                'type': 'int',
            },
            'ex_soa_ttl': {
                'type': 'int',
            },
            'ex_serial': {
                'type': 'int',
            },
            'refresh': {
                'type': 'int',
            },
            'ex_mail': {
                'type': 'str',
            },
            'expire': {
                'type': 'int',
            },
            'ex_expire': {
                'type': 'int',
            },
            'external': {
                'type': 'str',
            },
            'mail': {
                'type': 'str',
            },
            'serial': {
                'type': 'int',
            },
            'ex_refresh': {
                'type': 'int',
            },
            'soa_ttl': {
                'type': 'int',
            }
        },
        'service_list': {
            'type': 'list',
            'dns_a_record': {
                'type': 'dict',
                'dns_a_record_ipv6_list': {
                    'type': 'list',
                    'as_replace': {
                        'type': 'bool',
                    },
                    'dns_a_record_ipv6': {
                        'type': 'str',
                        'required': True,
                    },
                    'as_backup': {
                        'type': 'bool',
                    },
                    'weight': {
                        'type': 'int',
                    },
                    'sampling_enable': {
                        'type': 'list',
                        'counters1': {
                            'type': 'str',
                            'choices': ['all', 'hits']
                        }
                    },
                    'disable': {
                        'type': 'bool',
                    },
                    'static': {
                        'type': 'bool',
                    },
                    'ttl': {
                        'type': 'int',
                    },
                    'no_resp': {
                        'type': 'bool',
                    },
                    'admin_ip': {
                        'type': 'int',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                },
                'dns_a_record_ipv4_list': {
                    'type': 'list',
                    'as_replace': {
                        'type': 'bool',
                    },
                    'dns_a_record_ip': {
                        'type': 'str',
                        'required': True,
                    },
                    'as_backup': {
                        'type': 'bool',
                    },
                    'weight': {
                        'type': 'int',
                    },
                    'sampling_enable': {
                        'type': 'list',
                        'counters1': {
                            'type': 'str',
                            'choices': ['all', 'hits']
                        }
                    },
                    'disable': {
                        'type': 'bool',
                    },
                    'static': {
                        'type': 'bool',
                    },
                    'ttl': {
                        'type': 'int',
                    },
                    'no_resp': {
                        'type': 'bool',
                    },
                    'admin_ip': {
                        'type': 'int',
                    },
                    'uuid': {
                        'type': 'str',
                    }
                },
                'dns_a_record_srv_list': {
                    'type': 'list',
                    'as_backup': {
                        'type': 'bool',
                    },
                    'as_replace': {
                        'type': 'bool',
                    },
                    'uuid': {
                        'type': 'str',
                    },
                    'weight': {
                        'type': 'int',
                    },
                    'svrname': {
                        'type': 'str',
                        'required': True,
                    },
                    'sampling_enable': {
                        'type': 'list',
                        'counters1': {
                            'type': 'str',
                            'choices': ['all', 'hits']
                        }
                    },
                    'disable': {
                        'type': 'bool',
                    },
                    'static': {
                        'type': 'bool',
                    },
                    'ttl': {
                        'type': 'int',
                    },
                    'admin_ip': {
                        'type': 'int',
                    },
                    'no_resp': {
                        'type': 'bool',
                    }
                }
            },
            'forward_type': {
                'type': 'str',
                'choices': ['both', 'query', 'response']
            },
            'uuid': {
                'type': 'str',
            },
            'health_check_port': {
                'type': 'list',
                'health_check_port': {
                    'type': 'int',
                }
            },
            'dns_txt_record_list': {
                'type': 'list',
                'record_name': {
                    'type': 'str',
                    'required': True,
                },
                'ttl': {
                    'type': 'int',
                },
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type': 'str',
                        'choices': ['all', 'hits']
                    }
                },
                'uuid': {
                    'type': 'str',
                },
                'txt_data': {
                    'type': 'str',
                }
            },
            'service_port': {
                'type': 'int',
                'required': True,
            },
            'dns_mx_record_list': {
                'type': 'list',
                'priority': {
                    'type': 'int',
                },
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type': 'str',
                        'choices': ['all', 'hits']
                    }
                },
                'uuid': {
                    'type': 'str',
                },
                'mx_name': {
                    'type': 'str',
                    'required': True,
                },
                'ttl': {
                    'type': 'int',
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
            'user_tag': {
                'type': 'str',
            },
            'dns_ns_record_list': {
                'type': 'list',
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type': 'str',
                        'choices': ['all', 'hits']
                    }
                },
                'ns_name': {
                    'type': 'str',
                    'required': True,
                },
                'uuid': {
                    'type': 'str',
                },
                'ttl': {
                    'type': 'int',
                }
            },
            'health_check_gateway': {
                'type': 'str',
                'choices': ['enable', 'disable']
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
            'disable': {
                'type': 'bool',
            },
            'dns_srv_record_list': {
                'type': 'list',
                'srv_name': {
                    'type': 'str',
                    'required': True,
                },
                'uuid': {
                    'type': 'str',
                },
                'weight': {
                    'type': 'int',
                },
                'priority': {
                    'type': 'int',
                },
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type': 'str',
                        'choices': ['all', 'hits']
                    }
                },
                'ttl': {
                    'type': 'int',
                },
                'port': {
                    'type': 'int',
                    'required': True,
                }
            },
            'service_name': {
                'type': 'str',
                'required': True,
            },
            'policy': {
                'type': 'str',
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
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type': 'str',
                        'choices': ['all', 'hits']
                    }
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'dns_cname_record_list': {
                'type': 'list',
                'alias_name': {
                    'type': 'str',
                    'required': True,
                },
                'uuid': {
                    'type': 'str',
                },
                'as_backup': {
                    'type': 'bool',
                },
                'weight': {
                    'type': 'int',
                },
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type': 'str',
                        'choices': ['all', 'cname-hits']
                    }
                },
                'admin_preference': {
                    'type': 'int',
                }
            },
            'action': {
                'type': 'str',
                'choices': ['drop', 'forward', 'ignore', 'reject']
            },
            'geo_location_list': {
                'type': 'list',
                'action_type': {
                    'type': 'str',
                    'choices':
                    ['allow', 'drop', 'forward', 'ignore', 'reject']
                },
                'uuid': {
                    'type': 'str',
                },
                'user_tag': {
                    'type': 'str',
                },
                'alias': {
                    'type': 'list',
                    'alias': {
                        'type': 'str',
                    }
                },
                'geo_name': {
                    'type': 'str',
                    'required': True,
                },
                'policy': {
                    'type': 'str',
                },
                'forward_type': {
                    'type': 'str',
                    'choices': ['both', 'query', 'response']
                },
                'action': {
                    'type': 'bool',
                }
            },
            'dns_naptr_record_list': {
                'type': 'list',
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type': 'str',
                        'choices': ['all', 'naptr-hits']
                    }
                },
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
                'preference': {
                    'type': 'int',
                },
                'ttl': {
                    'type': 'int',
                },
                'regexp': {
                    'type': 'bool',
                },
                'order': {
                    'type': 'int',
                },
                'uuid': {
                    'type': 'str',
                }
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
    if existing_config:
        for k, v in payload["zone"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["zone"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["zone"][k] = v
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
    payload = build_json("zone", module)
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
