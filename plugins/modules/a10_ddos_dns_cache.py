#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_dns_cache
description:
    - DNS Cache Settings
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
        - "DNS Cache Instance Name"
        type: str
        required: True
    zone_domain_lookup_miss_action:
        description:
        - "'respond-nxdomain'= Send NxDomain response; 'drop'= Drop the request;"
        type: str
        required: False
    default_serving_action:
        description:
        - "'serve-from-cache'= Serve DNS records; 'forward'= Forward to DNS server;
          'drop'= Drop the request;"
        type: str
        required: False
    any_query_action_str:
        description:
        - "'respond-refuse'= Send refuse response (default); 'respond-empty'= Send empty
          response; 'drop'= Drop the request;"
        type: str
        required: False
    non_authoritative_zone_query_action_str:
        description:
        - "'default'= Default action= respond-refuse; 'forward'= Forward to DNS server;
          'respond-refuse'= Send refuse response; 'drop'= Drop the request;"
        type: str
        required: False
    neg_cache_action_follow_q_rate:
        description:
        - "Negative cached response queries counted toward query-rate-threshold"
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'total-cached-fqdn'= total-cached-fqdn; 'total-cached-records'=
          total-cached-records; 'fqdn-a'= fqdn-a; 'fqdn-aaaa'= fqdn-aaaa; 'fqdn-cname'=
          fqdn-cname; 'fqdn-ns'= fqdn-ns; 'fqdn-mx'= fqdn-mx; 'fqdn-soa'= fqdn-soa;
          'fqdn-srv'= fqdn-srv; 'fqdn-txt'= fqdn-txt; 'fqdn-ptr'= fqdn-ptr; 'fqdn-other'=
          fqdn-other; 'fqdn-wildcard'= fqdn-wildcard; 'fqdn-delegation'= fqdn-delegation;
          'shard-size'= shard-size; 'resp-ext-size'= resp-ext-size; 'a-record'= a-record;
          'aaaa-record'= aaaa-record; 'cname-record'= cname-record; 'ns-record'= ns-
          record; 'mx-record'= mx-record; 'soa-record'= soa-record; 'srv-record'= srv-
          record; 'txt-record'= txt-record; 'ptr-record'= ptr-record; 'other-record'=
          other-record; 'fqdn-in-shard-filter'= fqdn-in-shard-filter;"
                type: str
    zone_transfer:
        description:
        - "Field zone_transfer"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    domain_group:
        description:
        - "Field domain_group"
        type: dict
        required: False
        suboptions:
            name:
                description:
                - "DNS domain group"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            domain_list_policy_list:
                description:
                - "Field domain_list_policy_list"
                type: list
    sharded_domain_group_list:
        description:
        - "Field sharded_domain_group_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "DNS sharded domain group"
                type: str
            match_action:
                description:
                - "'forward'= Forward query to server (default); 'tunnel-encap'= Encapsulate the
          query and send on a tunnel;"
                type: str
            encap_template:
                description:
                - "DDOS encap template to sepcify the tunnel endpoint"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            sharded_domain_list_policy_list:
                description:
                - "Field sharded_domain_list_policy_list"
                type: list
    fqdn_manual_override_action_list:
        description:
        - "Field fqdn_manual_override_action_list"
        type: list
        required: False
        suboptions:
            fqdn_name:
                description:
                - "Specify fqdn name"
                type: str
            action:
                description:
                - "'default'= Default; 'forward'= Forward to DNS server; 'drop'= Drop the request;
          'serve-from-cache'= Serve DNS records;"
                type: str
    zone_manual_override_action_list:
        description:
        - "Field zone_manual_override_action_list"
        type: list
        required: False
        suboptions:
            zone_name:
                description:
                - "Specify zone name"
                type: str
            action:
                description:
                - "'default'= Default; 'forward'= Forward to DNS server; 'drop'= Drop the request;
          'serve-from-cache'= Serve DNS records;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            domain_entries:
                description:
                - "Field domain_entries"
                type: list
            response_status:
                description:
                - "response status"
                type: str
            response_flag:
                description:
                - "response flag"
                type: str
            answer_section_record_count:
                description:
                - "Answer section record Count"
                type: int
            answer_section_size:
                description:
                - "Answer section size"
                type: int
            authority_section_record_count:
                description:
                - "Authority section record Count"
                type: int
            authority_section_size:
                description:
                - "Autority section size"
                type: int
            additional_section_record_count:
                description:
                - "Additional section record Count"
                type: int
            additional_section_size:
                description:
                - "Additional section size"
                type: int
            answer_section:
                description:
                - "Field answer_section"
                type: list
            authoritative_section:
                description:
                - "Field authoritative_section"
                type: list
            additional_section:
                description:
                - "Field additional_section"
                type: list
            all_cached_fqdn:
                description:
                - "Field all_cached_fqdn"
                type: bool
            cached_fqdn_name:
                description:
                - "Field cached_fqdn_name"
                type: str
            record_type:
                description:
                - "Field record_type"
                type: str
            debug_mode:
                description:
                - "Field debug_mode"
                type: bool
            name:
                description:
                - "DNS Cache Instance Name"
                type: str
            zone_transfer:
                description:
                - "Field zone_transfer"
                type: dict
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            total_cached_fqdn:
                description:
                - "Field total_cached_fqdn"
                type: str
            total_cached_records:
                description:
                - "Field total_cached_records"
                type: str
            fqdn_a:
                description:
                - "Field fqdn_a"
                type: str
            fqdn_aaaa:
                description:
                - "Field fqdn_aaaa"
                type: str
            fqdn_cname:
                description:
                - "Field fqdn_cname"
                type: str
            fqdn_ns:
                description:
                - "Field fqdn_ns"
                type: str
            fqdn_mx:
                description:
                - "Field fqdn_mx"
                type: str
            fqdn_soa:
                description:
                - "Field fqdn_soa"
                type: str
            fqdn_srv:
                description:
                - "Field fqdn_srv"
                type: str
            fqdn_txt:
                description:
                - "Field fqdn_txt"
                type: str
            fqdn_ptr:
                description:
                - "Field fqdn_ptr"
                type: str
            fqdn_other:
                description:
                - "Field fqdn_other"
                type: str
            fqdn_wildcard:
                description:
                - "Field fqdn_wildcard"
                type: str
            fqdn_delegation:
                description:
                - "Field fqdn_delegation"
                type: str
            shard_size:
                description:
                - "Field shard_size"
                type: str
            resp_ext_size:
                description:
                - "Field resp_ext_size"
                type: str
            a_record:
                description:
                - "Field a_record"
                type: str
            aaaa_record:
                description:
                - "Field aaaa_record"
                type: str
            cname_record:
                description:
                - "Field cname_record"
                type: str
            ns_record:
                description:
                - "Field ns_record"
                type: str
            mx_record:
                description:
                - "Field mx_record"
                type: str
            soa_record:
                description:
                - "Field soa_record"
                type: str
            srv_record:
                description:
                - "Field srv_record"
                type: str
            txt_record:
                description:
                - "Field txt_record"
                type: str
            ptr_record:
                description:
                - "Field ptr_record"
                type: str
            other_record:
                description:
                - "Field other_record"
                type: str
            fqdn_in_shard_filter:
                description:
                - "Field fqdn_in_shard_filter"
                type: str
            name:
                description:
                - "DNS Cache Instance Name"
                type: str

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
AVAILABLE_PROPERTIES = [
    "any_query_action_str", "default_serving_action", "domain_group", "fqdn_manual_override_action_list", "name", "neg_cache_action_follow_q_rate", "non_authoritative_zone_query_action_str", "oper", "sampling_enable", "sharded_domain_group_list", "stats", "user_tag", "uuid", "zone_domain_lookup_miss_action", "zone_manual_override_action_list",
    "zone_transfer",
    ]


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
        'zone_domain_lookup_miss_action': {
            'type': 'str',
            'choices': ['respond-nxdomain', 'drop']
            },
        'default_serving_action': {
            'type': 'str',
            'choices': ['serve-from-cache', 'forward', 'drop']
            },
        'any_query_action_str': {
            'type': 'str',
            'choices': ['respond-refuse', 'respond-empty', 'drop']
            },
        'non_authoritative_zone_query_action_str': {
            'type': 'str',
            'choices': ['default', 'forward', 'respond-refuse', 'drop']
            },
        'neg_cache_action_follow_q_rate': {
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
                    'all', 'total-cached-fqdn', 'total-cached-records', 'fqdn-a', 'fqdn-aaaa', 'fqdn-cname', 'fqdn-ns', 'fqdn-mx', 'fqdn-soa', 'fqdn-srv', 'fqdn-txt', 'fqdn-ptr', 'fqdn-other', 'fqdn-wildcard', 'fqdn-delegation', 'shard-size', 'resp-ext-size', 'a-record', 'aaaa-record', 'cname-record', 'ns-record', 'mx-record', 'soa-record',
                    'srv-record', 'txt-record', 'ptr-record', 'other-record', 'fqdn-in-shard-filter'
                    ]
                }
            },
        'zone_transfer': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'domain_group': {
            'type': 'dict',
            'name': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'domain_list_policy_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'server_ipv4': {
                    'type': 'str',
                    },
                'server_v4_port': {
                    'type': 'int',
                    },
                'client_ipv4': {
                    'type': 'str',
                    },
                'server_ipv6': {
                    'type': 'str',
                    },
                'server_v6_port': {
                    'type': 'int',
                    },
                'client_ipv6': {
                    'type': 'str',
                    },
                'refresh_interval_hours': {
                    'type': 'int',
                    },
                'ttl_override': {
                    'type': 'int',
                    },
                'respond_with_authority': {
                    'type': 'bool',
                    },
                'oversize_answer_response': {
                    'type': 'str',
                    'choices': ['set-truncate-bit', 'disable-truncate-bit']
                    },
                'resolve_cname_record': {
                    'type': 'bool',
                    },
                'manual_refresh': {
                    'type': 'str',
                    },
                'force': {
                    'type': 'bool',
                    },
                'cache_all_records': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'packet_capturing': {
                    'type': 'dict',
                    'root_zone_list': {
                        'type': 'list',
                        'root_zone': {
                            'type': 'str',
                            },
                        'capture_config': {
                            'type': 'str',
                            },
                        'capture_mode': {
                            'type': 'str',
                            'choices': ['regular', 'capture-on-failure']
                            }
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                }
            },
        'sharded_domain_group_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'match_action': {
                'type': 'str',
                'choices': ['forward', 'tunnel-encap']
                },
            'encap_template': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'sharded_domain_list_policy_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'server_ipv4': {
                    'type': 'str',
                    },
                'server_v4_port': {
                    'type': 'int',
                    },
                'client_ipv4': {
                    'type': 'str',
                    },
                'server_ipv6': {
                    'type': 'str',
                    },
                'server_v6_port': {
                    'type': 'int',
                    },
                'client_ipv6': {
                    'type': 'str',
                    },
                'refresh_interval_hours': {
                    'type': 'int',
                    },
                'manual_refresh': {
                    'type': 'str',
                    },
                'force': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'packet_capturing': {
                    'type': 'dict',
                    'root_zone_list': {
                        'type': 'list',
                        'root_zone': {
                            'type': 'str',
                            },
                        'capture_config': {
                            'type': 'str',
                            },
                        'capture_mode': {
                            'type': 'str',
                            'choices': ['regular', 'capture-on-failure']
                            }
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                }
            },
        'fqdn_manual_override_action_list': {
            'type': 'list',
            'fqdn_name': {
                'type': 'str',
                'required': True,
                },
            'action': {
                'type': 'str',
                'choices': ['default', 'forward', 'drop', 'serve-from-cache']
                }
            },
        'zone_manual_override_action_list': {
            'type': 'list',
            'zone_name': {
                'type': 'str',
                'required': True,
                },
            'action': {
                'type': 'str',
                'choices': ['default', 'forward', 'drop', 'serve-from-cache']
                }
            },
        'oper': {
            'type': 'dict',
            'domain_entries': {
                'type': 'list',
                'fqdn_name': {
                    'type': 'str',
                    },
                'fqdn_manual_override_action': {
                    'type': 'str',
                    },
                'wild_card_node': {
                    'type': 'str',
                    'choices': ['Yes', 'No']
                    },
                'delegation_node': {
                    'type': 'str',
                    'choices': ['Yes', 'No']
                    },
                'empty_non_terminal_node': {
                    'type': 'str',
                    'choices': ['Yes', 'No']
                    },
                'record_types': {
                    'type': 'str',
                    }
                },
            'response_status': {
                'type': 'str',
                },
            'response_flag': {
                'type': 'str',
                },
            'answer_section_record_count': {
                'type': 'int',
                },
            'answer_section_size': {
                'type': 'int',
                },
            'authority_section_record_count': {
                'type': 'int',
                },
            'authority_section_size': {
                'type': 'int',
                },
            'additional_section_record_count': {
                'type': 'int',
                },
            'additional_section_size': {
                'type': 'int',
                },
            'answer_section': {
                'type': 'list',
                'record_domain_name': {
                    'type': 'str',
                    },
                'record_type': {
                    'type': 'str',
                    },
                'record_class': {
                    'type': 'str',
                    },
                'record_ttl': {
                    'type': 'int',
                    },
                'record_data': {
                    'type': 'str',
                    }
                },
            'authoritative_section': {
                'type': 'list',
                'record_domain_name': {
                    'type': 'str',
                    },
                'record_type': {
                    'type': 'str',
                    },
                'record_class': {
                    'type': 'str',
                    },
                'record_ttl': {
                    'type': 'int',
                    },
                'record_data': {
                    'type': 'str',
                    }
                },
            'additional_section': {
                'type': 'list',
                'record_domain_name': {
                    'type': 'str',
                    },
                'record_type': {
                    'type': 'str',
                    },
                'record_class': {
                    'type': 'str',
                    },
                'record_ttl': {
                    'type': 'int',
                    },
                'record_data': {
                    'type': 'str',
                    }
                },
            'all_cached_fqdn': {
                'type': 'bool',
                },
            'cached_fqdn_name': {
                'type': 'str',
                },
            'record_type': {
                'type': 'str',
                },
            'debug_mode': {
                'type': 'bool',
                },
            'name': {
                'type': 'str',
                'required': True,
                },
            'zone_transfer': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'zone_transfer_status_list': {
                        'type': 'list',
                        'zone_name': {
                            'type': 'str',
                            },
                        'sflow_source_id': {
                            'type': 'str',
                            },
                        'last_update': {
                            'type': 'str',
                            },
                        'last_complete_update': {
                            'type': 'str',
                            },
                        'last_complete_serial': {
                            'type': 'str',
                            },
                        'estimated_next_update': {
                            'type': 'str',
                            }
                        },
                    'zone_name': {
                        'type': 'str',
                        },
                    'sflow_source_id': {
                        'type': 'str',
                        },
                    'local_ip': {
                        'type': 'str',
                        },
                    'remote_ip': {
                        'type': 'str',
                        },
                    'estimated_next_update': {
                        'type': 'str',
                        },
                    'zone_transfer_history_list': {
                        'type': 'list',
                        'update_status': {
                            'type': 'str',
                            },
                        'zone_transfer_result': {
                            'type': 'str',
                            },
                        'zone_transfer_begin_time': {
                            'type': 'str',
                            },
                        'zone_transfer_end_time': {
                            'type': 'str',
                            },
                        'tcp_connection_begin_time': {
                            'type': 'str',
                            },
                        'tcp_connection_end_time': {
                            'type': 'str',
                            },
                        'serial_number': {
                            'type': 'str',
                            },
                        'dns_message_processed': {
                            'type': 'int',
                            },
                        'records_processed': {
                            'type': 'int',
                            },
                        'dns_message_pending_processed': {
                            'type': 'int',
                            },
                        'total_failure': {
                            'type': 'str',
                            }
                        },
                    'zone_transfer_statistics': {
                        'type': 'list',
                        'stats_name': {
                            'type': 'str',
                            },
                        'stats_count': {
                            'type': 'int',
                            }
                        },
                    'zts_sflow_source_id': {
                        'type': 'str',
                        },
                    'status': {
                        'type': 'str',
                        'choices': ['ongoing', 'completed', 'scheduled']
                        },
                    'zone': {
                        'type': 'str',
                        },
                    'statistics': {
                        'type': 'bool',
                        },
                    'zt_statistics': {
                        'type': 'bool',
                        },
                    'debug_mode': {
                        'type': 'bool',
                        }
                    }
                }
            },
        'stats': {
            'type': 'dict',
            'total_cached_fqdn': {
                'type': 'str',
                },
            'total_cached_records': {
                'type': 'str',
                },
            'fqdn_a': {
                'type': 'str',
                },
            'fqdn_aaaa': {
                'type': 'str',
                },
            'fqdn_cname': {
                'type': 'str',
                },
            'fqdn_ns': {
                'type': 'str',
                },
            'fqdn_mx': {
                'type': 'str',
                },
            'fqdn_soa': {
                'type': 'str',
                },
            'fqdn_srv': {
                'type': 'str',
                },
            'fqdn_txt': {
                'type': 'str',
                },
            'fqdn_ptr': {
                'type': 'str',
                },
            'fqdn_other': {
                'type': 'str',
                },
            'fqdn_wildcard': {
                'type': 'str',
                },
            'fqdn_delegation': {
                'type': 'str',
                },
            'shard_size': {
                'type': 'str',
                },
            'resp_ext_size': {
                'type': 'str',
                },
            'a_record': {
                'type': 'str',
                },
            'aaaa_record': {
                'type': 'str',
                },
            'cname_record': {
                'type': 'str',
                },
            'ns_record': {
                'type': 'str',
                },
            'mx_record': {
                'type': 'str',
                },
            'soa_record': {
                'type': 'str',
                },
            'srv_record': {
                'type': 'str',
                },
            'txt_record': {
                'type': 'str',
                },
            'ptr_record': {
                'type': 'str',
                },
            'other_record': {
                'type': 'str',
                },
            'fqdn_in_shard_filter': {
                'type': 'str',
                },
            'name': {
                'type': 'str',
                'required': True,
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/dns-cache/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/dns-cache"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["dns-cache"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["dns-cache"].get(k) != v:
            change_results["changed"] = True
            config_changes["dns-cache"][k] = v

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
    payload = utils.build_json("dns-cache", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["dns-cache"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["dns-cache-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["dns-cache"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["dns-cache"]["stats"] if info != "NotFound" else info
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
