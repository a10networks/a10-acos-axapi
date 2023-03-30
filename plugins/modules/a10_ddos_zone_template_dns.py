#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_zone_template_dns
description:
    - DNS template Configuration
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
        - "Field name"
        type: str
        required: True
    dns_any_check:
        description:
        - "Drop DNS queries of Type ANY"
        type: bool
        required: False
    dns_any_check_action_list_name:
        description:
        - "Configure action-list to take"
        type: str
        required: False
    dns_any_check_action:
        description:
        - "'drop'= Drop packets (Default); 'ignore'= Take no action; 'blacklist-src'=
          Blacklist-src; 'reset'= Reset client connection;"
        type: str
        required: False
    multi_pu_threshold_distribution:
        description:
        - "Field multi_pu_threshold_distribution"
        type: dict
        required: False
        suboptions:
            multi_pu_threshold_distribution_value:
                description:
                - "Destination side rate limit only. Default= 0"
                type: int
            multi_pu_threshold_distribution_disable:
                description:
                - "'disable'= Destination side rate limit only. Default= Enable;"
                type: str
    dns_udp_authentication:
        description:
        - "Field dns_udp_authentication"
        type: dict
        required: False
        suboptions:
            force_tcp_cfg:
                description:
                - "Field force_tcp_cfg"
                type: dict
            udp_timeout:
                description:
                - "UDP authentication timeout in seconds"
                type: int
            min_delay:
                description:
                - "Optional minimum delay between DNS retransmits for authentication to pass, unit
          is specified by min-delay-interval"
                type: int
            min_delay_interval:
                description:
                - "'100ms'= 100ms; '1sec'= 1sec;"
                type: str
            dns_udp_auth_pass_action_list_name:
                description:
                - "Configure action-list to take for passing the authentication"
                type: str
            dns_udp_auth_pass_action:
                description:
                - "'authenticate-src'= authenticate-src (Default);"
                type: str
            dns_udp_auth_fail_action_list_name:
                description:
                - "Configure action-list to take for failing the authentication. (Applicable to
          dns-udp retry only)"
                type: str
            dns_udp_auth_fail_action:
                description:
                - "'drop'= Drop packets (Default); 'blacklist-src'= Blacklist-src;"
                type: str
    fqdn_label_len_cfg:
        description:
        - "Field fqdn_label_len_cfg"
        type: list
        required: False
        suboptions:
            label_length:
                description:
                - "Maximum length of FQDN label"
                type: int
            fqdn_label_suffix:
                description:
                - "Number of suffixes"
                type: int
            fqdn_label_length_action_list_name:
                description:
                - "Configure action-list to take"
                type: str
            fqdn_label_length_action:
                description:
                - "'drop'= Drop packets (Default); 'ignore'= Take no action; 'blacklist-src'=
          Blacklist-src; 'reset'= Reset client connection;"
                type: str
    fqdn_label_count_cfg:
        description:
        - "Field fqdn_label_count_cfg"
        type: dict
        required: False
        suboptions:
            label_count:
                description:
                - "Maximum number of FQDN labels per FQDN"
                type: int
            fqdn_label_count_action_list_name:
                description:
                - "Configure action-list to take"
                type: str
            fqdn_label_count_action:
                description:
                - "'drop'= Drop packets (Default); 'ignore'= Take no action; 'blacklist-src'=
          Blacklist-src; 'reset'= Send reset to client;"
                type: str
    src:
        description:
        - "Field src"
        type: dict
        required: False
        suboptions:
            rate_limit:
                description:
                - "Field rate_limit"
                type: dict
    dst:
        description:
        - "Field dst"
        type: dict
        required: False
        suboptions:
            rate_limit:
                description:
                - "Field rate_limit"
                type: dict
    domain_group_name:
        description:
        - "Apply a domain-group to the DNS template"
        type: str
        required: False
    on_no_match:
        description:
        - "'permit'= permit; 'deny'= deny (default);"
        type: str
        required: False
    symtimeout_cfg:
        description:
        - "Field symtimeout_cfg"
        type: dict
        required: False
        suboptions:
            sym_timeout:
                description:
                - "Timeout for DNS Symmetric session"
                type: bool
            sym_timeout_value:
                description:
                - "Session timeout value in seconds"
                type: int
    allow_query_class:
        description:
        - "Field allow_query_class"
        type: dict
        required: False
        suboptions:
            allow_internet_query_class:
                description:
                - "INTERNET query class"
                type: bool
            allow_csnet_query_class:
                description:
                - "CSNET query class"
                type: bool
            allow_chaos_query_class:
                description:
                - "CHAOS query class"
                type: bool
            allow_hesiod_query_class:
                description:
                - "HESIOD query class"
                type: bool
            allow_none_query_class:
                description:
                - "NONE query class"
                type: bool
            allow_any_query_class:
                description:
                - "ANY query class"
                type: bool
            allow_query_class_action_list_name:
                description:
                - "Configure action-list to take when query class doesn't match"
                type: str
            allow_query_class_action:
                description:
                - "'drop'= Drop packets (Default); 'blacklist-src'= Blacklist-src; 'reset'= Reset
          client connection;"
                type: str
    allow_record_type:
        description:
        - "Field allow_record_type"
        type: dict
        required: False
        suboptions:
            allow_a_type:
                description:
                - "Address record"
                type: bool
            allow_aaaa_type:
                description:
                - "IPv6 address record"
                type: bool
            allow_cname_type:
                description:
                - "Canonical name record"
                type: bool
            allow_mx_type:
                description:
                - "Mail exchange record"
                type: bool
            allow_ns_type:
                description:
                - "Name server record"
                type: bool
            allow_srv_type:
                description:
                - "Service locator"
                type: bool
            record_num_cfg:
                description:
                - "Field record_num_cfg"
                type: list
            allow_record_type_action_list_name:
                description:
                - "Configure action-list to take"
                type: str
            allow_record_type_action:
                description:
                - "'drop'= Drop packets (Default); 'blacklist-src'= Blacklist-src; 'reset'= Reset
          client connection;"
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
    malformed_query_check:
        description:
        - "Field malformed_query_check"
        type: dict
        required: False
        suboptions:
            validation_type:
                description:
                - "'basic-header-check'= Basic header validation for DNS TCP/UDP queries;
          'extended-header-check'= Extended header/query validation for DNS TCP/UDP
          queries; 'disable'= Disable Malform query validation for DNS TCP/UDP;"
                type: str
            non_query_opcode_check:
                description:
                - "'disable'= When malform check is enabled, TPS always drops DNS query with non
          query opcode, this option disables this opcode check;"
                type: str
            skip_multi_packet_check:
                description:
                - "Bypass DNS fragmented and TCP segmented Queries(Default= dropped)"
                type: bool
            dns_malformed_query_action_list_name:
                description:
                - "Configure action-list to take"
                type: str
            dns_malformed_query_action:
                description:
                - "'drop'= Drop packets (Default); 'ignore'= Take no action; 'blacklist-src'=
          Blacklist-src; 'reset'= Reset client connection;"
                type: str
            uuid:
                description:
                - "uuid of the object"
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
    "allow_query_class", "allow_record_type", "dns_any_check", "dns_any_check_action", "dns_any_check_action_list_name", "dns_udp_authentication", "domain_group_name", "dst", "fqdn_label_count_cfg", "fqdn_label_len_cfg", "malformed_query_check", "multi_pu_threshold_distribution", "name", "on_no_match", "src", "symtimeout_cfg", "user_tag", "uuid",
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
        'dns_any_check': {
            'type': 'bool',
            },
        'dns_any_check_action_list_name': {
            'type': 'str',
            },
        'dns_any_check_action': {
            'type': 'str',
            'choices': ['drop', 'ignore', 'blacklist-src', 'reset']
            },
        'multi_pu_threshold_distribution': {
            'type': 'dict',
            'multi_pu_threshold_distribution_value': {
                'type': 'int',
                },
            'multi_pu_threshold_distribution_disable': {
                'type': 'str',
                'choices': ['disable']
                }
            },
        'dns_udp_authentication': {
            'type': 'dict',
            'force_tcp_cfg': {
                'type': 'dict',
                'force_tcp': {
                    'type': 'bool',
                    },
                'force_tcp_timeout': {
                    'type': 'int',
                    },
                'force_tcp_min_delay': {
                    'type': 'int',
                    },
                'force_tcp_ignore_client_source_port': {
                    'type': 'bool',
                    }
                },
            'udp_timeout': {
                'type': 'int',
                },
            'min_delay': {
                'type': 'int',
                },
            'min_delay_interval': {
                'type': 'str',
                'choices': ['100ms', '1sec']
                },
            'dns_udp_auth_pass_action_list_name': {
                'type': 'str',
                },
            'dns_udp_auth_pass_action': {
                'type': 'str',
                'choices': ['authenticate-src']
                },
            'dns_udp_auth_fail_action_list_name': {
                'type': 'str',
                },
            'dns_udp_auth_fail_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src']
                }
            },
        'fqdn_label_len_cfg': {
            'type': 'list',
            'label_length': {
                'type': 'int',
                },
            'fqdn_label_suffix': {
                'type': 'int',
                },
            'fqdn_label_length_action_list_name': {
                'type': 'str',
                },
            'fqdn_label_length_action': {
                'type': 'str',
                'choices': ['drop', 'ignore', 'blacklist-src', 'reset']
                }
            },
        'fqdn_label_count_cfg': {
            'type': 'dict',
            'label_count': {
                'type': 'int',
                },
            'fqdn_label_count_action_list_name': {
                'type': 'str',
                },
            'fqdn_label_count_action': {
                'type': 'str',
                'choices': ['drop', 'ignore', 'blacklist-src', 'reset']
                }
            },
        'src': {
            'type': 'dict',
            'rate_limit': {
                'type': 'dict',
                'nxdomain': {
                    'type': 'dict',
                    'dns_nxdomain_rate': {
                        'type': 'int',
                        },
                    'dns_nxdomain_rate_limit_action_list_name': {
                        'type': 'str',
                        },
                    'dns_nxdomain_rate_limit_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore', 'blacklist-src', 'reset']
                        }
                    },
                'request': {
                    'type': 'dict',
                    'ntype': {
                        'type': 'dict',
                        'A_cfg': {
                            'type': 'dict',
                            'A': {
                                'type': 'bool',
                                },
                            'src_dns_a_rate': {
                                'type': 'int',
                                }
                            },
                        'AAAA_cfg': {
                            'type': 'dict',
                            'AAAA': {
                                'type': 'bool',
                                },
                            'src_dns_aaaa_rate': {
                                'type': 'int',
                                }
                            },
                        'CNAME_cfg': {
                            'type': 'dict',
                            'CNAME': {
                                'type': 'bool',
                                },
                            'src_dns_cname_rate': {
                                'type': 'int',
                                }
                            },
                        'MX_cfg': {
                            'type': 'dict',
                            'MX': {
                                'type': 'bool',
                                },
                            'src_dns_mx_rate': {
                                'type': 'int',
                                }
                            },
                        'NS_cfg': {
                            'type': 'dict',
                            'NS': {
                                'type': 'bool',
                                },
                            'src_dns_ns_rate': {
                                'type': 'int',
                                }
                            },
                        'SRV_cfg': {
                            'type': 'dict',
                            'SRV': {
                                'type': 'bool',
                                },
                            'src_dns_srv_rate': {
                                'type': 'int',
                                }
                            },
                        'dns_type_cfg': {
                            'type': 'list',
                            'src_dns_request_type': {
                                'type': 'int',
                                },
                            'src_dns_request_type_rate': {
                                'type': 'int',
                                }
                            }
                        },
                    'src_dns_request_rate_limit_action_list_name': {
                        'type': 'str',
                        },
                    'src_dns_request_rate_limit_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore', 'blacklist-src', 'reset']
                        }
                    }
                }
            },
        'dst': {
            'type': 'dict',
            'rate_limit': {
                'type': 'dict',
                'fqdn': {
                    'type': 'dict',
                    'dns_fqdn_rate_cfg': {
                        'type': 'list',
                        'dns_fqdn_rate': {
                            'type': 'int',
                            },
                        'per': {
                            'type': 'str',
                            'choices': ['domain-name', 'src-ip', 'label-count']
                            },
                        'per_domain_per_src_ip': {
                            'type': 'bool',
                            },
                        'fqdn_rate_suffix': {
                            'type': 'int',
                            },
                        'fqdn_rate_label_count': {
                            'type': 'int',
                            }
                        },
                    'dns_fqdn_rate_limit_action_list_name': {
                        'type': 'str',
                        },
                    'dns_fqdn_rate_limit_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore', 'reset', 'blacklist-src']
                        }
                    },
                'domain_group_rate_exceed_action': {
                    'type': 'str',
                    'choices': ['drop', 'tunnel-encap-packet']
                    },
                'encap_template': {
                    'type': 'str',
                    },
                'domain_group_rate_per_service': {
                    'type': 'bool',
                    },
                'request': {
                    'type': 'dict',
                    'ntype': {
                        'type': 'dict',
                        'A_cfg': {
                            'type': 'dict',
                            'A': {
                                'type': 'bool',
                                },
                            'dns_a_rate': {
                                'type': 'int',
                                }
                            },
                        'AAAA_cfg': {
                            'type': 'dict',
                            'AAAA': {
                                'type': 'bool',
                                },
                            'dns_aaaa_rate': {
                                'type': 'int',
                                }
                            },
                        'CNAME_cfg': {
                            'type': 'dict',
                            'CNAME': {
                                'type': 'bool',
                                },
                            'dns_cname_rate': {
                                'type': 'int',
                                }
                            },
                        'MX_cfg': {
                            'type': 'dict',
                            'MX': {
                                'type': 'bool',
                                },
                            'dns_mx_rate': {
                                'type': 'int',
                                }
                            },
                        'NS_cfg': {
                            'type': 'dict',
                            'NS': {
                                'type': 'bool',
                                },
                            'dns_ns_rate': {
                                'type': 'int',
                                }
                            },
                        'SRV_cfg': {
                            'type': 'dict',
                            'SRV': {
                                'type': 'bool',
                                },
                            'dns_srv_rate': {
                                'type': 'int',
                                }
                            },
                        'dns_type_cfg': {
                            'type': 'list',
                            'dns_request_type': {
                                'type': 'int',
                                },
                            'dns_request_type_rate': {
                                'type': 'int',
                                }
                            }
                        },
                    'dst_dns_request_rate_limit_action_list_name': {
                        'type': 'str',
                        },
                    'dst_dns_request_rate_limit_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore', 'reset', 'blacklist-src']
                        }
                    }
                }
            },
        'domain_group_name': {
            'type': 'str',
            },
        'on_no_match': {
            'type': 'str',
            'choices': ['permit', 'deny']
            },
        'symtimeout_cfg': {
            'type': 'dict',
            'sym_timeout': {
                'type': 'bool',
                },
            'sym_timeout_value': {
                'type': 'int',
                }
            },
        'allow_query_class': {
            'type': 'dict',
            'allow_internet_query_class': {
                'type': 'bool',
                },
            'allow_csnet_query_class': {
                'type': 'bool',
                },
            'allow_chaos_query_class': {
                'type': 'bool',
                },
            'allow_hesiod_query_class': {
                'type': 'bool',
                },
            'allow_none_query_class': {
                'type': 'bool',
                },
            'allow_any_query_class': {
                'type': 'bool',
                },
            'allow_query_class_action_list_name': {
                'type': 'str',
                },
            'allow_query_class_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'reset']
                }
            },
        'allow_record_type': {
            'type': 'dict',
            'allow_a_type': {
                'type': 'bool',
                },
            'allow_aaaa_type': {
                'type': 'bool',
                },
            'allow_cname_type': {
                'type': 'bool',
                },
            'allow_mx_type': {
                'type': 'bool',
                },
            'allow_ns_type': {
                'type': 'bool',
                },
            'allow_srv_type': {
                'type': 'bool',
                },
            'record_num_cfg': {
                'type': 'list',
                'allow_num_type': {
                    'type': 'int',
                    }
                },
            'allow_record_type_action_list_name': {
                'type': 'str',
                },
            'allow_record_type_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'reset']
                }
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'malformed_query_check': {
            'type': 'dict',
            'validation_type': {
                'type': 'str',
                'choices': ['basic-header-check', 'extended-header-check', 'disable']
                },
            'non_query_opcode_check': {
                'type': 'str',
                'choices': ['disable']
                },
            'skip_multi_packet_check': {
                'type': 'bool',
                },
            'dns_malformed_query_action_list_name': {
                'type': 'str',
                },
            'dns_malformed_query_action': {
                'type': 'str',
                'choices': ['drop', 'ignore', 'blacklist-src', 'reset']
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
    url_base = "/axapi/v3/ddos/zone-template/dns/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/zone-template/dns"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["dns"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["dns"].get(k) != v:
            change_results["changed"] = True
            config_changes["dns"][k] = v

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
    payload = utils.build_json("dns", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["dns"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["dns-list"] if info != "NotFound" else info
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
