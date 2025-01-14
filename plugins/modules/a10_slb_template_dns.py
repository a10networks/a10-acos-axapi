#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_dns
description:
    - DNS template
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
        - "DNS Template Name"
        type: str
        required: True
    category_lookup_online_lookup:
        description:
        - "Enable online webroot lookup"
        type: bool
        required: False
    category_lookup_bypass:
        description:
        - "DNS type class-lists for bypassing category lookup"
        type: str
        required: False
    default_policy:
        description:
        - "'nocache'= Cache disable; 'cache'= Cache enable;"
        type: str
        required: False
    cache_record_serving_policy:
        description:
        - "'global'= Follow global cofiguration (Default); 'no-change'= No change in
          record order; 'round-robin'= Round-robin;"
        type: str
        required: False
    dns_cookie_cache_policy:
        description:
        - "'served-by-cache'= Answer from cache for requests with cookie; 'served-by-
          backend'= Answer from server for requests with cookie;"
        type: str
        required: False
    remove_aa_flag:
        description:
        - "Make answers created from cache non-authoritative"
        type: bool
        required: False
    disable_dns_template:
        description:
        - "Disable DNS template"
        type: bool
        required: False
    period:
        description:
        - "Period in minutes"
        type: int
        required: False
    drop:
        description:
        - "Drop the malformed query"
        type: bool
        required: False
    forward:
        description:
        - "Forward to service group (Service group name)"
        type: str
        required: False
    max_query_length:
        description:
        - "Define Maximum DNS Query Length, default is unlimited (Specify Maximum Length)"
        type: int
        required: False
    max_cache_entry_size:
        description:
        - "Define maximum cache entry size (Maximum cache entry size per VIP (default
          1024))"
        type: int
        required: False
    max_cache_size:
        description:
        - "Define maximum cache size (Maximum cache entry per VIP)"
        type: int
        required: False
    enable_cache_sharing:
        description:
        - "Enable DNS cache sharing"
        type: bool
        required: False
    disable_ra_cached_resp:
        description:
        - "Disable DNS recursive available flag in cached response"
        type: bool
        required: False
    remove_padding_to_server:
        description:
        - "Remove EDNS(0) padding to server"
        type: bool
        required: False
    add_padding_to_client:
        description:
        - "'block-length'= Block-Length Padding; 'random-block-length'= Random-Block-
          Length Padding;"
        type: str
        required: False
    remove_csubnet:
        description:
        - "Remove EDNS(0) client subnet from client queries"
        type: bool
        required: False
    insert_ipv4:
        description:
        - "prefix-length to insert for IPv4"
        type: int
        required: False
    insert_ipv6:
        description:
        - "prefix-length to insert for IPv6"
        type: int
        required: False
    redirect_to_tcp_port:
        description:
        - "Direct the client to retry with TCP for DNS UDP request"
        type: bool
        required: False
    query_id_switch:
        description:
        - "Use DNS query ID to create sesion"
        type: bool
        required: False
    dnssec_service_group:
        description:
        - "Use different service group if DNSSEC DO bit set (Service Group Name)"
        type: str
        required: False
    disable_rpz_attach_soa:
        description:
        - "Disable attaching SOA due to RPZ"
        type: bool
        required: False
    cache_ttl_adjustment_enable:
        description:
        - "enable the ttl adjustment for dns cache response"
        type: bool
        required: False
    dns_logging:
        description:
        - "dns logging template (DNS Logging template name)"
        type: str
        required: False
    tld_filter_white_list:
        description:
        - "white-list class-list name (string-insensitive type)"
        type: str
        required: False
    tld_filter_log_enable:
        description:
        - "Enable dns tld filter logging"
        type: bool
        required: False
    qps_log_high:
        description:
        - "high threshold for QPS logging (queries per second)"
        type: int
        required: False
    qps_log_low:
        description:
        - "low threshold for QPS logging (queries per second)"
        type: int
        required: False
    qps_threshold_log:
        description:
        - "enable threshold log for DNS QPS"
        type: bool
        required: False
    cache_hitcount_enable:
        description:
        - "Enable DNS cache entry hit count"
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
    label_length_filter:
        description:
        - "Field label_length_filter"
        type: dict
        required: False
        suboptions:
            drop_log_enable:
                description:
                - "enable the log when hit the rule"
                type: bool
            label_length_filter_action:
                description:
                - "'drop'= drop; 'ignore'= ignore;"
                type: str
            fqdn_label_length:
                description:
                - "Field fqdn_label_length"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
    label_count_filter:
        description:
        - "Field label_count_filter"
        type: dict
        required: False
        suboptions:
            drop_log_enable:
                description:
                - "enable the log when hit the rule"
                type: bool
            label_count_filter_action:
                description:
                - "'drop'= drop; 'ignore'= ignore;"
                type: str
            min_fqdn_label_count:
                description:
                - "Minimum number of FQDN labels per FQDN"
                type: int
            max_fqdn_label_count:
                description:
                - "Maximum number of FQDN labels per FQDN"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    dns64:
        description:
        - "Field dns64"
        type: dict
        required: False
        suboptions:
            enable:
                description:
                - "Enable DNS64"
                type: bool
            cache:
                description:
                - "Use a cached A-query response to provide AAAA query responses for the same
          hostname"
                type: bool
            change_query:
                description:
                - "Always change incoming AAAA DNS Query to A"
                type: bool
            parallel_query:
                description:
                - "Forward AAAA Query & generate A Query in parallel"
                type: bool
            retry:
                description:
                - "Retry count, default is 3 (Retry Number)"
                type: int
            single_response_disable:
                description:
                - "Disable Single Response which is used to avoid ambiguity"
                type: bool
            timeout:
                description:
                - "Timeout to send additional Queries, unit= second, default is 1"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    negative_dns_cache:
        description:
        - "Field negative_dns_cache"
        type: dict
        required: False
        suboptions:
            enable_negative_dns_cache:
                description:
                - "Enable DNS negative cache (Need to turn-on the dns-cache for this feature)"
                type: bool
            bypass_query_threshold:
                description:
                - "the threshold bypass the query, default is 100"
                type: int
            max_negative_cache_ttl:
                description:
                - "Max negative cache ttl, default is 2 hours"
                type: int
            cache_non_valid:
                description:
                - "Enable caching non-valid negative response, otherwise will only cache valid
          negative response"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    udp_retransmit:
        description:
        - "Field udp_retransmit"
        type: dict
        required: False
        suboptions:
            retry_interval:
                description:
                - "DNS Retry Interval value 1 - 400 in units of 100ms, default is 10 (default is
          1000ms) (1 - 400 in units of 100ms, default is 10 (1000ms/1sec))"
                type: int
            max_trials:
                description:
                - "Total number of times to try DNS query to server before closing client
          connection, default 3"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    query_type_filter:
        description:
        - "Field query_type_filter"
        type: dict
        required: False
        suboptions:
            query_type_action:
                description:
                - "'allow'= Allow only certain DNS query types; 'deny'= Deny only certain DNS
          query types;"
                type: str
            query_type:
                description:
                - "Field query_type"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
    query_class_filter:
        description:
        - "Field query_class_filter"
        type: dict
        required: False
        suboptions:
            query_class_action:
                description:
                - "'allow'= Allow only certain DNS query classes; 'deny'= Deny only certain DNS
          query classes;"
                type: str
            query_class:
                description:
                - "Field query_class"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
    rpz_list:
        description:
        - "Field rpz_list"
        type: list
        required: False
        suboptions:
            seq_id:
                description:
                - "sequential id of RPZ"
                type: int
            name:
                description:
                - "Specify a Response Policy Zone name"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            logging:
                description:
                - "Field logging"
                type: dict
    class_list:
        description:
        - "Field class_list"
        type: dict
        required: False
        suboptions:
            name:
                description:
                - "Specify a class list name"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            lid_list:
                description:
                - "Field lid_list"
                type: list
    response_rate_limiting:
        description:
        - "Field response_rate_limiting"
        type: dict
        required: False
        suboptions:
            response_rate:
                description:
                - "Responses exceeding this rate within the window will be dropped (default 5 per
          second)"
                type: int
            nx_response_rate:
                description:
                - "Queries from entries whose NX Responses exceeding this rate within the window
          will be dropped (default 5 per second)"
                type: int
            filter_response_rate:
                description:
                - "Maximum allowed request rate for the filter. This should match average traffic.
          (default 10 per seconds)"
                type: int
            slip_rate:
                description:
                - "Every n'th response that would be rate-limited will be let through instead"
                type: int
            TC_rate:
                description:
                - "Every n'th response that would be rate-limited will respond with TC bit"
                type: int
            match_subnet:
                description:
                - "IP subnet mask (response rate by IP subnet mask)"
                type: str
            match_subnet_v6:
                description:
                - "IPV6 subnet mask (response rate by IPv6 subnet mask)"
                type: int
            window:
                description:
                - "Rate-Limiting Interval in Seconds (default is one)"
                type: int
            src_ip_only:
                description:
                - "Field src_ip_only"
                type: bool
            enable_log:
                description:
                - "Enable logging"
                type: bool
            action:
                description:
                - "'log-only'= Only log rate-limiting, do not actually rate limit. Requires
          enable-log configuration; 'rate-limit'= Rate-Limit based on configuration
          (Default); 'whitelist'= Whitelist, disable rate-limiting;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            rrl_class_list_list:
                description:
                - "Field rrl_class_list_list"
                type: list
    local_dns_resolution:
        description:
        - "Field local_dns_resolution"
        type: dict
        required: False
        suboptions:
            host_list_cfg:
                description:
                - "Field host_list_cfg"
                type: list
            local_resolver_cfg:
                description:
                - "Field local_resolver_cfg"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
    recursive_dns_resolution:
        description:
        - "Field recursive_dns_resolution"
        type: dict
        required: False
        suboptions:
            host_list_cfg:
                description:
                - "Field host_list_cfg"
                type: list
            csubnet_retry:
                description:
                - "retry when server REFUSED AX inserted EDNS(0) subnet, works only when insert-
          client-subnet is configured"
                type: bool
            ns_cache_lookup:
                description:
                - "'disabled'= Disable NS Cache Lookup; 'enabled'= Enable NS Cache Lookup;"
                type: str
            ns_longest_match:
                description:
                - "'disabled'= Look up NS of top level label, do a nearly-full resolution;
          'enabled'= Enable NS cache longest match;"
                type: str
            use_service_group_response:
                description:
                - "'disabled'= Start Recursive Resolver if Server response doesnt have final
          answer; 'enabled'= Forward Backend Server response to client and dont start
          recursive resolver;"
                type: str
            ipv4_nat_pool:
                description:
                - "IPv4 Source NAT pool or pool group"
                type: str
            ipv6_nat_pool:
                description:
                - "IPv6 Source NAT pool or pool group"
                type: str
            retries_per_level:
                description:
                - "Number of DNS query retries at each server level before closing client
          connection, default 6"
                type: int
            parallel_queries:
                description:
                - "Number of parallel queries to send to servers"
                type: int
            full_response:
                description:
                - "Serve all records (authority and additional) when applicable"
                type: bool
            max_trials:
                description:
                - "Total number of times to try DNS query to server before closing client
          connection, default 255"
                type: int
            request_for_pending_resolution:
                description:
                - "'drop'= Drop of the request during ongoing; 'respond-with-servfail'= Respond
          with SERVFAIL of the request during ongoing; 'start-new-resolution'= Start new
          resolution of the request during ongoing;"
                type: str
            udp_retry_interval:
                description:
                - "UDP DNS Retry Interval value 1-6, default is 1 sec (1-6 , default is 1 sec)"
                type: int
            udp_initial_interval:
                description:
                - "UDP DNS Retry Interval value 1-6, default is 5 sec (1-6, default is 5sec)"
                type: int
            use_client_qid:
                description:
                - "Use client side query id for recursive query"
                type: bool
            default_recursive:
                description:
                - "Default recursive mode, forward query to bound service-group if hostnames
          matched"
                type: bool
            force_cname_resolution:
                description:
                - "'enabled'= Force CNAME resolution always; 'disabled'= Use answer record in
          CNAME response if it exists, else resolve;"
                type: str
            fast_ns_selection:
                description:
                - "'enabled'= Enable fast NS selection; 'disabled'= Disable fast NS selection;"
                type: str
            dnssec_validation:
                description:
                - "'enabled'= Enable DNSSEC validation; 'disabled'= Disable DNSSEC validation;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            lookup_order:
                description:
                - "Field lookup_order"
                type: dict
            gateway_health_check:
                description:
                - "Field gateway_health_check"
                type: dict
    category_lookup_list:
        description:
        - "Field category_lookup_list"
        type: list
        required: False
        suboptions:
            category_name:
                description:
                - "category-list name"
                type: str
            permit:
                description:
                - "Permit matching DNS domains"
                type: bool
            drop:
                description:
                - "Deny matching DNS domains"
                type: bool
            respond:
                description:
                - "Respond to matching DNS domains"
                type: bool
            respond_nxdomain:
                description:
                - "Respond with NXDOMAIN"
                type: bool
            respond_ip_addr:
                description:
                - "Type A record to respond (IPv4 address)"
                type: str
            respond_ipv6_addr:
                description:
                - "TYPE AAAA record to respond (IPv6 address)"
                type: str
            respond_cname_str:
                description:
                - "CNAME to respond (Canonical name)"
                type: str
            response_ttl:
                description:
                - "Set response TTL in seconds (TTL value in seconds)"
                type: int
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
    "add_padding_to_client", "cache_hitcount_enable", "cache_record_serving_policy", "cache_ttl_adjustment_enable", "category_lookup_bypass", "category_lookup_list", "category_lookup_online_lookup", "class_list", "default_policy", "disable_dns_template", "disable_ra_cached_resp", "disable_rpz_attach_soa", "dns_cookie_cache_policy", "dns_logging",
    "dns64", "dnssec_service_group", "drop", "enable_cache_sharing", "forward", "insert_ipv4", "insert_ipv6", "label_count_filter", "label_length_filter", "local_dns_resolution", "max_cache_entry_size", "max_cache_size", "max_query_length", "name", "negative_dns_cache", "period", "qps_log_high", "qps_log_low", "qps_threshold_log",
    "query_class_filter", "query_id_switch", "query_type_filter", "recursive_dns_resolution", "redirect_to_tcp_port", "remove_aa_flag", "remove_csubnet", "remove_padding_to_server", "response_rate_limiting", "rpz_list", "tld_filter_log_enable", "tld_filter_white_list", "udp_retransmit", "user_tag", "uuid",
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
        'category_lookup_online_lookup': {
            'type': 'bool',
            },
        'category_lookup_bypass': {
            'type': 'str',
            },
        'default_policy': {
            'type': 'str',
            'choices': ['nocache', 'cache']
            },
        'cache_record_serving_policy': {
            'type': 'str',
            'choices': ['global', 'no-change', 'round-robin']
            },
        'dns_cookie_cache_policy': {
            'type': 'str',
            'choices': ['served-by-cache', 'served-by-backend']
            },
        'remove_aa_flag': {
            'type': 'bool',
            },
        'disable_dns_template': {
            'type': 'bool',
            },
        'period': {
            'type': 'int',
            },
        'drop': {
            'type': 'bool',
            },
        'forward': {
            'type': 'str',
            },
        'max_query_length': {
            'type': 'int',
            },
        'max_cache_entry_size': {
            'type': 'int',
            },
        'max_cache_size': {
            'type': 'int',
            },
        'enable_cache_sharing': {
            'type': 'bool',
            },
        'disable_ra_cached_resp': {
            'type': 'bool',
            },
        'remove_padding_to_server': {
            'type': 'bool',
            },
        'add_padding_to_client': {
            'type': 'str',
            'choices': ['block-length', 'random-block-length']
            },
        'remove_csubnet': {
            'type': 'bool',
            },
        'insert_ipv4': {
            'type': 'int',
            },
        'insert_ipv6': {
            'type': 'int',
            },
        'redirect_to_tcp_port': {
            'type': 'bool',
            },
        'query_id_switch': {
            'type': 'bool',
            },
        'dnssec_service_group': {
            'type': 'str',
            },
        'disable_rpz_attach_soa': {
            'type': 'bool',
            },
        'cache_ttl_adjustment_enable': {
            'type': 'bool',
            },
        'dns_logging': {
            'type': 'str',
            },
        'tld_filter_white_list': {
            'type': 'str',
            },
        'tld_filter_log_enable': {
            'type': 'bool',
            },
        'qps_log_high': {
            'type': 'int',
            },
        'qps_log_low': {
            'type': 'int',
            },
        'qps_threshold_log': {
            'type': 'bool',
            },
        'cache_hitcount_enable': {
            'type': 'bool',
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'label_length_filter': {
            'type': 'dict',
            'drop_log_enable': {
                'type': 'bool',
                },
            'label_length_filter_action': {
                'type': 'str',
                'choices': ['drop', 'ignore']
                },
            'fqdn_label_length': {
                'type': 'list',
                'length': {
                    'type': 'int',
                    },
                'suffix': {
                    'type': 'int',
                    }
                },
            'uuid': {
                'type': 'str',
                }
            },
        'label_count_filter': {
            'type': 'dict',
            'drop_log_enable': {
                'type': 'bool',
                },
            'label_count_filter_action': {
                'type': 'str',
                'choices': ['drop', 'ignore']
                },
            'min_fqdn_label_count': {
                'type': 'int',
                },
            'max_fqdn_label_count': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'dns64': {
            'type': 'dict',
            'enable': {
                'type': 'bool',
                },
            'cache': {
                'type': 'bool',
                },
            'change_query': {
                'type': 'bool',
                },
            'parallel_query': {
                'type': 'bool',
                },
            'retry': {
                'type': 'int',
                },
            'single_response_disable': {
                'type': 'bool',
                },
            'timeout': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'negative_dns_cache': {
            'type': 'dict',
            'enable_negative_dns_cache': {
                'type': 'bool',
                },
            'bypass_query_threshold': {
                'type': 'int',
                },
            'max_negative_cache_ttl': {
                'type': 'int',
                },
            'cache_non_valid': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'udp_retransmit': {
            'type': 'dict',
            'retry_interval': {
                'type': 'int',
                },
            'max_trials': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'query_type_filter': {
            'type': 'dict',
            'query_type_action': {
                'type': 'str',
                'choices': ['allow', 'deny']
                },
            'query_type': {
                'type': 'list',
                'str_query_type': {
                    'type': 'str',
                    'choices': ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SRV', 'PTR', 'SOA', 'TXT', 'ANY']
                    },
                'num_query_type': {
                    'type': 'int',
                    }
                },
            'uuid': {
                'type': 'str',
                }
            },
        'query_class_filter': {
            'type': 'dict',
            'query_class_action': {
                'type': 'str',
                'choices': ['allow', 'deny']
                },
            'query_class': {
                'type': 'list',
                'str_query_class': {
                    'type': 'str',
                    'choices': ['INTERNET', 'CHAOS', 'HESIOD', 'NONE', 'ANY']
                    },
                'num_query_class': {
                    'type': 'int',
                    }
                },
            'uuid': {
                'type': 'str',
                }
            },
        'rpz_list': {
            'type': 'list',
            'seq_id': {
                'type': 'int',
                'required': True,
                },
            'name': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'logging': {
                'type': 'dict',
                'enable': {
                    'type': 'bool',
                    },
                'rpz_action': {
                    'type': 'list',
                    'str_rpz_action': {
                        'type': 'str',
                        'choices': ['drop', 'pass-thru', 'nxdomain', 'nodata', 'tcp-only', 'local-data']
                        }
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'class_list': {
            'type': 'dict',
            'name': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'lid_list': {
                'type': 'list',
                'lidnum': {
                    'type': 'int',
                    'required': True,
                    },
                'conn_rate_limit': {
                    'type': 'int',
                    },
                'per': {
                    'type': 'int',
                    },
                'over_limit_action': {
                    'type': 'bool',
                    },
                'action_value': {
                    'type': 'str',
                    'choices': ['dns-cache-disable', 'dns-cache-enable', 'forward']
                    },
                'lockout': {
                    'type': 'int',
                    },
                'log': {
                    'type': 'bool',
                    },
                'log_interval': {
                    'type': 'int',
                    },
                'dns': {
                    'type': 'dict',
                    'cache_action': {
                        'type': 'str',
                        'choices': ['cache-disable', 'cache-enable']
                        },
                    'ttl': {
                        'type': 'int',
                        },
                    'weight': {
                        'type': 'int',
                        },
                    'honor_server_response_ttl': {
                        'type': 'bool',
                        }
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    }
                }
            },
        'response_rate_limiting': {
            'type': 'dict',
            'response_rate': {
                'type': 'int',
                },
            'nx_response_rate': {
                'type': 'int',
                },
            'filter_response_rate': {
                'type': 'int',
                },
            'slip_rate': {
                'type': 'int',
                },
            'TC_rate': {
                'type': 'int',
                },
            'match_subnet': {
                'type': 'str',
                },
            'match_subnet_v6': {
                'type': 'int',
                },
            'window': {
                'type': 'int',
                },
            'src_ip_only': {
                'type': 'bool',
                },
            'enable_log': {
                'type': 'bool',
                },
            'action': {
                'type': 'str',
                'choices': ['log-only', 'rate-limit', 'whitelist']
                },
            'uuid': {
                'type': 'str',
                },
            'rrl_class_list_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'lid_list': {
                    'type': 'list',
                    'lidnum': {
                        'type': 'int',
                        'required': True,
                        },
                    'lid_response_rate': {
                        'type': 'int',
                        },
                    'lid_slip_rate': {
                        'type': 'int',
                        },
                    'lid_nx_response_rate': {
                        'type': 'int',
                        },
                    'lid_tc_rate': {
                        'type': 'int',
                        },
                    'lid_match_subnet': {
                        'type': 'str',
                        },
                    'lid_match_subnet_v6': {
                        'type': 'int',
                        },
                    'lid_window': {
                        'type': 'int',
                        },
                    'lid_src_ip_only': {
                        'type': 'bool',
                        },
                    'lid_enable_log': {
                        'type': 'bool',
                        },
                    'lid_action': {
                        'type': 'str',
                        'choices': ['log-only', 'rate-limit', 'whitelist']
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        }
                    }
                }
            },
        'local_dns_resolution': {
            'type': 'dict',
            'host_list_cfg': {
                'type': 'list',
                'hostnames': {
                    'type': 'str',
                    }
                },
            'local_resolver_cfg': {
                'type': 'list',
                'local_resolver': {
                    'type': 'str',
                    }
                },
            'uuid': {
                'type': 'str',
                }
            },
        'recursive_dns_resolution': {
            'type': 'dict',
            'host_list_cfg': {
                'type': 'list',
                'hostnames': {
                    'type': 'str',
                    }
                },
            'csubnet_retry': {
                'type': 'bool',
                },
            'ns_cache_lookup': {
                'type': 'str',
                'choices': ['disabled', 'enabled']
                },
            'ns_longest_match': {
                'type': 'str',
                'choices': ['disabled', 'enabled']
                },
            'use_service_group_response': {
                'type': 'str',
                'choices': ['disabled', 'enabled']
                },
            'ipv4_nat_pool': {
                'type': 'str',
                },
            'ipv6_nat_pool': {
                'type': 'str',
                },
            'retries_per_level': {
                'type': 'int',
                },
            'parallel_queries': {
                'type': 'int',
                },
            'full_response': {
                'type': 'bool',
                },
            'max_trials': {
                'type': 'int',
                },
            'request_for_pending_resolution': {
                'type': 'str',
                'choices': ['drop', 'respond-with-servfail', 'start-new-resolution']
                },
            'udp_retry_interval': {
                'type': 'int',
                },
            'udp_initial_interval': {
                'type': 'int',
                },
            'use_client_qid': {
                'type': 'bool',
                },
            'default_recursive': {
                'type': 'bool',
                },
            'force_cname_resolution': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'fast_ns_selection': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'dnssec_validation': {
                'type': 'str',
                'choices': ['enabled', 'disabled']
                },
            'uuid': {
                'type': 'str',
                },
            'lookup_order': {
                'type': 'dict',
                'query_type': {
                    'type': 'list',
                    'str_query_type': {
                        'type': 'str',
                        'choices': ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SRV', 'PTR', 'SOA', 'TXT', 'ANY']
                        },
                    'num_query_type': {
                        'type': 'int',
                        },
                    'order': {
                        'type': 'str',
                        'choices': ['ipv4-precede-ipv6', 'ipv6-precede-ipv4']
                        }
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'gateway_health_check': {
                'type': 'dict',
                'query_name': {
                    'type': 'str',
                    },
                'retry': {
                    'type': 'int',
                    },
                'timeout': {
                    'type': 'int',
                    },
                'interval': {
                    'type': 'int',
                    },
                'up_retry': {
                    'type': 'int',
                    },
                'retry_multi': {
                    'type': 'int',
                    },
                'gwhc_ns_cache_lookup': {
                    'type': 'str',
                    'choices': ['disabled', 'enabled']
                    },
                'str_query_type': {
                    'type': 'str',
                    'choices': ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SRV', 'PTR', 'SOA', 'TXT']
                    },
                'num_query_type': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'category_lookup_list': {
            'type': 'list',
            'category_name': {
                'type': 'str',
                'required': True,
                },
            'permit': {
                'type': 'bool',
                },
            'drop': {
                'type': 'bool',
                },
            'respond': {
                'type': 'bool',
                },
            'respond_nxdomain': {
                'type': 'bool',
                },
            'respond_ip_addr': {
                'type': 'str',
                },
            'respond_ipv6_addr': {
                'type': 'str',
                },
            'respond_cname_str': {
                'type': 'str',
                },
            'response_ttl': {
                'type': 'int',
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
    url_base = "/axapi/v3/slb/template/dns/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/dns"

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
