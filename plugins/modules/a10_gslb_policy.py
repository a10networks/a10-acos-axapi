#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_gslb_policy
description:
    - Policy for GSLB zone, service or geo-location
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
        - "Specify policy name"
        type: str
        required: True
    health_check:
        description:
        - "Select Service-IP by health status"
        type: bool
        required: False
    health_check_preference_enable:
        description:
        - "Check health preference"
        type: bool
        required: False
    health_preference_top:
        description:
        - "Only keep top n"
        type: int
        required: False
    amount_first:
        description:
        - "Select record based on the amount of available service-ip"
        type: bool
        required: False
    weighted_ip_enable:
        description:
        - "Enable Select Service-IP by weighted preference"
        type: bool
        required: False
    weighted_ip_total_hits:
        description:
        - "Weighted by total hits"
        type: bool
        required: False
    weighted_site_enable:
        description:
        - "Enable Select Service-IP by weighted site preference"
        type: bool
        required: False
    weighted_site_total_hits:
        description:
        - "Weighted by total hits"
        type: bool
        required: False
    weighted_alias:
        description:
        - "Select alias name by weighted preference"
        type: bool
        required: False
    active_servers_enable:
        description:
        - "Enable Select Service-IP with the highest number of active servers"
        type: bool
        required: False
    active_servers_fail_break:
        description:
        - "Break when no active server"
        type: bool
        required: False
    bw_cost_enable:
        description:
        - "Enable bw cost"
        type: bool
        required: False
    bw_cost_fail_break:
        description:
        - "Break when exceed limit"
        type: bool
        required: False
    geographic:
        description:
        - "Select Service-IP by geographic"
        type: bool
        required: False
    num_session_enable:
        description:
        - "Enable Select Service-IP for device having maximum number of available sessions"
        type: bool
        required: False
    num_session_tolerance:
        description:
        - "The difference between the available sessions, default is 10 (Tolerance)"
        type: int
        required: False
    admin_preference:
        description:
        - "Select Service-IP for the device having maximum admin preference"
        type: bool
        required: False
    alias_admin_preference:
        description:
        - "Select alias name having maximum admin preference"
        type: bool
        required: False
    least_response:
        description:
        - "Least response selection"
        type: bool
        required: False
    admin_ip_enable:
        description:
        - "Enable admin ip"
        type: bool
        required: False
    admin_ip_top_only:
        description:
        - "Return highest priority server only"
        type: bool
        required: False
    ordered_ip_top_only:
        description:
        - "Return highest priority server only"
        type: bool
        required: False
    round_robin:
        description:
        - "Round robin selection, enabled by default"
        type: bool
        required: False
    metric_force_check:
        description:
        - "Always check Service-IP for all enabled metrics"
        type: bool
        required: False
    metric_fail_break:
        description:
        - "Break if no valid Service-IP"
        type: bool
        required: False
    ip_list:
        description:
        - "Specify IP List (IP List Name)"
        type: str
        required: False
    metric_order:
        description:
        - "Specify order of metric"
        type: bool
        required: False
    metric_type:
        description:
        - "Field metric_type"
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
    capacity:
        description:
        - "Field capacity"
        type: dict
        required: False
        suboptions:
            capacity_enable:
                description:
                - "Enable capacity"
                type: bool
            threshold:
                description:
                - "Specify capacity threshold, default is 90"
                type: int
            capacity_fail_break:
                description:
                - "Break when exceed threshold"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    connection_load:
        description:
        - "Field connection_load"
        type: dict
        required: False
        suboptions:
            connection_load_enable:
                description:
                - "Enable connection-load"
                type: bool
            connection_load_fail_break:
                description:
                - "Break when exceed limit"
                type: bool
            connection_load_samples:
                description:
                - "Specify samples for connection-load (Number of samples used to calculate the
          connection load, default is 5)"
                type: int
            connection_load_interval:
                description:
                - "Interval between two samples, Unit= second (Interval value,default is 5)"
                type: int
            limit:
                description:
                - "Limit of maxinum connection load, default is unlimited"
                type: bool
            connection_load_limit:
                description:
                - "The value of the connection-load limit, default is unlimited"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    connection_count_by_site:
        description:
        - "Field connection_count_by_site"
        type: dict
        required: False
        suboptions:
            connection_count_enable:
                description:
                - "Enable connection-count-by-site"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    dns:
        description:
        - "Field dns"
        type: dict
        required: False
        suboptions:
            action:
                description:
                - "Apply DNS action for service"
                type: bool
            active_only:
                description:
                - "Only keep active servers"
                type: bool
            active_only_fail_safe:
                description:
                - "Continue if no candidate"
                type: bool
            dns_addition_mx:
                description:
                - "Append MX Records in Addition Section"
                type: bool
            dns_auto_map:
                description:
                - "Automatically build DNS Infrastructure"
                type: bool
            backup_alias:
                description:
                - "Return alias name when fail"
                type: bool
            backup_server:
                description:
                - "Return fallback server when fail"
                type: bool
            external_ip:
                description:
                - "Return DNS response with external IP address"
                type: bool
            external_soa:
                description:
                - "Return DNS response with external SOA Record"
                type: bool
            cname_detect:
                description:
                - "Apply GSLB for DNS Server response when service is Canonical Name (CNAME)"
                type: bool
            ip_replace:
                description:
                - "Replace DNS Server Response with GSLB Service-IPs"
                type: bool
            geoloc_alias:
                description:
                - "Return alias name by geo-location"
                type: bool
            geoloc_action:
                description:
                - "Apply DNS action by geo-location"
                type: bool
            geoloc_policy:
                description:
                - "Apply different policy by geo-location"
                type: bool
            selected_only:
                description:
                - "Only keep selected servers"
                type: bool
            selected_only_value:
                description:
                - "Answer Number"
                type: int
            cache:
                description:
                - "Cache DNS Server response"
                type: bool
            aging_time:
                description:
                - "Specify aging-time, default is TTL in DNS record, unit= second (Aging time,
          default 0 means using TTL in DNS record as aging time)"
                type: int
            delegation:
                description:
                - "Zone Delegation"
                type: bool
            hint:
                description:
                - "'none'= None; 'answer'= Append Hint Records in DNS Answer Section; 'addition'=
          Append Hint Records in DNS Addition Section;"
                type: str
            logging:
                description:
                - "'none'= None; 'query'= DNS Query; 'response'= DNS Response; 'both'= Both DNS
          Query and Response;"
                type: str
            template:
                description:
                - "Logging template (Logging Template Name)"
                type: str
            ttl:
                description:
                - "Specify the TTL value contained in DNS record (TTL value, unit= second, default
          is 10)"
                type: int
            use_server_ttl:
                description:
                - "Use DNS Server Response TTL value in GSLB Proxy mode"
                type: bool
            server:
                description:
                - "Run GSLB as DNS server mode"
                type: bool
            server_srv:
                description:
                - "Provide SRV Records"
                type: bool
            server_mx:
                description:
                - "Provide MX Records"
                type: bool
            server_naptr:
                description:
                - "Provide NAPTR Records"
                type: bool
            server_addition_mx:
                description:
                - "Append MX Records in Addition Section"
                type: bool
            server_ns:
                description:
                - "Provide NS Records"
                type: bool
            server_auto_ns:
                description:
                - "Provide A-Records for NS-Records automatically"
                type: bool
            server_ptr:
                description:
                - "Provide PTR Records"
                type: bool
            server_auto_ptr:
                description:
                - "Provide PTR Records automatically"
                type: bool
            server_txt:
                description:
                - "Provide TXT Records"
                type: bool
            server_custom:
                description:
                - "Provide Custom Records"
                type: bool
            server_any:
                description:
                - "Provide All Records"
                type: bool
            server_any_with_metric:
                description:
                - "Provide All Records with GSLB Metrics applied to A/AAAA Records"
                type: bool
            server_authoritative:
                description:
                - "As authoritative server"
                type: bool
            server_sec:
                description:
                - "Provide DNSSEC support"
                type: bool
            server_ns_list:
                description:
                - "Append All NS Records in Authoritative Section"
                type: bool
            server_full_list:
                description:
                - "Append All A Records in Authoritative Section"
                type: bool
            server_mode_only:
                description:
                - "Only run GSLB as DNS server mode"
                type: bool
            zone_owner_mode:
                description:
                - "Only run GSLB as DNS server mode with zone ownership"
                type: bool
            server_cname:
                description:
                - "Provide CNAME Records"
                type: bool
            server_caa:
                description:
                - "Provide CAA Records"
                type: bool
            ipv6:
                description:
                - "Field ipv6"
                type: list
            block_action:
                description:
                - "Specify Action"
                type: bool
            action_type:
                description:
                - "'drop'= Drop query; 'reject'= Send refuse response; 'ignore'= Send empty
          response;"
                type: str
            proxy_block_port_range_list:
                description:
                - "Field proxy_block_port_range_list"
                type: list
            block_value:
                description:
                - "Field block_value"
                type: list
            block_type:
                description:
                - "Field block_type"
                type: str
            sticky:
                description:
                - "Make DNS Record sticky for certain time"
                type: bool
            sticky_mask:
                description:
                - "Specify IP mask, default is /32"
                type: str
            sticky_ipv6_mask:
                description:
                - "Specify IPv6 mask length, default is 128"
                type: int
            sticky_aging_time:
                description:
                - "Specify aging-time, unit= min, default is 5 (Aging time)"
                type: int
            dynamic_preference:
                description:
                - "Make dynamically change the preference"
                type: bool
            dynamic_weight:
                description:
                - "dynamically change the weight"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            sticky_options:
                description:
                - "Field sticky_options"
                type: dict
    geo_location_list:
        description:
        - "Field geo_location_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Specify geo-location name, section range is (1-15)"
                type: str
            ip_multiple_fields:
                description:
                - "Field ip_multiple_fields"
                type: list
            ipv6_multiple_fields:
                description:
                - "Field ipv6_multiple_fields"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    geo_location_match:
        description:
        - "Field geo_location_match"
        type: dict
        required: False
        suboptions:
            overlap:
                description:
                - "Enable overlap mode to do longest match"
                type: bool
            geo_type_overlap:
                description:
                - "'global'= Global Geo-location; 'policy'= Policy Geo-location;"
                type: str
            match_first:
                description:
                - "'global'= Global Geo-location; 'policy'= Policy Geo-location;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    active_rdt:
        description:
        - "Field active_rdt"
        type: dict
        required: False
        suboptions:
            enable:
                description:
                - "Enable the active rdt"
                type: bool
            single_shot:
                description:
                - "Single Shot RDT"
                type: bool
            prefer_dns_sticky:
                description:
                - "Use dns sticky if available"
                type: bool
            sticky_difference:
                description:
                - "The difference between the round-delay-time of sticky entry"
                type: int
            timeout:
                description:
                - "Specify timeout if round-delay-time samples are not ready (Specify timeout,
          unit=sec,default is 3)"
                type: int
            skip:
                description:
                - "Skip query if round-delay-time samples are not ready (Specify maximum skip
          count,default is 3)"
                type: int
            keep_tracking:
                description:
                - "Keep tracking client even round-delay-time samples are ready"
                type: bool
            ignore_id:
                description:
                - "Ignore IP Address specified in IP List by ID"
                type: int
            samples:
                description:
                - "Specify samples number for round-delay-time (Number of samples,default is 5)"
                type: int
            tolerance:
                description:
                - "The difference percentage between the round-delay-time, default is 10
          (Tolerance)"
                type: int
            difference:
                description:
                - "The difference between the round-delay-time, default is 0"
                type: int
            limit:
                description:
                - "Limit of allowed RDT, default is 16383 (Limit, unit= millisecond)"
                type: int
            fail_break:
                description:
                - "Break when no valid RDT"
                type: bool
            controller:
                description:
                - "Active round-delay-time by controller"
                type: bool
            proto_rdt_enable:
                description:
                - "Enable the round-delay-time to the controller"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    auto_map:
        description:
        - "Field auto_map"
        type: dict
        required: False
        suboptions:
            ttl:
                description:
                - "Specify Auto Map TTL (TTL, default is 300)"
                type: int
            module_disable:
                description:
                - "Specify Disable Auto Map Module"
                type: bool
            all:
                description:
                - "All modules"
                type: bool
            module_type:
                description:
                - "Field module_type"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    edns:
        description:
        - "Field edns"
        type: dict
        required: False
        suboptions:
            client_subnet_geographic:
                description:
                - "Use client subnet for geo-location"
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
            metric_list:
                description:
                - "Field metric_list"
                type: list
            name:
                description:
                - "Specify policy name"
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
    "active_rdt", "active_servers_enable", "active_servers_fail_break", "admin_ip_enable", "admin_ip_top_only", "admin_preference", "alias_admin_preference", "amount_first", "auto_map", "bw_cost_enable", "bw_cost_fail_break", "capacity", "connection_count_by_site", "connection_load", "dns", "edns", "geo_location_list", "geo_location_match",
    "geographic", "health_check", "health_check_preference_enable", "health_preference_top", "ip_list", "least_response", "metric_fail_break", "metric_force_check", "metric_order", "metric_type", "name", "num_session_enable", "num_session_tolerance", "oper", "ordered_ip_top_only", "round_robin", "user_tag", "uuid", "weighted_alias",
    "weighted_ip_enable", "weighted_ip_total_hits", "weighted_site_enable", "weighted_site_total_hits",
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
        'health_check': {
            'type': 'bool',
            },
        'health_check_preference_enable': {
            'type': 'bool',
            },
        'health_preference_top': {
            'type': 'int',
            },
        'amount_first': {
            'type': 'bool',
            },
        'weighted_ip_enable': {
            'type': 'bool',
            },
        'weighted_ip_total_hits': {
            'type': 'bool',
            },
        'weighted_site_enable': {
            'type': 'bool',
            },
        'weighted_site_total_hits': {
            'type': 'bool',
            },
        'weighted_alias': {
            'type': 'bool',
            },
        'active_servers_enable': {
            'type': 'bool',
            },
        'active_servers_fail_break': {
            'type': 'bool',
            },
        'bw_cost_enable': {
            'type': 'bool',
            },
        'bw_cost_fail_break': {
            'type': 'bool',
            },
        'geographic': {
            'type': 'bool',
            },
        'num_session_enable': {
            'type': 'bool',
            },
        'num_session_tolerance': {
            'type': 'int',
            },
        'admin_preference': {
            'type': 'bool',
            },
        'alias_admin_preference': {
            'type': 'bool',
            },
        'least_response': {
            'type': 'bool',
            },
        'admin_ip_enable': {
            'type': 'bool',
            },
        'admin_ip_top_only': {
            'type': 'bool',
            },
        'ordered_ip_top_only': {
            'type': 'bool',
            },
        'round_robin': {
            'type': 'bool',
            },
        'metric_force_check': {
            'type': 'bool',
            },
        'metric_fail_break': {
            'type': 'bool',
            },
        'ip_list': {
            'type': 'str',
            },
        'metric_order': {
            'type': 'bool',
            },
        'metric_type': {
            'type': 'str',
            'choices': ['health-check', 'weighted-ip', 'weighted-site', 'capacity', 'active-servers', 'active-rdt', 'geographic', 'connection-load', 'connection-count-by-site', 'num-session', 'admin-preference', 'bw-cost', 'least-response', 'admin-ip']
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'capacity': {
            'type': 'dict',
            'capacity_enable': {
                'type': 'bool',
                },
            'threshold': {
                'type': 'int',
                },
            'capacity_fail_break': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'connection_load': {
            'type': 'dict',
            'connection_load_enable': {
                'type': 'bool',
                },
            'connection_load_fail_break': {
                'type': 'bool',
                },
            'connection_load_samples': {
                'type': 'int',
                },
            'connection_load_interval': {
                'type': 'int',
                },
            'limit': {
                'type': 'bool',
                },
            'connection_load_limit': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'connection_count_by_site': {
            'type': 'dict',
            'connection_count_enable': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'dns': {
            'type': 'dict',
            'action': {
                'type': 'bool',
                },
            'active_only': {
                'type': 'bool',
                },
            'active_only_fail_safe': {
                'type': 'bool',
                },
            'dns_addition_mx': {
                'type': 'bool',
                },
            'dns_auto_map': {
                'type': 'bool',
                },
            'backup_alias': {
                'type': 'bool',
                },
            'backup_server': {
                'type': 'bool',
                },
            'external_ip': {
                'type': 'bool',
                },
            'external_soa': {
                'type': 'bool',
                },
            'cname_detect': {
                'type': 'bool',
                },
            'ip_replace': {
                'type': 'bool',
                },
            'geoloc_alias': {
                'type': 'bool',
                },
            'geoloc_action': {
                'type': 'bool',
                },
            'geoloc_policy': {
                'type': 'bool',
                },
            'selected_only': {
                'type': 'bool',
                },
            'selected_only_value': {
                'type': 'int',
                },
            'cache': {
                'type': 'bool',
                },
            'aging_time': {
                'type': 'int',
                },
            'delegation': {
                'type': 'bool',
                },
            'hint': {
                'type': 'str',
                'choices': ['none', 'answer', 'addition']
                },
            'logging': {
                'type': 'str',
                'choices': ['none', 'query', 'response', 'both']
                },
            'template': {
                'type': 'str',
                },
            'ttl': {
                'type': 'int',
                },
            'use_server_ttl': {
                'type': 'bool',
                },
            'server': {
                'type': 'bool',
                },
            'server_srv': {
                'type': 'bool',
                },
            'server_mx': {
                'type': 'bool',
                },
            'server_naptr': {
                'type': 'bool',
                },
            'server_addition_mx': {
                'type': 'bool',
                },
            'server_ns': {
                'type': 'bool',
                },
            'server_auto_ns': {
                'type': 'bool',
                },
            'server_ptr': {
                'type': 'bool',
                },
            'server_auto_ptr': {
                'type': 'bool',
                },
            'server_txt': {
                'type': 'bool',
                },
            'server_custom': {
                'type': 'bool',
                },
            'server_any': {
                'type': 'bool',
                },
            'server_any_with_metric': {
                'type': 'bool',
                },
            'server_authoritative': {
                'type': 'bool',
                },
            'server_sec': {
                'type': 'bool',
                },
            'server_ns_list': {
                'type': 'bool',
                },
            'server_full_list': {
                'type': 'bool',
                },
            'server_mode_only': {
                'type': 'bool',
                },
            'zone_owner_mode': {
                'type': 'bool',
                },
            'server_cname': {
                'type': 'bool',
                },
            'server_caa': {
                'type': 'bool',
                },
            'ipv6': {
                'type': 'list',
                'dns_ipv6_option': {
                    'type': 'str',
                    'choices': ['mix', 'smart', 'mapping']
                    },
                'dns_ipv6_mapping_type': {
                    'type': 'str',
                    'choices': ['addition', 'answer', 'exclusive', 'replace']
                    }
                },
            'block_action': {
                'type': 'bool',
                },
            'action_type': {
                'type': 'str',
                'choices': ['drop', 'reject', 'ignore']
                },
            'proxy_block_port_range_list': {
                'type': 'list',
                'proxy_block_range_from': {
                    'type': 'int',
                    },
                'proxy_block_range_to': {
                    'type': 'int',
                    }
                },
            'block_value': {
                'type': 'list',
                'block_value': {
                    'type': 'int',
                    }
                },
            'block_type': {
                'type': 'str',
                'choices': ['a', 'aaaa', 'ns', 'mx', 'srv', 'cname', 'ptr', 'soa', 'txt']
                },
            'sticky': {
                'type': 'bool',
                },
            'sticky_mask': {
                'type': 'str',
                },
            'sticky_ipv6_mask': {
                'type': 'int',
                },
            'sticky_aging_time': {
                'type': 'int',
                },
            'dynamic_preference': {
                'type': 'bool',
                },
            'dynamic_weight': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                },
            'sticky_options': {
                'type': 'dict',
                'edns_client_subnet': {
                    'type': 'bool',
                    },
                'only_ecs': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'geo_location_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'ip_multiple_fields': {
                'type': 'list',
                'ip_sub': {
                    'type': 'str',
                    },
                'ip_mask_sub': {
                    'type': 'str',
                    },
                'ip_addr2_sub': {
                    'type': 'str',
                    }
                },
            'ipv6_multiple_fields': {
                'type': 'list',
                'ipv6_sub': {
                    'type': 'str',
                    },
                'ipv6_mask_sub': {
                    'type': 'int',
                    },
                'ipv6_addr2_sub': {
                    'type': 'str',
                    }
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            },
        'geo_location_match': {
            'type': 'dict',
            'overlap': {
                'type': 'bool',
                },
            'geo_type_overlap': {
                'type': 'str',
                'choices': ['global', 'policy']
                },
            'match_first': {
                'type': 'str',
                'choices': ['global', 'policy']
                },
            'uuid': {
                'type': 'str',
                }
            },
        'active_rdt': {
            'type': 'dict',
            'enable': {
                'type': 'bool',
                },
            'single_shot': {
                'type': 'bool',
                },
            'prefer_dns_sticky': {
                'type': 'bool',
                },
            'sticky_difference': {
                'type': 'int',
                },
            'timeout': {
                'type': 'int',
                },
            'skip': {
                'type': 'int',
                },
            'keep_tracking': {
                'type': 'bool',
                },
            'ignore_id': {
                'type': 'int',
                },
            'samples': {
                'type': 'int',
                },
            'tolerance': {
                'type': 'int',
                },
            'difference': {
                'type': 'int',
                },
            'limit': {
                'type': 'int',
                },
            'fail_break': {
                'type': 'bool',
                },
            'controller': {
                'type': 'bool',
                },
            'proto_rdt_enable': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'auto_map': {
            'type': 'dict',
            'ttl': {
                'type': 'int',
                },
            'module_disable': {
                'type': 'bool',
                },
            'all': {
                'type': 'bool',
                },
            'module_type': {
                'type': 'str',
                'choices': ['slb-virtual-server', 'slb-device', 'slb-server', 'gslb-service-ip', 'gslb-site', 'gslb-group', 'hostname']
                },
            'uuid': {
                'type': 'str',
                }
            },
        'edns': {
            'type': 'dict',
            'client_subnet_geographic': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'metric_list': {
                'type': 'list',
                'ntype': {
                    'type': 'str',
                    },
                'order': {
                    'type': 'int',
                    }
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
    url_base = "/axapi/v3/gslb/policy/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/policy"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["policy"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["policy"].get(k) != v:
            change_results["changed"] = True
            config_changes["policy"][k] = v

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
    payload = utils.build_json("policy", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["policy"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["policy-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["policy"]["oper"] if info != "NotFound" else info
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
