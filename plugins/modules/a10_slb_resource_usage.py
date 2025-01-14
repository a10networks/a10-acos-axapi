#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_resource_usage
description:
    - Configure SLB Resource Usage
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
    client_ssl_template_count:
        description:
        - "Total configurable Client SSL Templates in the System"
        type: int
        required: False
    conn_reuse_template_count:
        description:
        - "Total configurable Connection reuse Templates in the System"
        type: int
        required: False
    fast_tcp_template_count:
        description:
        - "Total configurable Fast TCP Templates in the System"
        type: int
        required: False
    fast_udp_template_count:
        description:
        - "Total configurable Fast UDP Templates in the System"
        type: int
        required: False
    http_template_count:
        description:
        - "Total configurable HTTP Templates in the System"
        type: int
        required: False
    fix_template_count:
        description:
        - "Total configurable FIX Templates in the System"
        type: int
        required: False
    cache_template_count:
        description:
        - "Total configurable HTTP Cache Templates in the System"
        type: int
        required: False
    nat_pool_addr_count:
        description:
        - "Total configurable NAT Pool addresses in the System (deprecated)"
        type: int
        required: False
    persist_cookie_template_count:
        description:
        - "Total configurable Persistent cookie Templates in the System"
        type: int
        required: False
    persist_srcip_template_count:
        description:
        - "Total configurable Source IP Persistent Templates in the System"
        type: int
        required: False
    proxy_template_count:
        description:
        - "Total configurable Proxy Templates in the System"
        type: int
        required: False
    real_port_count:
        description:
        - "Total Real Server Ports in the System"
        type: int
        required: False
    real_server_count:
        description:
        - "Total Real Servers in the System"
        type: int
        required: False
    server_ssl_template_count:
        description:
        - "Total configurable Server SSL Templates in the System"
        type: int
        required: False
    link_cost_template_count:
        description:
        - "Total configurable Link-cost Templates in the System"
        type: int
        required: False
    pbslb_entry_count:
        description:
        - "Total configurable pbslb entry in the System"
        type: int
        required: False
    service_group_count:
        description:
        - "Total Service Groups in the System"
        type: int
        required: False
    stream_template_count:
        description:
        - "Total configurable Streaming media in the System"
        type: int
        required: False
    virtual_port_count:
        description:
        - "Total Virtual Server Ports in the System"
        type: int
        required: False
    virtual_server_count:
        description:
        - "Total Virtual Servers in the System"
        type: int
        required: False
    log_template_count:
        description:
        - "Total configurable SLB Logging Templates in the System"
        type: int
        required: False
    gslb_site_count:
        description:
        - "Total GSLB sites in the System"
        type: int
        required: False
    gslb_device_count:
        description:
        - "Total GSLB devices in the System"
        type: int
        required: False
    gslb_service_ip_count:
        description:
        - "Total GSLB service-ip in the System"
        type: int
        required: False
    gslb_service_port_count:
        description:
        - "Total GSLB service-port in the System"
        type: int
        required: False
    gslb_zone_count:
        description:
        - "Total GSLB zones in the System"
        type: int
        required: False
    gslb_service_count:
        description:
        - "Total GSLB services in the System"
        type: int
        required: False
    gslb_policy_count:
        description:
        - "Total GSLB policies in the System"
        type: int
        required: False
    gslb_geo_location_count:
        description:
        - "Total GSLB geo-location in the System"
        type: int
        required: False
    gslb_ip_list_count:
        description:
        - "Total GSLB ip-list in the System"
        type: int
        required: False
    gslb_template_count:
        description:
        - "Total GSLB templates in the System"
        type: int
        required: False
    gslb_svc_group_count:
        description:
        - "Total GSLB services in the System"
        type: int
        required: False
    health_monitor_count:
        description:
        - "Total Health Monitors in the System"
        type: int
        required: False
    pbslb_subnet_count:
        description:
        - "Total PBSLB Subnets in the System"
        type: int
        required: False
    slb_threshold_res_usage_percent:
        description:
        - "Enter the threshold as a percentage (Threshold in percentage(default is 0%))"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            nat_pool_addr_min:
                description:
                - "Field nat_pool_addr_min"
                type: int
            nat_pool_addr_max:
                description:
                - "Field nat_pool_addr_max"
                type: int
            nat_pool_addr_default:
                description:
                - "Field nat_pool_addr_default"
                type: int
            real_server_min:
                description:
                - "Field real_server_min"
                type: int
            real_server_max:
                description:
                - "Field real_server_max"
                type: int
            real_server_default:
                description:
                - "Field real_server_default"
                type: int
            real_port_min:
                description:
                - "Field real_port_min"
                type: int
            real_port_max:
                description:
                - "Field real_port_max"
                type: int
            real_port_default:
                description:
                - "Field real_port_default"
                type: int
            service_group_min:
                description:
                - "Field service_group_min"
                type: int
            service_group_max:
                description:
                - "Field service_group_max"
                type: int
            service_group_default:
                description:
                - "Field service_group_default"
                type: int
            virtual_port_min:
                description:
                - "Field virtual_port_min"
                type: int
            virtual_port_max:
                description:
                - "Field virtual_port_max"
                type: int
            virtual_port_default:
                description:
                - "Field virtual_port_default"
                type: int
            virtual_server_min:
                description:
                - "Field virtual_server_min"
                type: int
            virtual_server_max:
                description:
                - "Field virtual_server_max"
                type: int
            virtual_server_default:
                description:
                - "Field virtual_server_default"
                type: int
            http_template_min:
                description:
                - "Field http_template_min"
                type: int
            http_template_max:
                description:
                - "Field http_template_max"
                type: int
            http_template_default:
                description:
                - "Field http_template_default"
                type: int
            fix_template_min:
                description:
                - "Field fix_template_min"
                type: int
            fix_template_max:
                description:
                - "Field fix_template_max"
                type: int
            fix_template_default:
                description:
                - "Field fix_template_default"
                type: int
            proxy_template_min:
                description:
                - "Field proxy_template_min"
                type: int
            proxy_template_max:
                description:
                - "Field proxy_template_max"
                type: int
            proxy_template_default:
                description:
                - "Field proxy_template_default"
                type: int
            conn_reuse_template_min:
                description:
                - "Field conn_reuse_template_min"
                type: int
            conn_reuse_template_max:
                description:
                - "Field conn_reuse_template_max"
                type: int
            conn_reuse_template_default:
                description:
                - "Field conn_reuse_template_default"
                type: int
            fast_tcp_template_min:
                description:
                - "Field fast_tcp_template_min"
                type: int
            fast_tcp_template_max:
                description:
                - "Field fast_tcp_template_max"
                type: int
            fast_tcp_template_default:
                description:
                - "Field fast_tcp_template_default"
                type: int
            fast_udp_template_min:
                description:
                - "Field fast_udp_template_min"
                type: int
            fast_udp_template_max:
                description:
                - "Field fast_udp_template_max"
                type: int
            fast_udp_template_default:
                description:
                - "Field fast_udp_template_default"
                type: int
            client_ssl_template_min:
                description:
                - "Field client_ssl_template_min"
                type: int
            client_ssl_template_max:
                description:
                - "Field client_ssl_template_max"
                type: int
            client_ssl_template_default:
                description:
                - "Field client_ssl_template_default"
                type: int
            server_ssl_template_min:
                description:
                - "Field server_ssl_template_min"
                type: int
            server_ssl_template_max:
                description:
                - "Field server_ssl_template_max"
                type: int
            server_ssl_template_default:
                description:
                - "Field server_ssl_template_default"
                type: int
            link_cost_template_min:
                description:
                - "Field link_cost_template_min"
                type: int
            link_cost_template_max:
                description:
                - "Field link_cost_template_max"
                type: int
            link_cost_template_default:
                description:
                - "Field link_cost_template_default"
                type: int
            pbslb_entry_min:
                description:
                - "Field pbslb_entry_min"
                type: int
            pbslb_entry_max:
                description:
                - "Field pbslb_entry_max"
                type: int
            pbslb_entry_default:
                description:
                - "Field pbslb_entry_default"
                type: int
            stream_template_min:
                description:
                - "Field stream_template_min"
                type: int
            stream_template_max:
                description:
                - "Field stream_template_max"
                type: int
            stream_template_default:
                description:
                - "Field stream_template_default"
                type: int
            persist_cookie_template_min:
                description:
                - "Field persist_cookie_template_min"
                type: int
            persist_cookie_template_max:
                description:
                - "Field persist_cookie_template_max"
                type: int
            persist_cookie_template_default:
                description:
                - "Field persist_cookie_template_default"
                type: int
            persist_srcip_template_min:
                description:
                - "Field persist_srcip_template_min"
                type: int
            persist_srcip_template_max:
                description:
                - "Field persist_srcip_template_max"
                type: int
            persist_srcip_template_default:
                description:
                - "Field persist_srcip_template_default"
                type: int
            health_monitor_count_min:
                description:
                - "Field health_monitor_count_min"
                type: int
            health_monitor_count_max:
                description:
                - "Field health_monitor_count_max"
                type: int
            health_monitor_count_default:
                description:
                - "Field health_monitor_count_default"
                type: int
            pbslb_subnet_count_min:
                description:
                - "Field pbslb_subnet_count_min"
                type: int
            pbslb_subnet_count_max:
                description:
                - "Field pbslb_subnet_count_max"
                type: int
            pbslb_subnet_count_default:
                description:
                - "Field pbslb_subnet_count_default"
                type: int
            gslb_site_count_min:
                description:
                - "Field gslb_site_count_min"
                type: int
            gslb_site_count_max:
                description:
                - "Field gslb_site_count_max"
                type: int
            gslb_site_count_default:
                description:
                - "Field gslb_site_count_default"
                type: int
            gslb_device_count_min:
                description:
                - "Field gslb_device_count_min"
                type: int
            gslb_device_count_max:
                description:
                - "Field gslb_device_count_max"
                type: int
            gslb_device_count_default:
                description:
                - "Field gslb_device_count_default"
                type: int
            gslb_service_ip_count_min:
                description:
                - "Field gslb_service_ip_count_min"
                type: int
            gslb_service_ip_count_max:
                description:
                - "Field gslb_service_ip_count_max"
                type: int
            gslb_service_ip_count_default:
                description:
                - "Field gslb_service_ip_count_default"
                type: int
            gslb_service_port_count_min:
                description:
                - "Field gslb_service_port_count_min"
                type: int
            gslb_service_port_count_max:
                description:
                - "Field gslb_service_port_count_max"
                type: int
            gslb_service_port_count_default:
                description:
                - "Field gslb_service_port_count_default"
                type: int
            gslb_zone_count_min:
                description:
                - "Field gslb_zone_count_min"
                type: int
            gslb_zone_count_max:
                description:
                - "Field gslb_zone_count_max"
                type: int
            gslb_zone_count_default:
                description:
                - "Field gslb_zone_count_default"
                type: int
            gslb_service_count_min:
                description:
                - "Field gslb_service_count_min"
                type: int
            gslb_service_count_max:
                description:
                - "Field gslb_service_count_max"
                type: int
            gslb_service_count_default:
                description:
                - "Field gslb_service_count_default"
                type: int
            gslb_policy_count_min:
                description:
                - "Field gslb_policy_count_min"
                type: int
            gslb_policy_count_max:
                description:
                - "Field gslb_policy_count_max"
                type: int
            gslb_policy_count_default:
                description:
                - "Field gslb_policy_count_default"
                type: int
            gslb_geo_location_count_min:
                description:
                - "Field gslb_geo_location_count_min"
                type: int
            gslb_geo_location_count_max:
                description:
                - "Field gslb_geo_location_count_max"
                type: int
            gslb_geo_location_count_default:
                description:
                - "Field gslb_geo_location_count_default"
                type: int
            gslb_ip_list_count_min:
                description:
                - "Field gslb_ip_list_count_min"
                type: int
            gslb_ip_list_count_max:
                description:
                - "Field gslb_ip_list_count_max"
                type: int
            gslb_ip_list_count_default:
                description:
                - "Field gslb_ip_list_count_default"
                type: int
            gslb_template_count_min:
                description:
                - "Field gslb_template_count_min"
                type: int
            gslb_template_count_max:
                description:
                - "Field gslb_template_count_max"
                type: int
            gslb_template_count_default:
                description:
                - "Field gslb_template_count_default"
                type: int
            gslb_svcgroup_count_min:
                description:
                - "Field gslb_svcgroup_count_min"
                type: int
            gslb_svcgroup_count_max:
                description:
                - "Field gslb_svcgroup_count_max"
                type: int
            gslb_svcgroup_count_default:
                description:
                - "Field gslb_svcgroup_count_default"
                type: int
            cache_template_min:
                description:
                - "Field cache_template_min"
                type: int
            cache_template_max:
                description:
                - "Field cache_template_max"
                type: int
            cache_template_default:
                description:
                - "Field cache_template_default"
                type: int
            log_template_min:
                description:
                - "Field log_template_min"
                type: int
            log_template_max:
                description:
                - "Field log_template_max"
                type: int
            log_template_default:
                description:
                - "Field log_template_default"
                type: int
            slb_threshold_res_usage_default:
                description:
                - "Field slb_threshold_res_usage_default"
                type: int
            slb_threshold_res_usage_min:
                description:
                - "Field slb_threshold_res_usage_min"
                type: int
            slb_threshold_res_usage_max:
                description:
                - "Field slb_threshold_res_usage_max"
                type: int

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
    "cache_template_count", "client_ssl_template_count", "conn_reuse_template_count", "fast_tcp_template_count", "fast_udp_template_count", "fix_template_count", "gslb_device_count", "gslb_geo_location_count", "gslb_ip_list_count", "gslb_policy_count", "gslb_service_count", "gslb_service_ip_count", "gslb_service_port_count", "gslb_site_count",
    "gslb_svc_group_count", "gslb_template_count", "gslb_zone_count", "health_monitor_count", "http_template_count", "link_cost_template_count", "log_template_count", "nat_pool_addr_count", "oper", "pbslb_entry_count", "pbslb_subnet_count", "persist_cookie_template_count", "persist_srcip_template_count", "proxy_template_count", "real_port_count",
    "real_server_count", "server_ssl_template_count", "service_group_count", "slb_threshold_res_usage_percent", "stream_template_count", "uuid", "virtual_port_count", "virtual_server_count",
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
        'client_ssl_template_count': {
            'type': 'int',
            },
        'conn_reuse_template_count': {
            'type': 'int',
            },
        'fast_tcp_template_count': {
            'type': 'int',
            },
        'fast_udp_template_count': {
            'type': 'int',
            },
        'http_template_count': {
            'type': 'int',
            },
        'fix_template_count': {
            'type': 'int',
            },
        'cache_template_count': {
            'type': 'int',
            },
        'nat_pool_addr_count': {
            'type': 'int',
            },
        'persist_cookie_template_count': {
            'type': 'int',
            },
        'persist_srcip_template_count': {
            'type': 'int',
            },
        'proxy_template_count': {
            'type': 'int',
            },
        'real_port_count': {
            'type': 'int',
            },
        'real_server_count': {
            'type': 'int',
            },
        'server_ssl_template_count': {
            'type': 'int',
            },
        'link_cost_template_count': {
            'type': 'int',
            },
        'pbslb_entry_count': {
            'type': 'int',
            },
        'service_group_count': {
            'type': 'int',
            },
        'stream_template_count': {
            'type': 'int',
            },
        'virtual_port_count': {
            'type': 'int',
            },
        'virtual_server_count': {
            'type': 'int',
            },
        'log_template_count': {
            'type': 'int',
            },
        'gslb_site_count': {
            'type': 'int',
            },
        'gslb_device_count': {
            'type': 'int',
            },
        'gslb_service_ip_count': {
            'type': 'int',
            },
        'gslb_service_port_count': {
            'type': 'int',
            },
        'gslb_zone_count': {
            'type': 'int',
            },
        'gslb_service_count': {
            'type': 'int',
            },
        'gslb_policy_count': {
            'type': 'int',
            },
        'gslb_geo_location_count': {
            'type': 'int',
            },
        'gslb_ip_list_count': {
            'type': 'int',
            },
        'gslb_template_count': {
            'type': 'int',
            },
        'gslb_svc_group_count': {
            'type': 'int',
            },
        'health_monitor_count': {
            'type': 'int',
            },
        'pbslb_subnet_count': {
            'type': 'int',
            },
        'slb_threshold_res_usage_percent': {
            'type': 'int',
            },
        'uuid': {
            'type': 'str',
            },
        'oper': {
            'type': 'dict',
            'nat_pool_addr_min': {
                'type': 'int',
                },
            'nat_pool_addr_max': {
                'type': 'int',
                },
            'nat_pool_addr_default': {
                'type': 'int',
                },
            'real_server_min': {
                'type': 'int',
                },
            'real_server_max': {
                'type': 'int',
                },
            'real_server_default': {
                'type': 'int',
                },
            'real_port_min': {
                'type': 'int',
                },
            'real_port_max': {
                'type': 'int',
                },
            'real_port_default': {
                'type': 'int',
                },
            'service_group_min': {
                'type': 'int',
                },
            'service_group_max': {
                'type': 'int',
                },
            'service_group_default': {
                'type': 'int',
                },
            'virtual_port_min': {
                'type': 'int',
                },
            'virtual_port_max': {
                'type': 'int',
                },
            'virtual_port_default': {
                'type': 'int',
                },
            'virtual_server_min': {
                'type': 'int',
                },
            'virtual_server_max': {
                'type': 'int',
                },
            'virtual_server_default': {
                'type': 'int',
                },
            'http_template_min': {
                'type': 'int',
                },
            'http_template_max': {
                'type': 'int',
                },
            'http_template_default': {
                'type': 'int',
                },
            'fix_template_min': {
                'type': 'int',
                },
            'fix_template_max': {
                'type': 'int',
                },
            'fix_template_default': {
                'type': 'int',
                },
            'proxy_template_min': {
                'type': 'int',
                },
            'proxy_template_max': {
                'type': 'int',
                },
            'proxy_template_default': {
                'type': 'int',
                },
            'conn_reuse_template_min': {
                'type': 'int',
                },
            'conn_reuse_template_max': {
                'type': 'int',
                },
            'conn_reuse_template_default': {
                'type': 'int',
                },
            'fast_tcp_template_min': {
                'type': 'int',
                },
            'fast_tcp_template_max': {
                'type': 'int',
                },
            'fast_tcp_template_default': {
                'type': 'int',
                },
            'fast_udp_template_min': {
                'type': 'int',
                },
            'fast_udp_template_max': {
                'type': 'int',
                },
            'fast_udp_template_default': {
                'type': 'int',
                },
            'client_ssl_template_min': {
                'type': 'int',
                },
            'client_ssl_template_max': {
                'type': 'int',
                },
            'client_ssl_template_default': {
                'type': 'int',
                },
            'server_ssl_template_min': {
                'type': 'int',
                },
            'server_ssl_template_max': {
                'type': 'int',
                },
            'server_ssl_template_default': {
                'type': 'int',
                },
            'link_cost_template_min': {
                'type': 'int',
                },
            'link_cost_template_max': {
                'type': 'int',
                },
            'link_cost_template_default': {
                'type': 'int',
                },
            'pbslb_entry_min': {
                'type': 'int',
                },
            'pbslb_entry_max': {
                'type': 'int',
                },
            'pbslb_entry_default': {
                'type': 'int',
                },
            'stream_template_min': {
                'type': 'int',
                },
            'stream_template_max': {
                'type': 'int',
                },
            'stream_template_default': {
                'type': 'int',
                },
            'persist_cookie_template_min': {
                'type': 'int',
                },
            'persist_cookie_template_max': {
                'type': 'int',
                },
            'persist_cookie_template_default': {
                'type': 'int',
                },
            'persist_srcip_template_min': {
                'type': 'int',
                },
            'persist_srcip_template_max': {
                'type': 'int',
                },
            'persist_srcip_template_default': {
                'type': 'int',
                },
            'health_monitor_count_min': {
                'type': 'int',
                },
            'health_monitor_count_max': {
                'type': 'int',
                },
            'health_monitor_count_default': {
                'type': 'int',
                },
            'pbslb_subnet_count_min': {
                'type': 'int',
                },
            'pbslb_subnet_count_max': {
                'type': 'int',
                },
            'pbslb_subnet_count_default': {
                'type': 'int',
                },
            'gslb_site_count_min': {
                'type': 'int',
                },
            'gslb_site_count_max': {
                'type': 'int',
                },
            'gslb_site_count_default': {
                'type': 'int',
                },
            'gslb_device_count_min': {
                'type': 'int',
                },
            'gslb_device_count_max': {
                'type': 'int',
                },
            'gslb_device_count_default': {
                'type': 'int',
                },
            'gslb_service_ip_count_min': {
                'type': 'int',
                },
            'gslb_service_ip_count_max': {
                'type': 'int',
                },
            'gslb_service_ip_count_default': {
                'type': 'int',
                },
            'gslb_service_port_count_min': {
                'type': 'int',
                },
            'gslb_service_port_count_max': {
                'type': 'int',
                },
            'gslb_service_port_count_default': {
                'type': 'int',
                },
            'gslb_zone_count_min': {
                'type': 'int',
                },
            'gslb_zone_count_max': {
                'type': 'int',
                },
            'gslb_zone_count_default': {
                'type': 'int',
                },
            'gslb_service_count_min': {
                'type': 'int',
                },
            'gslb_service_count_max': {
                'type': 'int',
                },
            'gslb_service_count_default': {
                'type': 'int',
                },
            'gslb_policy_count_min': {
                'type': 'int',
                },
            'gslb_policy_count_max': {
                'type': 'int',
                },
            'gslb_policy_count_default': {
                'type': 'int',
                },
            'gslb_geo_location_count_min': {
                'type': 'int',
                },
            'gslb_geo_location_count_max': {
                'type': 'int',
                },
            'gslb_geo_location_count_default': {
                'type': 'int',
                },
            'gslb_ip_list_count_min': {
                'type': 'int',
                },
            'gslb_ip_list_count_max': {
                'type': 'int',
                },
            'gslb_ip_list_count_default': {
                'type': 'int',
                },
            'gslb_template_count_min': {
                'type': 'int',
                },
            'gslb_template_count_max': {
                'type': 'int',
                },
            'gslb_template_count_default': {
                'type': 'int',
                },
            'gslb_svcgroup_count_min': {
                'type': 'int',
                },
            'gslb_svcgroup_count_max': {
                'type': 'int',
                },
            'gslb_svcgroup_count_default': {
                'type': 'int',
                },
            'cache_template_min': {
                'type': 'int',
                },
            'cache_template_max': {
                'type': 'int',
                },
            'cache_template_default': {
                'type': 'int',
                },
            'log_template_min': {
                'type': 'int',
                },
            'log_template_max': {
                'type': 'int',
                },
            'log_template_default': {
                'type': 'int',
                },
            'slb_threshold_res_usage_default': {
                'type': 'int',
                },
            'slb_threshold_res_usage_min': {
                'type': 'int',
                },
            'slb_threshold_res_usage_max': {
                'type': 'int',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/resource-usage"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/resource-usage"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["resource-usage"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["resource-usage"].get(k) != v:
            change_results["changed"] = True
            config_changes["resource-usage"][k] = v

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
    payload = utils.build_json("resource-usage", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["resource-usage"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["resource-usage-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["resource-usage"]["oper"] if info != "NotFound" else info
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
