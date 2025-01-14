#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_logging
description:
    - CGNV6 Logging Statistics
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
    uuid:
        description:
        - "uuid of the object"
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
                - "'all'= all; 'tcp-session-created'= TCP Session Created; 'tcp-session-deleted'=
          TCP Session Deleted; 'tcp-port-allocated'= TCP Port Allocated; 'tcp-port-
          freed'= TCP Port Freed; 'tcp-port-batch-allocated'= TCP Port Batch Allocated;
          'tcp-port-batch-freed'= TCP Port Batch Freed; 'udp-session-created'= UDP
          Session Created; 'udp-session-deleted'= UDP Session Deleted; 'udp-port-
          allocated'= UDP Port Allocated; 'udp-port-freed'= UDP Port Freed; 'udp-port-
          batch-allocated'= UDP Port Batch Allocated; 'udp-port-batch-freed'= UDP Port
          Batch Freed; 'icmp-session-created'= ICMP Session Created; 'icmp-session-
          deleted'= ICMP Session Deleted; 'icmp-resource-allocated'= ICMP Resource
          Allocated; 'icmp-resource-freed'= ICMP Resource Freed; 'icmpv6-session-
          created'= ICMPV6 Session Created; 'icmpv6-session-deleted'= ICMPV6 Session
          Deleted; 'icmpv6-resource-allocated'= ICMPV6 Resource Allocated;
          'icmpv6-resource-freed'= ICMPV6 Resource Freed; 'gre-session-created'= GRE
          Session Created; 'gre-session-deleted'= GRE Session Deleted; 'gre-resource-
          allocated'= GRE Resource Allocated; 'gre-resource-freed'= GRE Resource Freed;
          'esp-session-created'= ESP Session Created; 'esp-session-deleted'= ESP Session
          Deleted; 'esp-resource-allocated'= ESP Resource Allocated; 'esp-resource-
          freed'= ESP Resource Freed; 'fixed-nat-user-ports'= Fixed NAT Inside User Port
          Mapping; 'fixed-nat-disable-config-logged'= Fixed NAT Periodic Configs Logged;
          'fixed-nat-disable-config-logs-sent'= Fixed NAT Periodic Config Logs Sent;
          'fixed-nat-periodic-config-logs-sent'= Fixed NAT Disabled Configs Logged;
          'fixed-nat-periodic-config-logged'= Fixed NAT Disabled Config Logs Sent;
          'fixed-nat-interim-updated'= Fixed NAT Interim Updated; 'enhanced-user-log'=
          Enhanced User Log; 'log-sent'= Log Packets Sent; 'log-dropped'= Log Packets
          Dropped; 'conn-tcp-established'= TCP Connection Established; 'conn-tcp-
          dropped'= TCP Connection Lost; 'tcp-port-overloading-allocated'= TCP Port
          Overloading Allocated; 'tcp-port-overloading-freed'= TCP Port Overloading
          Freed; 'udp-port-overloading-allocated'= UDP Port Overloading Allocated; 'udp-
          port-overloading-freed'= UDP Port Overloading Freed; 'http-request-logged'=
          HTTP Request Logged; 'reduced-logs-by-destination'= Reduced Logs by Destination
          Protocol and Port; 'out-of-buffers'= Out of Buffers; 'add-msg-failed'= Add
          Message to Buffer Failed; 'rtsp-port-allocated'= RTSP UDP Port Allocated;
          'rtsp-port-freed'= RTSP UDP Port Freed; 'conn-tcp-create-failed'= TCP
          Connection Failed; 'ipv4-frag-applied'= IPv4 Fragmentation Applied; 'ipv4-frag-
          failed'= IPv4 Fragmentation Failed; 'ipv6-frag-applied'= IPv6 Fragmentation
          Applied; 'ipv6-frag-failed'= IPv6 Fragmentation Failed; 'interim-update-
          scheduled'= Port Allocation Interim Update Scheduled; 'interim-update-schedule-
          failed'= Port Allocation Interim Update Failed; 'interim-update-terminated'=
          Port Allocation Interim Update Terminated; 'interim-update-memory-freed'= Port
          Allocation Interim Update Memory Freed; 'interim-update-no-buff-retried'= Port
          Allocation Interim Update Memory Freed; 'tcp-port-batch-interim-updated'= TCP
          Port Batch Interim Updated; 'udp-port-batch-interim-updated'= UDP Port Batch
          Interim Updated; 'port-block-accounting-freed'= Port Allocation Accounting
          Freed; 'port-block-accounting-allocated'= Port Allocation Accounting Allocated;
          'log-message-too-long'= Log message too long; 'http-out-of-order-dropped'= HTTP
          out-of-order dropped; 'http-alloc-failed'= HTTP Request Info Allocation Failed;
          'http-frag-merge-failed-dropped'= HTTP frag merge failed dropped; 'http-
          malloc'= HTTP mem allocate; 'http-mfree'= HTTP mem free; 'http-spm-alloc-
          type0'= HTTP Conn SPM Type 0 allocate; 'http-spm-alloc-type1'= HTTP Conn SPM
          Type 1 allocate; 'http-spm-alloc-type2'= HTTP Conn SPM Type 2 allocate; 'http-
          spm-alloc-type3'= HTTP Conn SPM Type 3 allocate; 'http-spm-alloc-type4'= HTTP
          Conn SPM Type 4 allocate; 'http-spm-free-type0'= HTTP Conn SPM Type 0 free;
          'http-spm-free-type1'= HTTP Conn SPM Type 1 free; 'http-spm-free-type2'= HTTP
          Conn SPM Type 2 free; 'http-spm-free-type3'= HTTP Conn SPM Type 3 free; 'http-
          spm-free-type4'= HTTP Conn SPM Type 4 free; 'iddos-l3-entry-create'= iDDoS L3
          Entry Created; 'iddos-l3-entry-delete'= iDDoS L3 Entry Deleted;
          'iddos-l4-entry-create'= iDDoS L4 Entry Created; 'iddos-l4-entry-delete'= iDDoS
          L4 Entry Deleted;"
                type: str
    source_address:
        description:
        - "Field source_address"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    tcp_svr_status:
        description:
        - "Field tcp_svr_status"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    nat_resource_exhausted:
        description:
        - "Field nat_resource_exhausted"
        type: dict
        required: False
        suboptions:
            level:
                description:
                - "'warning'= Log level Warning; 'critical'= Log level Critical (Default);
          'notice'= Log level Notice;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    nat_quota_exceeded:
        description:
        - "Field nat_quota_exceeded"
        type: dict
        required: False
        suboptions:
            level:
                description:
                - "'warning'= Log level Warning (Default); 'critical'= Log level Critical;
          'notice'= Log level Notice;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    pool_based_log:
        description:
        - "Field pool_based_log"
        type: dict
        required: False
        suboptions:
            cycle:
                description:
                - "Logging cycle"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            tcp_session_created:
                description:
                - "TCP Session Created"
                type: str
            tcp_session_deleted:
                description:
                - "TCP Session Deleted"
                type: str
            tcp_port_allocated:
                description:
                - "TCP Port Allocated"
                type: str
            tcp_port_freed:
                description:
                - "TCP Port Freed"
                type: str
            tcp_port_batch_allocated:
                description:
                - "TCP Port Batch Allocated"
                type: str
            tcp_port_batch_freed:
                description:
                - "TCP Port Batch Freed"
                type: str
            udp_session_created:
                description:
                - "UDP Session Created"
                type: str
            udp_session_deleted:
                description:
                - "UDP Session Deleted"
                type: str
            udp_port_allocated:
                description:
                - "UDP Port Allocated"
                type: str
            udp_port_freed:
                description:
                - "UDP Port Freed"
                type: str
            udp_port_batch_allocated:
                description:
                - "UDP Port Batch Allocated"
                type: str
            udp_port_batch_freed:
                description:
                - "UDP Port Batch Freed"
                type: str
            icmp_session_created:
                description:
                - "ICMP Session Created"
                type: str
            icmp_session_deleted:
                description:
                - "ICMP Session Deleted"
                type: str
            icmp_resource_allocated:
                description:
                - "ICMP Resource Allocated"
                type: str
            icmp_resource_freed:
                description:
                - "ICMP Resource Freed"
                type: str
            icmpv6_session_created:
                description:
                - "ICMPV6 Session Created"
                type: str
            icmpv6_session_deleted:
                description:
                - "ICMPV6 Session Deleted"
                type: str
            icmpv6_resource_allocated:
                description:
                - "ICMPV6 Resource Allocated"
                type: str
            icmpv6_resource_freed:
                description:
                - "ICMPV6 Resource Freed"
                type: str
            gre_session_created:
                description:
                - "GRE Session Created"
                type: str
            gre_session_deleted:
                description:
                - "GRE Session Deleted"
                type: str
            gre_resource_allocated:
                description:
                - "GRE Resource Allocated"
                type: str
            gre_resource_freed:
                description:
                - "GRE Resource Freed"
                type: str
            esp_session_created:
                description:
                - "ESP Session Created"
                type: str
            esp_session_deleted:
                description:
                - "ESP Session Deleted"
                type: str
            esp_resource_allocated:
                description:
                - "ESP Resource Allocated"
                type: str
            esp_resource_freed:
                description:
                - "ESP Resource Freed"
                type: str
            fixed_nat_user_ports:
                description:
                - "Fixed NAT Inside User Port Mapping"
                type: str
            fixed_nat_disable_config_logged:
                description:
                - "Fixed NAT Periodic Configs Logged"
                type: str
            fixed_nat_disable_config_logs_sent:
                description:
                - "Fixed NAT Periodic Config Logs Sent"
                type: str
            fixed_nat_periodic_config_logs_sent:
                description:
                - "Fixed NAT Disabled Configs Logged"
                type: str
            fixed_nat_periodic_config_logged:
                description:
                - "Fixed NAT Disabled Config Logs Sent"
                type: str
            fixed_nat_interim_updated:
                description:
                - "Fixed NAT Interim Updated"
                type: str
            enhanced_user_log:
                description:
                - "Enhanced User Log"
                type: str
            log_sent:
                description:
                - "Log Packets Sent"
                type: str
            log_dropped:
                description:
                - "Log Packets Dropped"
                type: str
            conn_tcp_established:
                description:
                - "TCP Connection Established"
                type: str
            conn_tcp_dropped:
                description:
                - "TCP Connection Lost"
                type: str
            tcp_port_overloading_allocated:
                description:
                - "TCP Port Overloading Allocated"
                type: str
            tcp_port_overloading_freed:
                description:
                - "TCP Port Overloading Freed"
                type: str
            udp_port_overloading_allocated:
                description:
                - "UDP Port Overloading Allocated"
                type: str
            udp_port_overloading_freed:
                description:
                - "UDP Port Overloading Freed"
                type: str
            http_request_logged:
                description:
                - "HTTP Request Logged"
                type: str
            reduced_logs_by_destination:
                description:
                - "Reduced Logs by Destination Protocol and Port"
                type: str
            interim_update_scheduled:
                description:
                - "Port Allocation Interim Update Scheduled"
                type: str
            tcp_port_batch_interim_updated:
                description:
                - "TCP Port Batch Interim Updated"
                type: str
            udp_port_batch_interim_updated:
                description:
                - "UDP Port Batch Interim Updated"
                type: str
            iddos_l3_entry_create:
                description:
                - "iDDoS L3 Entry Created"
                type: str
            iddos_l3_entry_delete:
                description:
                - "iDDoS L3 Entry Deleted"
                type: str
            iddos_l4_entry_create:
                description:
                - "iDDoS L4 Entry Created"
                type: str
            iddos_l4_entry_delete:
                description:
                - "iDDoS L4 Entry Deleted"
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
AVAILABLE_PROPERTIES = ["nat_quota_exceeded", "nat_resource_exhausted", "pool_based_log", "sampling_enable", "source_address", "stats", "tcp_svr_status", "uuid", ]


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
        'uuid': {
            'type': 'str',
            },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'tcp-session-created', 'tcp-session-deleted', 'tcp-port-allocated', 'tcp-port-freed', 'tcp-port-batch-allocated', 'tcp-port-batch-freed', 'udp-session-created', 'udp-session-deleted', 'udp-port-allocated', 'udp-port-freed', 'udp-port-batch-allocated', 'udp-port-batch-freed', 'icmp-session-created', 'icmp-session-deleted',
                    'icmp-resource-allocated', 'icmp-resource-freed', 'icmpv6-session-created', 'icmpv6-session-deleted', 'icmpv6-resource-allocated', 'icmpv6-resource-freed', 'gre-session-created', 'gre-session-deleted', 'gre-resource-allocated', 'gre-resource-freed', 'esp-session-created', 'esp-session-deleted', 'esp-resource-allocated',
                    'esp-resource-freed', 'fixed-nat-user-ports', 'fixed-nat-disable-config-logged', 'fixed-nat-disable-config-logs-sent', 'fixed-nat-periodic-config-logs-sent', 'fixed-nat-periodic-config-logged', 'fixed-nat-interim-updated', 'enhanced-user-log', 'log-sent', 'log-dropped', 'conn-tcp-established', 'conn-tcp-dropped',
                    'tcp-port-overloading-allocated', 'tcp-port-overloading-freed', 'udp-port-overloading-allocated', 'udp-port-overloading-freed', 'http-request-logged', 'reduced-logs-by-destination', 'out-of-buffers', 'add-msg-failed', 'rtsp-port-allocated', 'rtsp-port-freed', 'conn-tcp-create-failed', 'ipv4-frag-applied', 'ipv4-frag-failed',
                    'ipv6-frag-applied', 'ipv6-frag-failed', 'interim-update-scheduled', 'interim-update-schedule-failed', 'interim-update-terminated', 'interim-update-memory-freed', 'interim-update-no-buff-retried', 'tcp-port-batch-interim-updated', 'udp-port-batch-interim-updated', 'port-block-accounting-freed', 'port-block-accounting-allocated',
                    'log-message-too-long', 'http-out-of-order-dropped', 'http-alloc-failed', 'http-frag-merge-failed-dropped', 'http-malloc', 'http-mfree', 'http-spm-alloc-type0', 'http-spm-alloc-type1', 'http-spm-alloc-type2', 'http-spm-alloc-type3', 'http-spm-alloc-type4', 'http-spm-free-type0', 'http-spm-free-type1', 'http-spm-free-type2',
                    'http-spm-free-type3', 'http-spm-free-type4', 'iddos-l3-entry-create', 'iddos-l3-entry-delete', 'iddos-l4-entry-create', 'iddos-l4-entry-delete'
                    ]
                }
            },
        'source_address': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'tcp_svr_status': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'nat_resource_exhausted': {
            'type': 'dict',
            'level': {
                'type': 'str',
                'choices': ['warning', 'critical', 'notice']
                },
            'uuid': {
                'type': 'str',
                }
            },
        'nat_quota_exceeded': {
            'type': 'dict',
            'level': {
                'type': 'str',
                'choices': ['warning', 'critical', 'notice']
                },
            'uuid': {
                'type': 'str',
                }
            },
        'pool_based_log': {
            'type': 'dict',
            'cycle': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'stats': {
            'type': 'dict',
            'tcp_session_created': {
                'type': 'str',
                },
            'tcp_session_deleted': {
                'type': 'str',
                },
            'tcp_port_allocated': {
                'type': 'str',
                },
            'tcp_port_freed': {
                'type': 'str',
                },
            'tcp_port_batch_allocated': {
                'type': 'str',
                },
            'tcp_port_batch_freed': {
                'type': 'str',
                },
            'udp_session_created': {
                'type': 'str',
                },
            'udp_session_deleted': {
                'type': 'str',
                },
            'udp_port_allocated': {
                'type': 'str',
                },
            'udp_port_freed': {
                'type': 'str',
                },
            'udp_port_batch_allocated': {
                'type': 'str',
                },
            'udp_port_batch_freed': {
                'type': 'str',
                },
            'icmp_session_created': {
                'type': 'str',
                },
            'icmp_session_deleted': {
                'type': 'str',
                },
            'icmp_resource_allocated': {
                'type': 'str',
                },
            'icmp_resource_freed': {
                'type': 'str',
                },
            'icmpv6_session_created': {
                'type': 'str',
                },
            'icmpv6_session_deleted': {
                'type': 'str',
                },
            'icmpv6_resource_allocated': {
                'type': 'str',
                },
            'icmpv6_resource_freed': {
                'type': 'str',
                },
            'gre_session_created': {
                'type': 'str',
                },
            'gre_session_deleted': {
                'type': 'str',
                },
            'gre_resource_allocated': {
                'type': 'str',
                },
            'gre_resource_freed': {
                'type': 'str',
                },
            'esp_session_created': {
                'type': 'str',
                },
            'esp_session_deleted': {
                'type': 'str',
                },
            'esp_resource_allocated': {
                'type': 'str',
                },
            'esp_resource_freed': {
                'type': 'str',
                },
            'fixed_nat_user_ports': {
                'type': 'str',
                },
            'fixed_nat_disable_config_logged': {
                'type': 'str',
                },
            'fixed_nat_disable_config_logs_sent': {
                'type': 'str',
                },
            'fixed_nat_periodic_config_logs_sent': {
                'type': 'str',
                },
            'fixed_nat_periodic_config_logged': {
                'type': 'str',
                },
            'fixed_nat_interim_updated': {
                'type': 'str',
                },
            'enhanced_user_log': {
                'type': 'str',
                },
            'log_sent': {
                'type': 'str',
                },
            'log_dropped': {
                'type': 'str',
                },
            'conn_tcp_established': {
                'type': 'str',
                },
            'conn_tcp_dropped': {
                'type': 'str',
                },
            'tcp_port_overloading_allocated': {
                'type': 'str',
                },
            'tcp_port_overloading_freed': {
                'type': 'str',
                },
            'udp_port_overloading_allocated': {
                'type': 'str',
                },
            'udp_port_overloading_freed': {
                'type': 'str',
                },
            'http_request_logged': {
                'type': 'str',
                },
            'reduced_logs_by_destination': {
                'type': 'str',
                },
            'interim_update_scheduled': {
                'type': 'str',
                },
            'tcp_port_batch_interim_updated': {
                'type': 'str',
                },
            'udp_port_batch_interim_updated': {
                'type': 'str',
                },
            'iddos_l3_entry_create': {
                'type': 'str',
                },
            'iddos_l3_entry_delete': {
                'type': 'str',
                },
            'iddos_l4_entry_create': {
                'type': 'str',
                },
            'iddos_l4_entry_delete': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/logging"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/logging"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["logging"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["logging"].get(k) != v:
            change_results["changed"] = True
            config_changes["logging"][k] = v

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
    payload = utils.build_json("logging", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["logging"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["logging-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["logging"]["stats"] if info != "NotFound" else info
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
