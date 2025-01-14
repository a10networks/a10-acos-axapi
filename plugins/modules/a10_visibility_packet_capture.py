#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_visibility_packet_capture
description:
    - Configure automated packet capture
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
    capture_config_list:
        description:
        - "Field capture_config_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Specify the name of the capture-config"
                type: str
            disable:
                description:
                - "Disable packet capture (default enabled)"
                type: bool
            concurrent_captures:
                description:
                - "Enable and specify maximum concurrent 3 tuple filter based captures in seperate
          pcaps."
                type: int
            concurrent_conn_per_capture:
                description:
                - "Specify maximum number of concurrent connnections(5 tuple matches) to be
          captured within in a 3 tuple based capture. (default 1"
                type: int
            concurrent_captures_age:
                description:
                - "Specify the time in minutes upto which a 3 tuple filter based capture will be
          kept active(default 1)"
                type: int
            concurrent_conn_tag:
                description:
                - "Enable and specify maximum concurrent connnections(only 5 tuple based) to be
          captured in common pcaps."
                type: int
            number_of_packets_per_conn:
                description:
                - "Specify maximum number of packets to be captured in a 5 tuple based connection
          (default 0 unlimited)."
                type: int
            packet_length:
                description:
                - "Packet length in Bytes to capture (Default 128)"
                type: int
            file_size:
                description:
                - "Specify pcapng filesize in MB, Will be distributed per CPU (default 1)"
                type: int
            file_count:
                description:
                - "Specify the number of continuous pcapng files that can be created for capturing
          packets (default 10)"
                type: int
            number_of_packets_per_capture:
                description:
                - "Specify Maximum number of packets per global or dynamic capture (default 0
          unlimited)"
                type: int
            number_of_packets_total:
                description:
                - "Specify Maximum number of packets for all captures (default 0 unlimited)"
                type: int
            enable_continuous_global_capture:
                description:
                - "Enable continuous capture of packets for the global capture(non 3 tuple based
          capture) overriding size limits"
                type: bool
            create_pcap_files_now:
                description:
                - "Operational command to force create temporary pcapng files before completion
          (for global/non 3 tuple based captures)"
                type: bool
            disable_auto_merge:
                description:
                - "Disable auto merging per CPU pcapng files(default enabled)"
                type: bool
            keep_pcap_files_after_merge:
                description:
                - "Keep original per CPU pcapng files after auto merging pcapng files(default
          disabled)"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    delete_packet_capture_file:
        description:
        - "Field delete_packet_capture_file"
        type: dict
        required: False
        suboptions:
            file_name:
                description:
                - "Specify the name of the packet capture file to be deleted"
                type: str
            all:
                description:
                - "Delete all files in this partition"
                type: bool
    global_templates:
        description:
        - "Field global_templates"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            template_list:
                description:
                - "Field template_list"
                type: list
            activate:
                description:
                - "Field activate"
                type: dict
    object_templates:
        description:
        - "Field object_templates"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
            templ_gtp_plcy_tmpl_list:
                description:
                - "Field templ_gtp_plcy_tmpl_list"
                type: list
            interface_ethernet_tmpl_list:
                description:
                - "Field interface_ethernet_tmpl_list"
                type: list
            interface_tunnel_tmpl_list:
                description:
                - "Field interface_tunnel_tmpl_list"
                type: list
            aam_jwt_authorization_tmpl_list:
                description:
                - "Field aam_jwt_authorization_tmpl_list"
                type: list
            aam_aaa_policy_tmpl_list:
                description:
                - "Field aam_aaa_policy_tmpl_list"
                type: list
            aam_auth_logon_http_ins_tmpl_list:
                description:
                - "Field aam_auth_logon_http_ins_tmpl_list"
                type: list
            aam_auth_server_ldap_inst_tmpl_list:
                description:
                - "Field aam_auth_server_ldap_inst_tmpl_list"
                type: list
            aam_auth_server_ocsp_inst_tmpl_list:
                description:
                - "Field aam_auth_server_ocsp_inst_tmpl_list"
                type: list
            aam_auth_server_rad_inst_tmpl_list:
                description:
                - "Field aam_auth_server_rad_inst_tmpl_list"
                type: list
            aam_auth_server_win_inst_tmpl_list:
                description:
                - "Field aam_auth_server_win_inst_tmpl_list"
                type: list
            aam_auth_saml_service_prov_tmpl_list:
                description:
                - "Field aam_auth_saml_service_prov_tmpl_list"
                type: list
            aam_auth_saml_id_prov_tmpl_list:
                description:
                - "Field aam_auth_saml_id_prov_tmpl_list"
                type: list
            aam_auth_service_group_tmpl_list:
                description:
                - "Field aam_auth_service_group_tmpl_list"
                type: list
            aam_auth_service_group_mem_tmpl_list:
                description:
                - "Field aam_auth_service_group_mem_tmpl_list"
                type: list
            aam_auth_relay_hbase_inst_tmpl_list:
                description:
                - "Field aam_auth_relay_hbase_inst_tmpl_list"
                type: list
            aam_auth_relay_form_inst_tmpl_list:
                description:
                - "Field aam_auth_relay_form_inst_tmpl_list"
                type: list
            aam_auth_relay_ws_fed_tmpl_list:
                description:
                - "Field aam_auth_relay_ws_fed_tmpl_list"
                type: list
            aam_auth_captcha_inst_tmpl_list:
                description:
                - "Field aam_auth_captcha_inst_tmpl_list"
                type: list
            slb_templ_cache_tmpl_list:
                description:
                - "Field slb_templ_cache_tmpl_list"
                type: list
            slb_port_tmpl_list:
                description:
                - "Field slb_port_tmpl_list"
                type: list
            slb_service_tmpl_list:
                description:
                - "Field slb_service_tmpl_list"
                type: list
            slb_vport_tmpl_list:
                description:
                - "Field slb_vport_tmpl_list"
                type: list
            cgnv6_serv_group_tmpl_list:
                description:
                - "Field cgnv6_serv_group_tmpl_list"
                type: list
            cgnv6_dns64_vs_port_tmpl_list:
                description:
                - "Field cgnv6_dns64_vs_port_tmpl_list"
                type: list
            cgnv6_map_trans_domain_tmpl_list:
                description:
                - "Field cgnv6_map_trans_domain_tmpl_list"
                type: list
            cgnv6_encap_domain_tmpl_list:
                description:
                - "Field cgnv6_encap_domain_tmpl_list"
                type: list
            netflow_monitor_tmpl_list:
                description:
                - "Field netflow_monitor_tmpl_list"
                type: list
            rule_set_tmpl_list:
                description:
                - "Field rule_set_tmpl_list"
                type: list
            rule_set_rule_tmpl_list:
                description:
                - "Field rule_set_rule_tmpl_list"
                type: list
            fw_server_port_tmpl_list:
                description:
                - "Field fw_server_port_tmpl_list"
                type: list
            fw_service_group_tmpl_list:
                description:
                - "Field fw_service_group_tmpl_list"
                type: list
            fw_service_group_mem_tmpl_list:
                description:
                - "Field fw_service_group_mem_tmpl_list"
                type: list
            dns_vport_tmpl_list:
                description:
                - "Field dns_vport_tmpl_list"
                type: list
            smtp_vport_tmpl_list:
                description:
                - "Field smtp_vport_tmpl_list"
                type: list
            pop3_vport_tmpl_list:
                description:
                - "Field pop3_vport_tmpl_list"
                type: list
            imap_vport_tmpl_list:
                description:
                - "Field imap_vport_tmpl_list"
                type: list
    automated_captures:
        description:
        - "Field automated_captures"
        type: dict
        required: False
        suboptions:
            slb_port_tmpl_error_code_return_inc:
                description:
                - "Trigger capture when there is 3xx or 4xx or 5xx responses from server"
                type: bool
            slb_port_tmpl_high_error_code_return:
                description:
                - "Trigger capture when there is high number of 3xx or 4xx or 5xx responses from
          server"
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
            packet_capture_files:
                description:
                - "Field packet_capture_files"
                type: bool
            memory_usage:
                description:
                - "Field memory_usage"
                type: bool
            total_number_of_files:
                description:
                - "Field total_number_of_files"
                type: int
            packet_capture_file_name_list:
                description:
                - "Field packet_capture_file_name_list"
                type: list
            total_memory:
                description:
                - "Field total_memory"
                type: str
            used_memory:
                description:
                - "Field used_memory"
                type: str
            automated_captures:
                description:
                - "Field automated_captures"
                type: dict
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            Concurrent_capture_created_by_ctr_increment:
                description:
                - "Dynamic 3 tuple based capture created (ctr increment based)"
                type: str
            Concurrent_capture_created_by_ctr_anomaly:
                description:
                - "Dynamic 3 tuple based capture created (ctr anomaly based)"
                type: str
            Concurrent_capture_created_by_other_feature:
                description:
                - "Dynamic 3 tuple based capture created (Other feature based)"
                type: str
            Concurrent_capture_create_failed_by_ctr_increment:
                description:
                - "Error, Dynamic Capture(ctr increment based) create failed"
                type: str
            Concurrent_capture_create_failed_by_ctr_anomaly:
                description:
                - "Error, Dynamic Capture(ctr anomaly based) create failed"
                type: str
            Concurrent_capture_create_failed_by_other_feature:
                description:
                - "Error, Dynamic Capture(Other feature based) create failed"
                type: str
            Concurrent_capture_create_failed_oom:
                description:
                - "Error, Dynamic Capture create failed, OOM"
                type: str
            Concurrent_capture_limit_reached:
                description:
                - "Dynamic Capture configured concurrent limit reached"
                type: str
            Concurrent_capture_by_ctr_increment_freed:
                description:
                - "Dynamic Capture(ctr increment based) freed"
                type: str
            Concurrent_capture_by_ctr_anomaly_freed:
                description:
                - "Dynamic Capture(ctr anomaly based) freed"
                type: str
            Concurrent_capture_by_ctr_other_feature_freed:
                description:
                - "Dynamic Capture(Other feature based) freed"
                type: str
            Global_capture_finished:
                description:
                - "Number of times global capture finished capturing"
                type: str
            Concurrent_capture_finished:
                description:
                - "Number of Dynamic captures(3 tuple based) finished capturing"
                type: str
            pktcapture_with_no_conn_success:
                description:
                - "Capture success, Packets without conn"
                type: str
            pktcapture_with_no_conn_failure:
                description:
                - "Capture fail, Packets without conn"
                type: str
            pktcapture_with_conn_but_not_tagged_success:
                description:
                - "Capture success, Packets with untagged conn"
                type: str
            pktcapture_with_conn_but_not_tagged_failure:
                description:
                - "Capture fail, Packets with untagged conn"
                type: str
            pktcapture_with_conn_success_global:
                description:
                - "Capture success, Packets with tagged conn (global capture)"
                type: str
            pktcapture_with_conn_success:
                description:
                - "Capture success, Packets with tagged conn (dynamic capture)"
                type: str
            pktcapture_with_conn_failure_global:
                description:
                - "Capture fail, Packets with tagged conn (global capture)"
                type: str
            pktcapture_with_conn_failure:
                description:
                - "Capture fail, Packets with tagged conn (dynamic capture)"
                type: str
            pktcapture_failure_wait_for_block:
                description:
                - "Capture fail, waiting to get free buffer"
                type: str
            pktcapture_failure_file_size_rchd:
                description:
                - "Capture fail, file size reached"
                type: str
            num_conns_tagged_global_increment:
                description:
                - "Conn tag success (based on ctr increment, Global)"
                type: str
            num_conns_tagged_global_anomaly:
                description:
                - "Conn tag success (based on ctr anomaly, Global)"
                type: str
            num_conns_tagged_global_other_feature:
                description:
                - "Conn tag success (based on Other feature, Global)"
                type: str
            num_conns_tagged_global_increment_fail:
                description:
                - "Conn tag fail (based on ctr increment, Global)"
                type: str
            num_conns_tagged_global_anomaly_fail:
                description:
                - "Conn tag fail (based on ctr anomaly, Global)"
                type: str
            num_conns_tagged_global_other_feature_fail:
                description:
                - "Conn tag fail (based on Other feature, Global)"
                type: str
            num_conns_tagged_global_increment_maxed:
                description:
                - "Conn tag fail, reached limit (based on ctr increment, Global)"
                type: str
            num_conns_tagged_global_anomaly_maxed:
                description:
                - "Conn tag fail, reached limit (based on ctr anomaly, Global)"
                type: str
            num_conns_tagged_global_other_feature_maxed:
                description:
                - "Conn tag fail, reached limit (based on Other feature, Global)"
                type: str
            num_conns_tagged_increment:
                description:
                - "Conn tag success (based on ctr increment, dynamic)"
                type: str
            num_conns_tagged_anomaly:
                description:
                - "Conn tag success (based on ctr anomaly, dynamic)"
                type: str
            num_conns_tagged_other_feature:
                description:
                - "Conn tag success (based on Other feature, dynamic)"
                type: str
            num_conns_tagged_increment_fail:
                description:
                - "Conn tag fail (based on ctr increment, dynamic)"
                type: str
            num_conns_tagged_anomaly_fail:
                description:
                - "Conn tag fail (based on ctr anomaly, dynamic)"
                type: str
            num_conns_tagged_other_feature_fail:
                description:
                - "Conn tag fail (based on Other feature, dynamic)"
                type: str
            num_conns_tagged_increment_maxed:
                description:
                - "Conn tag fail, reached limit (based on ctr increment, dynamic)"
                type: str
            num_conns_tagged_anomaly_maxed:
                description:
                - "Conn tag fail, reached limit (based on ctr anomaly, dynamic)"
                type: str
            num_conns_tagged_other_feature_maxed:
                description:
                - "Conn tag fail, reached limit (based on Other feature, dynamic)"
                type: str
            num_conns_untagged:
                description:
                - "Number of conns untagged (done with conn limit or capture)"
                type: str
            pktcapture_triggered_by_increment:
                description:
                - "Capture triggered by counter increment"
                type: str
            pktcapture_triggered_by_anomaly:
                description:
                - "Capture triggered by counter anomaly"
                type: str
            pktcapture_triggered_by_other_feature:
                description:
                - "Capture triggered by Other feature"
                type: str
            num_of_anomalies_detected:
                description:
                - "Number of times ctr Anomaly detected"
                type: str
            num_of_anomalies_cleared:
                description:
                - "Number of times ctr Anomaly cleared"
                type: str
            num_pcaps_created:
                description:
                - "Number of pcapng files created"
                type: str
            num_tmp_pcaps_created:
                description:
                - "Number of temporary pcapng files created"
                type: str
            num_pcaps_create_failed:
                description:
                - "Error, Number of pcapng files creation failed"
                type: str
            pktcap_oom:
                description:
                - "Error, Automated Packet capture infra OOM"
                type: str
            failed_disk_full:
                description:
                - "Error, Capture fail, Disk limit reached"
                type: str
            conn_ext_failed:
                description:
                - "Error, Conn extension creation fail"
                type: str
            skip_as_conn_already_recapture:
                description:
                - "Skip creating capture, conn was already captured"
                type: str
            skip_capture_as_conn_created_before_smp:
                description:
                - "Skip capturing, conn was created before the capture started"
                type: str
            failed_as_return_completed_set:
                description:
                - "Skip capturing, capture-config marked completed"
                type: str
            non_pkt_path:
                description:
                - "Skip capturing, not packet processing path"
                type: str
            pkt_already_captured:
                description:
                - "Skip capturing, packet already captured"
                type: str
            wrong_ctr_incremented:
                description:
                - "Counter increment issue"
                type: str
            auto_pcap_file_merged:
                description:
                - "Auto pcapng files merged"
                type: str
            auto_pcap_file_merged_failed:
                description:
                - "Auto pcapng files merged failed"
                type: str
            num_global_tmpl_created:
                description:
                - "Number of global templates created"
                type: str
            num_object_tmpl_created:
                description:
                - "Number of object templates created"
                type: str
            num_global_tmpl_deleted:
                description:
                - "Number of global templates deleted"
                type: str
            num_object_tmpl_deleted:
                description:
                - "Number of object templates deleted"
                type: str
            num_capture_config_created:
                description:
                - "Number of capture-config created"
                type: str
            num_dynamic_capture_config_created:
                description:
                - "Number of dynamic capture-config created"
                type: str
            num_capture_config_deleted:
                description:
                - "Number of capture-config deleted"
                type: str
            num_dynamic_capture_config_deleted:
                description:
                - "Number of dynamic capture-config deleted"
                type: str
            num_capture_config_delete_q:
                description:
                - "Number of capture-config set for deletion"
                type: str
            num_dynamic_capture_config_delete_q:
                description:
                - "Number of dynamic capture-config set for deletion"
                type: str
            num_capture_config_linked:
                description:
                - "Number of times capture-config linked to template"
                type: str
            num_dynamic_capture_config_linked:
                description:
                - "Number of times dynamic capture-config linked to template"
                type: str
            num_capture_config_unlinked:
                description:
                - "Number of times capture-config unlinked from template"
                type: str
            num_dynamic_capture_config_unlinked:
                description:
                - "Number of times dynamic capture-config unlinked from template"
                type: str
            num_global_counters_registered:
                description:
                - "Number of global objects registered"
                type: str
            num_global_counters_deregistered:
                description:
                - "Number of global objects deregistered"
                type: str
            num_per_object_counters_registered:
                description:
                - "Number of per instance objects registered"
                type: str
            num_per_object_counters_deregistered:
                description:
                - "Number of per instance objects deregistered"
                type: str
            capture_config_list:
                description:
                - "Field capture_config_list"
                type: list
            automated_captures:
                description:
                - "Field automated_captures"
                type: dict

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
AVAILABLE_PROPERTIES = ["automated_captures", "capture_config_list", "delete_packet_capture_file", "global_templates", "object_templates", "oper", "stats", "uuid", ]


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
        'capture_config_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'disable': {
                'type': 'bool',
                },
            'concurrent_captures': {
                'type': 'int',
                },
            'concurrent_conn_per_capture': {
                'type': 'int',
                },
            'concurrent_captures_age': {
                'type': 'int',
                },
            'concurrent_conn_tag': {
                'type': 'int',
                },
            'number_of_packets_per_conn': {
                'type': 'int',
                },
            'packet_length': {
                'type': 'int',
                },
            'file_size': {
                'type': 'int',
                },
            'file_count': {
                'type': 'int',
                },
            'number_of_packets_per_capture': {
                'type': 'int',
                },
            'number_of_packets_total': {
                'type': 'int',
                },
            'enable_continuous_global_capture': {
                'type': 'bool',
                },
            'create_pcap_files_now': {
                'type': 'bool',
                },
            'disable_auto_merge': {
                'type': 'bool',
                },
            'keep_pcap_files_after_merge': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            },
        'delete_packet_capture_file': {
            'type': 'dict',
            'file_name': {
                'type': 'str',
                },
            'all': {
                'type': 'bool',
                }
            },
        'global_templates': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                },
            'template_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_sys_obj_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_sys_obj_stats_change': {
                    'type': 'dict',
                    'uuid': {
                        'type': 'str',
                        },
                    'system_ctr_lib_acct': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'total_nodes_free_failed': {
                                'type': 'bool',
                                },
                            'total_nodes_unlink_failed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'total_nodes_free_failed': {
                                'type': 'bool',
                                },
                            'total_nodes_unlink_failed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'system_hardware_accelerate': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'hw_fwd_prog_errors': {
                                'type': 'bool',
                                },
                            'hw_fwd_flow_singlebit_errors': {
                                'type': 'bool',
                                },
                            'hw_fwd_flow_tag_mismatch': {
                                'type': 'bool',
                                },
                            'hw_fwd_flow_seq_mismatch': {
                                'type': 'bool',
                                },
                            'hw_fwd_flow_error_count': {
                                'type': 'bool',
                                },
                            'hw_fwd_flow_unalign_count': {
                                'type': 'bool',
                                },
                            'hw_fwd_flow_underflow_count': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'hw_fwd_prog_errors': {
                                'type': 'bool',
                                },
                            'hw_fwd_flow_singlebit_errors': {
                                'type': 'bool',
                                },
                            'hw_fwd_flow_tag_mismatch': {
                                'type': 'bool',
                                },
                            'hw_fwd_flow_seq_mismatch': {
                                'type': 'bool',
                                },
                            'hw_fwd_flow_error_count': {
                                'type': 'bool',
                                },
                            'hw_fwd_flow_unalign_count': {
                                'type': 'bool',
                                },
                            'hw_fwd_flow_underflow_count': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'system_radius_server': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'radius_request_dropped': {
                                'type': 'bool',
                                },
                            'request_bad_secret_dropped': {
                                'type': 'bool',
                                },
                            'request_no_key_vap_dropped': {
                                'type': 'bool',
                                },
                            'request_malformed_dropped': {
                                'type': 'bool',
                                },
                            'radius_table_full': {
                                'type': 'bool',
                                },
                            'secret_not_configured_dropped': {
                                'type': 'bool',
                                },
                            'ha_standby_dropped': {
                                'type': 'bool',
                                },
                            'ipv6_prefix_length_mismatch': {
                                'type': 'bool',
                                },
                            'invalid_key': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'radius_request_dropped': {
                                'type': 'bool',
                                },
                            'request_bad_secret_dropped': {
                                'type': 'bool',
                                },
                            'request_no_key_vap_dropped': {
                                'type': 'bool',
                                },
                            'request_malformed_dropped': {
                                'type': 'bool',
                                },
                            'radius_table_full': {
                                'type': 'bool',
                                },
                            'secret_not_configured_dropped': {
                                'type': 'bool',
                                },
                            'ha_standby_dropped': {
                                'type': 'bool',
                                },
                            'ipv6_prefix_length_mismatch': {
                                'type': 'bool',
                                },
                            'invalid_key': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'system_ip_threat_list': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'error_out_of_memory': {
                                'type': 'bool',
                                },
                            'error_out_of_spe_entries': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'error_out_of_memory': {
                                'type': 'bool',
                                },
                            'error_out_of_spe_entries': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'system_fpga_drop': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'mrx_drop': {
                                'type': 'bool',
                                },
                            'hrx_drop': {
                                'type': 'bool',
                                },
                            'siz_drop': {
                                'type': 'bool',
                                },
                            'fcs_drop': {
                                'type': 'bool',
                                },
                            'land_drop': {
                                'type': 'bool',
                                },
                            'empty_frag_drop': {
                                'type': 'bool',
                                },
                            'mic_frag_drop': {
                                'type': 'bool',
                                },
                            'ipv4_opt_drop': {
                                'type': 'bool',
                                },
                            'ipv4_frag': {
                                'type': 'bool',
                                },
                            'bad_ip_hdr_len': {
                                'type': 'bool',
                                },
                            'bad_ip_flags_drop': {
                                'type': 'bool',
                                },
                            'bad_ip_ttl_drop': {
                                'type': 'bool',
                                },
                            'no_ip_payload_drop': {
                                'type': 'bool',
                                },
                            'oversize_ip_payload': {
                                'type': 'bool',
                                },
                            'bad_ip_payload_len': {
                                'type': 'bool',
                                },
                            'bad_ip_frag_offset': {
                                'type': 'bool',
                                },
                            'bad_ip_chksum_drop': {
                                'type': 'bool',
                                },
                            'icmp_pod_drop': {
                                'type': 'bool',
                                },
                            'tcp_bad_urg_offet': {
                                'type': 'bool',
                                },
                            'tcp_short_hdr': {
                                'type': 'bool',
                                },
                            'tcp_bad_ip_len': {
                                'type': 'bool',
                                },
                            'tcp_null_flags': {
                                'type': 'bool',
                                },
                            'tcp_null_scan': {
                                'type': 'bool',
                                },
                            'tcp_fin_sin': {
                                'type': 'bool',
                                },
                            'tcp_xmas_flags': {
                                'type': 'bool',
                                },
                            'tcp_xmas_scan': {
                                'type': 'bool',
                                },
                            'tcp_syn_frag': {
                                'type': 'bool',
                                },
                            'tcp_frag_hdr': {
                                'type': 'bool',
                                },
                            'tcp_bad_chksum': {
                                'type': 'bool',
                                },
                            'udp_short_hdr': {
                                'type': 'bool',
                                },
                            'udp_bad_ip_len': {
                                'type': 'bool',
                                },
                            'udp_kb_frags': {
                                'type': 'bool',
                                },
                            'udp_port_lb': {
                                'type': 'bool',
                                },
                            'udp_bad_chksum': {
                                'type': 'bool',
                                },
                            'runt_ip_hdr': {
                                'type': 'bool',
                                },
                            'runt_tcpudp_hdr': {
                                'type': 'bool',
                                },
                            'tun_mismatch': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'mrx_drop': {
                                'type': 'bool',
                                },
                            'hrx_drop': {
                                'type': 'bool',
                                },
                            'siz_drop': {
                                'type': 'bool',
                                },
                            'fcs_drop': {
                                'type': 'bool',
                                },
                            'land_drop': {
                                'type': 'bool',
                                },
                            'empty_frag_drop': {
                                'type': 'bool',
                                },
                            'mic_frag_drop': {
                                'type': 'bool',
                                },
                            'ipv4_opt_drop': {
                                'type': 'bool',
                                },
                            'ipv4_frag': {
                                'type': 'bool',
                                },
                            'bad_ip_hdr_len': {
                                'type': 'bool',
                                },
                            'bad_ip_flags_drop': {
                                'type': 'bool',
                                },
                            'bad_ip_ttl_drop': {
                                'type': 'bool',
                                },
                            'no_ip_payload_drop': {
                                'type': 'bool',
                                },
                            'oversize_ip_payload': {
                                'type': 'bool',
                                },
                            'bad_ip_payload_len': {
                                'type': 'bool',
                                },
                            'bad_ip_frag_offset': {
                                'type': 'bool',
                                },
                            'bad_ip_chksum_drop': {
                                'type': 'bool',
                                },
                            'icmp_pod_drop': {
                                'type': 'bool',
                                },
                            'tcp_bad_urg_offet': {
                                'type': 'bool',
                                },
                            'tcp_short_hdr': {
                                'type': 'bool',
                                },
                            'tcp_bad_ip_len': {
                                'type': 'bool',
                                },
                            'tcp_null_flags': {
                                'type': 'bool',
                                },
                            'tcp_null_scan': {
                                'type': 'bool',
                                },
                            'tcp_fin_sin': {
                                'type': 'bool',
                                },
                            'tcp_xmas_flags': {
                                'type': 'bool',
                                },
                            'tcp_xmas_scan': {
                                'type': 'bool',
                                },
                            'tcp_syn_frag': {
                                'type': 'bool',
                                },
                            'tcp_frag_hdr': {
                                'type': 'bool',
                                },
                            'tcp_bad_chksum': {
                                'type': 'bool',
                                },
                            'udp_short_hdr': {
                                'type': 'bool',
                                },
                            'udp_bad_ip_len': {
                                'type': 'bool',
                                },
                            'udp_kb_frags': {
                                'type': 'bool',
                                },
                            'udp_port_lb': {
                                'type': 'bool',
                                },
                            'udp_bad_chksum': {
                                'type': 'bool',
                                },
                            'runt_ip_hdr': {
                                'type': 'bool',
                                },
                            'runt_tcpudp_hdr': {
                                'type': 'bool',
                                },
                            'tun_mismatch': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'system_dpdk_stats': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'pkt_drop': {
                                'type': 'bool',
                                },
                            'pkt_lnk_down_drop': {
                                'type': 'bool',
                                },
                            'err_pkt_drop': {
                                'type': 'bool',
                                },
                            'rx_err': {
                                'type': 'bool',
                                },
                            'tx_err': {
                                'type': 'bool',
                                },
                            'tx_drop': {
                                'type': 'bool',
                                },
                            'rx_len_err': {
                                'type': 'bool',
                                },
                            'rx_over_err': {
                                'type': 'bool',
                                },
                            'rx_crc_err': {
                                'type': 'bool',
                                },
                            'rx_frame_err': {
                                'type': 'bool',
                                },
                            'rx_no_buff_err': {
                                'type': 'bool',
                                },
                            'rx_miss_err': {
                                'type': 'bool',
                                },
                            'tx_abort_err': {
                                'type': 'bool',
                                },
                            'tx_carrier_err': {
                                'type': 'bool',
                                },
                            'tx_fifo_err': {
                                'type': 'bool',
                                },
                            'tx_hbeat_err': {
                                'type': 'bool',
                                },
                            'tx_windows_err': {
                                'type': 'bool',
                                },
                            'rx_long_len_err': {
                                'type': 'bool',
                                },
                            'rx_short_len_err': {
                                'type': 'bool',
                                },
                            'rx_align_err': {
                                'type': 'bool',
                                },
                            'rx_csum_offload_err': {
                                'type': 'bool',
                                },
                            'io_rx_que_drop': {
                                'type': 'bool',
                                },
                            'io_tx_que_drop': {
                                'type': 'bool',
                                },
                            'io_ring_drop': {
                                'type': 'bool',
                                },
                            'w_tx_que_drop': {
                                'type': 'bool',
                                },
                            'w_link_down_drop': {
                                'type': 'bool',
                                },
                            'w_ring_drop': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'pkt_drop': {
                                'type': 'bool',
                                },
                            'pkt_lnk_down_drop': {
                                'type': 'bool',
                                },
                            'err_pkt_drop': {
                                'type': 'bool',
                                },
                            'rx_err': {
                                'type': 'bool',
                                },
                            'tx_err': {
                                'type': 'bool',
                                },
                            'tx_drop': {
                                'type': 'bool',
                                },
                            'rx_len_err': {
                                'type': 'bool',
                                },
                            'rx_over_err': {
                                'type': 'bool',
                                },
                            'rx_crc_err': {
                                'type': 'bool',
                                },
                            'rx_frame_err': {
                                'type': 'bool',
                                },
                            'rx_no_buff_err': {
                                'type': 'bool',
                                },
                            'rx_miss_err': {
                                'type': 'bool',
                                },
                            'tx_abort_err': {
                                'type': 'bool',
                                },
                            'tx_carrier_err': {
                                'type': 'bool',
                                },
                            'tx_fifo_err': {
                                'type': 'bool',
                                },
                            'tx_hbeat_err': {
                                'type': 'bool',
                                },
                            'tx_windows_err': {
                                'type': 'bool',
                                },
                            'rx_long_len_err': {
                                'type': 'bool',
                                },
                            'rx_short_len_err': {
                                'type': 'bool',
                                },
                            'rx_align_err': {
                                'type': 'bool',
                                },
                            'rx_csum_offload_err': {
                                'type': 'bool',
                                },
                            'io_rx_que_drop': {
                                'type': 'bool',
                                },
                            'io_tx_que_drop': {
                                'type': 'bool',
                                },
                            'io_ring_drop': {
                                'type': 'bool',
                                },
                            'w_tx_que_drop': {
                                'type': 'bool',
                                },
                            'w_link_down_drop': {
                                'type': 'bool',
                                },
                            'w_ring_drop': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'ip_anomaly_drop': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'land': {
                                'type': 'bool',
                                },
                            'emp_frg': {
                                'type': 'bool',
                                },
                            'emp_mic_frg': {
                                'type': 'bool',
                                },
                            'opt': {
                                'type': 'bool',
                                },
                            'frg': {
                                'type': 'bool',
                                },
                            'bad_ip_hdrlen': {
                                'type': 'bool',
                                },
                            'bad_ip_flg': {
                                'type': 'bool',
                                },
                            'bad_ip_ttl': {
                                'type': 'bool',
                                },
                            'no_ip_payload': {
                                'type': 'bool',
                                },
                            'over_ip_payload': {
                                'type': 'bool',
                                },
                            'bad_ip_payload_len': {
                                'type': 'bool',
                                },
                            'bad_ip_frg_offset': {
                                'type': 'bool',
                                },
                            'csum': {
                                'type': 'bool',
                                },
                            'pod': {
                                'type': 'bool',
                                },
                            'bad_tcp_urg_offset': {
                                'type': 'bool',
                                },
                            'tcp_sht_hdr': {
                                'type': 'bool',
                                },
                            'tcp_bad_iplen': {
                                'type': 'bool',
                                },
                            'tcp_null_frg': {
                                'type': 'bool',
                                },
                            'tcp_null_scan': {
                                'type': 'bool',
                                },
                            'tcp_syn_fin': {
                                'type': 'bool',
                                },
                            'tcp_xmas': {
                                'type': 'bool',
                                },
                            'tcp_xmas_scan': {
                                'type': 'bool',
                                },
                            'tcp_syn_frg': {
                                'type': 'bool',
                                },
                            'tcp_frg_hdr': {
                                'type': 'bool',
                                },
                            'tcp_bad_csum': {
                                'type': 'bool',
                                },
                            'udp_srt_hdr': {
                                'type': 'bool',
                                },
                            'udp_bad_len': {
                                'type': 'bool',
                                },
                            'udp_kerb_frg': {
                                'type': 'bool',
                                },
                            'udp_port_lb': {
                                'type': 'bool',
                                },
                            'udp_bad_csum': {
                                'type': 'bool',
                                },
                            'runt_ip_hdr': {
                                'type': 'bool',
                                },
                            'runt_tcp_udp_hdr': {
                                'type': 'bool',
                                },
                            'ipip_tnl_msmtch': {
                                'type': 'bool',
                                },
                            'tcp_opt_err': {
                                'type': 'bool',
                                },
                            'ipip_tnl_err': {
                                'type': 'bool',
                                },
                            'vxlan_err': {
                                'type': 'bool',
                                },
                            'nvgre_err': {
                                'type': 'bool',
                                },
                            'gre_pptp_err': {
                                'type': 'bool',
                                },
                            'ipv6_eh_hbh': {
                                'type': 'bool',
                                },
                            'ipv6_eh_dest': {
                                'type': 'bool',
                                },
                            'ipv6_eh_routing': {
                                'type': 'bool',
                                },
                            'ipv6_eh_frag': {
                                'type': 'bool',
                                },
                            'ipv6_eh_ah': {
                                'type': 'bool',
                                },
                            'ipv6_eh_esp': {
                                'type': 'bool',
                                },
                            'ipv6_eh_mobility': {
                                'type': 'bool',
                                },
                            'ipv6_eh_none': {
                                'type': 'bool',
                                },
                            'ipv6_eh_other': {
                                'type': 'bool',
                                },
                            'ipv6_eh_malformed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'land': {
                                'type': 'bool',
                                },
                            'emp_frg': {
                                'type': 'bool',
                                },
                            'emp_mic_frg': {
                                'type': 'bool',
                                },
                            'opt': {
                                'type': 'bool',
                                },
                            'frg': {
                                'type': 'bool',
                                },
                            'bad_ip_hdrlen': {
                                'type': 'bool',
                                },
                            'bad_ip_flg': {
                                'type': 'bool',
                                },
                            'bad_ip_ttl': {
                                'type': 'bool',
                                },
                            'no_ip_payload': {
                                'type': 'bool',
                                },
                            'over_ip_payload': {
                                'type': 'bool',
                                },
                            'bad_ip_payload_len': {
                                'type': 'bool',
                                },
                            'bad_ip_frg_offset': {
                                'type': 'bool',
                                },
                            'csum': {
                                'type': 'bool',
                                },
                            'pod': {
                                'type': 'bool',
                                },
                            'bad_tcp_urg_offset': {
                                'type': 'bool',
                                },
                            'tcp_sht_hdr': {
                                'type': 'bool',
                                },
                            'tcp_bad_iplen': {
                                'type': 'bool',
                                },
                            'tcp_null_frg': {
                                'type': 'bool',
                                },
                            'tcp_null_scan': {
                                'type': 'bool',
                                },
                            'tcp_syn_fin': {
                                'type': 'bool',
                                },
                            'tcp_xmas': {
                                'type': 'bool',
                                },
                            'tcp_xmas_scan': {
                                'type': 'bool',
                                },
                            'tcp_syn_frg': {
                                'type': 'bool',
                                },
                            'tcp_frg_hdr': {
                                'type': 'bool',
                                },
                            'tcp_bad_csum': {
                                'type': 'bool',
                                },
                            'udp_srt_hdr': {
                                'type': 'bool',
                                },
                            'udp_bad_len': {
                                'type': 'bool',
                                },
                            'udp_kerb_frg': {
                                'type': 'bool',
                                },
                            'udp_port_lb': {
                                'type': 'bool',
                                },
                            'udp_bad_csum': {
                                'type': 'bool',
                                },
                            'runt_ip_hdr': {
                                'type': 'bool',
                                },
                            'runt_tcp_udp_hdr': {
                                'type': 'bool',
                                },
                            'ipip_tnl_msmtch': {
                                'type': 'bool',
                                },
                            'tcp_opt_err': {
                                'type': 'bool',
                                },
                            'ipip_tnl_err': {
                                'type': 'bool',
                                },
                            'vxlan_err': {
                                'type': 'bool',
                                },
                            'nvgre_err': {
                                'type': 'bool',
                                },
                            'gre_pptp_err': {
                                'type': 'bool',
                                },
                            'ipv6_eh_hbh': {
                                'type': 'bool',
                                },
                            'ipv6_eh_dest': {
                                'type': 'bool',
                                },
                            'ipv6_eh_routing': {
                                'type': 'bool',
                                },
                            'ipv6_eh_frag': {
                                'type': 'bool',
                                },
                            'ipv6_eh_ah': {
                                'type': 'bool',
                                },
                            'ipv6_eh_esp': {
                                'type': 'bool',
                                },
                            'ipv6_eh_mobility': {
                                'type': 'bool',
                                },
                            'ipv6_eh_none': {
                                'type': 'bool',
                                },
                            'ipv6_eh_other': {
                                'type': 'bool',
                                },
                            'ipv6_eh_malformed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'aam_authentication_global': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'misses': {
                                'type': 'bool',
                                },
                            'open_socket_failed': {
                                'type': 'bool',
                                },
                            'connect_failed': {
                                'type': 'bool',
                                },
                            'create_timer_failed': {
                                'type': 'bool',
                                },
                            'get_socket_option_failed': {
                                'type': 'bool',
                                },
                            'aflex_authz_fail': {
                                'type': 'bool',
                                },
                            'authn_failure': {
                                'type': 'bool',
                                },
                            'authz_failure': {
                                'type': 'bool',
                                },
                            'dns_resolve_failed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'misses': {
                                'type': 'bool',
                                },
                            'open_socket_failed': {
                                'type': 'bool',
                                },
                            'connect_failed': {
                                'type': 'bool',
                                },
                            'create_timer_failed': {
                                'type': 'bool',
                                },
                            'get_socket_option_failed': {
                                'type': 'bool',
                                },
                            'aflex_authz_fail': {
                                'type': 'bool',
                                },
                            'authn_failure': {
                                'type': 'bool',
                                },
                            'authz_failure': {
                                'type': 'bool',
                                },
                            'dns_resolve_failed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'aam_rdns': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'request_dropped': {
                                'type': 'bool',
                                },
                            'response_failure': {
                                'type': 'bool',
                                },
                            'response_error': {
                                'type': 'bool',
                                },
                            'response_timeout': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'request_dropped': {
                                'type': 'bool',
                                },
                            'response_failure': {
                                'type': 'bool',
                                },
                            'response_error': {
                                'type': 'bool',
                                },
                            'response_timeout': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'aam_auth_server_ldap': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'admin_bind_failure': {
                                'type': 'bool',
                                },
                            'bind_failure': {
                                'type': 'bool',
                                },
                            'search_failure': {
                                'type': 'bool',
                                },
                            'authorize_failure': {
                                'type': 'bool',
                                },
                            'timeout_error': {
                                'type': 'bool',
                                },
                            'other_error': {
                                'type': 'bool',
                                },
                            'request_dropped': {
                                'type': 'bool',
                                },
                            'response_failure': {
                                'type': 'bool',
                                },
                            'response_error': {
                                'type': 'bool',
                                },
                            'response_timeout': {
                                'type': 'bool',
                                },
                            'job_start_error': {
                                'type': 'bool',
                                },
                            'polling_control_error': {
                                'type': 'bool',
                                },
                            'ssl_session_failure': {
                                'type': 'bool',
                                },
                            'pw_change_failure': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'admin_bind_failure': {
                                'type': 'bool',
                                },
                            'bind_failure': {
                                'type': 'bool',
                                },
                            'search_failure': {
                                'type': 'bool',
                                },
                            'authorize_failure': {
                                'type': 'bool',
                                },
                            'timeout_error': {
                                'type': 'bool',
                                },
                            'other_error': {
                                'type': 'bool',
                                },
                            'request_dropped': {
                                'type': 'bool',
                                },
                            'response_failure': {
                                'type': 'bool',
                                },
                            'response_error': {
                                'type': 'bool',
                                },
                            'response_timeout': {
                                'type': 'bool',
                                },
                            'job_start_error': {
                                'type': 'bool',
                                },
                            'polling_control_error': {
                                'type': 'bool',
                                },
                            'ssl_session_failure': {
                                'type': 'bool',
                                },
                            'pw_change_failure': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'aam_auth_server_ocsp': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'stapling_request_dropped': {
                                'type': 'bool',
                                },
                            'stapling_response_failure': {
                                'type': 'bool',
                                },
                            'stapling_response_error': {
                                'type': 'bool',
                                },
                            'stapling_response_timeout': {
                                'type': 'bool',
                                },
                            'request_dropped': {
                                'type': 'bool',
                                },
                            'response_failure': {
                                'type': 'bool',
                                },
                            'response_error': {
                                'type': 'bool',
                                },
                            'response_timeout': {
                                'type': 'bool',
                                },
                            'job_start_error': {
                                'type': 'bool',
                                },
                            'polling_control_error': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'stapling_request_dropped': {
                                'type': 'bool',
                                },
                            'stapling_response_failure': {
                                'type': 'bool',
                                },
                            'stapling_response_error': {
                                'type': 'bool',
                                },
                            'stapling_response_timeout': {
                                'type': 'bool',
                                },
                            'request_dropped': {
                                'type': 'bool',
                                },
                            'response_failure': {
                                'type': 'bool',
                                },
                            'response_error': {
                                'type': 'bool',
                                },
                            'response_timeout': {
                                'type': 'bool',
                                },
                            'job_start_error': {
                                'type': 'bool',
                                },
                            'polling_control_error': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'aam_auth_server_radius': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'authen_failure': {
                                'type': 'bool',
                                },
                            'authorize_failure': {
                                'type': 'bool',
                                },
                            'timeout_error': {
                                'type': 'bool',
                                },
                            'other_error': {
                                'type': 'bool',
                                },
                            'request_dropped': {
                                'type': 'bool',
                                },
                            'response_failure': {
                                'type': 'bool',
                                },
                            'response_error': {
                                'type': 'bool',
                                },
                            'response_timeout': {
                                'type': 'bool',
                                },
                            'job_start_error': {
                                'type': 'bool',
                                },
                            'polling_control_error': {
                                'type': 'bool',
                                },
                            'accounting_failure': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'authen_failure': {
                                'type': 'bool',
                                },
                            'authorize_failure': {
                                'type': 'bool',
                                },
                            'timeout_error': {
                                'type': 'bool',
                                },
                            'other_error': {
                                'type': 'bool',
                                },
                            'request_dropped': {
                                'type': 'bool',
                                },
                            'response_failure': {
                                'type': 'bool',
                                },
                            'response_error': {
                                'type': 'bool',
                                },
                            'response_timeout': {
                                'type': 'bool',
                                },
                            'job_start_error': {
                                'type': 'bool',
                                },
                            'polling_control_error': {
                                'type': 'bool',
                                },
                            'accounting_failure': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'aam_auth_server_win': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'kerberos_timeout_error': {
                                'type': 'bool',
                                },
                            'kerberos_other_error': {
                                'type': 'bool',
                                },
                            'kerberos_request_dropped': {
                                'type': 'bool',
                                },
                            'kerberos_response_failure': {
                                'type': 'bool',
                                },
                            'kerberos_response_error': {
                                'type': 'bool',
                                },
                            'kerberos_response_timeout': {
                                'type': 'bool',
                                },
                            'kerberos_job_start_error': {
                                'type': 'bool',
                                },
                            'kerberos_polling_control_error': {
                                'type': 'bool',
                                },
                            'kerberos_pw_expiry': {
                                'type': 'bool',
                                },
                            'kerberos_pw_change_failure': {
                                'type': 'bool',
                                },
                            'kerberos_validate_kdc_failure': {
                                'type': 'bool',
                                },
                            'kerberos_generate_kdc_keytab_failure': {
                                'type': 'bool',
                                },
                            'kerberos_delete_kdc_keytab_failure': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'kerberos_timeout_error': {
                                'type': 'bool',
                                },
                            'kerberos_other_error': {
                                'type': 'bool',
                                },
                            'kerberos_request_dropped': {
                                'type': 'bool',
                                },
                            'kerberos_response_failure': {
                                'type': 'bool',
                                },
                            'kerberos_response_error': {
                                'type': 'bool',
                                },
                            'kerberos_response_timeout': {
                                'type': 'bool',
                                },
                            'kerberos_job_start_error': {
                                'type': 'bool',
                                },
                            'kerberos_polling_control_error': {
                                'type': 'bool',
                                },
                            'kerberos_pw_expiry': {
                                'type': 'bool',
                                },
                            'kerberos_pw_change_failure': {
                                'type': 'bool',
                                },
                            'kerberos_validate_kdc_failure': {
                                'type': 'bool',
                                },
                            'kerberos_generate_kdc_keytab_failure': {
                                'type': 'bool',
                                },
                            'kerberos_delete_kdc_keytab_failure': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'aam_auth_account': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'request_dropped': {
                                'type': 'bool',
                                },
                            'response_failure': {
                                'type': 'bool',
                                },
                            'response_error': {
                                'type': 'bool',
                                },
                            'response_timeout': {
                                'type': 'bool',
                                },
                            'response_other': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'request_dropped': {
                                'type': 'bool',
                                },
                            'response_failure': {
                                'type': 'bool',
                                },
                            'response_error': {
                                'type': 'bool',
                                },
                            'response_timeout': {
                                'type': 'bool',
                                },
                            'response_other': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'aam_auth_saml_global': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'acs_authz_fail': {
                                'type': 'bool',
                                },
                            'acs_error': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'acs_authz_fail': {
                                'type': 'bool',
                                },
                            'acs_error': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'aam_auth_relay_kerberos': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'timeout_error': {
                                'type': 'bool',
                                },
                            'other_error': {
                                'type': 'bool',
                                },
                            'request_dropped': {
                                'type': 'bool',
                                },
                            'response_failure': {
                                'type': 'bool',
                                },
                            'response_error': {
                                'type': 'bool',
                                },
                            'response_timeout': {
                                'type': 'bool',
                                },
                            'job_start_error': {
                                'type': 'bool',
                                },
                            'polling_control_error': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'timeout_error': {
                                'type': 'bool',
                                },
                            'other_error': {
                                'type': 'bool',
                                },
                            'request_dropped': {
                                'type': 'bool',
                                },
                            'response_failure': {
                                'type': 'bool',
                                },
                            'response_error': {
                                'type': 'bool',
                                },
                            'response_timeout': {
                                'type': 'bool',
                                },
                            'job_start_error': {
                                'type': 'bool',
                                },
                            'polling_control_error': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'aam_auth_captcha': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'request_dropped': {
                                'type': 'bool',
                                },
                            'response_failure': {
                                'type': 'bool',
                                },
                            'response_error': {
                                'type': 'bool',
                                },
                            'response_timeout': {
                                'type': 'bool',
                                },
                            'json_fail': {
                                'type': 'bool',
                                },
                            'attr_fail': {
                                'type': 'bool',
                                },
                            'timeout_error': {
                                'type': 'bool',
                                },
                            'other_error': {
                                'type': 'bool',
                                },
                            'job_start_error': {
                                'type': 'bool',
                                },
                            'polling_control_error': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'request_dropped': {
                                'type': 'bool',
                                },
                            'response_failure': {
                                'type': 'bool',
                                },
                            'response_error': {
                                'type': 'bool',
                                },
                            'response_timeout': {
                                'type': 'bool',
                                },
                            'json_fail': {
                                'type': 'bool',
                                },
                            'attr_fail': {
                                'type': 'bool',
                                },
                            'timeout_error': {
                                'type': 'bool',
                                },
                            'other_error': {
                                'type': 'bool',
                                },
                            'job_start_error': {
                                'type': 'bool',
                                },
                            'polling_control_error': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_ssl_error': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'app_data_in_handshake': {
                                'type': 'bool',
                                },
                            'attempt_to_reuse_sess_in_diff_context': {
                                'type': 'bool',
                                },
                            'bad_alert_record': {
                                'type': 'bool',
                                },
                            'bad_authentication_type': {
                                'type': 'bool',
                                },
                            'bad_change_cipher_spec': {
                                'type': 'bool',
                                },
                            'bad_checksum': {
                                'type': 'bool',
                                },
                            'bad_data_returned_by_callback': {
                                'type': 'bool',
                                },
                            'bad_decompression': {
                                'type': 'bool',
                                },
                            'bad_dh_g_length': {
                                'type': 'bool',
                                },
                            'bad_dh_pub_key_length': {
                                'type': 'bool',
                                },
                            'bad_dh_p_length': {
                                'type': 'bool',
                                },
                            'bad_digest_length': {
                                'type': 'bool',
                                },
                            'bad_dsa_signature': {
                                'type': 'bool',
                                },
                            'bad_hello_request': {
                                'type': 'bool',
                                },
                            'bad_length': {
                                'type': 'bool',
                                },
                            'bad_mac_decode': {
                                'type': 'bool',
                                },
                            'bad_message_type': {
                                'type': 'bool',
                                },
                            'bad_packet_length': {
                                'type': 'bool',
                                },
                            'bad_protocol_version_counter': {
                                'type': 'bool',
                                },
                            'bad_response_argument': {
                                'type': 'bool',
                                },
                            'bad_rsa_decrypt': {
                                'type': 'bool',
                                },
                            'bad_rsa_encrypt': {
                                'type': 'bool',
                                },
                            'bad_rsa_e_length': {
                                'type': 'bool',
                                },
                            'bad_rsa_modulus_length': {
                                'type': 'bool',
                                },
                            'bad_rsa_signature': {
                                'type': 'bool',
                                },
                            'bad_signature': {
                                'type': 'bool',
                                },
                            'bad_ssl_filetype': {
                                'type': 'bool',
                                },
                            'bad_ssl_session_id_length': {
                                'type': 'bool',
                                },
                            'bad_state': {
                                'type': 'bool',
                                },
                            'bad_write_retry': {
                                'type': 'bool',
                                },
                            'bio_not_set': {
                                'type': 'bool',
                                },
                            'block_cipher_pad_is_wrong': {
                                'type': 'bool',
                                },
                            'bn_lib': {
                                'type': 'bool',
                                },
                            'ca_dn_length_mismatch': {
                                'type': 'bool',
                                },
                            'ca_dn_too_long': {
                                'type': 'bool',
                                },
                            'ccs_received_early': {
                                'type': 'bool',
                                },
                            'certificate_verify_failed': {
                                'type': 'bool',
                                },
                            'cert_length_mismatch': {
                                'type': 'bool',
                                },
                            'challenge_is_different': {
                                'type': 'bool',
                                },
                            'cipher_code_wrong_length': {
                                'type': 'bool',
                                },
                            'cipher_or_hash_unavailable': {
                                'type': 'bool',
                                },
                            'cipher_table_src_error': {
                                'type': 'bool',
                                },
                            'compressed_length_too_long': {
                                'type': 'bool',
                                },
                            'compression_failure': {
                                'type': 'bool',
                                },
                            'compression_library_error': {
                                'type': 'bool',
                                },
                            'connection_id_is_different': {
                                'type': 'bool',
                                },
                            'connection_type_not_set': {
                                'type': 'bool',
                                },
                            'data_between_ccs_and_finished': {
                                'type': 'bool',
                                },
                            'data_length_too_long': {
                                'type': 'bool',
                                },
                            'decryption_failed': {
                                'type': 'bool',
                                },
                            'decryption_failed_or_bad_record_mac': {
                                'type': 'bool',
                                },
                            'dh_public_value_length_is_wrong': {
                                'type': 'bool',
                                },
                            'digest_check_failed': {
                                'type': 'bool',
                                },
                            'encrypted_length_too_long': {
                                'type': 'bool',
                                },
                            'error_generating_tmp_rsa_key': {
                                'type': 'bool',
                                },
                            'error_in_received_cipher_list': {
                                'type': 'bool',
                                },
                            'excessive_message_size': {
                                'type': 'bool',
                                },
                            'extra_data_in_message': {
                                'type': 'bool',
                                },
                            'got_a_fin_before_a_ccs': {
                                'type': 'bool',
                                },
                            'https_proxy_request': {
                                'type': 'bool',
                                },
                            'http_request': {
                                'type': 'bool',
                                },
                            'illegal_padding': {
                                'type': 'bool',
                                },
                            'inappropriate_fallback': {
                                'type': 'bool',
                                },
                            'invalid_challenge_length': {
                                'type': 'bool',
                                },
                            'invalid_command': {
                                'type': 'bool',
                                },
                            'invalid_purpose': {
                                'type': 'bool',
                                },
                            'invalid_status_response': {
                                'type': 'bool',
                                },
                            'invalid_trust': {
                                'type': 'bool',
                                },
                            'key_arg_too_long': {
                                'type': 'bool',
                                },
                            'krb5': {
                                'type': 'bool',
                                },
                            'krb5_client_cc_principal': {
                                'type': 'bool',
                                },
                            'krb5_client_get_cred': {
                                'type': 'bool',
                                },
                            'krb5_client_init': {
                                'type': 'bool',
                                },
                            'krb5_client_mk_req': {
                                'type': 'bool',
                                },
                            'krb5_server_bad_ticket': {
                                'type': 'bool',
                                },
                            'krb5_server_init': {
                                'type': 'bool',
                                },
                            'krb5_server_rd_req': {
                                'type': 'bool',
                                },
                            'krb5_server_tkt_expired': {
                                'type': 'bool',
                                },
                            'krb5_server_tkt_not_yet_valid': {
                                'type': 'bool',
                                },
                            'krb5_server_tkt_skew': {
                                'type': 'bool',
                                },
                            'length_mismatch': {
                                'type': 'bool',
                                },
                            'length_too_short': {
                                'type': 'bool',
                                },
                            'library_bug': {
                                'type': 'bool',
                                },
                            'library_has_no_ciphers': {
                                'type': 'bool',
                                },
                            'mast_key_too_long': {
                                'type': 'bool',
                                },
                            'message_too_long': {
                                'type': 'bool',
                                },
                            'missing_dh_dsa_cert': {
                                'type': 'bool',
                                },
                            'missing_dh_key': {
                                'type': 'bool',
                                },
                            'missing_dh_rsa_cert': {
                                'type': 'bool',
                                },
                            'missing_dsa_signing_cert': {
                                'type': 'bool',
                                },
                            'missing_export_tmp_dh_key': {
                                'type': 'bool',
                                },
                            'missing_export_tmp_rsa_key': {
                                'type': 'bool',
                                },
                            'missing_rsa_certificate': {
                                'type': 'bool',
                                },
                            'missing_rsa_encrypting_cert': {
                                'type': 'bool',
                                },
                            'missing_rsa_signing_cert': {
                                'type': 'bool',
                                },
                            'missing_tmp_dh_key': {
                                'type': 'bool',
                                },
                            'missing_tmp_rsa_key': {
                                'type': 'bool',
                                },
                            'missing_tmp_rsa_pkey': {
                                'type': 'bool',
                                },
                            'missing_verify_message': {
                                'type': 'bool',
                                },
                            'non_sslv2_initial_packet': {
                                'type': 'bool',
                                },
                            'no_certificates_returned': {
                                'type': 'bool',
                                },
                            'no_certificate_assigned': {
                                'type': 'bool',
                                },
                            'no_certificate_returned': {
                                'type': 'bool',
                                },
                            'no_certificate_set': {
                                'type': 'bool',
                                },
                            'no_certificate_specified': {
                                'type': 'bool',
                                },
                            'no_ciphers_available': {
                                'type': 'bool',
                                },
                            'no_ciphers_passed': {
                                'type': 'bool',
                                },
                            'no_ciphers_specified': {
                                'type': 'bool',
                                },
                            'no_cipher_list': {
                                'type': 'bool',
                                },
                            'no_cipher_match': {
                                'type': 'bool',
                                },
                            'no_client_cert_received': {
                                'type': 'bool',
                                },
                            'no_compression_specified': {
                                'type': 'bool',
                                },
                            'no_method_specified': {
                                'type': 'bool',
                                },
                            'no_privatekey': {
                                'type': 'bool',
                                },
                            'no_private_key_assigned': {
                                'type': 'bool',
                                },
                            'no_protocols_available': {
                                'type': 'bool',
                                },
                            'no_publickey': {
                                'type': 'bool',
                                },
                            'no_shared_cipher': {
                                'type': 'bool',
                                },
                            'no_verify_callback': {
                                'type': 'bool',
                                },
                            'null_ssl_ctx': {
                                'type': 'bool',
                                },
                            'null_ssl_method_passed': {
                                'type': 'bool',
                                },
                            'old_session_cipher_not_returned': {
                                'type': 'bool',
                                },
                            'packet_length_too_long': {
                                'type': 'bool',
                                },
                            'path_too_long': {
                                'type': 'bool',
                                },
                            'peer_did_not_return_a_certificate': {
                                'type': 'bool',
                                },
                            'peer_error': {
                                'type': 'bool',
                                },
                            'peer_error_certificate': {
                                'type': 'bool',
                                },
                            'peer_error_no_certificate': {
                                'type': 'bool',
                                },
                            'peer_error_no_cipher': {
                                'type': 'bool',
                                },
                            'peer_error_unsupported_certificate_type': {
                                'type': 'bool',
                                },
                            'pre_mac_length_too_long': {
                                'type': 'bool',
                                },
                            'problems_mapping_cipher_functions': {
                                'type': 'bool',
                                },
                            'protocol_is_shutdown': {
                                'type': 'bool',
                                },
                            'public_key_encrypt_error': {
                                'type': 'bool',
                                },
                            'public_key_is_not_rsa': {
                                'type': 'bool',
                                },
                            'public_key_not_rsa': {
                                'type': 'bool',
                                },
                            'read_bio_not_set': {
                                'type': 'bool',
                                },
                            'read_wrong_packet_type': {
                                'type': 'bool',
                                },
                            'record_length_mismatch': {
                                'type': 'bool',
                                },
                            'record_too_large': {
                                'type': 'bool',
                                },
                            'record_too_small': {
                                'type': 'bool',
                                },
                            'required_cipher_missing': {
                                'type': 'bool',
                                },
                            'reuse_cert_length_not_zero': {
                                'type': 'bool',
                                },
                            'reuse_cert_type_not_zero': {
                                'type': 'bool',
                                },
                            'reuse_cipher_list_not_zero': {
                                'type': 'bool',
                                },
                            'scsv_received_when_renegotiating': {
                                'type': 'bool',
                                },
                            'session_id_context_uninitialized': {
                                'type': 'bool',
                                },
                            'short_read': {
                                'type': 'bool',
                                },
                            'signature_for_non_signing_certificate': {
                                'type': 'bool',
                                },
                            'ssl23_doing_session_id_reuse': {
                                'type': 'bool',
                                },
                            'ssl2_connection_id_too_long': {
                                'type': 'bool',
                                },
                            'ssl3_session_id_too_long': {
                                'type': 'bool',
                                },
                            'ssl3_session_id_too_short': {
                                'type': 'bool',
                                },
                            'sslv3_alert_bad_certificate': {
                                'type': 'bool',
                                },
                            'sslv3_alert_bad_record_mac': {
                                'type': 'bool',
                                },
                            'sslv3_alert_certificate_expired': {
                                'type': 'bool',
                                },
                            'sslv3_alert_certificate_revoked': {
                                'type': 'bool',
                                },
                            'sslv3_alert_certificate_unknown': {
                                'type': 'bool',
                                },
                            'sslv3_alert_decompression_failure': {
                                'type': 'bool',
                                },
                            'sslv3_alert_handshake_failure': {
                                'type': 'bool',
                                },
                            'sslv3_alert_illegal_parameter': {
                                'type': 'bool',
                                },
                            'sslv3_alert_no_certificate': {
                                'type': 'bool',
                                },
                            'sslv3_alert_peer_error_cert': {
                                'type': 'bool',
                                },
                            'sslv3_alert_peer_error_no_cert': {
                                'type': 'bool',
                                },
                            'sslv3_alert_peer_error_no_cipher': {
                                'type': 'bool',
                                },
                            'sslv3_alert_peer_error_unsupp_cert_type': {
                                'type': 'bool',
                                },
                            'sslv3_alert_unexpected_msg': {
                                'type': 'bool',
                                },
                            'sslv3_alert_unknown_remote_err_type': {
                                'type': 'bool',
                                },
                            'sslv3_alert_unspported_cert': {
                                'type': 'bool',
                                },
                            'ssl_ctx_has_no_default_ssl_version': {
                                'type': 'bool',
                                },
                            'ssl_handshake_failure': {
                                'type': 'bool',
                                },
                            'ssl_library_has_no_ciphers': {
                                'type': 'bool',
                                },
                            'ssl_session_id_callback_failed': {
                                'type': 'bool',
                                },
                            'ssl_session_id_conflict': {
                                'type': 'bool',
                                },
                            'ssl_session_id_context_too_long': {
                                'type': 'bool',
                                },
                            'ssl_session_id_has_bad_length': {
                                'type': 'bool',
                                },
                            'ssl_session_id_is_different': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_access_denied': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_decode_error': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_decryption_failed': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_decrypt_error': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_export_restriction': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_insufficient_security': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_internal_error': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_no_renegotiation': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_protocol_version': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_record_overflow': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_unknown_ca': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_user_cancelled': {
                                'type': 'bool',
                                },
                            'tls_client_cert_req_with_anon_cipher': {
                                'type': 'bool',
                                },
                            'tls_peer_did_not_respond_with_cert_list': {
                                'type': 'bool',
                                },
                            'tls_rsa_encrypted_value_length_is_wrong': {
                                'type': 'bool',
                                },
                            'tried_to_use_unsupported_cipher': {
                                'type': 'bool',
                                },
                            'unable_to_decode_dh_certs': {
                                'type': 'bool',
                                },
                            'unable_to_extract_public_key': {
                                'type': 'bool',
                                },
                            'unable_to_find_dh_parameters': {
                                'type': 'bool',
                                },
                            'unable_to_find_public_key_parameters': {
                                'type': 'bool',
                                },
                            'unable_to_find_ssl_method': {
                                'type': 'bool',
                                },
                            'unable_to_load_ssl2_md5_routines': {
                                'type': 'bool',
                                },
                            'unable_to_load_ssl3_md5_routines': {
                                'type': 'bool',
                                },
                            'unable_to_load_ssl3_sha1_routines': {
                                'type': 'bool',
                                },
                            'unexpected_message': {
                                'type': 'bool',
                                },
                            'unexpected_record': {
                                'type': 'bool',
                                },
                            'uninitialized': {
                                'type': 'bool',
                                },
                            'unknown_alert_type': {
                                'type': 'bool',
                                },
                            'unknown_certificate_type': {
                                'type': 'bool',
                                },
                            'unknown_cipher_returned': {
                                'type': 'bool',
                                },
                            'unknown_cipher_type': {
                                'type': 'bool',
                                },
                            'unknown_key_exchange_type': {
                                'type': 'bool',
                                },
                            'unknown_pkey_type': {
                                'type': 'bool',
                                },
                            'unknown_protocol': {
                                'type': 'bool',
                                },
                            'unknown_remote_error_type': {
                                'type': 'bool',
                                },
                            'unknown_ssl_version': {
                                'type': 'bool',
                                },
                            'unknown_state': {
                                'type': 'bool',
                                },
                            'unsupported_cipher': {
                                'type': 'bool',
                                },
                            'unsupported_compression_algorithm': {
                                'type': 'bool',
                                },
                            'unsupported_option': {
                                'type': 'bool',
                                },
                            'unsupported_protocol': {
                                'type': 'bool',
                                },
                            'unsupported_ssl_version': {
                                'type': 'bool',
                                },
                            'unsupported_status_type': {
                                'type': 'bool',
                                },
                            'write_bio_not_set': {
                                'type': 'bool',
                                },
                            'wrong_cipher_returned': {
                                'type': 'bool',
                                },
                            'wrong_message_type': {
                                'type': 'bool',
                                },
                            'wrong_counter_of_key_bits': {
                                'type': 'bool',
                                },
                            'wrong_signature_length': {
                                'type': 'bool',
                                },
                            'wrong_signature_size': {
                                'type': 'bool',
                                },
                            'wrong_ssl_version': {
                                'type': 'bool',
                                },
                            'wrong_version_counter': {
                                'type': 'bool',
                                },
                            'x509_lib': {
                                'type': 'bool',
                                },
                            'x509_verification_setup_problems': {
                                'type': 'bool',
                                },
                            'clienthello_tlsext': {
                                'type': 'bool',
                                },
                            'parse_tlsext': {
                                'type': 'bool',
                                },
                            'serverhello_tlsext': {
                                'type': 'bool',
                                },
                            'ssl3_ext_invalid_servername': {
                                'type': 'bool',
                                },
                            'ssl3_ext_invalid_servername_type': {
                                'type': 'bool',
                                },
                            'multiple_sgc_restarts': {
                                'type': 'bool',
                                },
                            'tls_invalid_ecpointformat_list': {
                                'type': 'bool',
                                },
                            'bad_ecc_cert': {
                                'type': 'bool',
                                },
                            'bad_ecdsa_sig': {
                                'type': 'bool',
                                },
                            'bad_ecpoint': {
                                'type': 'bool',
                                },
                            'cookie_mismatch': {
                                'type': 'bool',
                                },
                            'unsupported_elliptic_curve': {
                                'type': 'bool',
                                },
                            'no_required_digest': {
                                'type': 'bool',
                                },
                            'unsupported_digest_type': {
                                'type': 'bool',
                                },
                            'bad_handshake_length': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'app_data_in_handshake': {
                                'type': 'bool',
                                },
                            'attempt_to_reuse_sess_in_diff_context': {
                                'type': 'bool',
                                },
                            'bad_alert_record': {
                                'type': 'bool',
                                },
                            'bad_authentication_type': {
                                'type': 'bool',
                                },
                            'bad_change_cipher_spec': {
                                'type': 'bool',
                                },
                            'bad_checksum': {
                                'type': 'bool',
                                },
                            'bad_data_returned_by_callback': {
                                'type': 'bool',
                                },
                            'bad_decompression': {
                                'type': 'bool',
                                },
                            'bad_dh_g_length': {
                                'type': 'bool',
                                },
                            'bad_dh_pub_key_length': {
                                'type': 'bool',
                                },
                            'bad_dh_p_length': {
                                'type': 'bool',
                                },
                            'bad_digest_length': {
                                'type': 'bool',
                                },
                            'bad_dsa_signature': {
                                'type': 'bool',
                                },
                            'bad_hello_request': {
                                'type': 'bool',
                                },
                            'bad_length': {
                                'type': 'bool',
                                },
                            'bad_mac_decode': {
                                'type': 'bool',
                                },
                            'bad_message_type': {
                                'type': 'bool',
                                },
                            'bad_packet_length': {
                                'type': 'bool',
                                },
                            'bad_protocol_version_counter': {
                                'type': 'bool',
                                },
                            'bad_response_argument': {
                                'type': 'bool',
                                },
                            'bad_rsa_decrypt': {
                                'type': 'bool',
                                },
                            'bad_rsa_encrypt': {
                                'type': 'bool',
                                },
                            'bad_rsa_e_length': {
                                'type': 'bool',
                                },
                            'bad_rsa_modulus_length': {
                                'type': 'bool',
                                },
                            'bad_rsa_signature': {
                                'type': 'bool',
                                },
                            'bad_signature': {
                                'type': 'bool',
                                },
                            'bad_ssl_filetype': {
                                'type': 'bool',
                                },
                            'bad_ssl_session_id_length': {
                                'type': 'bool',
                                },
                            'bad_state': {
                                'type': 'bool',
                                },
                            'bad_write_retry': {
                                'type': 'bool',
                                },
                            'bio_not_set': {
                                'type': 'bool',
                                },
                            'block_cipher_pad_is_wrong': {
                                'type': 'bool',
                                },
                            'bn_lib': {
                                'type': 'bool',
                                },
                            'ca_dn_length_mismatch': {
                                'type': 'bool',
                                },
                            'ca_dn_too_long': {
                                'type': 'bool',
                                },
                            'ccs_received_early': {
                                'type': 'bool',
                                },
                            'certificate_verify_failed': {
                                'type': 'bool',
                                },
                            'cert_length_mismatch': {
                                'type': 'bool',
                                },
                            'challenge_is_different': {
                                'type': 'bool',
                                },
                            'cipher_code_wrong_length': {
                                'type': 'bool',
                                },
                            'cipher_or_hash_unavailable': {
                                'type': 'bool',
                                },
                            'cipher_table_src_error': {
                                'type': 'bool',
                                },
                            'compressed_length_too_long': {
                                'type': 'bool',
                                },
                            'compression_failure': {
                                'type': 'bool',
                                },
                            'compression_library_error': {
                                'type': 'bool',
                                },
                            'connection_id_is_different': {
                                'type': 'bool',
                                },
                            'connection_type_not_set': {
                                'type': 'bool',
                                },
                            'data_between_ccs_and_finished': {
                                'type': 'bool',
                                },
                            'data_length_too_long': {
                                'type': 'bool',
                                },
                            'decryption_failed': {
                                'type': 'bool',
                                },
                            'decryption_failed_or_bad_record_mac': {
                                'type': 'bool',
                                },
                            'dh_public_value_length_is_wrong': {
                                'type': 'bool',
                                },
                            'digest_check_failed': {
                                'type': 'bool',
                                },
                            'encrypted_length_too_long': {
                                'type': 'bool',
                                },
                            'error_generating_tmp_rsa_key': {
                                'type': 'bool',
                                },
                            'error_in_received_cipher_list': {
                                'type': 'bool',
                                },
                            'excessive_message_size': {
                                'type': 'bool',
                                },
                            'extra_data_in_message': {
                                'type': 'bool',
                                },
                            'got_a_fin_before_a_ccs': {
                                'type': 'bool',
                                },
                            'https_proxy_request': {
                                'type': 'bool',
                                },
                            'http_request': {
                                'type': 'bool',
                                },
                            'illegal_padding': {
                                'type': 'bool',
                                },
                            'inappropriate_fallback': {
                                'type': 'bool',
                                },
                            'invalid_challenge_length': {
                                'type': 'bool',
                                },
                            'invalid_command': {
                                'type': 'bool',
                                },
                            'invalid_purpose': {
                                'type': 'bool',
                                },
                            'invalid_status_response': {
                                'type': 'bool',
                                },
                            'invalid_trust': {
                                'type': 'bool',
                                },
                            'key_arg_too_long': {
                                'type': 'bool',
                                },
                            'krb5': {
                                'type': 'bool',
                                },
                            'krb5_client_cc_principal': {
                                'type': 'bool',
                                },
                            'krb5_client_get_cred': {
                                'type': 'bool',
                                },
                            'krb5_client_init': {
                                'type': 'bool',
                                },
                            'krb5_client_mk_req': {
                                'type': 'bool',
                                },
                            'krb5_server_bad_ticket': {
                                'type': 'bool',
                                },
                            'krb5_server_init': {
                                'type': 'bool',
                                },
                            'krb5_server_rd_req': {
                                'type': 'bool',
                                },
                            'krb5_server_tkt_expired': {
                                'type': 'bool',
                                },
                            'krb5_server_tkt_not_yet_valid': {
                                'type': 'bool',
                                },
                            'krb5_server_tkt_skew': {
                                'type': 'bool',
                                },
                            'length_mismatch': {
                                'type': 'bool',
                                },
                            'length_too_short': {
                                'type': 'bool',
                                },
                            'library_bug': {
                                'type': 'bool',
                                },
                            'library_has_no_ciphers': {
                                'type': 'bool',
                                },
                            'mast_key_too_long': {
                                'type': 'bool',
                                },
                            'message_too_long': {
                                'type': 'bool',
                                },
                            'missing_dh_dsa_cert': {
                                'type': 'bool',
                                },
                            'missing_dh_key': {
                                'type': 'bool',
                                },
                            'missing_dh_rsa_cert': {
                                'type': 'bool',
                                },
                            'missing_dsa_signing_cert': {
                                'type': 'bool',
                                },
                            'missing_export_tmp_dh_key': {
                                'type': 'bool',
                                },
                            'missing_export_tmp_rsa_key': {
                                'type': 'bool',
                                },
                            'missing_rsa_certificate': {
                                'type': 'bool',
                                },
                            'missing_rsa_encrypting_cert': {
                                'type': 'bool',
                                },
                            'missing_rsa_signing_cert': {
                                'type': 'bool',
                                },
                            'missing_tmp_dh_key': {
                                'type': 'bool',
                                },
                            'missing_tmp_rsa_key': {
                                'type': 'bool',
                                },
                            'missing_tmp_rsa_pkey': {
                                'type': 'bool',
                                },
                            'missing_verify_message': {
                                'type': 'bool',
                                },
                            'non_sslv2_initial_packet': {
                                'type': 'bool',
                                },
                            'no_certificates_returned': {
                                'type': 'bool',
                                },
                            'no_certificate_assigned': {
                                'type': 'bool',
                                },
                            'no_certificate_returned': {
                                'type': 'bool',
                                },
                            'no_certificate_set': {
                                'type': 'bool',
                                },
                            'no_certificate_specified': {
                                'type': 'bool',
                                },
                            'no_ciphers_available': {
                                'type': 'bool',
                                },
                            'no_ciphers_passed': {
                                'type': 'bool',
                                },
                            'no_ciphers_specified': {
                                'type': 'bool',
                                },
                            'no_cipher_list': {
                                'type': 'bool',
                                },
                            'no_cipher_match': {
                                'type': 'bool',
                                },
                            'no_client_cert_received': {
                                'type': 'bool',
                                },
                            'no_compression_specified': {
                                'type': 'bool',
                                },
                            'no_method_specified': {
                                'type': 'bool',
                                },
                            'no_privatekey': {
                                'type': 'bool',
                                },
                            'no_private_key_assigned': {
                                'type': 'bool',
                                },
                            'no_protocols_available': {
                                'type': 'bool',
                                },
                            'no_publickey': {
                                'type': 'bool',
                                },
                            'no_shared_cipher': {
                                'type': 'bool',
                                },
                            'no_verify_callback': {
                                'type': 'bool',
                                },
                            'null_ssl_ctx': {
                                'type': 'bool',
                                },
                            'null_ssl_method_passed': {
                                'type': 'bool',
                                },
                            'old_session_cipher_not_returned': {
                                'type': 'bool',
                                },
                            'packet_length_too_long': {
                                'type': 'bool',
                                },
                            'path_too_long': {
                                'type': 'bool',
                                },
                            'peer_did_not_return_a_certificate': {
                                'type': 'bool',
                                },
                            'peer_error': {
                                'type': 'bool',
                                },
                            'peer_error_certificate': {
                                'type': 'bool',
                                },
                            'peer_error_no_certificate': {
                                'type': 'bool',
                                },
                            'peer_error_no_cipher': {
                                'type': 'bool',
                                },
                            'peer_error_unsupported_certificate_type': {
                                'type': 'bool',
                                },
                            'pre_mac_length_too_long': {
                                'type': 'bool',
                                },
                            'problems_mapping_cipher_functions': {
                                'type': 'bool',
                                },
                            'protocol_is_shutdown': {
                                'type': 'bool',
                                },
                            'public_key_encrypt_error': {
                                'type': 'bool',
                                },
                            'public_key_is_not_rsa': {
                                'type': 'bool',
                                },
                            'public_key_not_rsa': {
                                'type': 'bool',
                                },
                            'read_bio_not_set': {
                                'type': 'bool',
                                },
                            'read_wrong_packet_type': {
                                'type': 'bool',
                                },
                            'record_length_mismatch': {
                                'type': 'bool',
                                },
                            'record_too_large': {
                                'type': 'bool',
                                },
                            'record_too_small': {
                                'type': 'bool',
                                },
                            'required_cipher_missing': {
                                'type': 'bool',
                                },
                            'reuse_cert_length_not_zero': {
                                'type': 'bool',
                                },
                            'reuse_cert_type_not_zero': {
                                'type': 'bool',
                                },
                            'reuse_cipher_list_not_zero': {
                                'type': 'bool',
                                },
                            'scsv_received_when_renegotiating': {
                                'type': 'bool',
                                },
                            'session_id_context_uninitialized': {
                                'type': 'bool',
                                },
                            'short_read': {
                                'type': 'bool',
                                },
                            'signature_for_non_signing_certificate': {
                                'type': 'bool',
                                },
                            'ssl23_doing_session_id_reuse': {
                                'type': 'bool',
                                },
                            'ssl2_connection_id_too_long': {
                                'type': 'bool',
                                },
                            'ssl3_session_id_too_long': {
                                'type': 'bool',
                                },
                            'ssl3_session_id_too_short': {
                                'type': 'bool',
                                },
                            'sslv3_alert_bad_certificate': {
                                'type': 'bool',
                                },
                            'sslv3_alert_bad_record_mac': {
                                'type': 'bool',
                                },
                            'sslv3_alert_certificate_expired': {
                                'type': 'bool',
                                },
                            'sslv3_alert_certificate_revoked': {
                                'type': 'bool',
                                },
                            'sslv3_alert_certificate_unknown': {
                                'type': 'bool',
                                },
                            'sslv3_alert_decompression_failure': {
                                'type': 'bool',
                                },
                            'sslv3_alert_handshake_failure': {
                                'type': 'bool',
                                },
                            'sslv3_alert_illegal_parameter': {
                                'type': 'bool',
                                },
                            'sslv3_alert_no_certificate': {
                                'type': 'bool',
                                },
                            'sslv3_alert_peer_error_cert': {
                                'type': 'bool',
                                },
                            'sslv3_alert_peer_error_no_cert': {
                                'type': 'bool',
                                },
                            'sslv3_alert_peer_error_no_cipher': {
                                'type': 'bool',
                                },
                            'sslv3_alert_peer_error_unsupp_cert_type': {
                                'type': 'bool',
                                },
                            'sslv3_alert_unexpected_msg': {
                                'type': 'bool',
                                },
                            'sslv3_alert_unknown_remote_err_type': {
                                'type': 'bool',
                                },
                            'sslv3_alert_unspported_cert': {
                                'type': 'bool',
                                },
                            'ssl_ctx_has_no_default_ssl_version': {
                                'type': 'bool',
                                },
                            'ssl_handshake_failure': {
                                'type': 'bool',
                                },
                            'ssl_library_has_no_ciphers': {
                                'type': 'bool',
                                },
                            'ssl_session_id_callback_failed': {
                                'type': 'bool',
                                },
                            'ssl_session_id_conflict': {
                                'type': 'bool',
                                },
                            'ssl_session_id_context_too_long': {
                                'type': 'bool',
                                },
                            'ssl_session_id_has_bad_length': {
                                'type': 'bool',
                                },
                            'ssl_session_id_is_different': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_access_denied': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_decode_error': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_decryption_failed': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_decrypt_error': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_export_restriction': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_insufficient_security': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_internal_error': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_no_renegotiation': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_protocol_version': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_record_overflow': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_unknown_ca': {
                                'type': 'bool',
                                },
                            'tlsv1_alert_user_cancelled': {
                                'type': 'bool',
                                },
                            'tls_client_cert_req_with_anon_cipher': {
                                'type': 'bool',
                                },
                            'tls_peer_did_not_respond_with_cert_list': {
                                'type': 'bool',
                                },
                            'tls_rsa_encrypted_value_length_is_wrong': {
                                'type': 'bool',
                                },
                            'tried_to_use_unsupported_cipher': {
                                'type': 'bool',
                                },
                            'unable_to_decode_dh_certs': {
                                'type': 'bool',
                                },
                            'unable_to_extract_public_key': {
                                'type': 'bool',
                                },
                            'unable_to_find_dh_parameters': {
                                'type': 'bool',
                                },
                            'unable_to_find_public_key_parameters': {
                                'type': 'bool',
                                },
                            'unable_to_find_ssl_method': {
                                'type': 'bool',
                                },
                            'unable_to_load_ssl2_md5_routines': {
                                'type': 'bool',
                                },
                            'unable_to_load_ssl3_md5_routines': {
                                'type': 'bool',
                                },
                            'unable_to_load_ssl3_sha1_routines': {
                                'type': 'bool',
                                },
                            'unexpected_message': {
                                'type': 'bool',
                                },
                            'unexpected_record': {
                                'type': 'bool',
                                },
                            'uninitialized': {
                                'type': 'bool',
                                },
                            'unknown_alert_type': {
                                'type': 'bool',
                                },
                            'unknown_certificate_type': {
                                'type': 'bool',
                                },
                            'unknown_cipher_returned': {
                                'type': 'bool',
                                },
                            'unknown_cipher_type': {
                                'type': 'bool',
                                },
                            'unknown_key_exchange_type': {
                                'type': 'bool',
                                },
                            'unknown_pkey_type': {
                                'type': 'bool',
                                },
                            'unknown_protocol': {
                                'type': 'bool',
                                },
                            'unknown_remote_error_type': {
                                'type': 'bool',
                                },
                            'unknown_ssl_version': {
                                'type': 'bool',
                                },
                            'unknown_state': {
                                'type': 'bool',
                                },
                            'unsupported_cipher': {
                                'type': 'bool',
                                },
                            'unsupported_compression_algorithm': {
                                'type': 'bool',
                                },
                            'unsupported_option': {
                                'type': 'bool',
                                },
                            'unsupported_protocol': {
                                'type': 'bool',
                                },
                            'unsupported_ssl_version': {
                                'type': 'bool',
                                },
                            'unsupported_status_type': {
                                'type': 'bool',
                                },
                            'write_bio_not_set': {
                                'type': 'bool',
                                },
                            'wrong_cipher_returned': {
                                'type': 'bool',
                                },
                            'wrong_message_type': {
                                'type': 'bool',
                                },
                            'wrong_counter_of_key_bits': {
                                'type': 'bool',
                                },
                            'wrong_signature_length': {
                                'type': 'bool',
                                },
                            'wrong_signature_size': {
                                'type': 'bool',
                                },
                            'wrong_ssl_version': {
                                'type': 'bool',
                                },
                            'wrong_version_counter': {
                                'type': 'bool',
                                },
                            'x509_lib': {
                                'type': 'bool',
                                },
                            'x509_verification_setup_problems': {
                                'type': 'bool',
                                },
                            'clienthello_tlsext': {
                                'type': 'bool',
                                },
                            'parse_tlsext': {
                                'type': 'bool',
                                },
                            'serverhello_tlsext': {
                                'type': 'bool',
                                },
                            'ssl3_ext_invalid_servername': {
                                'type': 'bool',
                                },
                            'ssl3_ext_invalid_servername_type': {
                                'type': 'bool',
                                },
                            'multiple_sgc_restarts': {
                                'type': 'bool',
                                },
                            'tls_invalid_ecpointformat_list': {
                                'type': 'bool',
                                },
                            'bad_ecc_cert': {
                                'type': 'bool',
                                },
                            'bad_ecdsa_sig': {
                                'type': 'bool',
                                },
                            'bad_ecpoint': {
                                'type': 'bool',
                                },
                            'cookie_mismatch': {
                                'type': 'bool',
                                },
                            'unsupported_elliptic_curve': {
                                'type': 'bool',
                                },
                            'no_required_digest': {
                                'type': 'bool',
                                },
                            'unsupported_digest_type': {
                                'type': 'bool',
                                },
                            'bad_handshake_length': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_ssl_cert_revoke': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'ocsp_chain_status_revoked': {
                                'type': 'bool',
                                },
                            'ocsp_chain_status_unknown': {
                                'type': 'bool',
                                },
                            'ocsp_connection_error': {
                                'type': 'bool',
                                },
                            'ocsp_uri_not_found': {
                                'type': 'bool',
                                },
                            'ocsp_uri_https': {
                                'type': 'bool',
                                },
                            'ocsp_uri_unsupported': {
                                'type': 'bool',
                                },
                            'ocsp_response_status_revoked': {
                                'type': 'bool',
                                },
                            'ocsp_response_status_unknown': {
                                'type': 'bool',
                                },
                            'ocsp_cache_status_revoked': {
                                'type': 'bool',
                                },
                            'ocsp_cache_miss': {
                                'type': 'bool',
                                },
                            'ocsp_other_error': {
                                'type': 'bool',
                                },
                            'ocsp_response_no_nonce': {
                                'type': 'bool',
                                },
                            'ocsp_response_nonce_error': {
                                'type': 'bool',
                                },
                            'crl_connection_error': {
                                'type': 'bool',
                                },
                            'crl_uri_not_found': {
                                'type': 'bool',
                                },
                            'crl_uri_https': {
                                'type': 'bool',
                                },
                            'crl_uri_unsupported': {
                                'type': 'bool',
                                },
                            'crl_response_status_revoked': {
                                'type': 'bool',
                                },
                            'crl_response_status_unknown': {
                                'type': 'bool',
                                },
                            'crl_cache_status_revoked': {
                                'type': 'bool',
                                },
                            'crl_other_error': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'ocsp_chain_status_revoked': {
                                'type': 'bool',
                                },
                            'ocsp_chain_status_unknown': {
                                'type': 'bool',
                                },
                            'ocsp_connection_error': {
                                'type': 'bool',
                                },
                            'ocsp_uri_not_found': {
                                'type': 'bool',
                                },
                            'ocsp_uri_https': {
                                'type': 'bool',
                                },
                            'ocsp_uri_unsupported': {
                                'type': 'bool',
                                },
                            'ocsp_response_status_revoked': {
                                'type': 'bool',
                                },
                            'ocsp_response_status_unknown': {
                                'type': 'bool',
                                },
                            'ocsp_cache_status_revoked': {
                                'type': 'bool',
                                },
                            'ocsp_cache_miss': {
                                'type': 'bool',
                                },
                            'ocsp_other_error': {
                                'type': 'bool',
                                },
                            'ocsp_response_no_nonce': {
                                'type': 'bool',
                                },
                            'ocsp_response_nonce_error': {
                                'type': 'bool',
                                },
                            'crl_connection_error': {
                                'type': 'bool',
                                },
                            'crl_uri_not_found': {
                                'type': 'bool',
                                },
                            'crl_uri_https': {
                                'type': 'bool',
                                },
                            'crl_uri_unsupported': {
                                'type': 'bool',
                                },
                            'crl_response_status_revoked': {
                                'type': 'bool',
                                },
                            'crl_response_status_unknown': {
                                'type': 'bool',
                                },
                            'crl_cache_status_revoked': {
                                'type': 'bool',
                                },
                            'crl_other_error': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_ssl_forward_proxy': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'failed_in_ssl_handshakes': {
                                'type': 'bool',
                                },
                            'failed_in_crypto_operations': {
                                'type': 'bool',
                                },
                            'failed_in_tcp': {
                                'type': 'bool',
                                },
                            'failed_in_certificate_verification': {
                                'type': 'bool',
                                },
                            'failed_in_certificate_signing': {
                                'type': 'bool',
                                },
                            'invalid_ocsp_stapling_response': {
                                'type': 'bool',
                                },
                            'revoked_ocsp_response': {
                                'type': 'bool',
                                },
                            'unsupported_ssl_version': {
                                'type': 'bool',
                                },
                            'connections_failed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'failed_in_ssl_handshakes': {
                                'type': 'bool',
                                },
                            'failed_in_crypto_operations': {
                                'type': 'bool',
                                },
                            'failed_in_tcp': {
                                'type': 'bool',
                                },
                            'failed_in_certificate_verification': {
                                'type': 'bool',
                                },
                            'failed_in_certificate_signing': {
                                'type': 'bool',
                                },
                            'invalid_ocsp_stapling_response': {
                                'type': 'bool',
                                },
                            'revoked_ocsp_response': {
                                'type': 'bool',
                                },
                            'unsupported_ssl_version': {
                                'type': 'bool',
                                },
                            'connections_failed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'vpn_error': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'bad_opcode': {
                                'type': 'bool',
                                },
                            'bad_sg_write_len': {
                                'type': 'bool',
                                },
                            'bad_len': {
                                'type': 'bool',
                                },
                            'bad_ipsec_protocol': {
                                'type': 'bool',
                                },
                            'bad_ipsec_auth': {
                                'type': 'bool',
                                },
                            'bad_ipsec_padding': {
                                'type': 'bool',
                                },
                            'bad_ip_version': {
                                'type': 'bool',
                                },
                            'bad_auth_type': {
                                'type': 'bool',
                                },
                            'bad_encrypt_type': {
                                'type': 'bool',
                                },
                            'bad_ipsec_spi': {
                                'type': 'bool',
                                },
                            'bad_checksum': {
                                'type': 'bool',
                                },
                            'bad_ipsec_context': {
                                'type': 'bool',
                                },
                            'bad_ipsec_context_direction': {
                                'type': 'bool',
                                },
                            'bad_ipsec_context_flag_mismatch': {
                                'type': 'bool',
                                },
                            'ipcomp_payload': {
                                'type': 'bool',
                                },
                            'bad_selector_match': {
                                'type': 'bool',
                                },
                            'bad_fragment_size': {
                                'type': 'bool',
                                },
                            'bad_inline_data': {
                                'type': 'bool',
                                },
                            'bad_frag_size_configuration': {
                                'type': 'bool',
                                },
                            'dummy_payload': {
                                'type': 'bool',
                                },
                            'bad_ip_payload_type': {
                                'type': 'bool',
                                },
                            'bad_min_frag_size_auth_sha384_512': {
                                'type': 'bool',
                                },
                            'bad_esp_next_header': {
                                'type': 'bool',
                                },
                            'bad_gre_header': {
                                'type': 'bool',
                                },
                            'bad_gre_protocol': {
                                'type': 'bool',
                                },
                            'ipv6_extension_headers_too_big': {
                                'type': 'bool',
                                },
                            'ipv6_hop_by_hop_error': {
                                'type': 'bool',
                                },
                            'error_ipv6_decrypt_rh_segs_left_error': {
                                'type': 'bool',
                                },
                            'ipv6_rh_length_error': {
                                'type': 'bool',
                                },
                            'ipv6_outbound_rh_copy_addr_error': {
                                'type': 'bool',
                                },
                            'error_IPv6_extension_header_bad': {
                                'type': 'bool',
                                },
                            'bad_encrypt_type_ctr_gcm': {
                                'type': 'bool',
                                },
                            'ah_not_supported_with_gcm_gmac_sha2': {
                                'type': 'bool',
                                },
                            'tfc_padding_with_prefrag_not_supported': {
                                'type': 'bool',
                                },
                            'bad_srtp_auth_tag': {
                                'type': 'bool',
                                },
                            'bad_ipcomp_configuration': {
                                'type': 'bool',
                                },
                            'dsiv_incorrect_param': {
                                'type': 'bool',
                                },
                            'bad_ipsec_unknown': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'bad_opcode': {
                                'type': 'bool',
                                },
                            'bad_sg_write_len': {
                                'type': 'bool',
                                },
                            'bad_len': {
                                'type': 'bool',
                                },
                            'bad_ipsec_protocol': {
                                'type': 'bool',
                                },
                            'bad_ipsec_auth': {
                                'type': 'bool',
                                },
                            'bad_ipsec_padding': {
                                'type': 'bool',
                                },
                            'bad_ip_version': {
                                'type': 'bool',
                                },
                            'bad_auth_type': {
                                'type': 'bool',
                                },
                            'bad_encrypt_type': {
                                'type': 'bool',
                                },
                            'bad_ipsec_spi': {
                                'type': 'bool',
                                },
                            'bad_checksum': {
                                'type': 'bool',
                                },
                            'bad_ipsec_context': {
                                'type': 'bool',
                                },
                            'bad_ipsec_context_direction': {
                                'type': 'bool',
                                },
                            'bad_ipsec_context_flag_mismatch': {
                                'type': 'bool',
                                },
                            'ipcomp_payload': {
                                'type': 'bool',
                                },
                            'bad_selector_match': {
                                'type': 'bool',
                                },
                            'bad_fragment_size': {
                                'type': 'bool',
                                },
                            'bad_inline_data': {
                                'type': 'bool',
                                },
                            'bad_frag_size_configuration': {
                                'type': 'bool',
                                },
                            'dummy_payload': {
                                'type': 'bool',
                                },
                            'bad_ip_payload_type': {
                                'type': 'bool',
                                },
                            'bad_min_frag_size_auth_sha384_512': {
                                'type': 'bool',
                                },
                            'bad_esp_next_header': {
                                'type': 'bool',
                                },
                            'bad_gre_header': {
                                'type': 'bool',
                                },
                            'bad_gre_protocol': {
                                'type': 'bool',
                                },
                            'ipv6_extension_headers_too_big': {
                                'type': 'bool',
                                },
                            'ipv6_hop_by_hop_error': {
                                'type': 'bool',
                                },
                            'error_ipv6_decrypt_rh_segs_left_error': {
                                'type': 'bool',
                                },
                            'ipv6_rh_length_error': {
                                'type': 'bool',
                                },
                            'ipv6_outbound_rh_copy_addr_error': {
                                'type': 'bool',
                                },
                            'error_IPv6_extension_header_bad': {
                                'type': 'bool',
                                },
                            'bad_encrypt_type_ctr_gcm': {
                                'type': 'bool',
                                },
                            'ah_not_supported_with_gcm_gmac_sha2': {
                                'type': 'bool',
                                },
                            'tfc_padding_with_prefrag_not_supported': {
                                'type': 'bool',
                                },
                            'bad_srtp_auth_tag': {
                                'type': 'bool',
                                },
                            'bad_ipcomp_configuration': {
                                'type': 'bool',
                                },
                            'dsiv_incorrect_param': {
                                'type': 'bool',
                                },
                            'bad_ipsec_unknown': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_ddos_proc': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'l3_entry_match_drop': {
                                'type': 'bool',
                                },
                            'l3_entry_match_drop_hw': {
                                'type': 'bool',
                                },
                            'l3_entry_drop_max_hw_exceeded': {
                                'type': 'bool',
                                },
                            'l4_entry_match_drop': {
                                'type': 'bool',
                                },
                            'l4_entry_match_drop_hw': {
                                'type': 'bool',
                                },
                            'l4_entry_drop_max_hw_exceeded': {
                                'type': 'bool',
                                },
                            'l4_entry_list_alloc_failure': {
                                'type': 'bool',
                                },
                            'ip_node_alloc_failure': {
                                'type': 'bool',
                                },
                            'ip_port_block_alloc_failure': {
                                'type': 'bool',
                                },
                            'ip_other_block_alloc_failure': {
                                'type': 'bool',
                                },
                            'l3_entry_add_to_bgp_failure': {
                                'type': 'bool',
                                },
                            'l3_entry_remove_from_bgp_failure': {
                                'type': 'bool',
                                },
                            'l3_entry_add_to_hw_failure': {
                                'type': 'bool',
                                },
                            'syn_cookie_verification_failed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'l3_entry_match_drop': {
                                'type': 'bool',
                                },
                            'l3_entry_match_drop_hw': {
                                'type': 'bool',
                                },
                            'l3_entry_drop_max_hw_exceeded': {
                                'type': 'bool',
                                },
                            'l4_entry_match_drop': {
                                'type': 'bool',
                                },
                            'l4_entry_match_drop_hw': {
                                'type': 'bool',
                                },
                            'l4_entry_drop_max_hw_exceeded': {
                                'type': 'bool',
                                },
                            'l4_entry_list_alloc_failure': {
                                'type': 'bool',
                                },
                            'ip_node_alloc_failure': {
                                'type': 'bool',
                                },
                            'ip_port_block_alloc_failure': {
                                'type': 'bool',
                                },
                            'ip_other_block_alloc_failure': {
                                'type': 'bool',
                                },
                            'l3_entry_add_to_bgp_failure': {
                                'type': 'bool',
                                },
                            'l3_entry_remove_from_bgp_failure': {
                                'type': 'bool',
                                },
                            'l3_entry_add_to_hw_failure': {
                                'type': 'bool',
                                },
                            'syn_cookie_verification_failed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_lsn': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'user_quota_failure': {
                                'type': 'bool',
                                },
                            'data_sesn_user_quota_exceeded': {
                                'type': 'bool',
                                },
                            'fullcone_failure': {
                                'type': 'bool',
                                },
                            'fullcone_self_hairpinning_drop': {
                                'type': 'bool',
                                },
                            'nat_pool_unusable': {
                                'type': 'bool',
                                },
                            'ha_nat_pool_unusable': {
                                'type': 'bool',
                                },
                            'ha_nat_pool_batch_type_mismatch': {
                                'type': 'bool',
                                },
                            'sip_alg_quota_inc_failure': {
                                'type': 'bool',
                                },
                            'sip_alg_alloc_rtp_rtcp_port_failure': {
                                'type': 'bool',
                                },
                            'sip_alg_alloc_single_port_failure': {
                                'type': 'bool',
                                },
                            'sip_alg_create_single_fullcone_failure': {
                                'type': 'bool',
                                },
                            'sip_alg_create_rtp_fullcone_failure': {
                                'type': 'bool',
                                },
                            'sip_alg_create_rtcp_fullcone_failure': {
                                'type': 'bool',
                                },
                            'h323_alg_alloc_single_port_failure': {
                                'type': 'bool',
                                },
                            'h323_alg_create_single_fullcone_failure': {
                                'type': 'bool',
                                },
                            'h323_alg_create_rtp_fullcone_failure': {
                                'type': 'bool',
                                },
                            'h323_alg_create_rtcp_fullcone_failure': {
                                'type': 'bool',
                                },
                            'port_overloading_out_of_memory': {
                                'type': 'bool',
                                },
                            'port_overloading_inc_overflow': {
                                'type': 'bool',
                                },
                            'fullcone_ext_mem_alloc_failure': {
                                'type': 'bool',
                                },
                            'fullcone_ext_mem_alloc_init_faulure': {
                                'type': 'bool',
                                },
                            'mgcp_alg_create_rtp_fullcone_failure': {
                                'type': 'bool',
                                },
                            'mgcp_alg_create_rtcp_fullcone_failure': {
                                'type': 'bool',
                                },
                            'mgcp_alg_port_pair_alloc_from_quota_par': {
                                'type': 'bool',
                                },
                            'user_quota_unusable_drop': {
                                'type': 'bool',
                                },
                            'user_quota_unusable': {
                                'type': 'bool',
                                },
                            'adc_port_allocation_failed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'user_quota_failure': {
                                'type': 'bool',
                                },
                            'data_sesn_user_quota_exceeded': {
                                'type': 'bool',
                                },
                            'fullcone_failure': {
                                'type': 'bool',
                                },
                            'fullcone_self_hairpinning_drop': {
                                'type': 'bool',
                                },
                            'nat_pool_unusable': {
                                'type': 'bool',
                                },
                            'ha_nat_pool_unusable': {
                                'type': 'bool',
                                },
                            'ha_nat_pool_batch_type_mismatch': {
                                'type': 'bool',
                                },
                            'sip_alg_quota_inc_failure': {
                                'type': 'bool',
                                },
                            'sip_alg_alloc_rtp_rtcp_port_failure': {
                                'type': 'bool',
                                },
                            'sip_alg_alloc_single_port_failure': {
                                'type': 'bool',
                                },
                            'sip_alg_create_single_fullcone_failure': {
                                'type': 'bool',
                                },
                            'sip_alg_create_rtp_fullcone_failure': {
                                'type': 'bool',
                                },
                            'sip_alg_create_rtcp_fullcone_failure': {
                                'type': 'bool',
                                },
                            'h323_alg_alloc_single_port_failure': {
                                'type': 'bool',
                                },
                            'h323_alg_create_single_fullcone_failure': {
                                'type': 'bool',
                                },
                            'h323_alg_create_rtp_fullcone_failure': {
                                'type': 'bool',
                                },
                            'h323_alg_create_rtcp_fullcone_failure': {
                                'type': 'bool',
                                },
                            'port_overloading_out_of_memory': {
                                'type': 'bool',
                                },
                            'port_overloading_inc_overflow': {
                                'type': 'bool',
                                },
                            'fullcone_ext_mem_alloc_failure': {
                                'type': 'bool',
                                },
                            'fullcone_ext_mem_alloc_init_faulure': {
                                'type': 'bool',
                                },
                            'mgcp_alg_create_rtp_fullcone_failure': {
                                'type': 'bool',
                                },
                            'mgcp_alg_create_rtcp_fullcone_failure': {
                                'type': 'bool',
                                },
                            'mgcp_alg_port_pair_alloc_from_quota_par': {
                                'type': 'bool',
                                },
                            'user_quota_unusable_drop': {
                                'type': 'bool',
                                },
                            'user_quota_unusable': {
                                'type': 'bool',
                                },
                            'adc_port_allocation_failed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_lsn_alg_esp': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'nat_ip_conflict': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'nat_ip_conflict': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_lsn_alg_pptp': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'no_gre_session_match': {
                                'type': 'bool',
                                },
                            'call_req_pns_call_id_mismatch': {
                                'type': 'bool',
                                },
                            'call_reply_pns_call_id_mismatch': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'no_gre_session_match': {
                                'type': 'bool',
                                },
                            'call_req_pns_call_id_mismatch': {
                                'type': 'bool',
                                },
                            'call_reply_pns_call_id_mismatch': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_lsn_alg_rtsp': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'stream_creation_failure': {
                                'type': 'bool',
                                },
                            'port_allocation_failure': {
                                'type': 'bool',
                                },
                            'unknown_client_port_from_server': {
                                'type': 'bool',
                                },
                            'no_session_mem': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'stream_creation_failure': {
                                'type': 'bool',
                                },
                            'port_allocation_failure': {
                                'type': 'bool',
                                },
                            'unknown_client_port_from_server': {
                                'type': 'bool',
                                },
                            'no_session_mem': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_lsn_alg_sip': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'method_unknown': {
                                'type': 'bool',
                                },
                            'parse_error': {
                                'type': 'bool',
                                },
                            'tcp_out_of_order_drop': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'method_unknown': {
                                'type': 'bool',
                                },
                            'parse_error': {
                                'type': 'bool',
                                },
                            'tcp_out_of_order_drop': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_lsn_alg_mgcp': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'parse_error': {
                                'type': 'bool',
                                },
                            'tcp_out_of_order_drop': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'parse_error': {
                                'type': 'bool',
                                },
                            'tcp_out_of_order_drop': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_lsn_alg_h323': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'parse_error': {
                                'type': 'bool',
                                },
                            'tcp_out_of_order_drop': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'parse_error': {
                                'type': 'bool',
                                },
                            'tcp_out_of_order_drop': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_lsn_radius': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'radius_request_dropped': {
                                'type': 'bool',
                                },
                            'request_bad_secret_dropped': {
                                'type': 'bool',
                                },
                            'request_no_key_vap_dropped': {
                                'type': 'bool',
                                },
                            'request_malformed_dropped': {
                                'type': 'bool',
                                },
                            'request_ignored': {
                                'type': 'bool',
                                },
                            'radius_table_full': {
                                'type': 'bool',
                                },
                            'secret_not_configured_dropped': {
                                'type': 'bool',
                                },
                            'ha_standby_dropped': {
                                'type': 'bool',
                                },
                            'invalid_key': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'radius_request_dropped': {
                                'type': 'bool',
                                },
                            'request_bad_secret_dropped': {
                                'type': 'bool',
                                },
                            'request_no_key_vap_dropped': {
                                'type': 'bool',
                                },
                            'request_malformed_dropped': {
                                'type': 'bool',
                                },
                            'request_ignored': {
                                'type': 'bool',
                                },
                            'radius_table_full': {
                                'type': 'bool',
                                },
                            'secret_not_configured_dropped': {
                                'type': 'bool',
                                },
                            'ha_standby_dropped': {
                                'type': 'bool',
                                },
                            'invalid_key': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_nat64_global': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'user_quota_failure': {
                                'type': 'bool',
                                },
                            'nat_port_unavailable_tcp': {
                                'type': 'bool',
                                },
                            'nat_port_unavailable_udp': {
                                'type': 'bool',
                                },
                            'nat_port_unavailable_icmp': {
                                'type': 'bool',
                                },
                            'new_user_resource_unavailable': {
                                'type': 'bool',
                                },
                            'fullcone_failure': {
                                'type': 'bool',
                                },
                            'fullcone_self_hairpinning_drop': {
                                'type': 'bool',
                                },
                            'eif_limit_exceeded': {
                                'type': 'bool',
                                },
                            'nat_pool_unusable': {
                                'type': 'bool',
                                },
                            'ha_nat_pool_unusable': {
                                'type': 'bool',
                                },
                            'ha_nat_pool_batch_type_mismatch': {
                                'type': 'bool',
                                },
                            'no_radius_profile_match': {
                                'type': 'bool',
                                },
                            'no_class_list_match': {
                                'type': 'bool',
                                },
                            'user_quota_unusable_drop': {
                                'type': 'bool',
                                },
                            'user_quota_unusable': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'user_quota_failure': {
                                'type': 'bool',
                                },
                            'nat_port_unavailable_tcp': {
                                'type': 'bool',
                                },
                            'nat_port_unavailable_udp': {
                                'type': 'bool',
                                },
                            'nat_port_unavailable_icmp': {
                                'type': 'bool',
                                },
                            'new_user_resource_unavailable': {
                                'type': 'bool',
                                },
                            'fullcone_failure': {
                                'type': 'bool',
                                },
                            'fullcone_self_hairpinning_drop': {
                                'type': 'bool',
                                },
                            'eif_limit_exceeded': {
                                'type': 'bool',
                                },
                            'nat_pool_unusable': {
                                'type': 'bool',
                                },
                            'ha_nat_pool_unusable': {
                                'type': 'bool',
                                },
                            'ha_nat_pool_batch_type_mismatch': {
                                'type': 'bool',
                                },
                            'no_radius_profile_match': {
                                'type': 'bool',
                                },
                            'no_class_list_match': {
                                'type': 'bool',
                                },
                            'user_quota_unusable_drop': {
                                'type': 'bool',
                                },
                            'user_quota_unusable': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_ds_lite_global': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'user_quota_failure': {
                                'type': 'bool',
                                },
                            'nat_port_unavailable_tcp': {
                                'type': 'bool',
                                },
                            'nat_port_unavailable_udp': {
                                'type': 'bool',
                                },
                            'nat_port_unavailable_icmp': {
                                'type': 'bool',
                                },
                            'fullcone_failure': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'user_quota_failure': {
                                'type': 'bool',
                                },
                            'nat_port_unavailable_tcp': {
                                'type': 'bool',
                                },
                            'nat_port_unavailable_udp': {
                                'type': 'bool',
                                },
                            'nat_port_unavailable_icmp': {
                                'type': 'bool',
                                },
                            'fullcone_failure': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_fixed_nat_global': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'nat_port_unavailable_tcp': {
                                'type': 'bool',
                                },
                            'nat_port_unavailable_udp': {
                                'type': 'bool',
                                },
                            'nat_port_unavailable_icmp': {
                                'type': 'bool',
                                },
                            'session_user_quota_exceeded': {
                                'type': 'bool',
                                },
                            'fullcone_failure': {
                                'type': 'bool',
                                },
                            'nat44_inbound_filtered': {
                                'type': 'bool',
                                },
                            'nat64_inbound_filtered': {
                                'type': 'bool',
                                },
                            'dslite_inbound_filtered': {
                                'type': 'bool',
                                },
                            'nat44_eif_limit_exceeded': {
                                'type': 'bool',
                                },
                            'nat64_eif_limit_exceeded': {
                                'type': 'bool',
                                },
                            'dslite_eif_limit_exceeded': {
                                'type': 'bool',
                                },
                            'standby_drop': {
                                'type': 'bool',
                                },
                            'fixed_nat_fullcone_self_hairpinning_dro': {
                                'type': 'bool',
                                },
                            'sixrd_drop': {
                                'type': 'bool',
                                },
                            'dest_rlist_drop': {
                                'type': 'bool',
                                },
                            'dest_rlist_pass_through': {
                                'type': 'bool',
                                },
                            'dest_rlist_snat_drop': {
                                'type': 'bool',
                                },
                            'config_not_found': {
                                'type': 'bool',
                                },
                            'port_overload_failed': {
                                'type': 'bool',
                                },
                            'ha_session_user_quota_exceeded': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'nat_port_unavailable_tcp': {
                                'type': 'bool',
                                },
                            'nat_port_unavailable_udp': {
                                'type': 'bool',
                                },
                            'nat_port_unavailable_icmp': {
                                'type': 'bool',
                                },
                            'session_user_quota_exceeded': {
                                'type': 'bool',
                                },
                            'fullcone_failure': {
                                'type': 'bool',
                                },
                            'nat44_inbound_filtered': {
                                'type': 'bool',
                                },
                            'nat64_inbound_filtered': {
                                'type': 'bool',
                                },
                            'dslite_inbound_filtered': {
                                'type': 'bool',
                                },
                            'nat44_eif_limit_exceeded': {
                                'type': 'bool',
                                },
                            'nat64_eif_limit_exceeded': {
                                'type': 'bool',
                                },
                            'dslite_eif_limit_exceeded': {
                                'type': 'bool',
                                },
                            'standby_drop': {
                                'type': 'bool',
                                },
                            'fixed_nat_fullcone_self_hairpinning_dro': {
                                'type': 'bool',
                                },
                            'sixrd_drop': {
                                'type': 'bool',
                                },
                            'dest_rlist_drop': {
                                'type': 'bool',
                                },
                            'dest_rlist_pass_through': {
                                'type': 'bool',
                                },
                            'dest_rlist_snat_drop': {
                                'type': 'bool',
                                },
                            'config_not_found': {
                                'type': 'bool',
                                },
                            'port_overload_failed': {
                                'type': 'bool',
                                },
                            'ha_session_user_quota_exceeded': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_fixed_nat_alg_pptp': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'call_req_pns_call_id_mismatch': {
                                'type': 'bool',
                                },
                            'call_reply_pns_call_id_mismatch': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'call_req_pns_call_id_mismatch': {
                                'type': 'bool',
                                },
                            'call_reply_pns_call_id_mismatch': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_fixed_nat_alg_rtsp': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'stream_creation_failure': {
                                'type': 'bool',
                                },
                            'port_allocation_failure': {
                                'type': 'bool',
                                },
                            'no_session_mem': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'stream_creation_failure': {
                                'type': 'bool',
                                },
                            'port_allocation_failure': {
                                'type': 'bool',
                                },
                            'no_session_mem': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_fixed_nat_alg_sip': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'method_unknown': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'method_unknown': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_pcp': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'pkt_not_request_drop': {
                                'type': 'bool',
                                },
                            'pkt_too_short_drop': {
                                'type': 'bool',
                                },
                            'noroute_drop': {
                                'type': 'bool',
                                },
                            'unsupported_version': {
                                'type': 'bool',
                                },
                            'not_authorized': {
                                'type': 'bool',
                                },
                            'malform_request': {
                                'type': 'bool',
                                },
                            'unsupp_opcode': {
                                'type': 'bool',
                                },
                            'unsupp_option': {
                                'type': 'bool',
                                },
                            'malform_option': {
                                'type': 'bool',
                                },
                            'no_resources': {
                                'type': 'bool',
                                },
                            'unsupp_protocol': {
                                'type': 'bool',
                                },
                            'cannot_provide_suggest': {
                                'type': 'bool',
                                },
                            'address_mismatch': {
                                'type': 'bool',
                                },
                            'excessive_remote_peers': {
                                'type': 'bool',
                                },
                            'pkt_not_from_nat_inside': {
                                'type': 'bool',
                                },
                            'l4_process_error': {
                                'type': 'bool',
                                },
                            'internal_error_drop': {
                                'type': 'bool',
                                },
                            'unsol_ance_sent_fail': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'pkt_not_request_drop': {
                                'type': 'bool',
                                },
                            'pkt_too_short_drop': {
                                'type': 'bool',
                                },
                            'noroute_drop': {
                                'type': 'bool',
                                },
                            'unsupported_version': {
                                'type': 'bool',
                                },
                            'not_authorized': {
                                'type': 'bool',
                                },
                            'malform_request': {
                                'type': 'bool',
                                },
                            'unsupp_opcode': {
                                'type': 'bool',
                                },
                            'unsupp_option': {
                                'type': 'bool',
                                },
                            'malform_option': {
                                'type': 'bool',
                                },
                            'no_resources': {
                                'type': 'bool',
                                },
                            'unsupp_protocol': {
                                'type': 'bool',
                                },
                            'cannot_provide_suggest': {
                                'type': 'bool',
                                },
                            'address_mismatch': {
                                'type': 'bool',
                                },
                            'excessive_remote_peers': {
                                'type': 'bool',
                                },
                            'pkt_not_from_nat_inside': {
                                'type': 'bool',
                                },
                            'l4_process_error': {
                                'type': 'bool',
                                },
                            'internal_error_drop': {
                                'type': 'bool',
                                },
                            'unsol_ance_sent_fail': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_logging': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'log_dropped': {
                                'type': 'bool',
                                },
                            'conn_tcp_dropped': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'log_dropped': {
                                'type': 'bool',
                                },
                            'conn_tcp_dropped': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_l4': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'out_of_session_memory': {
                                'type': 'bool',
                                },
                            'icmp_host_unreachable_sent': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'out_of_session_memory': {
                                'type': 'bool',
                                },
                            'icmp_host_unreachable_sent': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_icmp': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'icmp_to_icmp_err': {
                                'type': 'bool',
                                },
                            'icmp_to_icmpv6_err': {
                                'type': 'bool',
                                },
                            'icmpv6_to_icmp_err': {
                                'type': 'bool',
                                },
                            'icmpv6_to_icmpv6_err': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'icmp_to_icmp_err': {
                                'type': 'bool',
                                },
                            'icmp_to_icmpv6_err': {
                                'type': 'bool',
                                },
                            'icmpv6_to_icmp_err': {
                                'type': 'bool',
                                },
                            'icmpv6_to_icmpv6_err': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_http_alg': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'radius_requst_dropped': {
                                'type': 'bool',
                                },
                            'radius_response_dropped': {
                                'type': 'bool',
                                },
                            'out_of_memory_dropped': {
                                'type': 'bool',
                                },
                            'queue_len_exceed_dropped': {
                                'type': 'bool',
                                },
                            'out_of_order_dropped': {
                                'type': 'bool',
                                },
                            'header_insertion_failed': {
                                'type': 'bool',
                                },
                            'header_removal_failed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'radius_requst_dropped': {
                                'type': 'bool',
                                },
                            'radius_response_dropped': {
                                'type': 'bool',
                                },
                            'out_of_memory_dropped': {
                                'type': 'bool',
                                },
                            'queue_len_exceed_dropped': {
                                'type': 'bool',
                                },
                            'out_of_order_dropped': {
                                'type': 'bool',
                                },
                            'header_insertion_failed': {
                                'type': 'bool',
                                },
                            'header_removal_failed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_dns64': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'query_bad_pkt': {
                                'type': 'bool',
                                },
                            'resp_bad_pkt': {
                                'type': 'bool',
                                },
                            'resp_bad_qr': {
                                'type': 'bool',
                                },
                            'drop': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'query_bad_pkt': {
                                'type': 'bool',
                                },
                            'resp_bad_pkt': {
                                'type': 'bool',
                                },
                            'resp_bad_qr': {
                                'type': 'bool',
                                },
                            'drop': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'cgnv6_dhcpv6': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'packets_dropped': {
                                'type': 'bool',
                                },
                            'pkts_dropped_during_clear': {
                                'type': 'bool',
                                },
                            'rcv_not_supported_msg': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'packets_dropped': {
                                'type': 'bool',
                                },
                            'pkts_dropped_during_clear': {
                                'type': 'bool',
                                },
                            'rcv_not_supported_msg': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'fw_logging': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'log_dropped': {
                                'type': 'bool',
                                },
                            'http_logging_invalid_format': {
                                'type': 'bool',
                                },
                            'session_limit_exceeded': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'log_dropped': {
                                'type': 'bool',
                                },
                            'http_logging_invalid_format': {
                                'type': 'bool',
                                },
                            'session_limit_exceeded': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'fw_global': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'fullcone_creation_failure': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'fullcone_creation_failure': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'fw_alg_rtsp': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'transport_alloc_failure': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'transport_alloc_failure': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'fw_alg_pptp': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'call_req_pns_call_id_mismatch': {
                                'type': 'bool',
                                },
                            'call_reply_pns_call_id_mismatch': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'call_req_pns_call_id_mismatch': {
                                'type': 'bool',
                                },
                            'call_reply_pns_call_id_mismatch': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'fw_rad_server': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'radius_request_dropped': {
                                'type': 'bool',
                                },
                            'request_bad_secret_dropped': {
                                'type': 'bool',
                                },
                            'request_no_key_vap_dropped': {
                                'type': 'bool',
                                },
                            'request_malformed_dropped': {
                                'type': 'bool',
                                },
                            'request_ignored': {
                                'type': 'bool',
                                },
                            'radius_table_full': {
                                'type': 'bool',
                                },
                            'ha_standby_dropped': {
                                'type': 'bool',
                                },
                            'ipv6_prefix_length_mismatch': {
                                'type': 'bool',
                                },
                            'invalid_key': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'radius_request_dropped': {
                                'type': 'bool',
                                },
                            'request_bad_secret_dropped': {
                                'type': 'bool',
                                },
                            'request_no_key_vap_dropped': {
                                'type': 'bool',
                                },
                            'request_malformed_dropped': {
                                'type': 'bool',
                                },
                            'request_ignored': {
                                'type': 'bool',
                                },
                            'radius_table_full': {
                                'type': 'bool',
                                },
                            'ha_standby_dropped': {
                                'type': 'bool',
                                },
                            'ipv6_prefix_length_mismatch': {
                                'type': 'bool',
                                },
                            'invalid_key': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'fw_tcp_syn_cookie': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'verification_failed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'verification_failed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'fw_ddos_protection': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'ddos_entries_too_many': {
                                'type': 'bool',
                                },
                            'ddos_entry_add_to_bgp_failure': {
                                'type': 'bool',
                                },
                            'ddos_entry_remove_from_bgp_failure': {
                                'type': 'bool',
                                },
                            'ddos_packet_dropped': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'ddos_entries_too_many': {
                                'type': 'bool',
                                },
                            'ddos_entry_add_to_bgp_failure': {
                                'type': 'bool',
                                },
                            'ddos_entry_remove_from_bgp_failure': {
                                'type': 'bool',
                                },
                            'ddos_packet_dropped': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'fw_gtp': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'out_of_session_memory': {
                                'type': 'bool',
                                },
                            'blade_out_of_session_memory': {
                                'type': 'bool',
                                },
                            'gtp_smp_path_check_failed': {
                                'type': 'bool',
                                },
                            'gtp_smp_c_check_failed': {
                                'type': 'bool',
                                },
                            'blade_gtp_smp_path_check_failed': {
                                'type': 'bool',
                                },
                            'blade_gtp_smp_c_check_failed': {
                                'type': 'bool',
                                },
                            'gtp_tunnel_rate_limit_entry_create_fail': {
                                'type': 'bool',
                                },
                            'gtp_u_tunnel_rate_limit_entry_create_fa': {
                                'type': 'bool',
                                },
                            'gtp_rate_limit_smp_create_failure': {
                                'type': 'bool',
                                },
                            'gtp_rate_limit_t3_ctr_create_failure': {
                                'type': 'bool',
                                },
                            'gtp_rate_limit_entry_create_failure': {
                                'type': 'bool',
                                },
                            'blade_gtp_rate_limit_smp_create_failure': {
                                'type': 'bool',
                                },
                            'blade_gtp_rate_limit_t3_ctr_create_fail': {
                                'type': 'bool',
                                },
                            'blade_gtp_rate_limit_entry_create_failu': {
                                'type': 'bool',
                                },
                            'gtp_smp_dec_sess_count_check_failed': {
                                'type': 'bool',
                                },
                            'gtp_u_smp_check_failed': {
                                'type': 'bool',
                                },
                            'gtp_info_ext_not_found': {
                                'type': 'bool',
                                },
                            'blade_gtp_smp_dec_sess_count_check_fail': {
                                'type': 'bool',
                                },
                            'blade_gtp_u_smp_check_failed': {
                                'type': 'bool',
                                },
                            'blade_gtp_info_ext_not_found': {
                                'type': 'bool',
                                },
                            'blade_gtp_smp_session_count_check_faile': {
                                'type': 'bool',
                                },
                            'gtp_c_smp_sig_check_failed': {
                                'type': 'bool',
                                },
                            'blade_gtp_c_smp_sig_check_failed': {
                                'type': 'bool',
                                },
                            'gtp_u_smp_sig_check_failed': {
                                'type': 'bool',
                                },
                            'blade_gtp_u_smp_sig_check_failed': {
                                'type': 'bool',
                                },
                            'gtp_smp_sig_check_failed': {
                                'type': 'bool',
                                },
                            'blade_gtp_smp_sig_check_failed': {
                                'type': 'bool',
                                },
                            'gtp_c_fail_conn_create_slow': {
                                'type': 'bool',
                                },
                            'gtp_u_fail_conn_create_slow': {
                                'type': 'bool',
                                },
                            'gtp_pathm_fail_conn_create_slow': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'out_of_session_memory': {
                                'type': 'bool',
                                },
                            'blade_out_of_session_memory': {
                                'type': 'bool',
                                },
                            'gtp_smp_path_check_failed': {
                                'type': 'bool',
                                },
                            'gtp_smp_c_check_failed': {
                                'type': 'bool',
                                },
                            'blade_gtp_smp_path_check_failed': {
                                'type': 'bool',
                                },
                            'blade_gtp_smp_c_check_failed': {
                                'type': 'bool',
                                },
                            'gtp_tunnel_rate_limit_entry_create_fail': {
                                'type': 'bool',
                                },
                            'gtp_u_tunnel_rate_limit_entry_create_fa': {
                                'type': 'bool',
                                },
                            'gtp_rate_limit_smp_create_failure': {
                                'type': 'bool',
                                },
                            'gtp_rate_limit_t3_ctr_create_failure': {
                                'type': 'bool',
                                },
                            'gtp_rate_limit_entry_create_failure': {
                                'type': 'bool',
                                },
                            'blade_gtp_rate_limit_smp_create_failure': {
                                'type': 'bool',
                                },
                            'blade_gtp_rate_limit_t3_ctr_create_fail': {
                                'type': 'bool',
                                },
                            'blade_gtp_rate_limit_entry_create_failu': {
                                'type': 'bool',
                                },
                            'gtp_smp_dec_sess_count_check_failed': {
                                'type': 'bool',
                                },
                            'gtp_u_smp_check_failed': {
                                'type': 'bool',
                                },
                            'gtp_info_ext_not_found': {
                                'type': 'bool',
                                },
                            'blade_gtp_smp_dec_sess_count_check_fail': {
                                'type': 'bool',
                                },
                            'blade_gtp_u_smp_check_failed': {
                                'type': 'bool',
                                },
                            'blade_gtp_info_ext_not_found': {
                                'type': 'bool',
                                },
                            'blade_gtp_smp_session_count_check_faile': {
                                'type': 'bool',
                                },
                            'gtp_c_smp_sig_check_failed': {
                                'type': 'bool',
                                },
                            'blade_gtp_c_smp_sig_check_failed': {
                                'type': 'bool',
                                },
                            'gtp_u_smp_sig_check_failed': {
                                'type': 'bool',
                                },
                            'blade_gtp_u_smp_sig_check_failed': {
                                'type': 'bool',
                                },
                            'gtp_smp_sig_check_failed': {
                                'type': 'bool',
                                },
                            'blade_gtp_smp_sig_check_failed': {
                                'type': 'bool',
                                },
                            'gtp_c_fail_conn_create_slow': {
                                'type': 'bool',
                                },
                            'gtp_u_fail_conn_create_slow': {
                                'type': 'bool',
                                },
                            'gtp_pathm_fail_conn_create_slow': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'system_tcp': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'attemptfails': {
                                'type': 'bool',
                                },
                            'noroute': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'attemptfails': {
                                'type': 'bool',
                                },
                            'noroute': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_conn_reuse': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'ntermi_err': {
                                'type': 'bool',
                                },
                            'pause_conn_fail': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'ntermi_err': {
                                'type': 'bool',
                                },
                            'pause_conn_fail': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_aflow': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'pause_conn_fail': {
                                'type': 'bool',
                                },
                            'error_resume_conn': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'pause_conn_fail': {
                                'type': 'bool',
                                },
                            'error_resume_conn': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_fix': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'svrsel_fail': {
                                'type': 'bool',
                                },
                            'noroute': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'client_err': {
                                'type': 'bool',
                                },
                            'server_err': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'svrsel_fail': {
                                'type': 'bool',
                                },
                            'noroute': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'client_err': {
                                'type': 'bool',
                                },
                            'server_err': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_spdy_proxy': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'tcp_err': {
                                'type': 'bool',
                                },
                            'stream_not_found': {
                                'type': 'bool',
                                },
                            'stream_err': {
                                'type': 'bool',
                                },
                            'session_err': {
                                'type': 'bool',
                                },
                            'data_no_stream': {
                                'type': 'bool',
                                },
                            'data_no_stream_no_goaway': {
                                'type': 'bool',
                                },
                            'data_no_stream_goaway_close': {
                                'type': 'bool',
                                },
                            'est_cb_no_tuple': {
                                'type': 'bool',
                                },
                            'data_cb_no_tuple': {
                                'type': 'bool',
                                },
                            'ctx_alloc_fail': {
                                'type': 'bool',
                                },
                            'stream_alloc_fail': {
                                'type': 'bool',
                                },
                            'http_conn_alloc_fail': {
                                'type': 'bool',
                                },
                            'request_header_alloc_fail': {
                                'type': 'bool',
                                },
                            'decompress_fail': {
                                'type': 'bool',
                                },
                            'invalid_frame_size': {
                                'type': 'bool',
                                },
                            'invalid_version': {
                                'type': 'bool',
                                },
                            'compress_ctx_alloc_fail': {
                                'type': 'bool',
                                },
                            'header_compress_fail': {
                                'type': 'bool',
                                },
                            'http_err_stream_closed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'tcp_err': {
                                'type': 'bool',
                                },
                            'stream_not_found': {
                                'type': 'bool',
                                },
                            'stream_err': {
                                'type': 'bool',
                                },
                            'session_err': {
                                'type': 'bool',
                                },
                            'data_no_stream': {
                                'type': 'bool',
                                },
                            'data_no_stream_no_goaway': {
                                'type': 'bool',
                                },
                            'data_no_stream_goaway_close': {
                                'type': 'bool',
                                },
                            'est_cb_no_tuple': {
                                'type': 'bool',
                                },
                            'data_cb_no_tuple': {
                                'type': 'bool',
                                },
                            'ctx_alloc_fail': {
                                'type': 'bool',
                                },
                            'stream_alloc_fail': {
                                'type': 'bool',
                                },
                            'http_conn_alloc_fail': {
                                'type': 'bool',
                                },
                            'request_header_alloc_fail': {
                                'type': 'bool',
                                },
                            'decompress_fail': {
                                'type': 'bool',
                                },
                            'invalid_frame_size': {
                                'type': 'bool',
                                },
                            'invalid_version': {
                                'type': 'bool',
                                },
                            'compress_ctx_alloc_fail': {
                                'type': 'bool',
                                },
                            'header_compress_fail': {
                                'type': 'bool',
                                },
                            'http_err_stream_closed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_http2': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'protocol_error': {
                                'type': 'bool',
                                },
                            'internal_error': {
                                'type': 'bool',
                                },
                            'proxy_alloc_error': {
                                'type': 'bool',
                                },
                            'split_buff_fail': {
                                'type': 'bool',
                                },
                            'invalid_frame_size': {
                                'type': 'bool',
                                },
                            'error_max_invalid_stream': {
                                'type': 'bool',
                                },
                            'data_no_stream': {
                                'type': 'bool',
                                },
                            'flow_control_error': {
                                'type': 'bool',
                                },
                            'settings_timeout': {
                                'type': 'bool',
                                },
                            'frame_size_error': {
                                'type': 'bool',
                                },
                            'refused_stream': {
                                'type': 'bool',
                                },
                            'cancel': {
                                'type': 'bool',
                                },
                            'compression_error': {
                                'type': 'bool',
                                },
                            'connect_error': {
                                'type': 'bool',
                                },
                            'enhance_your_calm': {
                                'type': 'bool',
                                },
                            'inadequate_security': {
                                'type': 'bool',
                                },
                            'http_1_1_required': {
                                'type': 'bool',
                                },
                            'deflate_alloc_fail': {
                                'type': 'bool',
                                },
                            'inflate_alloc_fail': {
                                'type': 'bool',
                                },
                            'inflate_header_fail': {
                                'type': 'bool',
                                },
                            'bad_connection_preface': {
                                'type': 'bool',
                                },
                            'cant_allocate_control_frame': {
                                'type': 'bool',
                                },
                            'cant_allocate_settings_frame': {
                                'type': 'bool',
                                },
                            'bad_frame_type_for_stream_state': {
                                'type': 'bool',
                                },
                            'wrong_stream_state': {
                                'type': 'bool',
                                },
                            'data_queue_alloc_error': {
                                'type': 'bool',
                                },
                            'buff_alloc_error': {
                                'type': 'bool',
                                },
                            'cant_allocate_rst_frame': {
                                'type': 'bool',
                                },
                            'cant_allocate_goaway_frame': {
                                'type': 'bool',
                                },
                            'cant_allocate_ping_frame': {
                                'type': 'bool',
                                },
                            'cant_allocate_stream': {
                                'type': 'bool',
                                },
                            'cant_allocate_window_frame': {
                                'type': 'bool',
                                },
                            'header_no_stream': {
                                'type': 'bool',
                                },
                            'header_padlen_gt_frame_payload': {
                                'type': 'bool',
                                },
                            'streams_gt_max_concur_streams': {
                                'type': 'bool',
                                },
                            'idle_state_unexpected_frame': {
                                'type': 'bool',
                                },
                            'reserved_local_state_unexpected_frame': {
                                'type': 'bool',
                                },
                            'reserved_remote_state_unexpected_frame': {
                                'type': 'bool',
                                },
                            'half_closed_remote_state_unexpected_fra': {
                                'type': 'bool',
                                },
                            'closed_state_unexpected_frame': {
                                'type': 'bool',
                                },
                            'zero_window_size_on_stream': {
                                'type': 'bool',
                                },
                            'exceeds_max_window_size_stream': {
                                'type': 'bool',
                                },
                            'continuation_before_headers': {
                                'type': 'bool',
                                },
                            'invalid_frame_during_headers': {
                                'type': 'bool',
                                },
                            'headers_after_continuation': {
                                'type': 'bool',
                                },
                            'invalid_push_promise': {
                                'type': 'bool',
                                },
                            'invalid_stream_id': {
                                'type': 'bool',
                                },
                            'headers_interleaved': {
                                'type': 'bool',
                                },
                            'trailers_no_end_stream': {
                                'type': 'bool',
                                },
                            'invalid_setting_value': {
                                'type': 'bool',
                                },
                            'invalid_window_update': {
                                'type': 'bool',
                                },
                            'alloc_fail_total': {
                                'type': 'bool',
                                },
                            'err_rcvd_total': {
                                'type': 'bool',
                                },
                            'err_sent_total': {
                                'type': 'bool',
                                },
                            'err_sent_proto_err': {
                                'type': 'bool',
                                },
                            'err_sent_internal_err': {
                                'type': 'bool',
                                },
                            'err_sent_flow_control': {
                                'type': 'bool',
                                },
                            'err_sent_setting_timeout': {
                                'type': 'bool',
                                },
                            'err_sent_stream_closed': {
                                'type': 'bool',
                                },
                            'err_sent_frame_size_err': {
                                'type': 'bool',
                                },
                            'err_sent_refused_stream': {
                                'type': 'bool',
                                },
                            'err_sent_cancel': {
                                'type': 'bool',
                                },
                            'err_sent_compression_err': {
                                'type': 'bool',
                                },
                            'err_sent_connect_err': {
                                'type': 'bool',
                                },
                            'err_sent_your_calm': {
                                'type': 'bool',
                                },
                            'err_sent_inadequate_security': {
                                'type': 'bool',
                                },
                            'err_sent_http11_required': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'protocol_error': {
                                'type': 'bool',
                                },
                            'internal_error': {
                                'type': 'bool',
                                },
                            'proxy_alloc_error': {
                                'type': 'bool',
                                },
                            'split_buff_fail': {
                                'type': 'bool',
                                },
                            'invalid_frame_size': {
                                'type': 'bool',
                                },
                            'error_max_invalid_stream': {
                                'type': 'bool',
                                },
                            'data_no_stream': {
                                'type': 'bool',
                                },
                            'flow_control_error': {
                                'type': 'bool',
                                },
                            'settings_timeout': {
                                'type': 'bool',
                                },
                            'frame_size_error': {
                                'type': 'bool',
                                },
                            'refused_stream': {
                                'type': 'bool',
                                },
                            'cancel': {
                                'type': 'bool',
                                },
                            'compression_error': {
                                'type': 'bool',
                                },
                            'connect_error': {
                                'type': 'bool',
                                },
                            'enhance_your_calm': {
                                'type': 'bool',
                                },
                            'inadequate_security': {
                                'type': 'bool',
                                },
                            'http_1_1_required': {
                                'type': 'bool',
                                },
                            'deflate_alloc_fail': {
                                'type': 'bool',
                                },
                            'inflate_alloc_fail': {
                                'type': 'bool',
                                },
                            'inflate_header_fail': {
                                'type': 'bool',
                                },
                            'bad_connection_preface': {
                                'type': 'bool',
                                },
                            'cant_allocate_control_frame': {
                                'type': 'bool',
                                },
                            'cant_allocate_settings_frame': {
                                'type': 'bool',
                                },
                            'bad_frame_type_for_stream_state': {
                                'type': 'bool',
                                },
                            'wrong_stream_state': {
                                'type': 'bool',
                                },
                            'data_queue_alloc_error': {
                                'type': 'bool',
                                },
                            'buff_alloc_error': {
                                'type': 'bool',
                                },
                            'cant_allocate_rst_frame': {
                                'type': 'bool',
                                },
                            'cant_allocate_goaway_frame': {
                                'type': 'bool',
                                },
                            'cant_allocate_ping_frame': {
                                'type': 'bool',
                                },
                            'cant_allocate_stream': {
                                'type': 'bool',
                                },
                            'cant_allocate_window_frame': {
                                'type': 'bool',
                                },
                            'header_no_stream': {
                                'type': 'bool',
                                },
                            'header_padlen_gt_frame_payload': {
                                'type': 'bool',
                                },
                            'streams_gt_max_concur_streams': {
                                'type': 'bool',
                                },
                            'idle_state_unexpected_frame': {
                                'type': 'bool',
                                },
                            'reserved_local_state_unexpected_frame': {
                                'type': 'bool',
                                },
                            'reserved_remote_state_unexpected_frame': {
                                'type': 'bool',
                                },
                            'half_closed_remote_state_unexpected_fra': {
                                'type': 'bool',
                                },
                            'closed_state_unexpected_frame': {
                                'type': 'bool',
                                },
                            'zero_window_size_on_stream': {
                                'type': 'bool',
                                },
                            'exceeds_max_window_size_stream': {
                                'type': 'bool',
                                },
                            'continuation_before_headers': {
                                'type': 'bool',
                                },
                            'invalid_frame_during_headers': {
                                'type': 'bool',
                                },
                            'headers_after_continuation': {
                                'type': 'bool',
                                },
                            'invalid_push_promise': {
                                'type': 'bool',
                                },
                            'invalid_stream_id': {
                                'type': 'bool',
                                },
                            'headers_interleaved': {
                                'type': 'bool',
                                },
                            'trailers_no_end_stream': {
                                'type': 'bool',
                                },
                            'invalid_setting_value': {
                                'type': 'bool',
                                },
                            'invalid_window_update': {
                                'type': 'bool',
                                },
                            'alloc_fail_total': {
                                'type': 'bool',
                                },
                            'err_rcvd_total': {
                                'type': 'bool',
                                },
                            'err_sent_total': {
                                'type': 'bool',
                                },
                            'err_sent_proto_err': {
                                'type': 'bool',
                                },
                            'err_sent_internal_err': {
                                'type': 'bool',
                                },
                            'err_sent_flow_control': {
                                'type': 'bool',
                                },
                            'err_sent_setting_timeout': {
                                'type': 'bool',
                                },
                            'err_sent_stream_closed': {
                                'type': 'bool',
                                },
                            'err_sent_frame_size_err': {
                                'type': 'bool',
                                },
                            'err_sent_refused_stream': {
                                'type': 'bool',
                                },
                            'err_sent_cancel': {
                                'type': 'bool',
                                },
                            'err_sent_compression_err': {
                                'type': 'bool',
                                },
                            'err_sent_connect_err': {
                                'type': 'bool',
                                },
                            'err_sent_your_calm': {
                                'type': 'bool',
                                },
                            'err_sent_inadequate_security': {
                                'type': 'bool',
                                },
                            'err_sent_http11_required': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_l7session': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'conn_not_exist': {
                                'type': 'bool',
                                },
                            'wbuf_cb_failed': {
                                'type': 'bool',
                                },
                            'err_event': {
                                'type': 'bool',
                                },
                            'err_cb_failed': {
                                'type': 'bool',
                                },
                            'server_conn_failed': {
                                'type': 'bool',
                                },
                            'server_select_fail': {
                                'type': 'bool',
                                },
                            'data_cb_failed': {
                                'type': 'bool',
                                },
                            'hps_fwdreq_fail': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'conn_not_exist': {
                                'type': 'bool',
                                },
                            'wbuf_cb_failed': {
                                'type': 'bool',
                                },
                            'err_event': {
                                'type': 'bool',
                                },
                            'err_cb_failed': {
                                'type': 'bool',
                                },
                            'server_conn_failed': {
                                'type': 'bool',
                                },
                            'server_select_fail': {
                                'type': 'bool',
                                },
                            'data_cb_failed': {
                                'type': 'bool',
                                },
                            'hps_fwdreq_fail': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_smpp': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'msg_proxy_client_fail': {
                                'type': 'bool',
                                },
                            'msg_proxy_server_fail': {
                                'type': 'bool',
                                },
                            'msg_proxy_fail_start_server_conn': {
                                'type': 'bool',
                                },
                            'select_client_fail': {
                                'type': 'bool',
                                },
                            'select_server_fail': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'msg_proxy_client_fail': {
                                'type': 'bool',
                                },
                            'msg_proxy_server_fail': {
                                'type': 'bool',
                                },
                            'msg_proxy_fail_start_server_conn': {
                                'type': 'bool',
                                },
                            'select_client_fail': {
                                'type': 'bool',
                                },
                            'select_server_fail': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_smtp': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'no_proxy': {
                                'type': 'bool',
                                },
                            'parse_req_fail': {
                                'type': 'bool',
                                },
                            'server_select_fail': {
                                'type': 'bool',
                                },
                            'forward_req_fail': {
                                'type': 'bool',
                                },
                            'forward_req_data_fail': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'send_client_service_not_ready': {
                                'type': 'bool',
                                },
                            'recv_server_unknow_reply_code': {
                                'type': 'bool',
                                },
                            'read_request_line_fail': {
                                'type': 'bool',
                                },
                            'get_all_headers_fail': {
                                'type': 'bool',
                                },
                            'too_many_headers': {
                                'type': 'bool',
                                },
                            'line_too_long': {
                                'type': 'bool',
                                },
                            'line_extend_fail': {
                                'type': 'bool',
                                },
                            'line_table_extend_fail': {
                                'type': 'bool',
                                },
                            'parse_request_line_fail': {
                                'type': 'bool',
                                },
                            'insert_resonse_line_fail': {
                                'type': 'bool',
                                },
                            'remove_resonse_line_fail': {
                                'type': 'bool',
                                },
                            'parse_resonse_line_fail': {
                                'type': 'bool',
                                },
                            'server_STARTTLS_fail': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'no_proxy': {
                                'type': 'bool',
                                },
                            'parse_req_fail': {
                                'type': 'bool',
                                },
                            'server_select_fail': {
                                'type': 'bool',
                                },
                            'forward_req_fail': {
                                'type': 'bool',
                                },
                            'forward_req_data_fail': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'send_client_service_not_ready': {
                                'type': 'bool',
                                },
                            'recv_server_unknow_reply_code': {
                                'type': 'bool',
                                },
                            'read_request_line_fail': {
                                'type': 'bool',
                                },
                            'get_all_headers_fail': {
                                'type': 'bool',
                                },
                            'too_many_headers': {
                                'type': 'bool',
                                },
                            'line_too_long': {
                                'type': 'bool',
                                },
                            'line_extend_fail': {
                                'type': 'bool',
                                },
                            'line_table_extend_fail': {
                                'type': 'bool',
                                },
                            'parse_request_line_fail': {
                                'type': 'bool',
                                },
                            'insert_resonse_line_fail': {
                                'type': 'bool',
                                },
                            'remove_resonse_line_fail': {
                                'type': 'bool',
                                },
                            'parse_resonse_line_fail': {
                                'type': 'bool',
                                },
                            'server_STARTTLS_fail': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_mqtt': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'parse_connect_fail': {
                                'type': 'bool',
                                },
                            'parse_publish_fail': {
                                'type': 'bool',
                                },
                            'parse_subscribe_fail': {
                                'type': 'bool',
                                },
                            'parse_unsubscribe_fail': {
                                'type': 'bool',
                                },
                            'tuple_not_linked': {
                                'type': 'bool',
                                },
                            'tuple_already_linked': {
                                'type': 'bool',
                                },
                            'conn_null': {
                                'type': 'bool',
                                },
                            'client_id_null': {
                                'type': 'bool',
                                },
                            'session_exist': {
                                'type': 'bool',
                                },
                            'insertion_failed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'parse_connect_fail': {
                                'type': 'bool',
                                },
                            'parse_publish_fail': {
                                'type': 'bool',
                                },
                            'parse_subscribe_fail': {
                                'type': 'bool',
                                },
                            'parse_unsubscribe_fail': {
                                'type': 'bool',
                                },
                            'tuple_not_linked': {
                                'type': 'bool',
                                },
                            'tuple_already_linked': {
                                'type': 'bool',
                                },
                            'conn_null': {
                                'type': 'bool',
                                },
                            'client_id_null': {
                                'type': 'bool',
                                },
                            'session_exist': {
                                'type': 'bool',
                                },
                            'insertion_failed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_icap': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'app_serv_conn_no_pcb_err': {
                                'type': 'bool',
                                },
                            'app_serv_conn_err': {
                                'type': 'bool',
                                },
                            'chunk1_hdr_err': {
                                'type': 'bool',
                                },
                            'chunk2_hdr_err': {
                                'type': 'bool',
                                },
                            'chunk_bad_trail_err': {
                                'type': 'bool',
                                },
                            'no_payload_next_buff_err': {
                                'type': 'bool',
                                },
                            'no_payload_buff_err': {
                                'type': 'bool',
                                },
                            'resp_hdr_incomplete_err': {
                                'type': 'bool',
                                },
                            'serv_sel_fail_err': {
                                'type': 'bool',
                                },
                            'start_icap_conn_fail_err': {
                                'type': 'bool',
                                },
                            'prep_req_fail_err': {
                                'type': 'bool',
                                },
                            'icap_ver_err': {
                                'type': 'bool',
                                },
                            'icap_line_err': {
                                'type': 'bool',
                                },
                            'encap_hdr_incomplete_err': {
                                'type': 'bool',
                                },
                            'no_icap_resp_err': {
                                'type': 'bool',
                                },
                            'resp_line_read_err': {
                                'type': 'bool',
                                },
                            'resp_line_parse_err': {
                                'type': 'bool',
                                },
                            'resp_hdr_err': {
                                'type': 'bool',
                                },
                            'req_hdr_incomplete_err': {
                                'type': 'bool',
                                },
                            'no_status_code_err': {
                                'type': 'bool',
                                },
                            'http_resp_line_read_err': {
                                'type': 'bool',
                                },
                            'http_resp_line_parse_err': {
                                'type': 'bool',
                                },
                            'http_resp_hdr_err': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'app_serv_conn_no_pcb_err': {
                                'type': 'bool',
                                },
                            'app_serv_conn_err': {
                                'type': 'bool',
                                },
                            'chunk1_hdr_err': {
                                'type': 'bool',
                                },
                            'chunk2_hdr_err': {
                                'type': 'bool',
                                },
                            'chunk_bad_trail_err': {
                                'type': 'bool',
                                },
                            'no_payload_next_buff_err': {
                                'type': 'bool',
                                },
                            'no_payload_buff_err': {
                                'type': 'bool',
                                },
                            'resp_hdr_incomplete_err': {
                                'type': 'bool',
                                },
                            'serv_sel_fail_err': {
                                'type': 'bool',
                                },
                            'start_icap_conn_fail_err': {
                                'type': 'bool',
                                },
                            'prep_req_fail_err': {
                                'type': 'bool',
                                },
                            'icap_ver_err': {
                                'type': 'bool',
                                },
                            'icap_line_err': {
                                'type': 'bool',
                                },
                            'encap_hdr_incomplete_err': {
                                'type': 'bool',
                                },
                            'no_icap_resp_err': {
                                'type': 'bool',
                                },
                            'resp_line_read_err': {
                                'type': 'bool',
                                },
                            'resp_line_parse_err': {
                                'type': 'bool',
                                },
                            'resp_hdr_err': {
                                'type': 'bool',
                                },
                            'req_hdr_incomplete_err': {
                                'type': 'bool',
                                },
                            'no_status_code_err': {
                                'type': 'bool',
                                },
                            'http_resp_line_read_err': {
                                'type': 'bool',
                                },
                            'http_resp_line_parse_err': {
                                'type': 'bool',
                                },
                            'http_resp_hdr_err': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_sip': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'msg_proxy_client_fail': {
                                'type': 'bool',
                                },
                            'msg_proxy_server_fail': {
                                'type': 'bool',
                                },
                            'msg_proxy_fail_start_server_conn': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'msg_proxy_client_fail': {
                                'type': 'bool',
                                },
                            'msg_proxy_server_fail': {
                                'type': 'bool',
                                },
                            'msg_proxy_fail_start_server_conn': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_hw_compress': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'failure_count': {
                                'type': 'bool',
                                },
                            'failure_code': {
                                'type': 'bool',
                                },
                            'ring_full_count': {
                                'type': 'bool',
                                },
                            'max_outstanding_request_count': {
                                'type': 'bool',
                                },
                            'max_outstanding_submit_count': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'failure_count': {
                                'type': 'bool',
                                },
                            'failure_code': {
                                'type': 'bool',
                                },
                            'ring_full_count': {
                                'type': 'bool',
                                },
                            'max_outstanding_request_count': {
                                'type': 'bool',
                                },
                            'max_outstanding_submit_count': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_mysql': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'session_err': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'session_err': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_mssql': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'session_err': {
                                'type': 'bool',
                                },
                            'auth_failure': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'session_err': {
                                'type': 'bool',
                                },
                            'auth_failure': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_crl_srcip': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'out_of_sessions': {
                                'type': 'bool',
                                },
                            'too_many_sessions': {
                                'type': 'bool',
                                },
                            'threshold_exceed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'out_of_sessions': {
                                'type': 'bool',
                                },
                            'too_many_sessions': {
                                'type': 'bool',
                                },
                            'threshold_exceed': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_generic': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'svrsel_fail': {
                                'type': 'bool',
                                },
                            'no_route': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'client_fail': {
                                'type': 'bool',
                                },
                            'server_fail': {
                                'type': 'bool',
                                },
                            'mismatch_fwd_id': {
                                'type': 'bool',
                                },
                            'mismatch_rev_id': {
                                'type': 'bool',
                                },
                            'unkwn_cmd_code': {
                                'type': 'bool',
                                },
                            'no_session_id': {
                                'type': 'bool',
                                },
                            'no_fwd_tuple': {
                                'type': 'bool',
                                },
                            'no_rev_tuple': {
                                'type': 'bool',
                                },
                            'dcmsg_error': {
                                'type': 'bool',
                                },
                            'retry_client_request_fail': {
                                'type': 'bool',
                                },
                            'reply_unknown_session_id': {
                                'type': 'bool',
                                },
                            'client_select_fail': {
                                'type': 'bool',
                                },
                            'invalid_avp': {
                                'type': 'bool',
                                },
                            'reply_error_info_fail': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'svrsel_fail': {
                                'type': 'bool',
                                },
                            'no_route': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'client_fail': {
                                'type': 'bool',
                                },
                            'server_fail': {
                                'type': 'bool',
                                },
                            'mismatch_fwd_id': {
                                'type': 'bool',
                                },
                            'mismatch_rev_id': {
                                'type': 'bool',
                                },
                            'unkwn_cmd_code': {
                                'type': 'bool',
                                },
                            'no_session_id': {
                                'type': 'bool',
                                },
                            'no_fwd_tuple': {
                                'type': 'bool',
                                },
                            'no_rev_tuple': {
                                'type': 'bool',
                                },
                            'dcmsg_error': {
                                'type': 'bool',
                                },
                            'retry_client_request_fail': {
                                'type': 'bool',
                                },
                            'reply_unknown_session_id': {
                                'type': 'bool',
                                },
                            'client_select_fail': {
                                'type': 'bool',
                                },
                            'invalid_avp': {
                                'type': 'bool',
                                },
                            'reply_error_info_fail': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_persist': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'hash_tbl_trylock_fail': {
                                'type': 'bool',
                                },
                            'hash_tbl_create_fail': {
                                'type': 'bool',
                                },
                            'hash_tbl_rst_updown': {
                                'type': 'bool',
                                },
                            'hash_tbl_rst_adddel': {
                                'type': 'bool',
                                },
                            'url_hash_fail': {
                                'type': 'bool',
                                },
                            'header_hash_fail': {
                                'type': 'bool',
                                },
                            'src_ip_fail': {
                                'type': 'bool',
                                },
                            'src_ip_new_sess_cache_fail': {
                                'type': 'bool',
                                },
                            'src_ip_new_sess_sel_fail': {
                                'type': 'bool',
                                },
                            'src_ip_hash_fail': {
                                'type': 'bool',
                                },
                            'dst_ip_fail': {
                                'type': 'bool',
                                },
                            'dst_ip_new_sess_cache_fail': {
                                'type': 'bool',
                                },
                            'dst_ip_new_sess_sel_fail': {
                                'type': 'bool',
                                },
                            'dst_ip_hash_fail': {
                                'type': 'bool',
                                },
                            'cssl_sid_not_found': {
                                'type': 'bool',
                                },
                            'cssl_sid_not_match': {
                                'type': 'bool',
                                },
                            'sssl_sid_not_found': {
                                'type': 'bool',
                                },
                            'sssl_sid_not_match': {
                                'type': 'bool',
                                },
                            'ssl_sid_persist_fail': {
                                'type': 'bool',
                                },
                            'ssl_sid_session_fail': {
                                'type': 'bool',
                                },
                            'cookie_persist_fail': {
                                'type': 'bool',
                                },
                            'cookie_not_found': {
                                'type': 'bool',
                                },
                            'cookie_invalid': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'hash_tbl_trylock_fail': {
                                'type': 'bool',
                                },
                            'hash_tbl_create_fail': {
                                'type': 'bool',
                                },
                            'hash_tbl_rst_updown': {
                                'type': 'bool',
                                },
                            'hash_tbl_rst_adddel': {
                                'type': 'bool',
                                },
                            'url_hash_fail': {
                                'type': 'bool',
                                },
                            'header_hash_fail': {
                                'type': 'bool',
                                },
                            'src_ip_fail': {
                                'type': 'bool',
                                },
                            'src_ip_new_sess_cache_fail': {
                                'type': 'bool',
                                },
                            'src_ip_new_sess_sel_fail': {
                                'type': 'bool',
                                },
                            'src_ip_hash_fail': {
                                'type': 'bool',
                                },
                            'dst_ip_fail': {
                                'type': 'bool',
                                },
                            'dst_ip_new_sess_cache_fail': {
                                'type': 'bool',
                                },
                            'dst_ip_new_sess_sel_fail': {
                                'type': 'bool',
                                },
                            'dst_ip_hash_fail': {
                                'type': 'bool',
                                },
                            'cssl_sid_not_found': {
                                'type': 'bool',
                                },
                            'cssl_sid_not_match': {
                                'type': 'bool',
                                },
                            'sssl_sid_not_found': {
                                'type': 'bool',
                                },
                            'sssl_sid_not_match': {
                                'type': 'bool',
                                },
                            'ssl_sid_persist_fail': {
                                'type': 'bool',
                                },
                            'ssl_sid_session_fail': {
                                'type': 'bool',
                                },
                            'cookie_persist_fail': {
                                'type': 'bool',
                                },
                            'cookie_not_found': {
                                'type': 'bool',
                                },
                            'cookie_invalid': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_http_proxy': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'parsereq_fail': {
                                'type': 'bool',
                                },
                            'svrsel_fail': {
                                'type': 'bool',
                                },
                            'fwdreq_fail': {
                                'type': 'bool',
                                },
                            'fwdreqdata_fail': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'req_over_limit': {
                                'type': 'bool',
                                },
                            'req_rate_over_limit': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'parsereq_fail': {
                                'type': 'bool',
                                },
                            'svrsel_fail': {
                                'type': 'bool',
                                },
                            'fwdreq_fail': {
                                'type': 'bool',
                                },
                            'fwdreqdata_fail': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'req_over_limit': {
                                'type': 'bool',
                                },
                            'req_rate_over_limit': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_l4': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'syncookiessentfailed': {
                                'type': 'bool',
                                },
                            'svrselfail': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'snat_no_fwd_route': {
                                'type': 'bool',
                                },
                            'snat_no_rev_route': {
                                'type': 'bool',
                                },
                            'snat_icmp_error_process': {
                                'type': 'bool',
                                },
                            'snat_icmp_no_match': {
                                'type': 'bool',
                                },
                            'smart_nat_id_mismatch': {
                                'type': 'bool',
                                },
                            'syncookiescheckfailed': {
                                'type': 'bool',
                                },
                            'connlimit_drop': {
                                'type': 'bool',
                                },
                            'conn_rate_limit_drop': {
                                'type': 'bool',
                                },
                            'conn_rate_limit_reset': {
                                'type': 'bool',
                                },
                            'dns_policy_drop': {
                                'type': 'bool',
                                },
                            'no_resourse_drop': {
                                'type': 'bool',
                                },
                            'bw_rate_limit_exceed': {
                                'type': 'bool',
                                },
                            'l4_cps_exceed': {
                                'type': 'bool',
                                },
                            'nat_cps_exceed': {
                                'type': 'bool',
                                },
                            'l7_cps_exceed': {
                                'type': 'bool',
                                },
                            'ssl_cps_exceed': {
                                'type': 'bool',
                                },
                            'ssl_tpt_exceed': {
                                'type': 'bool',
                                },
                            'concurrent_conn_exceed': {
                                'type': 'bool',
                                },
                            'svr_syn_handshake_fail': {
                                'type': 'bool',
                                },
                            'synattack': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'syncookiessentfailed': {
                                'type': 'bool',
                                },
                            'svrselfail': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'snat_no_fwd_route': {
                                'type': 'bool',
                                },
                            'snat_no_rev_route': {
                                'type': 'bool',
                                },
                            'snat_icmp_error_process': {
                                'type': 'bool',
                                },
                            'snat_icmp_no_match': {
                                'type': 'bool',
                                },
                            'smart_nat_id_mismatch': {
                                'type': 'bool',
                                },
                            'syncookiescheckfailed': {
                                'type': 'bool',
                                },
                            'connlimit_drop': {
                                'type': 'bool',
                                },
                            'conn_rate_limit_drop': {
                                'type': 'bool',
                                },
                            'conn_rate_limit_reset': {
                                'type': 'bool',
                                },
                            'dns_policy_drop': {
                                'type': 'bool',
                                },
                            'no_resourse_drop': {
                                'type': 'bool',
                                },
                            'bw_rate_limit_exceed': {
                                'type': 'bool',
                                },
                            'l4_cps_exceed': {
                                'type': 'bool',
                                },
                            'nat_cps_exceed': {
                                'type': 'bool',
                                },
                            'l7_cps_exceed': {
                                'type': 'bool',
                                },
                            'ssl_cps_exceed': {
                                'type': 'bool',
                                },
                            'ssl_tpt_exceed': {
                                'type': 'bool',
                                },
                            'concurrent_conn_exceed': {
                                'type': 'bool',
                                },
                            'svr_syn_handshake_fail': {
                                'type': 'bool',
                                },
                            'synattack': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_fast_http': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'parsereq_fail': {
                                'type': 'bool',
                                },
                            'svrsel_fail': {
                                'type': 'bool',
                                },
                            'fwdreq_fail': {
                                'type': 'bool',
                                },
                            'fwdreqdata_fail': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'full_proxy_fpga_err': {
                                'type': 'bool',
                                },
                            'req_over_limit': {
                                'type': 'bool',
                                },
                            'req_rate_over_limit': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'parsereq_fail': {
                                'type': 'bool',
                                },
                            'svrsel_fail': {
                                'type': 'bool',
                                },
                            'fwdreq_fail': {
                                'type': 'bool',
                                },
                            'fwdreqdata_fail': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'full_proxy_fpga_err': {
                                'type': 'bool',
                                },
                            'req_over_limit': {
                                'type': 'bool',
                                },
                            'req_rate_over_limit': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_ftp_proxy': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'svrsel_fail': {
                                'type': 'bool',
                                },
                            'no_route': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'line_too_long': {
                                'type': 'bool',
                                },
                            'invalid_start_line': {
                                'type': 'bool',
                                },
                            'smp_create_fail': {
                                'type': 'bool',
                                },
                            'data_server_conn_fail': {
                                'type': 'bool',
                                },
                            'data_send_fail': {
                                'type': 'bool',
                                },
                            'unsupported_pbsz_value': {
                                'type': 'bool',
                                },
                            'unsupported_prot_value': {
                                'type': 'bool',
                                },
                            'unsupported_command': {
                                'type': 'bool',
                                },
                            'bad_sequence': {
                                'type': 'bool',
                                },
                            'rsv_persist_conn_fail': {
                                'type': 'bool',
                                },
                            'smp_v6_fail': {
                                'type': 'bool',
                                },
                            'smp_v4_fail': {
                                'type': 'bool',
                                },
                            'insert_tuple_fail': {
                                'type': 'bool',
                                },
                            'cl_est_err': {
                                'type': 'bool',
                                },
                            'ser_connecting_err': {
                                'type': 'bool',
                                },
                            'server_response_err': {
                                'type': 'bool',
                                },
                            'cl_request_err': {
                                'type': 'bool',
                                },
                            'data_conn_start_err': {
                                'type': 'bool',
                                },
                            'data_serv_connecting_err': {
                                'type': 'bool',
                                },
                            'data_serv_connected_err': {
                                'type': 'bool',
                                },
                            'auth_fail': {
                                'type': 'bool',
                                },
                            'ds_fail': {
                                'type': 'bool',
                                },
                            'cant_find_port': {
                                'type': 'bool',
                                },
                            'cant_find_eprt': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'svrsel_fail': {
                                'type': 'bool',
                                },
                            'no_route': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'line_too_long': {
                                'type': 'bool',
                                },
                            'invalid_start_line': {
                                'type': 'bool',
                                },
                            'smp_create_fail': {
                                'type': 'bool',
                                },
                            'data_server_conn_fail': {
                                'type': 'bool',
                                },
                            'data_send_fail': {
                                'type': 'bool',
                                },
                            'unsupported_pbsz_value': {
                                'type': 'bool',
                                },
                            'unsupported_prot_value': {
                                'type': 'bool',
                                },
                            'unsupported_command': {
                                'type': 'bool',
                                },
                            'bad_sequence': {
                                'type': 'bool',
                                },
                            'rsv_persist_conn_fail': {
                                'type': 'bool',
                                },
                            'smp_v6_fail': {
                                'type': 'bool',
                                },
                            'smp_v4_fail': {
                                'type': 'bool',
                                },
                            'insert_tuple_fail': {
                                'type': 'bool',
                                },
                            'cl_est_err': {
                                'type': 'bool',
                                },
                            'ser_connecting_err': {
                                'type': 'bool',
                                },
                            'server_response_err': {
                                'type': 'bool',
                                },
                            'cl_request_err': {
                                'type': 'bool',
                                },
                            'data_conn_start_err': {
                                'type': 'bool',
                                },
                            'data_serv_connecting_err': {
                                'type': 'bool',
                                },
                            'data_serv_connected_err': {
                                'type': 'bool',
                                },
                            'auth_fail': {
                                'type': 'bool',
                                },
                            'ds_fail': {
                                'type': 'bool',
                                },
                            'cant_find_port': {
                                'type': 'bool',
                                },
                            'cant_find_eprt': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_imap_proxy': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'svrsel_fail': {
                                'type': 'bool',
                                },
                            'no_route': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'line_too_long': {
                                'type': 'bool',
                                },
                            'invalid_start_line': {
                                'type': 'bool',
                                },
                            'cant_find_pasv': {
                                'type': 'bool',
                                },
                            'smp_create_fail': {
                                'type': 'bool',
                                },
                            'data_server_conn_fail': {
                                'type': 'bool',
                                },
                            'data_send_fail': {
                                'type': 'bool',
                                },
                            'cant_find_epsv': {
                                'type': 'bool',
                                },
                            'auth_unsupported': {
                                'type': 'bool',
                                },
                            'unsupported_pbsz_value': {
                                'type': 'bool',
                                },
                            'unsupported_prot_value': {
                                'type': 'bool',
                                },
                            'bad_sequence': {
                                'type': 'bool',
                                },
                            'rsv_persist_conn_fail': {
                                'type': 'bool',
                                },
                            'smp_v6_fail': {
                                'type': 'bool',
                                },
                            'smp_v4_fail': {
                                'type': 'bool',
                                },
                            'insert_tuple_fail': {
                                'type': 'bool',
                                },
                            'cl_est_err': {
                                'type': 'bool',
                                },
                            'ser_connecting_err': {
                                'type': 'bool',
                                },
                            'server_response_err': {
                                'type': 'bool',
                                },
                            'cl_request_err': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'svrsel_fail': {
                                'type': 'bool',
                                },
                            'no_route': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'line_too_long': {
                                'type': 'bool',
                                },
                            'invalid_start_line': {
                                'type': 'bool',
                                },
                            'cant_find_pasv': {
                                'type': 'bool',
                                },
                            'smp_create_fail': {
                                'type': 'bool',
                                },
                            'data_server_conn_fail': {
                                'type': 'bool',
                                },
                            'data_send_fail': {
                                'type': 'bool',
                                },
                            'cant_find_epsv': {
                                'type': 'bool',
                                },
                            'auth_unsupported': {
                                'type': 'bool',
                                },
                            'unsupported_pbsz_value': {
                                'type': 'bool',
                                },
                            'unsupported_prot_value': {
                                'type': 'bool',
                                },
                            'bad_sequence': {
                                'type': 'bool',
                                },
                            'rsv_persist_conn_fail': {
                                'type': 'bool',
                                },
                            'smp_v6_fail': {
                                'type': 'bool',
                                },
                            'smp_v4_fail': {
                                'type': 'bool',
                                },
                            'insert_tuple_fail': {
                                'type': 'bool',
                                },
                            'cl_est_err': {
                                'type': 'bool',
                                },
                            'ser_connecting_err': {
                                'type': 'bool',
                                },
                            'server_response_err': {
                                'type': 'bool',
                                },
                            'cl_request_err': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_pop3_proxy': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'svrsel_fail': {
                                'type': 'bool',
                                },
                            'no_route': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'line_too_long': {
                                'type': 'bool',
                                },
                            'invalid_start_line': {
                                'type': 'bool',
                                },
                            'unsupported_command': {
                                'type': 'bool',
                                },
                            'bad_sequence': {
                                'type': 'bool',
                                },
                            'rsv_persist_conn_fail': {
                                'type': 'bool',
                                },
                            'smp_v6_fail': {
                                'type': 'bool',
                                },
                            'smp_v4_fail': {
                                'type': 'bool',
                                },
                            'insert_tuple_fail': {
                                'type': 'bool',
                                },
                            'cl_est_err': {
                                'type': 'bool',
                                },
                            'ser_connecting_err': {
                                'type': 'bool',
                                },
                            'server_response_err': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'svrsel_fail': {
                                'type': 'bool',
                                },
                            'no_route': {
                                'type': 'bool',
                                },
                            'snat_fail': {
                                'type': 'bool',
                                },
                            'line_too_long': {
                                'type': 'bool',
                                },
                            'invalid_start_line': {
                                'type': 'bool',
                                },
                            'unsupported_command': {
                                'type': 'bool',
                                },
                            'bad_sequence': {
                                'type': 'bool',
                                },
                            'rsv_persist_conn_fail': {
                                'type': 'bool',
                                },
                            'smp_v6_fail': {
                                'type': 'bool',
                                },
                            'smp_v4_fail': {
                                'type': 'bool',
                                },
                            'insert_tuple_fail': {
                                'type': 'bool',
                                },
                            'cl_est_err': {
                                'type': 'bool',
                                },
                            'ser_connecting_err': {
                                'type': 'bool',
                                },
                            'server_response_err': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_switch': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'lacp_tx_intf_err_drop': {
                                'type': 'bool',
                                },
                            'unnumbered_nat_error': {
                                'type': 'bool',
                                },
                            'unnumbered_unsupported_drop': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'lacp_tx_intf_err_drop': {
                                'type': 'bool',
                                },
                            'unnumbered_nat_error': {
                                'type': 'bool',
                                },
                            'unnumbered_unsupported_drop': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_rc_cache': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'rv_failure': {
                                'type': 'bool',
                                },
                            'content_toobig': {
                                'type': 'bool',
                                },
                            'content_toosmall': {
                                'type': 'bool',
                                },
                            'entry_create_failures': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'rv_failure': {
                                'type': 'bool',
                                },
                            'content_toobig': {
                                'type': 'bool',
                                },
                            'content_toosmall': {
                                'type': 'bool',
                                },
                            'entry_create_failures': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'so_counters': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'so_pkts_slb_nat_reserve_fail': {
                                'type': 'bool',
                                },
                            'so_pkts_slb_nat_release_fail': {
                                'type': 'bool',
                                },
                            'so_pkts_l2redirect_dest_mac_zero_drop': {
                                'type': 'bool',
                                },
                            'so_pkts_l2redirect_interface_not_up': {
                                'type': 'bool',
                                },
                            'so_pkts_l2redirect_invalid_redirect_inf': {
                                'type': 'bool',
                                },
                            'so_pkts_l3_redirect_encap_error_drop': {
                                'type': 'bool',
                                },
                            'so_pkts_l3_redirect_inner_mac_zero_drop': {
                                'type': 'bool',
                                },
                            'so_pkts_l3_redirect_table_error': {
                                'type': 'bool',
                                },
                            'so_pkts_l3_redirect_fragmentation_error': {
                                'type': 'bool',
                                },
                            'so_pkts_l3_redirect_table_no_entry_foun': {
                                'type': 'bool',
                                },
                            'so_pkts_l3_redirect_invalid_dev_dir': {
                                'type': 'bool',
                                },
                            'so_pkts_l3_redirect_chassis_dest_mac_er': {
                                'type': 'bool',
                                },
                            'so_pkts_l2redirect_vlan_retrieval_error': {
                                'type': 'bool',
                                },
                            'so_pkts_l2redirect_port_retrieval_error': {
                                'type': 'bool',
                                },
                            'so_pkts_l2redirect_loop_detect_drop': {
                                'type': 'bool',
                                },
                            'so_pkts_l2redirect_frag_vlan_retrieval_': {
                                'type': 'bool',
                                },
                            'so_pkts_l2redirect_tx_frag_vlan_add_fai': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'so_pkts_slb_nat_reserve_fail': {
                                'type': 'bool',
                                },
                            'so_pkts_slb_nat_release_fail': {
                                'type': 'bool',
                                },
                            'so_pkts_l2redirect_dest_mac_zero_drop': {
                                'type': 'bool',
                                },
                            'so_pkts_l2redirect_interface_not_up': {
                                'type': 'bool',
                                },
                            'so_pkts_l2redirect_invalid_redirect_inf': {
                                'type': 'bool',
                                },
                            'so_pkts_l3_redirect_encap_error_drop': {
                                'type': 'bool',
                                },
                            'so_pkts_l3_redirect_inner_mac_zero_drop': {
                                'type': 'bool',
                                },
                            'so_pkts_l3_redirect_table_error': {
                                'type': 'bool',
                                },
                            'so_pkts_l3_redirect_fragmentation_error': {
                                'type': 'bool',
                                },
                            'so_pkts_l3_redirect_table_no_entry_foun': {
                                'type': 'bool',
                                },
                            'so_pkts_l3_redirect_invalid_dev_dir': {
                                'type': 'bool',
                                },
                            'so_pkts_l3_redirect_chassis_dest_mac_er': {
                                'type': 'bool',
                                },
                            'so_pkts_l2redirect_vlan_retrieval_error': {
                                'type': 'bool',
                                },
                            'so_pkts_l2redirect_port_retrieval_error': {
                                'type': 'bool',
                                },
                            'so_pkts_l2redirect_loop_detect_drop': {
                                'type': 'bool',
                                },
                            'so_pkts_l2redirect_frag_vlan_retrieval_': {
                                'type': 'bool',
                                },
                            'so_pkts_l2redirect_tx_frag_vlan_add_fai': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_plyr_id_gbl': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'total_invalid_playerid_pkts': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'total_invalid_playerid_pkts': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_sport_rate': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'total_reset': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'total_reset': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'logging_local_log_global': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'enqueue_full': {
                                'type': 'bool',
                                },
                            'enqueue_error': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'enqueue_full': {
                                'type': 'bool',
                                },
                            'enqueue_error': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_mlb': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'mlb_dcmsg_error': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'mlb_dcmsg_error': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_link_probe': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'err_entry_create_failed': {
                                'type': 'bool',
                                },
                            'err_entry_create_oom': {
                                'type': 'bool',
                                },
                            'err_entry_insert_failed': {
                                'type': 'bool',
                                },
                            'err_tmpl_probe_create_failed': {
                                'type': 'bool',
                                },
                            'err_tmpl_probe_create_oom': {
                                'type': 'bool',
                                },
                            'total_http_response_bad': {
                                'type': 'bool',
                                },
                            'total_tcp_err': {
                                'type': 'bool',
                                },
                            'err_smart_nat_alloc': {
                                'type': 'bool',
                                },
                            'err_smart_nat_port_alloc': {
                                'type': 'bool',
                                },
                            'err_l4_sess_alloc': {
                                'type': 'bool',
                                },
                            'err_probe_tcp_conn_send': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'err_entry_create_failed': {
                                'type': 'bool',
                                },
                            'err_entry_create_oom': {
                                'type': 'bool',
                                },
                            'err_entry_insert_failed': {
                                'type': 'bool',
                                },
                            'err_tmpl_probe_create_failed': {
                                'type': 'bool',
                                },
                            'err_tmpl_probe_create_oom': {
                                'type': 'bool',
                                },
                            'total_http_response_bad': {
                                'type': 'bool',
                                },
                            'total_tcp_err': {
                                'type': 'bool',
                                },
                            'err_smart_nat_alloc': {
                                'type': 'bool',
                                },
                            'err_smart_nat_port_alloc': {
                                'type': 'bool',
                                },
                            'err_l4_sess_alloc': {
                                'type': 'bool',
                                },
                            'err_probe_tcp_conn_send': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        },
                    'slb_rpz': {
                        'type': 'dict',
                        'uuid': {
                            'type': 'str',
                            },
                        'trigger_stats_inc': {
                            'type': 'dict',
                            'set_bw_error': {
                                'type': 'bool',
                                },
                            'parse_error': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            },
                        'trigger_stats_rate': {
                            'type': 'dict',
                            'threshold_exceeded_by': {
                                'type': 'int',
                                },
                            'duration': {
                                'type': 'int',
                                },
                            'set_bw_error': {
                                'type': 'bool',
                                },
                            'parse_error': {
                                'type': 'bool',
                                },
                            'uuid': {
                                'type': 'str',
                                }
                            }
                        }
                    }
                },
            'activate': {
                'type': 'dict',
                'template': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'object_templates': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                },
            'templ_gtp_plcy_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'drop_vld_gtp_ie_repeat_count_exceed': {
                        'type': 'bool',
                        },
                    'drop_vld_reserved_field_set': {
                        'type': 'bool',
                        },
                    'drop_vld_tunnel_id_flag': {
                        'type': 'bool',
                        },
                    'drop_vld_invalid_flow_label_v0': {
                        'type': 'bool',
                        },
                    'drop_vld_invalid_teid': {
                        'type': 'bool',
                        },
                    'drop_vld_out_of_state': {
                        'type': 'bool',
                        },
                    'drop_vld_mandatory_information_element': {
                        'type': 'bool',
                        },
                    'drop_vld_mandatory_ie_in_grouped_ie': {
                        'type': 'bool',
                        },
                    'drop_vld_out_of_order_ie': {
                        'type': 'bool',
                        },
                    'drop_vld_out_of_state_ie': {
                        'type': 'bool',
                        },
                    'drop_vld_reserved_information_element': {
                        'type': 'bool',
                        },
                    'drop_vld_version_not_supported': {
                        'type': 'bool',
                        },
                    'drop_vld_message_length': {
                        'type': 'bool',
                        },
                    'drop_vld_cross_layer_correlation': {
                        'type': 'bool',
                        },
                    'drop_vld_country_code_mismatch': {
                        'type': 'bool',
                        },
                    'drop_vld_gtp_u_spoofed_source_address': {
                        'type': 'bool',
                        },
                    'drop_vld_gtp_bearer_count_exceed': {
                        'type': 'bool',
                        },
                    'drop_vld_gtp_v2_wrong_lbi_create_bearer': {
                        'type': 'bool',
                        },
                    'drop_vld_v0_reserved_message_drop': {
                        'type': 'bool',
                        },
                    'drop_vld_v1_reserved_message_drop': {
                        'type': 'bool',
                        },
                    'drop_vld_v2_reserved_message_drop': {
                        'type': 'bool',
                        },
                    'drop_vld_invalid_pkt_len_piggyback': {
                        'type': 'bool',
                        },
                    'drop_vld_sanity_failed_piggyback': {
                        'type': 'bool',
                        },
                    'drop_vld_sequence_num_correlation': {
                        'type': 'bool',
                        },
                    'drop_vld_gtpv0_seqnum_buffer_full': {
                        'type': 'bool',
                        },
                    'drop_vld_gtpv1_seqnum_buffer_full': {
                        'type': 'bool',
                        },
                    'drop_vld_gtpv2_seqnum_buffer_full': {
                        'type': 'bool',
                        },
                    'drop_vld_gtp_invalid_imsi_len_drop': {
                        'type': 'bool',
                        },
                    'drop_vld_gtp_invalid_apn_len_drop': {
                        'type': 'bool',
                        },
                    'drop_vld_protocol_flag_unset': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'drop_vld_gtp_ie_repeat_count_exceed': {
                        'type': 'bool',
                        },
                    'drop_vld_reserved_field_set': {
                        'type': 'bool',
                        },
                    'drop_vld_tunnel_id_flag': {
                        'type': 'bool',
                        },
                    'drop_vld_invalid_flow_label_v0': {
                        'type': 'bool',
                        },
                    'drop_vld_invalid_teid': {
                        'type': 'bool',
                        },
                    'drop_vld_out_of_state': {
                        'type': 'bool',
                        },
                    'drop_vld_mandatory_information_element': {
                        'type': 'bool',
                        },
                    'drop_vld_mandatory_ie_in_grouped_ie': {
                        'type': 'bool',
                        },
                    'drop_vld_out_of_order_ie': {
                        'type': 'bool',
                        },
                    'drop_vld_out_of_state_ie': {
                        'type': 'bool',
                        },
                    'drop_vld_reserved_information_element': {
                        'type': 'bool',
                        },
                    'drop_vld_version_not_supported': {
                        'type': 'bool',
                        },
                    'drop_vld_message_length': {
                        'type': 'bool',
                        },
                    'drop_vld_cross_layer_correlation': {
                        'type': 'bool',
                        },
                    'drop_vld_country_code_mismatch': {
                        'type': 'bool',
                        },
                    'drop_vld_gtp_u_spoofed_source_address': {
                        'type': 'bool',
                        },
                    'drop_vld_gtp_bearer_count_exceed': {
                        'type': 'bool',
                        },
                    'drop_vld_gtp_v2_wrong_lbi_create_bearer': {
                        'type': 'bool',
                        },
                    'drop_vld_v0_reserved_message_drop': {
                        'type': 'bool',
                        },
                    'drop_vld_v1_reserved_message_drop': {
                        'type': 'bool',
                        },
                    'drop_vld_v2_reserved_message_drop': {
                        'type': 'bool',
                        },
                    'drop_vld_invalid_pkt_len_piggyback': {
                        'type': 'bool',
                        },
                    'drop_vld_sanity_failed_piggyback': {
                        'type': 'bool',
                        },
                    'drop_vld_sequence_num_correlation': {
                        'type': 'bool',
                        },
                    'drop_vld_gtpv0_seqnum_buffer_full': {
                        'type': 'bool',
                        },
                    'drop_vld_gtpv1_seqnum_buffer_full': {
                        'type': 'bool',
                        },
                    'drop_vld_gtpv2_seqnum_buffer_full': {
                        'type': 'bool',
                        },
                    'drop_vld_gtp_invalid_imsi_len_drop': {
                        'type': 'bool',
                        },
                    'drop_vld_gtp_invalid_apn_len_drop': {
                        'type': 'bool',
                        },
                    'drop_vld_protocol_flag_unset': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'interface_ethernet_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'input_errors': {
                        'type': 'bool',
                        },
                    'crc': {
                        'type': 'bool',
                        },
                    'runts': {
                        'type': 'bool',
                        },
                    'giants': {
                        'type': 'bool',
                        },
                    'output_errors': {
                        'type': 'bool',
                        },
                    'collisions': {
                        'type': 'bool',
                        },
                    'giants_output': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'input_errors': {
                        'type': 'bool',
                        },
                    'crc': {
                        'type': 'bool',
                        },
                    'runts': {
                        'type': 'bool',
                        },
                    'giants': {
                        'type': 'bool',
                        },
                    'output_errors': {
                        'type': 'bool',
                        },
                    'collisions': {
                        'type': 'bool',
                        },
                    'giants_output': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'interface_tunnel_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'num_rx_err_pkts': {
                        'type': 'bool',
                        },
                    'num_tx_err_pkts': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'num_rx_err_pkts': {
                        'type': 'bool',
                        },
                    'num_tx_err_pkts': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'aam_jwt_authorization_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'jwt_authorize_failure': {
                        'type': 'bool',
                        },
                    'jwt_missing_token': {
                        'type': 'bool',
                        },
                    'jwt_missing_claim': {
                        'type': 'bool',
                        },
                    'jwt_token_expired': {
                        'type': 'bool',
                        },
                    'jwt_signature_failure': {
                        'type': 'bool',
                        },
                    'jwt_other_error': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'jwt_authorize_failure': {
                        'type': 'bool',
                        },
                    'jwt_missing_token': {
                        'type': 'bool',
                        },
                    'jwt_missing_claim': {
                        'type': 'bool',
                        },
                    'jwt_token_expired': {
                        'type': 'bool',
                        },
                    'jwt_signature_failure': {
                        'type': 'bool',
                        },
                    'jwt_other_error': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'aam_aaa_policy_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'error': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'aam_auth_logon_http_ins_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'spn_krb_faiure': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'spn_krb_faiure': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'aam_auth_server_ldap_inst_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'admin_bind_failure': {
                        'type': 'bool',
                        },
                    'bind_failure': {
                        'type': 'bool',
                        },
                    'search_failure': {
                        'type': 'bool',
                        },
                    'authorize_failure': {
                        'type': 'bool',
                        },
                    'timeout_error': {
                        'type': 'bool',
                        },
                    'other_error': {
                        'type': 'bool',
                        },
                    'ssl_session_failure': {
                        'type': 'bool',
                        },
                    'pw_change_failure': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'admin_bind_failure': {
                        'type': 'bool',
                        },
                    'bind_failure': {
                        'type': 'bool',
                        },
                    'search_failure': {
                        'type': 'bool',
                        },
                    'authorize_failure': {
                        'type': 'bool',
                        },
                    'timeout_error': {
                        'type': 'bool',
                        },
                    'other_error': {
                        'type': 'bool',
                        },
                    'ssl_session_failure': {
                        'type': 'bool',
                        },
                    'pw_change_failure': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'aam_auth_server_ocsp_inst_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'timeout': {
                        'type': 'bool',
                        },
                    'fail': {
                        'type': 'bool',
                        },
                    'stapling_timeout': {
                        'type': 'bool',
                        },
                    'stapling_fail': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'timeout': {
                        'type': 'bool',
                        },
                    'fail': {
                        'type': 'bool',
                        },
                    'stapling_timeout': {
                        'type': 'bool',
                        },
                    'stapling_fail': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'aam_auth_server_rad_inst_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'authen_failure': {
                        'type': 'bool',
                        },
                    'authorize_failure': {
                        'type': 'bool',
                        },
                    'timeout_error': {
                        'type': 'bool',
                        },
                    'other_error': {
                        'type': 'bool',
                        },
                    'accounting_failure': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'authen_failure': {
                        'type': 'bool',
                        },
                    'authorize_failure': {
                        'type': 'bool',
                        },
                    'timeout_error': {
                        'type': 'bool',
                        },
                    'other_error': {
                        'type': 'bool',
                        },
                    'accounting_failure': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'aam_auth_server_win_inst_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'krb_timeout_error': {
                        'type': 'bool',
                        },
                    'krb_other_error': {
                        'type': 'bool',
                        },
                    'krb_pw_expiry': {
                        'type': 'bool',
                        },
                    'krb_pw_change_failure': {
                        'type': 'bool',
                        },
                    'krb_validate_kdc_failure': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'krb_timeout_error': {
                        'type': 'bool',
                        },
                    'krb_other_error': {
                        'type': 'bool',
                        },
                    'krb_pw_expiry': {
                        'type': 'bool',
                        },
                    'krb_pw_change_failure': {
                        'type': 'bool',
                        },
                    'krb_validate_kdc_failure': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'aam_auth_saml_service_prov_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'acs_authz_fail': {
                        'type': 'bool',
                        },
                    'acs_error': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'acs_authz_fail': {
                        'type': 'bool',
                        },
                    'acs_error': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'aam_auth_saml_id_prov_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'md_fail': {
                        'type': 'bool',
                        },
                    'acs_fail': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'md_fail': {
                        'type': 'bool',
                        },
                    'acs_fail': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'aam_auth_service_group_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'server_selection_fail_reset': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'server_selection_fail_reset': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'aam_auth_service_group_mem_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'curr_conn_overflow': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'curr_conn_overflow': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'aam_auth_relay_hbase_inst_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'no_creds': {
                        'type': 'bool',
                        },
                    'bad_req': {
                        'type': 'bool',
                        },
                    'unauth': {
                        'type': 'bool',
                        },
                    'forbidden': {
                        'type': 'bool',
                        },
                    'not_found': {
                        'type': 'bool',
                        },
                    'server_error': {
                        'type': 'bool',
                        },
                    'unavailable': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'no_creds': {
                        'type': 'bool',
                        },
                    'bad_req': {
                        'type': 'bool',
                        },
                    'unauth': {
                        'type': 'bool',
                        },
                    'forbidden': {
                        'type': 'bool',
                        },
                    'not_found': {
                        'type': 'bool',
                        },
                    'server_error': {
                        'type': 'bool',
                        },
                    'unavailable': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'aam_auth_relay_form_inst_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'invalid_srv_rsp': {
                        'type': 'bool',
                        },
                    'post_fail': {
                        'type': 'bool',
                        },
                    'invalid_cred': {
                        'type': 'bool',
                        },
                    'bad_req': {
                        'type': 'bool',
                        },
                    'not_fnd': {
                        'type': 'bool',
                        },
                    'error': {
                        'type': 'bool',
                        },
                    'other_error': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'invalid_srv_rsp': {
                        'type': 'bool',
                        },
                    'post_fail': {
                        'type': 'bool',
                        },
                    'invalid_cred': {
                        'type': 'bool',
                        },
                    'bad_req': {
                        'type': 'bool',
                        },
                    'not_fnd': {
                        'type': 'bool',
                        },
                    'error': {
                        'type': 'bool',
                        },
                    'other_error': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'aam_auth_relay_ws_fed_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'failure': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'failure': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'aam_auth_captcha_inst_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'parse_fail': {
                        'type': 'bool',
                        },
                    'json_fail': {
                        'type': 'bool',
                        },
                    'attr_fail': {
                        'type': 'bool',
                        },
                    'timeout_error': {
                        'type': 'bool',
                        },
                    'other_error': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'parse_fail': {
                        'type': 'bool',
                        },
                    'json_fail': {
                        'type': 'bool',
                        },
                    'attr_fail': {
                        'type': 'bool',
                        },
                    'timeout_error': {
                        'type': 'bool',
                        },
                    'other_error': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'slb_templ_cache_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'nc_req_header': {
                        'type': 'bool',
                        },
                    'nc_res_header': {
                        'type': 'bool',
                        },
                    'rv_failure': {
                        'type': 'bool',
                        },
                    'content_toobig': {
                        'type': 'bool',
                        },
                    'content_toosmall': {
                        'type': 'bool',
                        },
                    'entry_create_failures': {
                        'type': 'bool',
                        },
                    'header_save_error': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'nc_req_header': {
                        'type': 'bool',
                        },
                    'nc_res_header': {
                        'type': 'bool',
                        },
                    'rv_failure': {
                        'type': 'bool',
                        },
                    'content_toobig': {
                        'type': 'bool',
                        },
                    'content_toosmall': {
                        'type': 'bool',
                        },
                    'entry_create_failures': {
                        'type': 'bool',
                        },
                    'header_save_error': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'slb_port_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'es_resp_300': {
                        'type': 'bool',
                        },
                    'es_resp_400': {
                        'type': 'bool',
                        },
                    'es_resp_500': {
                        'type': 'bool',
                        },
                    'resp_3xx': {
                        'type': 'bool',
                        },
                    'resp_4xx': {
                        'type': 'bool',
                        },
                    'resp_5xx': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'es_resp_300': {
                        'type': 'bool',
                        },
                    'es_resp_400': {
                        'type': 'bool',
                        },
                    'es_resp_500': {
                        'type': 'bool',
                        },
                    'resp_3xx': {
                        'type': 'bool',
                        },
                    'resp_4xx': {
                        'type': 'bool',
                        },
                    'resp_5xx': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'slb_service_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'es_resp_300': {
                        'type': 'bool',
                        },
                    'es_resp_400': {
                        'type': 'bool',
                        },
                    'es_resp_500': {
                        'type': 'bool',
                        },
                    'resp_3xx': {
                        'type': 'bool',
                        },
                    'resp_4xx': {
                        'type': 'bool',
                        },
                    'resp_5xx': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'es_resp_300': {
                        'type': 'bool',
                        },
                    'es_resp_400': {
                        'type': 'bool',
                        },
                    'es_resp_500': {
                        'type': 'bool',
                        },
                    'resp_3xx': {
                        'type': 'bool',
                        },
                    'resp_4xx': {
                        'type': 'bool',
                        },
                    'resp_5xx': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'slb_vport_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'total_mf_dns_pkts': {
                        'type': 'bool',
                        },
                    'es_total_failure_actions': {
                        'type': 'bool',
                        },
                    'compression_miss_no_client': {
                        'type': 'bool',
                        },
                    'compression_miss_template_exclusion': {
                        'type': 'bool',
                        },
                    'loc_deny': {
                        'type': 'bool',
                        },
                    'dnsrrl_total_dropped': {
                        'type': 'bool',
                        },
                    'dnsrrl_bad_fqdn': {
                        'type': 'bool',
                        },
                    'dnsrrl_nx_exceed': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'total_mf_dns_pkts': {
                        'type': 'bool',
                        },
                    'es_total_failure_actions': {
                        'type': 'bool',
                        },
                    'compression_miss_no_client': {
                        'type': 'bool',
                        },
                    'compression_miss_template_exclusion': {
                        'type': 'bool',
                        },
                    'loc_deny': {
                        'type': 'bool',
                        },
                    'dnsrrl_total_dropped': {
                        'type': 'bool',
                        },
                    'dnsrrl_bad_fqdn': {
                        'type': 'bool',
                        },
                    'dnsrrl_nx_exceed': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'cgnv6_serv_group_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'server_selection_fail_drop': {
                        'type': 'bool',
                        },
                    'server_selection_fail_reset': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'server_selection_fail_drop': {
                        'type': 'bool',
                        },
                    'server_selection_fail_reset': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'cgnv6_dns64_vs_port_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'es_total_failure_actions': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'es_total_failure_actions': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'cgnv6_map_trans_domain_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'inbound_addr_port_validation_failed': {
                        'type': 'bool',
                        },
                    'inbound_rev_lookup_failed': {
                        'type': 'bool',
                        },
                    'inbound_dest_unreachable': {
                        'type': 'bool',
                        },
                    'outbound_addr_validation_failed': {
                        'type': 'bool',
                        },
                    'outbound_rev_lookup_failed': {
                        'type': 'bool',
                        },
                    'outbound_dest_unreachable': {
                        'type': 'bool',
                        },
                    'packet_mtu_exceeded': {
                        'type': 'bool',
                        },
                    'interface_not_configured': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'inbound_addr_port_validation_failed': {
                        'type': 'bool',
                        },
                    'inbound_rev_lookup_failed': {
                        'type': 'bool',
                        },
                    'inbound_dest_unreachable': {
                        'type': 'bool',
                        },
                    'outbound_addr_validation_failed': {
                        'type': 'bool',
                        },
                    'outbound_rev_lookup_failed': {
                        'type': 'bool',
                        },
                    'outbound_dest_unreachable': {
                        'type': 'bool',
                        },
                    'packet_mtu_exceeded': {
                        'type': 'bool',
                        },
                    'interface_not_configured': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'cgnv6_encap_domain_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'inbound_addr_port_validation_failed': {
                        'type': 'bool',
                        },
                    'inbound_rev_lookup_failed': {
                        'type': 'bool',
                        },
                    'inbound_dest_unreachable': {
                        'type': 'bool',
                        },
                    'outbound_addr_validation_failed': {
                        'type': 'bool',
                        },
                    'outbound_rev_lookup_failed': {
                        'type': 'bool',
                        },
                    'outbound_dest_unreachable': {
                        'type': 'bool',
                        },
                    'packet_mtu_exceeded': {
                        'type': 'bool',
                        },
                    'interface_not_configured': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'inbound_addr_port_validation_failed': {
                        'type': 'bool',
                        },
                    'inbound_rev_lookup_failed': {
                        'type': 'bool',
                        },
                    'inbound_dest_unreachable': {
                        'type': 'bool',
                        },
                    'outbound_addr_validation_failed': {
                        'type': 'bool',
                        },
                    'outbound_rev_lookup_failed': {
                        'type': 'bool',
                        },
                    'outbound_dest_unreachable': {
                        'type': 'bool',
                        },
                    'packet_mtu_exceeded': {
                        'type': 'bool',
                        },
                    'interface_not_configured': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'netflow_monitor_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'nat44_records_sent_failure': {
                        'type': 'bool',
                        },
                    'nat64_records_sent_failure': {
                        'type': 'bool',
                        },
                    'dslite_records_sent_failure': {
                        'type': 'bool',
                        },
                    'session_event_nat44_records_sent_failur': {
                        'type': 'bool',
                        },
                    'session_event_nat64_records_sent_failur': {
                        'type': 'bool',
                        },
                    'session_event_dslite_records_sent_failu': {
                        'type': 'bool',
                        },
                    'session_event_fw4_records_sent_failure': {
                        'type': 'bool',
                        },
                    'session_event_fw6_records_sent_failure': {
                        'type': 'bool',
                        },
                    'port_mapping_nat44_records_sent_failure': {
                        'type': 'bool',
                        },
                    'port_mapping_nat64_records_sent_failure': {
                        'type': 'bool',
                        },
                    'port_mapping_dslite_records_sent_failur': {
                        'type': 'bool',
                        },
                    'netflow_v5_records_sent_failure': {
                        'type': 'bool',
                        },
                    'netflow_v5_ext_records_sent_failure': {
                        'type': 'bool',
                        },
                    'port_batching_nat44_records_sent_failur': {
                        'type': 'bool',
                        },
                    'port_batching_nat64_records_sent_failur': {
                        'type': 'bool',
                        },
                    'port_batching_dslite_records_sent_failu': {
                        'type': 'bool',
                        },
                    'port_batching_v2_nat44_records_sent_fai': {
                        'type': 'bool',
                        },
                    'port_batching_v2_nat64_records_sent_fai': {
                        'type': 'bool',
                        },
                    'port_batching_v2_dslite_records_sent_fa': {
                        'type': 'bool',
                        },
                    'custom_session_event_nat44_creation_rec': {
                        'type': 'bool',
                        },
                    'custom_session_event_nat64_creation_rec': {
                        'type': 'bool',
                        },
                    'custom_session_event_dslite_creation_re': {
                        'type': 'bool',
                        },
                    'custom_session_event_nat44_deletion_rec': {
                        'type': 'bool',
                        },
                    'custom_session_event_nat64_deletion_rec': {
                        'type': 'bool',
                        },
                    'custom_session_event_dslite_deletion_re': {
                        'type': 'bool',
                        },
                    'custom_session_event_fw4_creation_recor': {
                        'type': 'bool',
                        },
                    'custom_session_event_fw6_creation_recor': {
                        'type': 'bool',
                        },
                    'custom_session_event_fw4_deletion_recor': {
                        'type': 'bool',
                        },
                    'custom_session_event_fw6_deletion_recor': {
                        'type': 'bool',
                        },
                    'custom_deny_reset_event_fw4_records_sen': {
                        'type': 'bool',
                        },
                    'custom_deny_reset_event_fw6_records_sen': {
                        'type': 'bool',
                        },
                    'custom_port_mapping_nat44_creation_reco': {
                        'type': 'bool',
                        },
                    'custom_port_mapping_nat64_creation_reco': {
                        'type': 'bool',
                        },
                    'custom_port_mapping_dslite_creation_rec': {
                        'type': 'bool',
                        },
                    'custom_port_mapping_nat44_deletion_reco': {
                        'type': 'bool',
                        },
                    'custom_port_mapping_nat64_deletion_reco': {
                        'type': 'bool',
                        },
                    'custom_port_mapping_dslite_deletion_rec': {
                        'type': 'bool',
                        },
                    'custom_port_batching_nat44_creation_rec': {
                        'type': 'bool',
                        },
                    'custom_port_batching_nat64_creation_rec': {
                        'type': 'bool',
                        },
                    'custom_port_batching_dslite_creation_re': {
                        'type': 'bool',
                        },
                    'custom_port_batching_nat44_deletion_rec': {
                        'type': 'bool',
                        },
                    'custom_port_batching_nat64_deletion_rec': {
                        'type': 'bool',
                        },
                    'custom_port_batching_dslite_deletion_re': {
                        'type': 'bool',
                        },
                    'custom_port_batching_v2_nat44_creation_': {
                        'type': 'bool',
                        },
                    'custom_port_batching_v2_nat64_creation_': {
                        'type': 'bool',
                        },
                    'custom_port_batching_v2_dslite_creation': {
                        'type': 'bool',
                        },
                    'custom_port_batching_v2_nat44_deletion_': {
                        'type': 'bool',
                        },
                    'custom_port_batching_v2_nat64_deletion_': {
                        'type': 'bool',
                        },
                    'custom_port_batching_v2_dslite_deletion': {
                        'type': 'bool',
                        },
                    'custom_gtp_c_tunnel_event_records_sent_': {
                        'type': 'bool',
                        },
                    'custom_gtp_u_tunnel_event_records_sent_': {
                        'type': 'bool',
                        },
                    'custom_gtp_deny_event_records_sent_fail': {
                        'type': 'bool',
                        },
                    'custom_gtp_info_event_records_sent_fail': {
                        'type': 'bool',
                        },
                    'custom_fw_iddos_entry_created_records_s': {
                        'type': 'bool',
                        },
                    'custom_fw_iddos_entry_deleted_records_s': {
                        'type': 'bool',
                        },
                    'custom_fw_sesn_limit_exceeded_records_s': {
                        'type': 'bool',
                        },
                    'custom_nat_iddos_l3_entry_created_recor': {
                        'type': 'bool',
                        },
                    'custom_nat_iddos_l3_entry_deleted_recor': {
                        'type': 'bool',
                        },
                    'custom_nat_iddos_l4_entry_created_recor': {
                        'type': 'bool',
                        },
                    'custom_nat_iddos_l4_entry_deleted_recor': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'nat44_records_sent_failure': {
                        'type': 'bool',
                        },
                    'nat64_records_sent_failure': {
                        'type': 'bool',
                        },
                    'dslite_records_sent_failure': {
                        'type': 'bool',
                        },
                    'session_event_nat44_records_sent_failur': {
                        'type': 'bool',
                        },
                    'session_event_nat64_records_sent_failur': {
                        'type': 'bool',
                        },
                    'session_event_dslite_records_sent_failu': {
                        'type': 'bool',
                        },
                    'session_event_fw4_records_sent_failure': {
                        'type': 'bool',
                        },
                    'session_event_fw6_records_sent_failure': {
                        'type': 'bool',
                        },
                    'port_mapping_nat44_records_sent_failure': {
                        'type': 'bool',
                        },
                    'port_mapping_nat64_records_sent_failure': {
                        'type': 'bool',
                        },
                    'port_mapping_dslite_records_sent_failur': {
                        'type': 'bool',
                        },
                    'netflow_v5_records_sent_failure': {
                        'type': 'bool',
                        },
                    'netflow_v5_ext_records_sent_failure': {
                        'type': 'bool',
                        },
                    'port_batching_nat44_records_sent_failur': {
                        'type': 'bool',
                        },
                    'port_batching_nat64_records_sent_failur': {
                        'type': 'bool',
                        },
                    'port_batching_dslite_records_sent_failu': {
                        'type': 'bool',
                        },
                    'port_batching_v2_nat44_records_sent_fai': {
                        'type': 'bool',
                        },
                    'port_batching_v2_nat64_records_sent_fai': {
                        'type': 'bool',
                        },
                    'port_batching_v2_dslite_records_sent_fa': {
                        'type': 'bool',
                        },
                    'custom_session_event_nat44_creation_rec': {
                        'type': 'bool',
                        },
                    'custom_session_event_nat64_creation_rec': {
                        'type': 'bool',
                        },
                    'custom_session_event_dslite_creation_re': {
                        'type': 'bool',
                        },
                    'custom_session_event_nat44_deletion_rec': {
                        'type': 'bool',
                        },
                    'custom_session_event_nat64_deletion_rec': {
                        'type': 'bool',
                        },
                    'custom_session_event_dslite_deletion_re': {
                        'type': 'bool',
                        },
                    'custom_session_event_fw4_creation_recor': {
                        'type': 'bool',
                        },
                    'custom_session_event_fw6_creation_recor': {
                        'type': 'bool',
                        },
                    'custom_session_event_fw4_deletion_recor': {
                        'type': 'bool',
                        },
                    'custom_session_event_fw6_deletion_recor': {
                        'type': 'bool',
                        },
                    'custom_deny_reset_event_fw4_records_sen': {
                        'type': 'bool',
                        },
                    'custom_deny_reset_event_fw6_records_sen': {
                        'type': 'bool',
                        },
                    'custom_port_mapping_nat44_creation_reco': {
                        'type': 'bool',
                        },
                    'custom_port_mapping_nat64_creation_reco': {
                        'type': 'bool',
                        },
                    'custom_port_mapping_dslite_creation_rec': {
                        'type': 'bool',
                        },
                    'custom_port_mapping_nat44_deletion_reco': {
                        'type': 'bool',
                        },
                    'custom_port_mapping_nat64_deletion_reco': {
                        'type': 'bool',
                        },
                    'custom_port_mapping_dslite_deletion_rec': {
                        'type': 'bool',
                        },
                    'custom_port_batching_nat44_creation_rec': {
                        'type': 'bool',
                        },
                    'custom_port_batching_nat64_creation_rec': {
                        'type': 'bool',
                        },
                    'custom_port_batching_dslite_creation_re': {
                        'type': 'bool',
                        },
                    'custom_port_batching_nat44_deletion_rec': {
                        'type': 'bool',
                        },
                    'custom_port_batching_nat64_deletion_rec': {
                        'type': 'bool',
                        },
                    'custom_port_batching_dslite_deletion_re': {
                        'type': 'bool',
                        },
                    'custom_port_batching_v2_nat44_creation_': {
                        'type': 'bool',
                        },
                    'custom_port_batching_v2_nat64_creation_': {
                        'type': 'bool',
                        },
                    'custom_port_batching_v2_dslite_creation': {
                        'type': 'bool',
                        },
                    'custom_port_batching_v2_nat44_deletion_': {
                        'type': 'bool',
                        },
                    'custom_port_batching_v2_nat64_deletion_': {
                        'type': 'bool',
                        },
                    'custom_port_batching_v2_dslite_deletion': {
                        'type': 'bool',
                        },
                    'custom_gtp_c_tunnel_event_records_sent_': {
                        'type': 'bool',
                        },
                    'custom_gtp_u_tunnel_event_records_sent_': {
                        'type': 'bool',
                        },
                    'custom_gtp_deny_event_records_sent_fail': {
                        'type': 'bool',
                        },
                    'custom_gtp_info_event_records_sent_fail': {
                        'type': 'bool',
                        },
                    'custom_fw_iddos_entry_created_records_s': {
                        'type': 'bool',
                        },
                    'custom_fw_iddos_entry_deleted_records_s': {
                        'type': 'bool',
                        },
                    'custom_fw_sesn_limit_exceeded_records_s': {
                        'type': 'bool',
                        },
                    'custom_nat_iddos_l3_entry_created_recor': {
                        'type': 'bool',
                        },
                    'custom_nat_iddos_l3_entry_deleted_recor': {
                        'type': 'bool',
                        },
                    'custom_nat_iddos_l4_entry_created_recor': {
                        'type': 'bool',
                        },
                    'custom_nat_iddos_l4_entry_deleted_recor': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'rule_set_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'unmatched_drops': {
                        'type': 'bool',
                        },
                    'deny': {
                        'type': 'bool',
                        },
                    'reset': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'unmatched_drops': {
                        'type': 'bool',
                        },
                    'deny': {
                        'type': 'bool',
                        },
                    'reset': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'rule_set_rule_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'syn_cookie_verification_failed': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'syn_cookie_verification_failed': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'fw_server_port_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'es_resp_400': {
                        'type': 'bool',
                        },
                    'es_resp_500': {
                        'type': 'bool',
                        },
                    'es_resp_invalid_http': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'es_resp_400': {
                        'type': 'bool',
                        },
                    'es_resp_500': {
                        'type': 'bool',
                        },
                    'es_resp_invalid_http': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'fw_service_group_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'server_selection_fail_reset': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'server_selection_fail_reset': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'fw_service_group_mem_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'curr_conn_overflow': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'curr_conn_overflow': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'dns_vport_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'dnsrrl_total_dropped': {
                        'type': 'bool',
                        },
                    'total_filter_drop': {
                        'type': 'bool',
                        },
                    'total_max_query_len_drop': {
                        'type': 'bool',
                        },
                    'rcode_notimpl_receive': {
                        'type': 'bool',
                        },
                    'rcode_notimpl_response': {
                        'type': 'bool',
                        },
                    'gslb_query_bad': {
                        'type': 'bool',
                        },
                    'gslb_response_bad': {
                        'type': 'bool',
                        },
                    'total_dns_filter_type_drop': {
                        'type': 'bool',
                        },
                    'total_dns_filter_class_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_a_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_aaaa_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_cname_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_mx_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_ns_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_srv_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_ptr_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_soa_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_txt_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_any_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_others_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_class_internet_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_class_chaos_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_class_hesiod_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_class_none_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_class_any_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_class_others_drop': {
                        'type': 'bool',
                        },
                    'dns_rpz_action_drop': {
                        'type': 'bool',
                        },
                    'dnsrrl_bad_fqdn': {
                        'type': 'bool',
                        },
                    'dns_filter_tld_drop': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'dnsrrl_total_dropped': {
                        'type': 'bool',
                        },
                    'total_filter_drop': {
                        'type': 'bool',
                        },
                    'total_max_query_len_drop': {
                        'type': 'bool',
                        },
                    'rcode_notimpl_receive': {
                        'type': 'bool',
                        },
                    'rcode_notimpl_response': {
                        'type': 'bool',
                        },
                    'gslb_query_bad': {
                        'type': 'bool',
                        },
                    'gslb_response_bad': {
                        'type': 'bool',
                        },
                    'total_dns_filter_type_drop': {
                        'type': 'bool',
                        },
                    'total_dns_filter_class_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_a_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_aaaa_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_cname_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_mx_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_ns_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_srv_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_ptr_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_soa_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_txt_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_any_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_type_others_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_class_internet_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_class_chaos_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_class_hesiod_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_class_none_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_class_any_drop': {
                        'type': 'bool',
                        },
                    'dns_filter_class_others_drop': {
                        'type': 'bool',
                        },
                    'dns_rpz_action_drop': {
                        'type': 'bool',
                        },
                    'dnsrrl_bad_fqdn': {
                        'type': 'bool',
                        },
                    'dns_filter_tld_drop': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'smtp_vport_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'no_proxy': {
                        'type': 'bool',
                        },
                    'parse_req_fail': {
                        'type': 'bool',
                        },
                    'server_select_fail': {
                        'type': 'bool',
                        },
                    'forward_req_fail': {
                        'type': 'bool',
                        },
                    'forward_req_data_fail': {
                        'type': 'bool',
                        },
                    'snat_fail': {
                        'type': 'bool',
                        },
                    'send_client_service_not_ready': {
                        'type': 'bool',
                        },
                    'recv_server_unknow_reply_code': {
                        'type': 'bool',
                        },
                    'read_request_line_fail': {
                        'type': 'bool',
                        },
                    'get_all_headers_fail': {
                        'type': 'bool',
                        },
                    'too_many_headers': {
                        'type': 'bool',
                        },
                    'line_too_long': {
                        'type': 'bool',
                        },
                    'line_extend_fail': {
                        'type': 'bool',
                        },
                    'line_table_extend_fail': {
                        'type': 'bool',
                        },
                    'parse_request_line_fail': {
                        'type': 'bool',
                        },
                    'insert_resonse_line_fail': {
                        'type': 'bool',
                        },
                    'remove_resonse_line_fail': {
                        'type': 'bool',
                        },
                    'parse_resonse_line_fail': {
                        'type': 'bool',
                        },
                    'server_STARTTLS_fail': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'no_proxy': {
                        'type': 'bool',
                        },
                    'parse_req_fail': {
                        'type': 'bool',
                        },
                    'server_select_fail': {
                        'type': 'bool',
                        },
                    'forward_req_fail': {
                        'type': 'bool',
                        },
                    'forward_req_data_fail': {
                        'type': 'bool',
                        },
                    'snat_fail': {
                        'type': 'bool',
                        },
                    'send_client_service_not_ready': {
                        'type': 'bool',
                        },
                    'recv_server_unknow_reply_code': {
                        'type': 'bool',
                        },
                    'read_request_line_fail': {
                        'type': 'bool',
                        },
                    'get_all_headers_fail': {
                        'type': 'bool',
                        },
                    'too_many_headers': {
                        'type': 'bool',
                        },
                    'line_too_long': {
                        'type': 'bool',
                        },
                    'line_extend_fail': {
                        'type': 'bool',
                        },
                    'line_table_extend_fail': {
                        'type': 'bool',
                        },
                    'parse_request_line_fail': {
                        'type': 'bool',
                        },
                    'insert_resonse_line_fail': {
                        'type': 'bool',
                        },
                    'remove_resonse_line_fail': {
                        'type': 'bool',
                        },
                    'parse_resonse_line_fail': {
                        'type': 'bool',
                        },
                    'server_STARTTLS_fail': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'pop3_vport_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'svrsel_fail': {
                        'type': 'bool',
                        },
                    'no_route': {
                        'type': 'bool',
                        },
                    'snat_fail': {
                        'type': 'bool',
                        },
                    'line_too_long': {
                        'type': 'bool',
                        },
                    'invalid_start_line': {
                        'type': 'bool',
                        },
                    'unsupported_command': {
                        'type': 'bool',
                        },
                    'bad_sequence': {
                        'type': 'bool',
                        },
                    'rsv_persist_conn_fail': {
                        'type': 'bool',
                        },
                    'smp_v6_fail': {
                        'type': 'bool',
                        },
                    'smp_v4_fail': {
                        'type': 'bool',
                        },
                    'insert_tuple_fail': {
                        'type': 'bool',
                        },
                    'cl_est_err': {
                        'type': 'bool',
                        },
                    'ser_connecting_err': {
                        'type': 'bool',
                        },
                    'server_response_err': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'svrsel_fail': {
                        'type': 'bool',
                        },
                    'no_route': {
                        'type': 'bool',
                        },
                    'snat_fail': {
                        'type': 'bool',
                        },
                    'line_too_long': {
                        'type': 'bool',
                        },
                    'invalid_start_line': {
                        'type': 'bool',
                        },
                    'unsupported_command': {
                        'type': 'bool',
                        },
                    'bad_sequence': {
                        'type': 'bool',
                        },
                    'rsv_persist_conn_fail': {
                        'type': 'bool',
                        },
                    'smp_v6_fail': {
                        'type': 'bool',
                        },
                    'smp_v4_fail': {
                        'type': 'bool',
                        },
                    'insert_tuple_fail': {
                        'type': 'bool',
                        },
                    'cl_est_err': {
                        'type': 'bool',
                        },
                    'ser_connecting_err': {
                        'type': 'bool',
                        },
                    'server_response_err': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'imap_vport_tmpl_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'capture_config': {
                    'type': 'str',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    },
                'trigger_stats_severity': {
                    'type': 'dict',
                    'error': {
                        'type': 'bool',
                        },
                    'error_alert': {
                        'type': 'bool',
                        },
                    'error_warning': {
                        'type': 'bool',
                        },
                    'error_critical': {
                        'type': 'bool',
                        },
                    'drop': {
                        'type': 'bool',
                        },
                    'drop_alert': {
                        'type': 'bool',
                        },
                    'drop_warning': {
                        'type': 'bool',
                        },
                    'drop_critical': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_inc': {
                    'type': 'dict',
                    'svrsel_fail': {
                        'type': 'bool',
                        },
                    'no_route': {
                        'type': 'bool',
                        },
                    'snat_fail': {
                        'type': 'bool',
                        },
                    'line_too_long': {
                        'type': 'bool',
                        },
                    'invalid_start_line': {
                        'type': 'bool',
                        },
                    'cant_find_pasv': {
                        'type': 'bool',
                        },
                    'smp_create_fail': {
                        'type': 'bool',
                        },
                    'data_server_conn_fail': {
                        'type': 'bool',
                        },
                    'data_send_fail': {
                        'type': 'bool',
                        },
                    'cant_find_epsv': {
                        'type': 'bool',
                        },
                    'auth_unsupported': {
                        'type': 'bool',
                        },
                    'unsupported_pbsz_value': {
                        'type': 'bool',
                        },
                    'unsupported_prot_value': {
                        'type': 'bool',
                        },
                    'bad_sequence': {
                        'type': 'bool',
                        },
                    'rsv_persist_conn_fail': {
                        'type': 'bool',
                        },
                    'smp_v6_fail': {
                        'type': 'bool',
                        },
                    'smp_v4_fail': {
                        'type': 'bool',
                        },
                    'insert_tuple_fail': {
                        'type': 'bool',
                        },
                    'cl_est_err': {
                        'type': 'bool',
                        },
                    'ser_connecting_err': {
                        'type': 'bool',
                        },
                    'server_response_err': {
                        'type': 'bool',
                        },
                    'cl_request_err': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'trigger_stats_rate': {
                    'type': 'dict',
                    'threshold_exceeded_by': {
                        'type': 'int',
                        },
                    'duration': {
                        'type': 'int',
                        },
                    'svrsel_fail': {
                        'type': 'bool',
                        },
                    'no_route': {
                        'type': 'bool',
                        },
                    'snat_fail': {
                        'type': 'bool',
                        },
                    'line_too_long': {
                        'type': 'bool',
                        },
                    'invalid_start_line': {
                        'type': 'bool',
                        },
                    'cant_find_pasv': {
                        'type': 'bool',
                        },
                    'smp_create_fail': {
                        'type': 'bool',
                        },
                    'data_server_conn_fail': {
                        'type': 'bool',
                        },
                    'data_send_fail': {
                        'type': 'bool',
                        },
                    'cant_find_epsv': {
                        'type': 'bool',
                        },
                    'auth_unsupported': {
                        'type': 'bool',
                        },
                    'unsupported_pbsz_value': {
                        'type': 'bool',
                        },
                    'unsupported_prot_value': {
                        'type': 'bool',
                        },
                    'bad_sequence': {
                        'type': 'bool',
                        },
                    'rsv_persist_conn_fail': {
                        'type': 'bool',
                        },
                    'smp_v6_fail': {
                        'type': 'bool',
                        },
                    'smp_v4_fail': {
                        'type': 'bool',
                        },
                    'insert_tuple_fail': {
                        'type': 'bool',
                        },
                    'cl_est_err': {
                        'type': 'bool',
                        },
                    'ser_connecting_err': {
                        'type': 'bool',
                        },
                    'server_response_err': {
                        'type': 'bool',
                        },
                    'cl_request_err': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                }
            },
        'automated_captures': {
            'type': 'dict',
            'slb_port_tmpl_error_code_return_inc': {
                'type': 'bool',
                },
            'slb_port_tmpl_high_error_code_return': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'packet_capture_files': {
                'type': 'bool',
                },
            'memory_usage': {
                'type': 'bool',
                },
            'total_number_of_files': {
                'type': 'int',
                },
            'packet_capture_file_name_list': {
                'type': 'list',
                'packet_capture_file_name': {
                    'type': 'str',
                    },
                'file_size': {
                    'type': 'int',
                    },
                'last_modified': {
                    'type': 'str',
                    }
                },
            'total_memory': {
                'type': 'str',
                },
            'used_memory': {
                'type': 'str',
                },
            'automated_captures': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'capture_name': {
                        'type': 'str',
                        },
                    'automated_capture_config': {
                        'type': 'list',
                        'automated_capture_config_line': {
                            'type': 'str',
                            }
                        }
                    }
                }
            },
        'stats': {
            'type': 'dict',
            'Concurrent_capture_created_by_ctr_increment': {
                'type': 'str',
                },
            'Concurrent_capture_created_by_ctr_anomaly': {
                'type': 'str',
                },
            'Concurrent_capture_created_by_other_feature': {
                'type': 'str',
                },
            'Concurrent_capture_create_failed_by_ctr_increment': {
                'type': 'str',
                },
            'Concurrent_capture_create_failed_by_ctr_anomaly': {
                'type': 'str',
                },
            'Concurrent_capture_create_failed_by_other_feature': {
                'type': 'str',
                },
            'Concurrent_capture_create_failed_oom': {
                'type': 'str',
                },
            'Concurrent_capture_limit_reached': {
                'type': 'str',
                },
            'Concurrent_capture_by_ctr_increment_freed': {
                'type': 'str',
                },
            'Concurrent_capture_by_ctr_anomaly_freed': {
                'type': 'str',
                },
            'Concurrent_capture_by_ctr_other_feature_freed': {
                'type': 'str',
                },
            'Global_capture_finished': {
                'type': 'str',
                },
            'Concurrent_capture_finished': {
                'type': 'str',
                },
            'pktcapture_with_no_conn_success': {
                'type': 'str',
                },
            'pktcapture_with_no_conn_failure': {
                'type': 'str',
                },
            'pktcapture_with_conn_but_not_tagged_success': {
                'type': 'str',
                },
            'pktcapture_with_conn_but_not_tagged_failure': {
                'type': 'str',
                },
            'pktcapture_with_conn_success_global': {
                'type': 'str',
                },
            'pktcapture_with_conn_success': {
                'type': 'str',
                },
            'pktcapture_with_conn_failure_global': {
                'type': 'str',
                },
            'pktcapture_with_conn_failure': {
                'type': 'str',
                },
            'pktcapture_failure_wait_for_block': {
                'type': 'str',
                },
            'pktcapture_failure_file_size_rchd': {
                'type': 'str',
                },
            'num_conns_tagged_global_increment': {
                'type': 'str',
                },
            'num_conns_tagged_global_anomaly': {
                'type': 'str',
                },
            'num_conns_tagged_global_other_feature': {
                'type': 'str',
                },
            'num_conns_tagged_global_increment_fail': {
                'type': 'str',
                },
            'num_conns_tagged_global_anomaly_fail': {
                'type': 'str',
                },
            'num_conns_tagged_global_other_feature_fail': {
                'type': 'str',
                },
            'num_conns_tagged_global_increment_maxed': {
                'type': 'str',
                },
            'num_conns_tagged_global_anomaly_maxed': {
                'type': 'str',
                },
            'num_conns_tagged_global_other_feature_maxed': {
                'type': 'str',
                },
            'num_conns_tagged_increment': {
                'type': 'str',
                },
            'num_conns_tagged_anomaly': {
                'type': 'str',
                },
            'num_conns_tagged_other_feature': {
                'type': 'str',
                },
            'num_conns_tagged_increment_fail': {
                'type': 'str',
                },
            'num_conns_tagged_anomaly_fail': {
                'type': 'str',
                },
            'num_conns_tagged_other_feature_fail': {
                'type': 'str',
                },
            'num_conns_tagged_increment_maxed': {
                'type': 'str',
                },
            'num_conns_tagged_anomaly_maxed': {
                'type': 'str',
                },
            'num_conns_tagged_other_feature_maxed': {
                'type': 'str',
                },
            'num_conns_untagged': {
                'type': 'str',
                },
            'pktcapture_triggered_by_increment': {
                'type': 'str',
                },
            'pktcapture_triggered_by_anomaly': {
                'type': 'str',
                },
            'pktcapture_triggered_by_other_feature': {
                'type': 'str',
                },
            'num_of_anomalies_detected': {
                'type': 'str',
                },
            'num_of_anomalies_cleared': {
                'type': 'str',
                },
            'num_pcaps_created': {
                'type': 'str',
                },
            'num_tmp_pcaps_created': {
                'type': 'str',
                },
            'num_pcaps_create_failed': {
                'type': 'str',
                },
            'pktcap_oom': {
                'type': 'str',
                },
            'failed_disk_full': {
                'type': 'str',
                },
            'conn_ext_failed': {
                'type': 'str',
                },
            'skip_as_conn_already_recapture': {
                'type': 'str',
                },
            'skip_capture_as_conn_created_before_smp': {
                'type': 'str',
                },
            'failed_as_return_completed_set': {
                'type': 'str',
                },
            'non_pkt_path': {
                'type': 'str',
                },
            'pkt_already_captured': {
                'type': 'str',
                },
            'wrong_ctr_incremented': {
                'type': 'str',
                },
            'auto_pcap_file_merged': {
                'type': 'str',
                },
            'auto_pcap_file_merged_failed': {
                'type': 'str',
                },
            'num_global_tmpl_created': {
                'type': 'str',
                },
            'num_object_tmpl_created': {
                'type': 'str',
                },
            'num_global_tmpl_deleted': {
                'type': 'str',
                },
            'num_object_tmpl_deleted': {
                'type': 'str',
                },
            'num_capture_config_created': {
                'type': 'str',
                },
            'num_dynamic_capture_config_created': {
                'type': 'str',
                },
            'num_capture_config_deleted': {
                'type': 'str',
                },
            'num_dynamic_capture_config_deleted': {
                'type': 'str',
                },
            'num_capture_config_delete_q': {
                'type': 'str',
                },
            'num_dynamic_capture_config_delete_q': {
                'type': 'str',
                },
            'num_capture_config_linked': {
                'type': 'str',
                },
            'num_dynamic_capture_config_linked': {
                'type': 'str',
                },
            'num_capture_config_unlinked': {
                'type': 'str',
                },
            'num_dynamic_capture_config_unlinked': {
                'type': 'str',
                },
            'num_global_counters_registered': {
                'type': 'str',
                },
            'num_global_counters_deregistered': {
                'type': 'str',
                },
            'num_per_object_counters_registered': {
                'type': 'str',
                },
            'num_per_object_counters_deregistered': {
                'type': 'str',
                },
            'capture_config_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'stats': {
                    'type': 'dict',
                    'Concurrent_capture_created_by_ctr_increment': {
                        'type': 'str',
                        },
                    'Concurrent_capture_created_by_ctr_anomaly': {
                        'type': 'str',
                        },
                    'Concurrent_capture_create_failed_by_ctr_increment': {
                        'type': 'str',
                        },
                    'Concurrent_capture_create_failed_by_ctr_anomaly': {
                        'type': 'str',
                        },
                    'Concurrent_capture_create_failed_by_other_feature': {
                        'type': 'str',
                        },
                    'Concurrent_capture_create_failed_oom': {
                        'type': 'str',
                        },
                    'Concurrent_capture_limit_reached': {
                        'type': 'str',
                        },
                    'Concurrent_capture_by_ctr_increment_freed': {
                        'type': 'str',
                        },
                    'Concurrent_capture_by_ctr_anomaly_freed': {
                        'type': 'str',
                        },
                    'Concurrent_capture_by_ctr_other_feature_freed': {
                        'type': 'str',
                        },
                    'Global_capture_finished': {
                        'type': 'str',
                        },
                    'Concurrent_capture_finished': {
                        'type': 'str',
                        },
                    'pktcapture_with_no_conn_success': {
                        'type': 'str',
                        },
                    'pktcapture_with_no_conn_failure': {
                        'type': 'str',
                        },
                    'pktcapture_with_conn_but_not_tagged_success': {
                        'type': 'str',
                        },
                    'pktcapture_with_conn_but_not_tagged_failure': {
                        'type': 'str',
                        },
                    'pktcapture_with_conn_success_global': {
                        'type': 'str',
                        },
                    'pktcapture_with_conn_success': {
                        'type': 'str',
                        },
                    'pktcapture_with_conn_failure_global': {
                        'type': 'str',
                        },
                    'pktcapture_with_conn_failure': {
                        'type': 'str',
                        },
                    'pktcapture_failure_wait_for_block': {
                        'type': 'str',
                        },
                    'pktcapture_failure_file_size_rchd': {
                        'type': 'str',
                        },
                    'num_conns_tagged_global_increment': {
                        'type': 'str',
                        },
                    'num_conns_tagged_global_anomaly': {
                        'type': 'str',
                        },
                    'num_conns_tagged_global_other_feature': {
                        'type': 'str',
                        },
                    'num_conns_tagged_global_increment_fail': {
                        'type': 'str',
                        },
                    'num_conns_tagged_global_anomaly_fail': {
                        'type': 'str',
                        },
                    'num_conns_tagged_global_other_feature_fail': {
                        'type': 'str',
                        },
                    'num_conns_tagged_global_increment_maxed': {
                        'type': 'str',
                        },
                    'num_conns_tagged_global_anomaly_maxed': {
                        'type': 'str',
                        },
                    'num_conns_tagged_global_other_feature_maxed': {
                        'type': 'str',
                        },
                    'num_conns_tagged_increment': {
                        'type': 'str',
                        },
                    'num_conns_tagged_anomaly': {
                        'type': 'str',
                        },
                    'num_conns_tagged_other_feature': {
                        'type': 'str',
                        },
                    'num_conns_tagged_increment_fail': {
                        'type': 'str',
                        },
                    'num_conns_tagged_anomaly_fail': {
                        'type': 'str',
                        },
                    'num_conns_tagged_other_feature_fail': {
                        'type': 'str',
                        },
                    'num_conns_tagged_increment_maxed': {
                        'type': 'str',
                        },
                    'num_conns_tagged_anomaly_maxed': {
                        'type': 'str',
                        },
                    'num_conns_tagged_other_feature_maxed': {
                        'type': 'str',
                        },
                    'num_conns_untagged': {
                        'type': 'str',
                        },
                    'pktcapture_triggered_by_increment': {
                        'type': 'str',
                        },
                    'pktcapture_triggered_by_anomaly': {
                        'type': 'str',
                        },
                    'pktcapture_triggered_by_other_feature': {
                        'type': 'str',
                        },
                    'num_of_anomalies_detected': {
                        'type': 'str',
                        },
                    'num_of_anomalies_cleared': {
                        'type': 'str',
                        },
                    'num_pcaps_created': {
                        'type': 'str',
                        },
                    'num_tmp_pcaps_created': {
                        'type': 'str',
                        },
                    'num_pcaps_create_failed': {
                        'type': 'str',
                        },
                    'pktcap_oom': {
                        'type': 'str',
                        },
                    'failed_disk_full': {
                        'type': 'str',
                        },
                    'conn_ext_failed': {
                        'type': 'str',
                        },
                    'skip_as_conn_already_recapture': {
                        'type': 'str',
                        },
                    'skip_capture_as_conn_created_before_smp': {
                        'type': 'str',
                        },
                    'failed_as_return_completed_set': {
                        'type': 'str',
                        },
                    'non_pkt_path': {
                        'type': 'str',
                        },
                    'pkt_already_captured': {
                        'type': 'str',
                        },
                    'wrong_ctr_incremented': {
                        'type': 'str',
                        },
                    'auto_pcap_file_merged': {
                        'type': 'str',
                        },
                    'auto_pcap_file_merged_failed': {
                        'type': 'str',
                        },
                    'num_dynamic_capture_config_created': {
                        'type': 'str',
                        },
                    'num_dynamic_capture_config_delete_q': {
                        'type': 'str',
                        },
                    'num_dynamic_capture_config_deleted': {
                        'type': 'str',
                        },
                    'num_global_counters_registered': {
                        'type': 'str',
                        },
                    'num_global_counters_deregistered': {
                        'type': 'str',
                        },
                    'num_per_object_counters_registered': {
                        'type': 'str',
                        },
                    'num_per_object_counters_deregistered': {
                        'type': 'str',
                        }
                    }
                },
            'automated_captures': {
                'type': 'dict',
                'stats': {
                    'type': 'dict',
                    'total_failure': {
                        'type': 'str',
                        }
                    }
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/packet-capture"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/packet-capture"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["packet-capture"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["packet-capture"].get(k) != v:
            change_results["changed"] = True
            config_changes["packet-capture"][k] = v

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
    payload = utils.build_json("packet-capture", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["packet-capture"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["packet-capture-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["packet-capture"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["packet-capture"]["stats"] if info != "NotFound" else info
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
