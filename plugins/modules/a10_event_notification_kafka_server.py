#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_event_notification_kafka_server
description:
    - Set remote kafka server ip address
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
    host_ipv4:
        description:
        - "Set kafka Broker ip address or hostname"
        type: str
        required: False
    use_mgmt_port:
        description:
        - "Use management port for connections"
        type: bool
        required: False
    port:
        description:
        - "Set remote kafka port number (Remote kafka port number 1-32767, default is
          9092)"
        type: int
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
                - "'all'= all; 'pr-acos-harmony-topic'= L7 PR logs sent; 'avro-device-status-
          topic'= Device Status Metrics sent; 'avro-partition-metrics-topic'= Partition
          Metrics sent; 'avro-generic-sent'= Generic Metrics sent; 'pr-acos-harmony-
          topic-enqueue-err'= L7 PR dropped,enq error on acos queues; 'pr-acos-harmony-
          topic-dequeue-err'= L7 PR dropped,enq error analytics queues; 'avro-generic-
          failed-encoding'= Generic Metrics dropped,encoding error; 'avro-generic-failed-
          sending'= Generic Metrics dropped,sending failure; 'avro-device-status-topic-
          enqueue-err'= Device Status dropped,enq error on acos queues; 'avro-device-
          status-topic-dequeue-err'= Device Status dropped,enq error analytics queues;
          'avro-partition-metrics-topic-enqueue-err'= Part metrics dropped,enq error on
          acos queues; 'avro-partition-metrics-topic-dequeue-err'= Part metrics
          dropped,enq error analytics queues; 'kafka-unknown-topic-dequeue-err'= Unknown
          type dropped,enq error analytics queues; 'kafka-broker-down'= Messages
          dropped,analytics down; 'kafka-queue-full-err'= Messages dropped,acos analytics
          queue full; 'pr-throttle-drop'= L7 PR dropped,log throttling; 'pr-not-allowed-
          drop'= L7 PR dropped, not allowed to be sent; 'pr-be-ttfb-anomaly'= L7 PR back-
          end ttfb is negative; 'pr-be-ttlb-anomaly'= L7 PR back-end ttlb is negative;
          'pr-in-latency-threshold-exceed'= L7 PR on latency threshold exceeded; 'pr-out-
          latency-threshold-exceed'= L7 PR out latency threshold exceeded; 'pr-out-
          latency-anomaly'= L7 PR out latency negative; 'pr-in-latency-anomaly'= L7 PR on
          latency negative; 'kafka-topic-error'= Module not supported by analytics; 'pc-
          encoding-failed'= L4 PC logs dropped,encoding error; 'pc-acos-harmony-topic'=
          L4 PC logs sent; 'pc-acos-harmony-topic-dequeue-err'= L4 PC logs dropped,enq
          error analytics queues; 'cgn-pc-acos-harmony-topic'= CGN PC logs sent; 'cgn-pc-
          acos-harmony-topic-dequeue-err'= CGN PC logs dropped,enq error analytics
          queues; 'cgn-pe-acos-harmony-topic'= CGN PE logs sent; 'cgn-pe-acos-harmony-
          topic-dequeue-err'= CGN PE logs dropped,enq error analytics queues; 'fw-pc-
          acos-harmony-topic'= FW PC logs sent; 'fw-pc-acos-harmony-topic-dequeue-err'=
          FW PC logs dropped,enq error analytics queues; 'fw-deny-pc-acos-harmony-topic'=
          FW DENY PC logs sent; 'fw-deny-pc-acos-harmony-topic-dequeue-err'= FW DENY PC
          logs dropped,enq error analytics queues; 'fw-rst-pc-acos-harmony-topic'= FW RST
          PC logs sent; 'fw-rst-pc-acos-harmony-topic-dequeue-err'= FW RST PC logs
          dropped,enq error analytics queues; 'cgn-summary-error-acos-harmony-topic'= CGN
          PE logs sent; 'cgn-summary-error-acos-harmony-topic-dequeue-err'= CGN PE logs
          dropped,enq error analytics queues; 'rule-set-application-metrics-topic'= AppFW
          metrics sent; 'rule-set-application-metrics-topic-dequeue-err'= AppFW metrics
          dropped,enq error analytics queues; 'slb-ssl-stats-metrics-topic'= SSL metrics
          sent; 'slb-ssl-stats-metrics-topic-dequeue-err'= SSL metrics dropped,enq error
          analytics queues; 'slb-client-ssl-counters-metrics-topic'= Client SSL metrics
          sent; 'slb-client-ssl-counters-metrics-topic-dequeue-err'= Cilent SSL metrics
          dropped,enq error analytics qs; 'slb-server-ssl-counters-metrics-topic'= Server
          SSL metrics sent; 'slb-server-ssl-counters-metrics-topic-dequeue-err'= Server
          SSL metrics dropped,enq error analytics qs; 'pc-throttle-drop'= L4 PC logs
          dropped,throttling; 'metrics-dropped-pt-missing'= Metrics dropped,missing
          partition tenant mapping; 'ssli-pc-acos-harmony-topic'= SSLi PC topic counter
          from acos to harmony; 'ssli-pc-acos-harmony-topic-dequeue-err'= SSLi PC topic
          to harmony dequeue error; 'ssli-pe-acos-harmony-topic'= SSLi PE topic counter
          from acos to harmony; 'ssli-pe-acos-harmony-topic-dequeue-err'= SSLi PE topic
          to harmony dequeue error; 'analytics-bus-restart'= Analytics bus restart count;
          'waf-learn-pr-topic'= WAF learn topic counter; 'waf-learn-pr-topic-dequeue-
          err'= WAF learn metrics dropped,enq error analytics qs; 'waf-events-topic'= WAF
          events topic counter; 'waf-events-topic-dequeue-err'= WAF events metrics
          dropped,enq error analytics qs; 'visibility-topn-harmony-topic'= Visibility
          TopN sent; 'visibility-topn-harmony-topic-dequeue-err'= Visibility TopN metrics
          dropped,enq error analytics qs; 'hc-logs-sent-to-master'= HC logs sent to
          master; 'hc-logs-received-from-blade'= HC logs received from blade; 'hc-oper-
          sent-to-master'= HC oper to master; 'hc-oper-received-from-blade'= HC oper
          received from blade; 'hc-counters-sent-to-master'= HC counters sent to master;
          'hc-counters-received-from-blade'= HC counters received from blade; 'hc-
          counters-dropped-from-blade'= HC counters dropped from blade (uuid or size
          mismatch); 'pe-acos-harmony-topic'= L7 PE logs sent; 'pe-acos-harmony-topic-
          enqueue-err'= L7 PE dropped,enq error on acos queues; 'pe-acos-harmony-topic-
          dequeue-err'= L7 PE dropped,enq error analytics queues; 'vpn-ipsec-sa-metrics-
          topic'= IPSec SA metrics sent; 'vpn-ipsec-sa-metrics-topic-dequeue-err'= IPSec
          SA metrics dropped,enq error analytics qs; 'vpn-ike-gateway-metrics-topic'= IKE
          gateway metrics sent; 'vpn-ike-gateway-metrics-topic-dequeue-err'= IKE gateway
          metrics dropped,enq error analytics qs; 'vpn-stats-metrics-topic'= VPN STATS
          metrics sent; 'vpn-stats-metrics-topic-dequeue-err'= VPN STATS metrics
          dropped,enq error analytics qs; 'cgn-port-usage-hstgrm-acos-harmony-topic'= CGN
          Port Usage Histogram HC Export; 'cgn-port-usage-hstgrm-acos-harmony-topic-
          dequeue-err'= CGN Port Usage Histogram HC Export Failed; 'avro-system-env-
          topic'= System environment sent; 'avro-system-env-dequeue-err'= System
          Environmet dropped,enq error analytics queues; 'cert-pinning-list-topic'= Cert-
          pinning candidate list sent; 'cert-pinning-list-topic-dequeue-err'= Cert-
          pinning candidate list dropped,enq error analytics queues;"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            kafka_broker_state:
                description:
                - "Field kafka_broker_state"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            pr_acos_harmony_topic:
                description:
                - "L7 PR logs sent"
                type: str
            avro_device_status_topic:
                description:
                - "Device Status Metrics sent"
                type: str
            avro_partition_metrics_topic:
                description:
                - "Partition Metrics sent"
                type: str
            avro_generic_sent:
                description:
                - "Generic Metrics sent"
                type: str
            pr_acos_harmony_topic_enqueue_err:
                description:
                - "L7 PR dropped,enq error on acos queues"
                type: str
            pr_acos_harmony_topic_dequeue_err:
                description:
                - "L7 PR dropped,enq error analytics queues"
                type: str
            avro_generic_failed_encoding:
                description:
                - "Generic Metrics dropped,encoding error"
                type: str
            avro_generic_failed_sending:
                description:
                - "Generic Metrics dropped,sending failure"
                type: str
            avro_device_status_topic_enqueue_err:
                description:
                - "Device Status dropped,enq error on acos queues"
                type: str
            avro_device_status_topic_dequeue_err:
                description:
                - "Device Status dropped,enq error analytics queues"
                type: str
            avro_partition_metrics_topic_enqueue_err:
                description:
                - "Part metrics dropped,enq error on acos queues"
                type: str
            avro_partition_metrics_topic_dequeue_err:
                description:
                - "Part metrics dropped,enq error analytics queues"
                type: str
            kafka_unknown_topic_dequeue_err:
                description:
                - "Unknown type dropped,enq error analytics queues"
                type: str
            kafka_broker_down:
                description:
                - "Messages dropped,analytics down"
                type: str
            kafka_queue_full_err:
                description:
                - "Messages dropped,acos analytics queue full"
                type: str
            pr_throttle_drop:
                description:
                - "L7 PR dropped,log throttling"
                type: str
            pr_not_allowed_drop:
                description:
                - "L7 PR dropped, not allowed to be sent"
                type: str
            pr_be_ttfb_anomaly:
                description:
                - "L7 PR back-end ttfb is negative"
                type: str
            pr_be_ttlb_anomaly:
                description:
                - "L7 PR back-end ttlb is negative"
                type: str
            pr_in_latency_threshold_exceed:
                description:
                - "L7 PR on latency threshold exceeded"
                type: str
            pr_out_latency_threshold_exceed:
                description:
                - "L7 PR out latency threshold exceeded"
                type: str
            pr_out_latency_anomaly:
                description:
                - "L7 PR out latency negative"
                type: str
            pr_in_latency_anomaly:
                description:
                - "L7 PR on latency negative"
                type: str
            kafka_topic_error:
                description:
                - "Module not supported by analytics"
                type: str
            pc_encoding_failed:
                description:
                - "L4 PC logs dropped,encoding error"
                type: str
            pc_acos_harmony_topic:
                description:
                - "L4 PC logs sent"
                type: str
            pc_acos_harmony_topic_dequeue_err:
                description:
                - "L4 PC logs dropped,enq error analytics queues"
                type: str
            cgn_pc_acos_harmony_topic:
                description:
                - "CGN PC logs sent"
                type: str
            cgn_pc_acos_harmony_topic_dequeue_err:
                description:
                - "CGN PC logs dropped,enq error analytics queues"
                type: str
            cgn_pe_acos_harmony_topic:
                description:
                - "CGN PE logs sent"
                type: str
            cgn_pe_acos_harmony_topic_dequeue_err:
                description:
                - "CGN PE logs dropped,enq error analytics queues"
                type: str
            fw_pc_acos_harmony_topic:
                description:
                - "FW PC logs sent"
                type: str
            fw_pc_acos_harmony_topic_dequeue_err:
                description:
                - "FW PC logs dropped,enq error analytics queues"
                type: str
            fw_deny_pc_acos_harmony_topic:
                description:
                - "FW DENY PC logs sent"
                type: str
            fw_deny_pc_acos_harmony_topic_dequeue_err:
                description:
                - "FW DENY PC logs dropped,enq error analytics queues"
                type: str
            fw_rst_pc_acos_harmony_topic:
                description:
                - "FW RST PC logs sent"
                type: str
            fw_rst_pc_acos_harmony_topic_dequeue_err:
                description:
                - "FW RST PC logs dropped,enq error analytics queues"
                type: str
            cgn_summary_error_acos_harmony_topic:
                description:
                - "CGN PE logs sent"
                type: str
            cgn_summary_error_acos_harmony_topic_dequeue_err:
                description:
                - "CGN PE logs dropped,enq error analytics queues"
                type: str
            rule_set_application_metrics_topic:
                description:
                - "AppFW metrics sent"
                type: str
            rule_set_application_metrics_topic_dequeue_err:
                description:
                - "AppFW metrics dropped,enq error analytics queues"
                type: str
            slb_ssl_stats_metrics_topic:
                description:
                - "SSL metrics sent"
                type: str
            slb_ssl_stats_metrics_topic_dequeue_err:
                description:
                - "SSL metrics dropped,enq error analytics queues"
                type: str
            slb_client_ssl_counters_metrics_topic:
                description:
                - "Client SSL metrics sent"
                type: str
            slb_client_ssl_counters_metrics_topic_dequeue_err:
                description:
                - "Cilent SSL metrics dropped,enq error analytics qs"
                type: str
            slb_server_ssl_counters_metrics_topic:
                description:
                - "Server SSL metrics sent"
                type: str
            slb_server_ssl_counters_metrics_topic_dequeue_err:
                description:
                - "Server SSL metrics dropped,enq error analytics qs"
                type: str
            pc_throttle_drop:
                description:
                - "L4 PC logs dropped,throttling"
                type: str
            metrics_dropped_pt_missing:
                description:
                - "Metrics dropped,missing partition tenant mapping"
                type: str
            ssli_pc_acos_harmony_topic:
                description:
                - "SSLi PC topic counter from acos to harmony"
                type: str
            ssli_pc_acos_harmony_topic_dequeue_err:
                description:
                - "SSLi PC topic to harmony dequeue error"
                type: str
            ssli_pe_acos_harmony_topic:
                description:
                - "SSLi PE topic counter from acos to harmony"
                type: str
            ssli_pe_acos_harmony_topic_dequeue_err:
                description:
                - "SSLi PE topic to harmony dequeue error"
                type: str
            analytics_bus_restart:
                description:
                - "Analytics bus restart count"
                type: str
            waf_learn_pr_topic:
                description:
                - "WAF learn topic counter"
                type: str
            waf_learn_pr_topic_dequeue_err:
                description:
                - "WAF learn metrics dropped,enq error analytics qs"
                type: str
            waf_events_topic:
                description:
                - "WAF events topic counter"
                type: str
            waf_events_topic_dequeue_err:
                description:
                - "WAF events metrics dropped,enq error analytics qs"
                type: str
            visibility_topn_harmony_topic:
                description:
                - "Visibility TopN sent"
                type: str
            visibility_topn_harmony_topic_dequeue_err:
                description:
                - "Visibility TopN metrics dropped,enq error analytics qs"
                type: str
            hc_logs_sent_to_master:
                description:
                - "HC logs sent to master"
                type: str
            hc_logs_received_from_blade:
                description:
                - "HC logs received from blade"
                type: str
            hc_oper_sent_to_master:
                description:
                - "HC oper to master"
                type: str
            hc_oper_received_from_blade:
                description:
                - "HC oper received from blade"
                type: str
            hc_counters_sent_to_master:
                description:
                - "HC counters sent to master"
                type: str
            hc_counters_received_from_blade:
                description:
                - "HC counters received from blade"
                type: str
            hc_counters_dropped_from_blade:
                description:
                - "HC counters dropped from blade (uuid or size mismatch)"
                type: str
            pe_acos_harmony_topic:
                description:
                - "L7 PE logs sent"
                type: str
            pe_acos_harmony_topic_enqueue_err:
                description:
                - "L7 PE dropped,enq error on acos queues"
                type: str
            pe_acos_harmony_topic_dequeue_err:
                description:
                - "L7 PE dropped,enq error analytics queues"
                type: str
            vpn_ipsec_sa_metrics_topic:
                description:
                - "IPSec SA metrics sent"
                type: str
            vpn_ipsec_sa_metrics_topic_dequeue_err:
                description:
                - "IPSec SA metrics dropped,enq error analytics qs"
                type: str
            vpn_ike_gateway_metrics_topic:
                description:
                - "IKE gateway metrics sent"
                type: str
            vpn_ike_gateway_metrics_topic_dequeue_err:
                description:
                - "IKE gateway metrics dropped,enq error analytics qs"
                type: str
            vpn_stats_metrics_topic:
                description:
                - "VPN STATS metrics sent"
                type: str
            vpn_stats_metrics_topic_dequeue_err:
                description:
                - "VPN STATS metrics dropped,enq error analytics qs"
                type: str
            cgn_port_usage_hstgrm_acos_harmony_topic:
                description:
                - "CGN Port Usage Histogram HC Export"
                type: str
            cgn_port_usage_hstgrm_acos_harmony_topic_dequeue_err:
                description:
                - "CGN Port Usage Histogram HC Export Failed"
                type: str
            avro_system_env_topic:
                description:
                - "System environment sent"
                type: str
            avro_system_env_dequeue_err:
                description:
                - "System Environmet dropped,enq error analytics queues"
                type: str
            cert_pinning_list_topic:
                description:
                - "Cert-pinning candidate list sent"
                type: str
            cert_pinning_list_topic_dequeue_err:
                description:
                - "Cert-pinning candidate list dropped,enq error analytics queues"
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
AVAILABLE_PROPERTIES = ["host_ipv4", "oper", "port", "sampling_enable", "stats", "use_mgmt_port", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({'host_ipv4': {'type': 'str', },
        'use_mgmt_port': {'type': 'bool', },
        'port': {'type': 'int', },
        'uuid': {'type': 'str', },
        'sampling_enable': {'type': 'list', 'counters1': {'type': 'str', 'choices': ['all', 'pr-acos-harmony-topic', 'avro-device-status-topic', 'avro-partition-metrics-topic', 'avro-generic-sent', 'pr-acos-harmony-topic-enqueue-err', 'pr-acos-harmony-topic-dequeue-err', 'avro-generic-failed-encoding', 'avro-generic-failed-sending', 'avro-device-status-topic-enqueue-err', 'avro-device-status-topic-dequeue-err', 'avro-partition-metrics-topic-enqueue-err', 'avro-partition-metrics-topic-dequeue-err', 'kafka-unknown-topic-dequeue-err', 'kafka-broker-down', 'kafka-queue-full-err', 'pr-throttle-drop', 'pr-not-allowed-drop', 'pr-be-ttfb-anomaly', 'pr-be-ttlb-anomaly', 'pr-in-latency-threshold-exceed', 'pr-out-latency-threshold-exceed', 'pr-out-latency-anomaly', 'pr-in-latency-anomaly', 'kafka-topic-error', 'pc-encoding-failed', 'pc-acos-harmony-topic', 'pc-acos-harmony-topic-dequeue-err', 'cgn-pc-acos-harmony-topic', 'cgn-pc-acos-harmony-topic-dequeue-err', 'cgn-pe-acos-harmony-topic', 'cgn-pe-acos-harmony-topic-dequeue-err', 'fw-pc-acos-harmony-topic', 'fw-pc-acos-harmony-topic-dequeue-err', 'fw-deny-pc-acos-harmony-topic', 'fw-deny-pc-acos-harmony-topic-dequeue-err', 'fw-rst-pc-acos-harmony-topic', 'fw-rst-pc-acos-harmony-topic-dequeue-err', 'cgn-summary-error-acos-harmony-topic', 'cgn-summary-error-acos-harmony-topic-dequeue-err', 'rule-set-application-metrics-topic', 'rule-set-application-metrics-topic-dequeue-err', 'slb-ssl-stats-metrics-topic', 'slb-ssl-stats-metrics-topic-dequeue-err', 'slb-client-ssl-counters-metrics-topic', 'slb-client-ssl-counters-metrics-topic-dequeue-err', 'slb-server-ssl-counters-metrics-topic', 'slb-server-ssl-counters-metrics-topic-dequeue-err', 'pc-throttle-drop', 'metrics-dropped-pt-missing', 'ssli-pc-acos-harmony-topic', 'ssli-pc-acos-harmony-topic-dequeue-err', 'ssli-pe-acos-harmony-topic', 'ssli-pe-acos-harmony-topic-dequeue-err', 'analytics-bus-restart', 'waf-learn-pr-topic', 'waf-learn-pr-topic-dequeue-err', 'waf-events-topic', 'waf-events-topic-dequeue-err', 'visibility-topn-harmony-topic', 'visibility-topn-harmony-topic-dequeue-err', 'hc-logs-sent-to-master', 'hc-logs-received-from-blade', 'hc-oper-sent-to-master', 'hc-oper-received-from-blade', 'hc-counters-sent-to-master', 'hc-counters-received-from-blade', 'hc-counters-dropped-from-blade', 'pe-acos-harmony-topic', 'pe-acos-harmony-topic-enqueue-err', 'pe-acos-harmony-topic-dequeue-err', 'vpn-ipsec-sa-metrics-topic', 'vpn-ipsec-sa-metrics-topic-dequeue-err', 'vpn-ike-gateway-metrics-topic', 'vpn-ike-gateway-metrics-topic-dequeue-err', 'vpn-stats-metrics-topic', 'vpn-stats-metrics-topic-dequeue-err', 'cgn-port-usage-hstgrm-acos-harmony-topic', 'cgn-port-usage-hstgrm-acos-harmony-topic-dequeue-err', 'avro-system-env-topic', 'avro-system-env-dequeue-err', 'cert-pinning-list-topic', 'cert-pinning-list-topic-dequeue-err']}},
        'oper': {'type': 'dict', 'kafka_broker_state': {'type': 'str', 'choices': ['Up', 'Down']}},
        'stats': {'type': 'dict', 'pr_acos_harmony_topic': {'type': 'str', }, 'avro_device_status_topic': {'type': 'str', }, 'avro_partition_metrics_topic': {'type': 'str', }, 'avro_generic_sent': {'type': 'str', }, 'pr_acos_harmony_topic_enqueue_err': {'type': 'str', }, 'pr_acos_harmony_topic_dequeue_err': {'type': 'str', }, 'avro_generic_failed_encoding': {'type': 'str', }, 'avro_generic_failed_sending': {'type': 'str', }, 'avro_device_status_topic_enqueue_err': {'type': 'str', }, 'avro_device_status_topic_dequeue_err': {'type': 'str', }, 'avro_partition_metrics_topic_enqueue_err': {'type': 'str', }, 'avro_partition_metrics_topic_dequeue_err': {'type': 'str', }, 'kafka_unknown_topic_dequeue_err': {'type': 'str', }, 'kafka_broker_down': {'type': 'str', }, 'kafka_queue_full_err': {'type': 'str', }, 'pr_throttle_drop': {'type': 'str', }, 'pr_not_allowed_drop': {'type': 'str', }, 'pr_be_ttfb_anomaly': {'type': 'str', }, 'pr_be_ttlb_anomaly': {'type': 'str', }, 'pr_in_latency_threshold_exceed': {'type': 'str', }, 'pr_out_latency_threshold_exceed': {'type': 'str', }, 'pr_out_latency_anomaly': {'type': 'str', }, 'pr_in_latency_anomaly': {'type': 'str', }, 'kafka_topic_error': {'type': 'str', }, 'pc_encoding_failed': {'type': 'str', }, 'pc_acos_harmony_topic': {'type': 'str', }, 'pc_acos_harmony_topic_dequeue_err': {'type': 'str', }, 'cgn_pc_acos_harmony_topic': {'type': 'str', }, 'cgn_pc_acos_harmony_topic_dequeue_err': {'type': 'str', }, 'cgn_pe_acos_harmony_topic': {'type': 'str', }, 'cgn_pe_acos_harmony_topic_dequeue_err': {'type': 'str', }, 'fw_pc_acos_harmony_topic': {'type': 'str', }, 'fw_pc_acos_harmony_topic_dequeue_err': {'type': 'str', }, 'fw_deny_pc_acos_harmony_topic': {'type': 'str', }, 'fw_deny_pc_acos_harmony_topic_dequeue_err': {'type': 'str', }, 'fw_rst_pc_acos_harmony_topic': {'type': 'str', }, 'fw_rst_pc_acos_harmony_topic_dequeue_err': {'type': 'str', }, 'cgn_summary_error_acos_harmony_topic': {'type': 'str', }, 'cgn_summary_error_acos_harmony_topic_dequeue_err': {'type': 'str', }, 'rule_set_application_metrics_topic': {'type': 'str', }, 'rule_set_application_metrics_topic_dequeue_err': {'type': 'str', }, 'slb_ssl_stats_metrics_topic': {'type': 'str', }, 'slb_ssl_stats_metrics_topic_dequeue_err': {'type': 'str', }, 'slb_client_ssl_counters_metrics_topic': {'type': 'str', }, 'slb_client_ssl_counters_metrics_topic_dequeue_err': {'type': 'str', }, 'slb_server_ssl_counters_metrics_topic': {'type': 'str', }, 'slb_server_ssl_counters_metrics_topic_dequeue_err': {'type': 'str', }, 'pc_throttle_drop': {'type': 'str', }, 'metrics_dropped_pt_missing': {'type': 'str', }, 'ssli_pc_acos_harmony_topic': {'type': 'str', }, 'ssli_pc_acos_harmony_topic_dequeue_err': {'type': 'str', }, 'ssli_pe_acos_harmony_topic': {'type': 'str', }, 'ssli_pe_acos_harmony_topic_dequeue_err': {'type': 'str', }, 'analytics_bus_restart': {'type': 'str', }, 'waf_learn_pr_topic': {'type': 'str', }, 'waf_learn_pr_topic_dequeue_err': {'type': 'str', }, 'waf_events_topic': {'type': 'str', }, 'waf_events_topic_dequeue_err': {'type': 'str', }, 'visibility_topn_harmony_topic': {'type': 'str', }, 'visibility_topn_harmony_topic_dequeue_err': {'type': 'str', }, 'hc_logs_sent_to_master': {'type': 'str', }, 'hc_logs_received_from_blade': {'type': 'str', }, 'hc_oper_sent_to_master': {'type': 'str', }, 'hc_oper_received_from_blade': {'type': 'str', }, 'hc_counters_sent_to_master': {'type': 'str', }, 'hc_counters_received_from_blade': {'type': 'str', }, 'hc_counters_dropped_from_blade': {'type': 'str', }, 'pe_acos_harmony_topic': {'type': 'str', }, 'pe_acos_harmony_topic_enqueue_err': {'type': 'str', }, 'pe_acos_harmony_topic_dequeue_err': {'type': 'str', }, 'vpn_ipsec_sa_metrics_topic': {'type': 'str', }, 'vpn_ipsec_sa_metrics_topic_dequeue_err': {'type': 'str', }, 'vpn_ike_gateway_metrics_topic': {'type': 'str', }, 'vpn_ike_gateway_metrics_topic_dequeue_err': {'type': 'str', }, 'vpn_stats_metrics_topic': {'type': 'str', }, 'vpn_stats_metrics_topic_dequeue_err': {'type': 'str', }, 'cgn_port_usage_hstgrm_acos_harmony_topic': {'type': 'str', }, 'cgn_port_usage_hstgrm_acos_harmony_topic_dequeue_err': {'type': 'str', }, 'avro_system_env_topic': {'type': 'str', }, 'avro_system_env_dequeue_err': {'type': 'str', }, 'cert_pinning_list_topic': {'type': 'str', }, 'cert_pinning_list_topic_dequeue_err': {'type': 'str', }}
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/event-notification/kafka/server"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/event-notification/kafka/server"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["server"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["server"].get(k) != v:
            change_results["changed"] = True
            config_changes["server"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(
        **call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(
            **call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("server", module.params, AVAILABLE_PROPERTIES)
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
    result = dict(
        changed=False,
        messages="",
        modified_values={},
        axapi_calls=[],
        ansible_facts={},
        acos_info={}
    )

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

    module.client = client_factory(ansible_host, ansible_port,
                                   protocol, ansible_username,
                                   ansible_password)

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
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
             result["axapi_calls"].append(
                api_client.switch_device_context(module.client, a10_device_context_id))

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
                result["acos_info"] = info["server"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["server-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module),
                                                      params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["server"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module),
                                                       params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["server"]["stats"] if info != "NotFound" else info
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
