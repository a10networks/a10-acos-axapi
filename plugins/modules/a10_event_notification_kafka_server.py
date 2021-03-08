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
                - "'all'= all; 'pr-acos-harmony-topic'= PR topic counter from acos to harmony;
          'avro-device-status-topic'= AVRO device status from acos to harmony; 'avro-
          partition-metrics-topic'= AVRO partition metrics from acos to harmony; 'avro-
          generic-sent'= Telemetry exported via avro; 'pr-acos-harmony-topic-enqueue-
          err'= PR topic to harmony enqueue error; 'pr-acos-harmony-topic-dequeue-err'=
          PR topic to harmony  dequeue error; 'avro-generic-failed-encoding'= Telemetry
          exported via avro failed encoding; 'avro-generic-failed-sending'= Telemetry
          exported via avro failed sending; 'avro-device-status-topic-enqueue-err'= AVRO
          device status enqueue error; 'avro-device-status-topic-dequeue-err'= AVRO
          device status dequeue error; 'avro-partition-metrics-topic-enqueue-err'= Part
          metrics dropped,enq error on acos queues; 'avro-partition-metrics-topic-
          dequeue-err'= Part metrics dropped,enq error analytics queues; 'kafka-unknown-
          topic-dequeue-err'= Unknown type dropped,enq error analytics queues; 'kafka-
          broker-down'= Telemetry drop because kafka broker is down; 'kafka-queue-full-
          err'= Telemetry drop because kafka Queue is full; 'pr-throttle-drop'= L7 PR
          dropped,log throttling; 'pr-not-allowed-drop'= PR drop because not allowed to
          log; 'pr-be-ttfb-anomaly'= PR back-end ttfb is negative; 'pr-be-ttlb-anomaly'=
          PR back-end ttlb is negative; 'pr-in-latency-threshold-exceed'= PR in latency
          threshold exceeded; 'pr-out-latency-threshold-exceed'= PR out latency threshold
          exceeded; 'pr-out-latency-anomaly'= PR out latency negative; 'pr-in-latency-
          anomaly'= PR in latency negative; 'kafka-topic-error'= Telemetry dropped
          because kafka topic not created; 'pc-encoding-failed'= Telemetry exported via
          avro failed encoding; 'pc-acos-harmony-topic'= PC topic counter from acos to
          harmony; 'pc-acos-harmony-topic-dequeue-err'= PC topic to harmony  dequeue
          error; 'cgn-pc-acos-harmony-topic'= CGN PC topic counter from acos to harmony;
          'cgn-pc-acos-harmony-topic-dequeue-err'= CGN PC topic to harmony dequeue error;
          'cgn-pe-acos-harmony-topic'= CGN PE topic counter from acos to harmony; 'cgn-
          pe-acos-harmony-topic-dequeue-err'= CGN PE topic to harmony dequeue error; 'fw-
          pc-acos-harmony-topic'= FW PC topic counter from acos to harmony; 'fw-pc-acos-
          harmony-topic-dequeue-err'= FW PC topic to harmony dequeue error; 'fw-deny-pc-
          acos-harmony-topic'= FW DENY PC topic counter from acos to harmony; 'fw-deny-
          pc-acos-harmony-topic-dequeue-err'= FW DENY PC logs dropped,enq error analytics
          queues; 'fw-rst-pc-acos-harmony-topic'= FW RST PC topic counter from acos to
          harmony; 'fw-rst-pc-acos-harmony-topic-dequeue-err'= FW RST PC topic to harmony
          dequeue error; 'cgn-summary-error-acos-harmony-topic'= CGN Summary PE topic
          counter from acos to harmony; 'cgn-summary-error-acos-harmony-topic-dequeue-
          err'= CGN Summary PE topic to harmony dequeue error; 'rule-set-application-
          metrics-topic'= AppFW metrics from acos to harmony; 'rule-set-application-
          metrics-topic-dequeue-err'= AppFW metrics dequeue error; 'slb-ssl-stats-
          metrics-topic'= SSL stats metrics from acos to harmony; 'slb-ssl-stats-metrics-
          topic-dequeue-err'= SSL stats metrics dequeue error; 'slb-client-ssl-counters-
          metrics-topic'= Client SSL counters metrics from acos to harmony; 'slb-client-
          ssl-counters-metrics-topic-dequeue-err'= Cilent SSL metrics dropped,enq error
          analytics qs; 'slb-server-ssl-counters-metrics-topic'= Server SSL counters
          metrics from acos to harmony; 'slb-server-ssl-counters-metrics-topic-dequeue-
          err'= Server SSL metrics dropped,enq error analytics qs; 'pc-throttle-drop'= PC
          drop due to throttling; 'metrics-dropped-pt-missing'= Partition-Tenant mapping
          not saved on HC; 'ssli-pc-acos-harmony-topic'= SSLi PC topic counter from acos
          to harmony; 'ssli-pc-acos-harmony-topic-dequeue-err'= SSLi PC topic to harmony
          dequeue error; 'ssli-pe-acos-harmony-topic'= SSLi PE topic counter from acos to
          harmony; 'ssli-pe-acos-harmony-topic-dequeue-err'= SSLi PE topic to harmony
          dequeue error; 'analytics-bus-restart'= Analytics bus restart count;"
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
                - "PR topic counter from acos to harmony"
                type: str
            avro_device_status_topic:
                description:
                - "AVRO device status from acos to harmony"
                type: str
            avro_partition_metrics_topic:
                description:
                - "AVRO partition metrics from acos to harmony"
                type: str
            avro_generic_sent:
                description:
                - "Telemetry exported via avro"
                type: str
            pr_acos_harmony_topic_enqueue_err:
                description:
                - "PR topic to harmony enqueue error"
                type: str
            pr_acos_harmony_topic_dequeue_err:
                description:
                - "PR topic to harmony  dequeue error"
                type: str
            avro_generic_failed_encoding:
                description:
                - "Telemetry exported via avro failed encoding"
                type: str
            avro_generic_failed_sending:
                description:
                - "Telemetry exported via avro failed sending"
                type: str
            avro_device_status_topic_enqueue_err:
                description:
                - "AVRO device status enqueue error"
                type: str
            avro_device_status_topic_dequeue_err:
                description:
                - "AVRO device status dequeue error"
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
                - "Telemetry drop because kafka broker is down"
                type: str
            kafka_queue_full_err:
                description:
                - "Telemetry drop because kafka Queue is full"
                type: str
            pr_throttle_drop:
                description:
                - "L7 PR dropped,log throttling"
                type: str
            pr_not_allowed_drop:
                description:
                - "PR drop because not allowed to log"
                type: str
            pr_be_ttfb_anomaly:
                description:
                - "PR back-end ttfb is negative"
                type: str
            pr_be_ttlb_anomaly:
                description:
                - "PR back-end ttlb is negative"
                type: str
            pr_in_latency_threshold_exceed:
                description:
                - "PR in latency threshold exceeded"
                type: str
            pr_out_latency_threshold_exceed:
                description:
                - "PR out latency threshold exceeded"
                type: str
            pr_out_latency_anomaly:
                description:
                - "PR out latency negative"
                type: str
            pr_in_latency_anomaly:
                description:
                - "PR in latency negative"
                type: str
            kafka_topic_error:
                description:
                - "Telemetry dropped because kafka topic not created"
                type: str
            pc_encoding_failed:
                description:
                - "Telemetry exported via avro failed encoding"
                type: str
            pc_acos_harmony_topic:
                description:
                - "PC topic counter from acos to harmony"
                type: str
            pc_acos_harmony_topic_dequeue_err:
                description:
                - "PC topic to harmony  dequeue error"
                type: str
            cgn_pc_acos_harmony_topic:
                description:
                - "CGN PC topic counter from acos to harmony"
                type: str
            cgn_pc_acos_harmony_topic_dequeue_err:
                description:
                - "CGN PC topic to harmony dequeue error"
                type: str
            cgn_pe_acos_harmony_topic:
                description:
                - "CGN PE topic counter from acos to harmony"
                type: str
            cgn_pe_acos_harmony_topic_dequeue_err:
                description:
                - "CGN PE topic to harmony dequeue error"
                type: str
            fw_pc_acos_harmony_topic:
                description:
                - "FW PC topic counter from acos to harmony"
                type: str
            fw_pc_acos_harmony_topic_dequeue_err:
                description:
                - "FW PC topic to harmony dequeue error"
                type: str
            fw_deny_pc_acos_harmony_topic:
                description:
                - "FW DENY PC topic counter from acos to harmony"
                type: str
            fw_deny_pc_acos_harmony_topic_dequeue_err:
                description:
                - "FW DENY PC logs dropped,enq error analytics queues"
                type: str
            fw_rst_pc_acos_harmony_topic:
                description:
                - "FW RST PC topic counter from acos to harmony"
                type: str
            fw_rst_pc_acos_harmony_topic_dequeue_err:
                description:
                - "FW RST PC topic to harmony dequeue error"
                type: str
            cgn_summary_error_acos_harmony_topic:
                description:
                - "CGN Summary PE topic counter from acos to harmony"
                type: str
            cgn_summary_error_acos_harmony_topic_dequeue_err:
                description:
                - "CGN Summary PE topic to harmony dequeue error"
                type: str
            rule_set_application_metrics_topic:
                description:
                - "AppFW metrics from acos to harmony"
                type: str
            rule_set_application_metrics_topic_dequeue_err:
                description:
                - "AppFW metrics dequeue error"
                type: str
            slb_ssl_stats_metrics_topic:
                description:
                - "SSL stats metrics from acos to harmony"
                type: str
            slb_ssl_stats_metrics_topic_dequeue_err:
                description:
                - "SSL stats metrics dequeue error"
                type: str
            slb_client_ssl_counters_metrics_topic:
                description:
                - "Client SSL counters metrics from acos to harmony"
                type: str
            slb_client_ssl_counters_metrics_topic_dequeue_err:
                description:
                - "Cilent SSL metrics dropped,enq error analytics qs"
                type: str
            slb_server_ssl_counters_metrics_topic:
                description:
                - "Server SSL counters metrics from acos to harmony"
                type: str
            slb_server_ssl_counters_metrics_topic_dequeue_err:
                description:
                - "Server SSL metrics dropped,enq error analytics qs"
                type: str
            pc_throttle_drop:
                description:
                - "PC drop due to throttling"
                type: str
            metrics_dropped_pt_missing:
                description:
                - "Partition-Tenant mapping not saved on HC"
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
    "host_ipv4",
    "oper",
    "port",
    "sampling_enable",
    "stats",
    "use_mgmt_port",
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
        'host_ipv4': {
            'type': 'str',
        },
        'use_mgmt_port': {
            'type': 'bool',
        },
        'port': {
            'type': 'int',
        },
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'pr-acos-harmony-topic', 'avro-device-status-topic',
                    'avro-partition-metrics-topic', 'avro-generic-sent',
                    'pr-acos-harmony-topic-enqueue-err',
                    'pr-acos-harmony-topic-dequeue-err',
                    'avro-generic-failed-encoding',
                    'avro-generic-failed-sending',
                    'avro-device-status-topic-enqueue-err',
                    'avro-device-status-topic-dequeue-err',
                    'avro-partition-metrics-topic-enqueue-err',
                    'avro-partition-metrics-topic-dequeue-err',
                    'kafka-unknown-topic-dequeue-err', 'kafka-broker-down',
                    'kafka-queue-full-err', 'pr-throttle-drop',
                    'pr-not-allowed-drop', 'pr-be-ttfb-anomaly',
                    'pr-be-ttlb-anomaly', 'pr-in-latency-threshold-exceed',
                    'pr-out-latency-threshold-exceed',
                    'pr-out-latency-anomaly', 'pr-in-latency-anomaly',
                    'kafka-topic-error', 'pc-encoding-failed',
                    'pc-acos-harmony-topic',
                    'pc-acos-harmony-topic-dequeue-err',
                    'cgn-pc-acos-harmony-topic',
                    'cgn-pc-acos-harmony-topic-dequeue-err',
                    'cgn-pe-acos-harmony-topic',
                    'cgn-pe-acos-harmony-topic-dequeue-err',
                    'fw-pc-acos-harmony-topic',
                    'fw-pc-acos-harmony-topic-dequeue-err',
                    'fw-deny-pc-acos-harmony-topic',
                    'fw-deny-pc-acos-harmony-topic-dequeue-err',
                    'fw-rst-pc-acos-harmony-topic',
                    'fw-rst-pc-acos-harmony-topic-dequeue-err',
                    'cgn-summary-error-acos-harmony-topic',
                    'cgn-summary-error-acos-harmony-topic-dequeue-err',
                    'rule-set-application-metrics-topic',
                    'rule-set-application-metrics-topic-dequeue-err',
                    'slb-ssl-stats-metrics-topic',
                    'slb-ssl-stats-metrics-topic-dequeue-err',
                    'slb-client-ssl-counters-metrics-topic',
                    'slb-client-ssl-counters-metrics-topic-dequeue-err',
                    'slb-server-ssl-counters-metrics-topic',
                    'slb-server-ssl-counters-metrics-topic-dequeue-err',
                    'pc-throttle-drop', 'metrics-dropped-pt-missing',
                    'ssli-pc-acos-harmony-topic',
                    'ssli-pc-acos-harmony-topic-dequeue-err',
                    'ssli-pe-acos-harmony-topic',
                    'ssli-pe-acos-harmony-topic-dequeue-err',
                    'analytics-bus-restart'
                ]
            }
        },
        'oper': {
            'type': 'dict',
            'kafka_broker_state': {
                'type': 'str',
                'choices': ['Up', 'Down']
            }
        },
        'stats': {
            'type': 'dict',
            'pr_acos_harmony_topic': {
                'type': 'str',
            },
            'avro_device_status_topic': {
                'type': 'str',
            },
            'avro_partition_metrics_topic': {
                'type': 'str',
            },
            'avro_generic_sent': {
                'type': 'str',
            },
            'pr_acos_harmony_topic_enqueue_err': {
                'type': 'str',
            },
            'pr_acos_harmony_topic_dequeue_err': {
                'type': 'str',
            },
            'avro_generic_failed_encoding': {
                'type': 'str',
            },
            'avro_generic_failed_sending': {
                'type': 'str',
            },
            'avro_device_status_topic_enqueue_err': {
                'type': 'str',
            },
            'avro_device_status_topic_dequeue_err': {
                'type': 'str',
            },
            'avro_partition_metrics_topic_enqueue_err': {
                'type': 'str',
            },
            'avro_partition_metrics_topic_dequeue_err': {
                'type': 'str',
            },
            'kafka_unknown_topic_dequeue_err': {
                'type': 'str',
            },
            'kafka_broker_down': {
                'type': 'str',
            },
            'kafka_queue_full_err': {
                'type': 'str',
            },
            'pr_throttle_drop': {
                'type': 'str',
            },
            'pr_not_allowed_drop': {
                'type': 'str',
            },
            'pr_be_ttfb_anomaly': {
                'type': 'str',
            },
            'pr_be_ttlb_anomaly': {
                'type': 'str',
            },
            'pr_in_latency_threshold_exceed': {
                'type': 'str',
            },
            'pr_out_latency_threshold_exceed': {
                'type': 'str',
            },
            'pr_out_latency_anomaly': {
                'type': 'str',
            },
            'pr_in_latency_anomaly': {
                'type': 'str',
            },
            'kafka_topic_error': {
                'type': 'str',
            },
            'pc_encoding_failed': {
                'type': 'str',
            },
            'pc_acos_harmony_topic': {
                'type': 'str',
            },
            'pc_acos_harmony_topic_dequeue_err': {
                'type': 'str',
            },
            'cgn_pc_acos_harmony_topic': {
                'type': 'str',
            },
            'cgn_pc_acos_harmony_topic_dequeue_err': {
                'type': 'str',
            },
            'cgn_pe_acos_harmony_topic': {
                'type': 'str',
            },
            'cgn_pe_acos_harmony_topic_dequeue_err': {
                'type': 'str',
            },
            'fw_pc_acos_harmony_topic': {
                'type': 'str',
            },
            'fw_pc_acos_harmony_topic_dequeue_err': {
                'type': 'str',
            },
            'fw_deny_pc_acos_harmony_topic': {
                'type': 'str',
            },
            'fw_deny_pc_acos_harmony_topic_dequeue_err': {
                'type': 'str',
            },
            'fw_rst_pc_acos_harmony_topic': {
                'type': 'str',
            },
            'fw_rst_pc_acos_harmony_topic_dequeue_err': {
                'type': 'str',
            },
            'cgn_summary_error_acos_harmony_topic': {
                'type': 'str',
            },
            'cgn_summary_error_acos_harmony_topic_dequeue_err': {
                'type': 'str',
            },
            'rule_set_application_metrics_topic': {
                'type': 'str',
            },
            'rule_set_application_metrics_topic_dequeue_err': {
                'type': 'str',
            },
            'slb_ssl_stats_metrics_topic': {
                'type': 'str',
            },
            'slb_ssl_stats_metrics_topic_dequeue_err': {
                'type': 'str',
            },
            'slb_client_ssl_counters_metrics_topic': {
                'type': 'str',
            },
            'slb_client_ssl_counters_metrics_topic_dequeue_err': {
                'type': 'str',
            },
            'slb_server_ssl_counters_metrics_topic': {
                'type': 'str',
            },
            'slb_server_ssl_counters_metrics_topic_dequeue_err': {
                'type': 'str',
            },
            'pc_throttle_drop': {
                'type': 'str',
            },
            'metrics_dropped_pt_missing': {
                'type': 'str',
            },
            'ssli_pc_acos_harmony_topic': {
                'type': 'str',
            },
            'ssli_pc_acos_harmony_topic_dequeue_err': {
                'type': 'str',
            },
            'ssli_pe_acos_harmony_topic': {
                'type': 'str',
            },
            'ssli_pe_acos_harmony_topic_dequeue_err': {
                'type': 'str',
            },
            'analytics_bus_restart': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/event-notification/kafka/server"

    f_dict = {}

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
    url_base = "/axapi/v3/event-notification/kafka/server"

    f_dict = {}

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
        for k, v in payload["server"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["server"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["server"][k] = v
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
    payload = build_json("server", module)
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
