#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_event_notification_kafka_server
description:
    - Set remote kafka server ip address
short_description: Configures A10 event.notification.kafka.server
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
        - present
        - absent
        required: True
    a10_host:
        description:
        - Host for AXAPI authentication
        required: True
    a10_username:
        description:
        - Username for AXAPI authentication
        required: True
    a10_password:
        description:
        - Password for AXAPI authentication
        required: True
    a10_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_protocol:
        description:
        - Protocol for AXAPI authentication
        required: True
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            kafka_broker_state:
                description:
                - "Field kafka_broker_state"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'pr-acos-harmony-topic'= PR topic counter from acos to harmony; 'avro-device-status-topic'= AVRO device status from acos to harmony; 'avro-partition-metrics-topic'= AVRO partition metrics from acos to harmony; 'avro-generic-sent'= Telemetry exported via avro; 'pr-acos-harmony-topic-enqueue-err'= PR topic to harmony enqueue error; 'pr-acos-harmony-topic-dequeue-err'= PR topic to harmony  dequeue error; 'avro-generic-failed-encoding'= Telemetry exported via avro failed encoding; 'avro-generic-failed-sending'= Telemetry exported via avro failed sending; 'avro-device-status-topic-enqueue-err'= AVRO device status enqueue error; 'avro-device-status-topic-dequeue-err'= AVRO device status dequeue error; 'avro-partition-metrics-topic-enqueue-err'= AVRO partition metrics enqueue error; 'avro-partition-metrics-topic-dequeue-err'= AVRO partition metrics dequeue error; 'kafka-unknown-topic-dequeue-err'= Kafka Unknown topic error; 'kafka-broker-down'= Telemetry drop because kafka broker is down; 'kafka-queue-full-err'= Telemetry drop because kafka Queue is full; 'pr-throttle-drop'= PR drop due to throttling; 'pr-not-allowed-drop'= PR drop because not allowed to log; 'pr-be-ttfb-anomaly'= PR back-end ttfb is negative; 'pr-be-ttlb-anomaly'= PR back-end ttlb is negative; 'pr-in-latency-threshold-exceed'= PR in latency threshold exceeded; 'pr-out-latency-threshold-exceed'= PR out latency threshold exceeded; 'pr-out-latency-anomaly'= PR out latency negative; 'pr-in-latency-anomaly'= PR in latency negative; 'kafka-topic-error'= Telemetry dropped because kafka topic not created; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            pr_out_latency_anomaly:
                description:
                - "PR out latency negative"
            pr_in_latency_threshold_exceed:
                description:
                - "PR in latency threshold exceeded"
            avro_generic_failed_sending:
                description:
                - "Telemetry exported via avro failed sending"
            kafka_topic_error:
                description:
                - "Telemetry dropped because kafka topic not created"
            avro_device_status_topic_dequeue_err:
                description:
                - "AVRO device status dequeue error"
            pr_acos_harmony_topic:
                description:
                - "PR topic counter from acos to harmony"
            pr_out_latency_threshold_exceed:
                description:
                - "PR out latency threshold exceeded"
            pr_in_latency_anomaly:
                description:
                - "PR in latency negative"
            pr_acos_harmony_topic_enqueue_err:
                description:
                - "PR topic to harmony enqueue error"
            avro_partition_metrics_topic_enqueue_err:
                description:
                - "AVRO partition metrics enqueue error"
            avro_device_status_topic_enqueue_err:
                description:
                - "AVRO device status enqueue error"
            kafka_queue_full_err:
                description:
                - "Telemetry drop because kafka Queue is full"
            pr_throttle_drop:
                description:
                - "PR drop due to throttling"
            avro_partition_metrics_topic:
                description:
                - "AVRO partition metrics from acos to harmony"
            kafka_broker_down:
                description:
                - "Telemetry drop because kafka broker is down"
            pr_acos_harmony_topic_dequeue_err:
                description:
                - "PR topic to harmony  dequeue error"
            avro_generic_sent:
                description:
                - "Telemetry exported via avro"
            kafka_unknown_topic_dequeue_err:
                description:
                - "Kafka Unknown topic error"
            avro_device_status_topic:
                description:
                - "AVRO device status from acos to harmony"
            pr_be_ttfb_anomaly:
                description:
                - "PR back-end ttfb is negative"
            avro_partition_metrics_topic_dequeue_err:
                description:
                - "AVRO partition metrics dequeue error"
            pr_be_ttlb_anomaly:
                description:
                - "PR back-end ttlb is negative"
            pr_not_allowed_drop:
                description:
                - "PR drop because not allowed to log"
            avro_generic_failed_encoding:
                description:
                - "Telemetry exported via avro failed encoding"
    uuid:
        description:
        - "uuid of the object"
        required: False
    use_mgmt_port:
        description:
        - "Use management port for connections"
        required: False
    host_ipv4:
        description:
        - "Set kafka Broker ip address or hostname"
        required: False
    port:
        description:
        - "Set remote kafka port number (Remote kafka port number 1-32767, default is 9092)"
        required: False


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["host_ipv4","oper","port","sampling_enable","stats","use_mgmt_port","uuid",]

# our imports go at the top so we fail fast.
try:
    from a10_ansible import errors as a10_ex
    from a10_ansible.axapi_http import client_factory, session_factory
    from a10_ansible.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=["present", "absent", "noop"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict',kafka_broker_state=dict(type='str',choices=['Up','Down'])),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','pr-acos-harmony-topic','avro-device-status-topic','avro-partition-metrics-topic','avro-generic-sent','pr-acos-harmony-topic-enqueue-err','pr-acos-harmony-topic-dequeue-err','avro-generic-failed-encoding','avro-generic-failed-sending','avro-device-status-topic-enqueue-err','avro-device-status-topic-dequeue-err','avro-partition-metrics-topic-enqueue-err','avro-partition-metrics-topic-dequeue-err','kafka-unknown-topic-dequeue-err','kafka-broker-down','kafka-queue-full-err','pr-throttle-drop','pr-not-allowed-drop','pr-be-ttfb-anomaly','pr-be-ttlb-anomaly','pr-in-latency-threshold-exceed','pr-out-latency-threshold-exceed','pr-out-latency-anomaly','pr-in-latency-anomaly','kafka-topic-error'])),
        stats=dict(type='dict',pr_out_latency_anomaly=dict(type='str',),pr_in_latency_threshold_exceed=dict(type='str',),avro_generic_failed_sending=dict(type='str',),kafka_topic_error=dict(type='str',),avro_device_status_topic_dequeue_err=dict(type='str',),pr_acos_harmony_topic=dict(type='str',),pr_out_latency_threshold_exceed=dict(type='str',),pr_in_latency_anomaly=dict(type='str',),pr_acos_harmony_topic_enqueue_err=dict(type='str',),avro_partition_metrics_topic_enqueue_err=dict(type='str',),avro_device_status_topic_enqueue_err=dict(type='str',),kafka_queue_full_err=dict(type='str',),pr_throttle_drop=dict(type='str',),avro_partition_metrics_topic=dict(type='str',),kafka_broker_down=dict(type='str',),pr_acos_harmony_topic_dequeue_err=dict(type='str',),avro_generic_sent=dict(type='str',),kafka_unknown_topic_dequeue_err=dict(type='str',),avro_device_status_topic=dict(type='str',),pr_be_ttfb_anomaly=dict(type='str',),avro_partition_metrics_topic_dequeue_err=dict(type='str',),pr_be_ttlb_anomaly=dict(type='str',),pr_not_allowed_drop=dict(type='str',),avro_generic_failed_encoding=dict(type='str',)),
        uuid=dict(type='str',),
        use_mgmt_port=dict(type='bool',),
        host_ipv4=dict(type='str',),
        port=dict(type='int',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/event-notification/kafka/server"

    f_dict = {}

    return url_base.format(**f_dict)

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

def build_envelope(title, data):
    return {
        title: data
    }

def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")

def _build_dict_from_param(param):
    rv = {}

    for k,v in param.items():
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

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params and params.get(x) is not None])
    
    errors = []
    marg = []
    
    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc,msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc,msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc,msg = REQUIRED_VALID
    
    if not rc:
        errors.append(msg.format(", ".join(marg)))
    
    return rc,errors

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k,v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v 
        return module.client.get(oper_url(module),
                                 params=query_params)
    return module.client.get(oper_url(module))

def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k,v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module),
                                 params=query_params)
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

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
                    if result["changed"] != True:
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

    result = dict(
        changed=False,
        original_message="",
        message="",
        result={}
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]
    a10_partition = module.params["a10_partition"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    if a10_partition:
        module.client.activate_partition(a10_partition)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
    elif state == 'absent':
        result = absent(module, result, existing_config)
    elif state == 'noop':
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
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()