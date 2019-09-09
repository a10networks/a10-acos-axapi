#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_visibility
description:
    - Display Network statistics
short_description: Configures A10 visibility
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
    partition:
        description:
        - Destination/target partition for object/command
    flow_collector:
        description:
        - "Field flow_collector"
        required: False
        suboptions:
            netflow:
                description:
                - "Field netflow"
            sflow:
                description:
                - "Field sflow"
    resource_usage:
        description:
        - "Field resource_usage"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    mon_entity_telemetry_data:
        description:
        - "Field mon_entity_telemetry_data"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    uuid:
        description:
        - "uuid of the object"
        required: False
    reporting:
        description:
        - "Field reporting"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
            template:
                description:
                - "Field template"
            telemetry_export_interval:
                description:
                - "Field telemetry_export_interval"
    topk:
        description:
        - "Field topk"
        required: False
        suboptions:
            sources:
                description:
                - "Field sources"
    initial_learning_interval:
        description:
        - "Initial learning interval (in hours) before processing"
        required: False
    monitored_entity:
        description:
        - "Field monitored_entity"
        required: False
        suboptions:
            detail:
                description:
                - "Field detail"
            sessions:
                description:
                - "Field sessions"
            topk:
                description:
                - "Field topk"
            uuid:
                description:
                - "uuid of the object"
            secondary:
                description:
                - "Field secondary"
    debug_files:
        description:
        - "Field debug_files"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'mon-entity-limit-exceed'= Total monitor entity limit exceed failures; 'ha-entity-create-sent'= Total montior entity HA create messages sent; 'ha-entity-delete-sent'= Total montior entity HA delete messages sent; 'ha-entity-anomaly-on-sent'= Total anomaly on HA messages sent; 'ha-entity-anomaly-off-sent'= Total anomaly off HA messages sent; 'ha-entity-periodic-sync-sent'= Total monitor entity periodic sync messages sent; 'out-of-memory-alloc-failures'= Out of memory allocation failures; 'lw-mon-entity-created'= Total Light-weight entities created; 'lw-mon-entity-deleted'= Total Light-weight entities deleted; 'lw-mon-entity-limit-exceed'= Light weight limit exceeded errors; 'lw-out-of-memory-alloc-failures'= Light Weight Out-of-memory allocation failures; 'mon-entity-rrd-file-timestamp-err'= Total monitor entity rrd file timestamp errors; 'mon-entity-rrd-update-err'= Total monitor entity rrd update error; 'mon-entity-rrd-last-update-fetch-failed-err'= Total monitor entity rrd last update fetch failed error; 'mon-entity-rrd-tune-err'= Total monitor entity rrd tune error; 'mon-entity-rrd-out-of-memory-err'= Total monitor entity rrd load failed, out of memory error; 'mon-entity-rrd-file-create-err'= Total monitor entity rrd file create error; "
    source_entity_topk:
        description:
        - "Enable topk for sources"
        required: False
    file:
        description:
        - "Field file"
        required: False
        suboptions:
            metrics:
                description:
                - "Field metrics"
    granularity:
        description:
        - "Granularity for rate based calculations in seconds (default 5)"
        required: False
    anomaly_detection:
        description:
        - "Field anomaly_detection"
        required: False
        suboptions:
            sensitivity:
                description:
                - "'high'= Highly sensitive anomaly detection. Can lead to false positives; 'low'= Low sensitivity anomaly detection. Can cause delay in detection and might not detect certain attacks. (default); "
            logging:
                description:
                - "'per-entity'= Enable per entity logging; 'per-metric'= Enable per metric logging with threshold details; 'disable'= Disable anomaly notifications (Default); "
            uuid:
                description:
                - "uuid of the object"
            feature_status:
                description:
                - "'enable'= Enable anomaly-detection; 'disable'= Disable anomaly detection (default); "
    monitor:
        description:
        - "Field monitor"
        required: False
        suboptions:
            primary_monitor:
                description:
                - "'traffic'= Mointor traffic; "
            mon_entity_topk:
                description:
                - "Enable topk for primary entities"
            monitor_key:
                description:
                - "'source'= Monitor traffic from all sources; 'dest'= Monitor traffic to any destination; 'service'= Monitor traffic to any service; 'source-nat-ip'= Monitor traffic to all source nat IPs; "
            debug_list:
                description:
                - "Field debug_list"
            uuid:
                description:
                - "uuid of the object"
            sflow:
                description:
                - "Field sflow"
            delete_debug_file:
                description:
                - "Field delete_debug_file"
            index_sessions:
                description:
                - "Start indexing associated sessions"
            source_entity_topk:
                description:
                - "Enable topk for sources to primary-entities"
            template:
                description:
                - "Field template"
            replay_debug_file:
                description:
                - "Field replay_debug_file"
            netflow:
                description:
                - "Field netflow"
            index_sessions_type:
                description:
                - "'per-cpu'= Use per cpu list; "
            secondary_monitor:
                description:
                - "Field secondary_monitor"
            agent_list:
                description:
                - "Field agent_list"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["anomaly_detection","debug_files","file","flow_collector","granularity","initial_learning_interval","mon_entity_telemetry_data","monitor","monitored_entity","reporting","resource_usage","sampling_enable","source_entity_topk","topk","uuid",]

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
        partition=dict(type='str', required=False),
        get_type=dict(type='str', choices=["single", "list"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        flow_collector=dict(type='dict',netflow=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','pkts-rcvd','v9-templates-created','v9-templates-deleted','v10-templates-created','v10-templates-deleted','template-drop-exceeded','template-drop-out-of-memory','frag-dropped','agent-not-found','version-not-supported','unknown-dir'])),uuid=dict(type='str',),template=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','templates-added-to-delq','templates-removed-from-delq'])),uuid=dict(type='str',),detail=dict(type='dict',uuid=dict(type='str',)))),sflow=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','pkts-received','frag-dropped','agent-not-found','version-not-supported','unknown-dir'])),uuid=dict(type='str',))),
        resource_usage=dict(type='dict',uuid=dict(type='str',)),
        mon_entity_telemetry_data=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','in_pkts','out_pkts','in_bytes','out_bytes','errors','in_small_pkt','in_frag','out_small_pkt','out_frag','new-conn','concurrent-conn','in_bytes_per_out_bytes','drop_pkts_per_pkts','tcp_in_syn','tcp_out_syn','tcp_in_fin','tcp_out_fin','tcp_in_payload','tcp_out_payload','tcp_in_rexmit','tcp_out_rexmit','tcp_in_rst','tcp_out_rst','tcp_in_empty_ack','tcp_out_empty_ack','tcp_in_zero_wnd','tcp_out_zero_wnd','tcp_fwd_syn_per_fin'])),uuid=dict(type='str',)),
        uuid=dict(type='str',),
        reporting=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','log-transmit-failure','buffer-alloc-failure','notif-jobs-in-queue','enqueue-fail','enqueue-pass','dequeued'])),uuid=dict(type='str',),template=dict(type='dict',notification=dict(type='dict',debug=dict(type='dict',uuid=dict(type='str',)),template_name_list=dict(type='list',protocol=dict(type='str',choices=['http','https']),name=dict(type='str',required=True,),use_mgmt_port=dict(type='bool',),https_port=dict(type='int',),debug_mode=dict(type='bool',),relative_uri=dict(type='str',),authentication=dict(type='dict',uuid=dict(type='str',),encrypted=dict(type='str',),relative_logoff_uri=dict(type='str',),api_key_encrypted=dict(type='str',),api_key=dict(type='bool',),auth_password_string=dict(type='str',),auth_password=dict(type='bool',),api_key_string=dict(type='str',),relative_login_uri=dict(type='str',),auth_username=dict(type='str',)),host_name=dict(type='str',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','sent_successful','send_fail','response_fail'])),http_port=dict(type='int',),ipv6_address=dict(type='str',),test_connectivity=dict(type='bool',),ipv4_address=dict(type='str',),action=dict(type='str',choices=['enable','disable']),uuid=dict(type='str',)))),telemetry_export_interval=dict(type='dict',uuid=dict(type='str',),value=dict(type='int',))),
        topk=dict(type='dict',sources=dict(type='dict',uuid=dict(type='str',))),
        initial_learning_interval=dict(type='int',),
        monitored_entity=dict(type='dict',detail=dict(type='dict',debug=dict(type='dict',uuid=dict(type='str',)),uuid=dict(type='str',)),sessions=dict(type='dict',uuid=dict(type='str',)),topk=dict(type='dict',sources=dict(type='dict',uuid=dict(type='str',)),uuid=dict(type='str',)),uuid=dict(type='str',),secondary=dict(type='dict',topk=dict(type='dict',sources=dict(type='dict',uuid=dict(type='str',)),uuid=dict(type='str',)))),
        debug_files=dict(type='dict',uuid=dict(type='str',)),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','mon-entity-limit-exceed','ha-entity-create-sent','ha-entity-delete-sent','ha-entity-anomaly-on-sent','ha-entity-anomaly-off-sent','ha-entity-periodic-sync-sent','out-of-memory-alloc-failures','lw-mon-entity-created','lw-mon-entity-deleted','lw-mon-entity-limit-exceed','lw-out-of-memory-alloc-failures','mon-entity-rrd-file-timestamp-err','mon-entity-rrd-update-err','mon-entity-rrd-last-update-fetch-failed-err','mon-entity-rrd-tune-err','mon-entity-rrd-out-of-memory-err','mon-entity-rrd-file-create-err'])),
        source_entity_topk=dict(type='bool',),
        file=dict(type='dict',metrics=dict(type='dict',action=dict(type='str',choices=['enable','disable']),uuid=dict(type='str',))),
        granularity=dict(type='int',),
        anomaly_detection=dict(type='dict',sensitivity=dict(type='str',choices=['high','low']),logging=dict(type='str',choices=['per-entity','per-metric','disable']),uuid=dict(type='str',),feature_status=dict(type='str',choices=['enable','disable'])),
        monitor=dict(type='dict',primary_monitor=dict(type='str',choices=['traffic']),mon_entity_topk=dict(type='bool',),monitor_key=dict(type='str',choices=['source','dest','service','source-nat-ip']),debug_list=dict(type='list',debug_port=dict(type='int',required=True,),debug_ip_addr=dict(type='str',required=True,),debug_protocol=dict(type='str',required=True,choices=['TCP','UDP','ICMP']),uuid=dict(type='str',)),uuid=dict(type='str',),sflow=dict(type='dict',uuid=dict(type='str',),listening_port=dict(type='int',)),delete_debug_file=dict(type='dict',debug_port=dict(type='int',),debug_ip_addr=dict(type='str',),debug_protocol=dict(type='str',choices=['TCP','UDP','ICMP'])),index_sessions=dict(type='bool',),source_entity_topk=dict(type='bool',),template=dict(type='dict',notification=dict(type='list',notif_template_name=dict(type='str',))),replay_debug_file=dict(type='dict',debug_port=dict(type='int',),debug_ip_addr=dict(type='str',),debug_protocol=dict(type='str',choices=['TCP','UDP','ICMP'])),netflow=dict(type='dict',template_active_timeout=dict(type='int',),uuid=dict(type='str',),listening_port=dict(type='int',)),index_sessions_type=dict(type='str',choices=['per-cpu']),secondary_monitor=dict(type='dict',mon_entity_topk=dict(type='bool',),debug_list=dict(type='list',debug_port=dict(type='int',required=True,),debug_ip_addr=dict(type='str',required=True,),debug_protocol=dict(type='str',required=True,choices=['TCP','UDP','ICMP']),uuid=dict(type='str',)),uuid=dict(type='str',),secondary_monitoring_key=dict(type='str',choices=['service']),delete_debug_file=dict(type='dict',debug_port=dict(type='int',),debug_ip_addr=dict(type='str',),debug_protocol=dict(type='str',choices=['TCP','UDP','ICMP'])),source_entity_topk=dict(type='bool',),replay_debug_file=dict(type='dict',debug_port=dict(type='int',),debug_ip_addr=dict(type='str',),debug_protocol=dict(type='str',choices=['TCP','UDP','ICMP']))),agent_list=dict(type='list',uuid=dict(type='str',),agent_v4_addr=dict(type='str',),agent_v6_addr=dict(type='str',),user_tag=dict(type='str',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','sflow-packets-received','sflow-samples-received','sflow-samples-bad-len','sflow-samples-non-std','sflow-samples-skipped','sflow-sample-record-bad-len','sflow-samples-sent-for-detection','sflow-sample-record-invalid-layer2','sflow-sample-ipv6-hdr-parse-fail','sflow-disabled','netflow-disabled','netflow-v5-packets-received','netflow-v5-samples-received','netflow-v5-samples-sent-for-detection','netflow-v5-sample-records-bad-len','netflow-v5-max-records-exceed','netflow-v9-packets-received','netflow-v9-samples-received','netflow-v9-samples-sent-for-detection','netflow-v9-sample-records-bad-len','netflow-v9-max-records-exceed','netflow-v10-packets-received','netflow-v10-samples-received','netflow-v10-samples-sent-for-detection','netflow-v10-sample-records-bad-len','netflow-v10-max-records-exceed','netflow-tcp-sample-received','netflow-udp-sample-received','netflow-icmp-sample-received','netflow-other-sample-received','netflow-record-copy-oom-error','netflow-record-rse-invalid','netflow-sample-flow-dur-error'])),agent_name=dict(type='str',required=True,)))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility"

    f_dict = {}

    return url_base.format(**f_dict)

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
        if v:
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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["visibility"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["visibility"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["visibility"][k] = v
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
    except a10_ex.Exists:
        result["changed"] = False
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
    payload = build_json("visibility", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("visibility", module)
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
    partition = module.params["partition"]

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
    if partition:
        module.client.activate_partition(partition)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
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