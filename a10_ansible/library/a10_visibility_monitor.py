#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_visibility_monitor
description:
    - Configure monitoring keys
short_description: Configures A10 visibility.monitor
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
    primary_monitor:
        description:
        - "'traffic'= Mointor traffic; "
        required: True
    mon_entity_topk:
        description:
        - "Enable topk for primary entities"
        required: False
    monitor_key:
        description:
        - "'source'= Monitor traffic from all sources; 'dest'= Monitor traffic to any destination; 'service'= Monitor traffic to any service; 'source-nat-ip'= Monitor traffic to all source nat IPs; "
        required: False
    debug_list:
        description:
        - "Field debug_list"
        required: False
        suboptions:
            debug_port:
                description:
                - "Specify port"
            debug_ip_addr:
                description:
                - "Specify source/dest ip addr"
            debug_protocol:
                description:
                - "'TCP'= TCP; 'UDP'= UDP; 'ICMP'= ICMP; "
            uuid:
                description:
                - "uuid of the object"
    uuid:
        description:
        - "uuid of the object"
        required: False
    sflow:
        description:
        - "Field sflow"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            listening_port:
                description:
                - "sFlow port to receive packets (sFlow port number(default 6343))"
    delete_debug_file:
        description:
        - "Field delete_debug_file"
        required: False
        suboptions:
            debug_port:
                description:
                - "Specify port"
            debug_ip_addr:
                description:
                - "Specify source/dest ip addr"
            debug_protocol:
                description:
                - "'TCP'= TCP; 'UDP'= UDP; 'ICMP'= ICMP; "
    index_sessions:
        description:
        - "Start indexing associated sessions"
        required: False
    source_entity_topk:
        description:
        - "Enable topk for sources to primary-entities"
        required: False
    template:
        description:
        - "Field template"
        required: False
        suboptions:
            notification:
                description:
                - "Field notification"
    replay_debug_file:
        description:
        - "Field replay_debug_file"
        required: False
        suboptions:
            debug_port:
                description:
                - "Specify port"
            debug_ip_addr:
                description:
                - "Specify source/dest ip addr"
            debug_protocol:
                description:
                - "'TCP'= TCP; 'UDP'= UDP; 'ICMP'= ICMP; "
    netflow:
        description:
        - "Field netflow"
        required: False
        suboptions:
            template_active_timeout:
                description:
                - "Configure active timeout of the netflow templates received in mins (Template active timeout(mins)(default 30mins))"
            uuid:
                description:
                - "uuid of the object"
            listening_port:
                description:
                - "Netflow port to receive packets (Netflow port number(default 9996))"
    index_sessions_type:
        description:
        - "'per-cpu'= Use per cpu list; "
        required: False
    secondary_monitor:
        description:
        - "Field secondary_monitor"
        required: False
        suboptions:
            mon_entity_topk:
                description:
                - "Enable topk for secondary entities"
            debug_list:
                description:
                - "Field debug_list"
            uuid:
                description:
                - "uuid of the object"
            secondary_monitoring_key:
                description:
                - "'service'= Monitor traffic to any service; "
            delete_debug_file:
                description:
                - "Field delete_debug_file"
            source_entity_topk:
                description:
                - "Enable topk for sources to secondary-entities"
            replay_debug_file:
                description:
                - "Field replay_debug_file"
    agent_list:
        description:
        - "Field agent_list"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            agent_v4_addr:
                description:
                - "Configure agent's IPv4 address"
            agent_v6_addr:
                description:
                - "Configure agent's IPv6 address"
            user_tag:
                description:
                - "Customized tag"
            sampling_enable:
                description:
                - "Field sampling_enable"
            agent_name:
                description:
                - "Specify name for the agent"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["agent_list","debug_list","delete_debug_file","index_sessions","index_sessions_type","mon_entity_topk","monitor_key","netflow","primary_monitor","replay_debug_file","secondary_monitor","sflow","source_entity_topk","template","uuid",]

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
        primary_monitor=dict(type='str',required=True,choices=['traffic']),
        mon_entity_topk=dict(type='bool',),
        monitor_key=dict(type='str',choices=['source','dest','service','source-nat-ip']),
        debug_list=dict(type='list',debug_port=dict(type='int',required=True,),debug_ip_addr=dict(type='str',required=True,),debug_protocol=dict(type='str',required=True,choices=['TCP','UDP','ICMP']),uuid=dict(type='str',)),
        uuid=dict(type='str',),
        sflow=dict(type='dict',uuid=dict(type='str',),listening_port=dict(type='int',)),
        delete_debug_file=dict(type='dict',debug_port=dict(type='int',),debug_ip_addr=dict(type='str',),debug_protocol=dict(type='str',choices=['TCP','UDP','ICMP'])),
        index_sessions=dict(type='bool',),
        source_entity_topk=dict(type='bool',),
        template=dict(type='dict',notification=dict(type='list',notif_template_name=dict(type='str',))),
        replay_debug_file=dict(type='dict',debug_port=dict(type='int',),debug_ip_addr=dict(type='str',),debug_protocol=dict(type='str',choices=['TCP','UDP','ICMP'])),
        netflow=dict(type='dict',template_active_timeout=dict(type='int',),uuid=dict(type='str',),listening_port=dict(type='int',)),
        index_sessions_type=dict(type='str',choices=['per-cpu']),
        secondary_monitor=dict(type='dict',mon_entity_topk=dict(type='bool',),debug_list=dict(type='list',debug_port=dict(type='int',required=True,),debug_ip_addr=dict(type='str',required=True,),debug_protocol=dict(type='str',required=True,choices=['TCP','UDP','ICMP']),uuid=dict(type='str',)),uuid=dict(type='str',),secondary_monitoring_key=dict(type='str',choices=['service']),delete_debug_file=dict(type='dict',debug_port=dict(type='int',),debug_ip_addr=dict(type='str',),debug_protocol=dict(type='str',choices=['TCP','UDP','ICMP'])),source_entity_topk=dict(type='bool',),replay_debug_file=dict(type='dict',debug_port=dict(type='int',),debug_ip_addr=dict(type='str',),debug_protocol=dict(type='str',choices=['TCP','UDP','ICMP']))),
        agent_list=dict(type='list',uuid=dict(type='str',),agent_v4_addr=dict(type='str',),agent_v6_addr=dict(type='str',),user_tag=dict(type='str',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','sflow-packets-received','sflow-samples-received','sflow-samples-bad-len','sflow-samples-non-std','sflow-samples-skipped','sflow-sample-record-bad-len','sflow-samples-sent-for-detection','sflow-sample-record-invalid-layer2','sflow-sample-ipv6-hdr-parse-fail','sflow-disabled','netflow-disabled','netflow-v5-packets-received','netflow-v5-samples-received','netflow-v5-samples-sent-for-detection','netflow-v5-sample-records-bad-len','netflow-v5-max-records-exceed','netflow-v9-packets-received','netflow-v9-samples-received','netflow-v9-samples-sent-for-detection','netflow-v9-sample-records-bad-len','netflow-v9-max-records-exceed','netflow-v10-packets-received','netflow-v10-samples-received','netflow-v10-samples-sent-for-detection','netflow-v10-sample-records-bad-len','netflow-v10-max-records-exceed','netflow-tcp-sample-received','netflow-udp-sample-received','netflow-icmp-sample-received','netflow-other-sample-received','netflow-record-copy-oom-error','netflow-record-rse-invalid','netflow-sample-flow-dur-error'])),agent_name=dict(type='str',required=True,))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/monitor"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/monitor"

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

def get_oper(module):
    return module.client.get(oper_url(module))

def get_stats(module):
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["monitor"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["monitor"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["monitor"][k] = v
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
    payload = build_json("monitor", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    if module.check_mode:
        result["changed"] = True
        return result
    else:
        return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("monitor", module)
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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