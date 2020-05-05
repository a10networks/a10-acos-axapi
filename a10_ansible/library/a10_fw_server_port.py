#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_fw_server_port
description:
    - Real Server Port
short_description: Configures A10 fw.server.port
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
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
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    server_name:
        description:
        - Key to identify parent object
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            vrid:
                description:
                - "Field vrid"
            ha_group_id:
                description:
                - "Field ha_group_id"
            alloc_failed:
                description:
                - "Field alloc_failed"
            ports_consumed:
                description:
                - "Field ports_consumed"
            protocol:
                description:
                - "'tcp'= TCP Port; 'udp'= UDP Port; "
            ipv6:
                description:
                - "Field ipv6"
            state:
                description:
                - "Field state"
            port_number:
                description:
                - "Port Number"
            ip:
                description:
                - "Field ip"
            ports_freed_total:
                description:
                - "Field ports_freed_total"
            ports_consumed_total:
                description:
                - "Field ports_consumed_total"
    health_check_disable:
        description:
        - "Disable health check"
        required: False
    protocol:
        description:
        - "'tcp'= TCP Port; 'udp'= UDP Port; "
        required: True
    uuid:
        description:
        - "uuid of the object"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'curr_conn'= Current connections; 'curr_req'= Current requests; 'total_req'= Total requests; 'total_req_succ'= Total request success; 'total_fwd_bytes'= Forward bytes; 'total_fwd_pkts'= Forward packets; 'total_rev_bytes'= Reverse bytes; 'total_rev_pkts'= Reverse packets; 'total_conn'= Total connections; 'last_total_conn'= Last total connections; 'peak_conn'= Peak connections; 'es_resp_200'= Response status 200; 'es_resp_300'= Response status 300; 'es_resp_400'= Response status 400; 'es_resp_500'= Response status 500; 'es_resp_other'= Response status other; 'es_req_count'= Total proxy request; 'es_resp_count'= Total proxy Response; 'es_resp_invalid_http'= Total non-http response; 'total_rev_pkts_inspected'= Total reverse packets inspected; 'total_rev_pkts_inspected_good_status_code'= Total reverse packets with good status code inspected; 'response_time'= Response time; 'fastest_rsp_time'= Fastest response time; 'slowest_rsp_time'= Slowest response time; "
    port_number:
        description:
        - "Port Number"
        required: True
    action:
        description:
        - "'enable'= enable; 'disable'= disable; "
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            es_resp_invalid_http:
                description:
                - "Total non-http response"
            curr_req:
                description:
                - "Current requests"
            protocol:
                description:
                - "'tcp'= TCP Port; 'udp'= UDP Port; "
            total_rev_pkts_inspected_good_status_code:
                description:
                - "Total reverse packets with good status code inspected"
            es_resp_count:
                description:
                - "Total proxy Response"
            total_fwd_bytes:
                description:
                - "Forward bytes"
            es_resp_other:
                description:
                - "Response status other"
            fastest_rsp_time:
                description:
                - "Fastest response time"
            total_fwd_pkts:
                description:
                - "Forward packets"
            es_req_count:
                description:
                - "Total proxy request"
            es_resp_500:
                description:
                - "Response status 500"
            peak_conn:
                description:
                - "Peak connections"
            total_req:
                description:
                - "Total requests"
            es_resp_400:
                description:
                - "Response status 400"
            es_resp_300:
                description:
                - "Response status 300"
            curr_conn:
                description:
                - "Current connections"
            port_number:
                description:
                - "Port Number"
            es_resp_200:
                description:
                - "Response status 200"
            total_rev_bytes:
                description:
                - "Reverse bytes"
            response_time:
                description:
                - "Response time"
            total_conn:
                description:
                - "Total connections"
            total_rev_pkts:
                description:
                - "Reverse packets"
            total_req_succ:
                description:
                - "Total request success"
            last_total_conn:
                description:
                - "Last total connections"
            total_rev_pkts_inspected:
                description:
                - "Total reverse packets inspected"
            slowest_rsp_time:
                description:
                - "Slowest response time"
    health_check:
        description:
        - "Health Check (Monitor Name)"
        required: False


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["action","health_check","health_check_disable","oper","port_number","protocol","sampling_enable","stats","user_tag","uuid",]

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
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict', vrid=dict(type='int', ), ha_group_id=dict(type='int', ), alloc_failed=dict(type='int', ), ports_consumed=dict(type='int', ), protocol=dict(type='str', required=True, choices=['tcp', 'udp']), ipv6=dict(type='str', ), state=dict(type='str', choices=['UP', 'DOWN', 'DELETE', 'DISABLED', 'MAINTENANCE']), port_number=dict(type='int', required=True, ), ip=dict(type='str', ), ports_freed_total=dict(type='int', ), ports_consumed_total=dict(type='int', )),
        health_check_disable=dict(type='bool', ),
        protocol=dict(type='str', required=True, choices=['tcp', 'udp']),
        uuid=dict(type='str', ),
        user_tag=dict(type='str', ),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'curr_conn', 'curr_req', 'total_req', 'total_req_succ', 'total_fwd_bytes', 'total_fwd_pkts', 'total_rev_bytes', 'total_rev_pkts', 'total_conn', 'last_total_conn', 'peak_conn', 'es_resp_200', 'es_resp_300', 'es_resp_400', 'es_resp_500', 'es_resp_other', 'es_req_count', 'es_resp_count', 'es_resp_invalid_http', 'total_rev_pkts_inspected', 'total_rev_pkts_inspected_good_status_code', 'response_time', 'fastest_rsp_time', 'slowest_rsp_time'])),
        port_number=dict(type='int', required=True, ),
        action=dict(type='str', choices=['enable', 'disable']),
        stats=dict(type='dict', es_resp_invalid_http=dict(type='str', ), curr_req=dict(type='str', ), protocol=dict(type='str', required=True, choices=['tcp', 'udp']), total_rev_pkts_inspected_good_status_code=dict(type='str', ), es_resp_count=dict(type='str', ), total_fwd_bytes=dict(type='str', ), es_resp_other=dict(type='str', ), fastest_rsp_time=dict(type='str', ), total_fwd_pkts=dict(type='str', ), es_req_count=dict(type='str', ), es_resp_500=dict(type='str', ), peak_conn=dict(type='str', ), total_req=dict(type='str', ), es_resp_400=dict(type='str', ), es_resp_300=dict(type='str', ), curr_conn=dict(type='str', ), port_number=dict(type='int', required=True, ), es_resp_200=dict(type='str', ), total_rev_bytes=dict(type='str', ), response_time=dict(type='str', ), total_conn=dict(type='str', ), total_rev_pkts=dict(type='str', ), total_req_succ=dict(type='str', ), last_total_conn=dict(type='str', ), total_rev_pkts_inspected=dict(type='str', ), slowest_rsp_time=dict(type='str', )),
        health_check=dict(type='str', )
    ))
   
    # Parent keys
    rv.update(dict(
        server_name=dict(type='str', required=True),
    ))

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/server/{server_name}/port/{port-number}+{protocol}"

    f_dict = {}
    f_dict["port-number"] = module.params["port_number"]
    f_dict["protocol"] = module.params["protocol"]
    f_dict["server_name"] = module.params["server_name"]

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

def build_envelope(title, data):
    return {
        title: data
    }

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/fw/server/{server_name}/port/{port-number}+{protocol}"

    f_dict = {}
    f_dict["port-number"] = ""
    f_dict["protocol"] = ""
    f_dict["server_name"] = module.params["server_name"]

    return url_base.format(**f_dict)

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
        for k, v in payload["port"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["port"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["port"][k] = v
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
    payload = build_json("port", module)
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
    a10_device_context_id = module.params["a10_device_context_id"]

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

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

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