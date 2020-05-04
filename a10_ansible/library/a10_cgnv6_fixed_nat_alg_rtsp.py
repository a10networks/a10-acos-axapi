#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_cgnv6_fixed_nat_alg_rtsp
description:
    - Change Fixed NAT RTSP ALG Settings
short_description: Configures A10 cgnv6.fixed.nat.alg.rtsp
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
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'streams-created'= Streams Created; 'streams-freed'= Streams Freed; 'stream-creation-failure'= Stream Creation Failures; 'ports-allocated'= Stream Client Ports Allocated; 'ports-freed'= Stream Client Ports Freed; 'port-allocation-failure'= Stream Client Port Allocation Failures; 'unknown-client-port-from-server'= Server Replies With Unknown Client Ports; 'data-session-created'= Data Session Created; 'data-session-freed'= Data Session Freed; 'no-session-mem'= Data Session Creation Failures; 'smp-inserted'= SMP Session Inserted; 'smp-removed'= SMP Session Removed; 'smp-reused'= SMP Session Reused; 'fixed-nat-lid-standby'= New Session Fixed NAT LID Standby; 'smp-deleted'= New Session SMP Already Deleted; 'control-closed'= New Session Closed; 'data-session-exists'= New Session Already Exists; 'data-session-creation-failure'= New Data Session Creation Failure; 'rtp-reversed'= RTP Reverse Creation; 'rtcp-reversed'= RTCP Reverse Creation; 'cross-cpu-sent'= Cross CPU Sent; 'cross-cpu-rcv'= Cross CPU Received; 'cross-cpu-no-session'= Cross CPU No Session Found; 'cross-cpu-created'= Cross CPU Creation; 'cross-cpu-rcv-failure'= Cross CPU Receive Failure; 'data-free-smp-retry-lookup'= Data Session Free SMP Retry Lookup; 'data-free-smp-not-found'= Data Session Free SMP Not Found; 'ha-streams-sent'= HA Streams Sent; 'ha-streams-rcv'= HA Streams Received; 'ha-stream-incompatible'= HA Incompatible Streams Received; 'ha-stream-exists'= HA Stream Already Exists; 'ha-port-allocation-failure'= HA Stream Port Allocation Failure; 'ha-data-session-sent'= HA Data Session Sent; 'ha-data-session-rcv'= HA Data Session Received; 'ha-data-no-smp'= HA Data Session SMP Not Found; 'ha-control-closed'= HA New Data Control Session Closed; 'ha-data-exists'= HA New Data Session Already Exists; 'ha-extension-failure'= HA Conn Extension Failure; 'ha-stream-smp-reused'= HA SMP Session Reused; 'ha-stream-smp-acquire-failure'= HA SMP Session Acquire Failure; 'smp-app-type-mismatch'= SMP ALG App Type Mismatch; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            stream_creation_failure:
                description:
                - "Stream Creation Failures"
            streams_created:
                description:
                - "Streams Created"
            no_session_mem:
                description:
                - "Data Session Creation Failures"
            ports_allocated:
                description:
                - "Stream Client Ports Allocated"
            port_allocation_failure:
                description:
                - "Stream Client Port Allocation Failures"
            streams_freed:
                description:
                - "Streams Freed"
            unknown_client_port_from_server:
                description:
                - "Server Replies With Unknown Client Ports"
            ports_freed:
                description:
                - "Stream Client Ports Freed"
            data_session_freed:
                description:
                - "Data Session Freed"
            data_session_created:
                description:
                - "Data Session Created"
    uuid:
        description:
        - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["sampling_enable","stats","uuid",]

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
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all','streams-created','streams-freed','stream-creation-failure','ports-allocated','ports-freed','port-allocation-failure','unknown-client-port-from-server','data-session-created','data-session-freed','no-session-mem','smp-inserted','smp-removed','smp-reused','fixed-nat-lid-standby','smp-deleted','control-closed','data-session-exists','data-session-creation-failure','rtp-reversed','rtcp-reversed','cross-cpu-sent','cross-cpu-rcv','cross-cpu-no-session','cross-cpu-created','cross-cpu-rcv-failure','data-free-smp-retry-lookup','data-free-smp-not-found','ha-streams-sent','ha-streams-rcv','ha-stream-incompatible','ha-stream-exists','ha-port-allocation-failure','ha-data-session-sent','ha-data-session-rcv','ha-data-no-smp','ha-control-closed','ha-data-exists','ha-extension-failure','ha-stream-smp-reused','ha-stream-smp-acquire-failure','smp-app-type-mismatch'])),
        stats=dict(type='dict', stream_creation_failure=dict(type='str', ),streams_created=dict(type='str', ),no_session_mem=dict(type='str', ),ports_allocated=dict(type='str', ),port_allocation_failure=dict(type='str', ),streams_freed=dict(type='str', ),unknown_client_port_from_server=dict(type='str', ),ports_freed=dict(type='str', ),data_session_freed=dict(type='str', ),data_session_created=dict(type='str', )),
        uuid=dict(type='str', )
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/fixed-nat/alg/rtsp"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/fixed-nat/alg/rtsp"

    f_dict = {}

    return url_base.format(**f_dict)

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
        for k, v in payload["rtsp"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["rtsp"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["rtsp"][k] = v
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
    payload = build_json("rtsp", module)
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