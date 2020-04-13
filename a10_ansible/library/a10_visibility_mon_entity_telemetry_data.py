#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_visibility_mon_entity_telemetry_data
description:
    - dummy schema for sflow exports
short_description: Configures A10 visibility.mon-entity-telemetry-data
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
                - "'all'= all; 'in_pkts'= Monitored Entity telemetry Metric IN pkts; 'out_pkts'= Monitored Entity telemetry Metric OUT pkts; 'in_bytes'= Monitored Entity telemetry Metric IN bytes; 'out_bytes'= Monitored Entity telemetry Metric OUT bytes; 'errors'= Monitored Entity telemetry Metric ERRORS; 'in_small_pkt'= Monitored Entity telemetry Metric IN SMALL pkt; 'in_frag'= Monitored Entity telemetry Metric IN frag; 'out_small_pkt'= Monitored Entity telemetry Metric OUT SMALL pkt; 'out_frag'= Monitored Entity telemetry Metric OUT frag; 'new-conn'= Monitored Entity telemetry Metric New Sessions; 'concurrent-conn'= concurrent-conn; 'in_bytes_per_out_bytes'= Monitored Entity telemetry Metric IN bytes per OUT bytes; 'drop_pkts_per_pkts'= Monitored Entity telemetry Metric Drop pkts per pkts; 'tcp_in_syn'= Monitored Entity telemetry Metric TCP IN syn; 'tcp_out_syn'= Monitored Entity telemetry Metric TCP OUT syn; 'tcp_in_fin'= Monitored Entity telemetry Metric TCP IN fin; 'tcp_out_fin'= Monitored Entity telemetry Metric TCP OUT fin; 'tcp_in_payload'= Monitored Entity telemetry Metric TCP IN payload; 'tcp_out_payload'= Monitored Entity telemetry Metric TCP OUT payload; 'tcp_in_rexmit'= Monitored Entity telemetry Metric TCP IN rexmit; 'tcp_out_rexmit'= Monitored Entity telemetry Metric TCP OUT rexmit; 'tcp_in_rst'= Monitored Entity telemetry Metric TCP IN rst; 'tcp_out_rst'= Monitored Entity telemetry Metric TCP OUT rst; 'tcp_in_empty_ack'= Monitored Entity telemetry Metric TCP_IN EMPTY ack; 'tcp_out_empty_ack'= Monitored Entity telemetry Metric TCP OUT EMPTY ack; 'tcp_in_zero_wnd'= Monitored Entity telemetry Metric TCP IN ZERO wnd; 'tcp_out_zero_wnd'= Monitored Entity telemetry Metric TCP OUT ZERO wnd; 'tcp_fwd_syn_per_fin'= Monitored Entity telemetry Metric TCP FWD SYN per FIN; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            in_bytes:
                description:
                - "Monitored Entity telemetry Metric IN bytes"
            tcp_in_empty_ack:
                description:
                - "Monitored Entity telemetry Metric TCP_IN EMPTY ack"
            in_small_pkt:
                description:
                - "Monitored Entity telemetry Metric IN SMALL pkt"
            tcp_out_empty_ack:
                description:
                - "Monitored Entity telemetry Metric TCP OUT EMPTY ack"
            concurrent_conn:
                description:
                - "Field concurrent_conn"
            out_frag:
                description:
                - "Monitored Entity telemetry Metric OUT frag"
            tcp_out_rst:
                description:
                - "Monitored Entity telemetry Metric TCP OUT rst"
            tcp_out_zero_wnd:
                description:
                - "Monitored Entity telemetry Metric TCP OUT ZERO wnd"
            errors:
                description:
                - "Monitored Entity telemetry Metric ERRORS"
            out_small_pkt:
                description:
                - "Monitored Entity telemetry Metric OUT SMALL pkt"
            tcp_in_rexmit:
                description:
                - "Monitored Entity telemetry Metric TCP IN rexmit"
            tcp_out_fin:
                description:
                - "Monitored Entity telemetry Metric TCP OUT fin"
            in_bytes_per_out_bytes:
                description:
                - "Monitored Entity telemetry Metric IN bytes per OUT bytes"
            tcp_in_payload:
                description:
                - "Monitored Entity telemetry Metric TCP IN payload"
            tcp_out_syn:
                description:
                - "Monitored Entity telemetry Metric TCP OUT syn"
            tcp_out_rexmit:
                description:
                - "Monitored Entity telemetry Metric TCP OUT rexmit"
            tcp_in_zero_wnd:
                description:
                - "Monitored Entity telemetry Metric TCP IN ZERO wnd"
            tcp_in_fin:
                description:
                - "Monitored Entity telemetry Metric TCP IN fin"
            out_pkts:
                description:
                - "Monitored Entity telemetry Metric OUT pkts"
            tcp_fwd_syn_per_fin:
                description:
                - "Monitored Entity telemetry Metric TCP FWD SYN per FIN"
            in_pkts:
                description:
                - "Monitored Entity telemetry Metric IN pkts"
            out_bytes:
                description:
                - "Monitored Entity telemetry Metric OUT bytes"
            in_frag:
                description:
                - "Monitored Entity telemetry Metric IN frag"
            drop_pkts_per_pkts:
                description:
                - "Monitored Entity telemetry Metric Drop pkts per pkts"
            tcp_in_syn:
                description:
                - "Monitored Entity telemetry Metric TCP IN syn"
            tcp_out_payload:
                description:
                - "Monitored Entity telemetry Metric TCP OUT payload"
            new_conn:
                description:
                - "Monitored Entity telemetry Metric New Sessions"
            tcp_in_rst:
                description:
                - "Monitored Entity telemetry Metric TCP IN rst"
    uuid:
        description:
        - "uuid of the object"
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
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','in_pkts','out_pkts','in_bytes','out_bytes','errors','in_small_pkt','in_frag','out_small_pkt','out_frag','new-conn','concurrent-conn','in_bytes_per_out_bytes','drop_pkts_per_pkts','tcp_in_syn','tcp_out_syn','tcp_in_fin','tcp_out_fin','tcp_in_payload','tcp_out_payload','tcp_in_rexmit','tcp_out_rexmit','tcp_in_rst','tcp_out_rst','tcp_in_empty_ack','tcp_out_empty_ack','tcp_in_zero_wnd','tcp_out_zero_wnd','tcp_fwd_syn_per_fin'])),
        stats=dict(type='dict',in_bytes=dict(type='str',),tcp_in_empty_ack=dict(type='str',),in_small_pkt=dict(type='str',),tcp_out_empty_ack=dict(type='str',),concurrent_conn=dict(type='str',),out_frag=dict(type='str',),tcp_out_rst=dict(type='str',),tcp_out_zero_wnd=dict(type='str',),errors=dict(type='str',),out_small_pkt=dict(type='str',),tcp_in_rexmit=dict(type='str',),tcp_out_fin=dict(type='str',),in_bytes_per_out_bytes=dict(type='str',),tcp_in_payload=dict(type='str',),tcp_out_syn=dict(type='str',),tcp_out_rexmit=dict(type='str',),tcp_in_zero_wnd=dict(type='str',),tcp_in_fin=dict(type='str',),out_pkts=dict(type='str',),tcp_fwd_syn_per_fin=dict(type='str',),in_pkts=dict(type='str',),out_bytes=dict(type='str',),in_frag=dict(type='str',),drop_pkts_per_pkts=dict(type='str',),tcp_in_syn=dict(type='str',),tcp_out_payload=dict(type='str',),new_conn=dict(type='str',),tcp_in_rst=dict(type='str',)),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/mon-entity-telemetry-data"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/mon-entity-telemetry-data"

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
        for k, v in payload["mon-entity-telemetry-data"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["mon-entity-telemetry-data"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["mon-entity-telemetry-data"][k] = v
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
    payload = build_json("mon-entity-telemetry-data", module)
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