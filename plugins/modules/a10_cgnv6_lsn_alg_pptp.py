#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_cgnv6_lsn_alg_pptp
description:
    - Change LSN PPTP ALG Settings
short_description: Configures A10 cgnv6.lsn.alg.pptp
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
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
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
    pptp_value:
        description:
        - "'enable'= Enable PPTP ALG for LSN; "
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            gre_sessions_created:
                description:
                - "GRE Sessions Created"
            mismatched_pns_call_id:
                description:
                - "Mismatched PNS Call ID"
            call_reply_pns_call_id_mismatch:
                description:
                - "Call ID Mismatch on Call Reply"
            calls_established:
                description:
                - "Calls Established"
            no_gre_session_match:
                description:
                - "No Matching GRE Session"
            call_req_pns_call_id_mismatch:
                description:
                - "Call ID Mismatch on Call Request"
            gre_sessions_freed:
                description:
                - "GRE Sessions Freed"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'calls-established'= Calls Established; 'mismatched-pns-call-id'= Mismatched PNS Call ID; 'gre-sessions-created'= GRE Sessions Created; 'gre-sessions-freed'= GRE Sessions Freed; 'no-gre-session-match'= No Matching GRE Session; 'smp-sessions-created'= SMP Sessions Created; 'smp-sessions-freed'= SMP Sessions Freed; 'smp-session-creation-failure'= SMP Session Creation Failures; 'extension-creation-failure'= Extension Creation Failures; 'ha-sent'= HA Info Sent; 'ha-rcv'= HA Info Received; 'ha-no-mem'= HA Memory Allocation Failure; 'ha-conflict'= HA Call ID Conflicts; 'ha-overwrite'= HA Call ID Overwrites; 'ha-call-sent'= HA Call Sent; 'ha-call-rcv'= HA Call Received; 'ha-smp-conflict'= HA SMP Conflicts; 'ha-smp-in-del-q'= HA SMP Deleted; 'smp-app-type-mismatch'= SMP ALG App Type Mismatch; 'quota-inc'= Quota Incremented; 'quota-dec'= Quota Decremented; 'quota-inc-not-found'= Quota Not Found on Increment; 'quota-dec-not-found'= Quota Not Found on Decrement; 'call-req-pns-call-id-mismatch'= Call ID Mismatch on Call Request; 'call-reply-pns-call-id-mismatch'= Call ID Mismatch on Call Reply; 'call-req-retransmit'= Call Request Retransmit; 'call-req-new'= Call Request New; 'call-req-ext-alloc-failure'= Call Request Ext Alloc Failure; 'call-reply-call-id-unknown'= Call Reply Unknown Client Call ID; 'call-reply-retransmit'= Call Reply Retransmit; 'call-reply-retransmit-wrong-control'= Call Reply Retransmit Wrong Control; 'call-reply-retransmit-acquired'= Call Reply Retransmit Acquired; 'call-reply-ext-alloc-failure'= Call Request Ext Alloc Failure; 'smp-client-call-id-mismatch'= SMP Client Call ID Mismatch; 'smp-alloc-failure'= SMP Session Alloc Failure; 'gre-conn-creation-failure'= GRE Conn Alloc Failure; 'gre-conn-ext-creation-failure'= GRE Conn Ext Alloc Failure; 'gre-no-fwd-route'= GRE No Fwd Route; 'gre-no-rev-route'= GRE No Rev Route; 'gre-no-control-conn'= GRE No Control Conn; 'gre-conn-already-exists'= GRE Conn Already Exists; 'gre-free-no-ext'= GRE Free No Ext; 'gre-free-no-smp'= GRE Free No SMP; 'gre-free-smp-app-type-mismatch'= GRE Free SMP App Type Mismatch; 'control-freed'= Control Session Freed; 'control-free-no-ext'= Control Free No Ext; 'control-free-no-smp'= Control Free No SMP; 'control-free-smp-app-type-mismatch'= Control Free SMP App Type Mismatch; "
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
AVAILABLE_PROPERTIES = ["pptp_value","sampling_enable","stats","uuid",]

# our imports go at the top so we fail fast.
try:
    from ansible_collections.a10.acos_axapi.plugins.module_utils import errors as a10_ex
    from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import client_factory, session_factory
    from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        pptp_value=dict(type='str', choices=['enable']),
        stats=dict(type='dict', gre_sessions_created=dict(type='str', ), mismatched_pns_call_id=dict(type='str', ), call_reply_pns_call_id_mismatch=dict(type='str', ), calls_established=dict(type='str', ), no_gre_session_match=dict(type='str', ), call_req_pns_call_id_mismatch=dict(type='str', ), gre_sessions_freed=dict(type='str', )),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'calls-established', 'mismatched-pns-call-id', 'gre-sessions-created', 'gre-sessions-freed', 'no-gre-session-match', 'smp-sessions-created', 'smp-sessions-freed', 'smp-session-creation-failure', 'extension-creation-failure', 'ha-sent', 'ha-rcv', 'ha-no-mem', 'ha-conflict', 'ha-overwrite', 'ha-call-sent', 'ha-call-rcv', 'ha-smp-conflict', 'ha-smp-in-del-q', 'smp-app-type-mismatch', 'quota-inc', 'quota-dec', 'quota-inc-not-found', 'quota-dec-not-found', 'call-req-pns-call-id-mismatch', 'call-reply-pns-call-id-mismatch', 'call-req-retransmit', 'call-req-new', 'call-req-ext-alloc-failure', 'call-reply-call-id-unknown', 'call-reply-retransmit', 'call-reply-retransmit-wrong-control', 'call-reply-retransmit-acquired', 'call-reply-ext-alloc-failure', 'smp-client-call-id-mismatch', 'smp-alloc-failure', 'gre-conn-creation-failure', 'gre-conn-ext-creation-failure', 'gre-no-fwd-route', 'gre-no-rev-route', 'gre-no-control-conn', 'gre-conn-already-exists', 'gre-free-no-ext', 'gre-free-no-smp', 'gre-free-smp-app-type-mismatch', 'control-freed', 'control-free-no-ext', 'control-free-no-smp', 'control-free-smp-app-type-mismatch'])),
        uuid=dict(type='str', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/lsn/alg/pptp"

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
    url_base = "/axapi/v3/cgnv6/lsn/alg/pptp"

    f_dict = {}

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
        for k, v in payload["pptp"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["pptp"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["pptp"][k] = v
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
    payload = build_json("pptp", module)
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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)
    
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