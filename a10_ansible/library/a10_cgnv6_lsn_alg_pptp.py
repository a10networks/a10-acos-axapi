#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
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
    a10_protocol:
        description:
        - HTTP / HTTPS Protocol for AXAPI authentication
        required: True
    a10_port:
        description:
        - Port number AXAPI is running on
        required: True
    partition:
        description:
        - Destination/target partition for object/command
    pptp_value:
        description:
        - "'enable'= Enable PPTP ALG for LSN; "
        required: False
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

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["pptp_value","sampling_enable","uuid",]

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
        get_type=dict(type='str', choices=["single", "list"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        pptp_value=dict(type='str',choices=['enable']),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','calls-established','mismatched-pns-call-id','gre-sessions-created','gre-sessions-freed','no-gre-session-match','smp-sessions-created','smp-sessions-freed','smp-session-creation-failure','extension-creation-failure','ha-sent','ha-rcv','ha-no-mem','ha-conflict','ha-overwrite','ha-call-sent','ha-call-rcv','ha-smp-conflict','ha-smp-in-del-q','smp-app-type-mismatch','quota-inc','quota-dec','quota-inc-not-found','quota-dec-not-found','call-req-pns-call-id-mismatch','call-reply-pns-call-id-mismatch','call-req-retransmit','call-req-new','call-req-ext-alloc-failure','call-reply-call-id-unknown','call-reply-retransmit','call-reply-retransmit-wrong-control','call-reply-retransmit-acquired','call-reply-ext-alloc-failure','smp-client-call-id-mismatch','smp-alloc-failure','gre-conn-creation-failure','gre-conn-ext-creation-failure','gre-no-fwd-route','gre-no-rev-route','gre-no-control-conn','gre-conn-already-exists','gre-free-no-ext','gre-free-no-smp','gre-free-smp-app-type-mismatch','control-freed','control-free-no-ext','control-free-no-smp','control-free-smp-app-type-mismatch'])),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/lsn/alg/pptp"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/lsn/alg/pptp"

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
        return False

def create(module, result):
    payload = build_json("pptp", module)
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

def update(module, result, existing_config):
    payload = build_json("pptp", module)
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
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result, existing_config)

def absent(module, result):
    return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("pptp", module)
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
    module = AnsibleModule(argument_spec=get_argspec())
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()