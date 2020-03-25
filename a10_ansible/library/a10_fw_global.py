#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_fw_global
description:
    - Configure firewall parameters
short_description: Configures A10 fw.global
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
    alg_processing:
        description:
        - "'honor-rule-set'= Honors firewall rule-sets; 'override-rule-set'= Override firewall rule-sets; "
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            data_session_freed:
                description:
                - "Data Session Freed"
            active_fullcone_session:
                description:
                - "Total Active Full-cone sessions"
            udp_fullcone_freed:
                description:
                - "UDP Full-cone Freed"
            data_session_created:
                description:
                - "Data Session Created"
            tcp_fullcone_created:
                description:
                - "TCP Full-cone Created"
            tcp_fullcone_freed:
                description:
                - "TCP Full-cone Freed"
            fullcone_creation_failure:
                description:
                - "Full-Cone Creation Failure"
            udp_fullcone_created:
                description:
                - "UDP Full-cone Created"
    uuid:
        description:
        - "uuid of the object"
        required: False
    listen_on_port_timeout:
        description:
        - "STUN timeout (default= 2 minutes)"
        required: False
    disable_ip_fw_sessions:
        description:
        - "disable create sessions for non TCP/UDP/ICMP"
        required: False
    extended_matching:
        description:
        - "'disable'= Disable extended matching; "
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'tcp_fullcone_created'= TCP Full-cone Created; 'tcp_fullcone_freed'= TCP Full-cone Freed; 'udp_fullcone_created'= UDP Full-cone Created; 'udp_fullcone_freed'= UDP Full-cone Freed; 'fullcone_creation_failure'= Full-Cone Creation Failure; 'data_session_created'= Data Session Created; 'data_session_freed'= Data Session Freed; 'fullcone_in_del_q'= Full-cone session found in delete queue; 'fullcone_retry_lookup'= Full-cone session retry look-up; 'fullcone_not_found'= Full-cone session not found; 'fullcone_overflow_eim'= Full-cone Session EIM Overflow; 'fullcone_overflow_eif'= Full-cone Session EIF Overflow; 'udp_fullcone_created_shadow'= Total UDP Full-cone sessions created; 'tcp_fullcone_created_shadow'= Total TCP Full-cone sessions created; 'udp_fullcone_freed_shadow'= Total UDP Full-cone sessions freed; 'tcp_fullcone_freed_shadow'= Total TCP Full-cone sessions freed; 'fullcone_created'= Total Full-cone sessions created; 'fullcone_freed'= Total Full-cone sessions freed; 'fullcone_ext_too_many'= Fullcone Extension Too Many; 'fullcone_ext_mem_allocated'= Fullcone Extension Memory Allocated; 'fullcone_ext_mem_alloc_failure'= Fullcone Extension Memory Allocate Failure; 'fullcone_ext_mem_alloc_init_faulure'= Fullcone Extension Initialization Failure; 'fullcone_ext_mem_freed'= Fullcone Extension Memory Freed; 'fullcone_ext_added'= Fullcone Extension Added; 'ha_fullcone_failure'= HA Full-cone Session Failure; 'data_session_created_shadow'= Total Data Sessions Created; 'data_session_freed_shadow'= Total Data Sessions Freed; 'active_fullcone_session'= Total Active Full-cone sessions; "
    permit_default_action:
        description:
        - "'forward'= Forward; 'next-service-mode'= Service to be applied chosen based on configuration; "
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
AVAILABLE_PROPERTIES = ["alg_processing","disable_ip_fw_sessions","extended_matching","listen_on_port_timeout","permit_default_action","sampling_enable","stats","uuid",]

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
        alg_processing=dict(type='str',choices=['honor-rule-set','override-rule-set']),
        stats=dict(type='dict',data_session_freed=dict(type='str',),active_fullcone_session=dict(type='str',),udp_fullcone_freed=dict(type='str',),data_session_created=dict(type='str',),tcp_fullcone_created=dict(type='str',),tcp_fullcone_freed=dict(type='str',),fullcone_creation_failure=dict(type='str',),udp_fullcone_created=dict(type='str',)),
        uuid=dict(type='str',),
        listen_on_port_timeout=dict(type='int',),
        disable_ip_fw_sessions=dict(type='bool',),
        extended_matching=dict(type='str',choices=['disable']),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','tcp_fullcone_created','tcp_fullcone_freed','udp_fullcone_created','udp_fullcone_freed','fullcone_creation_failure','data_session_created','data_session_freed','fullcone_in_del_q','fullcone_retry_lookup','fullcone_not_found','fullcone_overflow_eim','fullcone_overflow_eif','udp_fullcone_created_shadow','tcp_fullcone_created_shadow','udp_fullcone_freed_shadow','tcp_fullcone_freed_shadow','fullcone_created','fullcone_freed','fullcone_ext_too_many','fullcone_ext_mem_allocated','fullcone_ext_mem_alloc_failure','fullcone_ext_mem_alloc_init_faulure','fullcone_ext_mem_freed','fullcone_ext_added','ha_fullcone_failure','data_session_created_shadow','data_session_freed_shadow','active_fullcone_session'])),
        permit_default_action=dict(type='str',choices=['forward','next-service-mode'])
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/fw/global"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/global"

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
        for k, v in payload["global"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["global"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["global"][k] = v
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
    payload = build_json("global", module)
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