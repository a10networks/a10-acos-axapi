#!/usr/bin/python

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
    partition:
        description:
        - Destination/target partition for object/command
    alg_processing:
        description:
        - "'honor-rule-set'= Honors firewall rule-sets (Default); 'override-rule-set'= Override firewall rule-sets; "
        required: False
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
AVAILABLE_PROPERTIES = ["alg_processing","disable_ip_fw_sessions","listen_on_port_timeout","permit_default_action","sampling_enable","uuid",]

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
        alg_processing=dict(type='str',choices=['honor-rule-set','override-rule-set']),
        uuid=dict(type='str',),
        listen_on_port_timeout=dict(type='int',),
        disable_ip_fw_sessions=dict(type='bool',),
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
    present_keys = sorted([x for x in requires_one_of if x in params])
    
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
    payload = build_json("global", module)
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
    payload = build_json("global", module)
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
    payload = build_json("global", module)
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
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
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