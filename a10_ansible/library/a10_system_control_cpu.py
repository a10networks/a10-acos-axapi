#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_system_control_cpu
description:
    - System control cpu information
short_description: Configures A10 system.control-cpu
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
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            cpu_14:
                description:
                - "Control CPU-14"
            cpu_49:
                description:
                - "Control CPU-49"
            cpu_48:
                description:
                - "Control CPU-48"
            cpu_23:
                description:
                - "Control CPU-23"
            cpu_22:
                description:
                - "Control CPU-22"
            cpu_21:
                description:
                - "Control CPU-21"
            cpu_20:
                description:
                - "Control CPU-20"
            cpu_27:
                description:
                - "Control CPU-27"
            cpu_26:
                description:
                - "Control CPU-26"
            cpu_25:
                description:
                - "Control CPU-25"
            cpu_24:
                description:
                - "Control CPU-24"
            cpu_29:
                description:
                - "Control CPU-29"
            cpu_28:
                description:
                - "Control CPU-28"
            cpu_45:
                description:
                - "Control CPU-45"
            cpu_44:
                description:
                - "Control CPU-44"
            cpu_47:
                description:
                - "Control CPU-47"
            cpu_46:
                description:
                - "Control CPU-46"
            cpu_41:
                description:
                - "Control CPU-41"
            cpu_40:
                description:
                - "Control CPU-40"
            cpu_43:
                description:
                - "Control CPU-43"
            cpu_42:
                description:
                - "Control CPU-42"
            cpu_64:
                description:
                - "Control CPU-64"
            cpu_63:
                description:
                - "Control CPU-63"
            cpu_62:
                description:
                - "Control CPU-62"
            cpu_61:
                description:
                - "Control CPU-61"
            cpu_60:
                description:
                - "Control CPU-60"
            cpu_18:
                description:
                - "Control CPU-18"
            cpu_19:
                description:
                - "Control CPU-19"
            cpu_34:
                description:
                - "Control CPU-34"
            cpu_35:
                description:
                - "Control CPU-35"
            cpu_36:
                description:
                - "Control CPU-36"
            cpu_37:
                description:
                - "Control CPU-37"
            cpu_30:
                description:
                - "Control CPU-30"
            cpu_31:
                description:
                - "Control CPU-31"
            cpu_32:
                description:
                - "Control CPU-32"
            cpu_33:
                description:
                - "Control CPU-33"
            cpu_38:
                description:
                - "Control CPU-38"
            cpu_39:
                description:
                - "Control CPU-39"
            cpu_56:
                description:
                - "Control CPU-56"
            cpu_57:
                description:
                - "Control CPU-57"
            cpu_54:
                description:
                - "Control CPU-54"
            cpu_55:
                description:
                - "Control CPU-55"
            cpu_52:
                description:
                - "Control CPU-52"
            cpu_53:
                description:
                - "Control CPU-53"
            cpu_50:
                description:
                - "Control CPU-50"
            cpu_51:
                description:
                - "Control CPU-51"
            cpu_12:
                description:
                - "Control CPU-12"
            cpu_13:
                description:
                - "Control CPU-13"
            cpu_10:
                description:
                - "Control CPU-10"
            cpu_11:
                description:
                - "Control CPU-11"
            cpu_16:
                description:
                - "Control CPU-16"
            cpu_17:
                description:
                - "Control CPU-17"
            cpu_58:
                description:
                - "Control CPU-58"
            cpu_15:
                description:
                - "Control CPU-15"
            cpu_1:
                description:
                - "Control CPU-1"
            cpu_2:
                description:
                - "Control CPU-2"
            cpu_3:
                description:
                - "Control CPU-3"
            cpu_4:
                description:
                - "Control CPU-4"
            cpu_5:
                description:
                - "Control CPU-5"
            cpu_6:
                description:
                - "Control CPU-6"
            cpu_7:
                description:
                - "Control CPU-7"
            cpu_8:
                description:
                - "Control CPU-8"
            cpu_9:
                description:
                - "Control CPU-9"
            ctrl_cpu_number:
                description:
                - "Number of ctrl cpus"
            cpu_59:
                description:
                - "Control CPU-59"
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
AVAILABLE_PROPERTIES = ["stats","uuid",]

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
        stats=dict(type='dict',cpu_14=dict(type='str',),cpu_49=dict(type='str',),cpu_48=dict(type='str',),cpu_23=dict(type='str',),cpu_22=dict(type='str',),cpu_21=dict(type='str',),cpu_20=dict(type='str',),cpu_27=dict(type='str',),cpu_26=dict(type='str',),cpu_25=dict(type='str',),cpu_24=dict(type='str',),cpu_29=dict(type='str',),cpu_28=dict(type='str',),cpu_45=dict(type='str',),cpu_44=dict(type='str',),cpu_47=dict(type='str',),cpu_46=dict(type='str',),cpu_41=dict(type='str',),cpu_40=dict(type='str',),cpu_43=dict(type='str',),cpu_42=dict(type='str',),cpu_64=dict(type='str',),cpu_63=dict(type='str',),cpu_62=dict(type='str',),cpu_61=dict(type='str',),cpu_60=dict(type='str',),cpu_18=dict(type='str',),cpu_19=dict(type='str',),cpu_34=dict(type='str',),cpu_35=dict(type='str',),cpu_36=dict(type='str',),cpu_37=dict(type='str',),cpu_30=dict(type='str',),cpu_31=dict(type='str',),cpu_32=dict(type='str',),cpu_33=dict(type='str',),cpu_38=dict(type='str',),cpu_39=dict(type='str',),cpu_56=dict(type='str',),cpu_57=dict(type='str',),cpu_54=dict(type='str',),cpu_55=dict(type='str',),cpu_52=dict(type='str',),cpu_53=dict(type='str',),cpu_50=dict(type='str',),cpu_51=dict(type='str',),cpu_12=dict(type='str',),cpu_13=dict(type='str',),cpu_10=dict(type='str',),cpu_11=dict(type='str',),cpu_16=dict(type='str',),cpu_17=dict(type='str',),cpu_58=dict(type='str',),cpu_15=dict(type='str',),cpu_1=dict(type='str',),cpu_2=dict(type='str',),cpu_3=dict(type='str',),cpu_4=dict(type='str',),cpu_5=dict(type='str',),cpu_6=dict(type='str',),cpu_7=dict(type='str',),cpu_8=dict(type='str',),cpu_9=dict(type='str',),ctrl_cpu_number=dict(type='str',),cpu_59=dict(type='str',)),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/system/control-cpu"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/control-cpu"

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

def report_changes(module, result, existing_config):
    if existing_config:
        result["changed"] = True
    return result

def create(module, result):
    try:
        post_result = module.client.post(new_url(module))
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
    try:
        post_result = module.client.post(existing_url(module))
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
    if module.check_mode:
        return report_changes(module, result, existing_config)
    if not existing_config:
        return create(module, result)
    else:
        return update(module, result, existing_config)

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

def replace(module, result, existing_config):
    try:
        post_result = module.client.put(existing_url(module))
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
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result, existing_config)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
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