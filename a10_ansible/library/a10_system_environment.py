#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_system_environment
description:
    - Field environment
short_description: Configures A10 system.environment
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
    device_id:
        description:
        - Device ID for configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            fan4a_value:
                description:
                - "Field fan4a_value"
            physical_temperature2:
                description:
                - "Field physical_temperature2"
            fan3a_report:
                description:
                - "Field fan3a_report"
            fan6a_value:
                description:
                - "Field fan6a_value"
            fan2b_value:
                description:
                - "Field fan2b_value"
            fan5a_report:
                description:
                - "Field fan5a_report"
            power_unit3:
                description:
                - "Field power_unit3"
            power_unit2:
                description:
                - "Field power_unit2"
            fan8a_report:
                description:
                - "Field fan8a_report"
            voltage_label_17:
                description:
                - "Field voltage_label_17"
            voltage_label_16:
                description:
                - "Field voltage_label_16"
            voltage_label_15:
                description:
                - "Field voltage_label_15"
            voltage_label_14:
                description:
                - "Field voltage_label_14"
            voltage_label_13:
                description:
                - "Field voltage_label_13"
            voltage_label_12:
                description:
                - "Field voltage_label_12"
            voltage_label_11:
                description:
                - "Field voltage_label_11"
            voltage_label_10:
                description:
                - "Field voltage_label_10"
            fan7b_value:
                description:
                - "Field fan7b_value"
            fan6b_report:
                description:
                - "Field fan6b_report"
            fan9a_report:
                description:
                - "Field fan9a_report"
            physical_temperature:
                description:
                - "Field physical_temperature"
            fan9a_value:
                description:
                - "Field fan9a_value"
            fan10a_value:
                description:
                - "Field fan10a_value"
            fan2a_value:
                description:
                - "Field fan2a_value"
            fan3a_value:
                description:
                - "Field fan3a_value"
            fan8b_report:
                description:
                - "Field fan8b_report"
            power_unit1:
                description:
                - "Field power_unit1"
            fan2a_report:
                description:
                - "Field fan2a_report"
            fan6b_value:
                description:
                - "Field fan6b_value"
            fan7a_value:
                description:
                - "Field fan7a_value"
            fan5b_report:
                description:
                - "Field fan5b_report"
            fan5a_value:
                description:
                - "Field fan5a_value"
            fan10b_report:
                description:
                - "Field fan10b_report"
            fan5b_value:
                description:
                - "Field fan5b_value"
            fan7b_report:
                description:
                - "Field fan7b_report"
            fan1b_value:
                description:
                - "Field fan1b_value"
            fan4b_value:
                description:
                - "Field fan4b_value"
            fan8a_value:
                description:
                - "Field fan8a_value"
            fan6a_report:
                description:
                - "Field fan6a_report"
            fan9b_report:
                description:
                - "Field fan9b_report"
            power_unit4:
                description:
                - "Field power_unit4"
            fan1b_report:
                description:
                - "Field fan1b_report"
            fan3b_value:
                description:
                - "Field fan3b_value"
            fan10b_value:
                description:
                - "Field fan10b_value"
            fan7a_report:
                description:
                - "Field fan7a_report"
            fan1a_value:
                description:
                - "Field fan1a_value"
            fan10a_report:
                description:
                - "Field fan10a_report"
            fan8b_value:
                description:
                - "Field fan8b_value"
            fan2b_report:
                description:
                - "Field fan2b_report"
            fan4b_report:
                description:
                - "Field fan4b_report"
            fan9b_value:
                description:
                - "Field fan9b_value"
            voltage_label_3:
                description:
                - "Field voltage_label_3"
            voltage_label_2:
                description:
                - "Field voltage_label_2"
            voltage_label_1:
                description:
                - "Field voltage_label_1"
            voltage_label_7:
                description:
                - "Field voltage_label_7"
            voltage_label_6:
                description:
                - "Field voltage_label_6"
            voltage_label_5:
                description:
                - "Field voltage_label_5"
            voltage_label_4:
                description:
                - "Field voltage_label_4"
            fan1a_report:
                description:
                - "Field fan1a_report"
            fan4a_report:
                description:
                - "Field fan4a_report"
            voltage_label_9:
                description:
                - "Field voltage_label_9"
            voltage_label_8:
                description:
                - "Field voltage_label_8"
            fan3b_report:
                description:
                - "Field fan3b_report"
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
AVAILABLE_PROPERTIES = ["oper","uuid",]

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
        device_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict',fan4a_value=dict(type='int',),physical_temperature2=dict(type='str',),fan3a_report=dict(type='str',),fan6a_value=dict(type='int',),fan2b_value=dict(type='int',),fan5a_report=dict(type='str',),power_unit3=dict(type='str',),power_unit2=dict(type='str',),fan8a_report=dict(type='str',),voltage_label_17=dict(type='str',),voltage_label_16=dict(type='str',),voltage_label_15=dict(type='str',),voltage_label_14=dict(type='str',),voltage_label_13=dict(type='str',),voltage_label_12=dict(type='str',),voltage_label_11=dict(type='str',),voltage_label_10=dict(type='str',),fan7b_value=dict(type='int',),fan6b_report=dict(type='str',),fan9a_report=dict(type='str',),physical_temperature=dict(type='str',),fan9a_value=dict(type='int',),fan10a_value=dict(type='int',),fan2a_value=dict(type='int',),fan3a_value=dict(type='int',),fan8b_report=dict(type='str',),power_unit1=dict(type='str',),fan2a_report=dict(type='str',),fan6b_value=dict(type='int',),fan7a_value=dict(type='int',),fan5b_report=dict(type='str',),fan5a_value=dict(type='int',),fan10b_report=dict(type='str',),fan5b_value=dict(type='int',),fan7b_report=dict(type='str',),fan1b_value=dict(type='int',),fan4b_value=dict(type='int',),fan8a_value=dict(type='int',),fan6a_report=dict(type='str',),fan9b_report=dict(type='str',),power_unit4=dict(type='str',),fan1b_report=dict(type='str',),fan3b_value=dict(type='int',),fan10b_value=dict(type='int',),fan7a_report=dict(type='str',),fan1a_value=dict(type='int',),fan10a_report=dict(type='str',),fan8b_value=dict(type='int',),fan2b_report=dict(type='str',),fan4b_report=dict(type='str',),fan9b_value=dict(type='int',),voltage_label_3=dict(type='str',),voltage_label_2=dict(type='str',),voltage_label_1=dict(type='str',),voltage_label_7=dict(type='str',),voltage_label_6=dict(type='str',),voltage_label_5=dict(type='str',),voltage_label_4=dict(type='str',),fan1a_report=dict(type='str',),fan4a_report=dict(type='str',),voltage_label_9=dict(type='str',),voltage_label_8=dict(type='str',),fan3b_report=dict(type='str',)),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/system/environment"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/environment"

    f_dict = {}

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

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

def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k,v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v 
        return module.client.get(oper_url(module),
                                 params=query_params)
    return module.client.get(oper_url(module))

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
    device_id = module.params["device_id"]

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
    
    if device_id:
        module.client.change_context(device_id)

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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
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