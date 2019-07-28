#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_aam_authorization_policy_attribute
description:
    - Authorization-policy attribute configuration
short_description: Configures A10 aam.authorization.policy.attribute
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
    policy_name:
        description:
        - Key to identify parent object
    attribute_name:
        description:
        - "Specify attribute name"
        required: False
    integer_type:
        description:
        - "Attribute type is integer"
        required: False
    custom_attr_type:
        description:
        - "Specify attribute type"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    string_type:
        description:
        - "Attribute type is string"
        required: False
    attr_str_val:
        description:
        - "Set attribute value"
        required: False
    attr_ipv4:
        description:
        - "IPv4 address"
        required: False
    attr_type:
        description:
        - "Specify attribute type"
        required: False
    attr_num:
        description:
        - "Set attribute ID for authorization policy"
        required: True
    a10_dynamic_defined:
        description:
        - "The value of this attribute will depend on AX configuration instead of user configuration"
        required: False
    attr_int:
        description:
        - "'equal'= Operation type is equal; 'not-equal'= Operation type is not equal; 'less-than'= Operation type is less-than; 'more-than'= Operation type is more-than; 'less-than-equal-to'= Operation type is less-than-equal-to; 'more-than-equal-to'= Operation type is more-thatn-equal-to; "
        required: False
    ip_type:
        description:
        - "IP address is transformed into network byte order"
        required: False
    attr_ip:
        description:
        - "'equal'= Operation type is equal; 'not-equal'= Operation type is not-equal; "
        required: False
    A10_AX_AUTH_URI:
        description:
        - "Custom-defined attribute"
        required: False
    attr_str:
        description:
        - "'match'= Operation type is match; 'sub-string'= Operation type is sub-string; "
        required: False
    any:
        description:
        - "Matched when attribute is present (with any value)."
        required: False
    custom_attr_str:
        description:
        - "'match'= Operation type is match; 'sub-string'= Operation type is sub-string; "
        required: False
    attr_int_val:
        description:
        - "Set attribute value"
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
AVAILABLE_PROPERTIES = ["A10_AX_AUTH_URI","a10_dynamic_defined","any","attr_int","attr_int_val","attr_ip","attr_ipv4","attr_num","attr_str","attr_str_val","attr_type","attribute_name","custom_attr_str","custom_attr_type","integer_type","ip_type","string_type","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        partition=dict(type='str', required=False)
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        attribute_name=dict(type='str',),
        integer_type=dict(type='bool',),
        custom_attr_type=dict(type='bool',),
        uuid=dict(type='str',),
        string_type=dict(type='bool',),
        attr_str_val=dict(type='str',),
        attr_ipv4=dict(type='str',),
        attr_type=dict(type='bool',),
        attr_num=dict(type='int',required=True,),
        a10_dynamic_defined=dict(type='bool',),
        attr_int=dict(type='str',choices=['equal','not-equal','less-than','more-than','less-than-equal-to','more-than-equal-to']),
        ip_type=dict(type='bool',),
        attr_ip=dict(type='str',choices=['equal','not-equal']),
        A10_AX_AUTH_URI=dict(type='bool',),
        attr_str=dict(type='str',choices=['match','sub-string']),
        any=dict(type='bool',),
        custom_attr_str=dict(type='str',choices=['match','sub-string']),
        attr_int_val=dict(type='int',)
    ))
   
    # Parent keys
    rv.update(dict(
        policy_name=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authorization/policy/{policy_name}/attribute/{attr-num}"

    f_dict = {}
    f_dict["attr-num"] = ""
    f_dict["policy_name"] = module.params["policy_name"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authorization/policy/{policy_name}/attribute/{attr-num}"

    f_dict = {}
    f_dict["attr-num"] = module.params["attr_num"]
    f_dict["policy_name"] = module.params["policy_name"]

    return url_base.format(**f_dict)


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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("attribute", module)
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
    payload = build_json("attribute", module)
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
    payload = build_json("attribute", module)
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
        message=""
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