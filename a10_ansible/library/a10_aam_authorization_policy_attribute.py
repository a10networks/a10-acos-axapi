#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_attribute
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    attr-num:
        description:
            - Set attribute ID for authorization policy
    
    attribute-name:
        description:
            - Specify attribute name
    
    attr-type:
        description:
            - Specify attribute type
    
    string-type:
        description:
            - Attribute type is string
    
    integer-type:
        description:
            - Attribute type is integer
    
    ip-type:
        description:
            - IP address is transformed into network byte order
    
    attr-str:
        description:
            - 'match': Operation type is match; 'sub-string': Operation type is sub-string; choices:['match', 'sub-string']
    
    attr-str-val:
        description:
            - Set attribute value
    
    attr-int:
        description:
            - 'equal': Operation type is equal; 'not-equal': Operation type is not equal; 'less-than': Operation type is less-than; 'more-than': Operation type is more-than; 'less-than-equal-to': Operation type is less-than-equal-to; 'more-than-equal-to': Operation type is more-thatn-equal-to; choices:['equal', 'not-equal', 'less-than', 'more-than', 'less-than-equal-to', 'more-than-equal-to']
    
    attr-int-val:
        description:
            - Set attribute value
    
    attr-ip:
        description:
            - 'equal': Operation type is equal; 'not-equal': Operation type is not-equal; choices:['equal', 'not-equal']
    
    attr-ipv4:
        description:
            - IPv4 address
    
    A10-AX-AUTH-URI:
        description:
            - Custom-defined attribute
    
    custom-attr-type:
        description:
            - Specify attribute type
    
    custom-attr-str:
        description:
            - 'match': Operation type is match; 'sub-string': Operation type is sub-string; choices:['match', 'sub-string']
    
    a10-dynamic-defined:
        description:
            - The value of this attribute will depend on AX configuration instead of user configuration
    
    uuid:
        description:
            - uuid of the object
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"A10_AX_AUTH_URI","a10_dynamic_defined","attr_int","attr_int_val","attr_ip","attr_ipv4","attr_num","attr_str","attr_str_val","attr_type","attribute_name","custom_attr_str","custom_attr_type","integer_type","ip_type","string_type","uuid",}

# our imports go at the top so we fail fast.
from a10_ansible.axapi_http import client_factory
from a10_ansible import errors as a10_ex

def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        
        A10_AX_AUTH_URI=dict(
            type='str' 
        ),
        a10_dynamic_defined=dict(
            type='str' 
        ),
        attr_int=dict(
            type='enum' , choices=['equal', 'not-equal', 'less-than', 'more-than', 'less-than-equal-to', 'more-than-equal-to']
        ),
        attr_int_val=dict(
            type='str' 
        ),
        attr_ip=dict(
            type='enum' , choices=['equal', 'not-equal']
        ),
        attr_ipv4=dict(
            type='str' 
        ),
        attr_num=dict(
            type='str' , required=True
        ),
        attr_str=dict(
            type='enum' , choices=['match', 'sub-string']
        ),
        attr_str_val=dict(
            type='str' 
        ),
        attr_type=dict(
            type='str' 
        ),
        attribute_name=dict(
            type='str' 
        ),
        custom_attr_str=dict(
            type='enum' , choices=['match', 'sub-string']
        ),
        custom_attr_type=dict(
            type='str' 
        ),
        integer_type=dict(
            type='str' 
        ),
        ip_type=dict(
            type='str' 
        ),
        string_type=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authorization/policy/{name}/attribute/{attr-num}"
    f_dict = {}
    
    f_dict["attr-num"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authorization/policy/{name}/attribute/{attr-num}"
    f_dict = {}
    
    f_dict["attr-num"] = module.params["attr-num"]

    return url_base.format(**f_dict)


def build_envelope(title, data):
    return {
        title: data
    }

def build_json(title, module):
    rv = {}
    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v:
            rx = x.replace("_", "-")
            rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if params.get(x)])
    
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

def exists(module):
    try:
        module.client.get(existing_url(module))
        return True
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("attribute", module)
    try:
        post_result = module.client.post(new_url(module), payload)
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

def update(module, result):
    payload = build_json("attribute", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
        result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result):
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result)

def absent(module, result):
    return delete(module, result)



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
    # TODO(remove hardcoded port #)
    a10_port = 443
    a10_protocol = "https"

    valid, validation_errors = validate(module.params)
    map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)

    if state == 'present':
        result = present(module, result)
    elif state == 'absent':
        result = absent(module, result)
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