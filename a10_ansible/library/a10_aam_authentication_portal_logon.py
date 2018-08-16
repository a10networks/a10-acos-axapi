#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_aam_authentication_portal_logon
description:
    - None
short_description: Configures A10 aam.authentication.portal.logon
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
    action_url:
        description:
        - "None"
        required: False
    submit_text:
        description:
        - "None"
        required: False
    passcode_cfg:
        description:
        - "Field passcode_cfg"
        required: False
        suboptions:
            passcode_font_custom:
                description:
                - "None"
            passcode_face:
                description:
                - "None"
            passcode_color:
                description:
                - "None"
            passcode_text:
                description:
                - "None"
            passcode_color_value:
                description:
                - "None"
            passcode_color_name:
                description:
                - "None"
            passcode_font:
                description:
                - "None"
            passcode:
                description:
                - "None"
            passcode_size:
                description:
                - "None"
    username_cfg:
        description:
        - "Field username_cfg"
        required: False
        suboptions:
            username:
                description:
                - "None"
            user_font:
                description:
                - "None"
            user_text:
                description:
                - "None"
            user_size:
                description:
                - "None"
            user_color_value:
                description:
                - "None"
            user_font_custom:
                description:
                - "None"
            user_color:
                description:
                - "None"
            user_face:
                description:
                - "None"
            user_color_name:
                description:
                - "None"
    username_var:
        description:
        - "None"
        required: False
    password_var:
        description:
        - "None"
        required: False
    background:
        description:
        - "Field background"
        required: False
        suboptions:
            bgfile:
                description:
                - "None"
            bgstyle:
                description:
                - "None"
            bgcolor_value:
                description:
                - "None"
            bgcolor_name:
                description:
                - "None"
    passcode_var:
        description:
        - "None"
        required: False
    fail_msg_cfg:
        description:
        - "Field fail_msg_cfg"
        required: False
        suboptions:
            fail_font_custom:
                description:
                - "None"
            fail_color:
                description:
                - "None"
            fail_face:
                description:
                - "None"
            fail_size:
                description:
                - "None"
            fail_msg:
                description:
                - "None"
            fail_text:
                description:
                - "None"
            fail_color_value:
                description:
                - "None"
            fail_font:
                description:
                - "None"
            fail_color_name:
                description:
                - "None"
            authz_fail_msg:
                description:
                - "None"
    password_cfg:
        description:
        - "Field password_cfg"
        required: False
        suboptions:
            pass_color_value:
                description:
                - "None"
            password:
                description:
                - "None"
            pass_color_name:
                description:
                - "None"
            pass_face:
                description:
                - "None"
            pass_font_custom:
                description:
                - "None"
            pass_size:
                description:
                - "None"
            pass_text:
                description:
                - "None"
            pass_font:
                description:
                - "None"
            pass_color:
                description:
                - "None"
    enable_passcode:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
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
AVAILABLE_PROPERTIES = ["action_url","background","enable_passcode","fail_msg_cfg","passcode_cfg","passcode_var","password_cfg","password_var","submit_text","username_cfg","username_var","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        action_url=dict(type='str',),
        submit_text=dict(type='str',),
        passcode_cfg=dict(type='dict',passcode_font_custom=dict(type='str',),passcode_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),passcode_color=dict(type='bool',),passcode_text=dict(type='str',),passcode_color_value=dict(type='str',),passcode_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),passcode_font=dict(type='bool',),passcode=dict(type='bool',),passcode_size=dict(type='int',)),
        username_cfg=dict(type='dict',username=dict(type='bool',),user_font=dict(type='bool',),user_text=dict(type='str',),user_size=dict(type='int',),user_color_value=dict(type='str',),user_font_custom=dict(type='str',),user_color=dict(type='bool',),user_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),user_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow'])),
        username_var=dict(type='str',),
        password_var=dict(type='str',),
        background=dict(type='dict',bgfile=dict(type='str',),bgstyle=dict(type='str',choices=['tile','stretch','fit']),bgcolor_value=dict(type='str',),bgcolor_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow'])),
        passcode_var=dict(type='str',),
        fail_msg_cfg=dict(type='dict',fail_font_custom=dict(type='str',),fail_color=dict(type='bool',),fail_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),fail_size=dict(type='int',),fail_msg=dict(type='bool',),fail_text=dict(type='str',),fail_color_value=dict(type='str',),fail_font=dict(type='bool',),fail_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),authz_fail_msg=dict(type='str',)),
        password_cfg=dict(type='dict',pass_color_value=dict(type='str',),password=dict(type='bool',),pass_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),pass_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),pass_font_custom=dict(type='str',),pass_size=dict(type='int',),pass_text=dict(type='str',),pass_font=dict(type='bool',),pass_color=dict(type='bool',)),
        enable_passcode=dict(type='bool',),
        uuid=dict(type='str',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authentication/portal/{name}/logon"
    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/portal/{name}/logon"
    f_dict = {}

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
        if isinstance(v, list):
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
            if isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
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

def get(module):
    return module.client.get(existing_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("logon", module)
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

def update(module, result, existing_config):
    payload = build_json("logon", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
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

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
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