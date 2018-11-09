#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_aam_authentication_portal_change_password
description:
    - None
short_description: Configures A10 aam.authentication.portal.change-password
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
    username_var:
        description:
        - "None"
        required: False
    new_pwd_cfg:
        description:
        - "Field new_pwd_cfg"
        required: False
        suboptions:
            new_password:
                description:
                - "None"
            new_size:
                description:
                - "None"
            new_font:
                description:
                - "None"
            new_text:
                description:
                - "None"
            new_color:
                description:
                - "None"
            new_color_value:
                description:
                - "None"
            new_color_name:
                description:
                - "None"
            new_font_custom:
                description:
                - "None"
            new_face:
                description:
                - "None"
    submit_text:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
        required: False
    confirm_password_var:
        description:
        - "None"
        required: False
    title_cfg:
        description:
        - "Field title_cfg"
        required: False
        suboptions:
            title_color:
                description:
                - "None"
            title:
                description:
                - "None"
            title_color_name:
                description:
                - "None"
            title_font_custom:
                description:
                - "None"
            title_face:
                description:
                - "None"
            title_color_value:
                description:
                - "None"
            title_size:
                description:
                - "None"
            title_text:
                description:
                - "None"
            title_font:
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
    new_password_var:
        description:
        - "None"
        required: False
    old_pwd_cfg:
        description:
        - "Field old_pwd_cfg"
        required: False
        suboptions:
            old_face:
                description:
                - "None"
            old_color:
                description:
                - "None"
            old_color_value:
                description:
                - "None"
            old_password:
                description:
                - "None"
            old_color_name:
                description:
                - "None"
            old_size:
                description:
                - "None"
            old_text:
                description:
                - "None"
            old_font_custom:
                description:
                - "None"
            old_font:
                description:
                - "None"
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
    old_password_var:
        description:
        - "None"
        required: False
    cfm_pwd_cfg:
        description:
        - "Field cfm_pwd_cfg"
        required: False
        suboptions:
            cfm_color_name:
                description:
                - "None"
            cfm_face:
                description:
                - "None"
            cfm_color_value:
                description:
                - "None"
            cfm_font_custom:
                description:
                - "None"
            cfm_size:
                description:
                - "None"
            cfm_font:
                description:
                - "None"
            cfm_text:
                description:
                - "None"
            confirm_password:
                description:
                - "None"
            cfm_color:
                description:
                - "None"
    reset_text:
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
AVAILABLE_PROPERTIES = ["action_url","background","cfm_pwd_cfg","confirm_password_var","new_password_var","new_pwd_cfg","old_password_var","old_pwd_cfg","reset_text","submit_text","title_cfg","username_cfg","username_var","uuid",]

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
        username_var=dict(type='str',),
        new_pwd_cfg=dict(type='dict',new_password=dict(type='bool',),new_size=dict(type='int',),new_font=dict(type='bool',),new_text=dict(type='str',),new_color=dict(type='bool',),new_color_value=dict(type='str',),new_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),new_font_custom=dict(type='str',),new_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana'])),
        submit_text=dict(type='str',),
        uuid=dict(type='str',),
        confirm_password_var=dict(type='str',),
        title_cfg=dict(type='dict',title_color=dict(type='bool',),title=dict(type='bool',),title_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),title_font_custom=dict(type='str',),title_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),title_color_value=dict(type='str',),title_size=dict(type='int',),title_text=dict(type='str',),title_font=dict(type='bool',)),
        username_cfg=dict(type='dict',username=dict(type='bool',),user_font=dict(type='bool',),user_text=dict(type='str',),user_size=dict(type='int',),user_color_value=dict(type='str',),user_font_custom=dict(type='str',),user_color=dict(type='bool',),user_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),user_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow'])),
        new_password_var=dict(type='str',),
        old_pwd_cfg=dict(type='dict',old_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),old_color=dict(type='bool',),old_color_value=dict(type='str',),old_password=dict(type='bool',),old_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),old_size=dict(type='int',),old_text=dict(type='str',),old_font_custom=dict(type='str',),old_font=dict(type='bool',)),
        background=dict(type='dict',bgfile=dict(type='str',),bgstyle=dict(type='str',choices=['tile','stretch','fit']),bgcolor_value=dict(type='str',),bgcolor_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow'])),
        old_password_var=dict(type='str',),
        cfm_pwd_cfg=dict(type='dict',cfm_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),cfm_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),cfm_color_value=dict(type='str',),cfm_font_custom=dict(type='str',),cfm_size=dict(type='int',),cfm_font=dict(type='bool',),cfm_text=dict(type='str',),confirm_password=dict(type='bool',),cfm_color=dict(type='bool',)),
        reset_text=dict(type='str',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authentication/portal/{name}/change-password"
    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/portal/{name}/change-password"
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
    payload = build_json("change-password", module)
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
    payload = build_json("change-password", module)
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