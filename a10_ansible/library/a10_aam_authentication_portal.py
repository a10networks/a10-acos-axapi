#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_aam_authentication_portal
description:
    - Authentication portal configuration
short_description: Configures A10 aam.authentication.portal
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
    name:
        description:
        - "'default-portal'= Default portal configuration; "
        required: True
    logon_fail:
        description:
        - "Field logon_fail"
        required: False
        suboptions:
            fail_msg_cfg:
                description:
                - "Field fail_msg_cfg"
            background:
                description:
                - "Field background"
            title_cfg:
                description:
                - "Field title_cfg"
            uuid:
                description:
                - "uuid of the object"
    logo_cfg:
        description:
        - "Field logo_cfg"
        required: False
        suboptions:
            logo:
                description:
                - "Specify logo image filename"
            width:
                description:
                - "Specify logo image width (Default= 134)"
            height:
                description:
                - "Specify logo image height (Default= 71)"
    user_tag:
        description:
        - "Customized tag"
        required: False
    notify_change_password:
        description:
        - "Field notify_change_password"
        required: False
        suboptions:
            old_pwd_cfg:
                description:
                - "Field old_pwd_cfg"
            username_var:
                description:
                - "Specify username variable name in default change password notification page (Default= cp_usr)"
            new_pwd_cfg:
                description:
                - "Field new_pwd_cfg"
            uuid:
                description:
                - "uuid of the object"
            cfm_pwd_cfg:
                description:
                - "Field cfm_pwd_cfg"
            confirm_password_var:
                description:
                - "Specify confirm password variable name in default change password notification page (Default= cp_cfm_pwd)"
            new_password_var:
                description:
                - "Specify new password variable name in default change password notification page (Default= cp_new_pwd)"
            change_url:
                description:
                - "Specify change password action URL in default change password notification page (Default= /notify_change.fo)"
            continue_url:
                description:
                - "Specify continue action URL in default change password notification page (Default= /continue.fo)"
            background:
                description:
                - "Field background"
            old_password_var:
                description:
                - "Specify old password variable name in default change password notification page (Default= cp_old_pwd)"
            change_text:
                description:
                - "Specify change button text in default change password notification page (Default= Change)"
            continue_text:
                description:
                - "Specify continue button text in default change password notification page (Default= Continue)"
            username_cfg:
                description:
                - "Field username_cfg"
    logon:
        description:
        - "Field logon"
        required: False
        suboptions:
            action_url:
                description:
                - "Specify form action URL in default logon page (Default= /logon.fo)"
            submit_text:
                description:
                - "Specify submit button text in default logon page (Default= Log In)"
            passcode_cfg:
                description:
                - "Field passcode_cfg"
            username_cfg:
                description:
                - "Field username_cfg"
            username_var:
                description:
                - "Specify username variable name in default logon page (Default= user)"
            password_var:
                description:
                - "Specify password variable name in default logon page (Default= pwd)"
            background:
                description:
                - "Field background"
            passcode_var:
                description:
                - "Specify passcode variable name in default logon page (Default= passcode)"
            fail_msg_cfg:
                description:
                - "Field fail_msg_cfg"
            password_cfg:
                description:
                - "Field password_cfg"
            enable_passcode:
                description:
                - "Enable passcode field in default logon page"
            uuid:
                description:
                - "uuid of the object"
    change_password:
        description:
        - "Field change_password"
        required: False
        suboptions:
            action_url:
                description:
                - "Specify form action URL in default change password page (Default= /change.fo)"
            username_var:
                description:
                - "Specify username variable name in default change password page (Default= cp_usr)"
            new_pwd_cfg:
                description:
                - "Field new_pwd_cfg"
            submit_text:
                description:
                - "Specify submit button text in default change password page (Default= Submit)"
            uuid:
                description:
                - "uuid of the object"
            confirm_password_var:
                description:
                - "Specify confirm password variable name in default change password page (Default= cp_cfm_pwd)"
            title_cfg:
                description:
                - "Field title_cfg"
            username_cfg:
                description:
                - "Field username_cfg"
            new_password_var:
                description:
                - "Specify new password variable name in default change password page (Default= cp_new_pwd)"
            old_pwd_cfg:
                description:
                - "Field old_pwd_cfg"
            background:
                description:
                - "Field background"
            old_password_var:
                description:
                - "Specify old password variable name in default change password page (Default= cp_old_pwd)"
            cfm_pwd_cfg:
                description:
                - "Field cfm_pwd_cfg"
            reset_text:
                description:
                - "Specify reset button text in default change password page (Default= Reset)"
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
AVAILABLE_PROPERTIES = ["change_password","logo_cfg","logon","logon_fail","name","notify_change_password","user_tag","uuid",]

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
        name=dict(type='str',required=True,choices=['default-portal']),
        logon_fail=dict(type='dict',fail_msg_cfg=dict(type='dict',fail_font_custom=dict(type='str',),fail_color=dict(type='bool',),fail_size=dict(type='int',),fail_msg=dict(type='bool',),fail_text=dict(type='str',),fail_color_value=dict(type='str',),fail_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),fail_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),fail_font=dict(type='bool',)),background=dict(type='dict',bgfile=dict(type='str',),bgstyle=dict(type='str',choices=['tile','stretch','fit']),bgcolor_value=dict(type='str',),bgcolor_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow'])),title_cfg=dict(type='dict',title_color=dict(type='bool',),title=dict(type='bool',),title_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),title_font_custom=dict(type='str',),title_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),title_color_value=dict(type='str',),title_size=dict(type='int',),title_text=dict(type='str',),title_font=dict(type='bool',)),uuid=dict(type='str',)),
        logo_cfg=dict(type='dict',logo=dict(type='str',),width=dict(type='int',),height=dict(type='int',)),
        user_tag=dict(type='str',),
        notify_change_password=dict(type='dict',old_pwd_cfg=dict(type='dict',old_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),old_color=dict(type='bool',),old_color_value=dict(type='str',),old_password=dict(type='bool',),old_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),old_size=dict(type='int',),old_text=dict(type='str',),old_font_custom=dict(type='str',),old_font=dict(type='bool',)),username_var=dict(type='str',),new_pwd_cfg=dict(type='dict',new_password=dict(type='bool',),new_size=dict(type='int',),new_font=dict(type='bool',),new_text=dict(type='str',),new_color=dict(type='bool',),new_color_value=dict(type='str',),new_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),new_font_custom=dict(type='str',),new_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana'])),uuid=dict(type='str',),cfm_pwd_cfg=dict(type='dict',cfm_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),cfm_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),cfm_color_value=dict(type='str',),cfm_font_custom=dict(type='str',),cfm_size=dict(type='int',),cfm_font=dict(type='bool',),cfm_text=dict(type='str',),confirm_password=dict(type='bool',),cfm_color=dict(type='bool',)),confirm_password_var=dict(type='str',),new_password_var=dict(type='str',),change_url=dict(type='str',),continue_url=dict(type='str',),background=dict(type='dict',bgfile=dict(type='str',),bgstyle=dict(type='str',choices=['tile','stretch','fit']),bgcolor_value=dict(type='str',),bgcolor_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow'])),old_password_var=dict(type='str',),change_text=dict(type='str',),continue_text=dict(type='str',),username_cfg=dict(type='dict',username=dict(type='bool',),user_font=dict(type='bool',),user_text=dict(type='str',),user_size=dict(type='int',),user_color_value=dict(type='str',),user_font_custom=dict(type='str',),user_color=dict(type='bool',),user_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),user_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']))),
        logon=dict(type='dict',action_url=dict(type='str',),submit_text=dict(type='str',),passcode_cfg=dict(type='dict',passcode_font_custom=dict(type='str',),passcode_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),passcode_color=dict(type='bool',),passcode_text=dict(type='str',),passcode_color_value=dict(type='str',),passcode_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),passcode_font=dict(type='bool',),passcode=dict(type='bool',),passcode_size=dict(type='int',)),username_cfg=dict(type='dict',username=dict(type='bool',),user_font=dict(type='bool',),user_text=dict(type='str',),user_size=dict(type='int',),user_color_value=dict(type='str',),user_font_custom=dict(type='str',),user_color=dict(type='bool',),user_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),user_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow'])),username_var=dict(type='str',),password_var=dict(type='str',),background=dict(type='dict',bgfile=dict(type='str',),bgstyle=dict(type='str',choices=['tile','stretch','fit']),bgcolor_value=dict(type='str',),bgcolor_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow'])),passcode_var=dict(type='str',),fail_msg_cfg=dict(type='dict',fail_font_custom=dict(type='str',),fail_color=dict(type='bool',),fail_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),fail_size=dict(type='int',),fail_msg=dict(type='bool',),fail_text=dict(type='str',),fail_color_value=dict(type='str',),fail_font=dict(type='bool',),fail_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),authz_fail_msg=dict(type='str',)),password_cfg=dict(type='dict',pass_color_value=dict(type='str',),password=dict(type='bool',),pass_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),pass_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),pass_font_custom=dict(type='str',),pass_size=dict(type='int',),pass_text=dict(type='str',),pass_font=dict(type='bool',),pass_color=dict(type='bool',)),enable_passcode=dict(type='bool',),uuid=dict(type='str',)),
        change_password=dict(type='dict',action_url=dict(type='str',),username_var=dict(type='str',),new_pwd_cfg=dict(type='dict',new_password=dict(type='bool',),new_size=dict(type='int',),new_font=dict(type='bool',),new_text=dict(type='str',),new_color=dict(type='bool',),new_color_value=dict(type='str',),new_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),new_font_custom=dict(type='str',),new_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana'])),submit_text=dict(type='str',),uuid=dict(type='str',),confirm_password_var=dict(type='str',),title_cfg=dict(type='dict',title_color=dict(type='bool',),title=dict(type='bool',),title_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),title_font_custom=dict(type='str',),title_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),title_color_value=dict(type='str',),title_size=dict(type='int',),title_text=dict(type='str',),title_font=dict(type='bool',)),username_cfg=dict(type='dict',username=dict(type='bool',),user_font=dict(type='bool',),user_text=dict(type='str',),user_size=dict(type='int',),user_color_value=dict(type='str',),user_font_custom=dict(type='str',),user_color=dict(type='bool',),user_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),user_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow'])),new_password_var=dict(type='str',),old_pwd_cfg=dict(type='dict',old_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),old_color=dict(type='bool',),old_color_value=dict(type='str',),old_password=dict(type='bool',),old_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),old_size=dict(type='int',),old_text=dict(type='str',),old_font_custom=dict(type='str',),old_font=dict(type='bool',)),background=dict(type='dict',bgfile=dict(type='str',),bgstyle=dict(type='str',choices=['tile','stretch','fit']),bgcolor_value=dict(type='str',),bgcolor_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow'])),old_password_var=dict(type='str',),cfm_pwd_cfg=dict(type='dict',cfm_color_name=dict(type='str',choices=['aqua','black','blue','fuchsia','gray','green','lime','maroon','navy','olive','orange','purple','red','silver','teal','white','yellow']),cfm_face=dict(type='str',choices=['Arial','Courier_New','Georgia','Times_New_Roman','Verdana']),cfm_color_value=dict(type='str',),cfm_font_custom=dict(type='str',),cfm_size=dict(type='int',),cfm_font=dict(type='bool',),cfm_text=dict(type='str',),confirm_password=dict(type='bool',),cfm_color=dict(type='bool',)),reset_text=dict(type='str',)),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authentication/portal/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/portal/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["portal"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["portal"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["portal"][k] = v
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
    payload = build_json("portal", module)
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
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result, existing_config)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
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