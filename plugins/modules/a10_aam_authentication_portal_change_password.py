#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_aam_authentication_portal_change_password
description:
    - Change password page configuration
short_description: Configures A10 aam.authentication.portal.change-password
author: A10 Networks 2018
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    portal_name:
        description:
        - Key to identify parent object    action_url:
        description:
        - "Specify form action URL in default change password page (Default= /change.fo)"
        required: False
    username_var:
        description:
        - "Specify username variable name in default change password page (Default=
          cp_usr)"
        required: False
    new_pwd_cfg:
        description:
        - "Field new_pwd_cfg"
        required: False
        suboptions:
            new_password:
                description:
                - "Configure new password text in default change password page"
            new_size:
                description:
                - "Specify font size (Default= 3)"
            new_font:
                description:
                - "Sepcify font (Default= Arial)"
            new_text:
                description:
                - "Specify new password text (Default= New Password)"
            new_color:
                description:
                - "Specify font color (Default= black)"
            new_color_value:
                description:
                - "Specify 6-digit HEX color value"
            new_color_name:
                description:
                - "'aqua'= aqua; 'black'= black; 'blue'= blue; 'fuchsia'= fuchsia; 'gray'= gray;
          'green'= green; 'lime'= lime; 'maroon'= maroon; 'navy'= navy; 'olive'= olive;
          'orange'= orange; 'purple'= purple; 'red'= red; 'silver'= silver; 'teal'= teal;
          'white'= white; 'yellow'= yellow;"
            new_font_custom:
                description:
                - "Specify custom font"
            new_face:
                description:
                - "'Arial'= Arial; 'Courier_New'= Courier New; 'Georgia'= Georgia;
          'Times_New_Roman'= Times New Roman; 'Verdana'= Verdana;"
    submit_text:
        description:
        - "Specify submit button text in default change password page (Default= Submit)"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    confirm_password_var:
        description:
        - "Specify confirm password variable name in default change password page
          (Default= cp_cfm_pwd)"
        required: False
    title_cfg:
        description:
        - "Field title_cfg"
        required: False
        suboptions:
            title_color:
                description:
                - "Specify font color (Default= black)"
            title:
                description:
                - "Configure title in default change password page"
            title_color_name:
                description:
                - "'aqua'= aqua; 'black'= black; 'blue'= blue; 'fuchsia'= fuchsia; 'gray'= gray;
          'green'= green; 'lime'= lime; 'maroon'= maroon; 'navy'= navy; 'olive'= olive;
          'orange'= orange; 'purple'= purple; 'red'= red; 'silver'= silver; 'teal'= teal;
          'white'= white; 'yellow'= yellow;"
            title_font_custom:
                description:
                - "Specify custom font"
            title_face:
                description:
                - "'Arial'= Arial; 'Courier_New'= Courier New; 'Georgia'= Georgia;
          'Times_New_Roman'= Times New Roman; 'Verdana'= Verdana;"
            title_color_value:
                description:
                - "Specify 6-digit HEX color value"
            title_size:
                description:
                - "Specify font size (Default= 5)"
            title_text:
                description:
                - "Specify title (Default= Please Change Your Password)"
            title_font:
                description:
                - "Sepcify font (Default= Arial)"
    username_cfg:
        description:
        - "Field username_cfg"
        required: False
        suboptions:
            username:
                description:
                - "Configure username text in default change password page"
            user_font:
                description:
                - "Sepcify font (Default= Arial)"
            user_text:
                description:
                - "Specify username text (Default= Username)"
            user_size:
                description:
                - "Specify font size (Default= 3)"
            user_color_value:
                description:
                - "Specify 6-digit HEX color value"
            user_font_custom:
                description:
                - "Specify custom font"
            user_color:
                description:
                - "Specify font color (Default= black)"
            user_face:
                description:
                - "'Arial'= Arial; 'Courier_New'= Courier New; 'Georgia'= Georgia;
          'Times_New_Roman'= Times New Roman; 'Verdana'= Verdana;"
            user_color_name:
                description:
                - "'aqua'= aqua; 'black'= black; 'blue'= blue; 'fuchsia'= fuchsia; 'gray'= gray;
          'green'= green; 'lime'= lime; 'maroon'= maroon; 'navy'= navy; 'olive'= olive;
          'orange'= orange; 'purple'= purple; 'red'= red; 'silver'= silver; 'teal'= teal;
          'white'= white; 'yellow'= yellow;"
    new_password_var:
        description:
        - "Specify new password variable name in default change password page (Default=
          cp_new_pwd)"
        required: False
    old_pwd_cfg:
        description:
        - "Field old_pwd_cfg"
        required: False
        suboptions:
            old_face:
                description:
                - "'Arial'= Arial; 'Courier_New'= Courier New; 'Georgia'= Georgia;
          'Times_New_Roman'= Times New Roman; 'Verdana'= Verdana;"
            old_color:
                description:
                - "Specify font color (Default= black)"
            old_color_value:
                description:
                - "Specify 6-digit HEX color value"
            old_password:
                description:
                - "Configure old password text in default change password page"
            old_color_name:
                description:
                - "'aqua'= aqua; 'black'= black; 'blue'= blue; 'fuchsia'= fuchsia; 'gray'= gray;
          'green'= green; 'lime'= lime; 'maroon'= maroon; 'navy'= navy; 'olive'= olive;
          'orange'= orange; 'purple'= purple; 'red'= red; 'silver'= silver; 'teal'= teal;
          'white'= white; 'yellow'= yellow;"
            old_size:
                description:
                - "Specify font size (Default= 3)"
            old_text:
                description:
                - "Specify old password text (Default= Old Password)"
            old_font_custom:
                description:
                - "Specify custom font"
            old_font:
                description:
                - "Sepcify font (Default= Arial)"
    background:
        description:
        - "Field background"
        required: False
        suboptions:
            bgfile:
                description:
                - "Specify background image filename"
            bgstyle:
                description:
                - "'tile'= Tile; 'stretch'= Stretch; 'fit'= Fit;"
            bgcolor_value:
                description:
                - "Specify 6-digit HEX color value"
            bgcolor_name:
                description:
                - "'aqua'= aqua; 'black'= black; 'blue'= blue; 'fuchsia'= fuchsia; 'gray'= gray;
          'green'= green; 'lime'= lime; 'maroon'= maroon; 'navy'= navy; 'olive'= olive;
          'orange'= orange; 'purple'= purple; 'red'= red; 'silver'= silver; 'teal'= teal;
          'white'= white; 'yellow'= yellow;"
    old_password_var:
        description:
        - "Specify old password variable name in default change password page (Default=
          cp_old_pwd)"
        required: False
    cfm_pwd_cfg:
        description:
        - "Field cfm_pwd_cfg"
        required: False
        suboptions:
            cfm_color_name:
                description:
                - "'aqua'= aqua; 'black'= black; 'blue'= blue; 'fuchsia'= fuchsia; 'gray'= gray;
          'green'= green; 'lime'= lime; 'maroon'= maroon; 'navy'= navy; 'olive'= olive;
          'orange'= orange; 'purple'= purple; 'red'= red; 'silver'= silver; 'teal'= teal;
          'white'= white; 'yellow'= yellow;"
            cfm_face:
                description:
                - "'Arial'= Arial; 'Courier_New'= Courier New; 'Georgia'= Georgia;
          'Times_New_Roman'= Times New Roman; 'Verdana'= Verdana;"
            cfm_color_value:
                description:
                - "Specify 6-digit HEX color value"
            cfm_font_custom:
                description:
                - "Specify custom font"
            cfm_size:
                description:
                - "Specify font size (Default= 3)"
            cfm_font:
                description:
                - "Sepcify font (Default= Arial)"
            cfm_text:
                description:
                - "Specify confirm password text (Default= Confirm New Password)"
            confirm_password:
                description:
                - "Configure confirm password text in default change password page"
            cfm_color:
                description:
                - "Specify font color (Default= black)"
    reset_text:
        description:
        - "Specify reset button text in default change password page (Default= Reset)"
        required: False

'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "action_url",
    "background",
    "cfm_pwd_cfg",
    "confirm_password_var",
    "new_password_var",
    "new_pwd_cfg",
    "old_password_var",
    "old_pwd_cfg",
    "reset_text",
    "submit_text",
    "title_cfg",
    "username_cfg",
    "username_var",
    "uuid",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str',
                   default="present",
                   choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
            required=False,
        ),
        a10_device_context_id=dict(
            type='int',
            choices=[1, 2, 3, 4, 5, 6, 7, 8],
            required=False,
        ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'action_url': {
            'type': 'str',
        },
        'username_var': {
            'type': 'str',
        },
        'new_pwd_cfg': {
            'type': 'dict',
            'new_password': {
                'type': 'bool',
            },
            'new_size': {
                'type': 'int',
            },
            'new_font': {
                'type': 'bool',
            },
            'new_text': {
                'type': 'str',
            },
            'new_color': {
                'type': 'bool',
            },
            'new_color_value': {
                'type': 'str',
            },
            'new_color_name': {
                'type':
                'str',
                'choices': [
                    'aqua', 'black', 'blue', 'fuchsia', 'gray', 'green',
                    'lime', 'maroon', 'navy', 'olive', 'orange', 'purple',
                    'red', 'silver', 'teal', 'white', 'yellow'
                ]
            },
            'new_font_custom': {
                'type': 'str',
            },
            'new_face': {
                'type':
                'str',
                'choices': [
                    'Arial', 'Courier_New', 'Georgia', 'Times_New_Roman',
                    'Verdana'
                ]
            }
        },
        'submit_text': {
            'type': 'str',
        },
        'uuid': {
            'type': 'str',
        },
        'confirm_password_var': {
            'type': 'str',
        },
        'title_cfg': {
            'type': 'dict',
            'title_color': {
                'type': 'bool',
            },
            'title': {
                'type': 'bool',
            },
            'title_color_name': {
                'type':
                'str',
                'choices': [
                    'aqua', 'black', 'blue', 'fuchsia', 'gray', 'green',
                    'lime', 'maroon', 'navy', 'olive', 'orange', 'purple',
                    'red', 'silver', 'teal', 'white', 'yellow'
                ]
            },
            'title_font_custom': {
                'type': 'str',
            },
            'title_face': {
                'type':
                'str',
                'choices': [
                    'Arial', 'Courier_New', 'Georgia', 'Times_New_Roman',
                    'Verdana'
                ]
            },
            'title_color_value': {
                'type': 'str',
            },
            'title_size': {
                'type': 'int',
            },
            'title_text': {
                'type': 'str',
            },
            'title_font': {
                'type': 'bool',
            }
        },
        'username_cfg': {
            'type': 'dict',
            'username': {
                'type': 'bool',
            },
            'user_font': {
                'type': 'bool',
            },
            'user_text': {
                'type': 'str',
            },
            'user_size': {
                'type': 'int',
            },
            'user_color_value': {
                'type': 'str',
            },
            'user_font_custom': {
                'type': 'str',
            },
            'user_color': {
                'type': 'bool',
            },
            'user_face': {
                'type':
                'str',
                'choices': [
                    'Arial', 'Courier_New', 'Georgia', 'Times_New_Roman',
                    'Verdana'
                ]
            },
            'user_color_name': {
                'type':
                'str',
                'choices': [
                    'aqua', 'black', 'blue', 'fuchsia', 'gray', 'green',
                    'lime', 'maroon', 'navy', 'olive', 'orange', 'purple',
                    'red', 'silver', 'teal', 'white', 'yellow'
                ]
            }
        },
        'new_password_var': {
            'type': 'str',
        },
        'old_pwd_cfg': {
            'type': 'dict',
            'old_face': {
                'type':
                'str',
                'choices': [
                    'Arial', 'Courier_New', 'Georgia', 'Times_New_Roman',
                    'Verdana'
                ]
            },
            'old_color': {
                'type': 'bool',
            },
            'old_color_value': {
                'type': 'str',
            },
            'old_password': {
                'type': 'bool',
            },
            'old_color_name': {
                'type':
                'str',
                'choices': [
                    'aqua', 'black', 'blue', 'fuchsia', 'gray', 'green',
                    'lime', 'maroon', 'navy', 'olive', 'orange', 'purple',
                    'red', 'silver', 'teal', 'white', 'yellow'
                ]
            },
            'old_size': {
                'type': 'int',
            },
            'old_text': {
                'type': 'str',
            },
            'old_font_custom': {
                'type': 'str',
            },
            'old_font': {
                'type': 'bool',
            }
        },
        'background': {
            'type': 'dict',
            'bgfile': {
                'type': 'str',
            },
            'bgstyle': {
                'type': 'str',
                'choices': ['tile', 'stretch', 'fit']
            },
            'bgcolor_value': {
                'type': 'str',
            },
            'bgcolor_name': {
                'type':
                'str',
                'choices': [
                    'aqua', 'black', 'blue', 'fuchsia', 'gray', 'green',
                    'lime', 'maroon', 'navy', 'olive', 'orange', 'purple',
                    'red', 'silver', 'teal', 'white', 'yellow'
                ]
            }
        },
        'old_password_var': {
            'type': 'str',
        },
        'cfm_pwd_cfg': {
            'type': 'dict',
            'cfm_color_name': {
                'type':
                'str',
                'choices': [
                    'aqua', 'black', 'blue', 'fuchsia', 'gray', 'green',
                    'lime', 'maroon', 'navy', 'olive', 'orange', 'purple',
                    'red', 'silver', 'teal', 'white', 'yellow'
                ]
            },
            'cfm_face': {
                'type':
                'str',
                'choices': [
                    'Arial', 'Courier_New', 'Georgia', 'Times_New_Roman',
                    'Verdana'
                ]
            },
            'cfm_color_value': {
                'type': 'str',
            },
            'cfm_font_custom': {
                'type': 'str',
            },
            'cfm_size': {
                'type': 'int',
            },
            'cfm_font': {
                'type': 'bool',
            },
            'cfm_text': {
                'type': 'str',
            },
            'confirm_password': {
                'type': 'bool',
            },
            'cfm_color': {
                'type': 'bool',
            }
        },
        'reset_text': {
            'type': 'str',
        }
    })
    # Parent keys
    rv.update(dict(portal_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/portal/{portal_name}/change-password"

    f_dict = {}
    f_dict["portal_name"] = module.params["portal_name"]

    return url_base.format(**f_dict)


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None


def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")


def _build_dict_from_param(param):
    rv = {}

    for k, v in param.items():
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


def build_envelope(title, data):
    return {title: data}


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authentication/portal/{portal_name}/change-password"

    f_dict = {}
    f_dict["portal_name"] = module.params["portal_name"]

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


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


def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["change-password"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["change-password"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["change-password"][k] = v
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
    payload = build_json("change-password", module)
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

    result = dict(changed=False, original_message="", message="", result={})

    state = module.params["state"]
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    if ansible_port == 80:
        protocol = "http"
    elif ansible_port == 443:
        protocol = "https"

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
