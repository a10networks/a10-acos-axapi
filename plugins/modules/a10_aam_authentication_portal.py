#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_aam_authentication_portal
description:
    - Authentication portal configuration
author: A10 Networks 2021
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        type: str
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        type: str
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        type: str
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        type: str
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        type: int
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        type: int
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        type: str
        required: False
    name:
        description:
        - "'default-portal'= Default portal configuration;"
        type: str
        required: True
    logo_cfg:
        description:
        - "Field logo_cfg"
        type: dict
        required: False
        suboptions:
            logo:
                description:
                - "Specify logo image filename"
                type: str
            width:
                description:
                - "Specify logo image width (Default= 134)"
                type: int
            height:
                description:
                - "Specify logo image height (Default= 71)"
                type: int
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    user_tag:
        description:
        - "Customized tag"
        type: str
        required: False
    logon:
        description:
        - "Field logon"
        type: dict
        required: False
        suboptions:
            background:
                description:
                - "Field background"
                type: dict
            fail_msg_cfg:
                description:
                - "Field fail_msg_cfg"
                type: dict
            action_url:
                description:
                - "Specify form action URL in default logon page (Default= /logon.fo)"
                type: str
            username_cfg:
                description:
                - "Field username_cfg"
                type: dict
            username_var:
                description:
                - "Specify username variable name in default logon page (Default= user)"
                type: str
            password_cfg:
                description:
                - "Field password_cfg"
                type: dict
            password_var:
                description:
                - "Specify password variable name in default logon page (Default= pwd)"
                type: str
            enable_passcode:
                description:
                - "Enable passcode field in default logon page"
                type: bool
            passcode_cfg:
                description:
                - "Field passcode_cfg"
                type: dict
            passcode_var:
                description:
                - "Specify passcode variable name in default logon page (Default= passcode)"
                type: str
            enable_CAPTCHA:
                description:
                - "Enable CAPTCHA in deafult logon page"
                type: bool
            captcha_type:
                description:
                - "'reCAPTCHAv2-checkbox'= Google reCAPTCHAv2 Checkbox; 'reCAPTCHAv2-invisible'=
          Google reCAPTCHAv2 Invisible; 'reCAPTCHAv3'= Google reCAPTCHAv3;"
                type: str
            site_key_string:
                description:
                - "Site key string"
                type: str
            encrypted:
                description:
                - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The
          ENCRYPTED secret string)"
                type: str
            reCAPTCHA_cfg:
                description:
                - "Field reCAPTCHA_cfg"
                type: dict
            submit_text:
                description:
                - "Specify submit button text in default logon page (Default= Log In)"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    change_password:
        description:
        - "Field change_password"
        type: dict
        required: False
        suboptions:
            background:
                description:
                - "Field background"
                type: dict
            title_cfg:
                description:
                - "Field title_cfg"
                type: dict
            action_url:
                description:
                - "Specify form action URL in default change password page (Default= /change.fo)"
                type: str
            username_cfg:
                description:
                - "Field username_cfg"
                type: dict
            username_var:
                description:
                - "Specify username variable name in default change password page (Default=
          cp_usr)"
                type: str
            old_pwd_cfg:
                description:
                - "Field old_pwd_cfg"
                type: dict
            old_password_var:
                description:
                - "Specify old password variable name in default change password page (Default=
          cp_old_pwd)"
                type: str
            new_pwd_cfg:
                description:
                - "Field new_pwd_cfg"
                type: dict
            new_password_var:
                description:
                - "Specify new password variable name in default change password page (Default=
          cp_new_pwd)"
                type: str
            cfm_pwd_cfg:
                description:
                - "Field cfm_pwd_cfg"
                type: dict
            confirm_password_var:
                description:
                - "Specify confirm password variable name in default change password page
          (Default= cp_cfm_pwd)"
                type: str
            submit_text:
                description:
                - "Specify submit button text in default change password page (Default= Submit)"
                type: str
            reset_text:
                description:
                - "Specify reset button text in default change password page (Default= Reset)"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    notify_change_password:
        description:
        - "Field notify_change_password"
        type: dict
        required: False
        suboptions:
            background:
                description:
                - "Field background"
                type: dict
            continue_url:
                description:
                - "Specify continue action URL in default change password notification page
          (Default= /continue.fo)"
                type: str
            change_url:
                description:
                - "Specify change password action URL in default change password notification page
          (Default= /notify_change.fo)"
                type: str
            username_cfg:
                description:
                - "Field username_cfg"
                type: dict
            username_var:
                description:
                - "Specify username variable name in default change password notification page
          (Default= cp_usr)"
                type: str
            old_pwd_cfg:
                description:
                - "Field old_pwd_cfg"
                type: dict
            old_password_var:
                description:
                - "Specify old password variable name in default change password notification page
          (Default= cp_old_pwd)"
                type: str
            new_pwd_cfg:
                description:
                - "Field new_pwd_cfg"
                type: dict
            new_password_var:
                description:
                - "Specify new password variable name in default change password notification page
          (Default= cp_new_pwd)"
                type: str
            cfm_pwd_cfg:
                description:
                - "Field cfm_pwd_cfg"
                type: dict
            confirm_password_var:
                description:
                - "Specify confirm password variable name in default change password notification
          page (Default= cp_cfm_pwd)"
                type: str
            change_text:
                description:
                - "Specify change button text in default change password notification page
          (Default= Change)"
                type: str
            continue_text:
                description:
                - "Specify continue button text in default change password notification page
          (Default= Continue)"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    logon_fail:
        description:
        - "Field logon_fail"
        type: dict
        required: False
        suboptions:
            background:
                description:
                - "Field background"
                type: dict
            title_cfg:
                description:
                - "Field title_cfg"
                type: dict
            fail_msg_cfg:
                description:
                - "Field fail_msg_cfg"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str

'''

RETURN = r'''
modified_values:
    description:
    - Values modified (or potential changes if using check_mode) as a result of task operation
    returned: changed
    type: dict
axapi_calls:
    description: Sequential list of AXAPI calls made by the task
    returned: always
    type: list
    elements: dict
    contains:
        endpoint:
            description: The AXAPI endpoint being accessed.
            type: str
            sample:
                - /axapi/v3/slb/virtual_server
                - /axapi/v3/file/ssl-cert
        http_method:
            description:
            - HTTP method being used by the primary task to interact with the AXAPI endpoint.
            type: str
            sample:
                - POST
                - GET
        request_body:
            description: Params used to query the AXAPI
            type: complex
        response_body:
            description: Response from the AXAPI
            type: complex
'''

EXAMPLES = """
"""

import copy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    wrapper as api_client
from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    utils
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["change_password", "logo_cfg", "logon", "logon_fail", "name", "notify_change_password", "user_tag", "uuid", ]


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(type='str', required=False,
                           ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False,
                                   ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
        )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'name': {
            'type': 'str',
            'required': True,
            'choices': ['default-portal']
            },
        'logo_cfg': {
            'type': 'dict',
            'logo': {
                'type': 'str',
                },
            'width': {
                'type': 'int',
                },
            'height': {
                'type': 'int',
                }
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'logon': {
            'type': 'dict',
            'background': {
                'type': 'dict',
                'bgfile': {
                    'type': 'str',
                    },
                'bgstyle': {
                    'type': 'str',
                    'choices': ['tile', 'stretch', 'fit']
                    },
                'bgcolor_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'bgcolor_value': {
                    'type': 'str',
                    }
                },
            'fail_msg_cfg': {
                'type': 'dict',
                'fail_msg': {
                    'type': 'bool',
                    },
                'fail_text': {
                    'type': 'str',
                    },
                'fail_font': {
                    'type': 'bool',
                    },
                'fail_face': {
                    'type': 'str',
                    'choices': ['Arial', 'Courier_New', 'Georgia', 'Times_New_Roman', 'Verdana']
                    },
                'fail_font_custom': {
                    'type': 'str',
                    },
                'fail_size': {
                    'type': 'int',
                    },
                'fail_color': {
                    'type': 'bool',
                    },
                'fail_color_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'fail_color_value': {
                    'type': 'str',
                    },
                'authz_fail_msg': {
                    'type': 'str',
                    }
                },
            'action_url': {
                'type': 'str',
                },
            'username_cfg': {
                'type': 'dict',
                'username': {
                    'type': 'bool',
                    },
                'user_text': {
                    'type': 'str',
                    },
                'user_font': {
                    'type': 'bool',
                    },
                'user_face': {
                    'type': 'str',
                    'choices': ['Arial', 'Courier_New', 'Georgia', 'Times_New_Roman', 'Verdana']
                    },
                'user_font_custom': {
                    'type': 'str',
                    },
                'user_size': {
                    'type': 'int',
                    },
                'user_color': {
                    'type': 'bool',
                    },
                'user_color_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'user_color_value': {
                    'type': 'str',
                    }
                },
            'username_var': {
                'type': 'str',
                },
            'password_cfg': {
                'type': 'dict',
                'password': {
                    'type': 'bool',
                    },
                'pass_text': {
                    'type': 'str',
                    },
                'pass_font': {
                    'type': 'bool',
                    },
                'pass_face': {
                    'type': 'str',
                    'choices': ['Arial', 'Courier_New', 'Georgia', 'Times_New_Roman', 'Verdana']
                    },
                'pass_font_custom': {
                    'type': 'str',
                    },
                'pass_size': {
                    'type': 'int',
                    },
                'pass_color': {
                    'type': 'bool',
                    },
                'pass_color_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'pass_color_value': {
                    'type': 'str',
                    }
                },
            'password_var': {
                'type': 'str',
                },
            'enable_passcode': {
                'type': 'bool',
                },
            'passcode_cfg': {
                'type': 'dict',
                'passcode': {
                    'type': 'bool',
                    },
                'passcode_text': {
                    'type': 'str',
                    },
                'passcode_font': {
                    'type': 'bool',
                    },
                'passcode_face': {
                    'type': 'str',
                    'choices': ['Arial', 'Courier_New', 'Georgia', 'Times_New_Roman', 'Verdana']
                    },
                'passcode_font_custom': {
                    'type': 'str',
                    },
                'passcode_size': {
                    'type': 'int',
                    },
                'passcode_color': {
                    'type': 'bool',
                    },
                'passcode_color_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'passcode_color_value': {
                    'type': 'str',
                    }
                },
            'passcode_var': {
                'type': 'str',
                },
            'enable_CAPTCHA': {
                'type': 'bool',
                },
            'captcha_type': {
                'type': 'str',
                'choices': ['reCAPTCHAv2-checkbox', 'reCAPTCHAv2-invisible', 'reCAPTCHAv3']
                },
            'site_key_string': {
                'type': 'str',
                },
            'encrypted': {
                'type': 'str',
                },
            'reCAPTCHA_cfg': {
                'type': 'dict',
                'reCAPTCHA_theme': {
                    'type': 'str',
                    'choices': ['light', 'dark']
                    },
                'reCAPTCHA_size': {
                    'type': 'str',
                    'choices': ['normal', 'compact']
                    },
                'reCAPTCHA_badge': {
                    'type': 'str',
                    'choices': ['bottom-left', 'bottom-right']
                    },
                'reCAPTCHA_action': {
                    'type': 'str',
                    }
                },
            'submit_text': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'change_password': {
            'type': 'dict',
            'background': {
                'type': 'dict',
                'bgfile': {
                    'type': 'str',
                    },
                'bgstyle': {
                    'type': 'str',
                    'choices': ['tile', 'stretch', 'fit']
                    },
                'bgcolor_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'bgcolor_value': {
                    'type': 'str',
                    }
                },
            'title_cfg': {
                'type': 'dict',
                'title': {
                    'type': 'bool',
                    },
                'title_text': {
                    'type': 'str',
                    },
                'title_font': {
                    'type': 'bool',
                    },
                'title_face': {
                    'type': 'str',
                    'choices': ['Arial', 'Courier_New', 'Georgia', 'Times_New_Roman', 'Verdana']
                    },
                'title_font_custom': {
                    'type': 'str',
                    },
                'title_size': {
                    'type': 'int',
                    },
                'title_color': {
                    'type': 'bool',
                    },
                'title_color_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'title_color_value': {
                    'type': 'str',
                    }
                },
            'action_url': {
                'type': 'str',
                },
            'username_cfg': {
                'type': 'dict',
                'username': {
                    'type': 'bool',
                    },
                'user_text': {
                    'type': 'str',
                    },
                'user_font': {
                    'type': 'bool',
                    },
                'user_face': {
                    'type': 'str',
                    'choices': ['Arial', 'Courier_New', 'Georgia', 'Times_New_Roman', 'Verdana']
                    },
                'user_font_custom': {
                    'type': 'str',
                    },
                'user_size': {
                    'type': 'int',
                    },
                'user_color': {
                    'type': 'bool',
                    },
                'user_color_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'user_color_value': {
                    'type': 'str',
                    }
                },
            'username_var': {
                'type': 'str',
                },
            'old_pwd_cfg': {
                'type': 'dict',
                'old_password': {
                    'type': 'bool',
                    },
                'old_text': {
                    'type': 'str',
                    },
                'old_font': {
                    'type': 'bool',
                    },
                'old_face': {
                    'type': 'str',
                    'choices': ['Arial', 'Courier_New', 'Georgia', 'Times_New_Roman', 'Verdana']
                    },
                'old_font_custom': {
                    'type': 'str',
                    },
                'old_size': {
                    'type': 'int',
                    },
                'old_color': {
                    'type': 'bool',
                    },
                'old_color_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'old_color_value': {
                    'type': 'str',
                    }
                },
            'old_password_var': {
                'type': 'str',
                },
            'new_pwd_cfg': {
                'type': 'dict',
                'new_password': {
                    'type': 'bool',
                    },
                'new_text': {
                    'type': 'str',
                    },
                'new_font': {
                    'type': 'bool',
                    },
                'new_face': {
                    'type': 'str',
                    'choices': ['Arial', 'Courier_New', 'Georgia', 'Times_New_Roman', 'Verdana']
                    },
                'new_font_custom': {
                    'type': 'str',
                    },
                'new_size': {
                    'type': 'int',
                    },
                'new_color': {
                    'type': 'bool',
                    },
                'new_color_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'new_color_value': {
                    'type': 'str',
                    }
                },
            'new_password_var': {
                'type': 'str',
                },
            'cfm_pwd_cfg': {
                'type': 'dict',
                'confirm_password': {
                    'type': 'bool',
                    },
                'cfm_text': {
                    'type': 'str',
                    },
                'cfm_font': {
                    'type': 'bool',
                    },
                'cfm_face': {
                    'type': 'str',
                    'choices': ['Arial', 'Courier_New', 'Georgia', 'Times_New_Roman', 'Verdana']
                    },
                'cfm_font_custom': {
                    'type': 'str',
                    },
                'cfm_size': {
                    'type': 'int',
                    },
                'cfm_color': {
                    'type': 'bool',
                    },
                'cfm_color_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'cfm_color_value': {
                    'type': 'str',
                    }
                },
            'confirm_password_var': {
                'type': 'str',
                },
            'submit_text': {
                'type': 'str',
                },
            'reset_text': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'notify_change_password': {
            'type': 'dict',
            'background': {
                'type': 'dict',
                'bgfile': {
                    'type': 'str',
                    },
                'bgstyle': {
                    'type': 'str',
                    'choices': ['tile', 'stretch', 'fit']
                    },
                'bgcolor_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'bgcolor_value': {
                    'type': 'str',
                    }
                },
            'continue_url': {
                'type': 'str',
                },
            'change_url': {
                'type': 'str',
                },
            'username_cfg': {
                'type': 'dict',
                'username': {
                    'type': 'bool',
                    },
                'user_text': {
                    'type': 'str',
                    },
                'user_font': {
                    'type': 'bool',
                    },
                'user_face': {
                    'type': 'str',
                    'choices': ['Arial', 'Courier_New', 'Georgia', 'Times_New_Roman', 'Verdana']
                    },
                'user_font_custom': {
                    'type': 'str',
                    },
                'user_size': {
                    'type': 'int',
                    },
                'user_color': {
                    'type': 'bool',
                    },
                'user_color_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'user_color_value': {
                    'type': 'str',
                    }
                },
            'username_var': {
                'type': 'str',
                },
            'old_pwd_cfg': {
                'type': 'dict',
                'old_password': {
                    'type': 'bool',
                    },
                'old_text': {
                    'type': 'str',
                    },
                'old_font': {
                    'type': 'bool',
                    },
                'old_face': {
                    'type': 'str',
                    'choices': ['Arial', 'Courier_New', 'Georgia', 'Times_New_Roman', 'Verdana']
                    },
                'old_font_custom': {
                    'type': 'str',
                    },
                'old_size': {
                    'type': 'int',
                    },
                'old_color': {
                    'type': 'bool',
                    },
                'old_color_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'old_color_value': {
                    'type': 'str',
                    }
                },
            'old_password_var': {
                'type': 'str',
                },
            'new_pwd_cfg': {
                'type': 'dict',
                'new_password': {
                    'type': 'bool',
                    },
                'new_text': {
                    'type': 'str',
                    },
                'new_font': {
                    'type': 'bool',
                    },
                'new_face': {
                    'type': 'str',
                    'choices': ['Arial', 'Courier_New', 'Georgia', 'Times_New_Roman', 'Verdana']
                    },
                'new_font_custom': {
                    'type': 'str',
                    },
                'new_size': {
                    'type': 'int',
                    },
                'new_color': {
                    'type': 'bool',
                    },
                'new_color_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'new_color_value': {
                    'type': 'str',
                    }
                },
            'new_password_var': {
                'type': 'str',
                },
            'cfm_pwd_cfg': {
                'type': 'dict',
                'confirm_password': {
                    'type': 'bool',
                    },
                'cfm_text': {
                    'type': 'str',
                    },
                'cfm_font': {
                    'type': 'bool',
                    },
                'cfm_face': {
                    'type': 'str',
                    'choices': ['Arial', 'Courier_New', 'Georgia', 'Times_New_Roman', 'Verdana']
                    },
                'cfm_font_custom': {
                    'type': 'str',
                    },
                'cfm_size': {
                    'type': 'int',
                    },
                'cfm_color': {
                    'type': 'bool',
                    },
                'cfm_color_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'cfm_color_value': {
                    'type': 'str',
                    }
                },
            'confirm_password_var': {
                'type': 'str',
                },
            'change_text': {
                'type': 'str',
                },
            'continue_text': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'logon_fail': {
            'type': 'dict',
            'background': {
                'type': 'dict',
                'bgfile': {
                    'type': 'str',
                    },
                'bgstyle': {
                    'type': 'str',
                    'choices': ['tile', 'stretch', 'fit']
                    },
                'bgcolor_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'bgcolor_value': {
                    'type': 'str',
                    }
                },
            'title_cfg': {
                'type': 'dict',
                'title': {
                    'type': 'bool',
                    },
                'title_text': {
                    'type': 'str',
                    },
                'title_font': {
                    'type': 'bool',
                    },
                'title_face': {
                    'type': 'str',
                    'choices': ['Arial', 'Courier_New', 'Georgia', 'Times_New_Roman', 'Verdana']
                    },
                'title_font_custom': {
                    'type': 'str',
                    },
                'title_size': {
                    'type': 'int',
                    },
                'title_color': {
                    'type': 'bool',
                    },
                'title_color_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'title_color_value': {
                    'type': 'str',
                    }
                },
            'fail_msg_cfg': {
                'type': 'dict',
                'fail_msg': {
                    'type': 'bool',
                    },
                'fail_text': {
                    'type': 'str',
                    },
                'fail_font': {
                    'type': 'bool',
                    },
                'fail_face': {
                    'type': 'str',
                    'choices': ['Arial', 'Courier_New', 'Georgia', 'Times_New_Roman', 'Verdana']
                    },
                'fail_font_custom': {
                    'type': 'str',
                    },
                'fail_size': {
                    'type': 'int',
                    },
                'fail_color': {
                    'type': 'bool',
                    },
                'fail_color_name': {
                    'type': 'str',
                    'choices': ['aqua', 'black', 'blue', 'fuchsia', 'gray', 'green', 'lime', 'maroon', 'navy', 'olive', 'orange', 'purple', 'red', 'silver', 'teal', 'white', 'yellow']
                    },
                'fail_color_value': {
                    'type': 'str',
                    }
                },
            'uuid': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/aam/authentication/portal/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/aam/authentication/portal/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["portal"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["portal"].get(k) != v:
            change_results["changed"] = True
            config_changes["portal"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(**call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    call_result = api_client.post(module.client, existing_url(module), payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("portal", module.params, AVAILABLE_PROPERTIES)
    change_results = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return change_results
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and change_results.get('changed'):
        return update(module, result, existing_config, payload)
    return result


def delete(module, result):
    try:
        call_result = api_client.delete(module.client, existing_url(module))
        result["axapi_calls"].append(call_result)
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    return result


def absent(module, result, existing_config):
    if not existing_config:
        result["changed"] = False
        return result

    if module.check_mode:
        result["changed"] = True
        return result

    return delete(module, result)


def run_command(module):
    result = dict(changed=False, messages="", modified_values={}, axapi_calls=[], ansible_facts={}, acos_info={})

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

    module.client = client_factory(ansible_host, ansible_port, protocol, ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params, requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(api_client.switch_device_context(module.client, a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
        result["axapi_calls"].append(existing_config)
        if existing_config['response_body'] != 'NotFound':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["portal"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["portal-list"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
