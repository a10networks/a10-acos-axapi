#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_aam_authorization_policy
description:
    - Authorization-policy configuration
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
        - "Specify authorization policy name"
        type: str
        required: True
    attribute_rule:
        description:
        - "Define attribute rule for authorization policy"
        type: str
        required: False
    server:
        description:
        - "Specify a LDAP or RADIUS server for authorization (Specify a LDAP or RADIUS
          server name)"
        type: str
        required: False
    service_group:
        description:
        - "Specify an authentication service group for authorization (Specify
          authentication service group name)"
        type: str
        required: False
    extended_filter:
        description:
        - "Extended search filter. EX= Check whether user belongs to a nested group.
          (memberOf=1.2.840.113556.1.4.1941==$GROUP-DN)"
        type: str
        required: False
    jwt_authorization:
        description:
        - "Specify JWT authorization template (Specify JWT authorization template name)"
        type: str
        required: False
    forward_policy_authorize_only:
        description:
        - "This policy only provides server info for forward policy feature"
        type: bool
        required: False
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
    attribute_list:
        description:
        - "Field attribute_list"
        type: list
        required: False
        suboptions:
            attr_num:
                description:
                - "Set attribute ID for authorization policy"
                type: int
            attribute_name:
                description:
                - "Specify attribute name"
                type: str
            any:
                description:
                - "Matched when attribute is present (with any value)."
                type: bool
            attr_type:
                description:
                - "Specify attribute type"
                type: bool
            string_type:
                description:
                - "Attribute type is string"
                type: bool
            integer_type:
                description:
                - "Attribute type is integer"
                type: bool
            ip_type:
                description:
                - "IP address is transformed into network byte order"
                type: bool
            attr_str:
                description:
                - "'match'= Operation type is match; 'sub-string'= Operation type is sub-string;"
                type: str
            attr_str_val:
                description:
                - "Set attribute value"
                type: str
            attr_int:
                description:
                - "'equal'= Operation type is equal; 'not-equal'= Operation type is not equal;
          'less-than'= Operation type is less-than; 'more-than'= Operation type is more-
          than; 'less-than-equal-to'= Operation type is less-than-equal-to; 'more-than-
          equal-to'= Operation type is more-thatn-equal-to;"
                type: str
            attr_int_val:
                description:
                - "Set attribute value"
                type: int
            attr_ip:
                description:
                - "'equal'= Operation type is equal; 'not-equal'= Operation type is not-equal;"
                type: str
            attr_ipv4:
                description:
                - "IPv4 address"
                type: str
            A10_AX_AUTH_URI:
                description:
                - "Custom-defined attribute"
                type: bool
            custom_attr_type:
                description:
                - "Specify attribute type"
                type: bool
            custom_attr_str:
                description:
                - "'match'= Operation type is match; 'sub-string'= Operation type is sub-string;"
                type: str
            a10_dynamic_defined:
                description:
                - "The value of this attribute will depend on AX configuration instead of user
          configuration"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    jwt_claim_map_list:
        description:
        - "Field jwt_claim_map_list"
        type: list
        required: False
        suboptions:
            attr_num:
                description:
                - "Spcify attribute ID for claim mapping"
                type: int
            claim:
                description:
                - "Specify JWT claim name to map to."
                type: str
            ntype:
                description:
                - "Specify claim type"
                type: bool
            string_type:
                description:
                - "Claim type is string"
                type: bool
            number_type:
                description:
                - "Claim type is number"
                type: bool
            boolean_type:
                description:
                - "Claim type is boolean"
                type: bool
            str_val:
                description:
                - "Specify JWT claim value."
                type: str
            num_val:
                description:
                - "Specify JWT claim value."
                type: int
            bool_val:
                description:
                - "'true'= True; 'false'= False;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str

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
    "attribute_list",
    "attribute_rule",
    "extended_filter",
    "forward_policy_authorize_only",
    "jwt_authorization",
    "jwt_claim_map_list",
    "name",
    "server",
    "service_group",
    "user_tag",
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
        'name': {
            'type': 'str',
            'required': True,
        },
        'attribute_rule': {
            'type': 'str',
        },
        'server': {
            'type': 'str',
        },
        'service_group': {
            'type': 'str',
        },
        'extended_filter': {
            'type': 'str',
        },
        'jwt_authorization': {
            'type': 'str',
        },
        'forward_policy_authorize_only': {
            'type': 'bool',
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        },
        'attribute_list': {
            'type': 'list',
            'attr_num': {
                'type': 'int',
                'required': True,
            },
            'attribute_name': {
                'type': 'str',
            },
            'any': {
                'type': 'bool',
            },
            'attr_type': {
                'type': 'bool',
            },
            'string_type': {
                'type': 'bool',
            },
            'integer_type': {
                'type': 'bool',
            },
            'ip_type': {
                'type': 'bool',
            },
            'attr_str': {
                'type': 'str',
                'choices': ['match', 'sub-string']
            },
            'attr_str_val': {
                'type': 'str',
            },
            'attr_int': {
                'type':
                'str',
                'choices': [
                    'equal', 'not-equal', 'less-than', 'more-than',
                    'less-than-equal-to', 'more-than-equal-to'
                ]
            },
            'attr_int_val': {
                'type': 'int',
            },
            'attr_ip': {
                'type': 'str',
                'choices': ['equal', 'not-equal']
            },
            'attr_ipv4': {
                'type': 'str',
            },
            'A10_AX_AUTH_URI': {
                'type': 'bool',
            },
            'custom_attr_type': {
                'type': 'bool',
            },
            'custom_attr_str': {
                'type': 'str',
                'choices': ['match', 'sub-string']
            },
            'a10_dynamic_defined': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'jwt_claim_map_list': {
            'type': 'list',
            'attr_num': {
                'type': 'int',
                'required': True,
            },
            'claim': {
                'type': 'str',
            },
            'ntype': {
                'type': 'bool',
            },
            'string_type': {
                'type': 'bool',
            },
            'number_type': {
                'type': 'bool',
            },
            'boolean_type': {
                'type': 'bool',
            },
            'str_val': {
                'type': 'str',
            },
            'num_val': {
                'type': 'int',
            },
            'bool_val': {
                'type': 'str',
                'choices': ['true', 'false']
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
    url_base = "/axapi/v3/aam/authorization/policy/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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
    url_base = "/axapi/v3/aam/authorization/policy/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
        for k, v in payload["policy"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["policy"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["policy"][k] = v
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
    payload = build_json("policy", module)
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
