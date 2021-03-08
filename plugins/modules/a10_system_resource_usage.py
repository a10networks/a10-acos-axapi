#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_system_resource_usage
description:
    - Configure System Resource Usage
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
    ssl_context_memory:
        description:
        - "Total SSL context memory needed in units of MB. Will be rounded to closest
          multiple of 2MB"
        type: int
        required: False
    ssl_dma_memory:
        description:
        - "Total SSL DMA memory needed in units of MB. Will be rounded to closest multiple
          of 2MB"
        type: int
        required: False
    nat_pool_addr_count:
        description:
        - "Total configurable NAT Pool addresses in the System"
        type: int
        required: False
    l4_session_count:
        description:
        - "Total Sessions in the System"
        type: int
        required: False
    auth_portal_html_file_size:
        description:
        - "Specify maximum html file size for each html page in auth portal (in KB)"
        type: int
        required: False
    auth_portal_image_file_size:
        description:
        - "Specify maximum image file size for default portal (in KB)"
        type: int
        required: False
    max_aflex_file_size:
        description:
        - "Set maximum aFleX file size (Maximum file size in KBytes, default is 32K)"
        type: int
        required: False
    aflex_table_entry_count:
        description:
        - "Total aFleX table entry in the system (Total aFlex entry in the system)"
        type: int
        required: False
    class_list_ipv6_addr_count:
        description:
        - "Total IPv6 addresses for class-list"
        type: int
        required: False
    class_list_ac_entry_count:
        description:
        - "Total entries for AC class-list"
        type: int
        required: False
    max_aflex_authz_collection_number:
        description:
        - "Specify the maximum number of collections supported by aFleX authorization"
        type: int
        required: False
    radius_table_size:
        description:
        - "Total configurable CGNV6 RADIUS Table entries"
        type: int
        required: False
    authz_policy_number:
        description:
        - "Specify the maximum number of authorization policies"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    visibility:
        description:
        - "Field visibility"
        type: dict
        required: False
        suboptions:
            monitored_entity_count:
                description:
                - "Total number of monitored entities for visibility"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            l4_session_count_min:
                description:
                - "Field l4_session_count_min"
                type: int
            l4_session_count_max:
                description:
                - "Field l4_session_count_max"
                type: int
            l4_session_count_default:
                description:
                - "Field l4_session_count_default"
                type: int
            nat_pool_addr_min:
                description:
                - "Field nat_pool_addr_min"
                type: int
            nat_pool_addr_max:
                description:
                - "Field nat_pool_addr_max"
                type: int
            nat_pool_addr_default:
                description:
                - "Field nat_pool_addr_default"
                type: int
            class_list_ipv6_addr_min:
                description:
                - "Field class_list_ipv6_addr_min"
                type: int
            class_list_ipv6_addr_max:
                description:
                - "Field class_list_ipv6_addr_max"
                type: int
            class_list_ipv6_addr_default:
                description:
                - "Field class_list_ipv6_addr_default"
                type: int
            class_list_ac_min:
                description:
                - "Field class_list_ac_min"
                type: int
            class_list_ac_max:
                description:
                - "Field class_list_ac_max"
                type: int
            class_list_ac_default:
                description:
                - "Field class_list_ac_default"
                type: int
            auth_portal_html_file_size_min:
                description:
                - "Field auth_portal_html_file_size_min"
                type: int
            auth_portal_html_file_size_max:
                description:
                - "Field auth_portal_html_file_size_max"
                type: int
            auth_portal_html_file_size_default:
                description:
                - "Field auth_portal_html_file_size_default"
                type: int
            auth_portal_image_file_size_min:
                description:
                - "Field auth_portal_image_file_size_min"
                type: int
            auth_portal_image_file_size_max:
                description:
                - "Field auth_portal_image_file_size_max"
                type: int
            auth_portal_image_file_size_default:
                description:
                - "Field auth_portal_image_file_size_default"
                type: int
            aflex_file_size_min:
                description:
                - "Field aflex_file_size_min"
                type: int
            aflex_file_size_max:
                description:
                - "Field aflex_file_size_max"
                type: int
            aflex_file_size_default:
                description:
                - "Field aflex_file_size_default"
                type: int
            aflex_table_entry_count_min:
                description:
                - "Field aflex_table_entry_count_min"
                type: int
            aflex_table_entry_count_max:
                description:
                - "Field aflex_table_entry_count_max"
                type: int
            aflex_table_entry_count_default:
                description:
                - "Field aflex_table_entry_count_default"
                type: int
            aflex_authz_collection_number_min:
                description:
                - "Field aflex_authz_collection_number_min"
                type: int
            aflex_authz_collection_number_max:
                description:
                - "Field aflex_authz_collection_number_max"
                type: int
            aflex_authz_collection_number_default:
                description:
                - "Field aflex_authz_collection_number_default"
                type: int
            radius_table_size_min:
                description:
                - "Field radius_table_size_min"
                type: int
            radius_table_size_max:
                description:
                - "Field radius_table_size_max"
                type: int
            radius_table_size_default:
                description:
                - "Field radius_table_size_default"
                type: int
            visibility_mon_entity_min:
                description:
                - "Field visibility_mon_entity_min"
                type: int
            visibility_mon_entity_max:
                description:
                - "Field visibility_mon_entity_max"
                type: int
            visibility_mon_entity_default:
                description:
                - "Field visibility_mon_entity_default"
                type: int
            authz_policy_number_min:
                description:
                - "Field authz_policy_number_min"
                type: int
            authz_policy_number_max:
                description:
                - "Field authz_policy_number_max"
                type: int
            authz_policy_number_default:
                description:
                - "Field authz_policy_number_default"
                type: int

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
    "aflex_table_entry_count",
    "auth_portal_html_file_size",
    "auth_portal_image_file_size",
    "authz_policy_number",
    "class_list_ac_entry_count",
    "class_list_ipv6_addr_count",
    "l4_session_count",
    "max_aflex_authz_collection_number",
    "max_aflex_file_size",
    "nat_pool_addr_count",
    "oper",
    "radius_table_size",
    "ssl_context_memory",
    "ssl_dma_memory",
    "uuid",
    "visibility",
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
        'ssl_context_memory': {
            'type': 'int',
        },
        'ssl_dma_memory': {
            'type': 'int',
        },
        'nat_pool_addr_count': {
            'type': 'int',
        },
        'l4_session_count': {
            'type': 'int',
        },
        'auth_portal_html_file_size': {
            'type': 'int',
        },
        'auth_portal_image_file_size': {
            'type': 'int',
        },
        'max_aflex_file_size': {
            'type': 'int',
        },
        'aflex_table_entry_count': {
            'type': 'int',
        },
        'class_list_ipv6_addr_count': {
            'type': 'int',
        },
        'class_list_ac_entry_count': {
            'type': 'int',
        },
        'max_aflex_authz_collection_number': {
            'type': 'int',
        },
        'radius_table_size': {
            'type': 'int',
        },
        'authz_policy_number': {
            'type': 'int',
        },
        'uuid': {
            'type': 'str',
        },
        'visibility': {
            'type': 'dict',
            'monitored_entity_count': {
                'type': 'int',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'oper': {
            'type': 'dict',
            'l4_session_count_min': {
                'type': 'int',
            },
            'l4_session_count_max': {
                'type': 'int',
            },
            'l4_session_count_default': {
                'type': 'int',
            },
            'nat_pool_addr_min': {
                'type': 'int',
            },
            'nat_pool_addr_max': {
                'type': 'int',
            },
            'nat_pool_addr_default': {
                'type': 'int',
            },
            'class_list_ipv6_addr_min': {
                'type': 'int',
            },
            'class_list_ipv6_addr_max': {
                'type': 'int',
            },
            'class_list_ipv6_addr_default': {
                'type': 'int',
            },
            'class_list_ac_min': {
                'type': 'int',
            },
            'class_list_ac_max': {
                'type': 'int',
            },
            'class_list_ac_default': {
                'type': 'int',
            },
            'auth_portal_html_file_size_min': {
                'type': 'int',
            },
            'auth_portal_html_file_size_max': {
                'type': 'int',
            },
            'auth_portal_html_file_size_default': {
                'type': 'int',
            },
            'auth_portal_image_file_size_min': {
                'type': 'int',
            },
            'auth_portal_image_file_size_max': {
                'type': 'int',
            },
            'auth_portal_image_file_size_default': {
                'type': 'int',
            },
            'aflex_file_size_min': {
                'type': 'int',
            },
            'aflex_file_size_max': {
                'type': 'int',
            },
            'aflex_file_size_default': {
                'type': 'int',
            },
            'aflex_table_entry_count_min': {
                'type': 'int',
            },
            'aflex_table_entry_count_max': {
                'type': 'int',
            },
            'aflex_table_entry_count_default': {
                'type': 'int',
            },
            'aflex_authz_collection_number_min': {
                'type': 'int',
            },
            'aflex_authz_collection_number_max': {
                'type': 'int',
            },
            'aflex_authz_collection_number_default': {
                'type': 'int',
            },
            'radius_table_size_min': {
                'type': 'int',
            },
            'radius_table_size_max': {
                'type': 'int',
            },
            'radius_table_size_default': {
                'type': 'int',
            },
            'visibility_mon_entity_min': {
                'type': 'int',
            },
            'visibility_mon_entity_max': {
                'type': 'int',
            },
            'visibility_mon_entity_default': {
                'type': 'int',
            },
            'authz_policy_number_min': {
                'type': 'int',
            },
            'authz_policy_number_max': {
                'type': 'int',
            },
            'authz_policy_number_default': {
                'type': 'int',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/resource-usage"

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


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_oper(module):
    if module.params.get("oper"):
        query_params = {}
        for k, v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(oper_url(module), params=query_params)
    return module.client.get(oper_url(module))


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
    url_base = "/axapi/v3/system/resource-usage"

    f_dict = {}

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
        for k, v in payload["resource-usage"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["resource-usage"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["resource-usage"][k] = v
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
    payload = build_json("resource-usage", module)
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
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
