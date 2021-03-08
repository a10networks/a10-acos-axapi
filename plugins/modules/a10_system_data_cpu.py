#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_system_data_cpu
description:
    - System data cpu information
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
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            data_cpu_number:
                description:
                - "Number of data cpus"
                type: str
            cpu_1:
                description:
                - "Data CPU-1"
                type: str
            cpu_2:
                description:
                - "Data CPU-2"
                type: str
            cpu_3:
                description:
                - "Data CPU-3"
                type: str
            cpu_4:
                description:
                - "Data CPU-4"
                type: str
            cpu_5:
                description:
                - "Data CPU-5"
                type: str
            cpu_6:
                description:
                - "Data CPU-6"
                type: str
            cpu_7:
                description:
                - "Data CPU-7"
                type: str
            cpu_8:
                description:
                - "Data CPU-8"
                type: str
            cpu_9:
                description:
                - "Data CPU-9"
                type: str
            cpu_10:
                description:
                - "Data CPU-10"
                type: str
            cpu_11:
                description:
                - "Data CPU-11"
                type: str
            cpu_12:
                description:
                - "Data CPU-12"
                type: str
            cpu_13:
                description:
                - "Data CPU-13"
                type: str
            cpu_14:
                description:
                - "Data CPU-14"
                type: str
            cpu_15:
                description:
                - "Data CPU-15"
                type: str
            cpu_16:
                description:
                - "Data CPU-16"
                type: str
            cpu_17:
                description:
                - "Data CPU-17"
                type: str
            cpu_18:
                description:
                - "Data CPU-18"
                type: str
            cpu_19:
                description:
                - "Data CPU-19"
                type: str
            cpu_20:
                description:
                - "Data CPU-20"
                type: str
            cpu_21:
                description:
                - "Data CPU-21"
                type: str
            cpu_22:
                description:
                - "Data CPU-22"
                type: str
            cpu_23:
                description:
                - "Data CPU-23"
                type: str
            cpu_24:
                description:
                - "Data CPU-24"
                type: str
            cpu_25:
                description:
                - "Data CPU-25"
                type: str
            cpu_26:
                description:
                - "Data CPU-26"
                type: str
            cpu_27:
                description:
                - "Data CPU-27"
                type: str
            cpu_28:
                description:
                - "Data CPU-28"
                type: str
            cpu_29:
                description:
                - "Data CPU-29"
                type: str
            cpu_30:
                description:
                - "Data CPU-30"
                type: str
            cpu_31:
                description:
                - "Data CPU-31"
                type: str
            cpu_32:
                description:
                - "Data CPU-32"
                type: str
            cpu_33:
                description:
                - "Data CPU-33"
                type: str
            cpu_34:
                description:
                - "Data CPU-34"
                type: str
            cpu_35:
                description:
                - "Data CPU-35"
                type: str
            cpu_36:
                description:
                - "Data CPU-36"
                type: str
            cpu_37:
                description:
                - "Data CPU-37"
                type: str
            cpu_38:
                description:
                - "Data CPU-38"
                type: str
            cpu_39:
                description:
                - "Data CPU-39"
                type: str
            cpu_40:
                description:
                - "Data CPU-40"
                type: str
            cpu_41:
                description:
                - "Data CPU-41"
                type: str
            cpu_42:
                description:
                - "Data CPU-42"
                type: str
            cpu_43:
                description:
                - "Data CPU-43"
                type: str
            cpu_44:
                description:
                - "Data CPU-44"
                type: str
            cpu_45:
                description:
                - "Data CPU-45"
                type: str
            cpu_46:
                description:
                - "Data CPU-46"
                type: str
            cpu_47:
                description:
                - "Data CPU-47"
                type: str
            cpu_48:
                description:
                - "Data CPU-48"
                type: str
            cpu_49:
                description:
                - "Data CPU-49"
                type: str
            cpu_50:
                description:
                - "Data CPU-50"
                type: str
            cpu_51:
                description:
                - "Data CPU-51"
                type: str
            cpu_52:
                description:
                - "Data CPU-52"
                type: str
            cpu_53:
                description:
                - "Data CPU-53"
                type: str
            cpu_54:
                description:
                - "Data CPU-54"
                type: str
            cpu_55:
                description:
                - "Data CPU-55"
                type: str
            cpu_56:
                description:
                - "Data CPU-56"
                type: str
            cpu_57:
                description:
                - "Data CPU-57"
                type: str
            cpu_58:
                description:
                - "Data CPU-58"
                type: str
            cpu_59:
                description:
                - "Data CPU-59"
                type: str
            cpu_60:
                description:
                - "Data CPU-60"
                type: str
            cpu_61:
                description:
                - "Data CPU-61"
                type: str
            cpu_62:
                description:
                - "Data CPU-62"
                type: str
            cpu_63:
                description:
                - "Data CPU-63"
                type: str
            cpu_64:
                description:
                - "Data CPU-64"
                type: str
            cpu_65:
                description:
                - "Data CPU-65"
                type: str
            cpu_66:
                description:
                - "Data CPU-66"
                type: str
            cpu_67:
                description:
                - "Data CPU-67"
                type: str
            cpu_68:
                description:
                - "Data CPU-68"
                type: str
            cpu_69:
                description:
                - "Data CPU-69"
                type: str
            cpu_70:
                description:
                - "Data CPU-70"
                type: str
            cpu_71:
                description:
                - "Data CPU-71"
                type: str
            cpu_72:
                description:
                - "Data CPU-72"
                type: str
            cpu_73:
                description:
                - "Data CPU-73"
                type: str
            cpu_74:
                description:
                - "Data CPU-74"
                type: str
            cpu_75:
                description:
                - "Data CPU-75"
                type: str
            cpu_76:
                description:
                - "Data CPU-76"
                type: str
            cpu_77:
                description:
                - "Data CPU-77"
                type: str
            cpu_78:
                description:
                - "Data CPU-78"
                type: str
            cpu_79:
                description:
                - "Data CPU-79"
                type: str
            cpu_80:
                description:
                - "Data CPU-80"
                type: str
            cpu_81:
                description:
                - "Data CPU-81"
                type: str
            cpu_82:
                description:
                - "Data CPU-82"
                type: str
            cpu_83:
                description:
                - "Data CPU-83"
                type: str
            cpu_84:
                description:
                - "Data CPU-84"
                type: str
            cpu_85:
                description:
                - "Data CPU-85"
                type: str
            cpu_86:
                description:
                - "Data CPU-86"
                type: str
            cpu_87:
                description:
                - "Data CPU-87"
                type: str
            cpu_88:
                description:
                - "Data CPU-88"
                type: str
            cpu_89:
                description:
                - "Data CPU-89"
                type: str
            cpu_90:
                description:
                - "Data CPU-90"
                type: str
            cpu_91:
                description:
                - "Data CPU-91"
                type: str
            cpu_92:
                description:
                - "Data CPU-92"
                type: str
            cpu_93:
                description:
                - "Data CPU-93"
                type: str
            cpu_94:
                description:
                - "Data CPU-94"
                type: str
            cpu_95:
                description:
                - "Data CPU-95"
                type: str
            cpu_96:
                description:
                - "Data CPU-96"
                type: str
            cpu_97:
                description:
                - "Data CPU-97"
                type: str
            cpu_98:
                description:
                - "Data CPU-98"
                type: str
            cpu_99:
                description:
                - "Data CPU-99"
                type: str
            cpu_100:
                description:
                - "Data CPU-100"
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
    "stats",
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
        'uuid': {
            'type': 'str',
        },
        'stats': {
            'type': 'dict',
            'data_cpu_number': {
                'type': 'str',
            },
            'cpu_1': {
                'type': 'str',
            },
            'cpu_2': {
                'type': 'str',
            },
            'cpu_3': {
                'type': 'str',
            },
            'cpu_4': {
                'type': 'str',
            },
            'cpu_5': {
                'type': 'str',
            },
            'cpu_6': {
                'type': 'str',
            },
            'cpu_7': {
                'type': 'str',
            },
            'cpu_8': {
                'type': 'str',
            },
            'cpu_9': {
                'type': 'str',
            },
            'cpu_10': {
                'type': 'str',
            },
            'cpu_11': {
                'type': 'str',
            },
            'cpu_12': {
                'type': 'str',
            },
            'cpu_13': {
                'type': 'str',
            },
            'cpu_14': {
                'type': 'str',
            },
            'cpu_15': {
                'type': 'str',
            },
            'cpu_16': {
                'type': 'str',
            },
            'cpu_17': {
                'type': 'str',
            },
            'cpu_18': {
                'type': 'str',
            },
            'cpu_19': {
                'type': 'str',
            },
            'cpu_20': {
                'type': 'str',
            },
            'cpu_21': {
                'type': 'str',
            },
            'cpu_22': {
                'type': 'str',
            },
            'cpu_23': {
                'type': 'str',
            },
            'cpu_24': {
                'type': 'str',
            },
            'cpu_25': {
                'type': 'str',
            },
            'cpu_26': {
                'type': 'str',
            },
            'cpu_27': {
                'type': 'str',
            },
            'cpu_28': {
                'type': 'str',
            },
            'cpu_29': {
                'type': 'str',
            },
            'cpu_30': {
                'type': 'str',
            },
            'cpu_31': {
                'type': 'str',
            },
            'cpu_32': {
                'type': 'str',
            },
            'cpu_33': {
                'type': 'str',
            },
            'cpu_34': {
                'type': 'str',
            },
            'cpu_35': {
                'type': 'str',
            },
            'cpu_36': {
                'type': 'str',
            },
            'cpu_37': {
                'type': 'str',
            },
            'cpu_38': {
                'type': 'str',
            },
            'cpu_39': {
                'type': 'str',
            },
            'cpu_40': {
                'type': 'str',
            },
            'cpu_41': {
                'type': 'str',
            },
            'cpu_42': {
                'type': 'str',
            },
            'cpu_43': {
                'type': 'str',
            },
            'cpu_44': {
                'type': 'str',
            },
            'cpu_45': {
                'type': 'str',
            },
            'cpu_46': {
                'type': 'str',
            },
            'cpu_47': {
                'type': 'str',
            },
            'cpu_48': {
                'type': 'str',
            },
            'cpu_49': {
                'type': 'str',
            },
            'cpu_50': {
                'type': 'str',
            },
            'cpu_51': {
                'type': 'str',
            },
            'cpu_52': {
                'type': 'str',
            },
            'cpu_53': {
                'type': 'str',
            },
            'cpu_54': {
                'type': 'str',
            },
            'cpu_55': {
                'type': 'str',
            },
            'cpu_56': {
                'type': 'str',
            },
            'cpu_57': {
                'type': 'str',
            },
            'cpu_58': {
                'type': 'str',
            },
            'cpu_59': {
                'type': 'str',
            },
            'cpu_60': {
                'type': 'str',
            },
            'cpu_61': {
                'type': 'str',
            },
            'cpu_62': {
                'type': 'str',
            },
            'cpu_63': {
                'type': 'str',
            },
            'cpu_64': {
                'type': 'str',
            },
            'cpu_65': {
                'type': 'str',
            },
            'cpu_66': {
                'type': 'str',
            },
            'cpu_67': {
                'type': 'str',
            },
            'cpu_68': {
                'type': 'str',
            },
            'cpu_69': {
                'type': 'str',
            },
            'cpu_70': {
                'type': 'str',
            },
            'cpu_71': {
                'type': 'str',
            },
            'cpu_72': {
                'type': 'str',
            },
            'cpu_73': {
                'type': 'str',
            },
            'cpu_74': {
                'type': 'str',
            },
            'cpu_75': {
                'type': 'str',
            },
            'cpu_76': {
                'type': 'str',
            },
            'cpu_77': {
                'type': 'str',
            },
            'cpu_78': {
                'type': 'str',
            },
            'cpu_79': {
                'type': 'str',
            },
            'cpu_80': {
                'type': 'str',
            },
            'cpu_81': {
                'type': 'str',
            },
            'cpu_82': {
                'type': 'str',
            },
            'cpu_83': {
                'type': 'str',
            },
            'cpu_84': {
                'type': 'str',
            },
            'cpu_85': {
                'type': 'str',
            },
            'cpu_86': {
                'type': 'str',
            },
            'cpu_87': {
                'type': 'str',
            },
            'cpu_88': {
                'type': 'str',
            },
            'cpu_89': {
                'type': 'str',
            },
            'cpu_90': {
                'type': 'str',
            },
            'cpu_91': {
                'type': 'str',
            },
            'cpu_92': {
                'type': 'str',
            },
            'cpu_93': {
                'type': 'str',
            },
            'cpu_94': {
                'type': 'str',
            },
            'cpu_95': {
                'type': 'str',
            },
            'cpu_96': {
                'type': 'str',
            },
            'cpu_97': {
                'type': 'str',
            },
            'cpu_98': {
                'type': 'str',
            },
            'cpu_99': {
                'type': 'str',
            },
            'cpu_100': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/data-cpu"

    f_dict = {}

    return url_base.format(**f_dict)


def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
    return module.client.get(stats_url(module))


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
    url_base = "/axapi/v3/system/data-cpu"

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
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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
