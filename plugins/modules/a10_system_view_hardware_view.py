#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_system_view_hardware_view
description:
    - Field hardware_view
author: A10 Networks
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
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            platform_description:
                description:
                - "Field platform_description"
                type: str
            serial:
                description:
                - "Field serial"
                type: str
            cpu:
                description:
                - "Field cpu"
                type: str
            cpu_cores:
                description:
                - "Field cpu_cores"
                type: int
            cpu_stepping:
                description:
                - "Field cpu_stepping"
                type: int
            storage:
                description:
                - "Field storage"
                type: str
            memory:
                description:
                - "Field memory"
                type: str
            ssl_cards:
                description:
                - "Field ssl_cards"
                type: dict
            octeon:
                description:
                - "Field octeon"
                type: int
            compression_cards:
                description:
                - "Field compression_cards"
                type: dict
            l23_asic:
                description:
                - "Field l23_asic"
                type: str
            ipmi:
                description:
                - "Field ipmi"
                type: str
            ports:
                description:
                - "Field ports"
                type: str
            plat_flag:
                description:
                - "Field plat_flag"
                type: str
            bios_version:
                description:
                - "Field bios_version"
                type: str
            bios_release_date:
                description:
                - "Field bios_release_date"
                type: str
            nvm_firmware_versoin:
                description:
                - "Field nvm_firmware_versoin"
                type: str
            fpga_summary:
                description:
                - "Field fpga_summary"
                type: str
            fpga_date:
                description:
                - "Field fpga_date"
                type: str
            disk_total:
                description:
                - "Field disk_total"
                type: int
            disk_used:
                description:
                - "Field disk_used"
                type: int
            disk_free:
                description:
                - "Field disk_free"
                type: int
            disk_percentage:
                description:
                - "Field disk_percentage"
                type: int
            disk1_status:
                description:
                - "Field disk1_status"
                type: str
            disk2_status:
                description:
                - "Field disk2_status"
                type: str
            num_disks:
                description:
                - "Field num_disks"
                type: int
            raid_present:
                description:
                - "Field raid_present"
                type: int
            raid_list:
                description:
                - "Field raid_list"
                type: list
            psu1_np15:
                description:
                - "Field psu1_np15"
                type: str
            psu2_np15:
                description:
                - "Field psu2_np15"
                type: str
            spe_present:
                description:
                - "Field spe_present"
                type: str
            bypass_pr:
                description:
                - "Field bypass_pr"
                type: int
            bypass_list:
                description:
                - "Field bypass_list"
                type: list
            alldynamic:
                description:
                - "Field alldynamic"
                type: int
            mcpld_type:
                description:
                - "Field mcpld_type"
                type: int
            mcpld_date:
                description:
                - "Field mcpld_date"
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
AVAILABLE_PROPERTIES = ["oper", "uuid", ]


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
        'uuid': {
            'type': 'str',
            },
        'oper': {
            'type': 'dict',
            'platform_description': {
                'type': 'str',
                },
            'serial': {
                'type': 'str',
                },
            'cpu': {
                'type': 'str',
                },
            'cpu_cores': {
                'type': 'int',
                },
            'cpu_stepping': {
                'type': 'int',
                },
            'storage': {
                'type': 'str',
                },
            'memory': {
                'type': 'str',
                },
            'ssl_cards': {
                'type': 'dict',
                'ssl_devices': {
                    'type': 'int',
                    },
                'nitroxpx': {
                    'type': 'int',
                    },
                'nitrox3': {
                    'type': 'int',
                    },
                'nitrox3_cores': {
                    'type': 'int',
                    },
                'nitrox5': {
                    'type': 'int',
                    },
                'nitrox5_cores': {
                    'type': 'int',
                    },
                'nitrox2': {
                    'type': 'int',
                    },
                'nitrox1': {
                    'type': 'int',
                    },
                'hsm': {
                    'type': 'int',
                    },
                'unknown_ssl_cards': {
                    'type': 'int',
                    },
                'coleto_ssl_cards': {
                    'type': 'int',
                    }
                },
            'octeon': {
                'type': 'int',
                },
            'compression_cards': {
                'type': 'dict',
                'gzip_devices': {
                    'type': 'int',
                    },
                'aha363': {
                    'type': 'int',
                    },
                'unknown_compression': {
                    'type': 'int',
                    }
                },
            'l23_asic': {
                'type': 'str',
                },
            'ipmi': {
                'type': 'str',
                },
            'ports': {
                'type': 'str',
                },
            'plat_flag': {
                'type': 'str',
                },
            'bios_version': {
                'type': 'str',
                },
            'bios_release_date': {
                'type': 'str',
                },
            'nvm_firmware_versoin': {
                'type': 'str',
                },
            'fpga_summary': {
                'type': 'str',
                },
            'fpga_date': {
                'type': 'str',
                },
            'disk_total': {
                'type': 'int',
                },
            'disk_used': {
                'type': 'int',
                },
            'disk_free': {
                'type': 'int',
                },
            'disk_percentage': {
                'type': 'int',
                },
            'disk1_status': {
                'type': 'str',
                },
            'disk2_status': {
                'type': 'str',
                },
            'num_disks': {
                'type': 'int',
                },
            'raid_present': {
                'type': 'int',
                },
            'raid_list': {
                'type': 'list',
                'md_name': {
                    'type': 'str',
                    },
                'md_pri': {
                    'type': 'str',
                    },
                'md_sec': {
                    'type': 'str',
                    }
                },
            'psu1_np15': {
                'type': 'str',
                },
            'psu2_np15': {
                'type': 'str',
                },
            'spe_present': {
                'type': 'str',
                },
            'bypass_pr': {
                'type': 'int',
                },
            'bypass_list': {
                'type': 'list',
                'bypass_name': {
                    'type': 'str',
                    },
                'bypass_info': {
                    'type': 'str',
                    }
                },
            'alldynamic': {
                'type': 'int',
                },
            'mcpld_type': {
                'type': 'int',
                },
            'mcpld_date': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system-view/hardware-view"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/system-view/hardware-view"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config):
    if existing_config:
        result["changed"] = True
    return result


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
    payload = utils.build_json("hardware-view", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["hardware-view"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["hardware-view-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["hardware-view"]["oper"] if info != "NotFound" else info
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
