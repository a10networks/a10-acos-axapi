#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_system_memory_block_debug
description:
    - Set memory block debug
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
    assert_block:
        description:
        - "Over size block allocation (Assert memory block over size (default= 65536))"
        type: int
        required: False
    pktdump_block:
        description:
        - "Enable pktdump Oversize block request packet"
        type: bool
        required: False
    first_blk:
        description:
        - "First memory block ascending order (default= 8192) (Memory blocks
          32,64,128,256,512,1K,2K,4K,8K,16K,32K,64K)"
        type: int
        required: False
    second_blk:
        description:
        - "Second memory block (default= 16384) (Memory blocks
          32,64,128,256,512,1K,2K,4K,8K,16K,32K,64K)"
        type: int
        required: False
    third_blk:
        description:
        - "Third memory block (default= 32768) (Memory blocks
          32,64,128,256,512,1K,2K,4K,8K,16K,32K,64K)"
        type: int
        required: False
    fourth_blk:
        description:
        - "Fourth memory block (default= 65536) (Memory blocks
          32,64,128,256,512,1K,2K,4K,8K,16K,32K,64K)"
        type: int
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
            a10_mem_id_max:
                description:
                - "Field a10_mem_id_max"
                type: int
            block_debug_arr_zero:
                description:
                - "Field block_debug_arr_zero"
                type: str
            block_debug_arr_one:
                description:
                - "Field block_debug_arr_one"
                type: str
            block_debug_arr_two:
                description:
                - "Field block_debug_arr_two"
                type: str
            block_debug_arr_three:
                description:
                - "Field block_debug_arr_three"
                type: str
            all_everything:
                description:
                - "Field all_everything"
                type: list
            thread_id:
                description:
                - "Field thread_id"
                type: int
            a10_mem:
                description:
                - "Field a10_mem"
                type: list

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
AVAILABLE_PROPERTIES = ["assert_block", "first_blk", "fourth_blk", "oper", "pktdump_block", "second_blk", "third_blk", "uuid", ]


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
        'assert_block': {
            'type': 'int',
            },
        'pktdump_block': {
            'type': 'bool',
            },
        'first_blk': {
            'type': 'int',
            },
        'second_blk': {
            'type': 'int',
            },
        'third_blk': {
            'type': 'int',
            },
        'fourth_blk': {
            'type': 'int',
            },
        'uuid': {
            'type': 'str',
            },
        'oper': {
            'type': 'dict',
            'a10_mem_id_max': {
                'type': 'int',
                },
            'block_debug_arr_zero': {
                'type': 'str',
                },
            'block_debug_arr_one': {
                'type': 'str',
                },
            'block_debug_arr_two': {
                'type': 'str',
                },
            'block_debug_arr_three': {
                'type': 'str',
                },
            'all_everything': {
                'type': 'list',
                'id': {
                    'type': 'int',
                    },
                'module_name': {
                    'type': 'str',
                    },
                'alloc_zero': {
                    'type': 'int',
                    },
                'alloc_one': {
                    'type': 'int',
                    },
                'alloc_two': {
                    'type': 'int',
                    },
                'alloc_three': {
                    'type': 'int',
                    },
                'free_four': {
                    'type': 'int',
                    },
                'free_five': {
                    'type': 'int',
                    },
                'free_six': {
                    'type': 'int',
                    },
                'free_seven': {
                    'type': 'int',
                    },
                'block_debug_alloc_over': {
                    'type': 'int',
                    },
                'block_debug_free_over': {
                    'type': 'int',
                    },
                'block_debug_alloc_max_over': {
                    'type': 'int',
                    },
                'debug_decision_over_size': {
                    'type': 'int',
                    },
                'debug_decision_alloc': {
                    'type': 'int',
                    },
                'debug_decision_free': {
                    'type': 'int',
                    }
                },
            'thread_id': {
                'type': 'int',
                },
            'a10_mem': {
                'type': 'list',
                't_id': {
                    'type': 'int',
                    },
                't_module_name': {
                    'type': 'str',
                    },
                't_alloc_zero': {
                    'type': 'int',
                    },
                't_alloc_one': {
                    'type': 'int',
                    },
                't_alloc_two': {
                    'type': 'int',
                    },
                't_alloc_three': {
                    'type': 'int',
                    },
                't_free_four': {
                    'type': 'int',
                    },
                't_free_five': {
                    'type': 'int',
                    },
                't_free_six': {
                    'type': 'int',
                    },
                't_free_seven': {
                    'type': 'int',
                    },
                't_block_debug_alloc_over': {
                    'type': 'int',
                    },
                't_block_debug_free_over': {
                    'type': 'int',
                    },
                't_block_debug_alloc_max_over': {
                    'type': 'int',
                    },
                't_debug_decision_over_size': {
                    'type': 'int',
                    },
                't_debug_decision_alloc': {
                    'type': 'int',
                    },
                't_debug_decision_free': {
                    'type': 'int',
                    }
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/memory-block-debug"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/system/memory-block-debug"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["memory-block-debug"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["memory-block-debug"].get(k) != v:
            change_results["changed"] = True
            config_changes["memory-block-debug"][k] = v

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
    payload = utils.build_json("memory-block-debug", module.params, AVAILABLE_PROPERTIES)
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

        if state == 'present' or state == 'absent':
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
            if module.params.get("get_type") == "single" or module.params.get("get_type") is None:
                get_result = api_client.get(module.client, existing_url(module))
                result["axapi_calls"].append(get_result)
                info = get_result["response_body"]
                result["acos_info"] = info["memory-block-debug"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["memory-block-debug-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["memory-block-debug"]["oper"] if info != "NotFound" else info
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.auth_session.session_id:
            module.client.auth_session.close()

    return result


"""
    Custom class which override the _check_required_arguments function to check check required arguments based on state and get_type.
"""


class AcosAnsibleModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        super(AcosAnsibleModule, self).__init__(*args, **kwargs)

    def _check_required_arguments(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        # skip validation if state is 'noop' and get_type is 'list'
        if not (param.get("state") == "noop" and param.get("get_type") == "list"):
            missing = []
            if spec is None:
                return missing
            # Check for missing required parameters in the provided argument spec
            for (k, v) in spec.items():
                required = v.get('required', False)
                if required and k not in param:
                    missing.append(k)
            if missing:
                self.fail_json(msg="Missing required parameters: {}".format(", ".join(missing)))


def main():
    module = AcosAnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
