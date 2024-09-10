#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_table
description:
    - table counters
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
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            dst_learn:
                description:
                - "Dst Entry Learned"
                type: str
            dst_hit:
                description:
                - "Dst Entry Hit"
                type: str
            dst_miss:
                description:
                - "Dst Entry Missed"
                type: str
            dst_entry_aged:
                description:
                - "Dst Entry Aged"
                type: str
            src_learn:
                description:
                - "Src Entry Learned"
                type: str
            src_hit:
                description:
                - "Src Entry Hit"
                type: str
            src_miss:
                description:
                - "Src Entry Missed"
                type: str
            src_entry_aged:
                description:
                - "Src Entry Aged"
                type: str
            src_dst_learn:
                description:
                - "SrcDst Entry Learned"
                type: str
            src_dst_hit:
                description:
                - "SrcDst Entry Hit"
                type: str
            src_dst_miss:
                description:
                - "SrcDst Entry Missed"
                type: str
            src_dst_entry_aged:
                description:
                - "SrcDst Entry Aged"
                type: str
            telem_err_misc:
                description:
                - "From-l3-peer= Misc Error"
                type: str
            telem_route_add_rcvd:
                description:
                - "From-l3-peer= Route-add Received"
                type: str
            telem_route_del_rcvd:
                description:
                - "From-l3-peer= Route-del Received"
                type: str
            telem_entry_created:
                description:
                - "From-l3-peer= Zone Entry Created"
                type: str
            telem_entry_cleared:
                description:
                - "From-l3-peer= Zone Entry Deleted"
                type: str
            telem_err_telem_entry_pre_exist:
                description:
                - "From-l3-peer= Zone Entry Pre-exist"
                type: str
            telem_err_conflict_with_static:
                description:
                - "From-l3-peer= Conflict with Static Entry"
                type: str
            telem_err_fail_to_create:
                description:
                - "From-l3-peer= Zone Entry Create Fail"
                type: str
            telem_err_fail_to_delete:
                description:
                - "From-l3-peer= Zone Entry Delete Fail"
                type: str
            src_zone_service_learn:
                description:
                - "SrcZoneService Entry Learned"
                type: str
            src_zone_service_hit:
                description:
                - "SrcZoneService Entry Hit"
                type: str
            src_zone_service_miss:
                description:
                - "SrcZoneService Entry Missed"
                type: str
            src_zone_service_entry_aged:
                description:
                - "SrcZoneService Entry Aged"
                type: str
            dst_white_list:
                description:
                - "Dst Entry Whitelisted"
                type: str
            src_white_list:
                description:
                - "Src Entry Whitelisted"
                type: str
            src_dst_white_list:
                description:
                - "SrcDst Entry Whitelisted"
                type: str
            src_zone_service_white_list:
                description:
                - "SrcZoneService Entry Whitelisted"
                type: str
            dst_black_list:
                description:
                - "Dst Entry Blacklisted"
                type: str
            src_black_list:
                description:
                - "Src Entry Blacklisted"
                type: str
            src_dst_black_list:
                description:
                - "SrcDst Entry Blacklisted"
                type: str
            src_zone_service_black_list:
                description:
                - "SrcZoneService Entry Blacklisted"
                type: str
            dst_learning_thre_exceed:
                description:
                - "Dst Dynamic Entry Count Overflow"
                type: str
            dst_over_thre_policy_at_learning:
                description:
                - "Dst Overflow Policy Hit At Learning Stage"
                type: str
            src_learning_thre_exceed:
                description:
                - "Src Dynamic Entry Count Overflow"
                type: str
            src_over_thre_policy_at_lookup:
                description:
                - "Src Overflow Policy Hit At Lookup Stage"
                type: str
            src_over_thre_policy_at_learning:
                description:
                - "Src Overflow Policy Hit At Learning Stage"
                type: str
            src_dst_learning_thre_exceed:
                description:
                - "SrcDst Dynamic Entry Count Overflow"
                type: str
            src_dst_over_thre_policy_at_lookup:
                description:
                - "SrcDst Overflow Policy Hit At Lookup Stage"
                type: str
            src_dst_over_thre_policy_at_learning:
                description:
                - "SrcDst Overflow Policy Hit At Learning Stage"
                type: str
            src_zone_service_learning_thre_exceed:
                description:
                - "SrcZoneService Dynamic Entry Count Overflow"
                type: str
            src_zone_service_over_thre_policy_at_lookup:
                description:
                - "SrcZoneService Overflow Policy Lookup Hit"
                type: str
            src_zone_service_over_thre_policy_at_learning:
                description:
                - "SrcZoneService Overflow Policy Learning Hit"
                type: str
            entry_oom:
                description:
                - "Out of Entry Memory"
                type: str
            entry_ext_oom:
                description:
                - "Out of Entry Extension Memory"
                type: str
            src_dst_classlist_overflow_policy_at_learning:
                description:
                - "SrcDst Class-List Overflow Policy Hit"
                type: str
            src_zone_service_classlist_overflow_policy_at_learning:
                description:
                - "SrcZoneService Class-List Overflow Policy Hit"
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
AVAILABLE_PROPERTIES = ["stats", "uuid", ]


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
        'stats': {
            'type': 'dict',
            'dst_learn': {
                'type': 'str',
                },
            'dst_hit': {
                'type': 'str',
                },
            'dst_miss': {
                'type': 'str',
                },
            'dst_entry_aged': {
                'type': 'str',
                },
            'src_learn': {
                'type': 'str',
                },
            'src_hit': {
                'type': 'str',
                },
            'src_miss': {
                'type': 'str',
                },
            'src_entry_aged': {
                'type': 'str',
                },
            'src_dst_learn': {
                'type': 'str',
                },
            'src_dst_hit': {
                'type': 'str',
                },
            'src_dst_miss': {
                'type': 'str',
                },
            'src_dst_entry_aged': {
                'type': 'str',
                },
            'telem_err_misc': {
                'type': 'str',
                },
            'telem_route_add_rcvd': {
                'type': 'str',
                },
            'telem_route_del_rcvd': {
                'type': 'str',
                },
            'telem_entry_created': {
                'type': 'str',
                },
            'telem_entry_cleared': {
                'type': 'str',
                },
            'telem_err_telem_entry_pre_exist': {
                'type': 'str',
                },
            'telem_err_conflict_with_static': {
                'type': 'str',
                },
            'telem_err_fail_to_create': {
                'type': 'str',
                },
            'telem_err_fail_to_delete': {
                'type': 'str',
                },
            'src_zone_service_learn': {
                'type': 'str',
                },
            'src_zone_service_hit': {
                'type': 'str',
                },
            'src_zone_service_miss': {
                'type': 'str',
                },
            'src_zone_service_entry_aged': {
                'type': 'str',
                },
            'dst_white_list': {
                'type': 'str',
                },
            'src_white_list': {
                'type': 'str',
                },
            'src_dst_white_list': {
                'type': 'str',
                },
            'src_zone_service_white_list': {
                'type': 'str',
                },
            'dst_black_list': {
                'type': 'str',
                },
            'src_black_list': {
                'type': 'str',
                },
            'src_dst_black_list': {
                'type': 'str',
                },
            'src_zone_service_black_list': {
                'type': 'str',
                },
            'dst_learning_thre_exceed': {
                'type': 'str',
                },
            'dst_over_thre_policy_at_learning': {
                'type': 'str',
                },
            'src_learning_thre_exceed': {
                'type': 'str',
                },
            'src_over_thre_policy_at_lookup': {
                'type': 'str',
                },
            'src_over_thre_policy_at_learning': {
                'type': 'str',
                },
            'src_dst_learning_thre_exceed': {
                'type': 'str',
                },
            'src_dst_over_thre_policy_at_lookup': {
                'type': 'str',
                },
            'src_dst_over_thre_policy_at_learning': {
                'type': 'str',
                },
            'src_zone_service_learning_thre_exceed': {
                'type': 'str',
                },
            'src_zone_service_over_thre_policy_at_lookup': {
                'type': 'str',
                },
            'src_zone_service_over_thre_policy_at_learning': {
                'type': 'str',
                },
            'entry_oom': {
                'type': 'str',
                },
            'entry_ext_oom': {
                'type': 'str',
                },
            'src_dst_classlist_overflow_policy_at_learning': {
                'type': 'str',
                },
            'src_zone_service_classlist_overflow_policy_at_learning': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/table"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/table"

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
    payload = utils.build_json("table", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["table"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["table-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["table"]["stats"] if info != "NotFound" else info
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
