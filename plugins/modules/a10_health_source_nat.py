#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_health_source_nat
description:
    - Define Source NAT for health monitor
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
    source_nat_pool:
        description:
        - "Use source nat for all health check (nat pool)"
        type: str
        required: False
    source_nat_pool_v6:
        description:
        - "Use ipv6 source nat for all health check (nat pool)"
        type: str
        required: False
    smart_nat_precedence:
        description:
        - "Use smart nat when resourece is presented in virtual port"
        type: bool
        required: False
    smart_nat_vrid:
        description:
        - "Smart nat VRID"
        type: int
        required: False
    enable_vrrp_a_mode:
        description:
        - "Forward health check by active device only"
        type: bool
        required: False
    interface:
        description:
        - "'ethernet'= ethernet; 'trunk'= trunk; 've'= ve;"
        type: str
        required: False
    ethernet:
        description:
        - "Ethernet interface number"
        type: str
        required: False
    trunk:
        description:
        - "Trunk interface number"
        type: int
        required: False
    ve:
        description:
        - "Virtual ethernet interface number"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'act_recv_from_sby'= Packets received from standby;
          'act_send_to_sby'= Packets sent to standby; 'sby_recv_from_act'= Packets
          received from active; 'sby_send_to_act'= Packets sent to active;
          'sby_recv_from_act_err'= Packets received from active error;
          'recv_from_kernel'= Packets received from kernel; 'send_to_kernel'= Packets
          sent to kernel; 'send_to_kernel_err'= Packets sent to kernel error;
          'sby_no_peer'= Peer not found on standby; 'dcmsg_err'= DCMSG error;
          'no_slb_object'= SLB object not found; 'smart_nat_init_port_err'= Smart NAT
          port initialization error; 'smart_nat_init_inst_err'= Smart NAT instance
          initialization error; 'smart_nat_rserver_route_err'= Smart NAT rserver route
          update error; 'smart_nat_rserver_ip_err'= Smart NAT rserver ip update error;
          'nat_resource_err'= NAT resource error; 'frag_err'= Fragmentation error;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            act_recv_from_sby:
                description:
                - "Packets received from standby"
                type: str
            act_send_to_sby:
                description:
                - "Packets sent to standby"
                type: str
            sby_recv_from_act:
                description:
                - "Packets received from active"
                type: str
            sby_send_to_act:
                description:
                - "Packets sent to active"
                type: str
            sby_recv_from_act_err:
                description:
                - "Packets received from active error"
                type: str
            recv_from_kernel:
                description:
                - "Packets received from kernel"
                type: str
            send_to_kernel:
                description:
                - "Packets sent to kernel"
                type: str
            send_to_kernel_err:
                description:
                - "Packets sent to kernel error"
                type: str
            sby_no_peer:
                description:
                - "Peer not found on standby"
                type: str
            dcmsg_err:
                description:
                - "DCMSG error"
                type: str
            no_slb_object:
                description:
                - "SLB object not found"
                type: str
            smart_nat_init_port_err:
                description:
                - "Smart NAT port initialization error"
                type: str
            smart_nat_init_inst_err:
                description:
                - "Smart NAT instance initialization error"
                type: str
            smart_nat_rserver_route_err:
                description:
                - "Smart NAT rserver route update error"
                type: str
            smart_nat_rserver_ip_err:
                description:
                - "Smart NAT rserver ip update error"
                type: str
            nat_resource_err:
                description:
                - "NAT resource error"
                type: str
            frag_err:
                description:
                - "Fragmentation error"
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
AVAILABLE_PROPERTIES = ["enable_vrrp_a_mode", "ethernet", "interface", "sampling_enable", "smart_nat_precedence", "smart_nat_vrid", "source_nat_pool", "source_nat_pool_v6", "stats", "trunk", "uuid", "ve", ]


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
        'source_nat_pool': {
            'type': 'str',
            },
        'source_nat_pool_v6': {
            'type': 'str',
            },
        'smart_nat_precedence': {
            'type': 'bool',
            },
        'smart_nat_vrid': {
            'type': 'int',
            },
        'enable_vrrp_a_mode': {
            'type': 'bool',
            },
        'interface': {
            'type': 'str',
            'choices': ['ethernet', 'trunk', 've']
            },
        'ethernet': {
            'type': 'str',
            },
        'trunk': {
            'type': 'int',
            },
        've': {
            'type': 'int',
            },
        'uuid': {
            'type': 'str',
            },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'act_recv_from_sby', 'act_send_to_sby', 'sby_recv_from_act', 'sby_send_to_act', 'sby_recv_from_act_err', 'recv_from_kernel', 'send_to_kernel', 'send_to_kernel_err', 'sby_no_peer', 'dcmsg_err', 'no_slb_object', 'smart_nat_init_port_err', 'smart_nat_init_inst_err', 'smart_nat_rserver_route_err', 'smart_nat_rserver_ip_err',
                    'nat_resource_err', 'frag_err'
                    ]
                }
            },
        'stats': {
            'type': 'dict',
            'act_recv_from_sby': {
                'type': 'str',
                },
            'act_send_to_sby': {
                'type': 'str',
                },
            'sby_recv_from_act': {
                'type': 'str',
                },
            'sby_send_to_act': {
                'type': 'str',
                },
            'sby_recv_from_act_err': {
                'type': 'str',
                },
            'recv_from_kernel': {
                'type': 'str',
                },
            'send_to_kernel': {
                'type': 'str',
                },
            'send_to_kernel_err': {
                'type': 'str',
                },
            'sby_no_peer': {
                'type': 'str',
                },
            'dcmsg_err': {
                'type': 'str',
                },
            'no_slb_object': {
                'type': 'str',
                },
            'smart_nat_init_port_err': {
                'type': 'str',
                },
            'smart_nat_init_inst_err': {
                'type': 'str',
                },
            'smart_nat_rserver_route_err': {
                'type': 'str',
                },
            'smart_nat_rserver_ip_err': {
                'type': 'str',
                },
            'nat_resource_err': {
                'type': 'str',
                },
            'frag_err': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/health/source-nat"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/health/source-nat"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["source-nat"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["source-nat"].get(k) != v:
            change_results["changed"] = True
            config_changes["source-nat"][k] = v

    change_results["modified_values"].update(**config_changes)
    return change_results


def create(module, result, payload={}):
    call_result = api_client.post(module.client, new_url(module), payload)
    result["axapi_calls"].append(call_result)
    result["modified_values"].update(**call_result["response_body"])
    result["changed"] = True
    return result


def update(module, result, existing_config, payload={}):
    final_payload = copy.deepcopy(payload)
    call_result = api_client.post(module.client, existing_url(module), final_payload)
    result["axapi_calls"].append(call_result)
    if call_result["response_body"] == existing_config:
        result["changed"] = False
    else:
        result["modified_values"].update(**call_result["response_body"])
        result["changed"] = True
    return result


def present(module, result, existing_config):
    payload = utils.build_json("source-nat", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["source-nat"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["source-nat-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["source-nat"]["stats"] if info != "NotFound" else info
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
