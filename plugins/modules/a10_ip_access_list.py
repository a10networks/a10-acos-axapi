#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ip_access_list
description:
    - Configure Access List
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
        - "IP Access List Name. Does not support name as digits or start with digit."
        type: str
        required: True
    rules:
        description:
        - "Field rules"
        type: list
        required: False
        suboptions:
            seq_num:
                description:
                - "Sequence Number"
                type: int
            action:
                description:
                - "'deny'= Deny; 'permit'= Permit; 'l3-vlan-fwd-disable'= Disable L3 forwarding
          between VLANs;"
                type: str
            remark:
                description:
                - "Access list entry comment (Notes for this ACL)"
                type: str
            icmp:
                description:
                - "Internet Control Message Protocol"
                type: bool
            tcp:
                description:
                - "protocol TCP"
                type: bool
            udp:
                description:
                - "protocol UDP"
                type: bool
            ip:
                description:
                - "Any Internet Protocol"
                type: bool
            service_obj_group:
                description:
                - "Service object group (Source object group name)"
                type: str
            geo_location:
                description:
                - "Specify geo-location name"
                type: str
            icmp_type:
                description:
                - "ICMP type number"
                type: int
            any_type:
                description:
                - "Any ICMP type"
                type: bool
            special_type:
                description:
                - "'echo-reply'= Type 0, echo reply; 'echo-request'= Type 8, echo request; 'info-
          reply'= Type 16, information reply; 'info-request'= Type 15, information
          request; 'mask-reply'= Type 18, address mask reply; 'mask-request'= Type 17,
          address mask request; 'parameter-problem'= Type 12, parameter problem;
          'redirect'= Type 5, redirect message; 'source-quench'= Type 4, source quench;
          'time-exceeded'= Type 11, time exceeded; 'timestamp'= Type 13, timestamp;
          'timestamp-reply'= Type 14, timestamp reply; 'dest-unreachable'= Type 3,
          destination unreachable;"
                type: str
            any_code:
                description:
                - "Any ICMP code"
                type: bool
            icmp_code:
                description:
                - "ICMP code number"
                type: int
            special_code:
                description:
                - "'frag-required'= Code 4, fragmentation required; 'host-unreachable'= Code 1,
          destination host unreachable; 'network-unreachable'= Code 0, destination
          network unreachable; 'port-unreachable'= Code 3, destination port unreachable;
          'proto-unreachable'= Code 2, destination protocol unreachable; 'route-failed'=
          Code 5, source route failed;"
                type: str
            src_any:
                description:
                - "Any source host"
                type: bool
            src_host:
                description:
                - "A single source host (Host address)"
                type: str
            src_subnet:
                description:
                - "Source Address"
                type: str
            src_mask:
                description:
                - "Source Mask 0=apply 255=ignore"
                type: str
            src_object_group:
                description:
                - "Network object group (Source network object group name)"
                type: str
            src_eq:
                description:
                - "Match only packets on a given source port (port number)"
                type: int
            src_gt:
                description:
                - "Match only packets with a greater port number"
                type: int
            src_lt:
                description:
                - "Match only packets with a lower port number"
                type: int
            src_range:
                description:
                - "match only packets in the range of port numbers (Starting Port Number)"
                type: int
            src_port_end:
                description:
                - "Ending Port Number"
                type: int
            dst_any:
                description:
                - "Any destination host"
                type: bool
            dst_host:
                description:
                - "A single destination host (Host address)"
                type: str
            dst_subnet:
                description:
                - "Destination Address"
                type: str
            dst_mask:
                description:
                - "Destination Mask 0=apply 255=ignore"
                type: str
            dst_object_group:
                description:
                - "Destination network object group name"
                type: str
            dst_eq:
                description:
                - "Match only packets on a given destination port (port number)"
                type: int
            dst_gt:
                description:
                - "Match only packets with a greater port number"
                type: int
            dst_lt:
                description:
                - "Match only packets with a lesser port number"
                type: int
            dst_range:
                description:
                - "Match only packets in the range of port numbers (Starting Destination Port
          Number)"
                type: int
            dst_port_end:
                description:
                - "Edning Destination Port Number"
                type: int
            fragments:
                description:
                - "IP fragments"
                type: bool
            vlan:
                description:
                - "VLAN ID"
                type: int
            ethernet:
                description:
                - "Ethernet interface (Port number)"
                type: str
            trunk:
                description:
                - "Ethernet trunk (trunk number)"
                type: str
            dscp:
                description:
                - "DSCP"
                type: int
            established:
                description:
                - "TCP established"
                type: bool
            acl_log:
                description:
                - "Log matches against this entry"
                type: bool
            transparent_session_only:
                description:
                - "Only log transparent sessions"
                type: bool
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
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "name",
    "rules",
    "user_tag",
    "uuid",
]


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
            type='str',
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
        'rules': {
            'type': 'list',
            'seq_num': {
                'type': 'int',
            },
            'action': {
                'type': 'str',
                'choices': ['deny', 'permit', 'l3-vlan-fwd-disable']
            },
            'remark': {
                'type': 'str',
            },
            'icmp': {
                'type': 'bool',
            },
            'tcp': {
                'type': 'bool',
            },
            'udp': {
                'type': 'bool',
            },
            'ip': {
                'type': 'bool',
            },
            'service_obj_group': {
                'type': 'str',
            },
            'geo_location': {
                'type': 'str',
            },
            'icmp_type': {
                'type': 'int',
            },
            'any_type': {
                'type': 'bool',
            },
            'special_type': {
                'type':
                'str',
                'choices': [
                    'echo-reply', 'echo-request', 'info-reply', 'info-request',
                    'mask-reply', 'mask-request', 'parameter-problem',
                    'redirect', 'source-quench', 'time-exceeded', 'timestamp',
                    'timestamp-reply', 'dest-unreachable'
                ]
            },
            'any_code': {
                'type': 'bool',
            },
            'icmp_code': {
                'type': 'int',
            },
            'special_code': {
                'type':
                'str',
                'choices': [
                    'frag-required', 'host-unreachable', 'network-unreachable',
                    'port-unreachable', 'proto-unreachable', 'route-failed'
                ]
            },
            'src_any': {
                'type': 'bool',
            },
            'src_host': {
                'type': 'str',
            },
            'src_subnet': {
                'type': 'str',
            },
            'src_mask': {
                'type': 'str',
            },
            'src_object_group': {
                'type': 'str',
            },
            'src_eq': {
                'type': 'int',
            },
            'src_gt': {
                'type': 'int',
            },
            'src_lt': {
                'type': 'int',
            },
            'src_range': {
                'type': 'int',
            },
            'src_port_end': {
                'type': 'int',
            },
            'dst_any': {
                'type': 'bool',
            },
            'dst_host': {
                'type': 'str',
            },
            'dst_subnet': {
                'type': 'str',
            },
            'dst_mask': {
                'type': 'str',
            },
            'dst_object_group': {
                'type': 'str',
            },
            'dst_eq': {
                'type': 'int',
            },
            'dst_gt': {
                'type': 'int',
            },
            'dst_lt': {
                'type': 'int',
            },
            'dst_range': {
                'type': 'int',
            },
            'dst_port_end': {
                'type': 'int',
            },
            'fragments': {
                'type': 'bool',
            },
            'vlan': {
                'type': 'int',
            },
            'ethernet': {
                'type': 'str',
            },
            'trunk': {
                'type': 'str',
            },
            'dscp': {
                'type': 'int',
            },
            'established': {
                'type': 'bool',
            },
            'acl_log': {
                'type': 'bool',
            },
            'transparent_session_only': {
                'type': 'bool',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'user_tag': {
            'type': 'str',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ip/access-list/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ip/access-list/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["access-list"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["access-list"].get(k) != v:
            change_results["changed"] = True
            config_changes["access-list"][k] = v

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
    payload = utils.build_json("access-list", module.params,
                               AVAILABLE_PROPERTIES)
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
    result = dict(changed=False,
                  messages="",
                  modified_values={},
                  axapi_calls=[])

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

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    valid = True

    run_errors = []
    if state == 'present':
        requires_one_of = sorted([])
        valid, validation_errors = utils.validate(module.params,
                                                  requires_one_of)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    try:
        if a10_partition:
            result["axapi_calls"].append(
                api_client.active_partition(module.client, a10_partition))

        if a10_device_context_id:
            result["axapi_calls"].append(
                api_client.switch_device_context(module.client,
                                                 a10_device_context_id))

        existing_config = api_client.get(module.client, existing_url(module))
        result["axapi_calls"].append(existing_config)
        if existing_config['response_body'] != 'Not Found':
            existing_config = existing_config["response_body"]
        else:
            existing_config = None

        if state == 'present':
            result = present(module, result, existing_config)

        if state == 'absent':
            result = absent(module, result, existing_config)

        if state == 'noop':
            if module.params.get("get_type") == "single":
                result["axapi_calls"].append(
                    api_client.get(module.client, existing_url(module)))
            elif module.params.get("get_type") == "list":
                result["axapi_calls"].append(
                    api_client.get_list(module.client, existing_url(module)))
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    finally:
        if module.client.session.session_id:
            module.client.session.close()

    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
