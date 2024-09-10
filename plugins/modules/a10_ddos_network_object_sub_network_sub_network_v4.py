#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_network_object_sub_network_sub_network_v4
description:
    - Configure sub-network in a DDos Network Object
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
    network_object_object_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    subnet_ip_addr:
        description:
        - "IPv4 Subnet/host, supported prefix range is from 24 to 32"
        type: str
        required: True
    host_anomaly_threshold:
        description:
        - "Field host_anomaly_threshold"
        type: dict
        required: False
        suboptions:
            static_pkt_rate_threshold:
                description:
                - "Packet rate of per host"
                type: int
            static_rev_pkt_rate_threshold:
                description:
                - "Packet rate of per host"
                type: int
            static_bit_rate_threshold:
                description:
                - "Bit rate of per host"
                type: int
            static_rev_bit_rate_threshold:
                description:
                - "Bit rate of per host"
                type: int
            static_undiscovered_pkt_rate_threshold:
                description:
                - "Undiscovered packet rate of per host"
                type: int
            static_flow_count_threshold:
                description:
                - "Flow count of per host"
                type: int
            static_syn_rate_threshold:
                description:
                - "SYN packet rate of per host"
                type: int
            static_fin_rate_threshold:
                description:
                - "FIN packet rate of per host"
                type: int
            static_rst_rate_threshold:
                description:
                - "RST packet rate of per host"
                type: int
            static_tcp_pkt_rate_threshold:
                description:
                - "TCP packet rate of per host"
                type: int
            static_udp_pkt_rate_threshold:
                description:
                - "UDP packet rate of per host"
                type: int
            static_icmp_pkt_rate_threshold:
                description:
                - "ICMP packet rate of per host"
                type: int
            static_undiscovered_host_pkt_rate_threshold:
                description:
                - "packet rate of per undiscovered host"
                type: int
            static_undiscovered_host_bit_rate_threshold:
                description:
                - "Bit rate of per undiscovered host"
                type: int
    sub_network_anomaly_threshold:
        description:
        - "Field sub_network_anomaly_threshold"
        type: dict
        required: False
        suboptions:
            static_sub_network_pkt_rate:
                description:
                - "Packet rate of the sub-network"
                type: int
            static_sub_network_bit_rate:
                description:
                - "Bit rate of the sub-network"
                type: int
    subnet_breakdown:
        description:
        - "additional layer of breakdown subnet"
        type: int
        required: False
    breakdown_subnet_threshold:
        description:
        - "Field breakdown_subnet_threshold"
        type: dict
        required: False
        suboptions:
            breakdown_subnet_pkt_rate:
                description:
                - "Packet rate of per host"
                type: int
            breakdown_subnet_bit_rate:
                description:
                - "Bit rate of per host"
                type: int
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
                - "'all'= all; 'packet_rate'= PPS; 'bit_rate'= B(bits)PS;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            packet_rate:
                description:
                - "PPS"
                type: str
            bit_rate:
                description:
                - "B(bits)PS"
                type: str
            subnet_ip_addr:
                description:
                - "IPv4 Subnet/host, supported prefix range is from 24 to 32"
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
AVAILABLE_PROPERTIES = ["breakdown_subnet_threshold", "host_anomaly_threshold", "sampling_enable", "stats", "sub_network_anomaly_threshold", "subnet_breakdown", "subnet_ip_addr", "uuid", ]


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
        'subnet_ip_addr': {
            'type': 'str',
            'required': True,
            },
        'host_anomaly_threshold': {
            'type': 'dict',
            'static_pkt_rate_threshold': {
                'type': 'int',
                },
            'static_rev_pkt_rate_threshold': {
                'type': 'int',
                },
            'static_bit_rate_threshold': {
                'type': 'int',
                },
            'static_rev_bit_rate_threshold': {
                'type': 'int',
                },
            'static_undiscovered_pkt_rate_threshold': {
                'type': 'int',
                },
            'static_flow_count_threshold': {
                'type': 'int',
                },
            'static_syn_rate_threshold': {
                'type': 'int',
                },
            'static_fin_rate_threshold': {
                'type': 'int',
                },
            'static_rst_rate_threshold': {
                'type': 'int',
                },
            'static_tcp_pkt_rate_threshold': {
                'type': 'int',
                },
            'static_udp_pkt_rate_threshold': {
                'type': 'int',
                },
            'static_icmp_pkt_rate_threshold': {
                'type': 'int',
                },
            'static_undiscovered_host_pkt_rate_threshold': {
                'type': 'int',
                },
            'static_undiscovered_host_bit_rate_threshold': {
                'type': 'int',
                }
            },
        'sub_network_anomaly_threshold': {
            'type': 'dict',
            'static_sub_network_pkt_rate': {
                'type': 'int',
                },
            'static_sub_network_bit_rate': {
                'type': 'int',
                }
            },
        'subnet_breakdown': {
            'type': 'int',
            },
        'breakdown_subnet_threshold': {
            'type': 'dict',
            'breakdown_subnet_pkt_rate': {
                'type': 'int',
                },
            'breakdown_subnet_bit_rate': {
                'type': 'int',
                }
            },
        'uuid': {
            'type': 'str',
            },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type': 'str',
                'choices': ['all', 'packet_rate', 'bit_rate']
                }
            },
        'stats': {
            'type': 'dict',
            'packet_rate': {
                'type': 'str',
                },
            'bit_rate': {
                'type': 'str',
                },
            'subnet_ip_addr': {
                'type': 'str',
                'required': True,
                }
            }
        })
    # Parent keys
    rv.update(dict(network_object_object_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/network-object/{network_object_object_name}/sub-network/sub-network-v4/{subnet_ip_addr}"

    f_dict = {}
    if '/' in str(module.params["subnet_ip_addr"]):
        f_dict["subnet_ip_addr"] = module.params["subnet_ip_addr"].replace("/", "%2F")
    else:
        f_dict["subnet_ip_addr"] = module.params["subnet_ip_addr"]
    if '/' in module.params["network_object_object_name"]:
        f_dict["network_object_object_name"] = module.params["network_object_object_name"].replace("/", "%2F")
    else:
        f_dict["network_object_object_name"] = module.params["network_object_object_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/network-object/{network_object_object_name}/sub-network/sub-network-v4"

    f_dict = {}
    f_dict["subnet_ip_addr"] = ""
    f_dict["network_object_object_name"] = module.params["network_object_object_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["sub-network-v4"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["sub-network-v4"].get(k) != v:
            change_results["changed"] = True
            config_changes["sub-network-v4"][k] = v

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
    payload = utils.build_json("sub-network-v4", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["sub-network-v4"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["sub-network-v4-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["sub-network-v4"]["stats"] if info != "NotFound" else info
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
