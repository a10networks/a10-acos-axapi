#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_template_limit_policy
description:
    - Create a Limit Policy
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
    policy_number:
        description:
        - "Limit Policy Number"
        type: int
        required: True
    max_min_fair:
        description:
        - "Enable max-min-fairness"
        type: bool
        required: False
    parent:
        description:
        - "Specify the parent of limit-policy"
        type: int
        required: False
    limit_concurrent_sessions:
        description:
        - "Enable Concurrent Session Limit (Number of Concurrent Sessions)"
        type: int
        required: False
    log:
        description:
        - "Log when Session Limit is exceeded"
        type: bool
        required: False
    limit_scope:
        description:
        - "'aggregate'= Rule Level; 'subscriber-ip'= Subscriber IP Level; 'subscriber-
          prefix'= Subscriber Prefix Level; 'radius'= To apply rate-limit using RADIUS
          attribute.;"
        type: str
        required: False
    prefix_length:
        description:
        - "Prefix length"
        type: int
        required: False
    attribute:
        description:
        - "'usergroup'= To apply rate-limit at the level of user group.; 'userid'= To
          apply rate-limit at the level of user ID.;"
        type: str
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
    limit_pps:
        description:
        - "Field limit_pps"
        type: dict
        required: False
        suboptions:
            uplink:
                description:
                - "Uplink PPS limit (Number of Packets per second)"
                type: int
            uplink_burstsize:
                description:
                - "PPS Token Bucket Size (Must Exceed Configured Rate) (In Packets)"
                type: int
            uplink_relaxed:
                description:
                - "Relax the limitation when the policy has more tokens from the parent of policy"
                type: bool
            downlink:
                description:
                - "Downlink PPS limit (Number of Packets per second)"
                type: int
            ddos_protection_factor:
                description:
                - "Enable DDoS Protection (Multiplier of the downlink PPS)"
                type: int
            downlink_burstsize:
                description:
                - "PPS Token Bucket Size (Must Exceed Configured Rate) (In Packets)"
                type: int
            downlink_relaxed:
                description:
                - "Relax the limitation when the policy has more tokens from the parent of policy"
                type: bool
            total:
                description:
                - "Total PPS limit (Number of Packets per second)"
                type: int
            total_burstsize:
                description:
                - "PPS Token Bucket Size (Must Exceed Configured Rate) (In Packets)"
                type: int
            total_relaxed:
                description:
                - "Relax the limitation when the policy has more tokens from the parent of policy"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    limit_throughput:
        description:
        - "Field limit_throughput"
        type: dict
        required: False
        suboptions:
            uplink:
                description:
                - "Uplink Throughput limit (Megabites/sec (default) other units= Kilobites/sec,
          Gigabites/sec)"
                type: int
            uplink_unit:
                description:
                - "'Mbps'= default; 'Kbps'= minimum configurable limit is 100 Kbps; 'Gbps'=
          maximum configurable limit is 10000 Gbps;"
                type: str
            uplink_burstsize:
                description:
                - "Token Bucket Size (Must Exceed Configured Rate) (Megabites/sec (default) other
          units= Kilobites/sec, Gigabites/sec)"
                type: int
            uplink_burstsize_unit:
                description:
                - "'Mbps'= default; 'Kbps'= minimum configurable limit is 100 Kbps; 'Gbps'=
          maximum configurable limit is 10000 Gbps;"
                type: str
            uplink_relaxed:
                description:
                - "Relax the limitation when the policy has more tokens from the parent of policy"
                type: bool
            downlink:
                description:
                - "Downlink Throughput limit (Megabites/sec (default) other units= Kilobites/sec,
          Gigabites/sec)"
                type: int
            downlink_unit:
                description:
                - "'Mbps'= default; 'Kbps'= minimum configurable limit is 100 Kbps; 'Gbps'=
          maximum configurable limit is 10000 Gbps;"
                type: str
            downlink_burstsize:
                description:
                - "Token Bucket Size (Must Exceed Configured Rate) (Megabites/sec (default) other
          units= Kilobites/sec, Gigabites/sec)"
                type: int
            downlink_burstsize_unit:
                description:
                - "'Mbps'= default; 'Kbps'= minimum configurable limit is 100 Kbps; 'Gbps'=
          maximum configurable limit is 10000 Gbps;"
                type: str
            downlink_relaxed:
                description:
                - "Relax the limitation when the policy has more tokens from the parent of policy"
                type: bool
            total:
                description:
                - "Total Throughput limit (Megabites/sec (default) other units= Kilobites/sec,
          Gigabites/sec)"
                type: int
            total_unit:
                description:
                - "'Mbps'= default; 'Kbps'= minimum configurable limit is 100 Kbps; 'Gbps'=
          maximum configurable limit is 10000 Gbps;"
                type: str
            total_burstsize:
                description:
                - "Token Bucket Size (Must Exceed Configured Rate) (Megabites/sec (default) other
          units= Kilobites/sec, Gigabites/sec)"
                type: int
            total_burstsize_unit:
                description:
                - "'Mbps'= default; 'Kbps'= minimum configurable limit is 100 Kbps; 'Gbps'=
          maximum configurable limit is 10000 Gbps;"
                type: str
            total_relaxed:
                description:
                - "Relax the limitation when the policy has more tokens from the parent of policy"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    limit_cps:
        description:
        - "Field limit_cps"
        type: dict
        required: False
        suboptions:
            value:
                description:
                - "Connections Per Second Rate Limit (Number of Connections per second)"
                type: int
            burstsize:
                description:
                - "CPS Token Bucket Size (Must Exceed Configured Rate) (In Connections per second)"
                type: int
            relaxed:
                description:
                - "Relax the limitation when the policy has more tokens from the parent of policy"
                type: bool
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
AVAILABLE_PROPERTIES = ["attribute", "limit_concurrent_sessions", "limit_cps", "limit_pps", "limit_scope", "limit_throughput", "log", "max_min_fair", "parent", "policy_number", "prefix_length", "user_tag", "uuid", ]


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
        'policy_number': {
            'type': 'int',
            'required': True,
            },
        'max_min_fair': {
            'type': 'bool',
            },
        'parent': {
            'type': 'int',
            },
        'limit_concurrent_sessions': {
            'type': 'int',
            },
        'log': {
            'type': 'bool',
            },
        'limit_scope': {
            'type': 'str',
            'choices': ['aggregate', 'subscriber-ip', 'subscriber-prefix', 'radius']
            },
        'prefix_length': {
            'type': 'int',
            },
        'attribute': {
            'type': 'str',
            'choices': ['usergroup', 'userid']
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'limit_pps': {
            'type': 'dict',
            'uplink': {
                'type': 'int',
                },
            'uplink_burstsize': {
                'type': 'int',
                },
            'uplink_relaxed': {
                'type': 'bool',
                },
            'downlink': {
                'type': 'int',
                },
            'ddos_protection_factor': {
                'type': 'int',
                },
            'downlink_burstsize': {
                'type': 'int',
                },
            'downlink_relaxed': {
                'type': 'bool',
                },
            'total': {
                'type': 'int',
                },
            'total_burstsize': {
                'type': 'int',
                },
            'total_relaxed': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'limit_throughput': {
            'type': 'dict',
            'uplink': {
                'type': 'int',
                },
            'uplink_unit': {
                'type': 'str',
                'choices': ['Mbps', 'Kbps', 'Gbps']
                },
            'uplink_burstsize': {
                'type': 'int',
                },
            'uplink_burstsize_unit': {
                'type': 'str',
                'choices': ['Mbps', 'Kbps', 'Gbps']
                },
            'uplink_relaxed': {
                'type': 'bool',
                },
            'downlink': {
                'type': 'int',
                },
            'downlink_unit': {
                'type': 'str',
                'choices': ['Mbps', 'Kbps', 'Gbps']
                },
            'downlink_burstsize': {
                'type': 'int',
                },
            'downlink_burstsize_unit': {
                'type': 'str',
                'choices': ['Mbps', 'Kbps', 'Gbps']
                },
            'downlink_relaxed': {
                'type': 'bool',
                },
            'total': {
                'type': 'int',
                },
            'total_unit': {
                'type': 'str',
                'choices': ['Mbps', 'Kbps', 'Gbps']
                },
            'total_burstsize': {
                'type': 'int',
                },
            'total_burstsize_unit': {
                'type': 'str',
                'choices': ['Mbps', 'Kbps', 'Gbps']
                },
            'total_relaxed': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'limit_cps': {
            'type': 'dict',
            'value': {
                'type': 'int',
                },
            'burstsize': {
                'type': 'int',
                },
            'relaxed': {
                'type': 'bool',
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
    url_base = "/axapi/v3/template/limit-policy/{policy_number}"

    f_dict = {}
    if '/' in str(module.params["policy_number"]):
        f_dict["policy_number"] = module.params["policy_number"].replace("/", "%2F")
    else:
        f_dict["policy_number"] = module.params["policy_number"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/template/limit-policy"

    f_dict = {}
    f_dict["policy_number"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["limit-policy"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["limit-policy"].get(k) != v:
            change_results["changed"] = True
            config_changes["limit-policy"][k] = v

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
    payload = utils.build_json("limit-policy", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["limit-policy"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["limit-policy-list"] if info != "NotFound" else info
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
