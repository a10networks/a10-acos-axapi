#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cloud_services_cloud_provider_aws_metrics
description:
    - AWS metrics configuration
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
    action:
        description:
        - "'enable'= Enable AWS CloudWatch; 'disable'= Disable AWS CloudWatch (default);"
        type: str
        required: False
    namespace:
        description:
        - "Specifies the AWS namespace where all the metrics must be published"
        type: str
        required: False
    active_partitions:
        description:
        - "Specifies the thunder active partition name separated by a comma for multiple
          values"
        type: str
        required: False
    cpu:
        description:
        - "'enable'= Enable CPU Metrics; 'disable'= Disable CPU Metrics;"
        type: str
        required: False
    memory:
        description:
        - "'enable'= Enable Memory Metrics; 'disable'= Disable Memory Metrics;"
        type: str
        required: False
    disk:
        description:
        - "'enable'= Enable Disk Metrics; 'disable'= Disable Disk Metrics;"
        type: str
        required: False
    throughput:
        description:
        - "'enable'= Enable Throughput Metrics; 'disable'= Disable Throughput Metrics;"
        type: str
        required: False
    interfaces:
        description:
        - "'enable'= Enable Interfaces Metrics; 'disable'= Disable Interfaces Metrics;"
        type: str
        required: False
    cps:
        description:
        - "'enable'= Enable CPS Metrics; 'disable'= Disable CPS Metrics;"
        type: str
        required: False
    tps:
        description:
        - "'enable'= Enable TPS Metrics; 'disable'= Disable TPS Metrics;"
        type: str
        required: False
    server_down_count:
        description:
        - "'enable'= Enable Server Down Count Metrics; 'disable'= Disable Server Down
          Count Metrics;"
        type: str
        required: False
    server_down_percentage:
        description:
        - "'enable'= Enable Server Down Percentage Metrics; 'disable'= Disable Server Down
          Percentage Metrics;"
        type: str
        required: False
    ssl_cert:
        description:
        - "'enable'= Enable SSL Cert Metrics; 'disable'= Disable SSL Cert Metrics;"
        type: str
        required: False
    server_error:
        description:
        - "'enable'= Enable Server Error Metrics; 'disable'= Disable Server Error Metrics;"
        type: str
        required: False
    sessions:
        description:
        - "'enable'= Enable Sessions Metrics; 'disable'= Disable Sessions Metrics;"
        type: str
        required: False
    packet_drop:
        description:
        - "'enable'= Enable Packet Drop Metrics; 'disable'= Disable Packet Drop Metrics;"
        type: str
        required: False
    packet_rate:
        description:
        - "'enable'= Enable Packet Rate Metrics; 'disable'= Disable Packet Rate Metrics;"
        type: str
        required: False
    uuid:
        description:
        - "uuid of the object"
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
from ansible_collections.a10.acos_axapi.plugins.module_utils.client import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["action", "active_partitions", "cps", "cpu", "disk", "interfaces", "memory", "namespace", "packet_drop", "packet_rate", "server_down_count", "server_down_percentage", "server_error", "sessions", "ssl_cert", "throughput", "tps", "uuid", ]


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
        'action': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'namespace': {
            'type': 'str',
            },
        'active_partitions': {
            'type': 'str',
            },
        'cpu': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'memory': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'disk': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'throughput': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'interfaces': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'cps': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'tps': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'server_down_count': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'server_down_percentage': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'ssl_cert': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'server_error': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'sessions': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'packet_drop': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'packet_rate': {
            'type': 'str',
            'choices': ['enable', 'disable']
            },
        'uuid': {
            'type': 'str',
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cloud-services/cloud-provider/aws/metrics"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cloud-services/cloud-provider/aws/metrics"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["metrics"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["metrics"].get(k) != v:
            change_results["changed"] = True
            config_changes["metrics"][k] = v

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
    payload = utils.build_json("metrics", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["metrics"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["metrics-list"] if info != "NotFound" else info
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
