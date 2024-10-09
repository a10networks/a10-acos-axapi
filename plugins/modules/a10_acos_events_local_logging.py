#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_acos_events_local_logging
description:
    - Configure local logging/persistant storage of FW logs
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
    enable:
        description:
        - "Enable local-logging when FW log servers are down (Default= Not enabled)"
        type: bool
        required: False
    rate_limit:
        description:
        - "Configure number of logs per second to be stored in disk (Default= 1000)"
        type: int
        required: False
    max_disk_space:
        description:
        - "Configure Max disk space in MB to be used for storing the logs (Default= 100MB)"
        type: int
        required: False
    debug_logs:
        description:
        - "Enable debug logs in var log"
        type: bool
        required: False
    send_if_all_servers_up:
        description:
        - "Start sending the stored logs only when all log servers are up"
        type: bool
        required: False
    max_memory:
        description:
        - "Configure Max memory in MB to be used for processing the logs (Default= 30MB)"
        type: int
        required: False
    queue_limit:
        description:
        - "Configure Max number of blocks that can be busy being scheduled (Default= 10, 0
          to disable)"
        type: int
        required: False
    max_backlog_memory:
        description:
        - "Configure Max memory in MB to be used for processing backlogs (Default= 10MB)"
        type: int
        required: False
    delete_old_logs_in_disk:
        description:
        - "Operational command to delete the old logs stored in disk"
        type: bool
        required: False
    string_decode_special_char:
        description:
        - "Enable processing special characters before storing"
        type: bool
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
                - "'all'= all; 'init-pass'= Local logging Init Successful; 'init-fail'= Local
          logging Init Fail; 'freed'= Local logging Stopped; 'disk-over-thres'= Number of
          logs Dropped, Disk reached threshold; 'rate-limited'= Number of logs Dropped,
          Rate limited; 'not-inited'= Number of logs Dropped, Local logging not inited;
          'sent-to-store'= Number of logs sent to be stored; 'sent-to-store-fail'= Number
          of Logs sent to be stored Failed; 'store-fail'= Number of logs failed to be
          stored; 'in-logs'= Number of logs successfully stored; 'in-bytes'= Number of
          bytes successfully stored; 'in-logs-backlog'= Number of backlogs loaded from
          disk; 'in-bytes-backlog'= Number of backlog bytes loaded from disk; 'in-store-
          fail-no-space'= Number of logs Dropped, failed without disk space; 'in-discard-
          logs'= Number of old logs discarded to fit in new logs; 'in-discard-bytes'=
          Number of old bytes discarded to fit in new logs; 'out-logs'= Number of logs
          sent to log servers; 'out-bytes'= Number of bytes sent to log-servers; 'out-
          error'= Number of errors during send; 'remaining-logs'= Total number of
          remaining logs yet to be sent; 'remaining-bytes'= Total number of remaining
          bytes yet to be sent; 'moved-to-delq'= Local Logging moved to delq to be
          deleted; 'out-retry'= Number of attempted retries to send logs; 'out-retry-
          fail'= Number of retries failed with error; 'curr-total-chunks'= Current Number
          of blocks; 'curr-mem-chunks'= Current blocks in memory; 'curr-fs-chunks'=
          Current blocks in file system; 'curr-fs-chunks-up'= Current blocks in file
          system loaded in memory; 'curr-fs-chunks-down'= Current blocks in file system
          not loaded in memory; 'in-logs-agg'= Total Aggregate, Number of logs
          successfully stored; 'in-bytes-agg'= Total Aggregate, Number of bytes
          successfully stored; 'in-logs-backlog-agg'= Total Aggregate, Number of backlogs
          loaded from disk; 'in-bytes-backlog-agg'= Total Aggregate, Number of backlog
          bytes loaded from disk; 'in-store-fail-no-space-agg'= Total Aggregate, Number
          of logs Dropped, failed without disk space; 'in-discard-logs-agg'= Total
          Aggregate, Number of old logs discarded to fit in new logs; 'in-discard-bytes-
          agg'= Total Aggregate, Number of old bytes discarded to fit in new logs; 'out-
          logs-agg'= Total Aggregate, Number of logs sent to log servers; 'out-bytes-
          agg'= Total Aggregate, Number of bytes sent to log-servers; 'out-error-agg'=
          Total Aggregate, Number of errors during send; 'out-retry-agg'= Total
          Aggregate, Number of attempted retries to send logs; 'out-retry-fail-agg'=
          Total Aggregate, Number of retries failed with error; 'in-logs-curr-agg'=
          Current Aggregate, Number of logs successfully stored; 'in-bytes-curr-agg'=
          Current Aggregate, Number of bytes successfully stored; 'in-logs-backlog-curr-
          agg'= Current Aggregate, Number of backlogs loaded from disk; 'in-bytes-
          backlog-curr-agg'= Current Aggregate, Number of backlog bytes loaded from disk;
          'in-discard-logs-curr-agg'= Current Aggregate, Number of old logs discarded to
          fit in new logs; 'in-discard-bytes-curr-agg'= Current Aggregate, Number of old
          bytes discarded to fit in new logs; 'out-logs-curr-agg'= Current Aggregate,
          Number of logs sent to log servers; 'out-bytes-curr-agg'= Current Aggregate,
          Number of bytes sent to log-servers;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            init_pass:
                description:
                - "Local logging Init Successful"
                type: str
            init_fail:
                description:
                - "Local logging Init Fail"
                type: str
            freed:
                description:
                - "Local logging Stopped"
                type: str
            disk_over_thres:
                description:
                - "Number of logs Dropped, Disk reached threshold"
                type: str
            rate_limited:
                description:
                - "Number of logs Dropped, Rate limited"
                type: str
            not_inited:
                description:
                - "Number of logs Dropped, Local logging not inited"
                type: str
            sent_to_store:
                description:
                - "Number of logs sent to be stored"
                type: str
            sent_to_store_fail:
                description:
                - "Number of Logs sent to be stored Failed"
                type: str
            store_fail:
                description:
                - "Number of logs failed to be stored"
                type: str
            in_logs:
                description:
                - "Number of logs successfully stored"
                type: str
            in_bytes:
                description:
                - "Number of bytes successfully stored"
                type: str
            in_logs_backlog:
                description:
                - "Number of backlogs loaded from disk"
                type: str
            in_bytes_backlog:
                description:
                - "Number of backlog bytes loaded from disk"
                type: str
            in_store_fail_no_space:
                description:
                - "Number of logs Dropped, failed without disk space"
                type: str
            in_discard_logs:
                description:
                - "Number of old logs discarded to fit in new logs"
                type: str
            in_discard_bytes:
                description:
                - "Number of old bytes discarded to fit in new logs"
                type: str
            out_logs:
                description:
                - "Number of logs sent to log servers"
                type: str
            out_bytes:
                description:
                - "Number of bytes sent to log-servers"
                type: str
            out_error:
                description:
                - "Number of errors during send"
                type: str
            remaining_logs:
                description:
                - "Total number of remaining logs yet to be sent"
                type: str
            remaining_bytes:
                description:
                - "Total number of remaining bytes yet to be sent"
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
AVAILABLE_PROPERTIES = ["debug_logs", "delete_old_logs_in_disk", "enable", "max_backlog_memory", "max_disk_space", "max_memory", "queue_limit", "rate_limit", "sampling_enable", "send_if_all_servers_up", "stats", "string_decode_special_char", "uuid", ]


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
        'enable': {
            'type': 'bool',
            },
        'rate_limit': {
            'type': 'int',
            },
        'max_disk_space': {
            'type': 'int',
            },
        'debug_logs': {
            'type': 'bool',
            },
        'send_if_all_servers_up': {
            'type': 'bool',
            },
        'max_memory': {
            'type': 'int',
            },
        'queue_limit': {
            'type': 'int',
            },
        'max_backlog_memory': {
            'type': 'int',
            },
        'delete_old_logs_in_disk': {
            'type': 'bool',
            },
        'string_decode_special_char': {
            'type': 'bool',
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
                    'all', 'init-pass', 'init-fail', 'freed', 'disk-over-thres', 'rate-limited', 'not-inited', 'sent-to-store', 'sent-to-store-fail', 'store-fail', 'in-logs', 'in-bytes', 'in-logs-backlog', 'in-bytes-backlog', 'in-store-fail-no-space', 'in-discard-logs', 'in-discard-bytes', 'out-logs', 'out-bytes', 'out-error', 'remaining-logs',
                    'remaining-bytes', 'moved-to-delq', 'out-retry', 'out-retry-fail', 'curr-total-chunks', 'curr-mem-chunks', 'curr-fs-chunks', 'curr-fs-chunks-up', 'curr-fs-chunks-down', 'in-logs-agg', 'in-bytes-agg', 'in-logs-backlog-agg', 'in-bytes-backlog-agg', 'in-store-fail-no-space-agg', 'in-discard-logs-agg', 'in-discard-bytes-agg',
                    'out-logs-agg', 'out-bytes-agg', 'out-error-agg', 'out-retry-agg', 'out-retry-fail-agg', 'in-logs-curr-agg', 'in-bytes-curr-agg', 'in-logs-backlog-curr-agg', 'in-bytes-backlog-curr-agg', 'in-discard-logs-curr-agg', 'in-discard-bytes-curr-agg', 'out-logs-curr-agg', 'out-bytes-curr-agg'
                    ]
                }
            },
        'stats': {
            'type': 'dict',
            'init_pass': {
                'type': 'str',
                },
            'init_fail': {
                'type': 'str',
                },
            'freed': {
                'type': 'str',
                },
            'disk_over_thres': {
                'type': 'str',
                },
            'rate_limited': {
                'type': 'str',
                },
            'not_inited': {
                'type': 'str',
                },
            'sent_to_store': {
                'type': 'str',
                },
            'sent_to_store_fail': {
                'type': 'str',
                },
            'store_fail': {
                'type': 'str',
                },
            'in_logs': {
                'type': 'str',
                },
            'in_bytes': {
                'type': 'str',
                },
            'in_logs_backlog': {
                'type': 'str',
                },
            'in_bytes_backlog': {
                'type': 'str',
                },
            'in_store_fail_no_space': {
                'type': 'str',
                },
            'in_discard_logs': {
                'type': 'str',
                },
            'in_discard_bytes': {
                'type': 'str',
                },
            'out_logs': {
                'type': 'str',
                },
            'out_bytes': {
                'type': 'str',
                },
            'out_error': {
                'type': 'str',
                },
            'remaining_logs': {
                'type': 'str',
                },
            'remaining_bytes': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/acos-events/local-logging"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/acos-events/local-logging"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["local-logging"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["local-logging"].get(k) != v:
            change_results["changed"] = True
            config_changes["local-logging"][k] = v

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
    payload = utils.build_json("local-logging", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["local-logging"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["local-logging-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["local-logging"]["stats"] if info != "NotFound" else info
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
