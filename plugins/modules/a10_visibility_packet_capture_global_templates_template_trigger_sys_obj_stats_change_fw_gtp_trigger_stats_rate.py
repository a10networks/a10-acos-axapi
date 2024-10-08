#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_visibility_packet_capture_global_templates_template_trigger_sys_obj_stats_change_fw_gtp_trigger_stats_rate
description:
    - Configure stats to trigger packet capture on increment rate
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
    template_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    threshold_exceeded_by:
        description:
        - "Set the threshold to the number of times greater than the previous duration to
          start the capture, default is 5"
        type: int
        required: False
    duration:
        description:
        - "Time in seconds to look for the anomaly, default is 60"
        type: int
        required: False
    out_of_session_memory:
        description:
        - "Enable automatic packet-capture for Out of Tunnel Memory for GTP-C"
        type: bool
        required: False
    blade_out_of_session_memory:
        description:
        - "Enable automatic packet-capture for Out of Tunnel Memory on PU2"
        type: bool
        required: False
    gtp_smp_path_check_failed:
        description:
        - "Enable automatic packet-capture for GTP SMP PATH check Failed"
        type: bool
        required: False
    gtp_smp_c_check_failed:
        description:
        - "Enable automatic packet-capture for GTP-C SMP check Failed"
        type: bool
        required: False
    blade_gtp_smp_path_check_failed:
        description:
        - "Enable automatic packet-capture for GTP SMP PATH check Failed on PU2"
        type: bool
        required: False
    blade_gtp_smp_c_check_failed:
        description:
        - "Enable automatic packet-capture for GTP-C SMP check Failed on PU2"
        type: bool
        required: False
    gtp_tunnel_rate_limit_entry_create_fail:
        description:
        - "Enable automatic packet-capture for GTP Tunnel Level Rate Limit Entry Create
          Failure"
        type: bool
        required: False
    gtp_u_tunnel_rate_limit_entry_create_fa:
        description:
        - "Enable automatic packet-capture for GTP-U Tunnel Level Rate Limit Entry Create
          Failure"
        type: bool
        required: False
    gtp_rate_limit_smp_create_failure:
        description:
        - "Enable automatic packet-capture for GTP Rate Limit SMP Create Failure"
        type: bool
        required: False
    gtp_rate_limit_t3_ctr_create_failure:
        description:
        - "Enable automatic packet-capture for GTP Rate Limit Dynamic Counters Create
          Failure"
        type: bool
        required: False
    gtp_rate_limit_entry_create_failure:
        description:
        - "Enable automatic packet-capture for GTP Rate Limit Entry Create Failure"
        type: bool
        required: False
    blade_gtp_rate_limit_smp_create_failure:
        description:
        - "Enable automatic packet-capture for GTP Rate Limit SMP Create Failure on PU2"
        type: bool
        required: False
    blade_gtp_rate_limit_t3_ctr_create_fail:
        description:
        - "Enable automatic packet-capture for GTP Rate Limit Dynamic Counters Create
          Failure on PU2"
        type: bool
        required: False
    blade_gtp_rate_limit_entry_create_failu:
        description:
        - "Enable automatic packet-capture for GTP Rate Limit Entry Create Failure on PU2"
        type: bool
        required: False
    gtp_smp_dec_sess_count_check_failed:
        description:
        - "Enable automatic packet-capture for GTP-U session count is 0 in GTP-C SMP"
        type: bool
        required: False
    gtp_u_smp_check_failed:
        description:
        - "Enable automatic packet-capture for GTP U-SMP check Failed"
        type: bool
        required: False
    gtp_info_ext_not_found:
        description:
        - "Enable automatic packet-capture for GTP-Info ext not found while freeing C-smp"
        type: bool
        required: False
    blade_gtp_smp_dec_sess_count_check_fail:
        description:
        - "Enable automatic packet-capture for GTP-U session count is 0 in GTP-C SMP on
          PU2"
        type: bool
        required: False
    blade_gtp_u_smp_check_failed:
        description:
        - "Enable automatic packet-capture for GTP U-SMP check Failed on PU2"
        type: bool
        required: False
    blade_gtp_info_ext_not_found:
        description:
        - "Enable automatic packet-capture for GTP-Info ext not found while freeing C-smp
          on PU2"
        type: bool
        required: False
    blade_gtp_smp_session_count_check_faile:
        description:
        - "Enable automatic packet-capture for GTP-U session count is not in range of 0-11
          in GTP-C SMP on PU2"
        type: bool
        required: False
    gtp_c_smp_sig_check_failed:
        description:
        - "Enable automatic packet-capture for GTP-C SMP signature check Failed"
        type: bool
        required: False
    blade_gtp_c_smp_sig_check_failed:
        description:
        - "Enable automatic packet-capture for GTP-C SMP signature check Failed on PU2"
        type: bool
        required: False
    gtp_u_smp_sig_check_failed:
        description:
        - "Enable automatic packet-capture for GTP SMP signature check Failed"
        type: bool
        required: False
    blade_gtp_u_smp_sig_check_failed:
        description:
        - "Enable automatic packet-capture for GTP-U SMP signature check Failed on PU2"
        type: bool
        required: False
    gtp_smp_sig_check_failed:
        description:
        - "Enable automatic packet-capture for GTP SMP signature check Failed"
        type: bool
        required: False
    blade_gtp_smp_sig_check_failed:
        description:
        - "Enable automatic packet-capture for GTP SMP signature check Failed on PU2"
        type: bool
        required: False
    gtp_c_fail_conn_create_slow:
        description:
        - "Enable automatic packet-capture for GTP-C packet failed creating L4-session in
          slowpath"
        type: bool
        required: False
    gtp_u_fail_conn_create_slow:
        description:
        - "Enable automatic packet-capture for GTP-U packet failed while creating
          L4-session in slowpath"
        type: bool
        required: False
    gtp_pathm_fail_conn_create_slow:
        description:
        - "Enable automatic packet-capture for GTP path packet failed while creating
          L4-session in slowpath"
        type: bool
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
AVAILABLE_PROPERTIES = [
    "blade_gtp_c_smp_sig_check_failed", "blade_gtp_info_ext_not_found", "blade_gtp_rate_limit_entry_create_failu", "blade_gtp_rate_limit_smp_create_failure", "blade_gtp_rate_limit_t3_ctr_create_fail", "blade_gtp_smp_c_check_failed", "blade_gtp_smp_dec_sess_count_check_fail", "blade_gtp_smp_path_check_failed",
    "blade_gtp_smp_session_count_check_faile", "blade_gtp_smp_sig_check_failed", "blade_gtp_u_smp_check_failed", "blade_gtp_u_smp_sig_check_failed", "blade_out_of_session_memory", "duration", "gtp_c_fail_conn_create_slow", "gtp_c_smp_sig_check_failed", "gtp_info_ext_not_found", "gtp_pathm_fail_conn_create_slow",
    "gtp_rate_limit_entry_create_failure", "gtp_rate_limit_smp_create_failure", "gtp_rate_limit_t3_ctr_create_failure", "gtp_smp_c_check_failed", "gtp_smp_dec_sess_count_check_failed", "gtp_smp_path_check_failed", "gtp_smp_sig_check_failed", "gtp_tunnel_rate_limit_entry_create_fail", "gtp_u_fail_conn_create_slow", "gtp_u_smp_check_failed",
    "gtp_u_smp_sig_check_failed", "gtp_u_tunnel_rate_limit_entry_create_fa", "out_of_session_memory", "threshold_exceeded_by", "uuid",
    ]


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
        'threshold_exceeded_by': {
            'type': 'int',
            },
        'duration': {
            'type': 'int',
            },
        'out_of_session_memory': {
            'type': 'bool',
            },
        'blade_out_of_session_memory': {
            'type': 'bool',
            },
        'gtp_smp_path_check_failed': {
            'type': 'bool',
            },
        'gtp_smp_c_check_failed': {
            'type': 'bool',
            },
        'blade_gtp_smp_path_check_failed': {
            'type': 'bool',
            },
        'blade_gtp_smp_c_check_failed': {
            'type': 'bool',
            },
        'gtp_tunnel_rate_limit_entry_create_fail': {
            'type': 'bool',
            },
        'gtp_u_tunnel_rate_limit_entry_create_fa': {
            'type': 'bool',
            },
        'gtp_rate_limit_smp_create_failure': {
            'type': 'bool',
            },
        'gtp_rate_limit_t3_ctr_create_failure': {
            'type': 'bool',
            },
        'gtp_rate_limit_entry_create_failure': {
            'type': 'bool',
            },
        'blade_gtp_rate_limit_smp_create_failure': {
            'type': 'bool',
            },
        'blade_gtp_rate_limit_t3_ctr_create_fail': {
            'type': 'bool',
            },
        'blade_gtp_rate_limit_entry_create_failu': {
            'type': 'bool',
            },
        'gtp_smp_dec_sess_count_check_failed': {
            'type': 'bool',
            },
        'gtp_u_smp_check_failed': {
            'type': 'bool',
            },
        'gtp_info_ext_not_found': {
            'type': 'bool',
            },
        'blade_gtp_smp_dec_sess_count_check_fail': {
            'type': 'bool',
            },
        'blade_gtp_u_smp_check_failed': {
            'type': 'bool',
            },
        'blade_gtp_info_ext_not_found': {
            'type': 'bool',
            },
        'blade_gtp_smp_session_count_check_faile': {
            'type': 'bool',
            },
        'gtp_c_smp_sig_check_failed': {
            'type': 'bool',
            },
        'blade_gtp_c_smp_sig_check_failed': {
            'type': 'bool',
            },
        'gtp_u_smp_sig_check_failed': {
            'type': 'bool',
            },
        'blade_gtp_u_smp_sig_check_failed': {
            'type': 'bool',
            },
        'gtp_smp_sig_check_failed': {
            'type': 'bool',
            },
        'blade_gtp_smp_sig_check_failed': {
            'type': 'bool',
            },
        'gtp_c_fail_conn_create_slow': {
            'type': 'bool',
            },
        'gtp_u_fail_conn_create_slow': {
            'type': 'bool',
            },
        'gtp_pathm_fail_conn_create_slow': {
            'type': 'bool',
            },
        'uuid': {
            'type': 'str',
            }
        })
    # Parent keys
    rv.update(dict(template_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/packet-capture/global-templates/template/{template_name}/trigger-sys-obj-stats-change/fw-gtp/trigger-stats-rate"

    f_dict = {}
    if '/' in module.params["template_name"]:
        f_dict["template_name"] = module.params["template_name"].replace("/", "%2F")
    else:
        f_dict["template_name"] = module.params["template_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/packet-capture/global-templates/template/{template_name}/trigger-sys-obj-stats-change/fw-gtp/trigger-stats-rate"

    f_dict = {}
    f_dict["template_name"] = module.params["template_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["trigger-stats-rate"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["trigger-stats-rate"].get(k) != v:
            change_results["changed"] = True
            config_changes["trigger-stats-rate"][k] = v

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
    payload = utils.build_json("trigger-stats-rate", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["trigger-stats-rate"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["trigger-stats-rate-list"] if info != "NotFound" else info
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
