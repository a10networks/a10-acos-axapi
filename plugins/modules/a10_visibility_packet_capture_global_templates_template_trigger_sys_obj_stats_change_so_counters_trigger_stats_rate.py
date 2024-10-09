#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_visibility_packet_capture_global_templates_template_trigger_sys_obj_stats_change_so_counters_trigger_stats_rate
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
    so_pkts_slb_nat_reserve_fail:
        description:
        - "Enable automatic packet-capture for Total SLB NAT reserve failures"
        type: bool
        required: False
    so_pkts_slb_nat_release_fail:
        description:
        - "Enable automatic packet-capture for Total SLB NAT release failures"
        type: bool
        required: False
    so_pkts_l2redirect_dest_mac_zero_drop:
        description:
        - "Enable automatic packet-capture for Destination MAC Address zero Drop"
        type: bool
        required: False
    so_pkts_l2redirect_interface_not_up:
        description:
        - "Enable automatic packet-capture for L2redirect Intf is not UP"
        type: bool
        required: False
    so_pkts_l2redirect_invalid_redirect_inf:
        description:
        - "Enable automatic packet-capture for Redirect Table Error due to invalid
          redirect info"
        type: bool
        required: False
    so_pkts_l3_redirect_encap_error_drop:
        description:
        - "Enable automatic packet-capture for L3 Redirect encap error drop during
          transmission"
        type: bool
        required: False
    so_pkts_l3_redirect_inner_mac_zero_drop:
        description:
        - "Enable automatic packet-capture for L3 Redirect inner mac zero drop during
          transmission"
        type: bool
        required: False
    so_pkts_l3_redirect_table_error:
        description:
        - "Enable automatic packet-capture for L3 Redirect Table error Drop"
        type: bool
        required: False
    so_pkts_l3_redirect_fragmentation_error:
        description:
        - "Enable automatic packet-capture for L3 redirect encap Fragmentation error"
        type: bool
        required: False
    so_pkts_l3_redirect_table_no_entry_foun:
        description:
        - "Enable automatic packet-capture for L3 redirect Table no redirect entry found
          error"
        type: bool
        required: False
    so_pkts_l3_redirect_invalid_dev_dir:
        description:
        - "Enable automatic packet-capture for L3 Redirect Invalid Device direction during
          transmission"
        type: bool
        required: False
    so_pkts_l3_redirect_chassis_dest_mac_er:
        description:
        - "Enable automatic packet-capture for L3 Redirect RX multi-slot Destination MAC
          Error"
        type: bool
        required: False
    so_pkts_l2redirect_vlan_retrieval_error:
        description:
        - "Enable automatic packet-capture for L2 redirect pkt vlan not retrieved"
        type: bool
        required: False
    so_pkts_l2redirect_port_retrieval_error:
        description:
        - "Enable automatic packet-capture for L2 redirect pkt port not retrieved"
        type: bool
        required: False
    so_pkts_l2redirect_loop_detect_drop:
        description:
        - "Enable automatic packet-capture for L2 redirect pkt loop detected and dropped"
        type: bool
        required: False
    so_pkts_l2redirect_frag_vlan_retrieval_:
        description:
        - "Enable automatic packet-capture for L2 redirect pkt frag vlan not retrieved"
        type: bool
        required: False
    so_pkts_l2redirect_tx_frag_vlan_add_fai:
        description:
        - "Enable automatic packet-capture for L2 redirect tx pkt failed to add vlan"
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
    "duration", "so_pkts_l2redirect_dest_mac_zero_drop", "so_pkts_l2redirect_frag_vlan_retrieval_", "so_pkts_l2redirect_interface_not_up", "so_pkts_l2redirect_invalid_redirect_inf", "so_pkts_l2redirect_loop_detect_drop", "so_pkts_l2redirect_port_retrieval_error", "so_pkts_l2redirect_tx_frag_vlan_add_fai", "so_pkts_l2redirect_vlan_retrieval_error",
    "so_pkts_l3_redirect_chassis_dest_mac_er", "so_pkts_l3_redirect_encap_error_drop", "so_pkts_l3_redirect_fragmentation_error", "so_pkts_l3_redirect_inner_mac_zero_drop", "so_pkts_l3_redirect_invalid_dev_dir", "so_pkts_l3_redirect_table_error", "so_pkts_l3_redirect_table_no_entry_foun", "so_pkts_slb_nat_release_fail",
    "so_pkts_slb_nat_reserve_fail", "threshold_exceeded_by", "uuid",
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
        'so_pkts_slb_nat_reserve_fail': {
            'type': 'bool',
            },
        'so_pkts_slb_nat_release_fail': {
            'type': 'bool',
            },
        'so_pkts_l2redirect_dest_mac_zero_drop': {
            'type': 'bool',
            },
        'so_pkts_l2redirect_interface_not_up': {
            'type': 'bool',
            },
        'so_pkts_l2redirect_invalid_redirect_inf': {
            'type': 'bool',
            },
        'so_pkts_l3_redirect_encap_error_drop': {
            'type': 'bool',
            },
        'so_pkts_l3_redirect_inner_mac_zero_drop': {
            'type': 'bool',
            },
        'so_pkts_l3_redirect_table_error': {
            'type': 'bool',
            },
        'so_pkts_l3_redirect_fragmentation_error': {
            'type': 'bool',
            },
        'so_pkts_l3_redirect_table_no_entry_foun': {
            'type': 'bool',
            },
        'so_pkts_l3_redirect_invalid_dev_dir': {
            'type': 'bool',
            },
        'so_pkts_l3_redirect_chassis_dest_mac_er': {
            'type': 'bool',
            },
        'so_pkts_l2redirect_vlan_retrieval_error': {
            'type': 'bool',
            },
        'so_pkts_l2redirect_port_retrieval_error': {
            'type': 'bool',
            },
        'so_pkts_l2redirect_loop_detect_drop': {
            'type': 'bool',
            },
        'so_pkts_l2redirect_frag_vlan_retrieval_': {
            'type': 'bool',
            },
        'so_pkts_l2redirect_tx_frag_vlan_add_fai': {
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
    url_base = "/axapi/v3/visibility/packet-capture/global-templates/template/{template_name}/trigger-sys-obj-stats-change/so-counters/trigger-stats-rate"

    f_dict = {}
    if '/' in module.params["template_name"]:
        f_dict["template_name"] = module.params["template_name"].replace("/", "%2F")
    else:
        f_dict["template_name"] = module.params["template_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/packet-capture/global-templates/template/{template_name}/trigger-sys-obj-stats-change/so-counters/trigger-stats-rate"

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
