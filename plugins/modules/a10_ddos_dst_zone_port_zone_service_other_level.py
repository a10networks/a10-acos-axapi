#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_dst_zone_port_zone_service_other_level
description:
    - Policy Level Configuration
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
    protocol:
        description:
        - Key to identify parent object
        type: str
        required: True
    zone_service_other_port_other:
        description:
        - Key to identify parent object
        type: str
        required: True
    zone_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    level_num:
        description:
        - "'0'= Default policy level; '1'= Policy level 1; '2'= Policy level 2; '3'=
          Policy level 3; '4'= Policy level 4;"
        type: str
        required: True
    src_default_glid:
        description:
        - "Global limit ID"
        type: str
        required: False
    glid_action:
        description:
        - "'drop'= Drop packets for glid exceed (Default); 'blacklist-src'= Blacklist-src
          for glid exceed; 'ignore'= Do nothing for glid exceed;"
        type: str
        required: False
    zone_escalation_score:
        description:
        - "Zone activation score of this level"
        type: int
        required: False
    zone_violation_actions:
        description:
        - "Violation actions apply due to zone escalate from this level"
        type: str
        required: False
    src_escalation_score:
        description:
        - "Source activation score of this level"
        type: int
        required: False
    src_violation_actions:
        description:
        - "Violation actions apply due to source escalate from this level"
        type: str
        required: False
    zone_template:
        description:
        - "Field zone_template"
        type: dict
        required: False
        suboptions:
            tcp:
                description:
                - "DDOS tcp template"
                type: str
            udp:
                description:
                - "DDOS udp template"
                type: str
            encap:
                description:
                - "DDOS encap template (IPv6-over-IPv4 / IPv4-over-IPv6 are not supported.)"
                type: str
    close_sessions_for_unauth_sources:
        description:
        - "Close session for unauthenticated sources"
        type: bool
        required: False
    close_sessions_for_all_sources:
        description:
        - "Close session for all sources"
        type: bool
        required: False
    clear_sources_upon_deescalation:
        description:
        - "Clear sources upon de-escalation from level 1 to 0 or manual to 0"
        type: bool
        required: False
    start_pattern_recognition:
        description:
        - "Start pattern recognition from this level"
        type: bool
        required: False
    apply_extracted_filters:
        description:
        - "Apply extracted filters from this level"
        type: bool
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
    indicator_list:
        description:
        - "Field indicator_list"
        type: list
        required: False
        suboptions:
            ntype:
                description:
                - "'pkt-rate'= rate of incoming packets; 'pkt-drop-rate'= rate of packets got
          dropped; 'bit-rate'= rate of incoming bits; 'pkt-drop-ratio'= ratio of incoming
          packet rate divided by the rate of dropping packets; 'bytes-to-bytes-from-
          ratio'= ratio of incoming packet rate divided by the rate of outgoing packets;
          'concurrent-conns'= number of concurrent connections; 'conn-miss-rate'= rate of
          incoming packets for which no previously established connection exists; 'syn-
          rate'= rate on incoming SYN packets; 'fin-rate'= rate on incoming FIN packets;
          'rst-rate'= rate of incoming RST packets; 'small-window-ack-rate'= rate of
          small window advertisement; 'empty-ack-rate'= rate of incoming packets which
          have no payload; 'small-payload-rate'= rate of short payload packet; 'syn-fin-
          ratio'= ratio of incoming SYN packet rate divided by the rate of incoming FIN
          packets; 'cpu-utilization'= average data CPU utilization; 'interface-
          utilization'= outside interface utilization; 'learnt-sources'= learnt sources;"
                type: str
            tcp_window_size:
                description:
                - "Expected minimal window size"
                type: int
            data_packet_size:
                description:
                - "Expected minimal data size"
                type: int
            score:
                description:
                - "Score corresponding to the indicator"
                type: int
            src_threshold_num:
                description:
                - "Indicator per-src threshold"
                type: int
            src_threshold_large_num:
                description:
                - "Indicator per-src threshold"
                type: int
            src_threshold_str:
                description:
                - "Indicator per-src threshold (Non-zero floating point)"
                type: str
            src_violation_actions:
                description:
                - "Violation actions to use when this src indicator threshold reaches"
                type: str
            zone_threshold_num:
                description:
                - "Threshold for the entire zone"
                type: int
            zone_threshold_large_num:
                description:
                - "Threshold for the entire zone"
                type: int
            zone_threshold_str:
                description:
                - "Threshold for the entire zone (Non-zero floating point)"
                type: str
            zone_violation_actions:
                description:
                - "Violation actions to use when this zone indicator threshold reaches"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
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
AVAILABLE_PROPERTIES = [
    "apply_extracted_filters", "clear_sources_upon_deescalation", "close_sessions_for_all_sources", "close_sessions_for_unauth_sources", "glid_action", "indicator_list", "level_num", "src_default_glid", "src_escalation_score", "src_violation_actions", "start_pattern_recognition", "user_tag", "uuid", "zone_escalation_score", "zone_template",
    "zone_violation_actions",
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
        'level_num': {
            'type': 'str',
            'required': True,
            'choices': ['0', '1', '2', '3', '4']
            },
        'src_default_glid': {
            'type': 'str',
            },
        'glid_action': {
            'type': 'str',
            'choices': ['drop', 'blacklist-src', 'ignore']
            },
        'zone_escalation_score': {
            'type': 'int',
            },
        'zone_violation_actions': {
            'type': 'str',
            },
        'src_escalation_score': {
            'type': 'int',
            },
        'src_violation_actions': {
            'type': 'str',
            },
        'zone_template': {
            'type': 'dict',
            'tcp': {
                'type': 'str',
                },
            'udp': {
                'type': 'str',
                },
            'encap': {
                'type': 'str',
                }
            },
        'close_sessions_for_unauth_sources': {
            'type': 'bool',
            },
        'close_sessions_for_all_sources': {
            'type': 'bool',
            },
        'clear_sources_upon_deescalation': {
            'type': 'bool',
            },
        'start_pattern_recognition': {
            'type': 'bool',
            },
        'apply_extracted_filters': {
            'type': 'bool',
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'indicator_list': {
            'type': 'list',
            'ntype': {
                'type': 'str',
                'required': True,
                'choices': ['pkt-rate', 'pkt-drop-rate', 'bit-rate', 'pkt-drop-ratio', 'bytes-to-bytes-from-ratio', 'concurrent-conns', 'conn-miss-rate', 'syn-rate', 'fin-rate', 'rst-rate', 'small-window-ack-rate', 'empty-ack-rate', 'small-payload-rate', 'syn-fin-ratio', 'cpu-utilization', 'interface-utilization', 'learnt-sources']
                },
            'tcp_window_size': {
                'type': 'int',
                },
            'data_packet_size': {
                'type': 'int',
                },
            'score': {
                'type': 'int',
                },
            'src_threshold_num': {
                'type': 'int',
                },
            'src_threshold_large_num': {
                'type': 'int',
                },
            'src_threshold_str': {
                'type': 'str',
                },
            'src_violation_actions': {
                'type': 'str',
                },
            'zone_threshold_num': {
                'type': 'int',
                },
            'zone_threshold_large_num': {
                'type': 'int',
                },
            'zone_threshold_str': {
                'type': 'str',
                },
            'zone_violation_actions': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            }
        })
    # Parent keys
    rv.update(dict(protocol=dict(type='str', required=True), zone_service_other_port_other=dict(type='str', required=True), zone_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/dst/zone/{zone_name}/port/zone-service-other/{zone_service_other_port_other}+{protocol}/level/{level_num}"

    f_dict = {}
    if '/' in str(module.params["level_num"]):
        f_dict["level_num"] = module.params["level_num"].replace("/", "%2F")
    else:
        f_dict["level_num"] = module.params["level_num"]
    if '/' in module.params["protocol"]:
        f_dict["protocol"] = module.params["protocol"].replace("/", "%2F")
    else:
        f_dict["protocol"] = module.params["protocol"]
    if '/' in module.params["zone_service_other_port_other"]:
        f_dict["zone_service_other_port_other"] = module.params["zone_service_other_port_other"].replace("/", "%2F")
    else:
        f_dict["zone_service_other_port_other"] = module.params["zone_service_other_port_other"]
    if '/' in module.params["zone_name"]:
        f_dict["zone_name"] = module.params["zone_name"].replace("/", "%2F")
    else:
        f_dict["zone_name"] = module.params["zone_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/dst/zone/{zone_name}/port/zone-service-other/{zone_service_other_port_other}+{protocol}/level"

    f_dict = {}
    f_dict["level_num"] = ""
    f_dict["protocol"] = module.params["protocol"]
    f_dict["zone_service_other_port_other"] = module.params["zone_service_other_port_other"]
    f_dict["zone_name"] = module.params["zone_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["level"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["level"].get(k) != v:
            change_results["changed"] = True
            config_changes["level"][k] = v

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
    payload = utils.build_json("level", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["level"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["level-list"] if info != "NotFound" else info
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
