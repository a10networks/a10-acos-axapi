#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_detection
description:
    - DDoS Detection Commands
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
    disable:
        description:
        - "Disable DDoS detection (default= enabled)"
        type: bool
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    resource_usage:
        description:
        - "Field resource_usage"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    ddos_script:
        description:
        - "Field ddos_script"
        type: dict
        required: False
        suboptions:
            file:
                description:
                - "startup-config local file name"
                type: str
            action:
                description:
                - "'delete'= delete;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    settings:
        description:
        - "Field settings"
        type: dict
        required: False
        suboptions:
            detector_mode:
                description:
                - "'standalone'= Standalone detector; 'on-box'= Mitigator and Detector on the same
          box; 'auto-svc-discovery'= Auto Service discovery using Visibility module
          (Deprecatd);"
                type: str
            dedicated_cpus:
                description:
                - "Configure the number of dedicated cores for detection"
                type: int
            ctrl_cpu_usage:
                description:
                - "Control cpu usage threshold for DDoS detection"
                type: int
            full_core_enable:
                description:
                - "Enable full core"
                type: bool
            top_k_reset_interval:
                description:
                - "Configure top-k reset interval"
                type: int
            pkt_sampling:
                description:
                - "Field pkt_sampling"
                type: dict
            histogram_escalate_percentage:
                description:
                - "histogram escalate sensitivity for DDoS detection"
                type: int
            histogram_de_escalate_percentage:
                description:
                - "histogram de-escalate sensitivity for DDoS detection"
                type: int
            detection_window_size:
                description:
                - "Configure detection window size in seconds (DDoS detection window size in
          seconds(default= 1))"
                type: int
            initial_learning_interval:
                description:
                - "Initial learning interval (in hours) before processing"
                type: int
            export_interval:
                description:
                - "Configure Baselining and export interval in seconds (DDoS Baselining and export
          interval in seconds(default= 20))"
                type: int
            notification_debug_log:
                description:
                - "'enable'= Enable detection notification debug log (default= disabled);"
                type: str
            network_object_window_size:
                description:
                - "'5'= 5 seconds; '10'= 10 seconds; '15'= 15 seconds; '30'= 30 seconds;  (DDoS
          detection window size in seconds(default= 30))"
                type: str
            network_object_flooding_multiple:
                description:
                - "multiplier for flooding detection threshold in network objects (default 2x
          threshold)"
                type: int
            de_escalation_quiet_time:
                description:
                - "Configure de-escalation needed time in minutes from level 1 to 0.(default 1
          minutes)"
                type: int
            network_object_subnet_notify_percent:
                description:
                - "Send subnet notification when anomaly children subnet entries over configured
          percentage.(default 50%)"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
            entry_saving:
                description:
                - "Field entry_saving"
                type: dict
            standalone_settings:
                description:
                - "Field standalone_settings"
                type: dict
            zone_notifications:
                description:
                - "Field zone_notifications"
                type: dict
    entry_saving:
        description:
        - "Field entry_saving"
        type: dict
        required: False
        suboptions:
            clear_saved_data:
                description:
                - "Clear all saved network-object-based detection entries and learned indicators"
                type: bool
            manual_save:
                description:
                - "Manually save network-object-based detection entries and learned indicators"
                type: bool
            manual_restore:
                description:
                - "Manually restore network-object-based detection entries and learned indicators"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
    agent_list:
        description:
        - "Field agent_list"
        type: list
        required: False
        suboptions:
            agent_name:
                description:
                - "Specify name for the agent"
                type: str
            agent_v4_addr:
                description:
                - "Configure agent's IPv4 address"
                type: str
            agent_v6_addr:
                description:
                - "Configure agent's IPv6 address"
                type: str
            agent_type:
                description:
                - "'Cisco'= Cisco; 'Juniper'= Juniper;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
            sampling_enable:
                description:
                - "Field sampling_enable"
                type: list
            sflow:
                description:
                - "Field sflow"
                type: dict
            netflow:
                description:
                - "Field netflow"
                type: dict
    agent_group_list:
        description:
        - "Field agent_group_list"
        type: list
        required: False
        suboptions:
            agent_group_name:
                description:
                - "Specify name for the agent-group"
                type: str
            agent:
                description:
                - "Field agent"
                type: list
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    trustlist:
        description:
        - "Field trustlist"
        type: dict
        required: False
        suboptions:
            v4_class_list:
                description:
                - "IPv4 Class-list name"
                type: str
            v6_class_list:
                description:
                - "IPv6 Class-list name"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    statistics:
        description:
        - "Field statistics"
        type: dict
        required: False
        suboptions:
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
AVAILABLE_PROPERTIES = ["agent_group_list", "agent_list", "ddos_script", "disable", "entry_saving", "resource_usage", "settings", "statistics", "trustlist", "uuid", ]


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
        'disable': {
            'type': 'bool',
            },
        'uuid': {
            'type': 'str',
            },
        'resource_usage': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'ddos_script': {
            'type': 'dict',
            'file': {
                'type': 'str',
                },
            'action': {
                'type': 'str',
                'choices': ['delete']
                },
            'uuid': {
                'type': 'str',
                }
            },
        'settings': {
            'type': 'dict',
            'detector_mode': {
                'type': 'str',
                'choices': ['standalone', 'on-box', 'auto-svc-discovery']
                },
            'dedicated_cpus': {
                'type': 'int',
                },
            'ctrl_cpu_usage': {
                'type': 'int',
                },
            'full_core_enable': {
                'type': 'bool',
                },
            'top_k_reset_interval': {
                'type': 'int',
                },
            'pkt_sampling': {
                'type': 'dict',
                'override_rate': {
                    'type': 'int',
                    },
                'assign_index': {
                    'type': 'int',
                    },
                'assign_rate': {
                    'type': 'int',
                    }
                },
            'histogram_escalate_percentage': {
                'type': 'int',
                },
            'histogram_de_escalate_percentage': {
                'type': 'int',
                },
            'detection_window_size': {
                'type': 'int',
                },
            'initial_learning_interval': {
                'type': 'int',
                },
            'export_interval': {
                'type': 'int',
                },
            'notification_debug_log': {
                'type': 'str',
                'choices': ['enable']
                },
            'network_object_window_size': {
                'type': 'str',
                'choices': ['5', '10', '15', '30']
                },
            'network_object_flooding_multiple': {
                'type': 'int',
                },
            'de_escalation_quiet_time': {
                'type': 'int',
                },
            'network_object_subnet_notify_percent': {
                'type': 'int',
                },
            'uuid': {
                'type': 'str',
                },
            'entry_saving': {
                'type': 'dict',
                'disable_bootup_restore': {
                    'type': 'bool',
                    },
                'interval': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'standalone_settings': {
                'type': 'dict',
                'action': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                    },
                'uuid': {
                    'type': 'str',
                    },
                'sflow': {
                    'type': 'dict',
                    'listening_port': {
                        'type': 'int',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'netflow': {
                    'type': 'dict',
                    'listening_port': {
                        'type': 'int',
                        },
                    'template_active_timeout': {
                        'type': 'int',
                        },
                    'distribute_by_duration': {
                        'type': 'str',
                        'choices': ['enable', 'disable']
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'zone_notifications': {
                'type': 'dict',
                'source_entry': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'entry_saving': {
            'type': 'dict',
            'clear_saved_data': {
                'type': 'bool',
                },
            'manual_save': {
                'type': 'bool',
                },
            'manual_restore': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'agent_list': {
            'type': 'list',
            'agent_name': {
                'type': 'str',
                'required': True,
                },
            'agent_v4_addr': {
                'type': 'str',
                },
            'agent_v6_addr': {
                'type': 'str',
                },
            'agent_type': {
                'type': 'str',
                'choices': ['Cisco', 'Juniper']
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                },
            'sampling_enable': {
                'type': 'list',
                'counters1': {
                    'type':
                    'str',
                    'choices': [
                        'all', 'sflow-packets-received', 'sflow-samples-received', 'sflow-samples-bad-len', 'sflow-samples-non-std', 'sflow-samples-skipped', 'sflow-sample-record-bad-len', 'sflow-samples-sent-for-detection', 'sflow-sample-record-invalid-layer2', 'sflow-sample-ipv6-hdr-parse-fail', 'sflow-disabled', 'netflow-disabled',
                        'netflow-v5-packets-received', 'netflow-v5-samples-received', 'netflow-v5-samples-sent-for-detection', 'netflow-v5-sample-records-bad-len', 'netflow-v5-max-records-exceed', 'netflow-v9-packets-received', 'netflow-v9-samples-received', 'netflow-v9-samples-sent-for-detection', 'netflow-v9-sample-records-bad-len',
                        'netflow-v9-sample-flowset-bad-padding', 'netflow-v9-max-records-exceed', 'netflow-v9-template-not-found', 'netflow-v10-packets-received', 'netflow-v10-samples-received', 'netflow-v10-samples-sent-for-detection', 'netflow-v10-sample-records-bad-len', 'netflow-v10-max-records-exceed', 'netflow-tcp-sample-received',
                        'netflow-udp-sample-received', 'netflow-icmp-sample-received', 'netflow-other-sample-received', 'netflow-record-copy-oom-error', 'netflow-record-rse-invalid', 'netflow-sample-flow-dur-error', 'flow-dst-entry-miss', 'flow-ip-proto-or-port-miss', 'flow-detection-msgq-full', 'flow-network-entry-miss'
                        ]
                    }
                },
            'sflow': {
                'type': 'dict',
                'sflow_pkt_samples_collection': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'netflow': {
                'type': 'dict',
                'netflow_samples_collection': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                    },
                'netflow_sampling_rate': {
                    'type': 'int',
                    },
                'active_timeout': {
                    'type': 'int',
                    },
                'inactive_timeout': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'agent_group_list': {
            'type': 'list',
            'agent_group_name': {
                'type': 'str',
                'required': True,
                },
            'agent': {
                'type': 'list',
                'agent_name': {
                    'type': 'str',
                    }
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            },
        'trustlist': {
            'type': 'dict',
            'v4_class_list': {
                'type': 'str',
                },
            'v6_class_list': {
                'type': 'str',
                },
            'uuid': {
                'type': 'str',
                }
            },
        'statistics': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/detection"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/detection"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["detection"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["detection"].get(k) != v:
            change_results["changed"] = True
            config_changes["detection"][k] = v

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
    payload = utils.build_json("detection", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["detection"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["detection-list"] if info != "NotFound" else info
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
