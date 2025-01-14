#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_scaleout_cluster
description:
    - Configure scaleout cluster
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
    cluster_id:
        description:
        - "Scaleout cluster-id"
        type: int
        required: True
    slog_level:
        description:
        - "Set the level of slog for Scaleout"
        type: int
        required: False
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    local_device:
        description:
        - "Field local_device"
        type: dict
        required: False
        suboptions:
            priority:
                description:
                - "Field priority"
                type: int
            id:
                description:
                - "Field id"
                type: int
            action:
                description:
                - "'enable'= enable; 'disable'= disable;"
                type: str
            start_delay:
                description:
                - "Field start_delay"
                type: int
            cluster_mode:
                description:
                - "'layer-2'= Nodes in cluster are layer 2 connected (default mode); 'layer-3'=
          Nodes in cluster are l3 connected;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            l2_redirect:
                description:
                - "Field l2_redirect"
                type: dict
            traffic_redirection:
                description:
                - "Field traffic_redirection"
                type: dict
            session_sync:
                description:
                - "Field session_sync"
                type: dict
            exclude_interfaces:
                description:
                - "Field exclude_interfaces"
                type: dict
            tracking_template:
                description:
                - "Field tracking_template"
                type: dict
    cluster_devices:
        description:
        - "Field cluster_devices"
        type: dict
        required: False
        suboptions:
            enable:
                description:
                - "Field enable"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            minimum_nodes:
                description:
                - "Field minimum_nodes"
                type: dict
            cluster_discovery_timeout:
                description:
                - "Field cluster_discovery_timeout"
                type: dict
            device_id_list:
                description:
                - "Field device_id_list"
                type: list
    device_groups:
        description:
        - "Field device_groups"
        type: dict
        required: False
        suboptions:
            enable:
                description:
                - "Field enable"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            device_group_list:
                description:
                - "Field device_group_list"
                type: list
    tracking_template:
        description:
        - "Field tracking_template"
        type: dict
        required: False
        suboptions:
            template_list:
                description:
                - "Field template_list"
                type: list
    service_config:
        description:
        - "Field service_config"
        type: dict
        required: False
        suboptions:
            default_user_group_count:
                description:
                - "Number of default traffic buckets"
                type: int
            enable:
                description:
                - "Field enable"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            template_list:
                description:
                - "Field template_list"
                type: list
    db_config:
        description:
        - "Field db_config"
        type: dict
        required: False
        suboptions:
            tickTime:
                description:
                - "Field tickTime"
                type: int
            initLimit:
                description:
                - "Field initLimit"
                type: int
            syncLimit:
                description:
                - "Field syncLimit"
                type: int
            minSessionTimeout:
                description:
                - "Field minSessionTimeout"
                type: int
            maxSessionTimeout:
                description:
                - "Field maxSessionTimeout"
                type: int
            client_recv_timeout:
                description:
                - "Field client_recv_timeout"
                type: int
            clientPort:
                description:
                - "client session port"
                type: int
            loopback_intf_support:
                description:
                - "support loopback interface for scaleout database (enabled by default)"
                type: bool
            broken_detect_timeout:
                description:
                - "database connection broken detection timeout (mseconds) (12000 mseconds for
          default)"
                type: int
            more_election_packet:
                description:
                - "send more election packet in election period (enabled by default)"
                type: bool
            elect_conn_timeout:
                description:
                - "election connection timeout (mseconds) (1200 for default)"
                type: int
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
AVAILABLE_PROPERTIES = ["cluster_devices", "cluster_id", "db_config", "device_groups", "local_device", "service_config", "slog_level", "tracking_template", "uuid", ]


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
        'cluster_id': {
            'type': 'int',
            'required': True,
            },
        'slog_level': {
            'type': 'int',
            },
        'uuid': {
            'type': 'str',
            },
        'local_device': {
            'type': 'dict',
            'priority': {
                'type': 'int',
                },
            'id': {
                'type': 'int',
                },
            'action': {
                'type': 'str',
                'choices': ['enable', 'disable']
                },
            'start_delay': {
                'type': 'int',
                },
            'cluster_mode': {
                'type': 'str',
                'choices': ['layer-2', 'layer-3']
                },
            'uuid': {
                'type': 'str',
                },
            'l2_redirect': {
                'type': 'dict',
                'redirect_eth': {
                    'type': 'str',
                    },
                'ethernet_vlan': {
                    'type': 'int',
                    },
                'redirect_trunk': {
                    'type': 'int',
                    },
                'trunk_vlan': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'traffic_redirection': {
                'type': 'dict',
                'follow_shared': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'interfaces': {
                    'type': 'dict',
                    'eth_cfg': {
                        'type': 'list',
                        'ethernet': {
                            'type': 'str',
                            }
                        },
                    'trunk_cfg': {
                        'type': 'list',
                        'trunk': {
                            'type': 'int',
                            }
                        },
                    've_cfg': {
                        'type': 'list',
                        've': {
                            'type': 'int',
                            }
                        },
                    'loopback_cfg': {
                        'type': 'list',
                        'loopback': {
                            'type': 'int',
                            }
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'reachability_options': {
                    'type': 'dict',
                    'skip_default_route': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'encap': {
                    'type': 'dict',
                    'ntype': {
                        'type': 'str',
                        'choices': ['vxlan']
                        },
                    'use_v4_vxlan': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'session_sync': {
                'type': 'dict',
                'follow_shared': {
                    'type': 'bool',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'interfaces': {
                    'type': 'dict',
                    'eth_cfg': {
                        'type': 'list',
                        'ethernet': {
                            'type': 'str',
                            }
                        },
                    'trunk_cfg': {
                        'type': 'list',
                        'trunk': {
                            'type': 'int',
                            }
                        },
                    've_cfg': {
                        'type': 'list',
                        've': {
                            'type': 'int',
                            }
                        },
                    'loopback_cfg': {
                        'type': 'list',
                        'loopback': {
                            'type': 'int',
                            }
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    },
                'reachability_options': {
                    'type': 'dict',
                    'skip_default_route': {
                        'type': 'bool',
                        },
                    'uuid': {
                        'type': 'str',
                        }
                    }
                },
            'exclude_interfaces': {
                'type': 'dict',
                'eth_cfg': {
                    'type': 'list',
                    'ethernet': {
                        'type': 'str',
                        }
                    },
                'trunk_cfg': {
                    'type': 'list',
                    'trunk': {
                        'type': 'int',
                        }
                    },
                've_cfg': {
                    'type': 'list',
                    've': {
                        'type': 'int',
                        }
                    },
                'loopback_cfg': {
                    'type': 'list',
                    'loopback': {
                        'type': 'int',
                        }
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'tracking_template': {
                'type': 'dict',
                'template_list': {
                    'type': 'list',
                    'template': {
                        'type': 'str',
                        'required': True,
                        },
                    'ip_version': {
                        'type': 'str',
                        'required': True,
                        'choices': ['ipv4', 'ipv6']
                        },
                    'threshold_cfg': {
                        'type': 'list',
                        'threshold': {
                            'type': 'int',
                            },
                        'action': {
                            'type': 'str',
                            'choices': ['down', 'exit-cluster']
                            }
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        }
                    },
                'multi_template_list': {
                    'type': 'list',
                    'multi_template': {
                        'type': 'str',
                        'required': True,
                        },
                    'template': {
                        'type': 'list',
                        'template_name': {
                            'type': 'str',
                            },
                        'partition_name': {
                            'type': 'str',
                            }
                        },
                    'threshold': {
                        'type': 'int',
                        },
                    'action': {
                        'type': 'str',
                        'choices': ['down', 'exit-cluster']
                        },
                    'ip_version': {
                        'type': 'str',
                        'required': True,
                        'choices': ['ipv4', 'ipv6']
                        },
                    'uuid': {
                        'type': 'str',
                        },
                    'user_tag': {
                        'type': 'str',
                        }
                    }
                }
            },
        'cluster_devices': {
            'type': 'dict',
            'enable': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                },
            'minimum_nodes': {
                'type': 'dict',
                'minimum_nodes_num': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                },
            'cluster_discovery_timeout': {
                'type': 'dict',
                'uuid': {
                    'type': 'str',
                    }
                },
            'device_id_list': {
                'type': 'list',
                'ip': {
                    'type': 'str',
                    },
                'action': {
                    'type': 'str',
                    'choices': ['enable', 'disable']
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'device_groups': {
            'type': 'dict',
            'enable': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                },
            'device_group_list': {
                'type': 'list',
                'device_group': {
                    'type': 'int',
                    'required': True,
                    },
                'device_id_list': {
                    'type': 'list',
                    'device_id_start': {
                        'type': 'int',
                        },
                    'device_id_end': {
                        'type': 'int',
                        }
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    }
                }
            },
        'tracking_template': {
            'type': 'dict',
            'template_list': {
                'type': 'list',
                'template': {
                    'type': 'str',
                    'required': True,
                    },
                'threshold_cfg': {
                    'type': 'list',
                    'threshold': {
                        'type': 'int',
                        },
                    'action': {
                        'type': 'str',
                        'choices': ['down', 'exit-cluster']
                        }
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    }
                }
            },
        'service_config': {
            'type': 'dict',
            'default_user_group_count': {
                'type': 'int',
                },
            'enable': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                },
            'template_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'user_group_count': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    },
                'user_tag': {
                    'type': 'str',
                    }
                }
            },
        'db_config': {
            'type': 'dict',
            'tickTime': {
                'type': 'int',
                },
            'initLimit': {
                'type': 'int',
                },
            'syncLimit': {
                'type': 'int',
                },
            'minSessionTimeout': {
                'type': 'int',
                },
            'maxSessionTimeout': {
                'type': 'int',
                },
            'client_recv_timeout': {
                'type': 'int',
                },
            'clientPort': {
                'type': 'int',
                },
            'loopback_intf_support': {
                'type': 'bool',
                },
            'broken_detect_timeout': {
                'type': 'int',
                },
            'more_election_packet': {
                'type': 'bool',
                },
            'elect_conn_timeout': {
                'type': 'int',
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
    url_base = "/axapi/v3/scaleout/cluster/{cluster_id}"

    f_dict = {}
    if '/' in str(module.params["cluster_id"]):
        f_dict["cluster_id"] = module.params["cluster_id"].replace("/", "%2F")
    else:
        f_dict["cluster_id"] = module.params["cluster_id"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/scaleout/cluster"

    f_dict = {}
    f_dict["cluster_id"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["cluster"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["cluster"].get(k) != v:
            change_results["changed"] = True
            config_changes["cluster"][k] = v

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
    payload = utils.build_json("cluster", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["cluster"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["cluster-list"] if info != "NotFound" else info
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
