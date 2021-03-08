#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_visibility_monitor
description:
    - Configure monitoring keys
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
    primary_monitor:
        description:
        - "'traffic'= Mointor traffic;"
        type: str
        required: True
    monitor_key:
        description:
        - "'source'= Monitor traffic from all sources; 'dest'= Monitor traffic to any
          destination; 'service'= Monitor traffic to any service; 'source-nat-ip'=
          Monitor traffic to all source nat IPs;"
        type: str
        required: False
    mon_entity_topk:
        description:
        - "Enable topk for primary entities"
        type: bool
        required: False
    source_entity_topk:
        description:
        - "Enable topk for sources to primary-entities"
        type: bool
        required: False
    index_sessions:
        description:
        - "Start indexing associated sessions"
        type: bool
        required: False
    index_sessions_type:
        description:
        - "'per-cpu'= Use per cpu list;"
        type: str
        required: False
    template:
        description:
        - "Field template"
        type: dict
        required: False
        suboptions:
            notification:
                description:
                - "Field notification"
                type: list
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
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
        required: False
        suboptions:
            listening_port:
                description:
                - "sFlow port to receive packets (sFlow port number(default 6343))"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    netflow:
        description:
        - "Field netflow"
        type: dict
        required: False
        suboptions:
            listening_port:
                description:
                - "Netflow port to receive packets (Netflow port number(default 9996))"
                type: int
            template_active_timeout:
                description:
                - "Configure active timeout of the netflow templates received in mins (Template
          active timeout(mins)(default 30mins))"
                type: int
            uuid:
                description:
                - "uuid of the object"
                type: str
    debug_list:
        description:
        - "Field debug_list"
        type: list
        required: False
        suboptions:
            debug_ip_addr:
                description:
                - "Specify source/dest ip addr"
                type: str
            debug_port:
                description:
                - "Specify port"
                type: int
            debug_protocol:
                description:
                - "'TCP'= TCP; 'UDP'= UDP; 'ICMP'= ICMP;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
    replay_debug_file:
        description:
        - "Field replay_debug_file"
        type: dict
        required: False
        suboptions:
            debug_ip_addr:
                description:
                - "Specify source/dest ip addr"
                type: str
            debug_port:
                description:
                - "Specify port"
                type: int
            debug_protocol:
                description:
                - "'TCP'= TCP; 'UDP'= UDP; 'ICMP'= ICMP;"
                type: str
    delete_debug_file:
        description:
        - "Field delete_debug_file"
        type: dict
        required: False
        suboptions:
            debug_ip_addr:
                description:
                - "Specify source/dest ip addr"
                type: str
            debug_port:
                description:
                - "Specify port"
                type: int
            debug_protocol:
                description:
                - "'TCP'= TCP; 'UDP'= UDP; 'ICMP'= ICMP;"
                type: str
    secondary_monitor:
        description:
        - "Field secondary_monitor"
        type: dict
        required: False
        suboptions:
            secondary_monitoring_key:
                description:
                - "'service'= Monitor traffic to any service;"
                type: str
            mon_entity_topk:
                description:
                - "Enable topk for secondary entities"
                type: bool
            source_entity_topk:
                description:
                - "Enable topk for sources to secondary-entities"
                type: bool
            uuid:
                description:
                - "uuid of the object"
                type: str
            debug_list:
                description:
                - "Field debug_list"
                type: list
            delete_debug_file:
                description:
                - "Field delete_debug_file"
                type: dict
            replay_debug_file:
                description:
                - "Field replay_debug_file"
                type: dict

'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = [
    "agent_list",
    "debug_list",
    "delete_debug_file",
    "index_sessions",
    "index_sessions_type",
    "mon_entity_topk",
    "monitor_key",
    "netflow",
    "primary_monitor",
    "replay_debug_file",
    "secondary_monitor",
    "sflow",
    "source_entity_topk",
    "template",
    "uuid",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


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
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
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
        'primary_monitor': {
            'type': 'str',
            'required': True,
            'choices': ['traffic']
        },
        'monitor_key': {
            'type': 'str',
            'choices': ['source', 'dest', 'service', 'source-nat-ip']
        },
        'mon_entity_topk': {
            'type': 'bool',
        },
        'source_entity_topk': {
            'type': 'bool',
        },
        'index_sessions': {
            'type': 'bool',
        },
        'index_sessions_type': {
            'type': 'str',
            'choices': ['per-cpu']
        },
        'template': {
            'type': 'dict',
            'notification': {
                'type': 'list',
                'notif_template_name': {
                    'type': 'str',
                }
            }
        },
        'uuid': {
            'type': 'str',
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
                        'all', 'sflow-packets-received',
                        'sflow-samples-received', 'sflow-samples-bad-len',
                        'sflow-samples-non-std', 'sflow-samples-skipped',
                        'sflow-sample-record-bad-len',
                        'sflow-samples-sent-for-detection',
                        'sflow-sample-record-invalid-layer2',
                        'sflow-sample-ipv6-hdr-parse-fail', 'sflow-disabled',
                        'netflow-disabled', 'netflow-v5-packets-received',
                        'netflow-v5-samples-received',
                        'netflow-v5-samples-sent-for-detection',
                        'netflow-v5-sample-records-bad-len',
                        'netflow-v5-max-records-exceed',
                        'netflow-v9-packets-received',
                        'netflow-v9-samples-received',
                        'netflow-v9-samples-sent-for-detection',
                        'netflow-v9-sample-records-bad-len',
                        'netflow-v9-max-records-exceed',
                        'netflow-v10-packets-received',
                        'netflow-v10-samples-received',
                        'netflow-v10-samples-sent-for-detection',
                        'netflow-v10-sample-records-bad-len',
                        'netflow-v10-max-records-exceed',
                        'netflow-tcp-sample-received',
                        'netflow-udp-sample-received',
                        'netflow-icmp-sample-received',
                        'netflow-other-sample-received',
                        'netflow-record-copy-oom-error',
                        'netflow-record-rse-invalid',
                        'netflow-sample-flow-dur-error'
                    ]
                }
            }
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
            'uuid': {
                'type': 'str',
            }
        },
        'debug_list': {
            'type': 'list',
            'debug_ip_addr': {
                'type': 'str',
                'required': True,
            },
            'debug_port': {
                'type': 'int',
                'required': True,
            },
            'debug_protocol': {
                'type': 'str',
                'required': True,
                'choices': ['TCP', 'UDP', 'ICMP']
            },
            'uuid': {
                'type': 'str',
            }
        },
        'replay_debug_file': {
            'type': 'dict',
            'debug_ip_addr': {
                'type': 'str',
            },
            'debug_port': {
                'type': 'int',
            },
            'debug_protocol': {
                'type': 'str',
                'choices': ['TCP', 'UDP', 'ICMP']
            }
        },
        'delete_debug_file': {
            'type': 'dict',
            'debug_ip_addr': {
                'type': 'str',
            },
            'debug_port': {
                'type': 'int',
            },
            'debug_protocol': {
                'type': 'str',
                'choices': ['TCP', 'UDP', 'ICMP']
            }
        },
        'secondary_monitor': {
            'type': 'dict',
            'secondary_monitoring_key': {
                'type': 'str',
                'choices': ['service']
            },
            'mon_entity_topk': {
                'type': 'bool',
            },
            'source_entity_topk': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            },
            'debug_list': {
                'type': 'list',
                'debug_ip_addr': {
                    'type': 'str',
                    'required': True,
                },
                'debug_port': {
                    'type': 'int',
                    'required': True,
                },
                'debug_protocol': {
                    'type': 'str',
                    'required': True,
                    'choices': ['TCP', 'UDP', 'ICMP']
                },
                'uuid': {
                    'type': 'str',
                }
            },
            'delete_debug_file': {
                'type': 'dict',
                'debug_ip_addr': {
                    'type': 'str',
                },
                'debug_port': {
                    'type': 'int',
                },
                'debug_protocol': {
                    'type': 'str',
                    'choices': ['TCP', 'UDP', 'ICMP']
                }
            },
            'replay_debug_file': {
                'type': 'dict',
                'debug_ip_addr': {
                    'type': 'str',
                },
                'debug_port': {
                    'type': 'int',
                },
                'debug_protocol': {
                    'type': 'str',
                    'choices': ['TCP', 'UDP', 'ICMP']
                }
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility/monitor"

    f_dict = {}

    return url_base.format(**f_dict)


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None


def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")


def _build_dict_from_param(param):
    rv = {}

    for k, v in param.items():
        hk = _to_axapi(k)
        if isinstance(v, dict):
            v_dict = _build_dict_from_param(v)
            rv[hk] = v_dict
        elif isinstance(v, list):
            nv = [_build_dict_from_param(x) for x in v]
            rv[hk] = nv
        else:
            rv[hk] = v

    return rv


def build_envelope(title, data):
    return {title: data}


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility/monitor"

    f_dict = {}

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v is not None:
            rx = _to_axapi(x)

            if isinstance(v, dict):
                nv = _build_dict_from_param(v)
                rv[rx] = nv
            elif isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)


def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["monitor"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["monitor"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["monitor"][k] = v
            result.update(**existing_config)
    else:
        result.update(**payload)
    return result


def create(module, result, payload):
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def update(module, result, existing_config, payload):
    try:
        post_result = module.client.post(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def present(module, result, existing_config):
    payload = build_json("monitor", module)
    changed_config = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return changed_config
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and not changed_config.get('changed'):
        return update(module, result, existing_config, payload)
    else:
        result["changed"] = True
        return result


def delete(module, result):
    try:
        module.client.delete(existing_url(module))
        result["changed"] = True
    except a10_ex.NotFound:
        result["changed"] = False
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def absent(module, result, existing_config):
    if module.check_mode:
        if existing_config:
            result["changed"] = True
            return result
        else:
            result["changed"] = False
            return result
    else:
        return delete(module, result)


def replace(module, result, existing_config, payload):
    try:
        post_result = module.client.put(existing_url(module), payload)
        if post_result:
            result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result


def run_command(module):
    run_errors = []

    result = dict(changed=False, original_message="", message="", result={})

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

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'absent':
        result = absent(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
