#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_policy_forward_policy
description:
    - Forward Policy commands
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
    policy_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    no_client_conn_reuse:
        description:
        - "Inspects only first request of a connection"
        type: bool
        required: False
    acos_event_log:
        description:
        - "Enable acos event logging"
        type: bool
        required: False
    local_logging:
        description:
        - "Enable local logging"
        type: bool
        required: False
    require_web_category:
        description:
        - "Wait for web category to be resolved before taking proxy decision"
        type: bool
        required: False
    filtering:
        description:
        - "Field filtering"
        type: list
        required: False
        suboptions:
            ssli_url_filtering:
                description:
                - "'bypassed-sni-disable'= Disable SNI filtering for bypassed URL's(enabled by
          default); 'intercepted-sni-enable'= Enable SNI filtering for intercepted
          URL's(disabled by default); 'intercepted-http-disable'= Disable HTTP(host/URL)
          filtering for intercepted URL's(enabled by default); 'no-sni-allow'= Allow
          connection if SNI filtering is enabled and SNI header is not present(Drop by
          default);"
                type: str
    san_filtering:
        description:
        - "Field san_filtering"
        type: list
        required: False
        suboptions:
            ssli_url_filtering_san:
                description:
                - "'enable-san'= Enable SAN filtering(disabled by default); 'bypassed-san-
          disable'= Disable SAN filtering for bypassed URL's(enabled by default);
          'intercepted-san-enable'= Enable SAN filtering for intercepted URL's(disabled
          by default); 'no-san-allow'= Allow connection if SAN filtering is enabled and
          SAN field is not present(Drop by default);"
                type: str
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    action_list:
        description:
        - "Field action_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Action policy name"
                type: str
            action1:
                description:
                - "'forward-to-internet'= Forward request to Internet; 'forward-to-service-group'=
          Forward request to service group; 'forward-to-proxy'= Forward request to HTTP
          proxy server; 'drop'= Drop request;"
                type: str
            fake_sg:
                description:
                - "service group to forward the packets to Internet"
                type: str
            real_sg:
                description:
                - "service group to forward the packets"
                type: str
            forward_snat:
                description:
                - "Source NAT pool or pool group"
                type: str
            fall_back:
                description:
                - "Fallback service group for Internet"
                type: str
            fall_back_snat:
                description:
                - "Source NAT pool or pool group for fallback server"
                type: str
            log:
                description:
                - "enable logging"
                type: bool
            drop_response_code:
                description:
                - "Specify response code for drop action"
                type: int
            drop_message:
                description:
                - "drop-message sent to the client as webpage(html tags are included and quotation
          marks are required for white spaces)"
                type: str
            drop_redirect_url:
                description:
                - "Specify URL to which client request is redirected upon being dropped"
                type: str
            http_status_code:
                description:
                - "'301'= Moved permanently; '302'= Found;"
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
    source_list:
        description:
        - "Field source_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "source destination match rule name"
                type: str
            match_class_list:
                description:
                - "Class List Name"
                type: str
            match_any:
                description:
                - "Match any source"
                type: bool
            match_authorize_policy:
                description:
                - "Authorize-policy for user and group based policy"
                type: str
            priority:
                description:
                - "Priority of the source(higher the number higher the priority, default 0)"
                type: int
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
            destination:
                description:
                - "Field destination"
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
    "acos_event_log",
    "action_list",
    "filtering",
    "local_logging",
    "no_client_conn_reuse",
    "require_web_category",
    "san_filtering",
    "source_list",
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
        'no_client_conn_reuse': {
            'type': 'bool',
        },
        'acos_event_log': {
            'type': 'bool',
        },
        'local_logging': {
            'type': 'bool',
        },
        'require_web_category': {
            'type': 'bool',
        },
        'filtering': {
            'type': 'list',
            'ssli_url_filtering': {
                'type':
                'str',
                'choices': [
                    'bypassed-sni-disable', 'intercepted-sni-enable',
                    'intercepted-http-disable', 'no-sni-allow'
                ]
            }
        },
        'san_filtering': {
            'type': 'list',
            'ssli_url_filtering_san': {
                'type':
                'str',
                'choices': [
                    'enable-san', 'bypassed-san-disable',
                    'intercepted-san-enable', 'no-san-allow'
                ]
            }
        },
        'uuid': {
            'type': 'str',
        },
        'action_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
            },
            'action1': {
                'type':
                'str',
                'choices': [
                    'forward-to-internet', 'forward-to-service-group',
                    'forward-to-proxy', 'drop'
                ]
            },
            'fake_sg': {
                'type': 'str',
            },
            'real_sg': {
                'type': 'str',
            },
            'forward_snat': {
                'type': 'str',
            },
            'fall_back': {
                'type': 'str',
            },
            'fall_back_snat': {
                'type': 'str',
            },
            'log': {
                'type': 'bool',
            },
            'drop_response_code': {
                'type': 'int',
            },
            'drop_message': {
                'type': 'str',
            },
            'drop_redirect_url': {
                'type': 'str',
            },
            'http_status_code': {
                'type': 'str',
                'choices': ['301', '302']
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
                    'type': 'str',
                    'choices': ['all', 'hits']
                }
            }
        },
        'source_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
            },
            'match_class_list': {
                'type': 'str',
            },
            'match_any': {
                'type': 'bool',
            },
            'match_authorize_policy': {
                'type': 'str',
            },
            'priority': {
                'type': 'int',
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
                        'all', 'hits', 'destination-match-not-found',
                        'no-host-info'
                    ]
                }
            },
            'destination': {
                'type': 'dict',
                'class_list_list': {
                    'type': 'list',
                    'dest_class_list': {
                        'type': 'str',
                        'required': True,
                    },
                    'action': {
                        'type': 'str',
                    },
                    'ntype': {
                        'type': 'str',
                        'choices': ['host', 'url', 'ip']
                    },
                    'priority': {
                        'type': 'int',
                    },
                    'uuid': {
                        'type': 'str',
                    },
                    'sampling_enable': {
                        'type': 'list',
                        'counters1': {
                            'type': 'str',
                            'choices': ['all', 'hits']
                        }
                    }
                },
                'web_category_list_list': {
                    'type': 'list',
                    'web_category_list': {
                        'type': 'str',
                        'required': True,
                    },
                    'action': {
                        'type': 'str',
                    },
                    'ntype': {
                        'type': 'str',
                        'choices': ['host', 'url']
                    },
                    'priority': {
                        'type': 'int',
                    },
                    'uuid': {
                        'type': 'str',
                    },
                    'sampling_enable': {
                        'type': 'list',
                        'counters1': {
                            'type': 'str',
                            'choices': ['all', 'hits']
                        }
                    }
                },
                'any': {
                    'type': 'dict',
                    'action': {
                        'type': 'str',
                    },
                    'uuid': {
                        'type': 'str',
                    },
                    'sampling_enable': {
                        'type': 'list',
                        'counters1': {
                            'type': 'str',
                            'choices': ['all', 'hits']
                        }
                    }
                }
            }
        }
    })
    # Parent keys
    rv.update(dict(policy_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/policy/{policy_name}/forward-policy"

    f_dict = {}
    f_dict["policy_name"] = module.params["policy_name"]

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
    url_base = "/axapi/v3/slb/template/policy/{policy_name}/forward-policy"

    f_dict = {}
    f_dict["policy_name"] = module.params["policy_name"]

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
        for k, v in payload["forward-policy"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["forward-policy"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["forward-policy"][k] = v
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
    payload = build_json("forward-policy", module)
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
