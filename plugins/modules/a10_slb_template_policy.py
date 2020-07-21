#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_slb_template_policy
description:
    - Policy config
short_description: Configures A10 slb.template.policy
author: A10 Networks 2018
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
          - absent
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    forward_policy:
        description:
        - "Field forward_policy"
        required: False
        suboptions:
            filtering:
                description:
                - "Field filtering"
            uuid:
                description:
                - "uuid of the object"
            local_logging:
                description:
                - "Enable local logging"
            san_filtering:
                description:
                - "Field san_filtering"
            action_list:
                description:
                - "Field action_list"
            no_client_conn_reuse:
                description:
                - "Inspects only first request of a connection"
            require_web_category:
                description:
                - "Wait for web category to be resolved before taking proxy decision"
            acos_event_log:
                description:
                - "Enable acos event logging"
            source_list:
                description:
                - "Field source_list"
    use_destination_ip:
        description:
        - "Use destination IP to match the policy"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            forward_policy:
                description:
                - "Field forward_policy"
            fwd_policy_dns_unresolved:
                description:
                - "Forward-policy unresolved DNS queries"
            fwd_policy_hits:
                description:
                - "Number of forward-policy requests for this policy template"
            fwd_policy_policy_drop:
                description:
                - "Number of forward-policy requests dropped"
            name:
                description:
                - "Policy template name"
            fwd_policy_forward_to_service_group:
                description:
                - "Number of forward-policy requests forwarded to service group"
            fwd_policy_forward_to_internet:
                description:
                - "Number of forward-policy requests forwarded to internet"
            fwd_policy_dns_outstanding:
                description:
                - "Forward-policy current DNS outstanding requests"
            fwd_policy_source_match_not_found:
                description:
                - "Forward-policy requests without matching source rule"
            fwd_policy_snat_fail:
                description:
                - "Forward-policy source-nat translation failure"
            exp_client_hello_not_found:
                description:
                - "Expected Client HELLO requests not found"
            fwd_policy_forward_to_proxy:
                description:
                - "Number of forward-policy requests forwarded to proxy"
    name:
        description:
        - "Policy template name"
        required: True
    over_limit:
        description:
        - "Specify operation in case over limit"
        required: False
    class_list:
        description:
        - "Field class_list"
        required: False
        suboptions:
            header_name:
                description:
                - "Specify L7 header name"
            lid_list:
                description:
                - "Field lid_list"
            name:
                description:
                - "Class list name or geo-location-class-list name"
            client_ip_l3_dest:
                description:
                - "Use destination IP as client IP address"
            client_ip_l7_header:
                description:
                - "Use extract client IP address from L7 header"
            uuid:
                description:
                - "uuid of the object"
    interval:
        description:
        - "Log interval (minute)"
        required: False
    share:
        description:
        - "Share counters between virtual ports and virtual servers"
        required: False
    full_domain_tree:
        description:
        - "Share counters between geo-location and sub regions"
        required: False
    over_limit_logging:
        description:
        - "Log a message"
        required: False
    bw_list_name:
        description:
        - "Specify a blacklist/whitelist name"
        required: False
    timeout:
        description:
        - "Define timeout value of PBSLB dynamic entry (Timeout value (minute, default is
          5))"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'fwd-policy-dns-unresolved'= Forward-policy unresolved DNS queries;
          'fwd-policy-dns-outstanding'= Forward-policy current DNS outstanding requests;
          'fwd-policy-snat-fail'= Forward-policy source-nat translation failure; 'fwd-
          policy-hits'= Number of forward-policy requests for this policy template; 'fwd-
          policy-forward-to-internet'= Number of forward-policy requests forwarded to
          internet; 'fwd-policy-forward-to-service-group'= Number of forward-policy
          requests forwarded to service group; 'fwd-policy-forward-to-proxy'= Number of
          forward-policy requests forwarded to proxy; 'fwd-policy-policy-drop'= Number of
          forward-policy requests dropped; 'fwd-policy-source-match-not-found'= Forward-
          policy requests without matching source rule; 'exp-client-hello-not-found'=
          Expected Client HELLO requests not found;"
    user_tag:
        description:
        - "Customized tag"
        required: False
    bw_list_id:
        description:
        - "Field bw_list_id"
        required: False
        suboptions:
            pbslb_interval:
                description:
                - "Specify logging interval in minutes"
            action_interval:
                description:
                - "Specify logging interval in minute (default is 3)"
            service_group:
                description:
                - "Specify a service group (Specify the service group name)"
            logging_drp_rst:
                description:
                - "Configure PBSLB logging"
            fail:
                description:
                - "Only log unsuccessful connections"
            pbslb_logging:
                description:
                - "Configure PBSLB logging"
            id:
                description:
                - "Specify id that maps to service group (The id number)"
            bw_list_action:
                description:
                - "'drop'= drop the packet; 'reset'= Send reset back;"
    over_limit_lockup:
        description:
        - "Don't accept any new connection for certain time (Lockup duration (minute))"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    over_limit_reset:
        description:
        - "Reset the connection when it exceeds limit"
        required: False
    overlap:
        description:
        - "Use overlap mode for geo-location to do longest match"
        required: False


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
    "bw_list_id",
    "bw_list_name",
    "class_list",
    "forward_policy",
    "full_domain_tree",
    "interval",
    "name",
    "over_limit",
    "over_limit_lockup",
    "over_limit_logging",
    "over_limit_reset",
    "overlap",
    "sampling_enable",
    "share",
    "stats",
    "timeout",
    "use_destination_ip",
    "user_tag",
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
        'forward_policy': {
            'type': 'dict',
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
            'uuid': {
                'type': 'str',
            },
            'local_logging': {
                'type': 'bool',
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
            'action_list': {
                'type': 'list',
                'log': {
                    'type': 'bool',
                },
                'http_status_code': {
                    'type': 'str',
                    'choices': ['301', '302']
                },
                'forward_snat': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                },
                'drop_response_code': {
                    'type': 'int',
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
                'user_tag': {
                    'type': 'str',
                },
                'real_sg': {
                    'type': 'str',
                },
                'drop_message': {
                    'type': 'str',
                },
                'sampling_enable': {
                    'type': 'list',
                    'counters1': {
                        'type': 'str',
                        'choices': ['all', 'hits']
                    }
                },
                'fall_back': {
                    'type': 'str',
                },
                'fall_back_snat': {
                    'type': 'str',
                },
                'drop_redirect_url': {
                    'type': 'str',
                },
                'name': {
                    'type': 'str',
                    'required': True,
                }
            },
            'no_client_conn_reuse': {
                'type': 'bool',
            },
            'require_web_category': {
                'type': 'bool',
            },
            'acos_event_log': {
                'type': 'bool',
            },
            'source_list': {
                'type': 'list',
                'match_any': {
                    'type': 'bool',
                },
                'name': {
                    'type': 'str',
                    'required': True,
                },
                'match_authorize_policy': {
                    'type': 'str',
                },
                'destination': {
                    'type': 'dict',
                    'class_list_list': {
                        'type': 'list',
                        'uuid': {
                            'type': 'str',
                        },
                        'dest_class_list': {
                            'type': 'str',
                            'required': True,
                        },
                        'priority': {
                            'type': 'int',
                        },
                        'sampling_enable': {
                            'type': 'list',
                            'counters1': {
                                'type': 'str',
                                'choices': ['all', 'hits']
                            }
                        },
                        'action': {
                            'type': 'str',
                        },
                        'ntype': {
                            'type': 'str',
                            'choices': ['host', 'url', 'ip']
                        }
                    },
                    'web_category_list_list': {
                        'type': 'list',
                        'uuid': {
                            'type': 'str',
                        },
                        'web_category_list': {
                            'type': 'str',
                            'required': True,
                        },
                        'priority': {
                            'type': 'int',
                        },
                        'sampling_enable': {
                            'type': 'list',
                            'counters1': {
                                'type': 'str',
                                'choices': ['all', 'hits']
                            }
                        },
                        'action': {
                            'type': 'str',
                        },
                        'ntype': {
                            'type': 'str',
                            'choices': ['host', 'url']
                        }
                    },
                    'any': {
                        'type': 'dict',
                        'action': {
                            'type': 'str',
                        },
                        'sampling_enable': {
                            'type': 'list',
                            'counters1': {
                                'type': 'str',
                                'choices': ['all', 'hits']
                            }
                        },
                        'uuid': {
                            'type': 'str',
                        }
                    }
                },
                'user_tag': {
                    'type': 'str',
                },
                'priority': {
                    'type': 'int',
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
                'match_class_list': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                }
            }
        },
        'use_destination_ip': {
            'type': 'bool',
        },
        'stats': {
            'type': 'dict',
            'forward_policy': {
                'type': 'dict',
            },
            'fwd_policy_dns_unresolved': {
                'type': 'str',
            },
            'fwd_policy_hits': {
                'type': 'str',
            },
            'fwd_policy_policy_drop': {
                'type': 'str',
            },
            'name': {
                'type': 'str',
                'required': True,
            },
            'fwd_policy_forward_to_service_group': {
                'type': 'str',
            },
            'fwd_policy_forward_to_internet': {
                'type': 'str',
            },
            'fwd_policy_dns_outstanding': {
                'type': 'str',
            },
            'fwd_policy_source_match_not_found': {
                'type': 'str',
            },
            'fwd_policy_snat_fail': {
                'type': 'str',
            },
            'exp_client_hello_not_found': {
                'type': 'str',
            },
            'fwd_policy_forward_to_proxy': {
                'type': 'str',
            }
        },
        'name': {
            'type': 'str',
            'required': True,
        },
        'over_limit': {
            'type': 'bool',
        },
        'class_list': {
            'type': 'dict',
            'header_name': {
                'type': 'str',
            },
            'lid_list': {
                'type': 'list',
                'request_rate_limit': {
                    'type': 'int',
                },
                'action_value': {
                    'type': 'str',
                    'choices': ['forward', 'reset']
                },
                'request_per': {
                    'type': 'int',
                },
                'bw_rate_limit': {
                    'type': 'int',
                },
                'conn_limit': {
                    'type': 'int',
                },
                'log': {
                    'type': 'bool',
                },
                'direct_action_value': {
                    'type': 'str',
                    'choices': ['drop', 'reset']
                },
                'conn_per': {
                    'type': 'int',
                },
                'direct_fail': {
                    'type': 'bool',
                },
                'conn_rate_limit': {
                    'type': 'int',
                },
                'direct_pbslb_logging': {
                    'type': 'bool',
                },
                'dns64': {
                    'type': 'dict',
                    'prefix': {
                        'type': 'str',
                    },
                    'exclusive_answer': {
                        'type': 'bool',
                    },
                    'disable': {
                        'type': 'bool',
                    }
                },
                'lidnum': {
                    'type': 'int',
                    'required': True,
                },
                'over_limit_action': {
                    'type': 'bool',
                },
                'response_code_rate_limit': {
                    'type': 'list',
                    'threshold': {
                        'type': 'int',
                    },
                    'code_range_end': {
                        'type': 'int',
                    },
                    'code_range_start': {
                        'type': 'int',
                    },
                    'period': {
                        'type': 'int',
                    }
                },
                'direct_service_group': {
                    'type': 'str',
                },
                'uuid': {
                    'type': 'str',
                },
                'request_limit': {
                    'type': 'int',
                },
                'direct_action_interval': {
                    'type': 'int',
                },
                'bw_per': {
                    'type': 'int',
                },
                'interval': {
                    'type': 'int',
                },
                'user_tag': {
                    'type': 'str',
                },
                'direct_action': {
                    'type': 'bool',
                },
                'lockout': {
                    'type': 'int',
                },
                'direct_logging_drp_rst': {
                    'type': 'bool',
                },
                'direct_pbslb_interval': {
                    'type': 'int',
                }
            },
            'name': {
                'type': 'str',
            },
            'client_ip_l3_dest': {
                'type': 'bool',
            },
            'client_ip_l7_header': {
                'type': 'bool',
            },
            'uuid': {
                'type': 'str',
            }
        },
        'interval': {
            'type': 'int',
        },
        'share': {
            'type': 'bool',
        },
        'full_domain_tree': {
            'type': 'bool',
        },
        'over_limit_logging': {
            'type': 'bool',
        },
        'bw_list_name': {
            'type': 'str',
        },
        'timeout': {
            'type': 'int',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'fwd-policy-dns-unresolved',
                    'fwd-policy-dns-outstanding', 'fwd-policy-snat-fail',
                    'fwd-policy-hits', 'fwd-policy-forward-to-internet',
                    'fwd-policy-forward-to-service-group',
                    'fwd-policy-forward-to-proxy', 'fwd-policy-policy-drop',
                    'fwd-policy-source-match-not-found',
                    'exp-client-hello-not-found'
                ]
            }
        },
        'user_tag': {
            'type': 'str',
        },
        'bw_list_id': {
            'type': 'list',
            'pbslb_interval': {
                'type': 'int',
            },
            'action_interval': {
                'type': 'int',
            },
            'service_group': {
                'type': 'str',
            },
            'logging_drp_rst': {
                'type': 'bool',
            },
            'fail': {
                'type': 'bool',
            },
            'pbslb_logging': {
                'type': 'bool',
            },
            'id': {
                'type': 'int',
            },
            'bw_list_action': {
                'type': 'str',
                'choices': ['drop', 'reset']
            }
        },
        'over_limit_lockup': {
            'type': 'int',
        },
        'uuid': {
            'type': 'str',
        },
        'over_limit_reset': {
            'type': 'bool',
        },
        'overlap': {
            'type': 'bool',
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/policy/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"


def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
    return module.client.get(stats_url(module))


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
    url_base = "/axapi/v3/slb/template/policy/{name}"

    f_dict = {}
    f_dict["name"] = ""

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
        for k, v in payload["policy"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["policy"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["policy"][k] = v
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
    payload = build_json("policy", module)
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
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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
