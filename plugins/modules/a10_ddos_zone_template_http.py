#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_zone_template_http
description:
    - HTTP template Configuration
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
    http_tmpl_name:
        description:
        - "DDOS HTTP Template Name"
        type: str
        required: True
    disable:
        description:
        - "Disable this template"
        type: bool
        required: False
    multi_pu_threshold_distribution:
        description:
        - "Field multi_pu_threshold_distribution"
        type: dict
        required: False
        suboptions:
            multi_pu_threshold_distribution_value:
                description:
                - "Destination side rate limit only. Default= 0"
                type: int
            multi_pu_threshold_distribution_disable:
                description:
                - "'disable'= Destination side rate limit only. Default= Enable;"
                type: str
    mss_timeout:
        description:
        - "Field mss_timeout"
        type: dict
        required: False
        suboptions:
            mss_percent:
                description:
                - "Configure percentage of mss such that if a packet size is below the mss times
          mss-percent, packet is considered bad."
                type: int
            number_packets:
                description:
                - "Specify percentage of mss. Default is 0, mss-timeout is not enabled."
                type: int
            mss_timeout_action_list_name:
                description:
                - "Configure action-list to take"
                type: str
            mss_timeout_action:
                description:
                - "'drop'= Drop packets (Default); 'ignore'= Take no action; 'blacklist-src'=
          Blacklist-src; 'reset'= Reset client connection;"
                type: str
    disallow_connect_method:
        description:
        - "Do not allow HTTP Connect method (asymmetric mode only)"
        type: bool
        required: False
    challenge:
        description:
        - "Field challenge"
        type: dict
        required: False
        suboptions:
            challenge_method:
                description:
                - "'http-redirect'= http-redirect; 'javascript'= javascript;"
                type: str
            challenge_redirect_code:
                description:
                - "'302'= 302 Found; '307'= 307 Temporary Redirect;"
                type: str
            challenge_uri_encode:
                description:
                - "Encode the challenge phrase in uri instead of in http cookie. Default encoded
          in http cookie"
                type: bool
            challenge_cookie_name:
                description:
                - "Set the cookie name used to send back to client. Default is sto-idd"
                type: str
            challenge_keep_cookie:
                description:
                - "Keep the challenge cookie from client and forward to backend. Default is do not
          keep"
                type: bool
            challenge_interval:
                description:
                - "Specify the challenge interval. Default is 8 seconds"
                type: int
            challenge_pass_action_list_name:
                description:
                - "Configure action-list to take for passing the authentication"
                type: str
            challenge_pass_action:
                description:
                - "'authenticate-src'= Authenticate-src (Default);"
                type: str
            challenge_fail_action_list_name:
                description:
                - "Configure action-list to take for failing the authentication"
                type: str
            challenge_fail_action:
                description:
                - "'blacklist-src'= Blacklist-src; 'reset'= Reset client connection(Default);"
                type: str
    non_http_bypass:
        description:
        - "Bypass non-http traffic instead of dropping"
        type: bool
        required: False
    client_source_ip:
        description:
        - "Field client_source_ip"
        type: dict
        required: False
        suboptions:
            client_source_ip:
                description:
                - "Mitigate on src ip specified by http header for example X-Forwarded-For header.
          Default is disabled"
                type: bool
            http_header_name:
                description:
                - "Set the http header name to parse for client ip. Default is X-Forwarded-For"
                type: str
    request_header:
        description:
        - "Field request_header"
        type: dict
        required: False
        suboptions:
            timeout:
                description:
                - "Field timeout"
                type: int
            header_timeout_action_list_name:
                description:
                - "Configure action-list to take"
                type: str
            header_timeout_action:
                description:
                - "'drop'= Drop packets (Default); 'blacklist-src'= Blacklist-src; 'reset'= Reset
          client connection;"
                type: str
    src:
        description:
        - "Field src"
        type: dict
        required: False
        suboptions:
            rate_limit:
                description:
                - "Field rate_limit"
                type: dict
    dst:
        description:
        - "Field dst"
        type: dict
        required: False
        suboptions:
            rate_limit:
                description:
                - "Field rate_limit"
                type: dict
    slow_read:
        description:
        - "Field slow_read"
        type: dict
        required: False
        suboptions:
            min_window_size:
                description:
                - "minimum window size"
                type: int
            min_window_count:
                description:
                - "Number of packets"
                type: int
            slow_read_action_list_name:
                description:
                - "Configure action-list to take"
                type: str
            slow_read_action:
                description:
                - "'drop'= Drop packets (Default); 'blacklist-src'= Blacklist-src; 'ignore'= Take
          no action; 'reset'= Reset client connection;"
                type: str
    out_of_order_queue_size:
        description:
        - "Set the number of packets for the out-of-order HTTP queue (asym mode only)"
        type: int
        required: False
    out_of_order_queue_timeout:
        description:
        - "Set the timeout value in seconds for out-of-order queue in HTTP (asym mode
          only)"
        type: int
        required: False
    idle_timeout:
        description:
        - "Field idle_timeout"
        type: dict
        required: False
        suboptions:
            idle_timeout_value:
                description:
                - "Set the the idle timeout value in seconds for HTTP connections"
                type: int
            ignore_zero_payload:
                description:
                - "Don't reset idle timer on packets with zero payload length from clients"
                type: bool
            idle_timeout_action_list_name:
                description:
                - "Configure action-list to take"
                type: str
            idle_timeout_action:
                description:
                - "'drop'= Drop packets (Default); 'blacklist-src'= Blacklist-src; 'reset'= Reset
          client connection;"
                type: str
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
    filter_list:
        description:
        - "Field filter_list"
        type: list
        required: False
        suboptions:
            http_filter_name:
                description:
                - "Field http_filter_name"
                type: str
            http_filter_seq:
                description:
                - "Sequence number"
                type: int
            http_header_cfg:
                description:
                - "Field http_header_cfg"
                type: dict
            http_referer_cfg:
                description:
                - "Field http_referer_cfg"
                type: dict
            http_agent_cfg:
                description:
                - "Field http_agent_cfg"
                type: dict
            http_uri_cfg:
                description:
                - "Field http_uri_cfg"
                type: dict
            dst:
                description:
                - "Field dst"
                type: dict
            http_filter_action_list_name:
                description:
                - "Configure action-list to take"
                type: str
            http_filter_action:
                description:
                - "'drop'= Drop packets (Default); 'ignore'= Take no action; 'blacklist-src'=
          Blacklist-src; 'authenticate-src'= Authenticate-src; 'reset'= Reset client
          connection;"
                type: str
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    malformed_http:
        description:
        - "Field malformed_http"
        type: dict
        required: False
        suboptions:
            malformed_http:
                description:
                - "'check'= Configure malformed HTTP parameters;"
                type: str
            malformed_http_max_line_size:
                description:
                - "Set the maximum line size. Default value is 32512"
                type: int
            malformed_http_max_num_headers:
                description:
                - "Set the maximum number of headers. Default value is 90"
                type: int
            malformed_http_max_req_line_size:
                description:
                - "Set the maximum request line size. Default value is 32512"
                type: int
            malformed_http_max_header_name_size:
                description:
                - "Set the maxinum header name length. Default value is 64."
                type: int
            malformed_http_max_content_length:
                description:
                - "Set the maxinum content-length header. Default value is 4294967295 bytes"
                type: int
            malformed_http_bad_chunk_mon_enabled:
                description:
                - "Enabling bad chunk monitoring. Default is disabled"
                type: bool
            malformed_http_action_list_name:
                description:
                - "Configure action-list to take"
                type: str
            malformed_http_action:
                description:
                - "'drop'= Drop packets (Default); 'reset'= Reset client connection; 'blacklist-
          src'= Blacklist-src;"
                type: str
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
AVAILABLE_PROPERTIES = [
    "challenge", "client_source_ip", "disable", "disallow_connect_method", "dst", "filter_list", "http_tmpl_name", "idle_timeout", "malformed_http", "mss_timeout", "multi_pu_threshold_distribution", "non_http_bypass", "out_of_order_queue_size", "out_of_order_queue_timeout", "request_header", "slow_read", "src", "user_tag", "uuid",
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
        'http_tmpl_name': {
            'type': 'str',
            'required': True,
            },
        'disable': {
            'type': 'bool',
            },
        'multi_pu_threshold_distribution': {
            'type': 'dict',
            'multi_pu_threshold_distribution_value': {
                'type': 'int',
                },
            'multi_pu_threshold_distribution_disable': {
                'type': 'str',
                'choices': ['disable']
                }
            },
        'mss_timeout': {
            'type': 'dict',
            'mss_percent': {
                'type': 'int',
                },
            'number_packets': {
                'type': 'int',
                },
            'mss_timeout_action_list_name': {
                'type': 'str',
                },
            'mss_timeout_action': {
                'type': 'str',
                'choices': ['drop', 'ignore', 'blacklist-src', 'reset']
                }
            },
        'disallow_connect_method': {
            'type': 'bool',
            },
        'challenge': {
            'type': 'dict',
            'challenge_method': {
                'type': 'str',
                'choices': ['http-redirect', 'javascript']
                },
            'challenge_redirect_code': {
                'type': 'str',
                'choices': ['302', '307']
                },
            'challenge_uri_encode': {
                'type': 'bool',
                },
            'challenge_cookie_name': {
                'type': 'str',
                },
            'challenge_keep_cookie': {
                'type': 'bool',
                },
            'challenge_interval': {
                'type': 'int',
                },
            'challenge_pass_action_list_name': {
                'type': 'str',
                },
            'challenge_pass_action': {
                'type': 'str',
                'choices': ['authenticate-src']
                },
            'challenge_fail_action_list_name': {
                'type': 'str',
                },
            'challenge_fail_action': {
                'type': 'str',
                'choices': ['blacklist-src', 'reset']
                }
            },
        'non_http_bypass': {
            'type': 'bool',
            },
        'client_source_ip': {
            'type': 'dict',
            'client_source_ip': {
                'type': 'bool',
                },
            'http_header_name': {
                'type': 'str',
                }
            },
        'request_header': {
            'type': 'dict',
            'timeout': {
                'type': 'int',
                },
            'header_timeout_action_list_name': {
                'type': 'str',
                },
            'header_timeout_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'reset']
                }
            },
        'src': {
            'type': 'dict',
            'rate_limit': {
                'type': 'dict',
                'http_post': {
                    'type': 'dict',
                    'src_post_rate_limit': {
                        'type': 'int',
                        },
                    'src_post_rate_limit_action_list_name': {
                        'type': 'str',
                        },
                    'src_post_rate_limit_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore', 'reset', 'blacklist-src']
                        }
                    },
                'http_request': {
                    'type': 'dict',
                    'src_request_rate': {
                        'type': 'int',
                        },
                    'src_request_rate_limit_action_list_name': {
                        'type': 'str',
                        },
                    'src_request_rate_limit_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore', 'reset', 'blacklist-src']
                        }
                    }
                }
            },
        'dst': {
            'type': 'dict',
            'rate_limit': {
                'type': 'dict',
                'http_post': {
                    'type': 'dict',
                    'dst_post_rate_limit': {
                        'type': 'int',
                        },
                    'dst_post_rate_limit_action_list_name': {
                        'type': 'str',
                        },
                    'dst_post_rate_limit_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore', 'reset', 'blacklist-src']
                        }
                    },
                'http_request': {
                    'type': 'dict',
                    'dst_request_rate': {
                        'type': 'int',
                        },
                    'dst_request_rate_limit_action_list_name': {
                        'type': 'str',
                        },
                    'dst_request_rate_limit_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore', 'reset', 'blacklist-src']
                        }
                    },
                'response_size': {
                    'type': 'dict',
                    'less_cfg': {
                        'type': 'list',
                        'obj_less': {
                            'type': 'int',
                            },
                        'obj_less_rate': {
                            'type': 'int',
                            }
                        },
                    'greater_cfg': {
                        'type': 'list',
                        'obj_greater': {
                            'type': 'int',
                            },
                        'obj_greater_rate': {
                            'type': 'int',
                            }
                        },
                    'between_cfg': {
                        'type': 'list',
                        'obj_between1': {
                            'type': 'int',
                            },
                        'obj_between2': {
                            'type': 'int',
                            },
                        'obj_between_rate': {
                            'type': 'int',
                            }
                        },
                    'response_size_action_list_name': {
                        'type': 'str',
                        },
                    'response_size_action': {
                        'type': 'str',
                        'choices': ['drop', 'ignore', 'blacklist-src', 'reset']
                        }
                    }
                }
            },
        'slow_read': {
            'type': 'dict',
            'min_window_size': {
                'type': 'int',
                },
            'min_window_count': {
                'type': 'int',
                },
            'slow_read_action_list_name': {
                'type': 'str',
                },
            'slow_read_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'ignore', 'reset']
                }
            },
        'out_of_order_queue_size': {
            'type': 'int',
            },
        'out_of_order_queue_timeout': {
            'type': 'int',
            },
        'idle_timeout': {
            'type': 'dict',
            'idle_timeout_value': {
                'type': 'int',
                },
            'ignore_zero_payload': {
                'type': 'bool',
                },
            'idle_timeout_action_list_name': {
                'type': 'str',
                },
            'idle_timeout_action': {
                'type': 'str',
                'choices': ['drop', 'blacklist-src', 'reset']
                }
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'filter_list': {
            'type': 'list',
            'http_filter_name': {
                'type': 'str',
                'required': True,
                },
            'http_filter_seq': {
                'type': 'int',
                },
            'http_header_cfg': {
                'type': 'dict',
                'http_filter_header_regex': {
                    'type': 'str',
                    },
                'http_filter_header_inverse_match': {
                    'type': 'bool',
                    }
                },
            'http_referer_cfg': {
                'type': 'dict',
                'referer_equals_cfg': {
                    'type': 'list',
                    'http_filter_referer_equals': {
                        'type': 'str',
                        }
                    },
                'referer_contains_cfg': {
                    'type': 'list',
                    'http_filter_referer_contains': {
                        'type': 'str',
                        }
                    },
                'referer_starts_cfg': {
                    'type': 'list',
                    'http_filter_referer_starts_with': {
                        'type': 'str',
                        }
                    },
                'referer_ends_cfg': {
                    'type': 'list',
                    'http_filter_referer_ends_with': {
                        'type': 'str',
                        }
                    }
                },
            'http_agent_cfg': {
                'type': 'dict',
                'agent_equals_cfg': {
                    'type': 'list',
                    'http_filter_agent_equals': {
                        'type': 'str',
                        }
                    },
                'agent_contains_cfg': {
                    'type': 'list',
                    'http_filter_agent_contains': {
                        'type': 'str',
                        }
                    },
                'agent_starts_cfg': {
                    'type': 'list',
                    'http_filter_agent_starts_with': {
                        'type': 'str',
                        }
                    },
                'agent_ends_cfg': {
                    'type': 'list',
                    'http_filter_agent_ends_with': {
                        'type': 'str',
                        }
                    }
                },
            'http_uri_cfg': {
                'type': 'dict',
                'uri_equal_cfg': {
                    'type': 'list',
                    'http_filter_uri_equals': {
                        'type': 'str',
                        }
                    },
                'uri_contains_cfg': {
                    'type': 'list',
                    'http_filter_uri_contains': {
                        'type': 'str',
                        }
                    },
                'uri_starts_cfg': {
                    'type': 'list',
                    'http_filter_uri_starts_with': {
                        'type': 'str',
                        }
                    },
                'uri_ends_cfg': {
                    'type': 'list',
                    'http_filter_uri_ends_with': {
                        'type': 'str',
                        }
                    }
                },
            'dst': {
                'type': 'dict',
                'http_filter_rate_limit': {
                    'type': 'int',
                    }
                },
            'http_filter_action_list_name': {
                'type': 'str',
                },
            'http_filter_action': {
                'type': 'str',
                'choices': ['drop', 'ignore', 'blacklist-src', 'authenticate-src', 'reset']
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            },
        'malformed_http': {
            'type': 'dict',
            'malformed_http': {
                'type': 'str',
                'choices': ['check']
                },
            'malformed_http_max_line_size': {
                'type': 'int',
                },
            'malformed_http_max_num_headers': {
                'type': 'int',
                },
            'malformed_http_max_req_line_size': {
                'type': 'int',
                },
            'malformed_http_max_header_name_size': {
                'type': 'int',
                },
            'malformed_http_max_content_length': {
                'type': 'int',
                },
            'malformed_http_bad_chunk_mon_enabled': {
                'type': 'bool',
                },
            'malformed_http_action_list_name': {
                'type': 'str',
                },
            'malformed_http_action': {
                'type': 'str',
                'choices': ['drop', 'reset', 'blacklist-src']
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
    url_base = "/axapi/v3/ddos/zone-template/http/{http_tmpl_name}"

    f_dict = {}
    if '/' in str(module.params["http_tmpl_name"]):
        f_dict["http_tmpl_name"] = module.params["http_tmpl_name"].replace("/", "%2F")
    else:
        f_dict["http_tmpl_name"] = module.params["http_tmpl_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/zone-template/http"

    f_dict = {}
    f_dict["http_tmpl_name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["http"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["http"].get(k) != v:
            change_results["changed"] = True
            config_changes["http"][k] = v

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
    payload = utils.build_json("http", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["http"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["http-list"] if info != "NotFound" else info
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
