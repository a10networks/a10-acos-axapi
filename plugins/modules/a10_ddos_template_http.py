#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_template_http
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
    action:
        description:
        - "'drop'= Drop packets for the connection; 'reset'= Send RST for the connection;"
        type: str
        required: False
    disable:
        description:
        - "Disable this template"
        type: bool
        required: False
    mss_cfg:
        description:
        - "Field mss_cfg"
        type: dict
        required: False
        suboptions:
            mss_timeout:
                description:
                - "Configure DDOS detection based on mss and packet size"
                type: bool
            mss_percent:
                description:
                - "Configure percentage of mss such that if a packet size is below the mss times
          mss-percent, packet is considered bad."
                type: int
            number_packets:
                description:
                - "Specify percentage of mss. Default is 0, mss-timeout is not enabled."
                type: int
    disallow_connect_method:
        description:
        - "Do not allow HTTP Connect method (asymmetric mode only)"
        type: bool
        required: False
    challenge_method:
        description:
        - "'http-redirect'= http-redirect; 'javascript'= javascript;"
        type: str
        required: False
    challenge_redirect_code:
        description:
        - "'302'= 302 Found; '307'= 307 Temporary Redirect;"
        type: str
        required: False
    challenge_uri_encode:
        description:
        - "Encode the challenge phrase in uri instead of in http cookie. Default encoded
          in http cookie"
        type: bool
        required: False
    challenge_cookie_name:
        description:
        - "Set the cookie name used to send back to client. Default is sto-idd"
        type: str
        required: False
    challenge_keep_cookie:
        description:
        - "Keep the challenge cookie from client and forward to backend. Default is do not
          keep"
        type: bool
        required: False
    challenge_interval:
        description:
        - "Specify the challenge interval. Default is 8 seconds"
        type: int
        required: False
    non_http_bypass:
        description:
        - "Bypass non-http traffic instead of dropping"
        type: bool
        required: False
    malformed_http:
        description:
        - "Field malformed_http"
        type: dict
        required: False
        suboptions:
            malformed_http_enabled:
                description:
                - "Enabling ddos malformed http protection. Default value is disabled."
                type: bool
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
                - "Set the maximum content-length header. Default value is 4294967295 bytes"
                type: int
            malformed_http_bad_chunk_mon_enabled:
                description:
                - "Enabling bad chunk monitoring. Default is disabled"
                type: bool
    use_hdr_ip_cfg:
        description:
        - "Field use_hdr_ip_cfg"
        type: dict
        required: False
        suboptions:
            use_hdr_ip_as_source:
                description:
                - "Mitigate on src ip specified by http header for example X-Forwarded-For header.
          Default is disabled"
                type: bool
            l7_hdr_name:
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
    post_rate_limit:
        description:
        - "Configure rate limiting for HTTP POST request"
        type: int
        required: False
    request_rate_limit:
        description:
        - "Field request_rate_limit"
        type: dict
        required: False
        suboptions:
            request_rate:
                description:
                - "HTTP request rate limit"
                type: int
            uri:
                description:
                - "Field uri"
                type: list
    response_rate_limit:
        description:
        - "Field response_rate_limit"
        type: dict
        required: False
        suboptions:
            obj_size:
                description:
                - "Field obj_size"
                type: dict
    slow_read_drop:
        description:
        - "Field slow_read_drop"
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
    idle_timeout:
        description:
        - "Set the the idle timeout value in seconds for HTTP connections"
        type: int
        required: False
    ignore_zero_payload:
        description:
        - "Don't reset idle timer on packets with zero payload length from clients"
        type: bool
        required: False
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
    referer_filter:
        description:
        - "Field referer_filter"
        type: dict
        required: False
        suboptions:
            ref_filter_blacklist:
                description:
                - "Blacklist the source if the referer matches"
                type: bool
            referer_equals_cfg:
                description:
                - "Field referer_equals_cfg"
                type: list
            referer_contains_cfg:
                description:
                - "Field referer_contains_cfg"
                type: list
            referer_starts_cfg:
                description:
                - "Field referer_starts_cfg"
                type: list
            referer_ends_cfg:
                description:
                - "Field referer_ends_cfg"
                type: list
    agent_filter:
        description:
        - "Field agent_filter"
        type: dict
        required: False
        suboptions:
            agent_filter_blacklist:
                description:
                - "Blacklist the source if the user-agent matches"
                type: bool
            agent_equals_cfg:
                description:
                - "Field agent_equals_cfg"
                type: list
            agent_contains_cfg:
                description:
                - "Field agent_contains_cfg"
                type: list
            agent_starts_cfg:
                description:
                - "Field agent_starts_cfg"
                type: list
            agent_ends_cfg:
                description:
                - "Field agent_ends_cfg"
                type: list
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
    filter_header_list:
        description:
        - "Field filter_header_list"
        type: list
        required: False
        suboptions:
            http_filter_header_seq:
                description:
                - "Sequence number"
                type: int
            http_filter_header_regex:
                description:
                - "Regex Expression"
                type: str
            http_filter_header_unmatched:
                description:
                - "action taken when it does not match"
                type: bool
            http_filter_header_blacklist:
                description:
                - "Also blacklist the source when action is taken"
                type: bool
            http_filter_header_whitelist:
                description:
                - "Whitelist the source after filter passes, packets are dropped until then"
                type: bool
            http_filter_header_count_only:
                description:
                - "Take no action and continue processing the next filter"
                type: bool
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
    "action", "agent_filter", "challenge_cookie_name", "challenge_interval", "challenge_keep_cookie", "challenge_method", "challenge_redirect_code", "challenge_uri_encode", "disable", "disallow_connect_method", "filter_header_list", "http_tmpl_name", "idle_timeout", "ignore_zero_payload", "malformed_http", "mss_cfg",
    "multi_pu_threshold_distribution", "non_http_bypass", "out_of_order_queue_size", "out_of_order_queue_timeout", "post_rate_limit", "referer_filter", "request_header", "request_rate_limit", "response_rate_limit", "slow_read_drop", "use_hdr_ip_cfg", "user_tag", "uuid",
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
        'action': {
            'type': 'str',
            'choices': ['drop', 'reset']
            },
        'disable': {
            'type': 'bool',
            },
        'mss_cfg': {
            'type': 'dict',
            'mss_timeout': {
                'type': 'bool',
                },
            'mss_percent': {
                'type': 'int',
                },
            'number_packets': {
                'type': 'int',
                }
            },
        'disallow_connect_method': {
            'type': 'bool',
            },
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
        'non_http_bypass': {
            'type': 'bool',
            },
        'malformed_http': {
            'type': 'dict',
            'malformed_http_enabled': {
                'type': 'bool',
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
                }
            },
        'use_hdr_ip_cfg': {
            'type': 'dict',
            'use_hdr_ip_as_source': {
                'type': 'bool',
                },
            'l7_hdr_name': {
                'type': 'str',
                }
            },
        'request_header': {
            'type': 'dict',
            'timeout': {
                'type': 'int',
                }
            },
        'post_rate_limit': {
            'type': 'int',
            },
        'request_rate_limit': {
            'type': 'dict',
            'request_rate': {
                'type': 'int',
                },
            'uri': {
                'type': 'list',
                'equal_cfg': {
                    'type': 'dict',
                    'url_equals': {
                        'type': 'str',
                        },
                    'url_equals_rate': {
                        'type': 'int',
                        }
                    },
                'contains_cfg': {
                    'type': 'dict',
                    'url_contains': {
                        'type': 'str',
                        },
                    'url_contains_rate': {
                        'type': 'int',
                        }
                    },
                'starts_cfg': {
                    'type': 'dict',
                    'url_starts_with': {
                        'type': 'str',
                        },
                    'url_starts_with_rate': {
                        'type': 'int',
                        }
                    },
                'ends_cfg': {
                    'type': 'dict',
                    'url_ends_with': {
                        'type': 'str',
                        },
                    'url_ends_with_rate': {
                        'type': 'int',
                        }
                    }
                }
            },
        'response_rate_limit': {
            'type': 'dict',
            'obj_size': {
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
                    }
                }
            },
        'slow_read_drop': {
            'type': 'dict',
            'min_window_size': {
                'type': 'int',
                },
            'min_window_count': {
                'type': 'int',
                }
            },
        'idle_timeout': {
            'type': 'int',
            },
        'ignore_zero_payload': {
            'type': 'bool',
            },
        'out_of_order_queue_size': {
            'type': 'int',
            },
        'out_of_order_queue_timeout': {
            'type': 'int',
            },
        'referer_filter': {
            'type': 'dict',
            'ref_filter_blacklist': {
                'type': 'bool',
                },
            'referer_equals_cfg': {
                'type': 'list',
                'referer_equals': {
                    'type': 'str',
                    }
                },
            'referer_contains_cfg': {
                'type': 'list',
                'referer_contains': {
                    'type': 'str',
                    }
                },
            'referer_starts_cfg': {
                'type': 'list',
                'referer_starts_with': {
                    'type': 'str',
                    }
                },
            'referer_ends_cfg': {
                'type': 'list',
                'referer_ends_with': {
                    'type': 'str',
                    }
                }
            },
        'agent_filter': {
            'type': 'dict',
            'agent_filter_blacklist': {
                'type': 'bool',
                },
            'agent_equals_cfg': {
                'type': 'list',
                'agent_equals': {
                    'type': 'str',
                    }
                },
            'agent_contains_cfg': {
                'type': 'list',
                'agent_contains': {
                    'type': 'str',
                    }
                },
            'agent_starts_cfg': {
                'type': 'list',
                'agent_starts_with': {
                    'type': 'str',
                    }
                },
            'agent_ends_cfg': {
                'type': 'list',
                'agent_ends_with': {
                    'type': 'str',
                    }
                }
            },
        'uuid': {
            'type': 'str',
            },
        'user_tag': {
            'type': 'str',
            },
        'filter_header_list': {
            'type': 'list',
            'http_filter_header_seq': {
                'type': 'int',
                'required': True,
                },
            'http_filter_header_regex': {
                'type': 'str',
                },
            'http_filter_header_unmatched': {
                'type': 'bool',
                },
            'http_filter_header_blacklist': {
                'type': 'bool',
                },
            'http_filter_header_whitelist': {
                'type': 'bool',
                },
            'http_filter_header_count_only': {
                'type': 'bool',
                },
            'uuid': {
                'type': 'str',
                },
            'user_tag': {
                'type': 'str',
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/template/http/{http_tmpl_name}"

    f_dict = {}
    if '/' in str(module.params["http_tmpl_name"]):
        f_dict["http_tmpl_name"] = module.params["http_tmpl_name"].replace("/", "%2F")
    else:
        f_dict["http_tmpl_name"] = module.params["http_tmpl_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/template/http"

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
