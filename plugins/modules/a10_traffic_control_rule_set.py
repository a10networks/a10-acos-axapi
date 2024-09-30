#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_traffic_control_rule_set
description:
    - Configure traffic control policy rule set
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
    name:
        description:
        - "Rule set name"
        type: str
        required: True
    remark:
        description:
        - "Rule set entry comment (Notes for this rule set)"
        type: str
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'hit-count'= Hit counts;"
                type: str
    rule_list:
        description:
        - "Field rule_list"
        type: list
        required: False
        suboptions:
            name:
                description:
                - "Rule name"
                type: str
            remark:
                description:
                - "Rule entry comment (Notes for this rule)"
                type: str
            status:
                description:
                - "'enable'= Enable rule; 'disable'= Disable rule;"
                type: str
            ip_version:
                description:
                - "'v4'= IPv4 rule; 'v6'= IPv6 rule; 'any'= IP version is not specified. Only
          compatible with filters by application, zone or the source class-list of radius
          type.;"
                type: str
            src_geoloc_name:
                description:
                - "Single geolocation name"
                type: str
            src_geoloc_list:
                description:
                - "Geolocation name list"
                type: str
            src_geoloc_list_shared:
                description:
                - "Use Geolocation list from shared partition"
                type: bool
            src_ipv4_any:
                description:
                - "'any'= Any IPv4 address;"
                type: str
            src_ipv6_any:
                description:
                - "'any'= Any IPv6 address;"
                type: str
            src_class_list:
                description:
                - "Match source IP against class-list"
                type: str
            src_class_list_type:
                description:
                - "'radius'= Match the value of specified RADIUS attribute in the class-list.;"
                type: str
            derived_attribute:
                description:
                - "'usergroup'= Match the value from the derived attribute of user group in the
          class-list.; 'userid'= Match the value from the derived attribute of user ID in
          the class-list.;"
                type: str
            source_list:
                description:
                - "Field source_list"
                type: list
            src_zone:
                description:
                - "Zone name"
                type: str
            src_zone_any:
                description:
                - "'any'= any;"
                type: str
            dst_geoloc_name:
                description:
                - "Single geolocation name"
                type: str
            dst_geoloc_list:
                description:
                - "Geolocation name list"
                type: str
            dst_geoloc_list_shared:
                description:
                - "Use Geolocation list from shared partition"
                type: bool
            dst_ipv4_any:
                description:
                - "'any'= Any IPv4 address;"
                type: str
            dst_ipv6_any:
                description:
                - "'any'= Any IPv6 address;"
                type: str
            dst_class_list:
                description:
                - "Match destination IP against class-list"
                type: str
            dest_list:
                description:
                - "Field dest_list"
                type: list
            dst_domain_list:
                description:
                - "Match destination IP against domain-list"
                type: str
            dst_zone:
                description:
                - "Zone name"
                type: str
            dst_zone_any:
                description:
                - "'any'= any;"
                type: str
            service_any:
                description:
                - "'any'= any;"
                type: str
            service_list:
                description:
                - "Field service_list"
                type: list
            application_any:
                description:
                - "'any'= any;"
                type: str
            app_list:
                description:
                - "Field app_list"
                type: list
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
            move_rule:
                description:
                - "Field move_rule"
                type: dict
            action_group:
                description:
                - "Field action_group"
                type: dict
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            policy_status:
                description:
                - "Field policy_status"
                type: str
            policy_rule_count:
                description:
                - "Field policy_rule_count"
                type: int
            rule_stats:
                description:
                - "Field rule_stats"
                type: list
            name:
                description:
                - "Rule set name"
                type: str
            rule_list:
                description:
                - "Field rule_list"
                type: list
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            hit_count:
                description:
                - "Hit counts"
                type: str
            name:
                description:
                - "Rule set name"
                type: str
            rule_list:
                description:
                - "Field rule_list"
                type: list

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
AVAILABLE_PROPERTIES = ["name", "oper", "remark", "rule_list", "sampling_enable", "stats", "user_tag", "uuid", ]


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
        'name': {
            'type': 'str',
            'required': True,
            },
        'remark': {
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
                'type': 'str',
                'choices': ['all', 'hit-count']
                }
            },
        'rule_list': {
            'type': 'list',
            'name': {
                'type': 'str',
                'required': True,
                },
            'remark': {
                'type': 'str',
                },
            'status': {
                'type': 'str',
                'choices': ['enable', 'disable']
                },
            'ip_version': {
                'type': 'str',
                'choices': ['v4', 'v6', 'any']
                },
            'src_geoloc_name': {
                'type': 'str',
                },
            'src_geoloc_list': {
                'type': 'str',
                },
            'src_geoloc_list_shared': {
                'type': 'bool',
                },
            'src_ipv4_any': {
                'type': 'str',
                'choices': ['any']
                },
            'src_ipv6_any': {
                'type': 'str',
                'choices': ['any']
                },
            'src_class_list': {
                'type': 'str',
                },
            'src_class_list_type': {
                'type': 'str',
                'choices': ['radius']
                },
            'derived_attribute': {
                'type': 'str',
                'choices': ['usergroup', 'userid']
                },
            'source_list': {
                'type': 'list',
                'src_ip_subnet': {
                    'type': 'str',
                    },
                'src_ipv6_subnet': {
                    'type': 'str',
                    },
                'src_obj_network': {
                    'type': 'str',
                    },
                'src_obj_grp_network': {
                    'type': 'str',
                    }
                },
            'src_zone': {
                'type': 'str',
                },
            'src_zone_any': {
                'type': 'str',
                'choices': ['any']
                },
            'dst_geoloc_name': {
                'type': 'str',
                },
            'dst_geoloc_list': {
                'type': 'str',
                },
            'dst_geoloc_list_shared': {
                'type': 'bool',
                },
            'dst_ipv4_any': {
                'type': 'str',
                'choices': ['any']
                },
            'dst_ipv6_any': {
                'type': 'str',
                'choices': ['any']
                },
            'dst_class_list': {
                'type': 'str',
                },
            'dest_list': {
                'type': 'list',
                'dst_ip_subnet': {
                    'type': 'str',
                    },
                'dst_ipv6_subnet': {
                    'type': 'str',
                    },
                'dst_obj_network': {
                    'type': 'str',
                    },
                'dst_obj_grp_network': {
                    'type': 'str',
                    },
                'dst_slb_vserver': {
                    'type': 'str',
                    }
                },
            'dst_domain_list': {
                'type': 'str',
                },
            'dst_zone': {
                'type': 'str',
                },
            'dst_zone_any': {
                'type': 'str',
                'choices': ['any']
                },
            'service_any': {
                'type': 'str',
                'choices': ['any']
                },
            'service_list': {
                'type': 'list',
                'protocols': {
                    'type': 'str',
                    'choices': ['tcp', 'udp', 'sctp']
                    },
                'proto_id': {
                    'type': 'int',
                    },
                'obj_grp_service': {
                    'type': 'str',
                    },
                'icmp': {
                    'type': 'bool',
                    },
                'icmpv6': {
                    'type': 'bool',
                    },
                'icmp_type': {
                    'type': 'int',
                    },
                'special_type': {
                    'type': 'str',
                    'choices': ['any-type', 'echo-reply', 'echo-request', 'info-reply', 'info-request', 'mask-reply', 'mask-request', 'parameter-problem', 'redirect', 'source-quench', 'time-exceeded', 'timestamp', 'timestamp-reply', 'dest-unreachable']
                    },
                'icmp_code': {
                    'type': 'int',
                    },
                'special_code': {
                    'type': 'str',
                    'choices': ['any-code', 'frag-required', 'host-unreachable', 'network-unreachable', 'port-unreachable', 'proto-unreachable', 'route-failed']
                    },
                'icmpv6_type': {
                    'type': 'int',
                    },
                'special_v6_type': {
                    'type': 'str',
                    'choices': ['any-type', 'dest-unreachable', 'echo-reply', 'echo-request', 'packet-too-big', 'param-prob', 'time-exceeded']
                    },
                'icmpv6_code': {
                    'type': 'int',
                    },
                'special_v6_code': {
                    'type': 'str',
                    'choices': ['any-code', 'addr-unreachable', 'admin-prohibited', 'no-route', 'not-neighbour', 'port-unreachable']
                    },
                'eq_src_port': {
                    'type': 'int',
                    },
                'gt_src_port': {
                    'type': 'int',
                    },
                'lt_src_port': {
                    'type': 'int',
                    },
                'range_src_port': {
                    'type': 'int',
                    },
                'port_num_end_src': {
                    'type': 'int',
                    },
                'eq_dst_port': {
                    'type': 'int',
                    },
                'gt_dst_port': {
                    'type': 'int',
                    },
                'lt_dst_port': {
                    'type': 'int',
                    },
                'range_dst_port': {
                    'type': 'int',
                    },
                'port_num_end_dst': {
                    'type': 'int',
                    },
                'sctp_template': {
                    'type': 'str',
                    }
                },
            'application_any': {
                'type': 'str',
                'choices': ['any']
                },
            'app_list': {
                'type': 'list',
                'obj_grp_application': {
                    'type': 'str',
                    },
                'protocol': {
                    'type': 'str',
                    },
                'protocol_tag': {
                    'type':
                    'str',
                    'choices': [
                        'aaa', 'adult-content', 'advertising', 'application-enforcing-tls', 'analytics-and-statistics', 'anonymizers-and-proxies', 'audio-chat', 'basic', 'blog', 'cdn', 'certification-authority', 'chat', 'classified-ads', 'cloud-based-services', 'crowdfunding', 'cryptocurrency', 'database', 'disposable-email', 'ebook-reader',
                        'education', 'email', 'enterprise', 'file-management', 'file-transfer', 'forum', 'gaming', 'healthcare', 'instant-messaging-and-multimedia-conferencing', 'internet-of-things', 'map-service', 'mobile', 'multimedia-streaming', 'networking', 'news-portal', 'payment-service', 'peer-to-peer', 'remote-access', 'scada',
                        'social-networks', 'software-update', 'speedtest', 'standards-based', 'transportation', 'video-chat', 'voip', 'vpn-tunnels', 'web', 'web-e-commerce', 'web-search-engines', 'web-websites', 'webmails', 'web-ext-adult', 'web-ext-auctions', 'web-ext-blogs', 'web-ext-business-and-economy', 'web-ext-cdns', 'web-ext-collaboration',
                        'web-ext-computer-and-internet-info', 'web-ext-computer-and-internet-security', 'web-ext-dating', 'web-ext-educational-institutions', 'web-ext-entertainment-and-arts', 'web-ext-fashion-and-beauty', 'web-ext-file-share', 'web-ext-financial-services', 'web-ext-gambling', 'web-ext-games', 'web-ext-government',
                        'web-ext-health-and-medicine', 'web-ext-individual-stock-advice-and-tools', 'web-ext-internet-portals', 'web-ext-job-search', 'web-ext-local-information', 'web-ext-malware', 'web-ext-motor-vehicles', 'web-ext-music', 'web-ext-news', 'web-ext-p2p', 'web-ext-parked-sites', 'web-ext-proxy-avoid-and-anonymizers',
                        'web-ext-real-estate', 'web-ext-reference-and-research', 'web-ext-search-engines', 'web-ext-shopping', 'web-ext-social-network', 'web-ext-society', 'web-ext-software', 'web-ext-sports', 'web-ext-streaming-media', 'web-ext-training-and-tools', 'web-ext-translation', 'web-ext-travel', 'web-ext-web-advertisements',
                        'web-ext-web-based-email', 'web-ext-web-hosting', 'web-ext-web-service'
                        ]
                    }
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
                    'choices': ['all', 'hit-count']
                    }
                },
            'move_rule': {
                'type': 'dict',
                'location': {
                    'type': 'str',
                    'choices': ['top', 'before', 'after', 'bottom']
                    },
                'target_rule': {
                    'type': 'str',
                    }
                },
            'action_group': {
                'type': 'dict',
                'limit_policy': {
                    'type': 'int',
                    },
                'uuid': {
                    'type': 'str',
                    }
                }
            },
        'oper': {
            'type': 'dict',
            'policy_status': {
                'type': 'str',
                },
            'policy_rule_count': {
                'type': 'int',
                },
            'rule_stats': {
                'type': 'list',
                'rule_name': {
                    'type': 'str',
                    },
                'rule_status': {
                    'type': 'str',
                    },
                'rule_hitcount': {
                    'type': 'int',
                    }
                },
            'name': {
                'type': 'str',
                'required': True,
                },
            'rule_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'oper': {
                    'type': 'dict',
                    'status': {
                        'type': 'str',
                        },
                    'hitcount': {
                        'type': 'int',
                        }
                    }
                }
            },
        'stats': {
            'type': 'dict',
            'hit_count': {
                'type': 'str',
                },
            'name': {
                'type': 'str',
                'required': True,
                },
            'rule_list': {
                'type': 'list',
                'name': {
                    'type': 'str',
                    'required': True,
                    },
                'stats': {
                    'type': 'dict',
                    'hit_count': {
                        'type': 'str',
                        }
                    }
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/traffic-control/rule-set/{name}"

    f_dict = {}
    if '/' in str(module.params["name"]):
        f_dict["name"] = module.params["name"].replace("/", "%2F")
    else:
        f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/traffic-control/rule-set"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["rule-set"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["rule-set"].get(k) != v:
            change_results["changed"] = True
            config_changes["rule-set"][k] = v

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
    payload = utils.build_json("rule-set", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["rule-set"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["rule-set-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["rule-set"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["rule-set"]["stats"] if info != "NotFound" else info
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
