#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_sessions
description:
    - Field sessions
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
    uuid:
        description:
        - "uuid of the object"
        type: str
        required: False
    ext:
        description:
        - "Field ext"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    smp:
        description:
        - "Field smp"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    smp_table:
        description:
        - "Field smp_table"
        type: dict
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            session_list:
                description:
                - "Field session_list"
                type: list
            total_sessions:
                description:
                - "Field total_sessions"
                type: int
            app_sessions:
                description:
                - "Field app_sessions"
                type: int
            filter_type:
                description:
                - "Field filter_type"
                type: str
            filter_debug:
                description:
                - "Field filter_debug"
                type: str
            src_ipv4_addr:
                description:
                - "Field src_ipv4_addr"
                type: str
            dst_ipv4_addr:
                description:
                - "Field dst_ipv4_addr"
                type: str
            nat_ipv4_addr:
                description:
                - "Field nat_ipv4_addr"
                type: str
            src_ipv6_addr:
                description:
                - "Field src_ipv6_addr"
                type: str
            dst_ipv6_addr:
                description:
                - "Field dst_ipv6_addr"
                type: str
            name_str:
                description:
                - "Field name_str"
                type: str
            dest_port:
                description:
                - "Field dest_port"
                type: int
            src_port:
                description:
                - "Field src_port"
                type: int
            nat_port:
                description:
                - "Field nat_port"
                type: int
            thread:
                description:
                - "Field thread"
                type: int
            bucket:
                description:
                - "Field bucket"
                type: int
            app_category:
                description:
                - "Field app_category"
                type: str
            app:
                description:
                - "Field app"
                type: str
            l4_protocol:
                description:
                - "Field l4_protocol"
                type: str
            fw_helper_sessions:
                description:
                - "Field fw_helper_sessions"
                type: bool
            fw_ip_type:
                description:
                - "Field fw_ip_type"
                type: str
            fw_rule:
                description:
                - "Field fw_rule"
                type: str
            fw_dest_zone:
                description:
                - "Field fw_dest_zone"
                type: str
            fw_src_zone:
                description:
                - "Field fw_src_zone"
                type: str
            fw_dest_obj:
                description:
                - "Field fw_dest_obj"
                type: str
            fw_src_obj:
                description:
                - "Field fw_src_obj"
                type: str
            fw_dest_obj_grp:
                description:
                - "Field fw_dest_obj_grp"
                type: str
            fw_src_obj_grp:
                description:
                - "Field fw_src_obj_grp"
                type: str
            fw_dest_rserver:
                description:
                - "Field fw_dest_rserver"
                type: str
            fw_src_rserver:
                description:
                - "Field fw_src_rserver"
                type: str
            fw_dest_vserver:
                description:
                - "Field fw_dest_vserver"
                type: str
            application:
                description:
                - "Field application"
                type: str
            session_id:
                description:
                - "Field session_id"
                type: str
            zone_name:
                description:
                - "Field zone_name"
                type: str
            sport_rate_limit_exceed:
                description:
                - "Field sport_rate_limit_exceed"
                type: bool
            sport_rate_limit_curr:
                description:
                - "Field sport_rate_limit_curr"
                type: bool
            src_ipv6_prefix:
                description:
                - "Field src_ipv6_prefix"
                type: str
            dst_ipv6_prefix:
                description:
                - "Field dst_ipv6_prefix"
                type: str
            check_inside_user:
                description:
                - "Field check_inside_user"
                type: bool
            rev_dest_teid:
                description:
                - "Field rev_dest_teid"
                type: int
            msisdn:
                description:
                - "Field msisdn"
                type: bool
            msisdn_val:
                description:
                - "Field msisdn_val"
                type: str
            imsi:
                description:
                - "Field imsi"
                type: bool
            imsi_val:
                description:
                - "Field imsi_val"
                type: str
            gtp_msg_type:
                description:
                - "Field gtp_msg_type"
                type: str
            gtp_version:
                description:
                - "Field gtp_version"
                type: str
            full_width:
                description:
                - "Field full_width"
                type: bool
            ext_filter_name:
                description:
                - "Field ext_filter_name"
                type: str
            uie:
                description:
                - "Field uie"
                type: str
            persist_ipv4:
                description:
                - "Field persist_ipv4"
                type: bool
            persist_type:
                description:
                - "Field persist_type"
                type: str
            persist_source_addr:
                description:
                - "Field persist_source_addr"
                type: str
            persist_source_port:
                description:
                - "Field persist_source_port"
                type: int
            persist_dest_addr:
                description:
                - "Field persist_dest_addr"
                type: str
            persist_dest_port:
                description:
                - "Field persist_dest_port"
                type: int
            persist_ipv6:
                description:
                - "Field persist_ipv6"
                type: bool
            persist_ipv6_type:
                description:
                - "Field persist_ipv6_type"
                type: str
            persist_v6_source_addr:
                description:
                - "Field persist_v6_source_addr"
                type: str
            persist_v6_source_port:
                description:
                - "Field persist_v6_source_port"
                type: int
            persist_v6_dest_addr:
                description:
                - "Field persist_v6_dest_addr"
                type: str
            persist_v6_dest_port:
                description:
                - "Field persist_v6_dest_port"
                type: int
            force:
                description:
                - "Field force"
                type: str
            ext:
                description:
                - "Field ext"
                type: dict
            smp:
                description:
                - "Field smp"
                type: dict
            smp_table:
                description:
                - "Field smp_table"
                type: dict

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
AVAILABLE_PROPERTIES = ["ext", "oper", "smp", "smp_table", "uuid", ]


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
        'uuid': {
            'type': 'str',
            },
        'ext': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'smp': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'smp_table': {
            'type': 'dict',
            'uuid': {
                'type': 'str',
                }
            },
        'oper': {
            'type': 'dict',
            'session_list': {
                'type': 'list',
                'protocol': {
                    'type': 'str',
                    },
                'forward_source': {
                    'type': 'str',
                    },
                'forward_dest': {
                    'type': 'str',
                    },
                'reverse_source': {
                    'type': 'str',
                    },
                'reverse_dest': {
                    'type': 'str',
                    },
                'rate': {
                    'type': 'int',
                    },
                'limit': {
                    'type': 'int',
                    },
                'drop': {
                    'type': 'int',
                    },
                'peak_rate': {
                    'type': 'int',
                    },
                'age': {
                    'type': 'int',
                    },
                'hash': {
                    'type': 'int',
                    },
                'flags': {
                    'type': 'str',
                    },
                'app_type': {
                    'type': 'str',
                    },
                '100ms': {
                    'type': 'str',
                    },
                'sip_call_id': {
                    'type': 'str',
                    },
                'app_name': {
                    'type': 'str',
                    },
                'service_name': {
                    'type': 'str',
                    },
                'rserver_name': {
                    'type': 'str',
                    },
                'category_name': {
                    'type': 'str',
                    },
                'bytes': {
                    'type': 'int',
                    },
                'duration': {
                    'type': 'int',
                    },
                'conn_idx': {
                    'type': 'int',
                    },
                'hash_idx': {
                    'type': 'int',
                    },
                'ddos_total_fwd_bytes': {
                    'type': 'int',
                    },
                'ddos_total_rev_bytes': {
                    'type': 'int',
                    },
                'ddos_total_out_of_order': {
                    'type': 'int',
                    },
                'ddos_total_zero_window': {
                    'type': 'int',
                    },
                'ddos_total_retrans': {
                    'type': 'int',
                    },
                'ddos_current_pkt_rate': {
                    'type': 'int',
                    },
                'ddos_exceeded_pkt_rate': {
                    'type': 'int',
                    },
                'extension_fields_list': {
                    'type': 'list',
                    'ext_field_name': {
                        'type': 'str',
                        },
                    'ext_field_val': {
                        'type': 'str',
                        }
                    },
                'dns_id': {
                    'type': 'int',
                    },
                'radius_id': {
                    'type': 'int',
                    }
                },
            'total_sessions': {
                'type': 'int',
                },
            'app_sessions': {
                'type': 'int',
                },
            'filter_type': {
                'type':
                'str',
                'choices': [
                    'ipv4', 'ipv6', 'nat44', 'nat64', 'persist-ipv6-src-ip', 'persist-ipv6-dst-ip', 'persist-ipv6-ssl-id', 'persist-dst-ip', 'persist-src-ip', 'persist-uie', 'persist-ssl-id', 'radius', 'server', 'virtual-server', 'sip', 'sixrd', 'filter', 'ds-lite', 'dns-id-switch', 'local', 'fw', 'clear-all', 'full-width', 'application', 'ipsec',
                    'diameter', 'zone', 'source-port-rate-limit', 'source-port-rate-limitv4', 'source-port-rate-limitv6', 'gtp', 'extended_filter', 'hm'
                    ]
                },
            'filter_debug': {
                'type': 'str',
                'choices': ['debug']
                },
            'src_ipv4_addr': {
                'type': 'str',
                },
            'dst_ipv4_addr': {
                'type': 'str',
                },
            'nat_ipv4_addr': {
                'type': 'str',
                },
            'src_ipv6_addr': {
                'type': 'str',
                },
            'dst_ipv6_addr': {
                'type': 'str',
                },
            'name_str': {
                'type': 'str',
                },
            'dest_port': {
                'type': 'int',
                },
            'src_port': {
                'type': 'int',
                },
            'nat_port': {
                'type': 'int',
                },
            'thread': {
                'type': 'int',
                },
            'bucket': {
                'type': 'int',
                },
            'app_category': {
                'type': 'str',
                },
            'app': {
                'type': 'str',
                },
            'l4_protocol': {
                'type': 'str',
                'choices': ['udp', 'tcp', 'icmp', 'icmpv6']
                },
            'fw_helper_sessions': {
                'type': 'bool',
                },
            'fw_ip_type': {
                'type': 'str',
                'choices': ['ipv4', 'ipv6']
                },
            'fw_rule': {
                'type': 'str',
                },
            'fw_dest_zone': {
                'type': 'str',
                },
            'fw_src_zone': {
                'type': 'str',
                },
            'fw_dest_obj': {
                'type': 'str',
                },
            'fw_src_obj': {
                'type': 'str',
                },
            'fw_dest_obj_grp': {
                'type': 'str',
                },
            'fw_src_obj_grp': {
                'type': 'str',
                },
            'fw_dest_rserver': {
                'type': 'str',
                },
            'fw_src_rserver': {
                'type': 'str',
                },
            'fw_dest_vserver': {
                'type': 'str',
                },
            'application': {
                'type': 'str',
                },
            'session_id': {
                'type': 'str',
                },
            'zone_name': {
                'type': 'str',
                },
            'sport_rate_limit_exceed': {
                'type': 'bool',
                },
            'sport_rate_limit_curr': {
                'type': 'bool',
                },
            'src_ipv6_prefix': {
                'type': 'str',
                },
            'dst_ipv6_prefix': {
                'type': 'str',
                },
            'check_inside_user': {
                'type': 'bool',
                },
            'rev_dest_teid': {
                'type': 'int',
                },
            'msisdn': {
                'type': 'bool',
                },
            'msisdn_val': {
                'type': 'str',
                },
            'imsi': {
                'type': 'bool',
                },
            'imsi_val': {
                'type': 'str',
                },
            'gtp_msg_type': {
                'type': 'str',
                },
            'gtp_version': {
                'type': 'str',
                },
            'full_width': {
                'type': 'bool',
                },
            'ext_filter_name': {
                'type': 'str',
                },
            'uie': {
                'type': 'str',
                },
            'persist_ipv4': {
                'type': 'bool',
                },
            'persist_type': {
                'type': 'str',
                },
            'persist_source_addr': {
                'type': 'str',
                },
            'persist_source_port': {
                'type': 'int',
                },
            'persist_dest_addr': {
                'type': 'str',
                },
            'persist_dest_port': {
                'type': 'int',
                },
            'persist_ipv6': {
                'type': 'bool',
                },
            'persist_ipv6_type': {
                'type': 'str',
                },
            'persist_v6_source_addr': {
                'type': 'str',
                },
            'persist_v6_source_port': {
                'type': 'int',
                },
            'persist_v6_dest_addr': {
                'type': 'str',
                },
            'persist_v6_dest_port': {
                'type': 'int',
                },
            'force': {
                'type': 'str',
                },
            'ext': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'session_ext_list': {
                        'type': 'list',
                        'ntype': {
                            'type': 'str',
                            },
                        'alloc': {
                            'type': 'int',
                            },
                        'free': {
                            'type': 'int',
                            },
                        'fail': {
                            'type': 'int',
                            },
                        'cpu_round_robin_fail': {
                            'type': 'int',
                            },
                        'alloc_exceed': {
                            'type': 'int',
                            }
                        }
                    }
                },
            'smp': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'session_smp_list': {
                        'type': 'list',
                        'ntype': {
                            'type': 'str',
                            },
                        'alloc': {
                            'type': 'int',
                            },
                        'free': {
                            'type': 'int',
                            },
                        'alloc_fail': {
                            'type': 'int',
                            }
                        }
                    }
                },
            'smp_table': {
                'type': 'dict',
                'oper': {
                    'type': 'dict',
                    'entry_list': {
                        'type': 'list',
                        'src4': {
                            'type': 'str',
                            },
                        'src6': {
                            'type': 'str',
                            },
                        'dst4': {
                            'type': 'str',
                            },
                        'dst6': {
                            'type': 'str',
                            },
                        'srcport': {
                            'type': 'int',
                            },
                        'dstport': {
                            'type': 'int',
                            },
                        'ttl': {
                            'type': 'int',
                            },
                        'ntype': {
                            'type': 'str',
                            },
                        'payload': {
                            'type': 'str',
                            }
                        }
                    }
                }
            }
        })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/sessions"

    f_dict = {}

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/sessions"

    f_dict = {}

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["sessions"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["sessions"].get(k) != v:
            change_results["changed"] = True
            config_changes["sessions"][k] = v

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
    payload = utils.build_json("sessions", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["sessions"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["sessions-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["sessions"]["oper"] if info != "NotFound" else info
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
