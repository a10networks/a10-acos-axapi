#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_ddos_dst_zone_ip_proto_proto_number_src_based_policy_policy_class_list
description:
    - Configure class-list
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
    src_based_policy_src_based_policy_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    proto_number_protocol_num:
        description:
        - Key to identify parent object
        type: str
        required: True
    zone_name:
        description:
        - Key to identify parent object
        type: str
        required: True
    class_list_name:
        description:
        - "Class-list name"
        type: str
        required: True
    class_list_glid:
        description:
        - "Global limit ID (class-list based)"
        type: str
        required: False
    glid:
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
    action:
        description:
        - "'bypass'= Always permit for the Source to bypass all feature & limit checks;
          'deny'= Blacklist incoming packets for service;"
        type: str
        required: False
    log_enable:
        description:
        - "Enable logging"
        type: bool
        required: False
    log_periodic:
        description:
        - "Enable log periodic"
        type: bool
        required: False
    max_dynamic_entry_count:
        description:
        - "Maximum count for dynamic source zone service entry allowed for this class-list"
        type: int
        required: False
    dynamic_entry_count_warn_threshold:
        description:
        - "Set threshold percentage of 'max-src-dst-entry' for generating warning logs.
          Including start and end."
        type: int
        required: False
    zone_template:
        description:
        - "Field zone_template"
        type: dict
        required: False
        suboptions:
            logging:
                description:
                - "DDOS logging template"
                type: str
            ip_proto:
                description:
                - "DDOS ip-proto template"
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        type: list
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'packet_received'= Packets Received; 'packet_dropped'= Packets
          Dropped; 'entry_learned'= Entry Learned; 'entry_count_overflow'= Entry Count
          Overflow; 'exceed_drop_pkt_rate_clist'= Packet Rate Exceeded;
          'exceed_drop_conn_rate_clist'= Conn Rate Exceeded;
          'exceed_drop_conn_limit_clist'= Conn Limit Exceeded;
          'exceed_drop_kbit_rate_clist'= KiBit Rate Exceeded;
          'exceed_drop_kbit_rate_clist_pkt'= KiBit Rate Exceeded Count;
          'exceed_drop_frag_rate_clist'= Frag Rate Exceeded;"
                type: str
    class_list_overflow_policy_list:
        description:
        - "Field class_list_overflow_policy_list"
        type: list
        required: False
        suboptions:
            dummy_name:
                description:
                - "'configuration'= Configure overflow policy for class-list;"
                type: str
            glid:
                description:
                - "Global limit ID"
                type: str
            action:
                description:
                - "'bypass'= Always permit for the Source to bypass all feature & limit checks;
          'deny'= Blacklist incoming packets for service;"
                type: str
            log_enable:
                description:
                - "Enable logging"
                type: bool
            log_periodic:
                description:
                - "Enable log periodic"
                type: bool
            zone_template:
                description:
                - "Field zone_template"
                type: dict
            uuid:
                description:
                - "uuid of the object"
                type: str
            user_tag:
                description:
                - "Customized tag"
                type: str
    oper:
        description:
        - "Field oper"
        type: dict
        required: False
        suboptions:
            current_connections:
                description:
                - "Field current_connections"
                type: int
            is_connections_exceed:
                description:
                - "Field is_connections_exceed"
                type: int
            connection_limit:
                description:
                - "Field connection_limit"
                type: int
            current_connection_rate:
                description:
                - "Field current_connection_rate"
                type: int
            is_connection_rate_exceed:
                description:
                - "Field is_connection_rate_exceed"
                type: int
            connection_rate_limit:
                description:
                - "Field connection_rate_limit"
                type: int
            current_packet_rate:
                description:
                - "Field current_packet_rate"
                type: int
            is_packet_rate_exceed:
                description:
                - "Field is_packet_rate_exceed"
                type: int
            packet_rate_limit:
                description:
                - "Field packet_rate_limit"
                type: int
            current_kBit_rate:
                description:
                - "Field current_kBit_rate"
                type: int
            is_kBit_rate_exceed:
                description:
                - "Field is_kBit_rate_exceed"
                type: int
            kBit_rate_limit:
                description:
                - "Field kBit_rate_limit"
                type: int
            current_frag_packet_rate:
                description:
                - "Field current_frag_packet_rate"
                type: int
            is_frag_packet_rate_exceed:
                description:
                - "Field is_frag_packet_rate_exceed"
                type: int
            frag_packet_rate_limit:
                description:
                - "Field frag_packet_rate_limit"
                type: int
            debug_str:
                description:
                - "Field debug_str"
                type: str
            class_list_name:
                description:
                - "Class-list name"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            packet_received:
                description:
                - "Packets Received"
                type: str
            packet_dropped:
                description:
                - "Packets Dropped"
                type: str
            entry_learned:
                description:
                - "Entry Learned"
                type: str
            entry_count_overflow:
                description:
                - "Entry Count Overflow"
                type: str
            exceed_drop_pkt_rate_clist:
                description:
                - "Packet Rate Exceeded"
                type: str
            exceed_drop_conn_rate_clist:
                description:
                - "Conn Rate Exceeded"
                type: str
            exceed_drop_conn_limit_clist:
                description:
                - "Conn Limit Exceeded"
                type: str
            exceed_drop_kbit_rate_clist:
                description:
                - "KiBit Rate Exceeded"
                type: str
            exceed_drop_kbit_rate_clist_pkt:
                description:
                - "KiBit Rate Exceeded Count"
                type: str
            exceed_drop_frag_rate_clist:
                description:
                - "Frag Rate Exceeded"
                type: str
            class_list_name:
                description:
                - "Class-list name"
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
AVAILABLE_PROPERTIES = ["action", "class_list_glid", "class_list_name", "class_list_overflow_policy_list", "dynamic_entry_count_warn_threshold", "glid", "glid_action", "log_enable", "log_periodic", "max_dynamic_entry_count", "oper", "sampling_enable", "stats", "user_tag", "uuid", "zone_template", ]


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
        'class_list_name': {
            'type': 'str',
            'required': True,
            },
        'class_list_glid': {
            'type': 'str',
            },
        'glid': {
            'type': 'str',
            },
        'glid_action': {
            'type': 'str',
            'choices': ['drop', 'blacklist-src', 'ignore']
            },
        'action': {
            'type': 'str',
            'choices': ['bypass', 'deny']
            },
        'log_enable': {
            'type': 'bool',
            },
        'log_periodic': {
            'type': 'bool',
            },
        'max_dynamic_entry_count': {
            'type': 'int',
            },
        'dynamic_entry_count_warn_threshold': {
            'type': 'int',
            },
        'zone_template': {
            'type': 'dict',
            'logging': {
                'type': 'str',
                },
            'ip_proto': {
                'type': 'str',
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
                'choices': ['all', 'packet_received', 'packet_dropped', 'entry_learned', 'entry_count_overflow', 'exceed_drop_pkt_rate_clist', 'exceed_drop_conn_rate_clist', 'exceed_drop_conn_limit_clist', 'exceed_drop_kbit_rate_clist', 'exceed_drop_kbit_rate_clist_pkt', 'exceed_drop_frag_rate_clist']
                }
            },
        'class_list_overflow_policy_list': {
            'type': 'list',
            'dummy_name': {
                'type': 'str',
                'required': True,
                'choices': ['configuration']
                },
            'glid': {
                'type': 'str',
                },
            'action': {
                'type': 'str',
                'choices': ['bypass', 'deny']
                },
            'log_enable': {
                'type': 'bool',
                },
            'log_periodic': {
                'type': 'bool',
                },
            'zone_template': {
                'type': 'dict',
                'ip_proto': {
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
        'oper': {
            'type': 'dict',
            'current_connections': {
                'type': 'int',
                },
            'is_connections_exceed': {
                'type': 'int',
                },
            'connection_limit': {
                'type': 'int',
                },
            'current_connection_rate': {
                'type': 'int',
                },
            'is_connection_rate_exceed': {
                'type': 'int',
                },
            'connection_rate_limit': {
                'type': 'int',
                },
            'current_packet_rate': {
                'type': 'int',
                },
            'is_packet_rate_exceed': {
                'type': 'int',
                },
            'packet_rate_limit': {
                'type': 'int',
                },
            'current_kBit_rate': {
                'type': 'int',
                },
            'is_kBit_rate_exceed': {
                'type': 'int',
                },
            'kBit_rate_limit': {
                'type': 'int',
                },
            'current_frag_packet_rate': {
                'type': 'int',
                },
            'is_frag_packet_rate_exceed': {
                'type': 'int',
                },
            'frag_packet_rate_limit': {
                'type': 'int',
                },
            'debug_str': {
                'type': 'str',
                },
            'class_list_name': {
                'type': 'str',
                'required': True,
                }
            },
        'stats': {
            'type': 'dict',
            'packet_received': {
                'type': 'str',
                },
            'packet_dropped': {
                'type': 'str',
                },
            'entry_learned': {
                'type': 'str',
                },
            'entry_count_overflow': {
                'type': 'str',
                },
            'exceed_drop_pkt_rate_clist': {
                'type': 'str',
                },
            'exceed_drop_conn_rate_clist': {
                'type': 'str',
                },
            'exceed_drop_conn_limit_clist': {
                'type': 'str',
                },
            'exceed_drop_kbit_rate_clist': {
                'type': 'str',
                },
            'exceed_drop_kbit_rate_clist_pkt': {
                'type': 'str',
                },
            'exceed_drop_frag_rate_clist': {
                'type': 'str',
                },
            'class_list_name': {
                'type': 'str',
                'required': True,
                }
            }
        })
    # Parent keys
    rv.update(dict(src_based_policy_src_based_policy_name=dict(type='str', required=True), proto_number_protocol_num=dict(type='str', required=True), zone_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/ddos/dst/zone/{zone_name}/ip-proto/proto-number/{proto_number_protocol_num}/src-based-policy/{src_based_policy_src_based_policy_name}/policy-class-list/{class_list_name}"

    f_dict = {}
    if '/' in str(module.params["class_list_name"]):
        f_dict["class_list_name"] = module.params["class_list_name"].replace("/", "%2F")
    else:
        f_dict["class_list_name"] = module.params["class_list_name"]
    if '/' in module.params["src_based_policy_src_based_policy_name"]:
        f_dict["src_based_policy_src_based_policy_name"] = module.params["src_based_policy_src_based_policy_name"].replace("/", "%2F")
    else:
        f_dict["src_based_policy_src_based_policy_name"] = module.params["src_based_policy_src_based_policy_name"]
    if '/' in module.params["proto_number_protocol_num"]:
        f_dict["proto_number_protocol_num"] = module.params["proto_number_protocol_num"].replace("/", "%2F")
    else:
        f_dict["proto_number_protocol_num"] = module.params["proto_number_protocol_num"]
    if '/' in module.params["zone_name"]:
        f_dict["zone_name"] = module.params["zone_name"].replace("/", "%2F")
    else:
        f_dict["zone_name"] = module.params["zone_name"]

    return url_base.format(**f_dict)


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/ddos/dst/zone/{zone_name}/ip-proto/proto-number/{proto_number_protocol_num}/src-based-policy/{src_based_policy_src_based_policy_name}/policy-class-list"

    f_dict = {}
    f_dict["class_list_name"] = ""
    f_dict["src_based_policy_src_based_policy_name"] = module.params["src_based_policy_src_based_policy_name"]
    f_dict["proto_number_protocol_num"] = module.params["proto_number_protocol_num"]
    f_dict["zone_name"] = module.params["zone_name"]

    return url_base.format(**f_dict)


def report_changes(module, result, existing_config, payload):
    change_results = copy.deepcopy(result)
    if not existing_config:
        change_results["modified_values"].update(**payload)
        return change_results

    config_changes = copy.deepcopy(existing_config)
    for k, v in payload["policy-class-list"].items():
        v = 1 if str(v).lower() == "true" else v
        v = 0 if str(v).lower() == "false" else v

        if config_changes["policy-class-list"].get(k) != v:
            change_results["changed"] = True
            config_changes["policy-class-list"][k] = v

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
    payload = utils.build_json("policy-class-list", module.params, AVAILABLE_PROPERTIES)
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
                result["acos_info"] = info["policy-class-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "list":
                get_list_result = api_client.get_list(module.client, existing_url(module))
                result["axapi_calls"].append(get_list_result)

                info = get_list_result["response_body"]
                result["acos_info"] = info["policy-class-list-list"] if info != "NotFound" else info
            elif module.params.get("get_type") == "oper":
                get_oper_result = api_client.get_oper(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_oper_result)
                info = get_oper_result["response_body"]
                result["acos_info"] = info["policy-class-list"]["oper"] if info != "NotFound" else info
            elif module.params.get("get_type") == "stats":
                get_type_result = api_client.get_stats(module.client, existing_url(module), params=module.params)
                result["axapi_calls"].append(get_type_result)
                info = get_type_result["response_body"]
                result["acos_info"] = info["policy-class-list"]["stats"] if info != "NotFound" else info
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
