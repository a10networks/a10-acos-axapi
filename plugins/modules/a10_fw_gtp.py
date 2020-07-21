#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_fw_gtp
description:
    - Configure GTP
short_description: Configures A10 fw.gtp
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'create-session-request'= Create Session Request; 'create-session-
          response'= Create Session Response; 'path-management-message'= Path Management
          Message; 'delete-session-request'= Delete Session Request; 'delete-session-
          response'= Delete Session Response; 'reserved-field-set-drop'= Reserved field
          set drop; 'tunnel-id-flag-drop'= Tunnel ID Flag Incorrect; 'message-filtering-
          drop'= Message Filtering Drop; 'reserved-information-element-drop'= Resevered
          Information Element Field Drop; 'mandatory-information-element-drop'= Mandatory
          Information Element Field Drop; 'filter-list-drop'= APN IMSI Information
          Filtering Drop; 'invalid-teid-drop'= Invalid TEID Drop; 'out-of-state-drop'=
          Out Of State Drop; 'message-length-drop'= Message Length Exceeded;
          'unsupported-message-type-v2'= GTP v2 message type is not supported; 'fast-
          conn-setup'= Fast Conn Setup Attempt; 'out-of-session-memory'= Out of Session
          Memory; 'no-fwd-route'= No Forward Route; 'no-rev-route'= NO Reverse Route;
          'invalid-key'= Invalid TEID Field; 'create-session-request-retransmit'=
          Retransmitted Create Session Request; 'delete-session-request-retransmit'=
          Retransmitted Delete Session Request; 'response-cause-not-accepted'= Response
          Cause indicates Request not Accepted; 'invalid-imsi-len-drop'= Invalid IMSI
          Length Drop; 'invalid-apn-len-drop'= Invalid APN Length Drop; 'create-pdp-
          context-request-v1'= GTP v1 Create PDP Context Request; 'create-pdp-context-
          response-v1'= GTP v1 Create PDP Context Response; 'path-management-message-v1'=
          GTP v1 Path Management Message; 'reserved-field-set-drop-v1'= GTP v1 Reserved
          field set drop; 'message-filtering-drop-v1'= GTP v1 Message Filtering Drop;
          'reserved-information-element-drop-v1'= GTP v1 Reserved Information Element
          Field Drop; 'mandatory-information-element-drop-v1'= GTP v1 Mandatory
          Information Element Field Drop; 'filter-list-drop-v1'= GTP v1 APN IMSI
          Information Filtering Drop; 'invalid-teid-drop-v1'= GTP v1 Invalid TEID Drop;
          'message-length-drop-v1'= GTP v1 Message Length Exceeded; 'version-not-
          supported'= GTP version is not supported; 'unsupported-message-type-v1'= GTP v1
          message type is not supported; 'delete-pdp-context-request-v1'= GTP v1 Delete
          Context PDP Request; 'delete-pdp-context-response-v1'= GTP v1 Delete Context
          PDP Response; 'create-pdp-context-request-v0'= GTP v0 Create PDP Context
          Request; 'create-pdp-context-response-v0'= GTP v0 Create PDP Context Response;
          'delete-pdp-context-request-v0'= GTP v0 Delete Context PDP Request; 'delete-
          pdp-context-response-v0'= GTP v0 Delete Context PDP Response; 'path-management-
          message-v0'= GTP v0 Path Management Message; 'message-filtering-drop-v0'= GTP
          v0 Message Filtering Drop; 'unsupported-message-type-v0'= GTP v0 message type
          is not supported; 'invalid-flow-label-drop-v0'= GTP v0 Invalid flow label drop;
          'invalid-tid-drop-v0'= GTP v0 Invalid tid drop; 'message-length-drop-v0'= GTP
          v0 Message Length Exceeded; 'mandatory-information-element-drop-v0'= GTP v0
          Mandatory Information Element Field Drop; 'filter-list-drop-v0'= GTP v0 APN
          IMSI Information Filtering Drop; 'gtp-in-gtp-drop'= GTP in GTP Filtering Drop;"
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            invalid_apn_len_drop:
                description:
                - "Invalid APN Length Drop"
            reserved_field_set_drop:
                description:
                - "Reserved field set drop"
            message_length_drop:
                description:
                - "Message Length Exceeded"
            out_of_session_memory:
                description:
                - "Out of Session Memory"
            reserved_information_element_drop:
                description:
                - "Resevered Information Element Field Drop"
            path_management_message_v0:
                description:
                - "GTP v0 Path Management Message"
            out_of_state_drop:
                description:
                - "Out Of State Drop"
            delete_session_response:
                description:
                - "Delete Session Response"
            invalid_flow_label_drop_v0:
                description:
                - "GTP v0 Invalid flow label drop"
            invalid_imsi_len_drop:
                description:
                - "Invalid IMSI Length Drop"
            filter_list_drop:
                description:
                - "APN IMSI Information Filtering Drop"
            response_cause_not_accepted:
                description:
                - "Response Cause indicates Request not Accepted"
            mandatory_information_element_drop:
                description:
                - "Mandatory Information Element Field Drop"
            unsupported_message_type_v0:
                description:
                - "GTP v0 message type is not supported"
            unsupported_message_type_v1:
                description:
                - "GTP v1 message type is not supported"
            unsupported_message_type_v2:
                description:
                - "GTP v2 message type is not supported"
            invalid_teid_drop:
                description:
                - "Invalid TEID Drop"
            message_filtering_drop:
                description:
                - "Message Filtering Drop"
            no_fwd_route:
                description:
                - "No Forward Route"
            create_pdp_context_request_v1:
                description:
                - "GTP v1 Create PDP Context Request"
            fast_conn_setup:
                description:
                - "Fast Conn Setup Attempt"
            path_management_message_v1:
                description:
                - "GTP v1 Path Management Message"
            create_session_request_retransmit:
                description:
                - "Retransmitted Create Session Request"
            create_session_request:
                description:
                - "Create Session Request"
            no_rev_route:
                description:
                - "NO Reverse Route"
            gtp_in_gtp_drop:
                description:
                - "GTP in GTP Filtering Drop"
            mandatory_information_element_drop_v1:
                description:
                - "GTP v1 Mandatory Information Element Field Drop"
            mandatory_information_element_drop_v0:
                description:
                - "GTP v0 Mandatory Information Element Field Drop"
            message_filtering_drop_v0:
                description:
                - "GTP v0 Message Filtering Drop"
            message_filtering_drop_v1:
                description:
                - "GTP v1 Message Filtering Drop"
            reserved_information_element_drop_v1:
                description:
                - "GTP v1 Reserved Information Element Field Drop"
            version_not_supported:
                description:
                - "GTP version is not supported"
            invalid_teid_drop_v1:
                description:
                - "GTP v1 Invalid TEID Drop"
            filter_list_drop_v0:
                description:
                - "GTP v0 APN IMSI Information Filtering Drop"
            reserved_field_set_drop_v1:
                description:
                - "GTP v1 Reserved field set drop"
            tunnel_id_flag_drop:
                description:
                - "Tunnel ID Flag Incorrect"
            filter_list_drop_v1:
                description:
                - "GTP v1 APN IMSI Information Filtering Drop"
            create_pdp_context_request_v0:
                description:
                - "GTP v0 Create PDP Context Request"
            message_length_drop_v1:
                description:
                - "GTP v1 Message Length Exceeded"
            message_length_drop_v0:
                description:
                - "GTP v0 Message Length Exceeded"
            delete_pdp_context_request_v0:
                description:
                - "GTP v0 Delete Context PDP Request"
            delete_pdp_context_request_v1:
                description:
                - "GTP v1 Delete Context PDP Request"
            delete_session_request_retransmit:
                description:
                - "Retransmitted Delete Session Request"
            create_session_response:
                description:
                - "Create Session Response"
            invalid_key:
                description:
                - "Invalid TEID Field"
            path_management_message:
                description:
                - "Path Management Message"
            delete_pdp_context_response_v1:
                description:
                - "GTP v1 Delete Context PDP Response"
            delete_pdp_context_response_v0:
                description:
                - "GTP v0 Delete Context PDP Response"
            delete_session_request:
                description:
                - "Delete Session Request"
            invalid_tid_drop_v0:
                description:
                - "GTP v0 Invalid tid drop"
            create_pdp_context_response_v0:
                description:
                - "GTP v0 Create PDP Context Response"
            create_pdp_context_response_v1:
                description:
                - "GTP v1 Create PDP Context Response"
    uuid:
        description:
        - "uuid of the object"
        required: False
    gtp_value:
        description:
        - "'enable'= Enable GTP Inspection;"
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
    "gtp_value",
    "sampling_enable",
    "stats",
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
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'create-session-request', 'create-session-response',
                    'path-management-message', 'delete-session-request',
                    'delete-session-response', 'reserved-field-set-drop',
                    'tunnel-id-flag-drop', 'message-filtering-drop',
                    'reserved-information-element-drop',
                    'mandatory-information-element-drop', 'filter-list-drop',
                    'invalid-teid-drop', 'out-of-state-drop',
                    'message-length-drop', 'unsupported-message-type-v2',
                    'fast-conn-setup', 'out-of-session-memory', 'no-fwd-route',
                    'no-rev-route', 'invalid-key',
                    'create-session-request-retransmit',
                    'delete-session-request-retransmit',
                    'response-cause-not-accepted', 'invalid-imsi-len-drop',
                    'invalid-apn-len-drop', 'create-pdp-context-request-v1',
                    'create-pdp-context-response-v1',
                    'path-management-message-v1', 'reserved-field-set-drop-v1',
                    'message-filtering-drop-v1',
                    'reserved-information-element-drop-v1',
                    'mandatory-information-element-drop-v1',
                    'filter-list-drop-v1', 'invalid-teid-drop-v1',
                    'message-length-drop-v1', 'version-not-supported',
                    'unsupported-message-type-v1',
                    'delete-pdp-context-request-v1',
                    'delete-pdp-context-response-v1',
                    'create-pdp-context-request-v0',
                    'create-pdp-context-response-v0',
                    'delete-pdp-context-request-v0',
                    'delete-pdp-context-response-v0',
                    'path-management-message-v0', 'message-filtering-drop-v0',
                    'unsupported-message-type-v0',
                    'invalid-flow-label-drop-v0', 'invalid-tid-drop-v0',
                    'message-length-drop-v0',
                    'mandatory-information-element-drop-v0',
                    'filter-list-drop-v0', 'gtp-in-gtp-drop'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'invalid_apn_len_drop': {
                'type': 'str',
            },
            'reserved_field_set_drop': {
                'type': 'str',
            },
            'message_length_drop': {
                'type': 'str',
            },
            'out_of_session_memory': {
                'type': 'str',
            },
            'reserved_information_element_drop': {
                'type': 'str',
            },
            'path_management_message_v0': {
                'type': 'str',
            },
            'out_of_state_drop': {
                'type': 'str',
            },
            'delete_session_response': {
                'type': 'str',
            },
            'invalid_flow_label_drop_v0': {
                'type': 'str',
            },
            'invalid_imsi_len_drop': {
                'type': 'str',
            },
            'filter_list_drop': {
                'type': 'str',
            },
            'response_cause_not_accepted': {
                'type': 'str',
            },
            'mandatory_information_element_drop': {
                'type': 'str',
            },
            'unsupported_message_type_v0': {
                'type': 'str',
            },
            'unsupported_message_type_v1': {
                'type': 'str',
            },
            'unsupported_message_type_v2': {
                'type': 'str',
            },
            'invalid_teid_drop': {
                'type': 'str',
            },
            'message_filtering_drop': {
                'type': 'str',
            },
            'no_fwd_route': {
                'type': 'str',
            },
            'create_pdp_context_request_v1': {
                'type': 'str',
            },
            'fast_conn_setup': {
                'type': 'str',
            },
            'path_management_message_v1': {
                'type': 'str',
            },
            'create_session_request_retransmit': {
                'type': 'str',
            },
            'create_session_request': {
                'type': 'str',
            },
            'no_rev_route': {
                'type': 'str',
            },
            'gtp_in_gtp_drop': {
                'type': 'str',
            },
            'mandatory_information_element_drop_v1': {
                'type': 'str',
            },
            'mandatory_information_element_drop_v0': {
                'type': 'str',
            },
            'message_filtering_drop_v0': {
                'type': 'str',
            },
            'message_filtering_drop_v1': {
                'type': 'str',
            },
            'reserved_information_element_drop_v1': {
                'type': 'str',
            },
            'version_not_supported': {
                'type': 'str',
            },
            'invalid_teid_drop_v1': {
                'type': 'str',
            },
            'filter_list_drop_v0': {
                'type': 'str',
            },
            'reserved_field_set_drop_v1': {
                'type': 'str',
            },
            'tunnel_id_flag_drop': {
                'type': 'str',
            },
            'filter_list_drop_v1': {
                'type': 'str',
            },
            'create_pdp_context_request_v0': {
                'type': 'str',
            },
            'message_length_drop_v1': {
                'type': 'str',
            },
            'message_length_drop_v0': {
                'type': 'str',
            },
            'delete_pdp_context_request_v0': {
                'type': 'str',
            },
            'delete_pdp_context_request_v1': {
                'type': 'str',
            },
            'delete_session_request_retransmit': {
                'type': 'str',
            },
            'create_session_response': {
                'type': 'str',
            },
            'invalid_key': {
                'type': 'str',
            },
            'path_management_message': {
                'type': 'str',
            },
            'delete_pdp_context_response_v1': {
                'type': 'str',
            },
            'delete_pdp_context_response_v0': {
                'type': 'str',
            },
            'delete_session_request': {
                'type': 'str',
            },
            'invalid_tid_drop_v0': {
                'type': 'str',
            },
            'create_pdp_context_response_v0': {
                'type': 'str',
            },
            'create_pdp_context_response_v1': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        },
        'gtp_value': {
            'type': 'str',
            'choices': ['enable']
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/fw/gtp"

    f_dict = {}

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
    url_base = "/axapi/v3/fw/gtp"

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
        for k, v in payload["gtp"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["gtp"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["gtp"][k] = v
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
    payload = build_json("gtp", module)
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
