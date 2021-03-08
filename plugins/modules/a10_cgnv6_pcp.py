#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2021 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_cgnv6_pcp
description:
    - Set Port Control Protocol parameters
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
    default_template:
        description:
        - "Bind the default template for PCP (Bind a PCP template)"
        type: str
        required: False
    uuid:
        description:
        - "uuid of the object"
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
                - "'all'= all; 'packets-rcv'= Packets Received; 'lsn-map-process-success'= PCP MAP
          Request Processing Success (NAT44); 'dslite-map-process-success'= PCP MAP
          Request Processing Success (DS-Lite); 'nat64-map-process-success'= PCP MAP
          Request Processing Success (NAT64); 'lsn-peer-process-success'= PCP PEER
          Request Processing Success (NAT44); 'dslite-peer-process-success'= PCP PEER
          Request Processing Success (DS-Lite); 'nat64-peer-process-success'= PCP PEER
          Request Processing Success (NAT64); 'lsn-announce-process-success'= PCP
          ANNOUNCE Request Processing Success (NAT44); 'dslite-announce-process-success'=
          PCP ANNOUNCE Request Processing Success (DS-Lite); 'nat64-announce-process-
          success'= PCP ANNOUNCE Request Processing Success (NAT64); 'pkt-not-request-
          drop'= Packet Not a PCP Request; 'pkt-too-short-drop'= Packet Too Short;
          'noroute-drop'= Response No Route; 'unsupported-version'= Unsupported PCP
          version; 'not-authorized'= PCP Request Not Authorized; 'malform-request'= PCP
          Request Malformed; 'unsupp-opcode'= Unsupported PCP Opcode; 'unsupp-option'=
          Unsupported PCP Option; 'malform-option'= PCP Option Malformed; 'no-resources'=
          No System or NAT Resources; 'unsupp-protocol'= Unsupported Mapping Protocol;
          'user-quota-exceeded'= User Quota Exceeded; 'cannot-provide-suggest'= Cannot
          Provide Suggested Port When PREFER_FAILURE; 'address-mismatch'= PCP Client
          Address Mismatch; 'excessive-remote-peers'= Excessive Remote Peers; 'pkt-not-
          from-nat-inside'= Packet Dropped For Not Coming From NAT Inside; 'l4-process-
          error'= L3/L4 Process Error; 'internal-error-drop'= Internal Error;
          'unsol_ance_sent_succ'= Unsolicited Announce Sent; 'unsol_ance_sent_fail'=
          Unsolicited Announce Send Failure; 'ha_sync_epoch_sent'= HA Sync PCP Epoch
          Sent; 'ha_sync_epoch_rcv'= HA Sync PCP Epoch Recv; 'fullcone-ext-alloc'= PCP
          Fullcone Extension Alloc; 'fullcone-ext-free'= PCP Fullcone Extension Free;
          'fullcone-ext-alloc-failure'= PCP Fullcone Extension Alloc Failure; 'fullcone-
          ext-notfound'= PCP Fullcone Extension Not Found; 'fullcone-ext-reuse'= PCP
          Fullcone Extension Reuse; 'client-nonce-mismatch'= PCP Client Nonce Mismatch;
          'map-filter-set'= PCP MAP Filter Set; 'map-filter-deny'= PCP MAP Filter Deny
          Inbound; 'inter-board-pkts'= PCP Inter board packets;"
                type: str
    stats:
        description:
        - "Field stats"
        type: dict
        required: False
        suboptions:
            packets_rcv:
                description:
                - "Packets Received"
                type: str
            lsn_map_process_success:
                description:
                - "PCP MAP Request Processing Success (NAT44)"
                type: str
            dslite_map_process_success:
                description:
                - "PCP MAP Request Processing Success (DS-Lite)"
                type: str
            nat64_map_process_success:
                description:
                - "PCP MAP Request Processing Success (NAT64)"
                type: str
            lsn_peer_process_success:
                description:
                - "PCP PEER Request Processing Success (NAT44)"
                type: str
            dslite_peer_process_success:
                description:
                - "PCP PEER Request Processing Success (DS-Lite)"
                type: str
            nat64_peer_process_success:
                description:
                - "PCP PEER Request Processing Success (NAT64)"
                type: str
            lsn_announce_process_success:
                description:
                - "PCP ANNOUNCE Request Processing Success (NAT44)"
                type: str
            dslite_announce_process_success:
                description:
                - "PCP ANNOUNCE Request Processing Success (DS-Lite)"
                type: str
            nat64_announce_process_success:
                description:
                - "PCP ANNOUNCE Request Processing Success (NAT64)"
                type: str
            pkt_not_request_drop:
                description:
                - "Packet Not a PCP Request"
                type: str
            pkt_too_short_drop:
                description:
                - "Packet Too Short"
                type: str
            noroute_drop:
                description:
                - "Response No Route"
                type: str
            unsupported_version:
                description:
                - "Unsupported PCP version"
                type: str
            not_authorized:
                description:
                - "PCP Request Not Authorized"
                type: str
            malform_request:
                description:
                - "PCP Request Malformed"
                type: str
            unsupp_opcode:
                description:
                - "Unsupported PCP Opcode"
                type: str
            unsupp_option:
                description:
                - "Unsupported PCP Option"
                type: str
            malform_option:
                description:
                - "PCP Option Malformed"
                type: str
            no_resources:
                description:
                - "No System or NAT Resources"
                type: str
            unsupp_protocol:
                description:
                - "Unsupported Mapping Protocol"
                type: str
            user_quota_exceeded:
                description:
                - "User Quota Exceeded"
                type: str
            cannot_provide_suggest:
                description:
                - "Cannot Provide Suggested Port When PREFER_FAILURE"
                type: str
            address_mismatch:
                description:
                - "PCP Client Address Mismatch"
                type: str
            excessive_remote_peers:
                description:
                - "Excessive Remote Peers"
                type: str
            pkt_not_from_nat_inside:
                description:
                - "Packet Dropped For Not Coming From NAT Inside"
                type: str
            l4_process_error:
                description:
                - "L3/L4 Process Error"
                type: str
            internal_error_drop:
                description:
                - "Internal Error"
                type: str
            unsol_ance_sent_succ:
                description:
                - "Unsolicited Announce Sent"
                type: str
            unsol_ance_sent_fail:
                description:
                - "Unsolicited Announce Send Failure"
                type: str
            ha_sync_epoch_sent:
                description:
                - "HA Sync PCP Epoch Sent"
                type: str
            ha_sync_epoch_rcv:
                description:
                - "HA Sync PCP Epoch Recv"
                type: str

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
    "default_template",
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
        'default_template': {
            'type': 'str',
        },
        'uuid': {
            'type': 'str',
        },
        'sampling_enable': {
            'type': 'list',
            'counters1': {
                'type':
                'str',
                'choices': [
                    'all', 'packets-rcv', 'lsn-map-process-success',
                    'dslite-map-process-success', 'nat64-map-process-success',
                    'lsn-peer-process-success', 'dslite-peer-process-success',
                    'nat64-peer-process-success',
                    'lsn-announce-process-success',
                    'dslite-announce-process-success',
                    'nat64-announce-process-success', 'pkt-not-request-drop',
                    'pkt-too-short-drop', 'noroute-drop',
                    'unsupported-version', 'not-authorized', 'malform-request',
                    'unsupp-opcode', 'unsupp-option', 'malform-option',
                    'no-resources', 'unsupp-protocol', 'user-quota-exceeded',
                    'cannot-provide-suggest', 'address-mismatch',
                    'excessive-remote-peers', 'pkt-not-from-nat-inside',
                    'l4-process-error', 'internal-error-drop',
                    'unsol_ance_sent_succ', 'unsol_ance_sent_fail',
                    'ha_sync_epoch_sent', 'ha_sync_epoch_rcv',
                    'fullcone-ext-alloc', 'fullcone-ext-free',
                    'fullcone-ext-alloc-failure', 'fullcone-ext-notfound',
                    'fullcone-ext-reuse', 'client-nonce-mismatch',
                    'map-filter-set', 'map-filter-deny', 'inter-board-pkts'
                ]
            }
        },
        'stats': {
            'type': 'dict',
            'packets_rcv': {
                'type': 'str',
            },
            'lsn_map_process_success': {
                'type': 'str',
            },
            'dslite_map_process_success': {
                'type': 'str',
            },
            'nat64_map_process_success': {
                'type': 'str',
            },
            'lsn_peer_process_success': {
                'type': 'str',
            },
            'dslite_peer_process_success': {
                'type': 'str',
            },
            'nat64_peer_process_success': {
                'type': 'str',
            },
            'lsn_announce_process_success': {
                'type': 'str',
            },
            'dslite_announce_process_success': {
                'type': 'str',
            },
            'nat64_announce_process_success': {
                'type': 'str',
            },
            'pkt_not_request_drop': {
                'type': 'str',
            },
            'pkt_too_short_drop': {
                'type': 'str',
            },
            'noroute_drop': {
                'type': 'str',
            },
            'unsupported_version': {
                'type': 'str',
            },
            'not_authorized': {
                'type': 'str',
            },
            'malform_request': {
                'type': 'str',
            },
            'unsupp_opcode': {
                'type': 'str',
            },
            'unsupp_option': {
                'type': 'str',
            },
            'malform_option': {
                'type': 'str',
            },
            'no_resources': {
                'type': 'str',
            },
            'unsupp_protocol': {
                'type': 'str',
            },
            'user_quota_exceeded': {
                'type': 'str',
            },
            'cannot_provide_suggest': {
                'type': 'str',
            },
            'address_mismatch': {
                'type': 'str',
            },
            'excessive_remote_peers': {
                'type': 'str',
            },
            'pkt_not_from_nat_inside': {
                'type': 'str',
            },
            'l4_process_error': {
                'type': 'str',
            },
            'internal_error_drop': {
                'type': 'str',
            },
            'unsol_ance_sent_succ': {
                'type': 'str',
            },
            'unsol_ance_sent_fail': {
                'type': 'str',
            },
            'ha_sync_epoch_sent': {
                'type': 'str',
            },
            'ha_sync_epoch_rcv': {
                'type': 'str',
            }
        }
    })
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/pcp"

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
    url_base = "/axapi/v3/cgnv6/pcp"

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
        for k, v in payload["pcp"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
                break
            else:
                if existing_config["pcp"][k] != v:
                    if result["changed"] is not True:
                        result["changed"] = True
                    existing_config["pcp"][k] = v
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
    payload = build_json("pcp", module)
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
