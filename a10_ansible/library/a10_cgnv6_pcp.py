#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_pcp
description:
    - Set Port Control Protocol parameters
short_description: Configures A10 cgnv6.pcp
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
        - present
        - absent
        required: True
    a10_host:
        description:
        - Host for AXAPI authentication
        required: True
    a10_username:
        description:
        - Username for AXAPI authentication
        required: True
    a10_password:
        description:
        - Password for AXAPI authentication
        required: True
    a10_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_protocol:
        description:
        - Protocol for AXAPI authentication
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
                - "'all'= all; 'packets-rcv'= Packets Received; 'lsn-map-process-success'= PCP MAP Request Processing Success (NAT44); 'dslite-map-process-success'= PCP MAP Request Processing Success (DS-Lite); 'nat64-map-process-success'= PCP MAP Request Processing Success (NAT64); 'lsn-peer-process-success'= PCP PEER Request Processing Success (NAT44); 'dslite-peer-process-success'= PCP PEER Request Processing Success (DS-Lite); 'nat64-peer-process-success'= PCP PEER Request Processing Success (NAT64); 'lsn-announce-process-success'= PCP ANNOUNCE Request Processing Success (NAT44); 'dslite-announce-process-success'= PCP ANNOUNCE Request Processing Success (DS-Lite); 'nat64-announce-process-success'= PCP ANNOUNCE Request Processing Success (NAT64); 'pkt-not-request-drop'= Packet Not a PCP Request; 'pkt-too-short-drop'= Packet Too Short; 'noroute-drop'= Response No Route; 'unsupported-version'= Unsupported PCP version; 'not-authorized'= PCP Request Not Authorized; 'malform-request'= PCP Request Malformed; 'unsupp-opcode'= Unsupported PCP Opcode; 'unsupp-option'= Unsupported PCP Option; 'malform-option'= PCP Option Malformed; 'no-resources'= No System or NAT Resources; 'unsupp-protocol'= Unsupported Mapping Protocol; 'user-quota-exceeded'= User Quota Exceeded; 'cannot-provide-suggest'= Cannot Provide Suggested Port When PREFER_FAILURE; 'address-mismatch'= PCP Client Address Mismatch; 'excessive-remote-peers'= Excessive Remote Peers; 'pkt-not-from-nat-inside'= Packet Dropped For Not Coming From NAT Inside; 'l4-process-error'= L3/L4 Process Error; 'internal-error-drop'= Internal Error; 'unsol_ance_sent_succ'= Unsolicited Announce Sent; 'unsol_ance_sent_fail'= Unsolicited Announce Send Failure; 'ha_sync_epoch_sent'= HA Sync PCP Epoch Sent; 'ha_sync_epoch_rcv'= HA Sync PCP Epoch Recv; 'fullcone-ext-alloc'= PCP Fullcone Extension Alloc; 'fullcone-ext-free'= PCP Fullcone Extension Free; 'fullcone-ext-alloc-failure'= PCP Fullcone Extension Alloc Failure; 'fullcone-ext-notfound'= PCP Fullcone Extension Not Found; 'fullcone-ext-reuse'= PCP Fullcone Extension Reuse; 'client-nonce-mismatch'= PCP Client Nonce Mismatch; 'map-filter-set'= PCP MAP Filter Set; 'map-filter-deny'= PCP MAP Filter Deny Inbound; 'inter-board-pkts'= PCP Inter board packets; "
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            unsol_ance_sent_fail:
                description:
                - "Unsolicited Announce Send Failure"
            unsupp_opcode:
                description:
                - "Unsupported PCP Opcode"
            malform_request:
                description:
                - "PCP Request Malformed"
            unsupp_option:
                description:
                - "Unsupported PCP Option"
            unsupported_version:
                description:
                - "Unsupported PCP version"
            l4_process_error:
                description:
                - "L3/L4 Process Error"
            nat64_map_process_success:
                description:
                - "PCP MAP Request Processing Success (NAT64)"
            dslite_announce_process_success:
                description:
                - "PCP ANNOUNCE Request Processing Success (DS-Lite)"
            not_authorized:
                description:
                - "PCP Request Not Authorized"
            ha_sync_epoch_sent:
                description:
                - "HA Sync PCP Epoch Sent"
            nat64_announce_process_success:
                description:
                - "PCP ANNOUNCE Request Processing Success (NAT64)"
            pkt_not_from_nat_inside:
                description:
                - "Packet Dropped For Not Coming From NAT Inside"
            user_quota_exceeded:
                description:
                - "User Quota Exceeded"
            dslite_map_process_success:
                description:
                - "PCP MAP Request Processing Success (DS-Lite)"
            packets_rcv:
                description:
                - "Packets Received"
            lsn_announce_process_success:
                description:
                - "PCP ANNOUNCE Request Processing Success (NAT44)"
            cannot_provide_suggest:
                description:
                - "Cannot Provide Suggested Port When PREFER_FAILURE"
            internal_error_drop:
                description:
                - "Internal Error"
            dslite_peer_process_success:
                description:
                - "PCP PEER Request Processing Success (DS-Lite)"
            malform_option:
                description:
                - "PCP Option Malformed"
            excessive_remote_peers:
                description:
                - "Excessive Remote Peers"
            lsn_map_process_success:
                description:
                - "PCP MAP Request Processing Success (NAT44)"
            address_mismatch:
                description:
                - "PCP Client Address Mismatch"
            unsupp_protocol:
                description:
                - "Unsupported Mapping Protocol"
            ha_sync_epoch_rcv:
                description:
                - "HA Sync PCP Epoch Recv"
            unsol_ance_sent_succ:
                description:
                - "Unsolicited Announce Sent"
            pkt_not_request_drop:
                description:
                - "Packet Not a PCP Request"
            no_resources:
                description:
                - "No System or NAT Resources"
            noroute_drop:
                description:
                - "Response No Route"
            lsn_peer_process_success:
                description:
                - "PCP PEER Request Processing Success (NAT44)"
            nat64_peer_process_success:
                description:
                - "PCP PEER Request Processing Success (NAT64)"
            pkt_too_short_drop:
                description:
                - "Packet Too Short"
    uuid:
        description:
        - "uuid of the object"
        required: False
    default_template:
        description:
        - "Bind the default template for PCP (Bind a PCP template)"
        required: False


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["default_template","sampling_enable","stats","uuid",]

# our imports go at the top so we fail fast.
try:
    from a10_ansible import errors as a10_ex
    from a10_ansible.axapi_http import client_factory, session_factory
    from a10_ansible.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=["present", "absent", "noop"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','packets-rcv','lsn-map-process-success','dslite-map-process-success','nat64-map-process-success','lsn-peer-process-success','dslite-peer-process-success','nat64-peer-process-success','lsn-announce-process-success','dslite-announce-process-success','nat64-announce-process-success','pkt-not-request-drop','pkt-too-short-drop','noroute-drop','unsupported-version','not-authorized','malform-request','unsupp-opcode','unsupp-option','malform-option','no-resources','unsupp-protocol','user-quota-exceeded','cannot-provide-suggest','address-mismatch','excessive-remote-peers','pkt-not-from-nat-inside','l4-process-error','internal-error-drop','unsol_ance_sent_succ','unsol_ance_sent_fail','ha_sync_epoch_sent','ha_sync_epoch_rcv','fullcone-ext-alloc','fullcone-ext-free','fullcone-ext-alloc-failure','fullcone-ext-notfound','fullcone-ext-reuse','client-nonce-mismatch','map-filter-set','map-filter-deny','inter-board-pkts'])),
        stats=dict(type='dict',unsol_ance_sent_fail=dict(type='str',),unsupp_opcode=dict(type='str',),malform_request=dict(type='str',),unsupp_option=dict(type='str',),unsupported_version=dict(type='str',),l4_process_error=dict(type='str',),nat64_map_process_success=dict(type='str',),dslite_announce_process_success=dict(type='str',),not_authorized=dict(type='str',),ha_sync_epoch_sent=dict(type='str',),nat64_announce_process_success=dict(type='str',),pkt_not_from_nat_inside=dict(type='str',),user_quota_exceeded=dict(type='str',),dslite_map_process_success=dict(type='str',),packets_rcv=dict(type='str',),lsn_announce_process_success=dict(type='str',),cannot_provide_suggest=dict(type='str',),internal_error_drop=dict(type='str',),dslite_peer_process_success=dict(type='str',),malform_option=dict(type='str',),excessive_remote_peers=dict(type='str',),lsn_map_process_success=dict(type='str',),address_mismatch=dict(type='str',),unsupp_protocol=dict(type='str',),ha_sync_epoch_rcv=dict(type='str',),unsol_ance_sent_succ=dict(type='str',),pkt_not_request_drop=dict(type='str',),no_resources=dict(type='str',),noroute_drop=dict(type='str',),lsn_peer_process_success=dict(type='str',),nat64_peer_process_success=dict(type='str',),pkt_too_short_drop=dict(type='str',)),
        uuid=dict(type='str',),
        default_template=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/pcp"

    f_dict = {}

    return url_base.format(**f_dict)

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

def build_envelope(title, data):
    return {
        title: data
    }

def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")

def _build_dict_from_param(param):
    rv = {}

    for k,v in param.items():
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

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params and params.get(x) is not None])
    
    errors = []
    marg = []
    
    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc,msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc,msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc,msg = REQUIRED_VALID
    
    if not rc:
        errors.append(msg.format(", ".join(marg)))
    
    return rc,errors

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k,v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module),
                                 params=query_params)
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

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
                    if result["changed"] != True:
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

    result = dict(
        changed=False,
        original_message="",
        message="",
        result={}
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    
    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
    elif state == 'absent':
        result = absent(module, result, existing_config)
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()