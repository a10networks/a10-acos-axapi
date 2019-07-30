#!/usr/bin/python

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
    partition:
        description:
        - Destination/target partition for object/command
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'packets-rcv'= Packets Received; 'lsn-map-process-success'= PCP MAP Request Processing Success (NAT44); 'dslite-map-process-success'= PCP MAP Request Processing Success (DS-Lite); 'nat64-map-process-success'= PCP MAP Request Processing Success (NAT64); 'lsn-peer-process-success'= PCP PEER Request Processing Success (NAT44); 'dslite-peer-process-success'= PCP PEER Request Processing Success (DS-Lite); 'nat64-peer-process-success'= PCP PEER Request Processing Success (NAT64); 'lsn-announce-process-success'= PCP ANNOUNCE Request Processing Success (NAT44); 'dslite-announce-process-success'= PCP ANNOUNCE Request Processing Success (DS-Lite); 'nat64-announce-process-success'= PCP ANNOUNCE Request Processing Success (NAT64); 'pkt-not-request-drop'= Packet Not a PCP Request; 'pkt-too-short-drop'= Packet Too Short; 'noroute-drop'= Response No Route; 'unsupported-version'= Unsupported PCP version; 'not-authorized'= PCP Request Not Authorized; 'malform-request'= PCP Request Malformed; 'unsupp-opcode'= Unsupported PCP Opcode; 'unsupp-option'= Unsupported PCP Option; 'malform-option'= PCP Option Malformed; 'no-resources'= No System or NAT Resources; 'unsupp-protocol'= Unsupported Mapping Protocol; 'user-quota-exceeded'= User Quota Exceeded; 'cannot-provide-suggest'= Cannot Provide Suggested Port When PREFER_FAILURE; 'address-mismatch'= PCP Client Address Mismatch; 'excessive-remote-peers'= Excessive Remote Peers; 'pkt-not-from-nat-inside'= Packet Dropped For Not Coming From NAT Inside; 'l4-process-error'= L3/L4 Process Error; 'internal-error-drop'= Internal Error; 'unsol_ance_sent_succ'= Unsolicited Announce Sent; 'unsol_ance_sent_fail'= Unsolicited Announce Send Failure; 'ha_sync_epoch_sent'= HA Sync PCP Epoch Sent; 'ha_sync_epoch_rcv'= HA Sync PCP Epoch Recv; 'fullcone-ext-alloc'= PCP Fullcone Extension Alloc; 'fullcone-ext-free'= PCP Fullcone Extension Free; 'fullcone-ext-alloc-failure'= PCP Fullcone Extension Alloc Failure; 'fullcone-ext-notfound'= PCP Fullcone Extension Not Found; 'fullcone-ext-reuse'= PCP Fullcone Extension Reuse; 'client-nonce-mismatch'= PCP Client Nonce Mismatch; 'map-filter-set'= PCP MAP Filter Set; 'map-filter-deny'= PCP MAP Filter Deny Inbound; 'inter-board-pkts'= PCP Inter board packets; "
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
AVAILABLE_PROPERTIES = ["default_template","sampling_enable","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        partition=dict(type='str', required=False)
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','packets-rcv','lsn-map-process-success','dslite-map-process-success','nat64-map-process-success','lsn-peer-process-success','dslite-peer-process-success','nat64-peer-process-success','lsn-announce-process-success','dslite-announce-process-success','nat64-announce-process-success','pkt-not-request-drop','pkt-too-short-drop','noroute-drop','unsupported-version','not-authorized','malform-request','unsupp-opcode','unsupp-option','malform-option','no-resources','unsupp-protocol','user-quota-exceeded','cannot-provide-suggest','address-mismatch','excessive-remote-peers','pkt-not-from-nat-inside','l4-process-error','internal-error-drop','unsol_ance_sent_succ','unsol_ance_sent_fail','ha_sync_epoch_sent','ha_sync_epoch_rcv','fullcone-ext-alloc','fullcone-ext-free','fullcone-ext-alloc-failure','fullcone-ext-notfound','fullcone-ext-reuse','client-nonce-mismatch','map-filter-set','map-filter-deny','inter-board-pkts'])),
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
        if v:
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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("pcp", module)
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.Exists:
        result["changed"] = False
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

def update(module, result, existing_config):
    payload = build_json("pcp", module)
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
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result, existing_config)

def absent(module, result):
    return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("pcp", module)
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
        message=""
    )

    state = module.params["state"]
    a10_host = module.params["a10_host"]
    a10_username = module.params["a10_username"]
    a10_password = module.params["a10_password"]
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]
    
    partition = module.params["partition"]

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
    if partition:
        module.client.activate_partition(partition)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
    return result

def main():
    module = AnsibleModule(argument_spec=get_argspec())
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()