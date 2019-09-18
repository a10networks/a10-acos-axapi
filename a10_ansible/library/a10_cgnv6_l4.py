#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_l4
description:
    - CGNV6 L4 Statistics
short_description: Configures A10 cgnv6.l4
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
                - "'all'= all; 'no-fwd-route'= No Forward Route for Session; 'no-rev-route'= No Reverse Route for Session; 'out-of-session-memory'= Out of Session Memory; 'tcp-rst-sent'= TCP RST Sent; 'ipip-icmp-reply-sent'= IPIP ICMP Echo Reply Sent; 'icmp-filtered-sent'= ICMP Administratively Filtered Sent; 'icmp-host-unreachable-sent'= ICMP Host Unreachable Sent; 'icmp-reply-no-session-drop'= ICMP Reply No Session Drop; 'ipip-truncated'= IPIP Truncated Packet; 'ip-src-invalid-unicast'= IPv4 Source Not Valid Unicast; 'ip-dst-invalid-unicast'= IPv4 Destination Not Valid Unicast; 'ipv6-src-invalid-unicast'= IPv6 Source Not Valid Unicast; 'ipv6-dst-invalid-unicast'= IPv6 Destination Not Valid Unicast; 'bad-l3-protocol'= Bad Layer 3 Protocol; 'special-ipv4-no-route'= Stateless IPv4 No Forward Route; 'special-ipv6-no-route'= Stateless IPv6 No Forward Route; 'icmp-reply-sent'= ICMP Echo Reply Sent; 'icmpv6-reply-sent'= ICMPv6 Echo Reply Sent; 'out-of-state-dropped'= L4 Out of State packets; 'ttl-exceeded-sent'= ICMP TTL Exceeded Sent; 'cross-cpu-alg-gre-no-match'= ALG GRE Cross CPU No Matching Session; 'cross-cpu-alg-gre-preprocess-err'= ALG GRE Cross CPU Preprocess Error; 'lsn-fast-setup'= LSN Fast Setup Attempt; 'lsn-fast-setup-err'= LSN Fast Setup Error; 'nat64-fast-setup'= NAT64 Fast Setup Attempt; 'nat64-fast-setup-err'= NAT64 Fast Setup Error; 'dslite-fast-setup'= DS-Lite Fast Setup Attempt; 'dslite-fast-setup-err'= DS-Lite Fast Setup Error; 'fast-setup-delayed-err'= Fast Setup Delayed Error; 'fast-setup-mtu-too-small'= Fast Setup MTU Too Small; 'fixed-nat44-fast-setup'= Fixed NAT Fast Setup Attempt; 'fixed-nat44-fast-setup-err'= Fixed NAT Fast Setup Error; 'fixed-nat64-fast-setup'= Fixed NAT Fast Setup Attempt; 'fixed-nat64-fast-setup-err'= Fixed NAT Fast Setup Error; 'fixed-nat-dslite-fast-setup'= Fixed NAT Fast Setup Attempt; 'fixed-nat-dslite-fast-setup-err'= Fixed NAT Fast Setup Error; 'fixed-nat-fast-setup-delayed-err'= Fixed NAT Fast Setup Delayed Error; 'fixed-nat-fast-setup-mtu-too-small'= Fixed NAT Fast Setup MTU Too Small; 'static-nat-fast-setup'= Static NAT Fast Setup Attempt; 'static-nat-fast-setup-err'= Static NAT Fast Setup Error; 'dst-nat-needed-drop'= Destination NAT Needed Drop; 'invalid-nat64-translated-addr'= Invalid NAT64 Translated IPv4 Address; 'tcp-rst-loop-drop'= RST Loop Drop; 'static-nat-alloc'= Static NAT Alloc; 'static-nat-free'= Static NAT Free; 'process-l4'= Process L4; 'preprocess-error'= Preprocess Error; 'process-special'= Process Special; 'process-continue'= Process Continue; 'process-error'= Process Error; 'fw-match-no-rule-drop'= Firewall Matched No CGNv6 Rule Drop; 'ip-unknown-process'= Process IP Unknown; 'src-nat-pool-not-found'= Src NAT Pool Not Found; 'dst-nat-pool-not-found'= Dst NAT Pool Not Found; 'l3-ip-src-invalid-unicast'= IPv4 L3 Source Invalid Unicast; 'l3-ip-dst-invalid-unicast'= IPv4 L3 Destination Invalid Unicast; 'l3-ipv6-src-invalid-unicast'= IPv6 L3 Source Invalid Unicast; 'l3-ipv6-dst-invalid-unicast'= IPv6 L3 Destination Invalid Unicast; 'fw-zone-mismatch-rerouting-drop'= Rerouting Zone Mismatch Drop; 'nat-range-list-acl-deny'= Nat range-list ACL deny; 'nat-range-list-acl-permit'= Nat range-list ACL permit; 'fw-next-action-incorrect-drop'= FW Next Action Incorrect Drop; "
    uuid:
        description:
        - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["sampling_enable","uuid",]

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
        partition=dict(type='str', required=False),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','no-fwd-route','no-rev-route','out-of-session-memory','tcp-rst-sent','ipip-icmp-reply-sent','icmp-filtered-sent','icmp-host-unreachable-sent','icmp-reply-no-session-drop','ipip-truncated','ip-src-invalid-unicast','ip-dst-invalid-unicast','ipv6-src-invalid-unicast','ipv6-dst-invalid-unicast','bad-l3-protocol','special-ipv4-no-route','special-ipv6-no-route','icmp-reply-sent','icmpv6-reply-sent','out-of-state-dropped','ttl-exceeded-sent','cross-cpu-alg-gre-no-match','cross-cpu-alg-gre-preprocess-err','lsn-fast-setup','lsn-fast-setup-err','nat64-fast-setup','nat64-fast-setup-err','dslite-fast-setup','dslite-fast-setup-err','fast-setup-delayed-err','fast-setup-mtu-too-small','fixed-nat44-fast-setup','fixed-nat44-fast-setup-err','fixed-nat64-fast-setup','fixed-nat64-fast-setup-err','fixed-nat-dslite-fast-setup','fixed-nat-dslite-fast-setup-err','fixed-nat-fast-setup-delayed-err','fixed-nat-fast-setup-mtu-too-small','static-nat-fast-setup','static-nat-fast-setup-err','dst-nat-needed-drop','invalid-nat64-translated-addr','tcp-rst-loop-drop','static-nat-alloc','static-nat-free','process-l4','preprocess-error','process-special','process-continue','process-error','fw-match-no-rule-drop','ip-unknown-process','src-nat-pool-not-found','dst-nat-pool-not-found','l3-ip-src-invalid-unicast','l3-ip-dst-invalid-unicast','l3-ipv6-src-invalid-unicast','l3-ipv6-dst-invalid-unicast','fw-zone-mismatch-rerouting-drop','nat-range-list-acl-deny','nat-range-list-acl-permit','fw-next-action-incorrect-drop'])),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/l4"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/l4"

    f_dict = {}

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

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

def get_list(module):
    return module.client.get(list_url(module))

def get_oper(module):
    return module.client.get(oper_url(module))

def get_stats(module):
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["l4"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["l4"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["l4"][k] = v
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
    payload = build_json("l4", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    if module.check_mode:
        result["changed"] = True
        return result
    else:
        return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("l4", module)
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
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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