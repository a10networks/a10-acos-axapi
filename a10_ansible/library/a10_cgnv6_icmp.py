#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_icmp
description:
    - CGNV6 ICMP Statistics
short_description: Configures A10 cgnv6.icmp
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
                - "'all'= all; 'icmp-unknown-type'= ICMP Unknown Type; 'icmp-no-port-info'= ICMP Port Info Not Included; 'icmp-no-session-drop'= ICMP No Matching Session Drop; 'icmpv6-unknown-type'= ICMPv6 Unknown Type; 'icmpv6-no-port-info'= ICMPv6 Port Info Not Included; 'icmpv6-no-session-drop'= ICMPv6 No Matching Session Drop; 'icmp-to-icmp'= ICMP to ICMP Conversion; 'icmp-to-icmpv6'= ICMP to ICMPv6 Conversion; 'icmpv6-to-icmp'= ICMPv6 to ICMP Conversion; 'icmpv6-to-icmpv6'= ICMPv6 to ICMPv6 Conversion; 'icmp-bad-type'= Bad Embedded ICMP Type; 'icmpv6-bad-type'= Bad Embedded ICMPv6 Type; '64-known-drop'= NAT64 Forward Known ICMPv6 Drop; '64-unknown-drop'= NAT64 Forward Unknown ICMPv6 Drop; '64-midpoint-hop'= NAT64 Forward Unknown Source Drop; '46-known-drop'= NAT64 Reverse Known ICMP Drop; '46-unknown-drop'= NAT64 Reverse Known ICMPv6 Drop; '46-no-prefix-for-ipv4'= NAT64 Reverse No Prefix Match for IPv4; '46-bad-encap-ip-header-len'= 4to6 Bad Encapsulated IP Header Length; 'icmp-to-icmp-err'= ICMP to ICMP Conversion Error; 'icmp-to-icmpv6-err'= ICMP to ICMPv6 Conversion Error; 'icmpv6-to-icmp-err'= ICMPv6 to ICMP Conversion Error; 'icmpv6-to-icmpv6-err'= ICMPv6 to ICMPv6 Conversion Error; 'encap-cross-cpu-no-match'= ICMP Embedded Cross CPU No Matching Session; 'encap-cross-cpu-preprocess-err'= ICMP Embedded Cross CPU Preprocess Error; 'icmp-to-icmp-unknown-l4'= ICMP Embedded Unknown L4 Protocol; 'icmp-to-icmpv6-unknown-l4'= ICMP to ICMPv6 Embedded Unknown L4 Protocol; 'icmpv6-to-icmp-unknown-l4'= ICMPv6 to ICMP Embedded Unknown L4 Protocol; 'icmpv6-to-icmpv6-unknown-l4'= ICMPv6 to ICMPv6 Embedded Unknown L4 Protocol; 'static-nat'= ICMP Static NAT; 'echo-to-pool-reply'= Ping to Pool Reply; 'echo-to-pool-drop'= Ping to Pool Drop; 'error-to-pool-drop'= Error to Pool Drop; 'echo-to-pool-reply-v6'= Ping6 to Pool Reply; 'echo-to-pool-drop-v6'= Ping6 to Pool Drop; 'error-to-pool-drop-v6'= Error to IPv6 Pool Drop; "
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
        get_type=dict(type='str', choices=["single", "list"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','icmp-unknown-type','icmp-no-port-info','icmp-no-session-drop','icmpv6-unknown-type','icmpv6-no-port-info','icmpv6-no-session-drop','icmp-to-icmp','icmp-to-icmpv6','icmpv6-to-icmp','icmpv6-to-icmpv6','icmp-bad-type','icmpv6-bad-type','64-known-drop','64-unknown-drop','64-midpoint-hop','46-known-drop','46-unknown-drop','46-no-prefix-for-ipv4','46-bad-encap-ip-header-len','icmp-to-icmp-err','icmp-to-icmpv6-err','icmpv6-to-icmp-err','icmpv6-to-icmpv6-err','encap-cross-cpu-no-match','encap-cross-cpu-preprocess-err','icmp-to-icmp-unknown-l4','icmp-to-icmpv6-unknown-l4','icmpv6-to-icmp-unknown-l4','icmpv6-to-icmpv6-unknown-l4','static-nat','echo-to-pool-reply','echo-to-pool-drop','error-to-pool-drop','echo-to-pool-reply-v6','echo-to-pool-drop-v6','error-to-pool-drop-v6'])),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/icmp"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/icmp"

    f_dict = {}

    return url_base.format(**f_dict)

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
    present_keys = sorted([x for x in requires_one_of if x in params])
    
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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("icmp", module)
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
    payload = build_json("icmp", module)
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
    payload = build_json("icmp", module)
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
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
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