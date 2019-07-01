#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_lsn_lid
description:
    - Create an LSN Lid
short_description: Configures A10 cgnv6.lsn-lid
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
    drop_on_nat_pool_mismatch:
        description:
        - "Drop traffic from users if their current NAT pool does not match the lid's (default= off)"
        required: False
    user_quota_prefix_length:
        description:
        - "NAT64/DS-Lite user quota prefix length (Prefix Length (Default= Uses the global NAT64/DS-Lite configured value))"
        required: False
    lid_number:
        description:
        - "LSN Lid"
        required: True
    extended_user_quota:
        description:
        - "Field extended_user_quota"
        required: False
        suboptions:
            udp:
                description:
                - "Field udp"
            tcp:
                description:
                - "Field tcp"
    ds_lite:
        description:
        - "Field ds_lite"
        required: False
        suboptions:
            inside_src_permit_list:
                description:
                - "Class-List of IPv4 addresses permitted (Class-list to match for DS-Lite)"
    user_quota:
        description:
        - "Field user_quota"
        required: False
        suboptions:
            quota_udp:
                description:
                - "Field quota_udp"
            icmp:
                description:
                - "User Quota for ICMP identifiers (NAT port quota per user (default= not configured))"
            session:
                description:
                - "User Quota for number of data sessions"
            quota_tcp:
                description:
                - "Field quota_tcp"
    user_tag:
        description:
        - "Customized tag"
        required: False
    name:
        description:
        - "LSN Lid Name"
        required: False
    respond_to_user_mac:
        description:
        - "Use the user's source MAC for the next hop rather than the routing table (default= off)"
        required: False
    source_nat_pool:
        description:
        - "Field source_nat_pool"
        required: False
        suboptions:
            shared:
                description:
                - "Use a shared source NAT pool or pool-group"
            pool_name:
                description:
                - "Source NAT Pool or Pool-Group"
    conn_rate_limit:
        description:
        - "Field conn_rate_limit"
        required: False
        suboptions:
            conn_rate_limit_val:
                description:
                - "Maximum connections per second (Default= No limit)"
    lsn_rule_list:
        description:
        - "Field lsn_rule_list"
        required: False
        suboptions:
            destination:
                description:
                - "Apply LSN Rule-List on Destination (LSN Rule-List Name)"
    override:
        description:
        - "'none'= Apply source NAT if configured (default); 'drop'= Drop packets that match this LSN lid; 'pass-through'= Layer-3 route packets that match this LSN lid and do not apply source NAT; "
        required: False
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
AVAILABLE_PROPERTIES = ["conn_rate_limit","drop_on_nat_pool_mismatch","ds_lite","extended_user_quota","lid_number","lsn_rule_list","name","override","respond_to_user_mac","source_nat_pool","user_quota","user_quota_prefix_length","user_tag","uuid",]

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
        drop_on_nat_pool_mismatch=dict(type='bool',),
        user_quota_prefix_length=dict(type='int',),
        lid_number=dict(type='int',required=True,),
        extended_user_quota=dict(type='dict',udp=dict(type='list',udp_sessions=dict(type='int',),udp_service_port=dict(type='int',)),tcp=dict(type='list',tcp_service_port=dict(type='int',),tcp_sessions=dict(type='int',))),
        ds_lite=dict(type='dict',inside_src_permit_list=dict(type='str',)),
        user_quota=dict(type='dict',quota_udp=dict(type='dict',udp_reserve=dict(type='int',),udp_quota=dict(type='int',)),icmp=dict(type='int',),session=dict(type='int',),quota_tcp=dict(type='dict',tcp_quota=dict(type='int',),tcp_reserve=dict(type='int',))),
        user_tag=dict(type='str',),
        name=dict(type='str',),
        respond_to_user_mac=dict(type='bool',),
        source_nat_pool=dict(type='dict',shared=dict(type='bool',),pool_name=dict(type='str',)),
        conn_rate_limit=dict(type='dict',conn_rate_limit_val=dict(type='int',)),
        lsn_rule_list=dict(type='dict',destination=dict(type='str',)),
        override=dict(type='str',choices=['none','drop','pass-through']),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/lsn-lid/{lid-number}"

    f_dict = {}
    f_dict["lid-number"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/lsn-lid/{lid-number}"

    f_dict = {}
    f_dict["lid-number"] = module.params["lid_number"]

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
    payload = build_json("lsn-lid", module)
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
    payload = build_json("lsn-lid", module)
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
    payload = build_json("lsn-lid", module)
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