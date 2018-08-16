#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_access_list_extended
description:
    - None
short_description: Configures A10 access-list.extended
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
    rules:
        description:
        - "Field rules"
        required: False
        suboptions:
            icmp_type:
                description:
                - "None"
            ip:
                description:
                - "None"
            service_obj_group:
                description:
                - "None"
            udp:
                description:
                - "None"
            tcp:
                description:
                - "None"
            src_range:
                description:
                - "None"
            any_code:
                description:
                - "None"
            src_lt:
                description:
                - "None"
            src_mask:
                description:
                - "None"
            src_port_end:
                description:
                - "None"
            dst_port_end:
                description:
                - "None"
            dst_range:
                description:
                - "None"
            established:
                description:
                - "None"
            src_subnet:
                description:
                - "None"
            extd_action:
                description:
                - "None"
            src_any:
                description:
                - "None"
            fragments:
                description:
                - "None"
            icmp_code:
                description:
                - "None"
            src_object_group:
                description:
                - "None"
            dst_eq:
                description:
                - "None"
            dst_subnet:
                description:
                - "None"
            dst_mask:
                description:
                - "None"
            extd_remark:
                description:
                - "None"
            vlan:
                description:
                - "None"
            dscp:
                description:
                - "None"
            special_code:
                description:
                - "None"
            trunk:
                description:
                - "None"
            icmp:
                description:
                - "None"
            dst_gt:
                description:
                - "None"
            acl_log:
                description:
                - "None"
            src_gt:
                description:
                - "None"
            dst_object_group:
                description:
                - "None"
            any_type:
                description:
                - "None"
            transparent_session_only:
                description:
                - "None"
            dst_any:
                description:
                - "None"
            src_host:
                description:
                - "None"
            dst_lt:
                description:
                - "None"
            ethernet:
                description:
                - "None"
            special_type:
                description:
                - "None"
            src_eq:
                description:
                - "None"
            dst_host:
                description:
                - "None"
            extd_seq_num:
                description:
                - "None"
    extd:
        description:
        - "None"
        required: True
    uuid:
        description:
        - "None"
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
AVAILABLE_PROPERTIES = ["extd","rules","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        rules=dict(type='list',icmp_type=dict(type='int',),ip=dict(type='bool',),service_obj_group=dict(type='str',),udp=dict(type='bool',),tcp=dict(type='bool',),src_range=dict(type='int',),any_code=dict(type='bool',),src_lt=dict(type='int',),src_mask=dict(type='str',),src_port_end=dict(type='int',),dst_port_end=dict(type='int',),dst_range=dict(type='int',),established=dict(type='bool',),src_subnet=dict(type='str',),extd_action=dict(type='str',choices=['deny','permit','l3-vlan-fwd-disable']),src_any=dict(type='bool',),fragments=dict(type='bool',),icmp_code=dict(type='int',),src_object_group=dict(type='str',),dst_eq=dict(type='int',),dst_subnet=dict(type='str',),dst_mask=dict(type='str',),extd_remark=dict(type='str',),vlan=dict(type='int',),dscp=dict(type='int',),special_code=dict(type='str',choices=['frag-required','host-unreachable','network-unreachable','port-unreachable','proto-unreachable','route-failed']),trunk=dict(type='str',),icmp=dict(type='bool',),dst_gt=dict(type='int',),acl_log=dict(type='bool',),src_gt=dict(type='int',),dst_object_group=dict(type='str',),any_type=dict(type='bool',),transparent_session_only=dict(type='bool',),dst_any=dict(type='bool',),src_host=dict(type='str',),dst_lt=dict(type='int',),ethernet=dict(type='str',),special_type=dict(type='str',choices=['echo-reply','echo-request','info-reply','info-request','mask-reply','mask-request','parameter-problem','redirect','source-quench','time-exceeded','timestamp','timestamp-reply','dest-unreachable']),src_eq=dict(type='int',),dst_host=dict(type='str',),extd_seq_num=dict(type='int',)),
        extd=dict(type='int',required=True,),
        uuid=dict(type='str',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/access-list/extended/{extd}"
    f_dict = {}
    f_dict["extd"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/access-list/extended/{extd}"
    f_dict = {}
    f_dict["extd"] = module.params["extd"]

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
        if isinstance(v, list):
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
            if isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if params.get(x)])
    
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
    payload = build_json("extended", module)
    try:
        post_result = module.client.post(new_url(module), payload)
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
    payload = build_json("extended", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
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
    # TODO(remove hardcoded port #)
    a10_port = 443
    a10_protocol = "https"

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
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