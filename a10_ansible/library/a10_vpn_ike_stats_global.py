#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_vpn_ike_stats_global
description:
    - IKE-stats-global statistic
short_description: Configures A10 vpn.ike-stats-global
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
                - "'all'= all; 'v2-init-rekey'= Initiate Rekey; 'v2-rsp-rekey'= Respond Rekey; 'v2-child-sa-rekey'= Child SA Rekey; 'v2-in-invalid'= Incoming Invalid; 'v2-in-invalid-spi'= Incoming Invalid SPI; 'v2-in-init-req'= Incoming Init Request; 'v2-in-init-rsp'= Incoming Init Response; 'v2-out-init-req'= Outgoing Init Request; 'v2-out-init-rsp'= Outgoing Init Response; 'v2-in-auth-req'= Incoming Auth Request; 'v2-in-auth-rsp'= Incoming Auth Response; 'v2-out-auth-req'= Outgoing Auth Request; 'v2-out-auth-rsp'= Outgoing Auth Response; 'v2-in-create-child-req'= Incoming Create Child Request; 'v2-in-create-child-rsp'= Incoming Create Child Response; 'v2-out-create-child-req'= Outgoing Create Child Request; 'v2-out-create-child-rsp'= Outgoing Create Child Response; 'v2-in-info-req'= Incoming Info Request; 'v2-in-info-rsp'= Incoming Info Response; 'v2-out-info-req'= Outgoing Info Request; 'v2-out-info-rsp'= Outgoing Info Response; 'v1-in-id-prot-req'= Incoming ID Protection Request; 'v1-in-id-prot-rsp'= Incoming ID Protection Response; 'v1-out-id-prot-req'= Outgoing ID Protection Request; 'v1-out-id-prot-rsp'= Outgoing ID Protection Response; 'v1-in-auth-only-req'= Incoming Auth Only Request; 'v1-in-auth-only-rsp'= Incoming Auth Only Response; 'v1-out-auth-only-req'= Outgoing Auth Only Request; 'v1-out-auth-only-rsp'= Outgoing Auth Only Response; 'v1-in-aggressive-req'= Incoming Aggressive Request; 'v1-in-aggressive-rsp'= Incoming Aggressive Response; 'v1-out-aggressive-req'= Outgoing Aggressive Request; 'v1-out-aggressive-rsp'= Outgoing Aggressive Response; 'v1-in-info-v1-req'= Incoming Info Request; 'v1-in-info-v1-rsp'= Incoming Info Response; 'v1-out-info-v1-req'= Outgoing Info Request; 'v1-out-info-v1-rsp'= Outgoing Info Response; 'v1-in-transaction-req'= Incoming Transaction Request; 'v1-in-transaction-rsp'= Incoming Transaction Response; 'v1-out-transaction-req'= Outgoing Transaction Request; 'v1-out-transaction-rsp'= Outgoing Transaction Response; 'v1-in-quick-mode-req'= Incoming Quick Mode Request; 'v1-in-quick-mode-rsp'= Incoming Quick Mode Response; 'v1-out-quick-mode-req'= Outgoing Quick Mode Request; 'v1-out-quick-mode-rsp'= Outgoing Quick Mode Response; 'v1-in-new-group-mode-req'= Incoming New Group Mode Request; 'v1-in-new-group-mode-rsp'= Incoming New Group Mode Response; 'v1-out-new-group-mode-req'= Outgoing New Group Mode Request; 'v1-out-new-group-mode-rsp'= Outgoing New Group Mode Response; "
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
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','v2-init-rekey','v2-rsp-rekey','v2-child-sa-rekey','v2-in-invalid','v2-in-invalid-spi','v2-in-init-req','v2-in-init-rsp','v2-out-init-req','v2-out-init-rsp','v2-in-auth-req','v2-in-auth-rsp','v2-out-auth-req','v2-out-auth-rsp','v2-in-create-child-req','v2-in-create-child-rsp','v2-out-create-child-req','v2-out-create-child-rsp','v2-in-info-req','v2-in-info-rsp','v2-out-info-req','v2-out-info-rsp','v1-in-id-prot-req','v1-in-id-prot-rsp','v1-out-id-prot-req','v1-out-id-prot-rsp','v1-in-auth-only-req','v1-in-auth-only-rsp','v1-out-auth-only-req','v1-out-auth-only-rsp','v1-in-aggressive-req','v1-in-aggressive-rsp','v1-out-aggressive-req','v1-out-aggressive-rsp','v1-in-info-v1-req','v1-in-info-v1-rsp','v1-out-info-v1-req','v1-out-info-v1-rsp','v1-in-transaction-req','v1-in-transaction-rsp','v1-out-transaction-req','v1-out-transaction-rsp','v1-in-quick-mode-req','v1-in-quick-mode-rsp','v1-out-quick-mode-req','v1-out-quick-mode-rsp','v1-in-new-group-mode-req','v1-in-new-group-mode-rsp','v1-out-new-group-mode-req','v1-out-new-group-mode-rsp'])),
        uuid=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/vpn/ike-stats-global"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vpn/ike-stats-global"

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
    payload = build_json("ike-stats-global", module)
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
    payload = build_json("ike-stats-global", module)
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
    payload = build_json("ike-stats-global", module)
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