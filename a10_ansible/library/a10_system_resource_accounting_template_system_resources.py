#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_system_resource_accounting_template_system_resources
description:
    - None
short_description: Configures A10 system.resource.accounting.template.system-resources
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
    l4_session_limit_cfg:
        description:
        - "Field l4_session_limit_cfg"
        required: False
        suboptions:
            l4_session_limit_max:
                description:
                - "None"
            l4_session_limit_min_guarantee:
                description:
                - "None"
    l7cps_limit_cfg:
        description:
        - "Field l7cps_limit_cfg"
        required: False
        suboptions:
            l7cps_limit_max:
                description:
                - "None"
    l4cps_limit_cfg:
        description:
        - "Field l4cps_limit_cfg"
        required: False
        suboptions:
            l4cps_limit_max:
                description:
                - "None"
    uuid:
        description:
        - "None"
        required: False
    natcps_limit_cfg:
        description:
        - "Field natcps_limit_cfg"
        required: False
        suboptions:
            natcps_limit_max:
                description:
                - "None"
    sslcps_limit_cfg:
        description:
        - "Field sslcps_limit_cfg"
        required: False
        suboptions:
            sslcps_limit_max:
                description:
                - "None"
    fwcps_limit_cfg:
        description:
        - "Field fwcps_limit_cfg"
        required: False
        suboptions:
            fwcps_limit_max:
                description:
                - "None"
    ssl_throughput_limit_cfg:
        description:
        - "Field ssl_throughput_limit_cfg"
        required: False
        suboptions:
            ssl_throughput_limit_watermark_disable:
                description:
                - "None"
            ssl_throughput_limit_max:
                description:
                - "None"
    threshold:
        description:
        - "None"
        required: False
    bw_limit_cfg:
        description:
        - "Field bw_limit_cfg"
        required: False
        suboptions:
            bw_limit_max:
                description:
                - "None"
            bw_limit_watermark_disable:
                description:
                - "None"
    concurrent_session_limit_cfg:
        description:
        - "Field concurrent_session_limit_cfg"
        required: False
        suboptions:
            concurrent_session_limit_max:
                description:
                - "None"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["bw_limit_cfg","concurrent_session_limit_cfg","fwcps_limit_cfg","l4_session_limit_cfg","l4cps_limit_cfg","l7cps_limit_cfg","natcps_limit_cfg","ssl_throughput_limit_cfg","sslcps_limit_cfg","threshold","uuid",]

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
        l4_session_limit_cfg=dict(type='dict',l4_session_limit_max=dict(type='str',),l4_session_limit_min_guarantee=dict(type='str',)),
        l7cps_limit_cfg=dict(type='dict',l7cps_limit_max=dict(type='int',)),
        l4cps_limit_cfg=dict(type='dict',l4cps_limit_max=dict(type='int',)),
        uuid=dict(type='str',),
        natcps_limit_cfg=dict(type='dict',natcps_limit_max=dict(type='int',)),
        sslcps_limit_cfg=dict(type='dict',sslcps_limit_max=dict(type='int',)),
        fwcps_limit_cfg=dict(type='dict',fwcps_limit_max=dict(type='int',)),
        ssl_throughput_limit_cfg=dict(type='dict',ssl_throughput_limit_watermark_disable=dict(type='bool',),ssl_throughput_limit_max=dict(type='int',)),
        threshold=dict(type='int',),
        bw_limit_cfg=dict(type='dict',bw_limit_max=dict(type='int',),bw_limit_watermark_disable=dict(type='bool',)),
        concurrent_session_limit_cfg=dict(type='dict',concurrent_session_limit_max=dict(type='int',))
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/system/resource-accounting/template/{name}/system-resources"
    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/system/resource-accounting/template/{name}/system-resources"
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
    payload = build_json("system-resources", module)
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
    payload = build_json("system-resources", module)
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