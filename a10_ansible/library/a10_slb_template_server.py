#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_template_server
description:
    - None
short_description: Configures A10 slb.template.server
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
    health_check_disable:
        description:
        - "None"
        required: False
    stats_data_action:
        description:
        - "None"
        required: False
    slow_start:
        description:
        - "None"
        required: False
    weight:
        description:
        - "None"
        required: False
    bw_rate_limit:
        description:
        - "None"
        required: False
    spoofing_cache:
        description:
        - "None"
        required: False
    conn_limit:
        description:
        - "None"
        required: False
    uuid:
        description:
        - "None"
        required: False
    resume:
        description:
        - "None"
        required: False
    max_dynamic_server:
        description:
        - "None"
        required: False
    rate_interval:
        description:
        - "None"
        required: False
    till:
        description:
        - "None"
        required: False
    add:
        description:
        - "None"
        required: False
    min_ttl_ratio:
        description:
        - "None"
        required: False
    bw_rate_limit_no_logging:
        description:
        - "None"
        required: False
    dynamic_server_prefix:
        description:
        - "None"
        required: False
    initial_slow_start:
        description:
        - "None"
        required: False
    every:
        description:
        - "None"
        required: False
    conn_limit_no_logging:
        description:
        - "None"
        required: False
    extended_stats:
        description:
        - "None"
        required: False
    conn_rate_limit_no_logging:
        description:
        - "None"
        required: False
    name:
        description:
        - "None"
        required: True
    bw_rate_limit_duration:
        description:
        - "None"
        required: False
    bw_rate_limit_resume:
        description:
        - "None"
        required: False
    bw_rate_limit_acct:
        description:
        - "None"
        required: False
    user_tag:
        description:
        - "None"
        required: False
    times:
        description:
        - "None"
        required: False
    log_selection_failure:
        description:
        - "None"
        required: False
    conn_rate_limit:
        description:
        - "None"
        required: False
    dns_query_interval:
        description:
        - "None"
        required: False
    health_check:
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
AVAILABLE_PROPERTIES = ["add","bw_rate_limit","bw_rate_limit_acct","bw_rate_limit_duration","bw_rate_limit_no_logging","bw_rate_limit_resume","conn_limit","conn_limit_no_logging","conn_rate_limit","conn_rate_limit_no_logging","dns_query_interval","dynamic_server_prefix","every","extended_stats","health_check","health_check_disable","initial_slow_start","log_selection_failure","max_dynamic_server","min_ttl_ratio","name","rate_interval","resume","slow_start","spoofing_cache","stats_data_action","till","times","user_tag","uuid","weight",]

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
        health_check_disable=dict(type='bool',),
        stats_data_action=dict(type='str',choices=['stats-data-enable','stats-data-disable']),
        slow_start=dict(type='bool',),
        weight=dict(type='int',),
        bw_rate_limit=dict(type='int',),
        spoofing_cache=dict(type='bool',),
        conn_limit=dict(type='int',),
        uuid=dict(type='str',),
        resume=dict(type='int',),
        max_dynamic_server=dict(type='int',),
        rate_interval=dict(type='str',choices=['100ms','second']),
        till=dict(type='int',),
        add=dict(type='int',),
        min_ttl_ratio=dict(type='int',),
        bw_rate_limit_no_logging=dict(type='bool',),
        dynamic_server_prefix=dict(type='str',),
        initial_slow_start=dict(type='int',),
        every=dict(type='int',),
        conn_limit_no_logging=dict(type='bool',),
        extended_stats=dict(type='bool',),
        conn_rate_limit_no_logging=dict(type='bool',),
        name=dict(type='str',required=True,),
        bw_rate_limit_duration=dict(type='int',),
        bw_rate_limit_resume=dict(type='int',),
        bw_rate_limit_acct=dict(type='str',choices=['to-server-only','from-server-only','all']),
        user_tag=dict(type='str',),
        times=dict(type='int',),
        log_selection_failure=dict(type='bool',),
        conn_rate_limit=dict(type='int',),
        dns_query_interval=dict(type='int',),
        health_check=dict(type='str',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/server/{name}"
    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/server/{name}"
    f_dict = {}
    f_dict["name"] = module.params["name"]

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
    payload = build_json("server", module)
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
    payload = build_json("server", module)
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