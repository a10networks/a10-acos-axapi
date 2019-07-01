#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_template_policy_class_list_lid
description:
    - Limit ID
short_description: Configures A10 slb.template.policy.class-list.lid
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
    policy_name:
        description:
        - Key to identify parent object
    request_rate_limit:
        description:
        - "Request rate limit (Specify request rate limit)"
        required: False
    action_value:
        description:
        - "'forward'= Forward the traffic even it exceeds limit; 'reset'= Reset the connection when it exceeds limit; "
        required: False
    request_per:
        description:
        - "Per (Specify interval in number of 100ms)"
        required: False
    bw_rate_limit:
        description:
        - "Specify bandwidth rate limit (Bandwidth rate limit in bytes)"
        required: False
    conn_limit:
        description:
        - "Connection limit"
        required: False
    log:
        description:
        - "Log a message"
        required: False
    direct_action_value:
        description:
        - "'drop'= drop the packet; 'reset'= Send reset back; "
        required: False
    conn_per:
        description:
        - "Per (Specify interval in number of 100ms)"
        required: False
    direct_fail:
        description:
        - "Only log unsuccessful connections"
        required: False
    conn_rate_limit:
        description:
        - "Specify connection rate limit"
        required: False
    direct_pbslb_logging:
        description:
        - "Configure PBSLB logging"
        required: False
    dns64:
        description:
        - "Field dns64"
        required: False
        suboptions:
            prefix:
                description:
                - "IPv6 prefix"
            exclusive_answer:
                description:
                - "Exclusive Answer in DNS Response"
            disable:
                description:
                - "Disable"
    lidnum:
        description:
        - "Specify a limit ID"
        required: True
    over_limit_action:
        description:
        - "Set action when exceeds limit"
        required: False
    response_code_rate_limit:
        description:
        - "Field response_code_rate_limit"
        required: False
        suboptions:
            threshold:
                description:
                - "the times of getting the response code"
            code_range_end:
                description:
                - "server response code range end"
            code_range_start:
                description:
                - "server response code range start"
            period:
                description:
                - "seconds"
    direct_service_group:
        description:
        - "Specify a service group (Specify the service group name)"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    request_limit:
        description:
        - "Request limit (Specify request limit)"
        required: False
    direct_action_interval:
        description:
        - "Specify logging interval in minute (default is 3)"
        required: False
    bw_per:
        description:
        - "Per (Specify interval in number of 100ms)"
        required: False
    interval:
        description:
        - "Specify log interval in minutes, by default system will log every over limit instance"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    direct_action:
        description:
        - "Set action when match the lid"
        required: False
    lockout:
        description:
        - "Don't accept any new connection for certain time (Lockout duration in minutes)"
        required: False
    direct_logging_drp_rst:
        description:
        - "Configure PBSLB logging"
        required: False
    direct_pbslb_interval:
        description:
        - "Specify logging interval in minutes(default is 3)"
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
AVAILABLE_PROPERTIES = ["action_value","bw_per","bw_rate_limit","conn_limit","conn_per","conn_rate_limit","direct_action","direct_action_interval","direct_action_value","direct_fail","direct_logging_drp_rst","direct_pbslb_interval","direct_pbslb_logging","direct_service_group","dns64","interval","lidnum","lockout","log","over_limit_action","request_limit","request_per","request_rate_limit","response_code_rate_limit","user_tag","uuid",]

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
        request_rate_limit=dict(type='int',),
        action_value=dict(type='str',choices=['forward','reset']),
        request_per=dict(type='int',),
        bw_rate_limit=dict(type='int',),
        conn_limit=dict(type='int',),
        log=dict(type='bool',),
        direct_action_value=dict(type='str',choices=['drop','reset']),
        conn_per=dict(type='int',),
        direct_fail=dict(type='bool',),
        conn_rate_limit=dict(type='int',),
        direct_pbslb_logging=dict(type='bool',),
        dns64=dict(type='dict',prefix=dict(type='str',),exclusive_answer=dict(type='bool',),disable=dict(type='bool',)),
        lidnum=dict(type='int',required=True,),
        over_limit_action=dict(type='bool',),
        response_code_rate_limit=dict(type='list',threshold=dict(type='int',),code_range_end=dict(type='int',),code_range_start=dict(type='int',),period=dict(type='int',)),
        direct_service_group=dict(type='str',),
        uuid=dict(type='str',),
        request_limit=dict(type='int',),
        direct_action_interval=dict(type='int',),
        bw_per=dict(type='int',),
        interval=dict(type='int',),
        user_tag=dict(type='str',),
        direct_action=dict(type='bool',),
        lockout=dict(type='int',),
        direct_logging_drp_rst=dict(type='bool',),
        direct_pbslb_interval=dict(type='int',)
    ))
   
    # Parent keys
    rv.update(dict(
        policy_name=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/policy/{policy_name}/class-list/lid/{lidnum}"

    f_dict = {}
    f_dict["lidnum"] = ""
    f_dict["policy_name"] = module.params["policy_name"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/policy/{policy_name}/class-list/lid/{lidnum}"

    f_dict = {}
    f_dict["lidnum"] = module.params["lidnum"]
    f_dict["policy_name"] = module.params["policy_name"]

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
    payload = build_json("lid", module)
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
    payload = build_json("lid", module)
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
    payload = build_json("lid", module)
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