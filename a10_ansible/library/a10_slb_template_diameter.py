#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_template_diameter
description:
    - diameter template
short_description: Configures A10 slb.template.diameter
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
    avp_string:
        description:
        - "pattern to be matched in the avp string name, max length 127 bytes"
        required: False
    terminate_on_cca_t:
        description:
        - "remove diameter session when receiving CCA-T message"
        required: False
    message_code_list:
        description:
        - "Field message_code_list"
        required: False
        suboptions:
            message_code:
                description:
                - "Field message_code"
    avp_list:
        description:
        - "Field avp_list"
        required: False
        suboptions:
            int32:
                description:
                - "32 bits integer"
            avp:
                description:
                - "customize avps for cer to the server (avp number)"
            mandatory:
                description:
                - "mandatory avp"
            string:
                description:
                - "String (string name, max length 127 bytes)"
            int64:
                description:
                - "64 bits integer"
    service_group_name:
        description:
        - "service group name, this is the service group that the message needs to be copied to"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    idle_timeout:
        description:
        - "user sesison idle timeout (in minutes, default is 5)"
        required: False
    customize_cea:
        description:
        - "customizing cea response"
        required: False
    product_name:
        description:
        - "product name avp"
        required: False
    dwr_up_retry:
        description:
        - "number of successful dwr health-check before declaring target up"
        required: False
    forward_unknown_session_id:
        description:
        - "Forward server message even it has unknown session id"
        required: False
    avp_code:
        description:
        - "avp code"
        required: False
    vendor_id:
        description:
        - "vendor-id avp (Vendor Id)"
        required: False
    session_age:
        description:
        - "user session age allowed (default 10), this is not idle-time (in minutes)"
        required: False
    load_balance_on_session_id:
        description:
        - "Load balance based on the session id"
        required: False
    name:
        description:
        - "diameter template Name"
        required: True
    dwr_time:
        description:
        - "dwr health-check timer interval (in 100 milli second unit, default is 100, 0 means unset this option)"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    origin_realm:
        description:
        - "origin-realm name avp"
        required: False
    origin_host:
        description:
        - "Field origin_host"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            origin_host_name:
                description:
                - "origin-host name avp"
    multiple_origin_host:
        description:
        - "allowing multiple origin-host to a single server"
        required: False
    forward_to_latest_server:
        description:
        - "Forward client message to the latest server that sends message with the same session id"
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
AVAILABLE_PROPERTIES = ["avp_code","avp_list","avp_string","customize_cea","dwr_time","dwr_up_retry","forward_to_latest_server","forward_unknown_session_id","idle_timeout","load_balance_on_session_id","message_code_list","multiple_origin_host","name","origin_host","origin_realm","product_name","service_group_name","session_age","terminate_on_cca_t","user_tag","uuid","vendor_id",]

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
        get_type=dict(type='str', choices=["single", "list"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        avp_string=dict(type='str',),
        terminate_on_cca_t=dict(type='bool',),
        message_code_list=dict(type='list',message_code=dict(type='int',)),
        avp_list=dict(type='list',int32=dict(type='int',),avp=dict(type='int',),mandatory=dict(type='bool',),string=dict(type='str',),int64=dict(type='int',)),
        service_group_name=dict(type='str',),
        uuid=dict(type='str',),
        idle_timeout=dict(type='int',),
        customize_cea=dict(type='bool',),
        product_name=dict(type='str',),
        dwr_up_retry=dict(type='int',),
        forward_unknown_session_id=dict(type='bool',),
        avp_code=dict(type='int',),
        vendor_id=dict(type='int',),
        session_age=dict(type='int',),
        load_balance_on_session_id=dict(type='bool',),
        name=dict(type='str',required=True,),
        dwr_time=dict(type='int',),
        user_tag=dict(type='str',),
        origin_realm=dict(type='str',),
        origin_host=dict(type='dict',uuid=dict(type='str',),origin_host_name=dict(type='str',)),
        multiple_origin_host=dict(type='bool',),
        forward_to_latest_server=dict(type='bool',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/diameter/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/diameter/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["diameter"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["diameter"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["diameter"][k] = v
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
    payload = build_json("diameter", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("diameter", module)
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
    if partition and not module.check_mode:
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
    module = AnsibleModule(argument_spec=get_argspec(), supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()