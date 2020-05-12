#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_slb_template_respmod_icap
description:
    - RESPMOD ICAP template
short_description: Configures A10 slb.template.respmod-icap
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
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
    a10_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_protocol:
        description:
        - Protocol for AXAPI authentication
        required: True
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    min_payload_size:
        description:
        - "min-payload-size value 0 - 65535, default is 0"
        required: False
    shared_partition_persist_source_ip_template:
        description:
        - "Reference a persist source ip template from shared partition"
        required: False
    template_tcp_proxy_shared:
        description:
        - "TCP Proxy Template name"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    source_ip:
        description:
        - "Source IP persistence template (Source IP persistence template name)"
        required: False
    shared_partition_tcp_proxy_template:
        description:
        - "Reference a TCP Proxy template from shared partition"
        required: False
    service_group:
        description:
        - "Bind a Service Group to the template (Service Group Name)"
        required: False
    tcp_proxy:
        description:
        - "TCP Proxy Template Name"
        required: False
    preview:
        description:
        - "Preview value 1 - 32768, default is 32768"
        required: False
    disable_http_server_reset:
        description:
        - "Don't reset http server"
        required: False
    server_ssl:
        description:
        - "Server SSL template (Server SSL template name)"
        required: False
    fail_close:
        description:
        - "When template sg is down mark vport down"
        required: False
    bypass_ip_cfg:
        description:
        - "Field bypass_ip_cfg"
        required: False
        suboptions:
            bypass_ip:
                description:
                - "ip address to bypass respmod-icap service"
            mask:
                description:
                - "IP prefix mask"
    template_persist_source_ip_shared:
        description:
        - "Source IP Persistence Template Name"
        required: False
    include_protocol_in_uri:
        description:
        - "Include protocol and port in HTTP URI"
        required: False
    logging:
        description:
        - "logging template (Logging template name)"
        required: False
    name:
        description:
        - "Reqmod ICAP Template Name"
        required: True
    user_tag:
        description:
        - "Customized tag"
        required: False
    x_auth_url:
        description:
        - "Use URL format for authentication"
        required: False
    log_only_allowed_method:
        description:
        - "Only log allowed HTTP method"
        required: False
    action:
        description:
        - "'continue'= Continue; 'drop'= Drop; 'reset'= Reset; "
        required: False
    cylance:
        description:
        - "cylance external server"
        required: False
    service_url:
        description:
        - "URL to send to ICAP server (Service URL Name)"
        required: False


'''

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["action","bypass_ip_cfg","cylance","disable_http_server_reset","fail_close","include_protocol_in_uri","log_only_allowed_method","logging","min_payload_size","name","preview","server_ssl","service_group","service_url","shared_partition_persist_source_ip_template","shared_partition_tcp_proxy_template","source_ip","tcp_proxy","template_persist_source_ip_shared","template_tcp_proxy_shared","user_tag","uuid","x_auth_url",]

# our imports go at the top so we fail fast.
try:
    from ansible_collections.a10.acos_axapi.plugins.module_utils import errors as a10_ex
    from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import client_factory, session_factory
    from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

except (ImportError) as ex:
    module.fail_json(msg="Import Error:{0}".format(ex))
except (Exception) as ex:
    module.fail_json(msg="General Exception in Ansible module import:{0}".format(ex))


def get_default_argspec():
    return dict(
        a10_host=dict(type='str', required=True),
        a10_username=dict(type='str', required=True),
        a10_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        min_payload_size=dict(type='int', ),
        shared_partition_persist_source_ip_template=dict(type='bool', ),
        template_tcp_proxy_shared=dict(type='str', ),
        uuid=dict(type='str', ),
        source_ip=dict(type='str', ),
        shared_partition_tcp_proxy_template=dict(type='bool', ),
        service_group=dict(type='str', ),
        tcp_proxy=dict(type='str', ),
        preview=dict(type='int', ),
        disable_http_server_reset=dict(type='bool', ),
        server_ssl=dict(type='str', ),
        fail_close=dict(type='bool', ),
        bypass_ip_cfg=dict(type='list', bypass_ip=dict(type='str', ), mask=dict(type='str', )),
        template_persist_source_ip_shared=dict(type='str', ),
        include_protocol_in_uri=dict(type='bool', ),
        logging=dict(type='str', ),
        name=dict(type='str', required=True, ),
        user_tag=dict(type='str', ),
        x_auth_url=dict(type='bool', ),
        log_only_allowed_method=dict(type='bool', ),
        action=dict(type='str', choices=['continue', 'drop', 'reset']),
        cylance=dict(type='bool', ),
        service_url=dict(type='str', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/respmod-icap/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

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

def build_envelope(title, data):
    return {
        title: data
    }

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/respmod-icap/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

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

def build_json(title, module):
    rv = {}

    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v is not None:
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

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["respmod-icap"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["respmod-icap"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["respmod-icap"][k] = v
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
    payload = build_json("respmod-icap", module)
    changed_config = report_changes(module, result, existing_config, payload)
    if module.check_mode:
        return changed_config
    elif not existing_config:
        return create(module, result, payload)
    elif existing_config and not changed_config.get('changed'):
        return update(module, result, existing_config, payload)
    else:
        result["changed"] = True
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

def absent(module, result, existing_config):
    if module.check_mode:
        if existing_config:
            result["changed"] = True
            return result
        else:
            result["changed"] = False
            return result
    else:
        return delete(module, result)

def replace(module, result, existing_config, payload):
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
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

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
    
    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)
    
    if state == 'present':
        result = present(module, result, existing_config)

    elif state == 'absent':
        result = absent(module, result, existing_config)
    
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
    module.client.session.close()
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