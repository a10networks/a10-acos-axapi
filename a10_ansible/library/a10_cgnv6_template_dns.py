#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_template_dns
description:
    - DNS template
short_description: Configures A10 cgnv6.template.dns
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
    name:
        description:
        - "DNS Template Name"
        required: True
    class_list:
        description:
        - "Field class_list"
        required: False
        suboptions:
            lid_list:
                description:
                - "Field lid_list"
            name:
                description:
                - "Specify a class list name"
            uuid:
                description:
                - "uuid of the object"
    dns64:
        description:
        - "Field dns64"
        required: False
        suboptions:
            deep_check_rr_disable:
                description:
                - "Disable Check DNS Response Records"
            answer_only_disable:
                description:
                - "Disable Only translate the Answer Section"
            enable:
                description:
                - "Enable DNS64 (Need to config this option before config any other dns64 options)"
            single_response_disable:
                description:
                - "Disable Single Response which is used to avoid ambiguity"
            uuid:
                description:
                - "uuid of the object"
            max_qr_length:
                description:
                - "Max Question Record Length, default is 128"
            ignore_rcode3_disable:
                description:
                - "Disable Ignore DNS error Response with rcode 3"
            auth_data:
                description:
                - "Set AA flag in DNS Response"
            change_query:
                description:
                - "Always change incoming AAAA DNS Query to A"
            drop_cname_disable:
                description:
                - "Disable Drop DNS CNAME Response"
            cache:
                description:
                - "Generate Response by DNS Cache"
            passive_query_disable:
                description:
                - "Disable Generate A query upon empty or error Response"
            retry:
                description:
                - "Retry count, default is 3 (Retry Number)"
            parallel_query:
                description:
                - "Forward AAAA Query & generate A Query in parallel"
            timeout:
                description:
                - "Timeout to send additional Queries, unit= second, default is 1"
            ttl:
                description:
                - "Specify Max TTL in DNS Response, unit= second"
            trans_ptr_query:
                description:
                - "Translate DNS PTR Query"
            trans_ptr:
                description:
                - "Translate DNS PTR Records"
            compress_disable:
                description:
                - "Disable Always try DNS Compression"
    drop:
        description:
        - "Drop the malformed query"
        required: False
    period:
        description:
        - "Period in minutes"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    default_policy:
        description:
        - "'nocache'= Cache disable; 'cache'= Cache enable; "
        required: False
    disable_dns_template:
        description:
        - "Disable DNS template"
        required: False
    forward:
        description:
        - "Forward to service group (Service group name)"
        required: False
    max_cache_size:
        description:
        - "Define maximum cache size (Maximum cache entry per VIP)"
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
AVAILABLE_PROPERTIES = ["class_list","default_policy","disable_dns_template","dns64","drop","forward","max_cache_size","name","period","user_tag","uuid",]

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
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        state=dict(type='str', default="present", choices=["present", "absent"]),
        partition=dict(type='str', required=False)
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        name=dict(type='str',required=True,),
        class_list=dict(type='dict',lid_list=dict(type='list',action_value=dict(type='str',choices=['dns-cache-disable','dns-cache-enable','forward']),log=dict(type='bool',),lidnum=dict(type='int',required=True,),over_limit_action=dict(type='bool',),per=dict(type='int',),lockout=dict(type='int',),user_tag=dict(type='str',),dns=dict(type='dict',cache_action=dict(type='str',choices=['cache-disable','cache-enable']),weight=dict(type='int',),ttl=dict(type='int',)),conn_rate_limit=dict(type='int',),log_interval=dict(type='int',),uuid=dict(type='str',)),name=dict(type='str',),uuid=dict(type='str',)),
        dns64=dict(type='dict',deep_check_rr_disable=dict(type='bool',),answer_only_disable=dict(type='bool',),enable=dict(type='bool',),single_response_disable=dict(type='bool',),uuid=dict(type='str',),max_qr_length=dict(type='int',),ignore_rcode3_disable=dict(type='bool',),auth_data=dict(type='bool',),change_query=dict(type='bool',),drop_cname_disable=dict(type='bool',),cache=dict(type='bool',),passive_query_disable=dict(type='bool',),retry=dict(type='int',),parallel_query=dict(type='bool',),timeout=dict(type='int',),ttl=dict(type='int',),trans_ptr_query=dict(type='bool',),trans_ptr=dict(type='bool',),compress_disable=dict(type='bool',)),
        drop=dict(type='bool',),
        period=dict(type='int',),
        user_tag=dict(type='str',),
        default_policy=dict(type='str',choices=['nocache','cache']),
        disable_dns_template=dict(type='bool',),
        forward=dict(type='str',),
        max_cache_size=dict(type='int',),
        uuid=dict(type='str',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/template/dns/{name}"
    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/template/dns/{name}"
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
    payload = build_json("dns", module)
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
    payload = build_json("dns", module)
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
    partition = module.params["partition"]

    # TODO(remove hardcoded port #)
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]

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