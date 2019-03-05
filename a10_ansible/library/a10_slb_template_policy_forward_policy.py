#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_template_policy_forward_policy
description:
    - Forward Policy commands
short_description: Configures A10 slb.template.policy.forward-policy
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

    filtering:
        description:
        - "Field filtering"
        required: False
        suboptions:
            ssli_url_filtering:
                description:
                - "'bypassed-sni-disable'= Disable SNI filtering for bypassed URL's(enabled by default); 'intercepted-sni-enable'= Enable SNI filtering for intercepted URL's(disabled by default); 'intercepted-http-disable'= Disable HTTP(host/URL) filtering for intercepted URL's(enabled by default); 'no-sni-allow'= Allow connection if SNI filtering is enabled and SNI header is not present(Drop by default); "
    uuid:
        description:
        - "uuid of the object"
        required: False
    local_logging:
        description:
        - "Enable local logging"
        required: False
    action_list:
        description:
        - "Field action_list"
        required: False
        suboptions:
            log:
                description:
                - "enable logging"
            forward_snat:
                description:
                - "Source NAT pool or pool group"
            uuid:
                description:
                - "uuid of the object"
            http_status_code:
                description:
                - "'301'= Moved permanently; '302'= Found; "
            action1:
                description:
                - "'forward-to-internet'= Forward request to Internet; 'forward-to-service-group'= Forward request to service group; 'forward-to-proxy'= Forward request to HTTP proxy server; 'drop'= Drop request; "
            fake_sg:
                description:
                - "service group to forward the packets to Internet"
            user_tag:
                description:
                - "Customized tag"
            real_sg:
                description:
                - "service group to forward the packets"
            drop_message:
                description:
                - "drop-message sent to the client as webpage(html tags are included and quotation marks are required for white spaces)"
            sampling_enable:
                description:
                - "Field sampling_enable"
            fall_back:
                description:
                - "Fallback service group for Internet"
            fall_back_snat:
                description:
                - "Source NAT pool or pool group for fallback server"
            drop_redirect_url:
                description:
                - "Specify URL to which client request is redirected upon being dropped"
            name:
                description:
                - "Action policy name"
    no_client_conn_reuse:
        description:
        - "Inspects only first request of a connection"
        required: False
    source_list:
        description:
        - "Field source_list"
        required: False
        suboptions:
            match_any:
                description:
                - "Match any source"
            name:
                description:
                - "source destination match rule name"
            match_authorize_policy:
                description:
                - "Authorize-policy for user and group based policy"
            destination:
                description:
                - "Field destination"
            user_tag:
                description:
                - "Customized tag"
            priority:
                description:
                - "Priority of the source(higher the number higher the priority, default 0)"
            sampling_enable:
                description:
                - "Field sampling_enable"
            match_class_list:
                description:
                - "Class List Name"
            uuid:
                description:
                - "uuid of the object"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["action_list","filtering","local_logging","no_client_conn_reuse","source_list","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        partition=dict(type='str', required=False)
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        filtering=dict(type='list',ssli_url_filtering=dict(type='str',choices=['bypassed-sni-disable','intercepted-sni-enable','intercepted-http-disable','no-sni-allow'])),
        uuid=dict(type='str',),
        local_logging=dict(type='bool',),
        action_list=dict(type='list',log=dict(type='bool',),forward_snat=dict(type='str',),uuid=dict(type='str',),http_status_code=dict(type='str',choices=['301','302']),action1=dict(type='str',choices=['forward-to-internet','forward-to-service-group','forward-to-proxy','drop']),fake_sg=dict(type='str',),user_tag=dict(type='str',),real_sg=dict(type='str',),drop_message=dict(type='str',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),fall_back=dict(type='str',),fall_back_snat=dict(type='str',),drop_redirect_url=dict(type='str',),name=dict(type='str',required=True,)),
        no_client_conn_reuse=dict(type='bool',),
        source_list=dict(type='list',match_any=dict(type='bool',),name=dict(type='str',required=True,),match_authorize_policy=dict(type='str',),destination=dict(type='dict',class_list_list=dict(type='list',uuid=dict(type='str',),dest_class_list=dict(type='str',required=True,),priority=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),action=dict(type='str',),ntype=dict(type='str',choices=['host','url','ip'])),web_category_list_list=dict(type='list',uuid=dict(type='str',),web_category_list=dict(type='str',required=True,),priority=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),action=dict(type='str',),ntype=dict(type='str',choices=['host','url'])),any=dict(type='dict',action=dict(type='str',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),uuid=dict(type='str',))),user_tag=dict(type='str',),priority=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits','destination-match-not-found','no-host-info'])),match_class_list=dict(type='str',),uuid=dict(type='str',))
    ))
   
    # Parent keys
    rv.update(dict(
        policy_name=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/policy/{policy_name}/forward-policy"

    f_dict = {}
    f_dict["policy_name"] = module.params["policy_name"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/policy/{policy_name}/forward-policy"

    f_dict = {}
    f_dict["policy_name"] = module.params["policy_name"]

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
    payload = build_json("forward-policy", module)
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
    payload = build_json("forward-policy", module)
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
    payload = build_json("forward-policy", module)
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
        message=""
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