#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_template_policy
description:
    - Policy config
short_description: Configures A10 slb.template.policy
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
    forward_policy:
        description:
        - "Field forward_policy"
        required: False
        suboptions:
            filtering:
                description:
                - "Field filtering"
            uuid:
                description:
                - "uuid of the object"
            local_logging:
                description:
                - "Enable local logging"
            san_filtering:
                description:
                - "Field san_filtering"
            action_list:
                description:
                - "Field action_list"
            no_client_conn_reuse:
                description:
                - "Inspects only first request of a connection"
            require_web_category:
                description:
                - "Wait for web category to be resolved before taking proxy decision"
            source_list:
                description:
                - "Field source_list"
    use_destination_ip:
        description:
        - "Use destination IP to match the policy"
        required: False
    name:
        description:
        - "Policy template name"
        required: True
    over_limit:
        description:
        - "Specify operation in case over limit"
        required: False
    class_list:
        description:
        - "Field class_list"
        required: False
        suboptions:
            header_name:
                description:
                - "Specify L7 header name"
            lid_list:
                description:
                - "Field lid_list"
            name:
                description:
                - "Class list name or geo-location-class-list name"
            client_ip_l3_dest:
                description:
                - "Use destination IP as client IP address"
            client_ip_l7_header:
                description:
                - "Use extract client IP address from L7 header"
            uuid:
                description:
                - "uuid of the object"
    interval:
        description:
        - "Log interval (minute)"
        required: False
    share:
        description:
        - "Share counters between virtual ports and virtual servers"
        required: False
    full_domain_tree:
        description:
        - "Share counters between geo-location and sub regions"
        required: False
    over_limit_logging:
        description:
        - "Log a message"
        required: False
    bw_list_name:
        description:
        - "Specify a blacklist/whitelist name"
        required: False
    timeout:
        description:
        - "Define timeout value of PBSLB dynamic entry (Timeout value (minute, default is 5))"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'fwd-policy-dns-unresolved'= Forward-policy unresolved DNS queries; 'fwd-policy-dns-outstanding'= Forward-policy current DNS outstanding requests; 'fwd-policy-snat-fail'= Forward-policy source-nat translation failure; 'fwd-policy-hits'= Number of forward-policy requests for this policy template; 'fwd-policy-forward-to-internet'= Number of forward-policy requests forwarded to internet; 'fwd-policy-forward-to-service-group'= Number of forward-policy requests forwarded to service group; 'fwd-policy-forward-to-proxy'= Number of forward-policy requests forwarded to proxy; 'fwd-policy-policy-drop'= Number of forward-policy requests dropped; 'fwd-policy-source-match-not-found'= Forward-policy requests without matching source rule; 'exp-client-hello-not-found'= Expected Client HELLO requests not found; "
    user_tag:
        description:
        - "Customized tag"
        required: False
    bw_list_id:
        description:
        - "Field bw_list_id"
        required: False
        suboptions:
            pbslb_interval:
                description:
                - "Specify logging interval in minutes"
            action_interval:
                description:
                - "Specify logging interval in minute (default is 3)"
            service_group:
                description:
                - "Specify a service group (Specify the service group name)"
            logging_drp_rst:
                description:
                - "Configure PBSLB logging"
            fail:
                description:
                - "Only log unsuccessful connections"
            pbslb_logging:
                description:
                - "Configure PBSLB logging"
            id:
                description:
                - "Specify id that maps to service group (The id number)"
            bw_list_action:
                description:
                - "'drop'= drop the packet; 'reset'= Send reset back; "
    over_limit_lockup:
        description:
        - "Don't accept any new connection for certain time (Lockup duration (minute))"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    over_limit_reset:
        description:
        - "Reset the connection when it exceeds limit"
        required: False
    overlap:
        description:
        - "Use overlap mode for geo-location to do longest match"
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
AVAILABLE_PROPERTIES = ["bw_list_id","bw_list_name","class_list","forward_policy","full_domain_tree","interval","name","over_limit","over_limit_lockup","over_limit_logging","over_limit_reset","overlap","sampling_enable","share","timeout","use_destination_ip","user_tag","uuid",]

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
        forward_policy=dict(type='dict',filtering=dict(type='list',ssli_url_filtering=dict(type='str',choices=['bypassed-sni-disable','intercepted-sni-enable','intercepted-http-disable','no-sni-allow'])),uuid=dict(type='str',),local_logging=dict(type='bool',),san_filtering=dict(type='list',ssli_url_filtering_san=dict(type='str',choices=['enable-san','bypassed-san-disable','intercepted-san-enable','no-san-allow'])),action_list=dict(type='list',log=dict(type='bool',),http_status_code=dict(type='str',choices=['301','302']),forward_snat=dict(type='str',),uuid=dict(type='str',),drop_response_code=dict(type='int',),action1=dict(type='str',choices=['forward-to-internet','forward-to-service-group','forward-to-proxy','drop']),fake_sg=dict(type='str',),user_tag=dict(type='str',),real_sg=dict(type='str',),drop_message=dict(type='str',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),fall_back=dict(type='str',),fall_back_snat=dict(type='str',),drop_redirect_url=dict(type='str',),name=dict(type='str',required=True,)),no_client_conn_reuse=dict(type='bool',),require_web_category=dict(type='bool',),source_list=dict(type='list',match_any=dict(type='bool',),name=dict(type='str',required=True,),match_authorize_policy=dict(type='str',),destination=dict(type='dict',class_list_list=dict(type='list',uuid=dict(type='str',),dest_class_list=dict(type='str',required=True,),priority=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),action=dict(type='str',),ntype=dict(type='str',choices=['host','url','ip'])),web_category_list_list=dict(type='list',uuid=dict(type='str',),web_category_list=dict(type='str',required=True,),priority=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),action=dict(type='str',),ntype=dict(type='str',choices=['host','url'])),any=dict(type='dict',action=dict(type='str',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),uuid=dict(type='str',))),user_tag=dict(type='str',),priority=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits','destination-match-not-found','no-host-info'])),match_class_list=dict(type='str',),uuid=dict(type='str',))),
        use_destination_ip=dict(type='bool',),
        name=dict(type='str',required=True,),
        over_limit=dict(type='bool',),
        class_list=dict(type='dict',header_name=dict(type='str',),lid_list=dict(type='list',request_rate_limit=dict(type='int',),action_value=dict(type='str',choices=['forward','reset']),request_per=dict(type='int',),bw_rate_limit=dict(type='int',),conn_limit=dict(type='int',),log=dict(type='bool',),direct_action_value=dict(type='str',choices=['drop','reset']),conn_per=dict(type='int',),direct_fail=dict(type='bool',),conn_rate_limit=dict(type='int',),direct_pbslb_logging=dict(type='bool',),dns64=dict(type='dict',prefix=dict(type='str',),exclusive_answer=dict(type='bool',),disable=dict(type='bool',)),lidnum=dict(type='int',required=True,),over_limit_action=dict(type='bool',),response_code_rate_limit=dict(type='list',threshold=dict(type='int',),code_range_end=dict(type='int',),code_range_start=dict(type='int',),period=dict(type='int',)),direct_service_group=dict(type='str',),uuid=dict(type='str',),request_limit=dict(type='int',),direct_action_interval=dict(type='int',),bw_per=dict(type='int',),interval=dict(type='int',),user_tag=dict(type='str',),direct_action=dict(type='bool',),lockout=dict(type='int',),direct_logging_drp_rst=dict(type='bool',),direct_pbslb_interval=dict(type='int',)),name=dict(type='str',),client_ip_l3_dest=dict(type='bool',),client_ip_l7_header=dict(type='bool',),uuid=dict(type='str',)),
        interval=dict(type='int',),
        share=dict(type='bool',),
        full_domain_tree=dict(type='bool',),
        over_limit_logging=dict(type='bool',),
        bw_list_name=dict(type='str',),
        timeout=dict(type='int',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','fwd-policy-dns-unresolved','fwd-policy-dns-outstanding','fwd-policy-snat-fail','fwd-policy-hits','fwd-policy-forward-to-internet','fwd-policy-forward-to-service-group','fwd-policy-forward-to-proxy','fwd-policy-policy-drop','fwd-policy-source-match-not-found','exp-client-hello-not-found'])),
        user_tag=dict(type='str',),
        bw_list_id=dict(type='list',pbslb_interval=dict(type='int',),action_interval=dict(type='int',),service_group=dict(type='str',),logging_drp_rst=dict(type='bool',),fail=dict(type='bool',),pbslb_logging=dict(type='bool',),id=dict(type='int',),bw_list_action=dict(type='str',choices=['drop','reset'])),
        over_limit_lockup=dict(type='int',),
        uuid=dict(type='str',),
        over_limit_reset=dict(type='bool',),
        overlap=dict(type='bool',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/template/policy/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/template/policy/{name}"

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
    payload = build_json("policy", module)
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
    payload = build_json("policy", module)
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
    payload = build_json("policy", module)
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