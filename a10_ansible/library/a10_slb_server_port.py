#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_server_port
description:
    - None
short_description: Configures A10 slb.server.port
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
    protocol:
        description:
        - "None"
        required: True
    weight:
        description:
        - "None"
        required: False
    stats_data_action:
        description:
        - "None"
        required: False
    health_check_follow_port:
        description:
        - "None"
        required: False
    template_port:
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "None"
    no_ssl:
        description:
        - "None"
        required: False
    follow_port_protocol:
        description:
        - "None"
        required: False
    template_server_ssl:
        description:
        - "None"
        required: False
    alternate_port:
        description:
        - "Field alternate_port"
        required: False
        suboptions:
            alternate_name:
                description:
                - "None"
            alternate:
                description:
                - "None"
            alternate_server_port:
                description:
                - "None"
    port_number:
        description:
        - "None"
        required: True
    extended_stats:
        description:
        - "None"
        required: False
    conn_resume:
        description:
        - "None"
        required: False
    user_tag:
        description:
        - "None"
        required: False
    range:
        description:
        - "None"
        required: False
    auth_cfg:
        description:
        - "Field auth_cfg"
        required: False
        suboptions:
            service_principal_name:
                description:
                - "None"
    action:
        description:
        - "None"
        required: False
    health_check:
        description:
        - "None"
        required: False
    no_logging:
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
AVAILABLE_PROPERTIES = ["action","alternate_port","auth_cfg","conn_limit","conn_resume","extended_stats","follow_port_protocol","health_check","health_check_disable","health_check_follow_port","no_logging","no_ssl","port_number","protocol","range","sampling_enable","stats_data_action","template_port","template_server_ssl","user_tag","uuid","weight",]

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
        protocol=dict(type='str',required=True,choices=['tcp','udp']),
        weight=dict(type='int',),
        stats_data_action=dict(type='str',choices=['stats-data-enable','stats-data-disable']),
        health_check_follow_port=dict(type='int',),
        template_port=dict(type='str',),
        conn_limit=dict(type='int',),
        uuid=dict(type='str',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','curr_req','total_req','total_req_succ','total_fwd_bytes','total_fwd_pkts','total_rev_bytes','total_rev_pkts','total_conn','last_total_conn','peak_conn','es_resp_200','es_resp_300','es_resp_400','es_resp_500','es_resp_other','es_req_count','es_resp_count','es_resp_invalid_http','total_rev_pkts_inspected','total_rev_pkts_inspected_good_status_code','response_time','fastest_rsp_time','slowest_rsp_time','curr_ssl_conn','total_ssl_conn','resp-count','resp-1xx','resp-2xx','resp-3xx','resp-4xx','resp-5xx','resp-other','resp-latency','curr_pconn'])),
        no_ssl=dict(type='bool',),
        follow_port_protocol=dict(type='str',choices=['tcp','udp']),
        template_server_ssl=dict(type='str',),
        alternate_port=dict(type='list',alternate_name=dict(type='str',),alternate=dict(type='int',),alternate_server_port=dict(type='int',)),
        port_number=dict(type='int',required=True,),
        extended_stats=dict(type='bool',),
        conn_resume=dict(type='int',),
        user_tag=dict(type='str',),
        range=dict(type='int',),
        auth_cfg=dict(type='dict',service_principal_name=dict(type='str',)),
        action=dict(type='str',choices=['enable','disable','disable-with-health-check']),
        health_check=dict(type='str',),
        no_logging=dict(type='bool',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/server/{name}/port/{port-number}+{protocol}"
    f_dict = {}
    f_dict["port-number"] = ""
    f_dict["protocol"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/server/{name}/port/{port-number}+{protocol}"
    f_dict = {}
    f_dict["port-number"] = module.params["port-number"]
    f_dict["protocol"] = module.params["protocol"]

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
    payload = build_json("port", module)
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
    payload = build_json("port", module)
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