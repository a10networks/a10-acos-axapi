#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_server_port
description:
    - Real Server Port
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
    a10_port:
        description:
        - Port for AXAPI authentication
        required: True
    a10_protocol:
        description:
        - Protocol for AXAPI authentication
        required: True
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    server_name:
        description:
        - Key to identify parent object
    health_check_disable:
        description:
        - "Disable health check"
        required: False
    protocol:
        description:
        - "'tcp'= TCP Port; 'udp'= UDP Port; "
        required: True
    weight:
        description:
        - "Port Weight (Connection Weight)"
        required: False
    shared_rport_health_check:
        description:
        - "Reference a health-check from shared partition"
        required: False
    stats_data_action:
        description:
        - "'stats-data-enable'= Enable statistical data collection for real server port; 'stats-data-disable'= Disable statistical data collection for real server port; "
        required: False
    health_check_follow_port:
        description:
        - "Specify which port to follow for health status (Port Number)"
        required: False
    template_port:
        description:
        - "Port template (Port template name)"
        required: False
    conn_limit:
        description:
        - "Connection Limit"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    support_http2:
        description:
        - "Starting HTTP/2 with Prior Knowledge"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'curr_req'= Current requests; 'total_req'= Total Requests; 'total_req_succ'= Total requests succ; 'total_fwd_bytes'= Bytes processed in forward direction; 'total_fwd_pkts'= Packets processed in forward direction; 'total_rev_bytes'= Bytes processed in reverse direction; 'total_rev_pkts'= Packets processed in reverse direction; 'total_conn'= Total connections; 'last_total_conn'= Last total connections; 'peak_conn'= Peak connections; 'es_resp_200'= Response status 200; 'es_resp_300'= Response status 300; 'es_resp_400'= Response status 400; 'es_resp_500'= Response status 500; 'es_resp_other'= Response status other; 'es_req_count'= Total proxy requests; 'es_resp_count'= Total proxy response; 'es_resp_invalid_http'= Total non-http response; 'total_rev_pkts_inspected'= Total reverse packets inspected; 'total_rev_pkts_inspected_good_status_code'= Total reverse packets with good status code inspected; 'response_time'= Response time; 'fastest_rsp_time'= Fastest response time; 'slowest_rsp_time'= Slowest response time; 'curr_ssl_conn'= Current SSL connections; 'total_ssl_conn'= Total SSL connections; 'resp-count'= Total Response Count; 'resp-1xx'= Response status 1xx; 'resp-2xx'= Response status 2xx; 'resp-3xx'= Response status 3xx; 'resp-4xx'= Response status 4xx; 'resp-5xx'= Response status 5xx; 'resp-other'= Response status Other; 'resp-latency'= Time to First Response Byte; 'curr_pconn'= Current persistent connections; "
    no_ssl:
        description:
        - "No SSL"
        required: False
    follow_port_protocol:
        description:
        - "'tcp'= TCP Port; 'udp'= UDP Port; "
        required: False
    template_server_ssl:
        description:
        - "Server side SSL template (Server side SSL Name)"
        required: False
    alternate_port:
        description:
        - "Field alternate_port"
        required: False
        suboptions:
            alternate_name:
                description:
                - "Alternate Name"
            alternate:
                description:
                - "Alternate Server Number"
            alternate_server_port:
                description:
                - "Port (Alternate Server Port Value)"
    port_number:
        description:
        - "Port Number"
        required: True
    extended_stats:
        description:
        - "Enable extended statistics on real server port"
        required: False
    rport_health_check_shared:
        description:
        - "Health Check (Monitor Name)"
        required: False
    conn_resume:
        description:
        - "Connection Resume"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    range:
        description:
        - "Port range (Port range value - used for vip-to-rport-mapping and vport-rport range mapping)"
        required: False
    auth_cfg:
        description:
        - "Field auth_cfg"
        required: False
        suboptions:
            service_principal_name:
                description:
                - "Service Principal Name (Kerberos principal name)"
    action:
        description:
        - "'enable'= enable; 'disable'= disable; 'disable-with-health-check'= disable port, but health check work; "
        required: False
    health_check:
        description:
        - "Health Check (Monitor Name)"
        required: False
    no_logging:
        description:
        - "Do not log connection over limit event"
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
AVAILABLE_PROPERTIES = ["action","alternate_port","auth_cfg","conn_limit","conn_resume","extended_stats","follow_port_protocol","health_check","health_check_disable","health_check_follow_port","no_logging","no_ssl","port_number","protocol","range","rport_health_check_shared","sampling_enable","shared_rport_health_check","stats_data_action","support_http2","template_port","template_server_ssl","user_tag","uuid","weight",]

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
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        health_check_disable=dict(type='bool',),
        protocol=dict(type='str',required=True,choices=['tcp','udp']),
        weight=dict(type='int',),
        shared_rport_health_check=dict(type='bool',),
        stats_data_action=dict(type='str',choices=['stats-data-enable','stats-data-disable']),
        health_check_follow_port=dict(type='int',),
        template_port=dict(type='str',),
        conn_limit=dict(type='int',),
        uuid=dict(type='str',),
        support_http2=dict(type='bool',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','curr_req','total_req','total_req_succ','total_fwd_bytes','total_fwd_pkts','total_rev_bytes','total_rev_pkts','total_conn','last_total_conn','peak_conn','es_resp_200','es_resp_300','es_resp_400','es_resp_500','es_resp_other','es_req_count','es_resp_count','es_resp_invalid_http','total_rev_pkts_inspected','total_rev_pkts_inspected_good_status_code','response_time','fastest_rsp_time','slowest_rsp_time','curr_ssl_conn','total_ssl_conn','resp-count','resp-1xx','resp-2xx','resp-3xx','resp-4xx','resp-5xx','resp-other','resp-latency','curr_pconn'])),
        no_ssl=dict(type='bool',),
        follow_port_protocol=dict(type='str',choices=['tcp','udp']),
        template_server_ssl=dict(type='str',),
        alternate_port=dict(type='list',alternate_name=dict(type='str',),alternate=dict(type='int',),alternate_server_port=dict(type='int',)),
        port_number=dict(type='int',required=True,),
        extended_stats=dict(type='bool',),
        rport_health_check_shared=dict(type='str',),
        conn_resume=dict(type='int',),
        user_tag=dict(type='str',),
        range=dict(type='int',),
        auth_cfg=dict(type='dict',service_principal_name=dict(type='str',)),
        action=dict(type='str',choices=['enable','disable','disable-with-health-check']),
        health_check=dict(type='str',),
        no_logging=dict(type='bool',)
    ))
   
    # Parent keys
    rv.update(dict(
        server_name=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/server/{server_name}/port/{port-number}+{protocol}"

    f_dict = {}
    f_dict["port-number"] = ""
    f_dict["protocol"] = ""
    f_dict["server_name"] = module.params["server_name"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/server/{server_name}/port/{port-number}+{protocol}"

    f_dict = {}
    f_dict["port-number"] = module.params["port_number"]
    f_dict["protocol"] = module.params["protocol"]
    f_dict["server_name"] = module.params["server_name"]

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"

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

def get_oper(module):
    return module.client.get(oper_url(module))

def get_stats(module):
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["port"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["port"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["port"][k] = v
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
    payload = build_json("port", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    if module.check_mode:
        result["changed"] = True
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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