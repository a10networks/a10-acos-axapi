#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_slb_server
description:
    - Server
short_description: Configures A10 slb.server
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
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            state:
                description:
                - "Field state"
            port_list:
                description:
                - "Field port_list"
            name:
                description:
                - "Server Name"
    health_check_disable:
        description:
        - "Disable configured health check configuration"
        required: False
    port_list:
        description:
        - "Field port_list"
        required: False
        suboptions:
            health_check_disable:
                description:
                - "Disable health check"
            protocol:
                description:
                - "'tcp'= TCP Port; 'udp'= UDP Port; "
            weight:
                description:
                - "Port Weight (Connection Weight)"
            stats_data_action:
                description:
                - "'stats-data-enable'= Enable statistical data collection for real server port; 'stats-data-disable'= Disable statistical data collection for real server port; "
            health_check_follow_port:
                description:
                - "Specify which port to follow for health status (Port Number)"
            template_port:
                description:
                - "Port template (Port template name)"
            conn_limit:
                description:
                - "Connection Limit"
            uuid:
                description:
                - "uuid of the object"
            sampling_enable:
                description:
                - "Field sampling_enable"
            no_ssl:
                description:
                - "No SSL"
            follow_port_protocol:
                description:
                - "'tcp'= TCP Port; 'udp'= UDP Port; "
            template_server_ssl:
                description:
                - "Server side SSL template (Server side SSL Name)"
            alternate_port:
                description:
                - "Field alternate_port"
            port_number:
                description:
                - "Port Number"
            extended_stats:
                description:
                - "Enable extended statistics on real server port"
            conn_resume:
                description:
                - "Connection Resume"
            user_tag:
                description:
                - "Customized tag"
            range:
                description:
                - "Port range (Port range value - used for vip-to-rport-mapping)"
            auth_cfg:
                description:
                - "Field auth_cfg"
            action:
                description:
                - "'enable'= enable; 'disable'= disable; 'disable-with-health-check'= disable port, but health check work; "
            health_check:
                description:
                - "Health Check (Monitor Name)"
            no_logging:
                description:
                - "Do not log connection over limit event"
    stats_data_action:
        description:
        - "'stats-data-enable'= Enable statistical data collection for real server; 'stats-data-disable'= Disable statistical data collection for real server; "
        required: False
    spoofing_cache:
        description:
        - "This server is a spoofing cache"
        required: False
    weight:
        description:
        - "Weight for this Real Server (Connection Weight)"
        required: False
    slow_start:
        description:
        - "Slowly ramp up the connection number after server is up (start from 128, then double every 10 sec till 4096)"
        required: False
    conn_limit:
        description:
        - "Connection Limit"
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            curr_conn:
                description:
                - "Current established connections"
            peak_conn:
                description:
                - "Peak number of established connections"
            rev_pkt:
                description:
                - "Reverse Packets Processed"
            total_rev_pkts:
                description:
                - "Packets processed in reverse direction"
            name:
                description:
                - "Server Name"
            total_ssl_conn:
                description:
                - "Total SSL connections established"
            total_fwd_pkts:
                description:
                - "Packets processed in forward direction"
            total_req:
                description:
                - "Total Requests processed"
            total_conn:
                description:
                - "Total established connections"
            curr_ssl_conn:
                description:
                - "Current SSL connections established"
            total_req_succ:
                description:
                - "Total Requests succeeded"
            port_list:
                description:
                - "Field port_list"
            fwd_pkt:
                description:
                - "Forward Packets Processed"
            total_fwd_bytes:
                description:
                - "Bytes processed in forward direction"
            total_rev_bytes:
                description:
                - "Bytes processed in reverse direction"
    uuid:
        description:
        - "uuid of the object"
        required: False
    fqdn_name:
        description:
        - "Server hostname"
        required: False
    external_ip:
        description:
        - "External IP address for NAT of GSLB"
        required: False
    ipv6:
        description:
        - "IPv6 address Mapping of GSLB"
        required: False
    template_server:
        description:
        - "Server template (Server template name)"
        required: False
    server_ipv6_addr:
        description:
        - "IPV6 address"
        required: False
    alternate_server:
        description:
        - "Field alternate_server"
        required: False
        suboptions:
            alternate_name:
                description:
                - "Alternate Name"
            alternate:
                description:
                - "Alternate Server (Alternate Server Number)"
    host:
        description:
        - "IP Address"
        required: False
    extended_stats:
        description:
        - "Enable extended statistics on real server"
        required: False
    conn_resume:
        description:
        - "Connection Resume (Connection Resume (min active conn before resume taking new conn))"
        required: False
    name:
        description:
        - "Server Name"
        required: True
    user_tag:
        description:
        - "Customized tag"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'total-conn'= Total established connections; 'fwd-pkt'= Forward Packets Processed; 'rev-pkt'= Reverse Packets Processed; 'peak-conn'= Peak number of established connections; 'total_req'= Total Requests processed; 'total_req_succ'= Total Requests succeeded; 'curr_ssl_conn'= Current SSL connections established; 'total_ssl_conn'= Total SSL connections established; 'total_fwd_bytes'= Bytes processed in forward direction; 'total_rev_bytes'= Bytes processed in reverse direction; 'total_fwd_pkts'= Packets processed in forward direction; 'total_rev_pkts'= Packets processed in reverse direction; "
    action:
        description:
        - "'enable'= Enable this Real Server; 'disable'= Disable this Real Server; 'disable-with-health-check'= disable real server, but health check work; "
        required: False
    health_check:
        description:
        - "Health Check Monitor (Health monitor name)"
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
AVAILABLE_PROPERTIES = ["action","alternate_server","conn_limit","conn_resume","extended_stats","external_ip","fqdn_name","health_check","health_check_disable","host","ipv6","name","no_logging","oper","port_list","sampling_enable","server_ipv6_addr","slow_start","spoofing_cache","stats","stats_data_action","template_server","user_tag","uuid","weight",]

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
        oper=dict(type='dict',state=dict(type='str',choices=['Up','Down','Disabled','Maintenance','Unknown','Functional Up','DIS-UP','DIS-DOWN','DIS-MAINTENANCE','DIS-EXCEED-RATE','DIS-UNKNOWN']),port_list=dict(type='list',oper=dict(type='dict',vrid=dict(type='int',),ha_group_id=dict(type='int',),alloc_failed=dict(type='int',),ports_consumed=dict(type='int',),ipv6=dict(type='str',),state=dict(type='str',choices=['Up','Down','Disabled','Maintenance','Unknown','DIS-UP','DIS-DOWN','DIS-MAINTENANCE','DIS-EXCEED-RATE']),ip=dict(type='str',),ports_freed_total=dict(type='int',),ports_consumed_total=dict(type='int',)),protocol=dict(type='str',required=True,choices=['tcp','udp']),port_number=dict(type='int',required=True,)),name=dict(type='str',required=True,)),
        health_check_disable=dict(type='bool',),
        port_list=dict(type='list',health_check_disable=dict(type='bool',),protocol=dict(type='str',required=True,choices=['tcp','udp']),weight=dict(type='int',),stats_data_action=dict(type='str',choices=['stats-data-enable','stats-data-disable']),health_check_follow_port=dict(type='int',),template_port=dict(type='str',),conn_limit=dict(type='int',),uuid=dict(type='str',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','curr_req','total_req','total_req_succ','total_fwd_bytes','total_fwd_pkts','total_rev_bytes','total_rev_pkts','total_conn','last_total_conn','peak_conn','es_resp_200','es_resp_300','es_resp_400','es_resp_500','es_resp_other','es_req_count','es_resp_count','es_resp_invalid_http','total_rev_pkts_inspected','total_rev_pkts_inspected_good_status_code','response_time','fastest_rsp_time','slowest_rsp_time','curr_ssl_conn','total_ssl_conn','resp-count','resp-1xx','resp-2xx','resp-3xx','resp-4xx','resp-5xx','resp-other','resp-latency'])),no_ssl=dict(type='bool',),follow_port_protocol=dict(type='str',choices=['tcp','udp']),template_server_ssl=dict(type='str',),alternate_port=dict(type='list',alternate_name=dict(type='str',),alternate=dict(type='int',),alternate_server_port=dict(type='int',)),port_number=dict(type='int',required=True,),extended_stats=dict(type='bool',),conn_resume=dict(type='int',),user_tag=dict(type='str',),range=dict(type='int',),auth_cfg=dict(type='dict',service_principal_name=dict(type='str',)),action=dict(type='str',choices=['enable','disable','disable-with-health-check']),health_check=dict(type='str',),no_logging=dict(type='bool',)),
        stats_data_action=dict(type='str',choices=['stats-data-enable','stats-data-disable']),
        spoofing_cache=dict(type='bool',),
        weight=dict(type='int',),
        slow_start=dict(type='bool',),
        conn_limit=dict(type='int',),
        stats=dict(type='dict',curr_conn=dict(type='str',),peak_conn=dict(type='str',),rev_pkt=dict(type='str',),total_rev_pkts=dict(type='str',),name=dict(type='str',required=True,),total_ssl_conn=dict(type='str',),total_fwd_pkts=dict(type='str',),total_req=dict(type='str',),total_conn=dict(type='str',),curr_ssl_conn=dict(type='str',),total_req_succ=dict(type='str',),port_list=dict(type='list',protocol=dict(type='str',required=True,choices=['tcp','udp']),stats=dict(type='dict',es_resp_invalid_http=dict(type='str',),curr_req=dict(type='str',),total_rev_pkts_inspected_good_status_code=dict(type='str',),resp_1xx=dict(type='str',),curr_ssl_conn=dict(type='str',),resp_2xx=dict(type='str',),es_resp_count=dict(type='str',),total_fwd_bytes=dict(type='str',),es_resp_other=dict(type='str',),fastest_rsp_time=dict(type='str',),total_fwd_pkts=dict(type='str',),resp_3xx=dict(type='str',),resp_latency=dict(type='str',),resp_count=dict(type='str',),es_req_count=dict(type='str',),resp_other=dict(type='str',),es_resp_500=dict(type='str',),peak_conn=dict(type='str',),total_req=dict(type='str',),es_resp_400=dict(type='str',),es_resp_300=dict(type='str',),curr_conn=dict(type='str',),es_resp_200=dict(type='str',),total_rev_bytes=dict(type='str',),response_time=dict(type='str',),resp_4xx=dict(type='str',),total_ssl_conn=dict(type='str',),total_conn=dict(type='str',),total_rev_pkts=dict(type='str',),total_req_succ=dict(type='str',),last_total_conn=dict(type='str',),total_rev_pkts_inspected=dict(type='str',),resp_5xx=dict(type='str',),slowest_rsp_time=dict(type='str',)),port_number=dict(type='int',required=True,)),fwd_pkt=dict(type='str',),total_fwd_bytes=dict(type='str',),total_rev_bytes=dict(type='str',)),
        uuid=dict(type='str',),
        fqdn_name=dict(type='str',),
        external_ip=dict(type='str',),
        ipv6=dict(type='str',),
        template_server=dict(type='str',),
        server_ipv6_addr=dict(type='str',),
        alternate_server=dict(type='list',alternate_name=dict(type='str',),alternate=dict(type='int',)),
        host=dict(type='str',),
        extended_stats=dict(type='bool',),
        conn_resume=dict(type='int',),
        name=dict(type='str',required=True,),
        user_tag=dict(type='str',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','total-conn','fwd-pkt','rev-pkt','peak-conn','total_req','total_req_succ','curr_ssl_conn','total_ssl_conn','total_fwd_bytes','total_rev_bytes','total_fwd_pkts','total_rev_pkts'])),
        action=dict(type='str',choices=['enable','disable','disable-with-health-check']),
        health_check=dict(type='str',),
        no_logging=dict(type='bool',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/server/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/server/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted(['host','fqdn_name','server_ipv6_addr'])
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
    if module.params.get("oper"):
        query_params = {}
        for k,v in module.params["oper"].items():
            query_params[k.replace('_', '-')] = v 
        return module.client.get(oper_url(module),
                                 params=query_params)
    return module.client.get(oper_url(module))

def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k,v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module),
                                 params=query_params)
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["server"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["server"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["server"][k] = v
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
    payload = build_json("server", module)
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
    elif state == 'absent':
        result = absent(module, result, existing_config)
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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