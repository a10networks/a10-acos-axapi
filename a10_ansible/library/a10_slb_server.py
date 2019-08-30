#!/usr/bin/python

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
    a10_protocol:
        description:
        - HTTP / HTTPS Protocol for AXAPI authentication
        required: True
    a10_port:
        description:
        - Port number AXAPI is running on
        required: True
    partition:
        description:
        - Destination/target partition for object/command
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
            shared_rport_health_check:
                description:
                - "Reference a health-check from shared partition"
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
            support_http2:
                description:
                - "Starting HTTP/2 with Prior Knowledge"
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
            rport_health_check_shared:
                description:
                - "Health Check (Monitor Name)"
            conn_resume:
                description:
                - "Connection Resume"
            user_tag:
                description:
                - "Customized tag"
            range:
                description:
                - "Port range (Port range value - used for vip-to-rport-mapping and vport-rport range mapping)"
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
    slow_start:
        description:
        - "Slowly ramp up the connection number after server is up (start from 128, then double every 10 sec till 4096)"
        required: False
    weight:
        description:
        - "Weight for this Real Server (Connection Weight)"
        required: False
    spoofing_cache:
        description:
        - "This server is a spoofing cache"
        required: False
    resolve_as:
        description:
        - "'resolve-to-ipv4'= Use A Query only to resolve FQDN; 'resolve-to-ipv6'= Use AAAA Query only to resolve FQDN; 'resolve-to-ipv4-and-ipv6'= Use A as well as AAAA Query to resolve FQDN; "
        required: False
    conn_limit:
        description:
        - "Connection Limit"
        required: False
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
    health_check_shared:
        description:
        - "Health Check Monitor (Health monitor name)"
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
    shared_partition_health_check:
        description:
        - "Reference a health-check from shared partition"
        required: False
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
AVAILABLE_PROPERTIES = ["action","alternate_server","conn_limit","conn_resume","extended_stats","external_ip","fqdn_name","health_check","health_check_disable","health_check_shared","host","ipv6","name","no_logging","port_list","resolve_as","sampling_enable","server_ipv6_addr","shared_partition_health_check","slow_start","spoofing_cache","stats_data_action","template_server","user_tag","uuid","weight",]

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
        health_check_disable=dict(type='bool',),
        port_list=dict(type='list',health_check_disable=dict(type='bool',),protocol=dict(type='str',required=True,choices=['tcp','udp']),weight=dict(type='int',),shared_rport_health_check=dict(type='bool',),stats_data_action=dict(type='str',choices=['stats-data-enable','stats-data-disable']),health_check_follow_port=dict(type='int',),template_port=dict(type='str',),conn_limit=dict(type='int',),uuid=dict(type='str',),support_http2=dict(type='bool',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','curr_req','total_req','total_req_succ','total_fwd_bytes','total_fwd_pkts','total_rev_bytes','total_rev_pkts','total_conn','last_total_conn','peak_conn','es_resp_200','es_resp_300','es_resp_400','es_resp_500','es_resp_other','es_req_count','es_resp_count','es_resp_invalid_http','total_rev_pkts_inspected','total_rev_pkts_inspected_good_status_code','response_time','fastest_rsp_time','slowest_rsp_time','curr_ssl_conn','total_ssl_conn','resp-count','resp-1xx','resp-2xx','resp-3xx','resp-4xx','resp-5xx','resp-other','resp-latency','curr_pconn'])),no_ssl=dict(type='bool',),follow_port_protocol=dict(type='str',choices=['tcp','udp']),template_server_ssl=dict(type='str',),alternate_port=dict(type='list',alternate_name=dict(type='str',),alternate=dict(type='int',),alternate_server_port=dict(type='int',)),port_number=dict(type='int',required=True,),extended_stats=dict(type='bool',),rport_health_check_shared=dict(type='str',),conn_resume=dict(type='int',),user_tag=dict(type='str',),range=dict(type='int',),auth_cfg=dict(type='dict',service_principal_name=dict(type='str',)),action=dict(type='str',choices=['enable','disable','disable-with-health-check']),health_check=dict(type='str',),no_logging=dict(type='bool',)),
        stats_data_action=dict(type='str',choices=['stats-data-enable','stats-data-disable']),
        slow_start=dict(type='bool',),
        weight=dict(type='int',),
        spoofing_cache=dict(type='bool',),
        resolve_as=dict(type='str',choices=['resolve-to-ipv4','resolve-to-ipv6','resolve-to-ipv4-and-ipv6']),
        conn_limit=dict(type='int',),
        uuid=dict(type='str',),
        fqdn_name=dict(type='str',),
        external_ip=dict(type='str',),
        health_check_shared=dict(type='str',),
        ipv6=dict(type='str',),
        template_server=dict(type='str',),
        server_ipv6_addr=dict(type='str',),
        alternate_server=dict(type='list',alternate_name=dict(type='str',),alternate=dict(type='int',)),
        shared_partition_health_check=dict(type='bool',),
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
    requires_one_of = sorted(['host','fqdn_host','server_ipv6_addr'])
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
        return False

def create(module, result):
    payload = build_json("server", module)
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
    payload = build_json("server", module)
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
    payload = build_json("server", module)
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