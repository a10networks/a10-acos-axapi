#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_gslb_policy
description:
    - Policy for GSLB zone, service or geo-location
short_description: Configures A10 gslb.policy
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
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            metric_list:
                description:
                - "Field metric_list"
            name:
                description:
                - "Specify policy name"
    weighted_ip_enable:
        description:
        - "Enable Select Service-IP by weighted preference"
        required: False
    alias_admin_preference:
        description:
        - "Select alias name having maximum admin preference"
        required: False
    admin_ip_top_only:
        description:
        - "Return highest priority server only"
        required: False
    least_response:
        description:
        - "Least response selection"
        required: False
    auto_map:
        description:
        - "Field auto_map"
        required: False
        suboptions:
            all:
                description:
                - "All modules"
            ttl:
                description:
                - "Specify Auto Map TTL (TTL, default is 300)"
            uuid:
                description:
                - "uuid of the object"
            module_type:
                description:
                - "Field module_type"
            module_disable:
                description:
                - "Specify Disable Auto Map Module"
    bw_cost_fail_break:
        description:
        - "Break when exceed limit"
        required: False
    metric_fail_break:
        description:
        - "Break if no valid Service-IP"
        required: False
    edns:
        description:
        - "Field edns"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            client_subnet_geographic:
                description:
                - "Use client subnet for geo-location"
    active_rdt:
        description:
        - "Field active_rdt"
        required: False
        suboptions:
            ignore_id:
                description:
                - "Ignore IP Address specified in IP List by ID"
            keep_tracking:
                description:
                - "Keep tracking client even round-delay-time samples are ready"
            enable:
                description:
                - "Enable the active rdt"
            timeout:
                description:
                - "Specify timeout if round-delay-time samples are not ready (Specify timeout, unit=sec,default is 3)"
            skip:
                description:
                - "Skip query if round-delay-time samples are not ready (Specify maximum skip count,default is 3)"
            fail_break:
                description:
                - "Break when no valid RDT"
            controller:
                description:
                - "Active round-delay-time by controller"
            limit:
                description:
                - "Limit of allowed RDT, default is 16383 (Limit, unit= millisecond)"
            samples:
                description:
                - "Specify samples number for round-delay-time (Number of samples,default is 5)"
            proto_rdt_enable:
                description:
                - "Enable the round-delay-time to the controller"
            single_shot:
                description:
                - "Single Shot RDT"
            difference:
                description:
                - "The difference between the round-delay-time, default is 0"
            tolerance:
                description:
                - "The difference percentage between the round-delay-time, default is 10 (Tolerance)"
            uuid:
                description:
                - "uuid of the object"
    round_robin:
        description:
        - "Round robin selection, enabled by default"
        required: False
    admin_preference:
        description:
        - "Select Service-IP for the device having maximum admin preference"
        required: False
    capacity:
        description:
        - "Field capacity"
        required: False
        suboptions:
            threshold:
                description:
                - "Specify capacity threshold, default is 90"
            capacity_enable:
                description:
                - "Enable capacity"
            capacity_fail_break:
                description:
                - "Break when exceed threshold"
            uuid:
                description:
                - "uuid of the object"
    uuid:
        description:
        - "uuid of the object"
        required: False
    active_servers_fail_break:
        description:
        - "Break when no active server"
        required: False
    metric_type:
        description:
        - "Field metric_type"
        required: False
    num_session_tolerance:
        description:
        - "The difference between the available sessions, default is 10 (Tolerance)"
        required: False
    name:
        description:
        - "Specify policy name"
        required: True
    dns:
        description:
        - "Field dns"
        required: False
        suboptions:
            server_mode_only:
                description:
                - "Only run GSLB as DNS server mode"
            external_soa:
                description:
                - "Return DNS response with external SOA Record"
            server_sec:
                description:
                - "Provide DNSSEC support"
            sticky_ipv6_mask:
                description:
                - "Specify IPv6 mask length, default is 128"
            sticky:
                description:
                - "Make DNS Record sticky for certain time"
            delegation:
                description:
                - "Zone Delegation"
            active_only_fail_safe:
                description:
                - "Continue if no candidate"
            cname_detect:
                description:
                - "Apply GSLB for DNS Server response when service is Canonical Name (CNAME)"
            ttl:
                description:
                - "Specify the TTL value contained in DNS record (TTL value, unit= second, default is 10)"
            dynamic_preference:
                description:
                - "Make dynamically change the preference"
            use_server_ttl:
                description:
                - "Use DNS Server Response TTL value in GSLB Proxy mode"
            server_ptr:
                description:
                - "Provide PTR Records"
            selected_only:
                description:
                - "Only keep selected servers"
            ip_replace:
                description:
                - "Replace DNS Server Response with GSLB Service-IPs"
            dns_addition_mx:
                description:
                - "Append MX Records in Addition Section"
            backup_alias:
                description:
                - "Return alias name when fail"
            server_any:
                description:
                - "Provide All Records"
            hint:
                description:
                - "'none'= None; 'answer'= Append Hint Records in DNS Answer Section; 'addition'= Append Hint Records in DNS Addition Section; "
            cache:
                description:
                - "Cache DNS Server response"
            external_ip:
                description:
                - "Return DNS response with external IP address"
            server_txt:
                description:
                - "Provide TXT Records"
            server_addition_mx:
                description:
                - "Append MX Records in Addition Section"
            aging_time:
                description:
                - "Specify aging-time, default is TTL in DNS record, unit= second (Aging time, default 0 means using TTL in DNS record as aging time)"
            block_action:
                description:
                - "Specify Action"
            template:
                description:
                - "Logging template (Logging Template Name)"
            ipv6:
                description:
                - "Field ipv6"
            selected_only_value:
                description:
                - "Answer Number"
            geoloc_action:
                description:
                - "Apply DNS action by geo-location"
            server_ns:
                description:
                - "Provide NS Records"
            action_type:
                description:
                - "'drop'= Drop query; 'reject'= Send refuse response; 'ignore'= Send empty response; "
            server_naptr:
                description:
                - "Provide NAPTR Records"
            active_only:
                description:
                - "Only keep active servers"
            block_value:
                description:
                - "Field block_value"
            server_srv:
                description:
                - "Provide SRV Records"
            server_auto_ptr:
                description:
                - "Provide PTR Records automatically"
            server_cname:
                description:
                - "Provide CNAME Records"
            server_authoritative:
                description:
                - "As authoritative server"
            server_full_list:
                description:
                - "Append All A Records in Authoritative Section"
            server_any_with_metric:
                description:
                - "Provide All Records with GSLB Metrics applied to A/AAAA Records"
            dns_auto_map:
                description:
                - "Automatically build DNS Infrastructure"
            block_type:
                description:
                - "Field block_type"
            sticky_mask:
                description:
                - "Specify IP mask, default is /32"
            geoloc_alias:
                description:
                - "Return alias name by geo-location"
            logging:
                description:
                - "'none'= None; 'query'= DNS Query; 'response'= DNS Response; 'both'= Both DNS Query and Response; "
            backup_server:
                description:
                - "Return fallback server when fail"
            sticky_aging_time:
                description:
                - "Specify aging-time, unit= min, default is 5 (Aging time)"
            geoloc_policy:
                description:
                - "Apply different policy by geo-location"
            uuid:
                description:
                - "uuid of the object"
            server:
                description:
                - "Run GSLB as DNS server mode"
            dynamic_weight:
                description:
                - "dynamically change the weight"
            server_ns_list:
                description:
                - "Append All NS Records in Authoritative Section"
            server_auto_ns:
                description:
                - "Provide A-Records for NS-Records automatically"
            action:
                description:
                - "Apply DNS action for service"
            proxy_block_port_range_list:
                description:
                - "Field proxy_block_port_range_list"
            server_mx:
                description:
                - "Provide MX Records"
    weighted_ip_total_hits:
        description:
        - "Weighted by total hits"
        required: False
    weighted_site_total_hits:
        description:
        - "Weighted by total hits"
        required: False
    ip_list:
        description:
        - "Specify IP List (IP List Name)"
        required: False
    ordered_ip_top_only:
        description:
        - "Return highest priority server only"
        required: False
    weighted_site_enable:
        description:
        - "Enable Select Service-IP by weighted site preference"
        required: False
    metric_force_check:
        description:
        - "Always check Service-IP for all enabled metrics"
        required: False
    admin_ip_enable:
        description:
        - "Enable admin ip"
        required: False
    geo_location_list:
        description:
        - "Field geo_location_list"
        required: False
        suboptions:
            ip_multiple_fields:
                description:
                - "Field ip_multiple_fields"
            uuid:
                description:
                - "uuid of the object"
            name:
                description:
                - "Specify geo-location name, section range is (1-15)"
            user_tag:
                description:
                - "Customized tag"
            ipv6_multiple_fields:
                description:
                - "Field ipv6_multiple_fields"
    weighted_alias:
        description:
        - "Select alias name by weighted preference"
        required: False
    geo_location_match:
        description:
        - "Field geo_location_match"
        required: False
        suboptions:
            match_first:
                description:
                - "'global'= Global Geo-location; 'policy'= Policy Geo-location; "
            uuid:
                description:
                - "uuid of the object"
            geo_type_overlap:
                description:
                - "'global'= Global Geo-location; 'policy'= Policy Geo-location; "
            overlap:
                description:
                - "Enable overlap mode to do longest match"
    num_session_enable:
        description:
        - "Enable Select Service-IP for device having maximum number of available sessions"
        required: False
    bw_cost_enable:
        description:
        - "Enable bw cost"
        required: False
    active_servers_enable:
        description:
        - "Enable Select Service-IP with the highest number of active servers"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    amount_first:
        description:
        - "Select record based on the amount of available service-ip"
        required: False
    connection_load:
        description:
        - "Field connection_load"
        required: False
        suboptions:
            uuid:
                description:
                - "uuid of the object"
            connection_load_enable:
                description:
                - "Enable connection-load"
            connection_load_interval:
                description:
                - "Interval between two samples, Unit= second (Interval value,default is 5)"
            limit:
                description:
                - "Limit of maxinum connection load, default is unlimited"
            connection_load_samples:
                description:
                - "Specify samples for connection-load (Number of samples used to calculate the connection load, default is 5)"
            connection_load_limit:
                description:
                - "The value of the connection-load limit, default is unlimited"
            connection_load_fail_break:
                description:
                - "Break when exceed limit"
    metric_order:
        description:
        - "Specify order of metric"
        required: False
    health_check_preference_enable:
        description:
        - "Check health preference"
        required: False
    health_preference_top:
        description:
        - "Only keep top n"
        required: False
    health_check:
        description:
        - "Select Service-IP by health status"
        required: False
    geographic:
        description:
        - "Select Service-IP by geographic"
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
AVAILABLE_PROPERTIES = ["active_rdt","active_servers_enable","active_servers_fail_break","admin_ip_enable","admin_ip_top_only","admin_preference","alias_admin_preference","amount_first","auto_map","bw_cost_enable","bw_cost_fail_break","capacity","connection_load","dns","edns","geo_location_list","geo_location_match","geographic","health_check","health_check_preference_enable","health_preference_top","ip_list","least_response","metric_fail_break","metric_force_check","metric_order","metric_type","name","num_session_enable","num_session_tolerance","oper","ordered_ip_top_only","round_robin","user_tag","uuid","weighted_alias","weighted_ip_enable","weighted_ip_total_hits","weighted_site_enable","weighted_site_total_hits",]

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
        oper=dict(type='dict', metric_list=dict(type='list', ntype=dict(type='str', ), order=dict(type='int', )), name=dict(type='str', required=True, )),
        weighted_ip_enable=dict(type='bool', ),
        alias_admin_preference=dict(type='bool', ),
        admin_ip_top_only=dict(type='bool', ),
        least_response=dict(type='bool', ),
        auto_map=dict(type='dict', all=dict(type='bool', ), ttl=dict(type='int', ), uuid=dict(type='str', ), module_type=dict(type='str', choices=['slb-virtual-server', 'slb-device', 'slb-server', 'gslb-service-ip', 'gslb-site', 'gslb-group', 'hostname']), module_disable=dict(type='bool', )),
        bw_cost_fail_break=dict(type='bool', ),
        metric_fail_break=dict(type='bool', ),
        edns=dict(type='dict', uuid=dict(type='str', ), client_subnet_geographic=dict(type='bool', )),
        active_rdt=dict(type='dict', ignore_id=dict(type='int', ), keep_tracking=dict(type='bool', ), enable=dict(type='bool', ), timeout=dict(type='int', ), skip=dict(type='int', ), fail_break=dict(type='bool', ), controller=dict(type='bool', ), limit=dict(type='int', ), samples=dict(type='int', ), proto_rdt_enable=dict(type='bool', ), single_shot=dict(type='bool', ), difference=dict(type='int', ), tolerance=dict(type='int', ), uuid=dict(type='str', )),
        round_robin=dict(type='bool', ),
        admin_preference=dict(type='bool', ),
        capacity=dict(type='dict', threshold=dict(type='int', ), capacity_enable=dict(type='bool', ), capacity_fail_break=dict(type='bool', ), uuid=dict(type='str', )),
        uuid=dict(type='str', ),
        active_servers_fail_break=dict(type='bool', ),
        metric_type=dict(type='str', choices=['health-check', 'weighted-ip', 'weighted-site', 'capacity', 'active-servers', 'active-rdt', 'geographic', 'connection-load', 'num-session', 'admin-preference', 'bw-cost', 'least-response', 'admin-ip']),
        num_session_tolerance=dict(type='int', ),
        name=dict(type='str', required=True, ),
        dns=dict(type='dict', server_mode_only=dict(type='bool', ), external_soa=dict(type='bool', ), server_sec=dict(type='bool', ), sticky_ipv6_mask=dict(type='int', ), sticky=dict(type='bool', ), delegation=dict(type='bool', ), active_only_fail_safe=dict(type='bool', ), cname_detect=dict(type='bool', ), ttl=dict(type='int', ), dynamic_preference=dict(type='bool', ), use_server_ttl=dict(type='bool', ), server_ptr=dict(type='bool', ), selected_only=dict(type='bool', ), ip_replace=dict(type='bool', ), dns_addition_mx=dict(type='bool', ), backup_alias=dict(type='bool', ), server_any=dict(type='bool', ), hint=dict(type='str', choices=['none', 'answer', 'addition']), cache=dict(type='bool', ), external_ip=dict(type='bool', ), server_txt=dict(type='bool', ), server_addition_mx=dict(type='bool', ), aging_time=dict(type='int', ), block_action=dict(type='bool', ), template=dict(type='str', ), ipv6=dict(type='list', dns_ipv6_mapping_type=dict(type='str', choices=['addition', 'answer', 'exclusive', 'replace']), dns_ipv6_option=dict(type='str', choices=['mix', 'smart', 'mapping'])), selected_only_value=dict(type='int', ), geoloc_action=dict(type='bool', ), server_ns=dict(type='bool', ), action_type=dict(type='str', choices=['drop', 'reject', 'ignore']), server_naptr=dict(type='bool', ), active_only=dict(type='bool', ), block_value=dict(type='list', block_value=dict(type='int', )), server_srv=dict(type='bool', ), server_auto_ptr=dict(type='bool', ), server_cname=dict(type='bool', ), server_authoritative=dict(type='bool', ), server_full_list=dict(type='bool', ), server_any_with_metric=dict(type='bool', ), dns_auto_map=dict(type='bool', ), block_type=dict(type='str', choices=['a', 'aaaa', 'ns', 'mx', 'srv', 'cname', 'ptr', 'soa', 'txt']), sticky_mask=dict(type='str', ), geoloc_alias=dict(type='bool', ), logging=dict(type='str', choices=['none', 'query', 'response', 'both']), backup_server=dict(type='bool', ), sticky_aging_time=dict(type='int', ), geoloc_policy=dict(type='bool', ), uuid=dict(type='str', ), server=dict(type='bool', ), dynamic_weight=dict(type='bool', ), server_ns_list=dict(type='bool', ), server_auto_ns=dict(type='bool', ), action=dict(type='bool', ), proxy_block_port_range_list=dict(type='list', proxy_block_range_from=dict(type='int', ), proxy_block_range_to=dict(type='int', )), server_mx=dict(type='bool', )),
        weighted_ip_total_hits=dict(type='bool', ),
        weighted_site_total_hits=dict(type='bool', ),
        ip_list=dict(type='str', ),
        ordered_ip_top_only=dict(type='bool', ),
        weighted_site_enable=dict(type='bool', ),
        metric_force_check=dict(type='bool', ),
        admin_ip_enable=dict(type='bool', ),
        geo_location_list=dict(type='list', ip_multiple_fields=dict(type='list', ip_addr2_sub=dict(type='str', ), ip_sub=dict(type='str', ), ip_mask_sub=dict(type='str', )), uuid=dict(type='str', ), name=dict(type='str', required=True, ), user_tag=dict(type='str', ), ipv6_multiple_fields=dict(type='list', ipv6_mask_sub=dict(type='int', ), ipv6_sub=dict(type='str', ), ipv6_addr2_sub=dict(type='str', ))),
        weighted_alias=dict(type='bool', ),
        geo_location_match=dict(type='dict', match_first=dict(type='str', choices=['global', 'policy']), uuid=dict(type='str', ), geo_type_overlap=dict(type='str', choices=['global', 'policy']), overlap=dict(type='bool', )),
        num_session_enable=dict(type='bool', ),
        bw_cost_enable=dict(type='bool', ),
        active_servers_enable=dict(type='bool', ),
        user_tag=dict(type='str', ),
        amount_first=dict(type='bool', ),
        connection_load=dict(type='dict', uuid=dict(type='str', ), connection_load_enable=dict(type='bool', ), connection_load_interval=dict(type='int', ), limit=dict(type='bool', ), connection_load_samples=dict(type='int', ), connection_load_limit=dict(type='int', ), connection_load_fail_break=dict(type='bool', )),
        metric_order=dict(type='bool', ),
        health_check_preference_enable=dict(type='bool', ),
        health_preference_top=dict(type='int', ),
        health_check=dict(type='bool', ),
        geographic=dict(type='bool', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/policy/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

    return url_base.format(**f_dict)

def oper_url(module):
    """Return the URL for operational data of an existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/oper"

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

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
    url_base = "/axapi/v3/gslb/policy/{name}"

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
        for k, v in payload["policy"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["policy"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["policy"][k] = v
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
    payload = build_json("policy", module)
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
        elif module.params.get("get_type") == "oper":
            result["result"] = get_oper(module)
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