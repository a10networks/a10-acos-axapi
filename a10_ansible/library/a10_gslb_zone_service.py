#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_gslb_zone_service
description:
    - Service information for the GSLB zone
short_description: Configures A10 gslb.zone.service
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
    zone_name:
        description:
        - Key to identify parent object
    oper:
        description:
        - "Field oper"
        required: False
        suboptions:
            cache_list:
                description:
                - "Field cache_list"
            dns_ns_record_list:
                description:
                - "Field dns_ns_record_list"
            total_sessions:
                description:
                - "Field total_sessions"
            service_port:
                description:
                - "Port number of the service"
            dns_mx_record_list:
                description:
                - "Field dns_mx_record_list"
            state:
                description:
                - "Field state"
            session_list:
                description:
                - "Field session_list"
            service_name:
                description:
                - "Specify the service name for the zone, * for wildcard"
            matched:
                description:
                - "Field matched"
    dns_ptr_record_list:
        description:
        - "Field dns_ptr_record_list"
        required: False
        suboptions:
            ptr_name:
                description:
                - "Specify Domain Name"
            ttl:
                description:
                - "Specify TTL"
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
    health_check_port:
        description:
        - "Field health_check_port"
        required: False
        suboptions:
            health_check_port:
                description:
                - "Check Related Port Status (Port Number)"
    service_port:
        description:
        - "Port number of the service"
        required: True
    dns_record_list:
        description:
        - "Field dns_record_list"
        required: False
        suboptions:
            ntype:
                description:
                - "Specify DNS Type"
            data:
                description:
                - "Specify DNS Data"
            uuid:
                description:
                - "uuid of the object"
    geo_location_list:
        description:
        - "Field geo_location_list"
        required: False
        suboptions:
            action_type:
                description:
                - "'allow'= Allow query from this geo-location; 'drop'= Drop query from this geo-location; 'forward'= Forward packet for this geo-location; 'ignore'= Send empty response to this geo-location; 'reject'= Send refuse response to this geo-location; "
            uuid:
                description:
                - "uuid of the object"
            user_tag:
                description:
                - "Customized tag"
            alias:
                description:
                - "Field alias"
            geo_name:
                description:
                - "Specify the geo-location"
            policy:
                description:
                - "Policy for this geo-location (Specify the policy name)"
            forward_type:
                description:
                - "'both'= Forward both query and response; 'query'= Forward query from this geo-location; 'response'= Forward response to this geo-location; "
            action:
                description:
                - "Action for this geo-location"
    action:
        description:
        - "'drop'= Drop query; 'forward'= Forward packet; 'ignore'= Send empty response; 'reject'= Send refuse response; "
        required: False
    disable:
        description:
        - "Disable"
        required: False
    service_name:
        description:
        - "Specify the service name for the zone, * for wildcard"
        required: True
    health_check_gateway:
        description:
        - "'enable'= Enable Gateway Status Check; 'disable'= Disable Gateway Status Check; "
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            dns_a_record:
                description:
                - "Field dns_a_record"
            received_query:
                description:
                - "Number of DNS queries received for the service"
            dns_cname_record_list:
                description:
                - "Field dns_cname_record_list"
            dns_ns_record_list:
                description:
                - "Field dns_ns_record_list"
            dns_txt_record_list:
                description:
                - "Field dns_txt_record_list"
            sent_response:
                description:
                - "Number of DNS replies sent to clients for the service"
            dns_mx_record_list:
                description:
                - "Field dns_mx_record_list"
            sticky_mode_response:
                description:
                - "Number of DNS replies sent to clients by the ACOS device to keep the clients on the same site. (This statistic applies only if "
            server_mode_response:
                description:
                - "Number of DNS replies sent to clients by the ACOS device as a DNS server for the service. (This statistic applies only if the D"
            cache_mode_response:
                description:
                - "Number of cached DNS replies sent to clients by the ACOS device for the service. (This statistic applies only if the DNS cache "
            service_port:
                description:
                - "Port number of the service"
            dns_srv_record_list:
                description:
                - "Field dns_srv_record_list"
            service_name:
                description:
                - "Specify the service name for the zone, * for wildcard"
            dns_ptr_record_list:
                description:
                - "Field dns_ptr_record_list"
            backup_mode_response:
                description:
                - "help Number of DNS replies sent to clients by the ACOS device in backup mode"
            dns_naptr_record_list:
                description:
                - "Field dns_naptr_record_list"
            proxy_mode_response:
                description:
                - "Number of DNS replies sent to clients by the ACOS device as a DNS proxy for the service"
    dns_cname_record_list:
        description:
        - "Field dns_cname_record_list"
        required: False
        suboptions:
            alias_name:
                description:
                - "Specify the alias name"
            uuid:
                description:
                - "uuid of the object"
            as_backup:
                description:
                - "As backup when fail"
            weight:
                description:
                - "Specify Weight, default is 1"
            sampling_enable:
                description:
                - "Field sampling_enable"
            admin_preference:
                description:
                - "Specify Administrative Preference, default is 100"
    dns_a_record:
        description:
        - "Field dns_a_record"
        required: False
        suboptions:
            dns_a_record_ipv6_list:
                description:
                - "Field dns_a_record_ipv6_list"
            dns_a_record_ipv4_list:
                description:
                - "Field dns_a_record_ipv4_list"
            dns_a_record_srv_list:
                description:
                - "Field dns_a_record_srv_list"
    forward_type:
        description:
        - "'both'= Forward both query and response; 'query'= Forward query; 'response'= Forward response; "
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    dns_ns_record_list:
        description:
        - "Field dns_ns_record_list"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            ns_name:
                description:
                - "Specify Domain Name"
            uuid:
                description:
                - "uuid of the object"
            ttl:
                description:
                - "Specify TTL"
    dns_txt_record_list:
        description:
        - "Field dns_txt_record_list"
        required: False
        suboptions:
            record_name:
                description:
                - "Specify the Object Name for TXT Data"
            ttl:
                description:
                - "Specify TTL"
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
            txt_data:
                description:
                - "Specify TXT Data"
    dns_mx_record_list:
        description:
        - "Field dns_mx_record_list"
        required: False
        suboptions:
            priority:
                description:
                - "Specify Priority"
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "uuid of the object"
            mx_name:
                description:
                - "Specify Domain Name"
            ttl:
                description:
                - "Specify TTL"
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
                - "'all'= all; 'received-query'= Number of DNS queries received for the service; 'sent-response'= Number of DNS replies sent to clients for the service; 'proxy-mode-response'= Number of DNS replies sent to clients by the ACOS device as a DNS proxy for the service; 'cache-mode-response'= Number of cached DNS replies sent to clients by the ACOS device for the service. (This statistic applies only if the DNS cache; 'server-mode-response'= Number of DNS replies sent to clients by the ACOS device as a DNS server for the service. (This statistic applies only if the D; 'sticky-mode-response'= Number of DNS replies sent to clients by the ACOS device to keep the clients on the same site. (This statistic applies only if; 'backup-mode-response'= help Number of DNS replies sent to clients by the ACOS device in backup mode; "
    dns_srv_record_list:
        description:
        - "Field dns_srv_record_list"
        required: False
        suboptions:
            srv_name:
                description:
                - "Specify Domain Name"
            uuid:
                description:
                - "uuid of the object"
            weight:
                description:
                - "Specify Weight, default is 10"
            priority:
                description:
                - "Specify Priority"
            sampling_enable:
                description:
                - "Field sampling_enable"
            ttl:
                description:
                - "Specify TTL"
            port:
                description:
                - "Specify Port (Port Number)"
    policy:
        description:
        - "Specify policy for this service (Specify policy name)"
        required: False
    dns_naptr_record_list:
        description:
        - "Field dns_naptr_record_list"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            naptr_target:
                description:
                - "Specify the replacement or regular expression"
            service_proto:
                description:
                - "Specify Service and Protocol"
            flag:
                description:
                - "Specify the flag (e.g., a, s). Default is empty flag"
            preference:
                description:
                - "Specify Preference"
            ttl:
                description:
                - "Specify TTL"
            regexp:
                description:
                - "Return the regular expression"
            order:
                description:
                - "Specify Order"
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
AVAILABLE_PROPERTIES = ["action","disable","dns_a_record","dns_cname_record_list","dns_mx_record_list","dns_naptr_record_list","dns_ns_record_list","dns_ptr_record_list","dns_record_list","dns_srv_record_list","dns_txt_record_list","forward_type","geo_location_list","health_check_gateway","health_check_port","oper","policy","sampling_enable","service_name","service_port","stats","user_tag","uuid",]

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
        oper=dict(type='dict',cache_list=dict(type='list',cache_ttl=dict(type='int',),additional_records=dict(type='int',),answer_records=dict(type='int',),cache_dns_flag=dict(type='str',),question_records=dict(type='int',),alias=dict(type='str',),cache_length=dict(type='int',),authority_records=dict(type='int',)),dns_ns_record_list=dict(type='list',oper=dict(type='dict',last_server=dict(type='str',)),ns_name=dict(type='str',required=True,)),total_sessions=dict(type='int',),service_port=dict(type='int',required=True,),dns_mx_record_list=dict(type='list',oper=dict(type='dict',last_server=dict(type='str',)),mx_name=dict(type='str',required=True,)),state=dict(type='str',),session_list=dict(type='list',aging=dict(type='int',),hits=dict(type='int',),update=dict(type='int',),client=dict(type='str',),last_second_hits=dict(type='int',),mode=dict(type='str',),ttl=dict(type='str',),best=dict(type='str',)),service_name=dict(type='str',required=True,),matched=dict(type='int',)),
        dns_ptr_record_list=dict(type='list',ptr_name=dict(type='str',required=True,),ttl=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),uuid=dict(type='str',)),
        health_check_port=dict(type='list',health_check_port=dict(type='int',)),
        service_port=dict(type='int',required=True,),
        dns_record_list=dict(type='list',ntype=dict(type='int',required=True,),data=dict(type='str',),uuid=dict(type='str',)),
        geo_location_list=dict(type='list',action_type=dict(type='str',choices=['allow','drop','forward','ignore','reject']),uuid=dict(type='str',),user_tag=dict(type='str',),alias=dict(type='list',alias=dict(type='str',)),geo_name=dict(type='str',required=True,),policy=dict(type='str',),forward_type=dict(type='str',choices=['both','query','response']),action=dict(type='bool',)),
        action=dict(type='str',choices=['drop','forward','ignore','reject']),
        disable=dict(type='bool',),
        service_name=dict(type='str',required=True,),
        health_check_gateway=dict(type='str',choices=['enable','disable']),
        stats=dict(type='dict',dns_a_record=dict(type='dict',),received_query=dict(type='str',),dns_cname_record_list=dict(type='list',alias_name=dict(type='str',required=True,),stats=dict(type='dict',cname_hits=dict(type='str',))),dns_ns_record_list=dict(type='list',ns_name=dict(type='str',required=True,),stats=dict(type='dict',hits=dict(type='str',))),dns_txt_record_list=dict(type='list',record_name=dict(type='str',required=True,),stats=dict(type='dict',hits=dict(type='str',))),sent_response=dict(type='str',),dns_mx_record_list=dict(type='list',stats=dict(type='dict',hits=dict(type='str',)),mx_name=dict(type='str',required=True,)),sticky_mode_response=dict(type='str',),server_mode_response=dict(type='str',),cache_mode_response=dict(type='str',),service_port=dict(type='int',required=True,),dns_srv_record_list=dict(type='list',srv_name=dict(type='str',required=True,),stats=dict(type='dict',hits=dict(type='str',)),port=dict(type='int',required=True,)),service_name=dict(type='str',required=True,),dns_ptr_record_list=dict(type='list',ptr_name=dict(type='str',required=True,),stats=dict(type='dict',hits=dict(type='str',))),backup_mode_response=dict(type='str',),dns_naptr_record_list=dict(type='list',flag=dict(type='str',required=True,),stats=dict(type='dict',naptr_hits=dict(type='str',)),service_proto=dict(type='str',required=True,),naptr_target=dict(type='str',required=True,)),proxy_mode_response=dict(type='str',)),
        dns_cname_record_list=dict(type='list',alias_name=dict(type='str',required=True,),uuid=dict(type='str',),as_backup=dict(type='bool',),weight=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','cname-hits'])),admin_preference=dict(type='int',)),
        dns_a_record=dict(type='dict',dns_a_record_ipv6_list=dict(type='list',as_replace=dict(type='bool',),dns_a_record_ipv6=dict(type='str',required=True,),as_backup=dict(type='bool',),weight=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),disable=dict(type='bool',),static=dict(type='bool',),ttl=dict(type='int',),no_resp=dict(type='bool',),admin_ip=dict(type='int',),uuid=dict(type='str',)),dns_a_record_ipv4_list=dict(type='list',as_replace=dict(type='bool',),dns_a_record_ip=dict(type='str',required=True,),as_backup=dict(type='bool',),weight=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),disable=dict(type='bool',),static=dict(type='bool',),ttl=dict(type='int',),no_resp=dict(type='bool',),admin_ip=dict(type='int',),uuid=dict(type='str',)),dns_a_record_srv_list=dict(type='list',as_backup=dict(type='bool',),as_replace=dict(type='bool',),uuid=dict(type='str',),weight=dict(type='int',),svrname=dict(type='str',required=True,),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),disable=dict(type='bool',),static=dict(type='bool',),ttl=dict(type='int',),admin_ip=dict(type='int',),no_resp=dict(type='bool',))),
        forward_type=dict(type='str',choices=['both','query','response']),
        uuid=dict(type='str',),
        dns_ns_record_list=dict(type='list',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),ns_name=dict(type='str',required=True,),uuid=dict(type='str',),ttl=dict(type='int',)),
        dns_txt_record_list=dict(type='list',record_name=dict(type='str',required=True,),ttl=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),uuid=dict(type='str',),txt_data=dict(type='str',)),
        dns_mx_record_list=dict(type='list',priority=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),uuid=dict(type='str',),mx_name=dict(type='str',required=True,),ttl=dict(type='int',)),
        user_tag=dict(type='str',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','received-query','sent-response','proxy-mode-response','cache-mode-response','server-mode-response','sticky-mode-response','backup-mode-response'])),
        dns_srv_record_list=dict(type='list',srv_name=dict(type='str',required=True,),uuid=dict(type='str',),weight=dict(type='int',),priority=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),ttl=dict(type='int',),port=dict(type='int',required=True,)),
        policy=dict(type='str',),
        dns_naptr_record_list=dict(type='list',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','naptr-hits'])),naptr_target=dict(type='str',required=True,),service_proto=dict(type='str',required=True,),flag=dict(type='str',required=True,),preference=dict(type='int',),ttl=dict(type='int',),regexp=dict(type='bool',),order=dict(type='int',),uuid=dict(type='str',))
    ))
   
    # Parent keys
    rv.update(dict(
        zone_name=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/zone/{zone_name}/service/{service-port}+{service-name}"

    f_dict = {}
    f_dict["service-port"] = ""
    f_dict["service-name"] = ""
    f_dict["zone_name"] = module.params["zone_name"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/zone/{zone_name}/service/{service-port}+{service-name}"

    f_dict = {}
    f_dict["service-port"] = module.params["service_port"]
    f_dict["service-name"] = module.params["service_name"]
    f_dict["zone_name"] = module.params["zone_name"]

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
        for k, v in payload["service"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["service"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["service"][k] = v
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
    payload = build_json("service", module)
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