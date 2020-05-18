#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_gslb_zone
description:
    - Specify the DNS zone name for which global SLB is provided
short_description: Configures A10 gslb.zone
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
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
        required: True
    ansible_protocol:
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
            service_list:
                description:
                - "Field service_list"
            state:
                description:
                - "Field state"
            dns_mx_record_list:
                description:
                - "Field dns_mx_record_list"
            name:
                description:
                - "Specify the name for the DNS zone"
            dns_ns_record_list:
                description:
                - "Field dns_ns_record_list"
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            received_query:
                description:
                - "Total Number of DNS queries received for the zone"
            name:
                description:
                - "Specify the name for the DNS zone"
            dns_ns_record_list:
                description:
                - "Field dns_ns_record_list"
            sent_response:
                description:
                - "Total Number of DNS replies sent to clients for the zone"
            dns_mx_record_list:
                description:
                - "Field dns_mx_record_list"
            sticky_mode_response:
                description:
                - "Total Number of DNS replies sent to clients by the ACOS device to keep the clients on the same site. (This statistic applies on"
            server_mode_response:
                description:
                - "Total Number of DNS replies sent to clients by the ACOS device as a DNS server for the zone. (This statistic applies only if th"
            cache_mode_response:
                description:
                - "Total Number of cached DNS replies sent to clients by the ACOS device for the zone. (This statistic applies only if the DNS cac"
            backup_mode_response:
                description:
                - "Total Number of DNS replies sent to clients by the ACOS device in backup mode"
            service_list:
                description:
                - "Field service_list"
            proxy_mode_response:
                description:
                - "Total Number of DNS replies sent to clients by the ACOS device as a DNS proxy for the zone"
    name:
        description:
        - "Specify the name for the DNS zone"
        required: True
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
                - "'all'= all; 'received-query'= Total Number of DNS queries received for the zone; 'sent-response'= Total Number of DNS replies sent to clients for the zone; 'proxy-mode-response'= Total Number of DNS replies sent to clients by the ACOS device as a DNS proxy for the zone; 'cache-mode-response'= Total Number of cached DNS replies sent to clients by the ACOS device for the zone. (This statistic applies only if the DNS cac; 'server-mode-response'= Total Number of DNS replies sent to clients by the ACOS device as a DNS server for the zone. (This statistic applies only if th; 'sticky-mode-response'= Total Number of DNS replies sent to clients by the ACOS device to keep the clients on the same site. (This statistic applies on; 'backup-mode-response'= Total Number of DNS replies sent to clients by the ACOS device in backup mode; "
    disable:
        description:
        - "Disable all services in the GSLB zone"
        required: False
    template:
        description:
        - "Field template"
        required: False
        suboptions:
            dnssec:
                description:
                - "Specify DNSSEC template (Specify template name)"
    ttl:
        description:
        - "Specify the zone ttl value (TTL value, unit= second, default is 10)"
        required: False
    policy:
        description:
        - "Specify the policy for this zone (Specify policy name)"
        required: False
    use_server_ttl:
        description:
        - "Use DNS Server Response TTL value in GSLB Proxy mode"
        required: False
    dns_soa_record:
        description:
        - "Field dns_soa_record"
        required: False
        suboptions:
            retry:
                description:
                - "Specify Retry Time Interval, default is 900"
            soa_name:
                description:
                - "DNS Server Name"
            ex_retry:
                description:
                - "Specify Retry Time Interval, default is 900"
            ex_soa_ttl:
                description:
                - "Specify Negative caching TTL, default is Zone TTL"
            ex_serial:
                description:
                - "Specify Serial Number, default is Current Time (Time Interval)"
            refresh:
                description:
                - "Specify Refresh Time Interval, default is 3600"
            ex_mail:
                description:
                - "Mailbox"
            expire:
                description:
                - "Specify Expire Time Interval, default is 1209600"
            ex_expire:
                description:
                - "Specify Expire Time Interval, default is 1209600"
            external:
                description:
                - "Specify External SOA Record (DNS Server Name)"
            mail:
                description:
                - "Mailbox"
            serial:
                description:
                - "Specify Serial Number, default is Current Time (Time Interval)"
            ex_refresh:
                description:
                - "Specify Refresh Time Interval, default is 3600"
            soa_ttl:
                description:
                - "Specify Negative caching TTL, default is Zone TTL"
    service_list:
        description:
        - "Field service_list"
        required: False
        suboptions:
            dns_a_record:
                description:
                - "Field dns_a_record"
            forward_type:
                description:
                - "'both'= Forward both query and response; 'query'= Forward query; 'response'= Forward response; "
            uuid:
                description:
                - "uuid of the object"
            health_check_port:
                description:
                - "Field health_check_port"
            dns_txt_record_list:
                description:
                - "Field dns_txt_record_list"
            service_port:
                description:
                - "Port number of the service"
            dns_mx_record_list:
                description:
                - "Field dns_mx_record_list"
            dns_record_list:
                description:
                - "Field dns_record_list"
            user_tag:
                description:
                - "Customized tag"
            dns_ns_record_list:
                description:
                - "Field dns_ns_record_list"
            health_check_gateway:
                description:
                - "'enable'= Enable Gateway Status Check; 'disable'= Disable Gateway Status Check; "
            sampling_enable:
                description:
                - "Field sampling_enable"
            disable:
                description:
                - "Disable"
            dns_srv_record_list:
                description:
                - "Field dns_srv_record_list"
            service_name:
                description:
                - "Specify the service name for the zone, * for wildcard"
            policy:
                description:
                - "Specify policy for this service (Specify policy name)"
            dns_ptr_record_list:
                description:
                - "Field dns_ptr_record_list"
            dns_cname_record_list:
                description:
                - "Field dns_cname_record_list"
            action:
                description:
                - "'drop'= Drop query; 'forward'= Forward packet; 'ignore'= Send empty response; 'reject'= Send refuse response; "
            geo_location_list:
                description:
                - "Field geo_location_list"
            dns_naptr_record_list:
                description:
                - "Field dns_naptr_record_list"
    uuid:
        description:
        - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["disable","dns_mx_record_list","dns_ns_record_list","dns_soa_record","name","oper","policy","sampling_enable","service_list","stats","template","ttl","use_server_ttl","user_tag","uuid",]

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
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present', 'absent']),
        ansible_port=dict(type='int', required=True),
        ansible_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        oper=dict(type='dict', service_list=dict(type='list', oper=dict(type='dict', cache_list=dict(type='list', cache_ttl=dict(type='int', ), additional_records=dict(type='int', ), answer_records=dict(type='int', ), cache_dns_flag=dict(type='str', ), question_records=dict(type='int', ), alias=dict(type='str', ), cache_length=dict(type='int', ), authority_records=dict(type='int', )), total_sessions=dict(type='int', ), matched=dict(type='int', ), state=dict(type='str', ), session_list=dict(type='list', aging=dict(type='int', ), hits=dict(type='int', ), update=dict(type='int', ), client=dict(type='str', ), last_second_hits=dict(type='int', ), mode=dict(type='str', ), ttl=dict(type='str', ), best=dict(type='str', ))), service_port=dict(type='int', required=True, ), dns_mx_record_list=dict(type='list', oper=dict(type='dict', last_server=dict(type='str', )), mx_name=dict(type='str', required=True, )), dns_ns_record_list=dict(type='list', oper=dict(type='dict', last_server=dict(type='str', )), ns_name=dict(type='str', required=True, )), service_name=dict(type='str', required=True, )), state=dict(type='str', ), dns_mx_record_list=dict(type='list', oper=dict(type='dict', last_server=dict(type='str', )), mx_name=dict(type='str', required=True, )), name=dict(type='str', required=True, ), dns_ns_record_list=dict(type='list', oper=dict(type='dict', last_server=dict(type='str', )), ns_name=dict(type='str', required=True, ))),
        stats=dict(type='dict', received_query=dict(type='str', ), name=dict(type='str', required=True, ), dns_ns_record_list=dict(type='list', ns_name=dict(type='str', required=True, ), stats=dict(type='dict', hits=dict(type='str', ))), sent_response=dict(type='str', ), dns_mx_record_list=dict(type='list', stats=dict(type='dict', hits=dict(type='str', )), mx_name=dict(type='str', required=True, )), sticky_mode_response=dict(type='str', ), server_mode_response=dict(type='str', ), cache_mode_response=dict(type='str', ), backup_mode_response=dict(type='str', ), service_list=dict(type='list', dns_a_record=dict(type='dict', ), stats=dict(type='dict', received_query=dict(type='str', ), sent_response=dict(type='str', ), sticky_mode_response=dict(type='str', ), server_mode_response=dict(type='str', ), cache_mode_response=dict(type='str', ), backup_mode_response=dict(type='str', ), proxy_mode_response=dict(type='str', )), dns_ns_record_list=dict(type='list', ns_name=dict(type='str', required=True, ), stats=dict(type='dict', hits=dict(type='str', ))), dns_cname_record_list=dict(type='list', alias_name=dict(type='str', required=True, ), stats=dict(type='dict', cname_hits=dict(type='str', ))), dns_txt_record_list=dict(type='list', record_name=dict(type='str', required=True, ), stats=dict(type='dict', hits=dict(type='str', ))), service_port=dict(type='int', required=True, ), dns_mx_record_list=dict(type='list', stats=dict(type='dict', hits=dict(type='str', )), mx_name=dict(type='str', required=True, )), dns_srv_record_list=dict(type='list', srv_name=dict(type='str', required=True, ), stats=dict(type='dict', hits=dict(type='str', )), port=dict(type='int', required=True, )), service_name=dict(type='str', required=True, ), dns_ptr_record_list=dict(type='list', ptr_name=dict(type='str', required=True, ), stats=dict(type='dict', hits=dict(type='str', ))), dns_naptr_record_list=dict(type='list', flag=dict(type='str', required=True, ), stats=dict(type='dict', naptr_hits=dict(type='str', )), service_proto=dict(type='str', required=True, ), naptr_target=dict(type='str', required=True, ))), proxy_mode_response=dict(type='str', )),
        name=dict(type='str', required=True, ),
        dns_ns_record_list=dict(type='list', sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'hits'])), ns_name=dict(type='str', required=True, ), uuid=dict(type='str', ), ttl=dict(type='int', )),
        dns_mx_record_list=dict(type='list', priority=dict(type='int', ), sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'hits'])), uuid=dict(type='str', ), mx_name=dict(type='str', required=True, ), ttl=dict(type='int', )),
        user_tag=dict(type='str', ),
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'received-query', 'sent-response', 'proxy-mode-response', 'cache-mode-response', 'server-mode-response', 'sticky-mode-response', 'backup-mode-response'])),
        disable=dict(type='bool', ),
        template=dict(type='dict', dnssec=dict(type='str', )),
        ttl=dict(type='int', ),
        policy=dict(type='str', ),
        use_server_ttl=dict(type='bool', ),
        dns_soa_record=dict(type='dict', retry=dict(type='int', ), soa_name=dict(type='str', ), ex_retry=dict(type='int', ), ex_soa_ttl=dict(type='int', ), ex_serial=dict(type='int', ), refresh=dict(type='int', ), ex_mail=dict(type='str', ), expire=dict(type='int', ), ex_expire=dict(type='int', ), external=dict(type='str', ), mail=dict(type='str', ), serial=dict(type='int', ), ex_refresh=dict(type='int', ), soa_ttl=dict(type='int', )),
        service_list=dict(type='list', dns_a_record=dict(type='dict', dns_a_record_ipv6_list=dict(type='list', as_replace=dict(type='bool', ), dns_a_record_ipv6=dict(type='str', required=True, ), as_backup=dict(type='bool', ), weight=dict(type='int', ), sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'hits'])), disable=dict(type='bool', ), static=dict(type='bool', ), ttl=dict(type='int', ), no_resp=dict(type='bool', ), admin_ip=dict(type='int', ), uuid=dict(type='str', )), dns_a_record_ipv4_list=dict(type='list', as_replace=dict(type='bool', ), dns_a_record_ip=dict(type='str', required=True, ), as_backup=dict(type='bool', ), weight=dict(type='int', ), sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'hits'])), disable=dict(type='bool', ), static=dict(type='bool', ), ttl=dict(type='int', ), no_resp=dict(type='bool', ), admin_ip=dict(type='int', ), uuid=dict(type='str', )), dns_a_record_srv_list=dict(type='list', as_backup=dict(type='bool', ), as_replace=dict(type='bool', ), uuid=dict(type='str', ), weight=dict(type='int', ), svrname=dict(type='str', required=True, ), sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'hits'])), disable=dict(type='bool', ), static=dict(type='bool', ), ttl=dict(type='int', ), admin_ip=dict(type='int', ), no_resp=dict(type='bool', ))), forward_type=dict(type='str', choices=['both', 'query', 'response']), uuid=dict(type='str', ), health_check_port=dict(type='list', health_check_port=dict(type='int', )), dns_txt_record_list=dict(type='list', record_name=dict(type='str', required=True, ), ttl=dict(type='int', ), sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'hits'])), uuid=dict(type='str', ), txt_data=dict(type='str', )), service_port=dict(type='int', required=True, ), dns_mx_record_list=dict(type='list', priority=dict(type='int', ), sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'hits'])), uuid=dict(type='str', ), mx_name=dict(type='str', required=True, ), ttl=dict(type='int', )), dns_record_list=dict(type='list', ntype=dict(type='int', required=True, ), data=dict(type='str', ), uuid=dict(type='str', )), user_tag=dict(type='str', ), dns_ns_record_list=dict(type='list', sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'hits'])), ns_name=dict(type='str', required=True, ), uuid=dict(type='str', ), ttl=dict(type='int', )), health_check_gateway=dict(type='str', choices=['enable', 'disable']), sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'received-query', 'sent-response', 'proxy-mode-response', 'cache-mode-response', 'server-mode-response', 'sticky-mode-response', 'backup-mode-response'])), disable=dict(type='bool', ), dns_srv_record_list=dict(type='list', srv_name=dict(type='str', required=True, ), uuid=dict(type='str', ), weight=dict(type='int', ), priority=dict(type='int', ), sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'hits'])), ttl=dict(type='int', ), port=dict(type='int', required=True, )), service_name=dict(type='str', required=True, ), policy=dict(type='str', ), dns_ptr_record_list=dict(type='list', ptr_name=dict(type='str', required=True, ), ttl=dict(type='int', ), sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'hits'])), uuid=dict(type='str', )), dns_cname_record_list=dict(type='list', alias_name=dict(type='str', required=True, ), uuid=dict(type='str', ), as_backup=dict(type='bool', ), weight=dict(type='int', ), sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'cname-hits'])), admin_preference=dict(type='int', )), action=dict(type='str', choices=['drop', 'forward', 'ignore', 'reject']), geo_location_list=dict(type='list', action_type=dict(type='str', choices=['allow', 'drop', 'forward', 'ignore', 'reject']), uuid=dict(type='str', ), user_tag=dict(type='str', ), alias=dict(type='list', alias=dict(type='str', )), geo_name=dict(type='str', required=True, ), policy=dict(type='str', ), forward_type=dict(type='str', choices=['both', 'query', 'response']), action=dict(type='bool', )), dns_naptr_record_list=dict(type='list', sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'naptr-hits'])), naptr_target=dict(type='str', required=True, ), service_proto=dict(type='str', required=True, ), flag=dict(type='str', required=True, ), preference=dict(type='int', ), ttl=dict(type='int', ), regexp=dict(type='bool', ), order=dict(type='int', ), uuid=dict(type='str', ))),
        uuid=dict(type='str', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/zone/{name}"

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
    url_base = "/axapi/v3/gslb/zone/{name}"

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
        for k, v in payload["zone"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["zone"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["zone"][k] = v
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
    payload = build_json("zone", module)
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
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    ansible_protocol = module.params["ansible_protocol"]
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

    module.client = client_factory(ansible_host, ansible_port, ansible_protocol, ansible_username, ansible_password)
    
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