#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_slb_resource_usage
description:
    - Configure SLB Resource Usage
short_description: Configures A10 slb.resource-usage
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
            service_group_min:
                description:
                - "Field service_group_min"
            service_group_default:
                description:
                - "Field service_group_default"
            service_group_max:
                description:
                - "Field service_group_max"
            gslb_service_port_count_max:
                description:
                - "Field gslb_service_port_count_max"
            slb_threshold_res_usage_default:
                description:
                - "Field slb_threshold_res_usage_default"
            gslb_service_port_count_min:
                description:
                - "Field gslb_service_port_count_min"
            health_monitor_count_default:
                description:
                - "Field health_monitor_count_default"
            gslb_template_count_min:
                description:
                - "Field gslb_template_count_min"
            gslb_policy_count_default:
                description:
                - "Field gslb_policy_count_default"
            proxy_template_default:
                description:
                - "Field proxy_template_default"
            client_ssl_template_min:
                description:
                - "Field client_ssl_template_min"
            client_ssl_template_default:
                description:
                - "Field client_ssl_template_default"
            fast_tcp_template_min:
                description:
                - "Field fast_tcp_template_min"
            fast_tcp_template_max:
                description:
                - "Field fast_tcp_template_max"
            client_ssl_template_max:
                description:
                - "Field client_ssl_template_max"
            gslb_site_count_min:
                description:
                - "Field gslb_site_count_min"
            gslb_service_count_max:
                description:
                - "Field gslb_service_count_max"
            cache_template_max:
                description:
                - "Field cache_template_max"
            gslb_template_count_max:
                description:
                - "Field gslb_template_count_max"
            cache_template_min:
                description:
                - "Field cache_template_min"
            proxy_template_max:
                description:
                - "Field proxy_template_max"
            pbslb_subnet_count_min:
                description:
                - "Field pbslb_subnet_count_min"
            gslb_service_count_min:
                description:
                - "Field gslb_service_count_min"
            cache_template_default:
                description:
                - "Field cache_template_default"
            real_port_max:
                description:
                - "Field real_port_max"
            nat_pool_addr_max:
                description:
                - "Field nat_pool_addr_max"
            gslb_geo_location_count_min:
                description:
                - "Field gslb_geo_location_count_min"
            real_server_min:
                description:
                - "Field real_server_min"
            virtual_server_default:
                description:
                - "Field virtual_server_default"
            gslb_device_count_max:
                description:
                - "Field gslb_device_count_max"
            gslb_template_count_default:
                description:
                - "Field gslb_template_count_default"
            fast_udp_template_max:
                description:
                - "Field fast_udp_template_max"
            fast_udp_template_min:
                description:
                - "Field fast_udp_template_min"
            gslb_geo_location_count_max:
                description:
                - "Field gslb_geo_location_count_max"
            gslb_site_count_max:
                description:
                - "Field gslb_site_count_max"
            gslb_service_ip_count_max:
                description:
                - "Field gslb_service_ip_count_max"
            gslb_device_count_min:
                description:
                - "Field gslb_device_count_min"
            gslb_zone_count_min:
                description:
                - "Field gslb_zone_count_min"
            gslb_service_ip_count_min:
                description:
                - "Field gslb_service_ip_count_min"
            gslb_service_count_default:
                description:
                - "Field gslb_service_count_default"
            persist_cookie_template_default:
                description:
                - "Field persist_cookie_template_default"
            fast_udp_template_default:
                description:
                - "Field fast_udp_template_default"
            real_server_default:
                description:
                - "Field real_server_default"
            gslb_zone_count_max:
                description:
                - "Field gslb_zone_count_max"
            gslb_device_count_default:
                description:
                - "Field gslb_device_count_default"
            conn_reuse_template_min:
                description:
                - "Field conn_reuse_template_min"
            real_port_default:
                description:
                - "Field real_port_default"
            gslb_ip_list_count_min:
                description:
                - "Field gslb_ip_list_count_min"
            http_template_default:
                description:
                - "Field http_template_default"
            persist_srcip_template_default:
                description:
                - "Field persist_srcip_template_default"
            gslb_policy_count_max:
                description:
                - "Field gslb_policy_count_max"
            gslb_svcgroup_count_max:
                description:
                - "Field gslb_svcgroup_count_max"
            proxy_template_min:
                description:
                - "Field proxy_template_min"
            gslb_policy_count_min:
                description:
                - "Field gslb_policy_count_min"
            gslb_geo_location_count_default:
                description:
                - "Field gslb_geo_location_count_default"
            gslb_zone_count_default:
                description:
                - "Field gslb_zone_count_default"
            server_ssl_template_default:
                description:
                - "Field server_ssl_template_default"
            server_ssl_template_min:
                description:
                - "Field server_ssl_template_min"
            slb_threshold_res_usage_min:
                description:
                - "Field slb_threshold_res_usage_min"
            real_port_min:
                description:
                - "Field real_port_min"
            gslb_ip_list_count_max:
                description:
                - "Field gslb_ip_list_count_max"
            persist_cookie_template_min:
                description:
                - "Field persist_cookie_template_min"
            slb_threshold_res_usage_max:
                description:
                - "Field slb_threshold_res_usage_max"
            server_ssl_template_max:
                description:
                - "Field server_ssl_template_max"
            gslb_site_count_default:
                description:
                - "Field gslb_site_count_default"
            gslb_ip_list_count_default:
                description:
                - "Field gslb_ip_list_count_default"
            virtual_server_max:
                description:
                - "Field virtual_server_max"
            real_server_max:
                description:
                - "Field real_server_max"
            conn_reuse_template_default:
                description:
                - "Field conn_reuse_template_default"
            persist_cookie_template_max:
                description:
                - "Field persist_cookie_template_max"
            virtual_server_min:
                description:
                - "Field virtual_server_min"
            stream_template_max:
                description:
                - "Field stream_template_max"
            fast_tcp_template_default:
                description:
                - "Field fast_tcp_template_default"
            virtual_port_min:
                description:
                - "Field virtual_port_min"
            nat_pool_addr_min:
                description:
                - "Field nat_pool_addr_min"
            virtual_port_max:
                description:
                - "Field virtual_port_max"
            virtual_port_default:
                description:
                - "Field virtual_port_default"
            pbslb_subnet_count_max:
                description:
                - "Field pbslb_subnet_count_max"
            gslb_service_port_count_default:
                description:
                - "Field gslb_service_port_count_default"
            persist_srcip_template_min:
                description:
                - "Field persist_srcip_template_min"
            stream_template_min:
                description:
                - "Field stream_template_min"
            nat_pool_addr_default:
                description:
                - "Field nat_pool_addr_default"
            http_template_max:
                description:
                - "Field http_template_max"
            stream_template_default:
                description:
                - "Field stream_template_default"
            gslb_svcgroup_count_default:
                description:
                - "Field gslb_svcgroup_count_default"
            health_monitor_count_min:
                description:
                - "Field health_monitor_count_min"
            pbslb_subnet_count_default:
                description:
                - "Field pbslb_subnet_count_default"
            health_monitor_count_max:
                description:
                - "Field health_monitor_count_max"
            persist_srcip_template_max:
                description:
                - "Field persist_srcip_template_max"
            conn_reuse_template_max:
                description:
                - "Field conn_reuse_template_max"
            http_template_min:
                description:
                - "Field http_template_min"
            gslb_svcgroup_count_min:
                description:
                - "Field gslb_svcgroup_count_min"
            gslb_service_ip_count_default:
                description:
                - "Field gslb_service_ip_count_default"
    nat_pool_addr_count:
        description:
        - "Total configurable NAT Pool addresses in the System (deprecated)"
        required: False
    fast_tcp_template_count:
        description:
        - "Total configurable Fast TCP Templates in the System"
        required: False
    cache_template_count:
        description:
        - "Total configurable HTTP Cache Templates in the System"
        required: False
    proxy_template_count:
        description:
        - "Total configurable Proxy Templates in the System"
        required: False
    persist_srcip_template_count:
        description:
        - "Total configurable Source IP Persistent Templates in the System"
        required: False
    client_ssl_template_count:
        description:
        - "Total configurable Client SSL Templates in the System"
        required: False
    pbslb_subnet_count:
        description:
        - "Total PBSLB Subnets in the System"
        required: False
    persist_cookie_template_count:
        description:
        - "Total configurable Persistent cookie Templates in the System"
        required: False
    stream_template_count:
        description:
        - "Total configurable Streaming media in the System"
        required: False
    conn_reuse_template_count:
        description:
        - "Total configurable Connection reuse Templates in the System"
        required: False
    real_port_count:
        description:
        - "Total Real Server Ports in the System"
        required: False
    http_template_count:
        description:
        - "Total configurable HTTP Templates in the System"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    service_group_count:
        description:
        - "Total Service Groups in the System"
        required: False
    virtual_server_count:
        description:
        - "Total Virtual Servers in the System"
        required: False
    fast_udp_template_count:
        description:
        - "Total configurable Fast UDP Templates in the System"
        required: False
    virtual_port_count:
        description:
        - "Total Virtual Server Ports in the System"
        required: False
    slb_threshold_res_usage_percent:
        description:
        - "Enter the threshold as a percentage (Threshold in percentage(default is 0%))"
        required: False
    health_monitor_count:
        description:
        - "Total Health Monitors in the System"
        required: False
    server_ssl_template_count:
        description:
        - "Total configurable Server SSL Templates in the System"
        required: False
    real_server_count:
        description:
        - "Total Real Servers in the System"
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
AVAILABLE_PROPERTIES = ["cache_template_count","client_ssl_template_count","conn_reuse_template_count","fast_tcp_template_count","fast_udp_template_count","health_monitor_count","http_template_count","nat_pool_addr_count","oper","pbslb_subnet_count","persist_cookie_template_count","persist_srcip_template_count","proxy_template_count","real_port_count","real_server_count","server_ssl_template_count","service_group_count","slb_threshold_res_usage_percent","stream_template_count","uuid","virtual_port_count","virtual_server_count",]

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
        oper=dict(type='dict', service_group_min=dict(type='int', ), service_group_default=dict(type='int', ), service_group_max=dict(type='int', ), gslb_service_port_count_max=dict(type='int', ), slb_threshold_res_usage_default=dict(type='int', ), gslb_service_port_count_min=dict(type='int', ), health_monitor_count_default=dict(type='int', ), gslb_template_count_min=dict(type='int', ), gslb_policy_count_default=dict(type='int', ), proxy_template_default=dict(type='int', ), client_ssl_template_min=dict(type='int', ), client_ssl_template_default=dict(type='int', ), fast_tcp_template_min=dict(type='int', ), fast_tcp_template_max=dict(type='int', ), client_ssl_template_max=dict(type='int', ), gslb_site_count_min=dict(type='int', ), gslb_service_count_max=dict(type='int', ), cache_template_max=dict(type='int', ), gslb_template_count_max=dict(type='int', ), cache_template_min=dict(type='int', ), proxy_template_max=dict(type='int', ), pbslb_subnet_count_min=dict(type='int', ), gslb_service_count_min=dict(type='int', ), cache_template_default=dict(type='int', ), real_port_max=dict(type='int', ), nat_pool_addr_max=dict(type='int', ), gslb_geo_location_count_min=dict(type='int', ), real_server_min=dict(type='int', ), virtual_server_default=dict(type='int', ), gslb_device_count_max=dict(type='int', ), gslb_template_count_default=dict(type='int', ), fast_udp_template_max=dict(type='int', ), fast_udp_template_min=dict(type='int', ), gslb_geo_location_count_max=dict(type='int', ), gslb_site_count_max=dict(type='int', ), gslb_service_ip_count_max=dict(type='int', ), gslb_device_count_min=dict(type='int', ), gslb_zone_count_min=dict(type='int', ), gslb_service_ip_count_min=dict(type='int', ), gslb_service_count_default=dict(type='int', ), persist_cookie_template_default=dict(type='int', ), fast_udp_template_default=dict(type='int', ), real_server_default=dict(type='int', ), gslb_zone_count_max=dict(type='int', ), gslb_device_count_default=dict(type='int', ), conn_reuse_template_min=dict(type='int', ), real_port_default=dict(type='int', ), gslb_ip_list_count_min=dict(type='int', ), http_template_default=dict(type='int', ), persist_srcip_template_default=dict(type='int', ), gslb_policy_count_max=dict(type='int', ), gslb_svcgroup_count_max=dict(type='int', ), proxy_template_min=dict(type='int', ), gslb_policy_count_min=dict(type='int', ), gslb_geo_location_count_default=dict(type='int', ), gslb_zone_count_default=dict(type='int', ), server_ssl_template_default=dict(type='int', ), server_ssl_template_min=dict(type='int', ), slb_threshold_res_usage_min=dict(type='int', ), real_port_min=dict(type='int', ), gslb_ip_list_count_max=dict(type='int', ), persist_cookie_template_min=dict(type='int', ), slb_threshold_res_usage_max=dict(type='int', ), server_ssl_template_max=dict(type='int', ), gslb_site_count_default=dict(type='int', ), gslb_ip_list_count_default=dict(type='int', ), virtual_server_max=dict(type='int', ), real_server_max=dict(type='int', ), conn_reuse_template_default=dict(type='int', ), persist_cookie_template_max=dict(type='int', ), virtual_server_min=dict(type='int', ), stream_template_max=dict(type='int', ), fast_tcp_template_default=dict(type='int', ), virtual_port_min=dict(type='int', ), nat_pool_addr_min=dict(type='int', ), virtual_port_max=dict(type='int', ), virtual_port_default=dict(type='int', ), pbslb_subnet_count_max=dict(type='int', ), gslb_service_port_count_default=dict(type='int', ), persist_srcip_template_min=dict(type='int', ), stream_template_min=dict(type='int', ), nat_pool_addr_default=dict(type='int', ), http_template_max=dict(type='int', ), stream_template_default=dict(type='int', ), gslb_svcgroup_count_default=dict(type='int', ), health_monitor_count_min=dict(type='int', ), pbslb_subnet_count_default=dict(type='int', ), health_monitor_count_max=dict(type='int', ), persist_srcip_template_max=dict(type='int', ), conn_reuse_template_max=dict(type='int', ), http_template_min=dict(type='int', ), gslb_svcgroup_count_min=dict(type='int', ), gslb_service_ip_count_default=dict(type='int', )),
        nat_pool_addr_count=dict(type='int', ),
        fast_tcp_template_count=dict(type='int', ),
        cache_template_count=dict(type='int', ),
        proxy_template_count=dict(type='int', ),
        persist_srcip_template_count=dict(type='int', ),
        client_ssl_template_count=dict(type='int', ),
        pbslb_subnet_count=dict(type='int', ),
        persist_cookie_template_count=dict(type='int', ),
        stream_template_count=dict(type='int', ),
        conn_reuse_template_count=dict(type='int', ),
        real_port_count=dict(type='int', ),
        http_template_count=dict(type='int', ),
        uuid=dict(type='str', ),
        service_group_count=dict(type='int', ),
        virtual_server_count=dict(type='int', ),
        fast_udp_template_count=dict(type='int', ),
        virtual_port_count=dict(type='int', ),
        slb_threshold_res_usage_percent=dict(type='int', ),
        health_monitor_count=dict(type='int', ),
        server_ssl_template_count=dict(type='int', ),
        real_server_count=dict(type='int', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/resource-usage"

    f_dict = {}

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
    url_base = "/axapi/v3/slb/resource-usage"

    f_dict = {}

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
        for k, v in payload["resource-usage"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["resource-usage"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["resource-usage"][k] = v
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
    payload = build_json("resource-usage", module)
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