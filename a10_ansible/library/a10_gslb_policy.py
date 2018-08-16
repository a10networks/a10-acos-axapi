#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_gslb_policy
description:
    - None
short_description: Configures A10 gslb.policy
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
    weighted_ip_enable:
        description:
        - "None"
        required: False
    alias_admin_preference:
        description:
        - "None"
        required: False
    admin_ip_top_only:
        description:
        - "None"
        required: False
    least_response:
        description:
        - "None"
        required: False
    auto_map:
        description:
        - "Field auto_map"
        required: False
        suboptions:
            all:
                description:
                - "None"
            ttl:
                description:
                - "None"
            uuid:
                description:
                - "None"
            module_type:
                description:
                - "Field module_type"
            module_disable:
                description:
                - "None"
    bw_cost_fail_break:
        description:
        - "None"
        required: False
    metric_fail_break:
        description:
        - "None"
        required: False
    edns:
        description:
        - "Field edns"
        required: False
        suboptions:
            uuid:
                description:
                - "None"
            client_subnet_geographic:
                description:
                - "None"
    active_rdt:
        description:
        - "Field active_rdt"
        required: False
        suboptions:
            ignore_id:
                description:
                - "None"
            keep_tracking:
                description:
                - "None"
            enable:
                description:
                - "None"
            timeout:
                description:
                - "None"
            skip:
                description:
                - "None"
            fail_break:
                description:
                - "None"
            controller:
                description:
                - "None"
            limit:
                description:
                - "None"
            samples:
                description:
                - "None"
            proto_rdt_enable:
                description:
                - "None"
            single_shot:
                description:
                - "None"
            difference:
                description:
                - "None"
            tolerance:
                description:
                - "None"
            uuid:
                description:
                - "None"
    round_robin:
        description:
        - "None"
        required: False
    admin_preference:
        description:
        - "None"
        required: False
    capacity:
        description:
        - "Field capacity"
        required: False
        suboptions:
            threshold:
                description:
                - "None"
            capacity_enable:
                description:
                - "None"
            capacity_fail_break:
                description:
                - "None"
            uuid:
                description:
                - "None"
    uuid:
        description:
        - "None"
        required: False
    active_servers_fail_break:
        description:
        - "None"
        required: False
    metric_type:
        description:
        - "Field metric_type"
        required: False
    num_session_tolerance:
        description:
        - "None"
        required: False
    name:
        description:
        - "None"
        required: True
    dns:
        description:
        - "Field dns"
        required: False
        suboptions:
            server_mode_only:
                description:
                - "None"
            external_soa:
                description:
                - "None"
            server_sec:
                description:
                - "None"
            sticky_ipv6_mask:
                description:
                - "None"
            sticky:
                description:
                - "None"
            delegation:
                description:
                - "None"
            active_only_fail_safe:
                description:
                - "None"
            cname_detect:
                description:
                - "None"
            ttl:
                description:
                - "None"
            dynamic_preference:
                description:
                - "None"
            use_server_ttl:
                description:
                - "None"
            server_ptr:
                description:
                - "None"
            selected_only:
                description:
                - "None"
            ip_replace:
                description:
                - "None"
            dns_addition_mx:
                description:
                - "None"
            backup_alias:
                description:
                - "None"
            server_any:
                description:
                - "None"
            hint:
                description:
                - "None"
            cache:
                description:
                - "None"
            external_ip:
                description:
                - "None"
            server_txt:
                description:
                - "None"
            server_addition_mx:
                description:
                - "None"
            aging_time:
                description:
                - "None"
            block_action:
                description:
                - "None"
            template:
                description:
                - "None"
            ipv6:
                description:
                - "Field ipv6"
            selected_only_value:
                description:
                - "None"
            geoloc_action:
                description:
                - "None"
            server_ns:
                description:
                - "None"
            action_type:
                description:
                - "None"
            server_naptr:
                description:
                - "None"
            active_only:
                description:
                - "None"
            block_value:
                description:
                - "Field block_value"
            server_srv:
                description:
                - "None"
            server_auto_ptr:
                description:
                - "None"
            server_cname:
                description:
                - "None"
            server_authoritative:
                description:
                - "None"
            server_full_list:
                description:
                - "None"
            dns_auto_map:
                description:
                - "None"
            block_type:
                description:
                - "Field block_type"
            sticky_mask:
                description:
                - "None"
            geoloc_alias:
                description:
                - "None"
            logging:
                description:
                - "None"
            backup_server:
                description:
                - "None"
            sticky_aging_time:
                description:
                - "None"
            geoloc_policy:
                description:
                - "None"
            uuid:
                description:
                - "None"
            server:
                description:
                - "None"
            dynamic_weight:
                description:
                - "None"
            server_ns_list:
                description:
                - "None"
            server_auto_ns:
                description:
                - "None"
            action:
                description:
                - "None"
            proxy_block_port_range_list:
                description:
                - "Field proxy_block_port_range_list"
            server_mx:
                description:
                - "None"
    weighted_ip_total_hits:
        description:
        - "None"
        required: False
    weighted_site_total_hits:
        description:
        - "None"
        required: False
    ip_list:
        description:
        - "None"
        required: False
    ordered_ip_top_only:
        description:
        - "None"
        required: False
    weighted_site_enable:
        description:
        - "None"
        required: False
    metric_force_check:
        description:
        - "None"
        required: False
    admin_ip_enable:
        description:
        - "None"
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
                - "None"
            name:
                description:
                - "None"
            user_tag:
                description:
                - "None"
            ipv6_multiple_fields:
                description:
                - "Field ipv6_multiple_fields"
    weighted_alias:
        description:
        - "None"
        required: False
    geo_location_match:
        description:
        - "Field geo_location_match"
        required: False
        suboptions:
            match_first:
                description:
                - "None"
            uuid:
                description:
                - "None"
            geo_type_overlap:
                description:
                - "None"
            overlap:
                description:
                - "None"
    num_session_enable:
        description:
        - "None"
        required: False
    bw_cost_enable:
        description:
        - "None"
        required: False
    active_servers_enable:
        description:
        - "None"
        required: False
    user_tag:
        description:
        - "None"
        required: False
    amount_first:
        description:
        - "None"
        required: False
    connection_load:
        description:
        - "Field connection_load"
        required: False
        suboptions:
            uuid:
                description:
                - "None"
            connection_load_enable:
                description:
                - "None"
            connection_load_interval:
                description:
                - "None"
            limit:
                description:
                - "None"
            connection_load_samples:
                description:
                - "None"
            connection_load_limit:
                description:
                - "None"
            connection_load_fail_break:
                description:
                - "None"
    metric_order:
        description:
        - "None"
        required: False
    health_check_preference_enable:
        description:
        - "None"
        required: False
    health_preference_top:
        description:
        - "None"
        required: False
    health_check:
        description:
        - "None"
        required: False
    geographic:
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
AVAILABLE_PROPERTIES = ["active_rdt","active_servers_enable","active_servers_fail_break","admin_ip_enable","admin_ip_top_only","admin_preference","alias_admin_preference","amount_first","auto_map","bw_cost_enable","bw_cost_fail_break","capacity","connection_load","dns","edns","geo_location_list","geo_location_match","geographic","health_check","health_check_preference_enable","health_preference_top","ip_list","least_response","metric_fail_break","metric_force_check","metric_order","metric_type","name","num_session_enable","num_session_tolerance","ordered_ip_top_only","round_robin","user_tag","uuid","weighted_alias","weighted_ip_enable","weighted_ip_total_hits","weighted_site_enable","weighted_site_total_hits",]

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
        weighted_ip_enable=dict(type='bool',),
        alias_admin_preference=dict(type='bool',),
        admin_ip_top_only=dict(type='bool',),
        least_response=dict(type='bool',),
        auto_map=dict(type='dict',all=dict(type='bool',),ttl=dict(type='int',),uuid=dict(type='str',),module_type=dict(type='str',choices=['slb-virtual-server','slb-device','slb-server','gslb-service-ip','gslb-site','gslb-group','hostname']),module_disable=dict(type='bool',)),
        bw_cost_fail_break=dict(type='bool',),
        metric_fail_break=dict(type='bool',),
        edns=dict(type='dict',uuid=dict(type='str',),client_subnet_geographic=dict(type='bool',)),
        active_rdt=dict(type='dict',ignore_id=dict(type='int',),keep_tracking=dict(type='bool',),enable=dict(type='bool',),timeout=dict(type='int',),skip=dict(type='int',),fail_break=dict(type='bool',),controller=dict(type='bool',),limit=dict(type='int',),samples=dict(type='int',),proto_rdt_enable=dict(type='bool',),single_shot=dict(type='bool',),difference=dict(type='int',),tolerance=dict(type='int',),uuid=dict(type='str',)),
        round_robin=dict(type='bool',),
        admin_preference=dict(type='bool',),
        capacity=dict(type='dict',threshold=dict(type='int',),capacity_enable=dict(type='bool',),capacity_fail_break=dict(type='bool',),uuid=dict(type='str',)),
        uuid=dict(type='str',),
        active_servers_fail_break=dict(type='bool',),
        metric_type=dict(type='str',choices=['health-check','weighted-ip','weighted-site','capacity','active-servers','active-rdt','geographic','connection-load','num-session','admin-preference','bw-cost','least-response','admin-ip']),
        num_session_tolerance=dict(type='int',),
        name=dict(type='str',required=True,),
        dns=dict(type='dict',server_mode_only=dict(type='bool',),external_soa=dict(type='bool',),server_sec=dict(type='bool',),sticky_ipv6_mask=dict(type='int',),sticky=dict(type='bool',),delegation=dict(type='bool',),active_only_fail_safe=dict(type='bool',),cname_detect=dict(type='bool',),ttl=dict(type='int',),dynamic_preference=dict(type='bool',),use_server_ttl=dict(type='bool',),server_ptr=dict(type='bool',),selected_only=dict(type='bool',),ip_replace=dict(type='bool',),dns_addition_mx=dict(type='bool',),backup_alias=dict(type='bool',),server_any=dict(type='bool',),hint=dict(type='str',choices=['none','answer','addition']),cache=dict(type='bool',),external_ip=dict(type='bool',),server_txt=dict(type='bool',),server_addition_mx=dict(type='bool',),aging_time=dict(type='int',),block_action=dict(type='bool',),template=dict(type='str',),ipv6=dict(type='list',dns_ipv6_mapping_type=dict(type='str',choices=['addition','answer','exclusive','replace']),dns_ipv6_option=dict(type='str',choices=['mix','smart','mapping'])),selected_only_value=dict(type='int',),geoloc_action=dict(type='bool',),server_ns=dict(type='bool',),action_type=dict(type='str',choices=['drop','reject','ignore']),server_naptr=dict(type='bool',),active_only=dict(type='bool',),block_value=dict(type='list',block_value=dict(type='int',)),server_srv=dict(type='bool',),server_auto_ptr=dict(type='bool',),server_cname=dict(type='bool',),server_authoritative=dict(type='bool',),server_full_list=dict(type='bool',),dns_auto_map=dict(type='bool',),block_type=dict(type='str',choices=['a','aaaa','ns','mx','srv','cname','ptr','soa','txt']),sticky_mask=dict(type='str',),geoloc_alias=dict(type='bool',),logging=dict(type='str',choices=['none','query','response','both']),backup_server=dict(type='bool',),sticky_aging_time=dict(type='int',),geoloc_policy=dict(type='bool',),uuid=dict(type='str',),server=dict(type='bool',),dynamic_weight=dict(type='bool',),server_ns_list=dict(type='bool',),server_auto_ns=dict(type='bool',),action=dict(type='bool',),proxy_block_port_range_list=dict(type='list',proxy_block_range_from=dict(type='int',),proxy_block_range_to=dict(type='int',)),server_mx=dict(type='bool',)),
        weighted_ip_total_hits=dict(type='bool',),
        weighted_site_total_hits=dict(type='bool',),
        ip_list=dict(type='str',),
        ordered_ip_top_only=dict(type='bool',),
        weighted_site_enable=dict(type='bool',),
        metric_force_check=dict(type='bool',),
        admin_ip_enable=dict(type='bool',),
        geo_location_list=dict(type='list',ip_multiple_fields=dict(type='list',ip_addr2_sub=dict(type='str',),ip_sub=dict(type='str',),ip_mask_sub=dict(type='str',)),uuid=dict(type='str',),name=dict(type='str',required=True,),user_tag=dict(type='str',),ipv6_multiple_fields=dict(type='list',ipv6_mask_sub=dict(type='int',),ipv6_sub=dict(type='str',),ipv6_addr2_sub=dict(type='str',))),
        weighted_alias=dict(type='bool',),
        geo_location_match=dict(type='dict',match_first=dict(type='str',choices=['global','policy']),uuid=dict(type='str',),geo_type_overlap=dict(type='str',choices=['global','policy']),overlap=dict(type='bool',)),
        num_session_enable=dict(type='bool',),
        bw_cost_enable=dict(type='bool',),
        active_servers_enable=dict(type='bool',),
        user_tag=dict(type='str',),
        amount_first=dict(type='bool',),
        connection_load=dict(type='dict',uuid=dict(type='str',),connection_load_enable=dict(type='bool',),connection_load_interval=dict(type='int',),limit=dict(type='bool',),connection_load_samples=dict(type='int',),connection_load_limit=dict(type='int',),connection_load_fail_break=dict(type='bool',)),
        metric_order=dict(type='bool',),
        health_check_preference_enable=dict(type='bool',),
        health_preference_top=dict(type='int',),
        health_check=dict(type='bool',),
        geographic=dict(type='bool',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/policy/{name}"
    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/policy/{name}"
    f_dict = {}
    f_dict["name"] = module.params["name"]

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
    payload = build_json("policy", module)
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
    payload = build_json("policy", module)
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