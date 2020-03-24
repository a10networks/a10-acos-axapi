#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_gslb_dns
description:
    - DNS Global Options
short_description: Configures A10 gslb.dns
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'total-query'= Total number of DNS queries received; 'total-response'= Total number of DNS replies sent to clients; 'bad-packet-query'= Number of queries with incorrect data length; 'bad-packet-response'= Number of replies with incorrect data length; 'bad-header-query'= Number of queries with incorrect header; 'bad-header-response'= Number of replies with incorrect header; 'bad-format-query'= Number of queries with incorrect format; 'bad-format-response'= Number of replies with incorrect format; 'bad-service-query'= Number of queries with unknown service; 'bad-service-response'= Number of replies with unknown service; 'bad-class-query'= Number of queries with incorrect class; 'bad-class-response'= Number of replies with incorrect class; 'bad-type-query'= Number of queries with incorrect type; 'bad-type-response'= Number of replies with incorrect type; 'no_answer'= Number of replies with unknown server IP; 'metric_health_check'= Metric Health Check Hit; 'metric_weighted_ip'= Metric Weighted IP Hit; 'metric_weighted_site'= Metric Weighted Site Hit; 'metric_capacity'= Metric Capacity Hit; 'metric_active_server'= Metric Active Server Hit; 'metric_easy_rdt'= Metric Easy RDT Hit; 'metric_active_rdt'= Metric Active RDT Hit; 'metric_geographic'= Metric Geographic Hit; 'metric_connection_load'= Metric Connection Load Hit; 'metric_number_of_sessions'= Metric Number of Sessions Hit; 'metric_active_weight'= Metric Active Weight Hit; 'metric_admin_preference'= Metric Admin Preference Hit; 'metric_bandwidth_quality'= Metric Bandwidth Quality Hit; 'metric_bandwidth_cost'= Metric Bandwidth Cost Hit; 'metric_user'= Metric User Hit; 'metric_least_reponse'= Metric Least Reponse Hit; 'metric_admin_ip'= Metric Admin IP Hit; 'metric_round_robin'= Metric Round Robin Hit; "
    logging:
        description:
        - "'none'= No logging (default); 'query'= DNS Query; 'response'= DNS Response; 'both'= Both DNS Query and Response; "
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    template:
        description:
        - "Logging template (Logging Template Name)"
        required: False
    action:
        description:
        - "'none'= No action (default); 'drop'= Drop query; 'reject'= Send refuse response; 'ignore'= Send empty response; "
        required: False
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            metric_capacity:
                description:
                - "Metric Capacity Hit"
            metric_admin_ip:
                description:
                - "Metric Admin IP Hit"
            no_answer:
                description:
                - "Number of replies with unknown server IP"
            bad_format_query:
                description:
                - "Number of queries with incorrect format"
            metric_active_server:
                description:
                - "Metric Active Server Hit"
            metric_active_rdt:
                description:
                - "Metric Active RDT Hit"
            metric_connection_load:
                description:
                - "Metric Connection Load Hit"
            bad_service_response:
                description:
                - "Number of replies with unknown service"
            metric_user:
                description:
                - "Metric User Hit"
            bad_packet_query:
                description:
                - "Number of queries with incorrect data length"
            total_query:
                description:
                - "Total number of DNS queries received"
            metric_bandwidth_cost:
                description:
                - "Metric Bandwidth Cost Hit"
            bad_class_query:
                description:
                - "Number of queries with incorrect class"
            metric_bandwidth_quality:
                description:
                - "Metric Bandwidth Quality Hit"
            bad_service_query:
                description:
                - "Number of queries with unknown service"
            bad_header_response:
                description:
                - "Number of replies with incorrect header"
            metric_least_reponse:
                description:
                - "Metric Least Reponse Hit"
            metric_weighted_site:
                description:
                - "Metric Weighted Site Hit"
            total_response:
                description:
                - "Total number of DNS replies sent to clients"
            metric_health_check:
                description:
                - "Metric Health Check Hit"
            metric_round_robin:
                description:
                - "Metric Round Robin Hit"
            metric_easy_rdt:
                description:
                - "Metric Easy RDT Hit"
            bad_type_query:
                description:
                - "Number of queries with incorrect type"
            bad_packet_response:
                description:
                - "Number of replies with incorrect data length"
            metric_weighted_ip:
                description:
                - "Metric Weighted IP Hit"
            bad_class_response:
                description:
                - "Number of replies with incorrect class"
            bad_format_response:
                description:
                - "Number of replies with incorrect format"
            metric_geographic:
                description:
                - "Metric Geographic Hit"
            bad_header_query:
                description:
                - "Number of queries with incorrect header"
            metric_active_weight:
                description:
                - "Metric Active Weight Hit"
            metric_admin_preference:
                description:
                - "Metric Admin Preference Hit"
            metric_number_of_sessions:
                description:
                - "Metric Number of Sessions Hit"
            bad_type_response:
                description:
                - "Number of replies with incorrect type"
<<<<<<< HEAD
=======

>>>>>>> 8cdbeb80... Incorporated changes to provide session close feature

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["action","logging","sampling_enable","stats","template","uuid",]

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
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','total-query','total-response','bad-packet-query','bad-packet-response','bad-header-query','bad-header-response','bad-format-query','bad-format-response','bad-service-query','bad-service-response','bad-class-query','bad-class-response','bad-type-query','bad-type-response','no_answer','metric_health_check','metric_weighted_ip','metric_weighted_site','metric_capacity','metric_active_server','metric_easy_rdt','metric_active_rdt','metric_geographic','metric_connection_load','metric_number_of_sessions','metric_active_weight','metric_admin_preference','metric_bandwidth_quality','metric_bandwidth_cost','metric_user','metric_least_reponse','metric_admin_ip','metric_round_robin'])),
        logging=dict(type='str',choices=['none','query','response','both']),
        uuid=dict(type='str',),
        template=dict(type='str',),
        action=dict(type='str',choices=['none','drop','reject','ignore']),
        stats=dict(type='dict',metric_capacity=dict(type='str',),metric_admin_ip=dict(type='str',),no_answer=dict(type='str',),bad_format_query=dict(type='str',),metric_active_server=dict(type='str',),metric_active_rdt=dict(type='str',),metric_connection_load=dict(type='str',),bad_service_response=dict(type='str',),metric_user=dict(type='str',),bad_packet_query=dict(type='str',),total_query=dict(type='str',),metric_bandwidth_cost=dict(type='str',),bad_class_query=dict(type='str',),metric_bandwidth_quality=dict(type='str',),bad_service_query=dict(type='str',),bad_header_response=dict(type='str',),metric_least_reponse=dict(type='str',),metric_weighted_site=dict(type='str',),total_response=dict(type='str',),metric_health_check=dict(type='str',),metric_round_robin=dict(type='str',),metric_easy_rdt=dict(type='str',),bad_type_query=dict(type='str',),bad_packet_response=dict(type='str',),metric_weighted_ip=dict(type='str',),bad_class_response=dict(type='str',),bad_format_response=dict(type='str',),metric_geographic=dict(type='str',),bad_header_query=dict(type='str',),metric_active_weight=dict(type='str',),metric_admin_preference=dict(type='str',),metric_number_of_sessions=dict(type='str',),bad_type_response=dict(type='str',))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/dns"

    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/dns"

    f_dict = {}

    return url_base.format(**f_dict)

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
        for k, v in payload["dns"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["dns"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["dns"][k] = v
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
    payload = build_json("dns", module)
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
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result, existing_config)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
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