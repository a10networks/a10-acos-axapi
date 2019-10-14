#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_health_monitor_method_dns
description:
    - DNS type
short_description: Configures A10 health.monitor.method.dns
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
    monitor_name:
        description:
        - Key to identify parent object
    dns_domain_type:
        description:
        - "'A'= Used for storing Ipv4 address (default); 'CNAME'= Canonical name for a DNS alias; 'SOA'= Start of authority; 'PTR'= Domain name pointer; 'MX'= Mail exchanger; 'TXT'= Text string; 'AAAA'= Used for storing Ipv6 128-bits address; "
        required: False
    dns_ipv4_recurse:
        description:
        - "'enabled'= Set the recursion bit; 'disabled'= Clear the recursion bit; "
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    dns_ipv6_port:
        description:
        - "Specify DNS port, default is 53 (DNS Port(default 53))"
        required: False
    dns_ipv4_addr:
        description:
        - "Specify IPv4 address"
        required: False
    dns_domain_expect:
        description:
        - "Field dns_domain_expect"
        required: False
        suboptions:
            dns_domain_response:
                description:
                - "Specify response code range (e.g. 0,1-5) (Format is xx,xx-xx (xx between [0,15]))"
    dns_ipv4_expect:
        description:
        - "Field dns_ipv4_expect"
        required: False
        suboptions:
            dns_ipv4_response:
                description:
                - "Specify response code range (e.g. 0,1-5) (Format is xx,xx-xx (xx between [0,15]))"
    dns_ipv4_port:
        description:
        - "Specify DNS port, default is 53 (DNS Port(default 53))"
        required: False
    dns_ipv6_expect:
        description:
        - "Field dns_ipv6_expect"
        required: False
        suboptions:
            dns_ipv6_response:
                description:
                - "Specify response code range (e.g. 0,1-5) (Format is xx,xx-xx (xx between [0,15]))"
    dns_ip_key:
        description:
        - "Reverse DNS lookup (Specify IPv4 or IPv6 address)"
        required: False
    dns_ipv6_recurse:
        description:
        - "'enabled'= Set the recursion bit; 'disabled'= Clear the recursion bit; "
        required: False
    dns_ipv6_tcp:
        description:
        - "Configure DNS transport over TCP, default is UDP"
        required: False
    dns_domain_recurse:
        description:
        - "'enabled'= Set the recursion bit; 'disabled'= Clear the recursion bit; "
        required: False
    dns_domain_tcp:
        description:
        - "Configure DNS transport over TCP, default is UDP"
        required: False
    dns:
        description:
        - "DNS type"
        required: False
    dns_ipv4_tcp:
        description:
        - "Configure DNS transport over TCP, default is UDP"
        required: False
    dns_domain:
        description:
        - "Specify fully qualified domain name of the host"
        required: False
    dns_ipv6_addr:
        description:
        - "Specify IPv6 address"
        required: False
    dns_domain_port:
        description:
        - "Specify DNS port, default is 53 (DNS Port(default 53))"
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
AVAILABLE_PROPERTIES = ["dns","dns_domain","dns_domain_expect","dns_domain_port","dns_domain_recurse","dns_domain_tcp","dns_domain_type","dns_ip_key","dns_ipv4_addr","dns_ipv4_expect","dns_ipv4_port","dns_ipv4_recurse","dns_ipv4_tcp","dns_ipv6_addr","dns_ipv6_expect","dns_ipv6_port","dns_ipv6_recurse","dns_ipv6_tcp","uuid",]

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
        dns_domain_type=dict(type='str',choices=['A','CNAME','SOA','PTR','MX','TXT','AAAA']),
        dns_ipv4_recurse=dict(type='str',choices=['enabled','disabled']),
        uuid=dict(type='str',),
        dns_ipv6_port=dict(type='int',),
        dns_ipv4_addr=dict(type='str',),
        dns_domain_expect=dict(type='dict',dns_domain_response=dict(type='str',)),
        dns_ipv4_expect=dict(type='dict',dns_ipv4_response=dict(type='str',)),
        dns_ipv4_port=dict(type='int',),
        dns_ipv6_expect=dict(type='dict',dns_ipv6_response=dict(type='str',)),
        dns_ip_key=dict(type='bool',),
        dns_ipv6_recurse=dict(type='str',choices=['enabled','disabled']),
        dns_ipv6_tcp=dict(type='bool',),
        dns_domain_recurse=dict(type='str',choices=['enabled','disabled']),
        dns_domain_tcp=dict(type='bool',),
        dns=dict(type='bool',),
        dns_ipv4_tcp=dict(type='bool',),
        dns_domain=dict(type='str',),
        dns_ipv6_addr=dict(type='str',),
        dns_domain_port=dict(type='int',)
    ))
   
    # Parent keys
    rv.update(dict(
        monitor_name=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/health/monitor/{monitor_name}/method/dns"

    f_dict = {}
    f_dict["monitor_name"] = module.params["monitor_name"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/health/monitor/{monitor_name}/method/dns"

    f_dict = {}
    f_dict["monitor_name"] = module.params["monitor_name"]

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
        for k, v in payload["dns"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
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
    payload = build_json("dns", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

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