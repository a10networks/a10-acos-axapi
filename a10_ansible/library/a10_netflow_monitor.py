#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_netflow_monitor
description:
    - None
short_description: Configures A10 netflow.monitor
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
    disable_log_by_destination:
        description:
        - "Field disable_log_by_destination"
        required: False
        suboptions:
            udp_list:
                description:
                - "Field udp_list"
            icmp:
                description:
                - "None"
            uuid:
                description:
                - "None"
            tcp_list:
                description:
                - "Field tcp_list"
            others:
                description:
                - "None"
    source_ip_use_mgmt:
        description:
        - "None"
        required: False
    protocol:
        description:
        - "None"
        required: False
    name:
        description:
        - "None"
        required: True
    source_address:
        description:
        - "Field source_address"
        required: False
        suboptions:
            ip:
                description:
                - "None"
            uuid:
                description:
                - "None"
            ipv6:
                description:
                - "None"
    destination:
        description:
        - "Field destination"
        required: False
        suboptions:
            ip_cfg:
                description:
                - "Field ip_cfg"
            service_group:
                description:
                - "None"
            uuid:
                description:
                - "None"
            ipv6_cfg:
                description:
                - "Field ipv6_cfg"
    user_tag:
        description:
        - "None"
        required: False
    sample:
        description:
        - "Field sample"
        required: False
        suboptions:
            ethernet_list:
                description:
                - "Field ethernet_list"
            nat_pool_list:
                description:
                - "Field nat_pool_list"
            ve_list:
                description:
                - "Field ve_list"
    record:
        description:
        - "Field record"
        required: False
        suboptions:
            nat44:
                description:
                - "None"
            uuid:
                description:
                - "None"
            sesn_event_nat64:
                description:
                - "None"
            nat64:
                description:
                - "None"
            port_batch_v2_nat64:
                description:
                - "None"
            dslite:
                description:
                - "None"
            port_batch_v2_dslite:
                description:
                - "None"
            sesn_event_fw6:
                description:
                - "None"
            netflow_v5_ext:
                description:
                - "None"
            port_mapping_nat64:
                description:
                - "None"
            sesn_event_dslite:
                description:
                - "None"
            sesn_event_nat44:
                description:
                - "None"
            port_batch_v2_nat44:
                description:
                - "None"
            netflow_v5:
                description:
                - "None"
            port_batch_dslite:
                description:
                - "None"
            port_mapping_dslite:
                description:
                - "None"
            port_mapping_nat44:
                description:
                - "None"
            sesn_event_fw4:
                description:
                - "None"
            port_batch_nat64:
                description:
                - "None"
            port_batch_nat44:
                description:
                - "None"
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "None"
    disable:
        description:
        - "None"
        required: False
    resend_template:
        description:
        - "Field resend_template"
        required: False
        suboptions:
            records:
                description:
                - "None"
            uuid:
                description:
                - "None"
            timeout:
                description:
                - "None"
    flow_timeout:
        description:
        - "None"
        required: False
    uuid:
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
AVAILABLE_PROPERTIES = ["destination","disable","disable_log_by_destination","flow_timeout","name","protocol","record","resend_template","sample","sampling_enable","source_address","source_ip_use_mgmt","user_tag","uuid",]

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
        disable_log_by_destination=dict(type='dict',udp_list=dict(type='list',udp_port_start=dict(type='int',),udp_port_end=dict(type='int',)),icmp=dict(type='bool',),uuid=dict(type='str',),tcp_list=dict(type='list',tcp_port_start=dict(type='int',),tcp_port_end=dict(type='int',)),others=dict(type='bool',)),
        source_ip_use_mgmt=dict(type='bool',),
        protocol=dict(type='str',choices=['v9','v10']),
        name=dict(type='str',required=True,),
        source_address=dict(type='dict',ip=dict(type='str',),uuid=dict(type='str',),ipv6=dict(type='str',)),
        destination=dict(type='dict',ip_cfg=dict(type='dict',ip=dict(type='str',),port4=dict(type='int',)),service_group=dict(type='str',),uuid=dict(type='str',),ipv6_cfg=dict(type='dict',port6=dict(type='int',),ipv6=dict(type='str',))),
        user_tag=dict(type='str',),
        sample=dict(type='dict',ethernet_list=dict(type='list',ifindex=dict(type='str',required=True,),uuid=dict(type='str',)),nat_pool_list=dict(type='list',uuid=dict(type='str',),pool_name=dict(type='str',required=True,)),ve_list=dict(type='list',uuid=dict(type='str',),ve_num=dict(type='int',required=True,))),
        record=dict(type='dict',nat44=dict(type='bool',),uuid=dict(type='str',),sesn_event_nat64=dict(type='str',choices=['both','creation','deletion']),nat64=dict(type='bool',),port_batch_v2_nat64=dict(type='str',choices=['both','creation','deletion']),dslite=dict(type='bool',),port_batch_v2_dslite=dict(type='str',choices=['both','creation','deletion']),sesn_event_fw6=dict(type='str',choices=['both','creation','deletion']),netflow_v5_ext=dict(type='bool',),port_mapping_nat64=dict(type='str',choices=['both','creation','deletion']),sesn_event_dslite=dict(type='str',choices=['both','creation','deletion']),sesn_event_nat44=dict(type='str',choices=['both','creation','deletion']),port_batch_v2_nat44=dict(type='str',choices=['both','creation','deletion']),netflow_v5=dict(type='bool',),port_batch_dslite=dict(type='str',choices=['both','creation','deletion']),port_mapping_dslite=dict(type='str',choices=['both','creation','deletion']),port_mapping_nat44=dict(type='str',choices=['both','creation','deletion']),sesn_event_fw4=dict(type='str',choices=['both','creation','deletion']),port_batch_nat64=dict(type='str',choices=['both','creation','deletion']),port_batch_nat44=dict(type='str',choices=['both','creation','deletion'])),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','packets-sent','bytes-sent','nat44-records-sent','nat44-records-sent-failure','nat64-records-sent','nat64-records-sent-failure','dslite-records-sent','dslite-records-sent-failure','session-event-nat44-records-sent','session-event-nat44-records-sent-failure','session-event-nat64-records-sent','session-event-nat64-records-sent-failure','session-event-dslite-records-sent','session-event-dslite-records-sent-failure','session-event-fw4-records-sent','session-event-fw4-records-sent-failure','session-event-fw6-records-sent','session-event-fw6-records-sent-failure','port-mapping-nat44-records-sent','port-mapping-nat44-records-sent-failure','port-mapping-nat64-records-sent','port-mapping-nat64-records-sent-failure','port-mapping-dslite-records-sent','port-mapping-dslite-records-sent-failure','netflow-v5-records-sent','netflow-v5-records-sent-failure','netflow-v5-ext-records-sent','netflow-v5-ext-records-sent-failure','port-batching-nat44-records-sent','port-batching-nat44-records-sent-failure','port-batching-nat64-records-sent','port-batching-nat64-records-sent-failure','port-batching-dslite-records-sent','port-batching-dslite-records-sent-failure','port-batching-v2-nat44-records-sent','port-batching-v2-nat44-records-sent-failure','port-batching-v2-nat64-records-sent','port-batching-v2-nat64-records-sent-failure','port-batching-v2-dslite-records-sent','port-batching-v2-dslite-records-sent-failure','reduced-logs-by-destination'])),
        disable=dict(type='bool',),
        resend_template=dict(type='dict',records=dict(type='int',),uuid=dict(type='str',),timeout=dict(type='int',)),
        flow_timeout=dict(type='int',),
        uuid=dict(type='str',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/netflow/monitor/{name}"
    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/netflow/monitor/{name}"
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
    payload = build_json("monitor", module)
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
    payload = build_json("monitor", module)
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