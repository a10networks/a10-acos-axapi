#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_router_ospf_area
description:
    - OSPF area parameters
short_description: Configures A10 router.ospf.area
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
    partition:
        description:
        - Destination/target partition for object/command
    ospf_process_id:
        description:
        - Key to identify parent object
    nssa_cfg:
        description:
        - "Field nssa_cfg"
        required: False
        suboptions:
            default_information_originate:
                description:
                - "Originate Type 7 default into NSSA area"
            translator_role:
                description:
                - "'always'= Translate always; 'candidate'= Candidate for translator (default); 'never'= Do not translate; "
            metric:
                description:
                - "OSPF default metric (OSPF metric)"
            nssa:
                description:
                - "Specify a NSSA area"
            no_redistribution:
                description:
                - "No redistribution into this NSSA area"
            no_summary:
                description:
                - "Do not send summary LSA into NSSA"
            metric_type:
                description:
                - "OSPF metric type (OSPF metric type for default routes)"
    uuid:
        description:
        - "uuid of the object"
        required: False
    filter_lists:
        description:
        - "Field filter_lists"
        required: False
        suboptions:
            acl_name:
                description:
                - "Filter networks by access-list (Name of an access-list)"
            acl_direction:
                description:
                - "'in'= Filter networks sent to this area; 'out'= Filter networks sent from this area; "
            filter_list:
                description:
                - "Filter networks between OSPF areas"
            plist_name:
                description:
                - "Filter networks by prefix-list (Name of an IP prefix-list)"
            plist_direction:
                description:
                - "'in'= Filter networks sent to this area; 'out'= Filter networks sent from this area; "
    area_num:
        description:
        - "OSPF area ID as a decimal value"
        required: True
    virtual_link_list:
        description:
        - "Field virtual_link_list"
        required: False
        suboptions:
            dead_interval:
                description:
                - "Dead router detection time (Seconds)"
            message_digest_key:
                description:
                - "Set message digest key (Key ID)"
            hello_interval:
                description:
                - "Hello packet interval (Seconds)"
            bfd:
                description:
                - "Bidirectional Forwarding Detection (BFD)"
            transmit_delay:
                description:
                - "LSA transmission delay (Seconds)"
            virtual_link_authentication:
                description:
                - "Enable authentication"
            virtual_link_ip_addr:
                description:
                - "ID (IP addr) associated with virtual link neighbor"
            virtual_link_auth_type:
                description:
                - "'message-digest'= Use message-digest authentication; 'null'= Use null authentication; "
            authentication_key:
                description:
                - "Set authentication key (Authentication key (8 chars))"
            retransmit_interval:
                description:
                - "LSA retransmit interval (Seconds)"
            md5:
                description:
                - "Use MD5 algorithm (Authentication key (16 chars))"
    stub_cfg:
        description:
        - "Field stub_cfg"
        required: False
        suboptions:
            stub:
                description:
                - "Configure OSPF area as stub"
            no_summary:
                description:
                - "Do not inject inter-area routes into area"
    shortcut:
        description:
        - "'default'= Set default shortcutting behavior; 'disable'= Disable shortcutting through the area; 'enable'= Enable shortcutting through the area; "
        required: False
    auth_cfg:
        description:
        - "Field auth_cfg"
        required: False
        suboptions:
            authentication:
                description:
                - "Enable authentication"
            message_digest:
                description:
                - "Use message-digest authentication"
    range_list:
        description:
        - "Field range_list"
        required: False
        suboptions:
            area_range_prefix:
                description:
                - "Area range for IPv4 prefix"
            option:
                description:
                - "'advertise'= Advertise this range (default); 'not-advertise'= DoNotAdvertise this range; "
    default_cost:
        description:
        - "Set the summary-default cost of a NSSA or stub area (Stub's advertised default summary cost)"
        required: False
    area_ipv4:
        description:
        - "OSPF area ID in IP address format"
        required: True

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["area_ipv4","area_num","auth_cfg","default_cost","filter_lists","nssa_cfg","range_list","shortcut","stub_cfg","uuid","virtual_link_list",]

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
        nssa_cfg=dict(type='dict',default_information_originate=dict(type='bool',),translator_role=dict(type='str',choices=['always','candidate','never']),metric=dict(type='int',),nssa=dict(type='bool',),no_redistribution=dict(type='bool',),no_summary=dict(type='bool',),metric_type=dict(type='int',)),
        uuid=dict(type='str',),
        filter_lists=dict(type='list',acl_name=dict(type='str',),acl_direction=dict(type='str',choices=['in','out']),filter_list=dict(type='bool',),plist_name=dict(type='str',),plist_direction=dict(type='str',choices=['in','out'])),
        area_num=dict(type='int',required=True,),
        virtual_link_list=dict(type='list',dead_interval=dict(type='int',),message_digest_key=dict(type='int',),hello_interval=dict(type='int',),bfd=dict(type='bool',),transmit_delay=dict(type='int',),virtual_link_authentication=dict(type='bool',),virtual_link_ip_addr=dict(type='str',),virtual_link_auth_type=dict(type='str',choices=['message-digest','null']),authentication_key=dict(type='str',),retransmit_interval=dict(type='int',),md5=dict(type='str',)),
        stub_cfg=dict(type='dict',stub=dict(type='bool',),no_summary=dict(type='bool',)),
        shortcut=dict(type='str',choices=['default','disable','enable']),
        auth_cfg=dict(type='dict',authentication=dict(type='bool',),message_digest=dict(type='bool',)),
        range_list=dict(type='list',area_range_prefix=dict(type='str',),option=dict(type='str',choices=['advertise','not-advertise'])),
        default_cost=dict(type='int',),
        area_ipv4=dict(type='str',required=True,)
    ))
   
    # Parent keys
    rv.update(dict(
        ospf_process_id=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/router/ospf/{ospf_process_id}/area/{area-ipv4}+{area-num}"

    f_dict = {}
    f_dict["area-ipv4"] = ""
    f_dict["area-num"] = ""
    f_dict["ospf_process_id"] = module.params["ospf_process_id"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/router/ospf/{ospf_process_id}/area/{area-ipv4}+{area-num}"

    f_dict = {}
    f_dict["area-ipv4"] = module.params["area_ipv4"]
    f_dict["area-num"] = module.params["area_num"]
    f_dict["ospf_process_id"] = module.params["ospf_process_id"]

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
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params])
    
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
    payload = build_json("area", module)
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
    payload = build_json("area", module)
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
    payload = build_json("area", module)
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
        map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
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