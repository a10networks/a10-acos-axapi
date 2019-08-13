#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_class_list
description:
    - Configure classification list
short_description: Configures A10 class-list
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
    dns:
        description:
        - "Field dns"
        required: False
        suboptions:
            dns_match_string:
                description:
                - "Domain name"
            dns_glid_shared:
                description:
                - "Use global Limit ID"
            dns_glid:
                description:
                - "Use global Limit ID (Specify global LID index)"
            dns_lid:
                description:
                - "Use Limit ID defined in template (Specify LID index)"
            shared_partition_dns_glid:
                description:
                - "Reference a glid from shared partition"
            dns_match_type:
                description:
                - "'contains'= Domain contains another string; 'ends-with'= Domain ends with another string; 'starts-with'= Domain starts-with another string; "
    name:
        description:
        - "Specify name of the class list"
        required: True
    ipv4_list:
        description:
        - "Field ipv4_list"
        required: False
        suboptions:
            lid:
                description:
                - "Use Limit ID defined in template (Specify LID index)"
            glid:
                description:
                - "Use global Limit ID (Specify global LID index)"
            glid_shared:
                description:
                - "Use global Limit ID"
            ipv4addr:
                description:
                - "Specify IP address"
            lsn_lid:
                description:
                - "LSN Limit ID (LID index)"
            shared_partition_glid:
                description:
                - "Reference a glid from shared partition"
            lsn_radius_profile:
                description:
                - "LSN RADIUS Profile Index"
    uuid:
        description:
        - "uuid of the object"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    ac_list:
        description:
        - "Field ac_list"
        required: False
        suboptions:
            ac_match_type:
                description:
                - "'contains'= String contains another string; 'ends-with'= String ends with another string; 'equals'= String equals another string; 'starts-with'= String starts with another string; "
            ac_key_string:
                description:
                - "Specify key string"
            ac_value:
                description:
                - "Specify value string"
    str_list:
        description:
        - "Field str_list"
        required: False
        suboptions:
            str_lid:
                description:
                - "LID index"
            shared_partition_str_glid:
                description:
                - "Reference a glid from shared partition"
            value_str:
                description:
                - "Specify value string"
            str_glid_shared:
                description:
                - "Use global Limit ID"
            str_glid_dummy:
                description:
                - "Use global Limit ID"
            str_glid:
                description:
                - "Global LID index"
            str_lid_dummy:
                description:
                - "Use Limit ID defined in template"
            str:
                description:
                - "Specify key string"
    file:
        description:
        - "Create/Edit a class-list stored as a file"
        required: False
    ntype:
        description:
        - "'ac'= Make class-list type Aho-Corasick; 'dns'= Make class-list type DNS; 'ipv4'= Make class-list type IPv4; 'ipv6'= Make class-list type IPv6; 'string'= Make class-list type String; 'string-case-insensitive'= Make class-list type String-case-insensitive. Case insensitive is applied to key string; "
        required: False
    ipv6_list:
        description:
        - "Field ipv6_list"
        required: False
        suboptions:
            v6_lsn_lid:
                description:
                - "LSN Limit ID (LID index)"
            v6_glid:
                description:
                - "Use global Limit ID (Specify global LID index)"
            ipv6_addr:
                description:
                - "Specify IPv6 host or subnet"
            v6_glid_shared:
                description:
                - "Use global Limit ID"
            v6_lid:
                description:
                - "Use Limit ID defined in template (Specify LID index)"
            shared_partition_v6_glid:
                description:
                - "Reference a glid from shared partition"
            v6_lsn_radius_profile:
                description:
                - "LSN RADIUS Profile Index"

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["ac_list","dns","file","ipv4_list","ipv6_list","name","str_list","ntype","user_tag","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        partition=dict(type='str', required=False)
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        dns=dict(type='list',dns_match_string=dict(type='str',),dns_glid_shared=dict(type='int',),dns_glid=dict(type='int',),dns_lid=dict(type='int',),shared_partition_dns_glid=dict(type='bool',),dns_match_type=dict(type='str',choices=['contains','ends-with','starts-with'])),
        name=dict(type='str',required=True,),
        ipv4_list=dict(type='list',lid=dict(type='int',),glid=dict(type='int',),glid_shared=dict(type='int',),ipv4addr=dict(type='str',),lsn_lid=dict(type='int',),shared_partition_glid=dict(type='bool',),lsn_radius_profile=dict(type='int',)),
        uuid=dict(type='str',),
        user_tag=dict(type='str',),
        ac_list=dict(type='list',ac_match_type=dict(type='str',choices=['contains','ends-with','equals','starts-with']),ac_key_string=dict(type='str',),ac_value=dict(type='str',)),
        str_list=dict(type='list',str_lid=dict(type='int',),shared_partition_str_glid=dict(type='bool',),value_str=dict(type='str',),str_glid_shared=dict(type='int',),str_glid_dummy=dict(type='bool',),str_glid=dict(type='int',),str_lid_dummy=dict(type='bool',),str=dict(type='str',)),
        file=dict(type='bool',),
        ntype=dict(type='str',choices=['ac','dns','ipv4','ipv6','string','string-case-insensitive']),
        ipv6_list=dict(type='list',v6_lsn_lid=dict(type='int',),v6_glid=dict(type='int',),ipv6_addr=dict(type='str',),v6_glid_shared=dict(type='int',),v6_lid=dict(type='int',),shared_partition_v6_glid=dict(type='bool',),v6_lsn_radius_profile=dict(type='int',))
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/class-list/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/class-list/{name}"

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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("class-list", module)
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
    payload = build_json("class-list", module)
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
    payload = build_json("class-list", module)
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
        message=""
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