#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_axdebug
description:
    - None
short_description: Configures A10 axdebug
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
    count:
        description:
        - "None"
        required: False
    save_config:
        description:
        - "None"
        required: False
    timeout:
        description:
        - "None"
        required: False
    sess_filter_dis:
        description:
        - "None"
        required: False
    outgoing_list:
        description:
        - "Field outgoing_list"
        required: False
        suboptions:
            outgoing:
                description:
                - "None"
            out_port_num:
                description:
                - "None"
    maxfile:
        description:
        - "None"
        required: False
    capture:
        description:
        - "Field capture"
        required: False
        suboptions:
            current_slot:
                description:
                - "None"
            outgoing:
                description:
                - "None"
            non_display:
                description:
                - "None"
            incoming:
                description:
                - "None"
            port_num:
                description:
                - "None"
            brief:
                description:
                - "None"
            detail:
                description:
                - "None"
            save:
                description:
                - "None"
            max_packets:
                description:
                - "None"
    length:
        description:
        - "None"
        required: False
    exit:
        description:
        - "None"
        required: False
    delete_file_list:
        description:
        - "Field delete_file_list"
        required: False
        suboptions:
            delete_config:
                description:
                - "None"
            delete_capture:
                description:
                - "None"
            delete:
                description:
                - "None"
    filter_config:
        description:
        - "Field filter_config"
        required: False
        suboptions:
            arp:
                description:
                - "None"
            ip:
                description:
                - "None"
            offset:
                description:
                - "None"
            number:
                description:
                - "None"
            tcp:
                description:
                - "Field tcp"
            l3_proto:
                description:
                - "None"
            ipv4_address:
                description:
                - "None"
            port:
                description:
                - "None"
            port_num_min:
                description:
                - "None"
            oper_range:
                description:
                - "None"
            ipv6_adddress:
                description:
                - "None"
            WORD:
                description:
                - "None"
            comp_hex:
                description:
                - "None"
            proto:
                description:
                - "None"
            dst:
                description:
                - "None"
            hex:
                description:
                - "None"
            integer_comp:
                description:
                - "None"
            port_num_max:
                description:
                - "None"
            exit:
                description:
                - "None"
            ipv6:
                description:
                - "None"
            length:
                description:
                - "None"
            udp:
                description:
                - "Field udp"
            neighbor:
                description:
                - "None"
            port_num:
                description:
                - "None"
            max_hex:
                description:
                - "None"
            mac:
                description:
                - "None"
            min_hex:
                description:
                - "None"
            WORD1:
                description:
                - "None"
            WORD2:
                description:
                - "None"
            integer_max:
                description:
                - "None"
            integer:
                description:
                - "None"
            icmp:
                description:
                - "Field icmp"
            src:
                description:
                - "None"
            mac_addr:
                description:
                - "None"
            ipv4_netmask:
                description:
                - "None"
            icmpv6:
                description:
                - "Field icmpv6"
            range:
                description:
                - "None"
            integer_min:
                description:
                - "None"
            prot_num:
                description:
                - "None"
    incoming_list:
        description:
        - "Field incoming_list"
        required: False
        suboptions:
            incoming:
                description:
                - "None"
            inc_port_num:
                description:
                - "None"
    apply_config:
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
AVAILABLE_PROPERTIES = ["apply_config","capture","count","delete_file_list","exit","filter_config","incoming_list","length","maxfile","outgoing_list","save_config","sess_filter_dis","timeout",]

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
        count=dict(type='int',),
        save_config=dict(type='str',),
        timeout=dict(type='int',),
        sess_filter_dis=dict(type='bool',),
        outgoing_list=dict(type='dict',outgoing=dict(type='bool',),out_port_num=dict(type='str',)),
        maxfile=dict(type='int',),
        capture=dict(type='dict',current_slot=dict(type='bool',),outgoing=dict(type='bool',),non_display=dict(type='bool',),incoming=dict(type='bool',),port_num=dict(type='str',),brief=dict(type='bool',),detail=dict(type='bool',),save=dict(type='str',),max_packets=dict(type='int',)),
        length=dict(type='int',),
        exit=dict(type='bool',),
        delete_file_list=dict(type='dict',delete_config=dict(type='str',),delete_capture=dict(type='str',),delete=dict(type='bool',)),
        filter_config=dict(type='dict',arp=dict(type='bool',),ip=dict(type='bool',),offset=dict(type='int',),number=dict(type='int',),tcp=dict(type='bool',),l3_proto=dict(type='bool',),ipv4_address=dict(type='str',),port=dict(type='bool',),port_num_min=dict(type='int',),oper_range=dict(type='str',choices=['gt','gte','se','st','eq']),ipv6_adddress=dict(type='str',),WORD=dict(type='str',),comp_hex=dict(type='str',),proto=dict(type='bool',),dst=dict(type='bool',),hex=dict(type='bool',),integer_comp=dict(type='int',),port_num_max=dict(type='int',),exit=dict(type='bool',),ipv6=dict(type='bool',),length=dict(type='int',),udp=dict(type='bool',),neighbor=dict(type='bool',),port_num=dict(type='int',),max_hex=dict(type='str',),mac=dict(type='bool',),min_hex=dict(type='str',),WORD1=dict(type='str',),WORD2=dict(type='str',),integer_max=dict(type='int',),integer=dict(type='bool',),icmp=dict(type='bool',),src=dict(type='bool',),mac_addr=dict(type='str',),ipv4_netmask=dict(type='str',),icmpv6=dict(type='bool',),range=dict(type='bool',),integer_min=dict(type='int',),prot_num=dict(type='int',)),
        incoming_list=dict(type='dict',incoming=dict(type='bool',),inc_port_num=dict(type='str',)),
        apply_config=dict(type='str',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/axdebug"
    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/axdebug"
    f_dict = {}

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
    payload = build_json("axdebug", module)
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
    payload = build_json("axdebug", module)
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