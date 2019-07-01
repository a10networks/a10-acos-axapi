#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_rule_set_tag
description:
    - Application Family statistics in Rule Set
short_description: Configures A10 rule.set.tag
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
    rule_set_name:
        description:
        - Key to identify parent object
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'categorystat1'= counter app category stat 1; 'categorystat2'= counter app category stat 2; 'categorystat3'= counter app category stat 3; 'categorystat4'= counter app category stat 4; 'categorystat5'= counter app category stat 5; 'categorystat6'= counter app category stat 6; 'categorystat7'= counter app category stat 7; 'categorystat8'= counter app category stat 8; 'categorystat9'= counter app category stat 9; 'categorystat10'= counter app category stat 10; 'categorystat11'= counter app category stat 11; 'categorystat12'= counter app category stat 12; 'categorystat13'= counter app category stat 13; 'categorystat14'= counter app category stat 14; 'categorystat15'= counter app category stat 15; 'categorystat16'= counter app category stat 16; 'categorystat17'= counter app category stat 17; 'categorystat18'= counter app category stat 18; 'categorystat19'= counter app category stat 19; 'categorystat20'= counter app category stat 20; 'categorystat21'= counter app category stat 21; 'categorystat22'= counter app category stat 22; 'categorystat23'= counter app category stat 23; 'categorystat24'= counter app category stat 24; 'categorystat25'= counter app category stat 25; 'categorystat26'= counter app category stat 26; 'categorystat27'= counter app category stat 27; 'categorystat28'= counter app category stat 28; 'categorystat29'= counter app category stat 29; 'categorystat30'= counter app category stat 30; 'categorystat31'= counter app category stat 31; 'categorystat32'= counter app category stat 32; 'categorystat33'= counter app category stat 33; 'categorystat34'= counter app category stat 34; 'categorystat35'= counter app category stat 35; 'categorystat36'= counter app category stat 36; 'categorystat37'= counter app category stat 37; 'categorystat38'= counter app category stat 38; 'categorystat39'= counter app category stat 39; 'categorystat40'= counter app category stat 40; 'categorystat41'= counter app category stat 41; 'categorystat42'= counter app category stat 42; 'categorystat43'= counter app category stat 43; 'categorystat44'= counter app category stat 44; 'categorystat45'= counter app category stat 45; 'categorystat46'= counter app category stat 46; 'categorystat47'= counter app category stat 47; 'categorystat48'= counter app category stat 48; 'categorystat49'= counter app category stat 49; 'categorystat50'= counter app category stat 50; 'categorystat51'= counter app category stat 51; 'categorystat52'= counter app category stat 52; 'categorystat53'= counter app category stat 53; 'categorystat54'= counter app category stat 54; 'categorystat55'= counter app category stat 55; 'categorystat56'= counter app category stat 56; 'categorystat57'= counter app category stat 57; 'categorystat58'= counter app category stat 58; 'categorystat59'= counter app category stat 59; 'categorystat60'= counter app category stat 60; 'categorystat61'= counter app category stat 61; 'categorystat62'= counter app category stat 62; 'categorystat63'= counter app category stat 63; 'categorystat64'= counter app category stat 64; 'categorystat65'= counter app category stat 65; 'categorystat66'= counter app category stat 66; 'categorystat67'= counter app category stat 67; 'categorystat68'= counter app category stat 68; 'categorystat69'= counter app category stat 69; 'categorystat70'= counter app category stat 70; 'categorystat71'= counter app category stat 71; 'categorystat72'= counter app category stat 72; 'categorystat73'= counter app category stat 73; 'categorystat74'= counter app category stat 74; 'categorystat75'= counter app category stat 75; 'categorystat76'= counter app category stat 76; 'categorystat77'= counter app category stat 77; 'categorystat78'= counter app category stat 78; 'categorystat79'= counter app category stat 79; 'categorystat80'= counter app category stat 80; 'categorystat81'= counter app category stat 81; 'categorystat82'= counter app category stat 82; 'categorystat83'= counter app category stat 83; 'categorystat84'= counter app category stat 84; 'categorystat85'= counter app category stat 85; 'categorystat86'= counter app category stat 86; 'categorystat87'= counter app category stat 87; 'categorystat88'= counter app category stat 88; 'categorystat89'= counter app category stat 89; 'categorystat90'= counter app category stat 90; 'categorystat91'= counter app category stat 91; 'categorystat92'= counter app category stat 92; 'categorystat93'= counter app category stat 93; 'categorystat94'= counter app category stat 94; 'categorystat95'= counter app category stat 95; 'categorystat96'= counter app category stat 96; 'categorystat97'= counter app category stat 97; 'categorystat98'= counter app category stat 98; 'categorystat99'= counter app category stat 99; 'categorystat100'= counter app category stat 100; 'categorystat101'= counter app category stat 101; 'categorystat102'= counter app category stat 102; 'categorystat103'= counter app category stat 103; 'categorystat104'= counter app category stat 104; 'categorystat105'= counter app category stat 105; 'categorystat106'= counter app category stat 106; 'categorystat107'= counter app category stat 107; 'categorystat108'= counter app category stat 108; 'categorystat109'= counter app category stat 109; 'categorystat110'= counter app category stat 110; 'categorystat111'= counter app category stat 111; 'categorystat112'= counter app category stat 112; 'categorystat113'= counter app category stat 113; 'categorystat114'= counter app category stat 114; 'categorystat115'= counter app category stat 115; 'categorystat116'= counter app category stat 116; 'categorystat117'= counter app category stat 117; 'categorystat118'= counter app category stat 118; 'categorystat119'= counter app category stat 119; 'categorystat120'= counter app category stat 120; "
    uuid:
        description:
        - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["sampling_enable","uuid",]

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
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','categorystat1','categorystat2','categorystat3','categorystat4','categorystat5','categorystat6','categorystat7','categorystat8','categorystat9','categorystat10','categorystat11','categorystat12','categorystat13','categorystat14','categorystat15','categorystat16','categorystat17','categorystat18','categorystat19','categorystat20','categorystat21','categorystat22','categorystat23','categorystat24','categorystat25','categorystat26','categorystat27','categorystat28','categorystat29','categorystat30','categorystat31','categorystat32','categorystat33','categorystat34','categorystat35','categorystat36','categorystat37','categorystat38','categorystat39','categorystat40','categorystat41','categorystat42','categorystat43','categorystat44','categorystat45','categorystat46','categorystat47','categorystat48','categorystat49','categorystat50','categorystat51','categorystat52','categorystat53','categorystat54','categorystat55','categorystat56','categorystat57','categorystat58','categorystat59','categorystat60','categorystat61','categorystat62','categorystat63','categorystat64','categorystat65','categorystat66','categorystat67','categorystat68','categorystat69','categorystat70','categorystat71','categorystat72','categorystat73','categorystat74','categorystat75','categorystat76','categorystat77','categorystat78','categorystat79','categorystat80','categorystat81','categorystat82','categorystat83','categorystat84','categorystat85','categorystat86','categorystat87','categorystat88','categorystat89','categorystat90','categorystat91','categorystat92','categorystat93','categorystat94','categorystat95','categorystat96','categorystat97','categorystat98','categorystat99','categorystat100','categorystat101','categorystat102','categorystat103','categorystat104','categorystat105','categorystat106','categorystat107','categorystat108','categorystat109','categorystat110','categorystat111','categorystat112','categorystat113','categorystat114','categorystat115','categorystat116','categorystat117','categorystat118','categorystat119','categorystat120'])),
        uuid=dict(type='str',)
    ))
   
    # Parent keys
    rv.update(dict(
        rule_set_name=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/rule-set/{rule_set_name}/tag"

    f_dict = {}
    f_dict["rule_set_name"] = module.params["rule_set_name"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/rule-set/{rule_set_name}/tag"

    f_dict = {}
    f_dict["rule_set_name"] = module.params["rule_set_name"]

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
    payload = build_json("tag", module)
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
    payload = build_json("tag", module)
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
    payload = build_json("tag", module)
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