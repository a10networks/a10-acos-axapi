#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_pki_scep_cert
description:
    - SCEP Certificate enrollment object
short_description: Configures A10 pki.scep-cert
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
    a10_device_context_id:
        description:
        - Device ID for aVCS configuration
        choices: [1-8]
        required: False
    a10_partition:
        description:
        - Destination/target partition for object/command
        required: False
    renew_every_type:
        description:
        - "'hour'= Periodic interval in hours; 'day'= Periodic interval in days; 'week'= Periodic interval in weeks; 'month'= Periodic interval in months(1 month=30 days); "
        required: False
    encrypted:
        description:
        - "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED secret string)"
        required: False
    log_level:
        description:
        - "level for logging output of scepclient commands(default 1 and detailed 4)"
        required: False
    uuid:
        description:
        - "uuid of the object"
        required: False
    renew_before_type:
        description:
        - "'hour'= Number of hours before cert expiry; 'day'= Number of days before cert expiry; 'week'= Number of weeks before cert expiry; 'month'= Number of months before cert expiry(1 month=30 days); "
        required: False
    renew_every:
        description:
        - "Specify periodic interval in which to renew the certificate"
        required: False
    key_length:
        description:
        - "'1024'= Key size 1024 bits; '2048'= Key size 2048 bits(default); '4096'= Key size 4096 bits; '8192'= Key size 8192 bits; "
        required: False
    method:
        description:
        - "'GET'= GET request; 'POST'= POST request; "
        required: False
    dn:
        description:
        - "Specify the Distinguished-Name to use while enrolling the certificate (Format= 'cn=user, dc=example, dc=com')"
        required: False
    subject_alternate_name:
        description:
        - "Field subject_alternate_name"
        required: False
        suboptions:
            san_type:
                description:
                - "'email'= Enter e-mail address of the subject; 'dns'= Enter hostname of the subject; 'ip'= Enter IP address of the subject; "
            san_value:
                description:
                - "Value of subject-alternate-name"
    renew_every_value:
        description:
        - "Value of renewal period"
        required: False
    max_polltime:
        description:
        - "Maximum time in seconds to poll when SCEP response is PENDING (default 180)"
        required: False
    password:
        description:
        - "Specify the password used to enroll the device's certificate"
        required: False
    minute:
        description:
        - "Periodic interval in minutes"
        required: False
    secret_string:
        description:
        - "secret password"
        required: False
    enroll:
        description:
        - "Initiates enrollment of device with the CA"
        required: False
    renew_before_value:
        description:
        - "Value of renewal period"
        required: False
    name:
        description:
        - "Specify Certificate name to be enrolled"
        required: True
    url:
        description:
        - "Specify the Enrollment Agent's absolute URL (Format= http=//host/path)"
        required: False
    interval:
        description:
        - "Interval time in seconds to poll when SCEP response is PENDING (default 5)"
        required: False
    user_tag:
        description:
        - "Customized tag"
        required: False
    renew_before:
        description:
        - "Specify interval before certificate expiry to renew the certificate"
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
AVAILABLE_PROPERTIES = ["dn","encrypted","enroll","interval","key_length","log_level","max_polltime","method","minute","name","password","renew_before","renew_before_type","renew_before_value","renew_every","renew_every_type","renew_every_value","secret_string","subject_alternate_name","url","user_tag","uuid",]

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
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        renew_every_type=dict(type='str',choices=['hour','day','week','month']),
        encrypted=dict(type='str',),
        log_level=dict(type='int',),
        uuid=dict(type='str',),
        renew_before_type=dict(type='str',choices=['hour','day','week','month']),
        renew_every=dict(type='bool',),
        key_length=dict(type='str',choices=['1024','2048','4096','8192']),
        method=dict(type='str',choices=['GET','POST']),
        dn=dict(type='str',),
        subject_alternate_name=dict(type='dict',san_type=dict(type='str',choices=['email','dns','ip']),san_value=dict(type='str',)),
        renew_every_value=dict(type='int',),
        max_polltime=dict(type='int',),
        password=dict(type='bool',),
        minute=dict(type='int',),
        secret_string=dict(type='str',),
        enroll=dict(type='bool',),
        renew_before_value=dict(type='int',),
        name=dict(type='str',required=True,),
        url=dict(type='str',),
        interval=dict(type='int',),
        user_tag=dict(type='str',),
        renew_before=dict(type='bool',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/pki/scep-cert/{name}"

    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/pki/scep-cert/{name}"

    f_dict = {}
    f_dict["name"] = module.params["name"]

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

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["scep-cert"].items():
            if isinstance(v, str):
                if v.lower() == "true":
                    v = 1
                else:
                    if v.lower() == "false":
                        v = 0
            elif k not in payload:
               break
            else:
                if existing_config["scep-cert"][k] != v:
                    if result["changed"] != True:
                        result["changed"] = True
                    existing_config["scep-cert"][k] = v
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
    payload = build_json("scep-cert", module)
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