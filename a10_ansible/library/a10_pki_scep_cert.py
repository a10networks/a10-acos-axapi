#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_scep-cert
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - Specify Certificate name to be enrolled
    
    url:
        description:
            - Specify the Enrollment Agent's absolute URL (Format: http://host/path)
    
    dn:
        description:
            - Specify the Distinguished-Name to use while enrolling the certificate (Format: "cn=user, dc=example, dc=com")
    
    subject-alternate-name:
        
    
    enroll:
        description:
            - Initiates enrollment of device with the CA
    
    log-level:
        description:
            - level for logging output of scepclient commands(default 1 and detailed 4)
    
    password:
        description:
            - Specify the password used to enroll the device's certificate
    
    secret-string:
        description:
            - secret password
    
    encrypted:
        description:
            - Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED secret string)
    
    renew-before:
        description:
            - Specify interval before certificate expiry to renew the certificate
    
    renew-before-type:
        description:
            - 'hour': Number of hours before cert expiry; 'day': Number of days before cert expiry; 'week': Number of weeks before cert expiry; 'month': Number of months before cert expiry(1 month=30 days); choices:['hour', 'day', 'week', 'month']
    
    renew-before-value:
        description:
            - Value of renewal period
    
    renew-every:
        description:
            - Specify periodic interval in which to renew the certificate
    
    minute:
        description:
            - Periodic interval in minutes
    
    renew-every-type:
        description:
            - 'hour': Periodic interval in hours; 'day': Periodic interval in days; 'week': Periodic interval in weeks; 'month': Periodic interval in months(1 month=30 days); choices:['hour', 'day', 'week', 'month']
    
    renew-every-value:
        description:
            - Value of renewal period
    
    key-length:
        description:
            - '1024': Key size 1024 bits; '2048': Key size 2048 bits(default); '4096': Key size 4096 bits; '8192': Key size 8192 bits; choices:['1024', '2048', '4096', '8192']
    
    method:
        description:
            - 'GET': GET request; 'POST': POST request; choices:['GET', 'POST']
    
    interval:
        description:
            - Interval time in seconds to poll when SCEP response is PENDING (default 5)
    
    max-polltime:
        description:
            - Maximum time in seconds to poll when SCEP response is PENDING (default 180)
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"dn","encrypted","enroll","interval","key_length","log_level","max_polltime","method","minute","name","password","renew_before","renew_before_type","renew_before_value","renew_every","renew_every_type","renew_every_value","secret_string","subject_alternate_name","url","user_tag","uuid",}

# our imports go at the top so we fail fast.
from a10_ansible.axapi_http import client_factory
from a10_ansible import errors as a10_ex

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
        
        dn=dict(
            type='str' 
        ),
        encrypted=dict(
            type='str' 
        ),
        enroll=dict(
            type='str' 
        ),
        interval=dict(
            type='str' 
        ),
        key_length=dict(
            type='enum' , choices=['1024', '2048', '4096', '8192']
        ),
        log_level=dict(
            type='str' 
        ),
        max_polltime=dict(
            type='str' 
        ),
        method=dict(
            type='enum' , choices=['GET', 'POST']
        ),
        minute=dict(
            type='str' 
        ),
        name=dict(
            type='str' , required=True
        ),
        password=dict(
            type='str' 
        ),
        renew_before=dict(
            type='str' 
        ),
        renew_before_type=dict(
            type='enum' , choices=['hour', 'day', 'week', 'month']
        ),
        renew_before_value=dict(
            type='str' 
        ),
        renew_every=dict(
            type='str' 
        ),
        renew_every_type=dict(
            type='enum' , choices=['hour', 'day', 'week', 'month']
        ),
        renew_every_value=dict(
            type='str' 
        ),
        secret_string=dict(
            type='str' 
        ),
        subject_alternate_name=dict(
            type='str' 
        ),
        url=dict(
            type='str' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ), 
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


def build_envelope(title, data):
    return {
        title: data
    }

def build_json(title, module):
    rv = {}
    for x in AVAILABLE_PROPERTIES:
        v = module.params.get(x)
        if v:
            rx = x.replace("_", "-")
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

def exists(module):
    try:
        module.client.get(existing_url(module))
        return True
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("scep-cert", module)
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

def update(module, result):
    payload = build_json("scep-cert", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
        result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def present(module, result):
    if not exists(module):
        return create(module, result)
    else:
        return update(module, result)

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

    valid, validation_errors = validate(module.params)
    map(run_errors.append, validation_errors)
    
    if not valid:
        result["messages"] = "Validation failure"
        err_msg = "\n".join(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)

    if state == 'present':
        result = present(module, result)
    elif state == 'absent':
        result = absent(module, result)
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