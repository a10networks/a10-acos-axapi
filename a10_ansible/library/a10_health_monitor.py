#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_monitor
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - Monitor Name
    
    dsr-l2-strict:
        description:
            - Enable strict L2dsr health-check
    
    retry:
        description:
            - Specify the Healthcheck Retries (Retry Count (default 3))
    
    up-retry:
        description:
            - Specify the Healthcheck Retries before declaring target up (Up-retry count (default 1))
    
    override-ipv4:
        description:
            - Override implicitly inherited IPv4 address from target
    
    override-ipv6:
        description:
            - Override implicitly inherited IPv6 address from target
    
    override-port:
        description:
            - Override implicitly inherited port from target (Port number (1-65534))
    
    passive:
        description:
            - Specify passive mode
    
    status-code:
        description:
            - 'status-code-2xx': Enable passive mode with 2xx http status code; 'status-code-non-5xx': Enable passive mode with non-5xx http status code; choices:['status-code-2xx', 'status-code-non-5xx']
    
    passive-interval:
        description:
            - Interval to do manual health checking while in passive mode (Specify value in seconds (Default is 10 s))
    
    sample-threshold:
        description:
            - Number of samples in one epoch above which passive HC is enabled. If below or equal to the threshold, passive HC is disabled (Specify number of samples in one second (Default is 50). If the number of samples is 0, no action is taken)
    
    threshold:
        description:
            - Threshold percentage above which passive mode is enabled (Specify percentage (Default is 75%))
    
    strict-retry-on-server-err-resp:
        description:
            - Require strictly retry
    
    disable-after-down:
        description:
            - Disable the target if health check failed
    
    interval:
        description:
            - Specify the Healthcheck Interval (Interval Value, in seconds (default 5))
    
    timeout:
        description:
            - Specify the Healthcheck Timeout (Timeout Value, in seconds(default 5), Timeout should be less than or equal to interval)
    
    ssl-ciphers:
        description:
            - Specify OpenSSL Cipher Suite name(s) for Health check (OpenSSL Cipher Suite(s) (Eg: AES128-SHA256), if the cipher is invalid, would give information at HM down reason)
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    method:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"disable_after_down","dsr_l2_strict","interval","method","name","override_ipv4","override_ipv6","override_port","passive","passive_interval","retry","sample_threshold","ssl_ciphers","status_code","strict_retry_on_server_err_resp","threshold","timeout","up_retry","user_tag","uuid",}

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
        
        disable_after_down=dict(
            type='str' 
        ),
        dsr_l2_strict=dict(
            type='str' 
        ),
        interval=dict(
            type='str' 
        ),
        method=dict(
            type='dict' 
        ),
        name=dict(
            type='str' , required=True
        ),
        override_ipv4=dict(
            type='str' 
        ),
        override_ipv6=dict(
            type='str' 
        ),
        override_port=dict(
            type='str' 
        ),
        passive=dict(
            type='str' 
        ),
        passive_interval=dict(
            type='str' 
        ),
        retry=dict(
            type='str' 
        ),
        sample_threshold=dict(
            type='str' 
        ),
        ssl_ciphers=dict(
            type='str' 
        ),
        status_code=dict(
            type='enum' , choices=['status-code-2xx', 'status-code-non-5xx']
        ),
        strict_retry_on_server_err_resp=dict(
            type='str' 
        ),
        threshold=dict(
            type='str' 
        ),
        timeout=dict(
            type='str' 
        ),
        up_retry=dict(
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
    url_base = "/axapi/v3/health/monitor/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/health/monitor/{name}"
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

def update(module, result):
    payload = build_json("monitor", module)
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
