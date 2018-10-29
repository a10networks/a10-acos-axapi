#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_logging
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - Logging template name
    
    resolution:
        description:
            - 'seconds': Logging timestamp resolution in seconds (default); '10-milliseconds': Logging timestamp resolution in 10s of milli-seconds; choices:['seconds', '10-milliseconds']
    
    log:
        
    
    include_destination:
        description:
            - Include the destination IP and port in logs
    
    include_inside_user_mac:
        description:
            - Include the inside user MAC address in logs
    
    include_partition_name:
        description:
            - Include partition name in logging events
    
    include_session_byte_count:
        description:
            - include byte count in session deletion logs
    
    include_radius_attribute:
        
    
    include_http:
        
    
    rule:
        
    
    facility:
        description:
            - 'kernel': 0: Kernel; 'user': 1: User-level; 'mail': 2: Mail; 'daemon': 3: System daemons; 'security-authorization': 4: Security/authorization; 'syslog': 5: Syslog internal; 'line-printer': 6: Line printer; 'news': 7: Network news; 'uucp': 8: UUCP subsystem; 'cron': 9: Time-related; 'security-authorization-private': 10: Private security/authorization; 'ftp': 11: FTP; 'ntp': 12: NTP; 'audit': 13: Audit; 'alert': 14: Alert; 'clock': 15: Clock-related; 'local0': 16: Local use 0; 'local1': 17: Local use 1; 'local2': 18: Local use 2; 'local3': 19: Local use 3; 'local4': 20: Local use 4; 'local5': 21: Local use 5; 'local6': 22: Local use 6; 'local7': 23: Local use 7; choices:['kernel', 'user', 'mail', 'daemon', 'security-authorization', 'syslog', 'line-printer', 'news', 'uucp', 'cron', 'security-authorization-private', 'ftp', 'ntp', 'audit', 'alert', 'clock', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7']
    
    severity:
        
    
    format:
        description:
            - 'binary': Binary logging format; 'compact': Compact ASCII logging format (Hex format with compact representation); 'custom': Arbitrary custom logging format; 'default': Default A10 logging format (ASCII); 'rfc5424': RFC5424 compliant logging format; 'cef': Common Event Format for logging; choices:['binary', 'compact', 'custom', 'default', 'rfc5424', 'cef']
    
    batched_logging_disable:
        description:
            - Disable multiple logs per packet
    
    log_receiver:
        
    
    service_group:
        description:
            - Set NAT logging service-group
    
    shared:
        description:
            - Service group is in shared patition
    
    source_port:
        
    
    rfc_custom:
        
    
    custom:
        
    
    uuid:
        description:
            - uuid of the object
    
    user_tag:
        description:
            - Customized tag
    
    source_address:
        
    
    disable_log_by_destination:
        
    

"""

EXAMPLES = """
- name: Create a10_cgnv6_template_logging
  a10_cgnv6_template_logging:
      a10_host: "{{ inventory_hostname }}"
      a10_username: admin
      a10_password: a10
      name: "FIXED-LOG-ANSIBLE"
      format: "compact"
      service_group: "SG-ANSIBLE"
      facility: "local5"
      include_destination: 1
      batched_logging_disable: 1
      log: {
        "fixed-nat": {
          "fixed-nat-port-mappings":"both",
          "fixed-nat-sessions":1
        },
        "sessions":1
      }
      disable_log_by_destination: {
        "udp-list": [
          {
            "udp-port-start":53,
            "udp-port-end":53
          }
        ],
        "icmp":1
      }

"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"batched_logging_disable","custom","disable_log_by_destination","facility","format","include_destination","include_http","include_inside_user_mac","include_partition_name","include_radius_attribute","include_session_byte_count","log","log_receiver","name","resolution","rfc_custom","rule","service_group","severity","shared","source_address","source_port","user_tag","uuid",}

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
        
        batched_logging_disable=dict(
            type='str' 
        ),
        custom=dict(
            type='str' 
        ),
        disable_log_by_destination=dict(
            type='dict' 
        ),
        facility=dict(
            type='str', choices=['kernel', 'user', 'mail', 'daemon', 'security-authorization', 'syslog', 'line-printer', 'news', 'uucp', 'cron', 'security-authorization-private', 'ftp', 'ntp', 'audit', 'alert', 'clock', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7']
        ),
        format=dict(
            type='str', choices=['binary', 'compact', 'custom', 'default', 'rfc5424', 'cef']
        ),
        include_destination=dict(
            type='str' 
        ),
        include_http=dict(
            type='str' 
        ),
        include_inside_user_mac=dict(
            type='str' 
        ),
        include_partition_name=dict(
            type='str' 
        ),
        include_radius_attribute=dict(
            type='str' 
        ),
        include_session_byte_count=dict(
            type='str' 
        ),
        log=dict(
            type='dict' 
        ),
        log_receiver=dict(
            type='str' 
        ),
        name=dict(
            type='str' , required=True
        ),
        resolution=dict(
            type='enum' , choices=['seconds', '10-milliseconds']
        ),
        rfc_custom=dict(
            type='str' 
        ),
        rule=dict(
            type='str' 
        ),
        service_group=dict(
            type='str' 
        ),
        severity=dict(
            type='str' 
        ),
        shared=dict(
            type='str' 
        ),
        source_address=dict(
            type='str' 
        ),
        source_port=dict(
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
    url_base = "/axapi/v3/cgnv6/template/logging/"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/template/logging/{name}"
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
    payload = build_json("logging", module)
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
    payload = build_json("logging", module)
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
