#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_ethernet
description:
    - 
author: A10 Networks 2018 
version_added: 1.8

options:
    
    ifnum:
        description:
            - Ethernet interface number
    
    name:
        description:
            - Name for the interface
    
    l3-vlan-fwd-disable:
        
    
    load-interval:
        description:
            - Configure Load Interval (Seconds (5-300, Multiple of 5), default 300)
    
    media-type-copper:
        description:
            - Set the media type to copper
    
    auto-neg-enable:
        description:
            - enable auto-negotiation
    
    fec-forced-on:
        description:
            - turn on the FEC
    
    fec-forced-off:
        description:
            - turn off the FEC
    
    speed-forced-40g:
        description:
            - force the speed to be 40G on 100G link
    
    remove-vlan-tag:
        description:
            - Remove the vlan tag for egressing packets
    
    mtu:
        description:
            - Interface mtu (Interface MTU, default 1 (min MTU is 1280 for IPv6))
    
    trap-source:
        description:
            - The trap source
    
    duplexity:
        description:
            - 'Full': Full; 'Half': Half; 'auto': auto; choices:['Full', 'Half', 'auto']
    
    speed:
        description:
            - '10': 10; '100': 100; '1000': 1000; 'auto': auto; choices:['10', '100', '1000', 'auto']
    
    flow-control:
        description:
            - Enable 802.3x flow control on full duplex port
    
    action:
        description:
            - 'enable': Enable; 'disable': Disable; choices:['enable', 'disable']
    
    icmp-rate-limit:
        
    
    icmpv6-rate-limit:
        
    
    monitor-list:
        
    
    cpu-process:
        description:
            - All Packets to this port are processed by CPU
    
    cpu-process-dir:
        description:
            - 'primary': Primary board; 'blade': blade board; 'hash-dip': Hash based on the Destination IP; 'hash-sip': Hash based on the Source IP; 'hash-dmac': Hash based on the Destination MAC; 'hash-smac': Hash based on the Source MAC; choices:['primary', 'blade', 'hash-dip', 'hash-sip', 'hash-dmac', 'hash-smac']
    
    traffic-distribution-mode:
        description:
            - 'sip': sip; 'dip': dip; 'primary': primary; 'blade': blade; 'l4-src-port': l4-src-port; 'l4-dst-port': l4-dst-port; choices:['sip', 'dip', 'primary', 'blade', 'l4-src-port', 'l4-dst-port']
    
    access-list:
        
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    sampling-enable:
        
    
    lldp:
        
    
    ddos:
        
    
    ip:
        
    
    ipv6:
        
    
    nptv6:
        
    
    map:
        
    
    lw-4o6:
        
    
    trunk-group-list:
        
    
    bfd:
        
    
    isis:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = {"access_list","action","auto_neg_enable","bfd","cpu_process","cpu_process_dir","ddos","duplexity","fec_forced_off","fec_forced_on","flow_control","icmp_rate_limit","icmpv6_rate_limit","ifnum","ip","ipv6","isis","l3_vlan_fwd_disable","lldp","load_interval","lw_4o6","map","media_type_copper","monitor_list","mtu","name","nptv6","remove_vlan_tag","sampling_enable","speed","speed_forced_40g","traffic_distribution_mode","trap_source","trunk_group_list","user_tag","uuid",}

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
        
        access_list=dict(
            type='str' 
        ),
        action=dict(
            type='enum' , choices=['enable', 'disable']
        ),
        auto_neg_enable=dict(
            type='str' 
        ),
        bfd=dict(
            type='str' 
        ),
        cpu_process=dict(
            type='str' 
        ),
        cpu_process_dir=dict(
            type='enum' , choices=['primary', 'blade', 'hash-dip', 'hash-sip', 'hash-dmac', 'hash-smac']
        ),
        ddos=dict(
            type='str' 
        ),
        duplexity=dict(
            type='enum' , choices=['Full', 'Half', 'auto']
        ),
        fec_forced_off=dict(
            type='str' 
        ),
        fec_forced_on=dict(
            type='str' 
        ),
        flow_control=dict(
            type='str' 
        ),
        icmp_rate_limit=dict(
            type='str' 
        ),
        icmpv6_rate_limit=dict(
            type='str' 
        ),
        ifnum=dict(
            type='str' , required=True
        ),
        ip=dict(
            type='str' 
        ),
        ipv6=dict(
            type='str' 
        ),
        isis=dict(
            type='str' 
        ),
        l3_vlan_fwd_disable=dict(
            type='str' 
        ),
        lldp=dict(
            type='str' 
        ),
        load_interval=dict(
            type='str' 
        ),
        lw_4o6=dict(
            type='str' 
        ),
        map=dict(
            type='str' 
        ),
        media_type_copper=dict(
            type='str' 
        ),
        monitor_list=dict(
            type='str' 
        ),
        mtu=dict(
            type='str' 
        ),
        name=dict(
            type='str' 
        ),
        nptv6=dict(
            type='str' 
        ),
        remove_vlan_tag=dict(
            type='str' 
        ),
        sampling_enable=dict(
            type='str' 
        ),
        speed=dict(
            type='enum' , choices=['10', '100', '1000', 'auto']
        ),
        speed_forced_40g=dict(
            type='str' 
        ),
        traffic_distribution_mode=dict(
            type='enum' , choices=['sip', 'dip', 'primary', 'blade', 'l4-src-port', 'l4-dst-port']
        ),
        trap_source=dict(
            type='str' 
        ),
        trunk_group_list=dict(
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
    url_base = "/axapi/v3/interface/ethernet/{ifnum}"
    f_dict = {}
    
    f_dict["ifnum"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/interface/ethernet/{ifnum}"
    f_dict = {}
    
    f_dict["ifnum"] = module.params["ifnum"]

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
    payload = build_json("ethernet", module)
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
    payload = build_json("ethernet", module)
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