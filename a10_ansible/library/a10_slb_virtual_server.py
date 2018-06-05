#!/usr/bin/python
REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = """
module: a10_slb_virtual-server
description:
    - Create a Virtual Server
author: A10 Networks 2018 
version_added: 1.8

options:
    
    name:
        description:
            - SLB Virtual Server Name
    
    ipv6-address:
        description:
            - IPV6 address
    
    ip-address:
        description:
            - IP Address
    
    netmask:
        description:
            - IP subnet mask
    
    ipv6-acl:
        description:
            - ipv6 acl name
    
    acl-id:
        description:
            - acl id
    
    acl-name:
        description:
            - Access List name (IPv4 Access List Name)
    
    use-if-ip:
        description:
            - Use Interface IP
    
    ethernet:
        description:
            - Ethernet interface
    
    description:
        description:
            - Create a description for VIP
    
    enable-disable-action:
        description:
            - 'enable': Enable Virtual Server (default); 'disable': Disable Virtual Server; 'disable-when-all-ports-down': Disable Virtual Server when all member ports are down; 'disable-when-any-port-down': Disable Virtual Server when any member port is down; choices:['enable', 'disable', 'disable-when-all-ports-down', 'disable-when-any-port-down']
    
    redistribution-flagged:
        description:
            - Flag VIP for special redistribution handling
    
    arp-disable:
        description:
            - Disable Respond to Virtual Server ARP request
    
    template-policy:
        description:
            - Policy template (Policy template name)
    
    template-virtual-server:
        description:
            - Virtual server template (Virtual server template name)
    
    template-logging:
        description:
            - NAT Logging template (NAT Logging template name)
    
    template-scaleout:
        description:
            - Scaleout template (Scaleout template name)
    
    stats-data-action:
        description:
            - 'stats-data-enable': Enable statistical data collection for virtual server; 'stats-data-disable': Disable statistical data collection for virtual server; choices:['stats-data-enable', 'stats-data-disable']
    
    extended-stats:
        description:
            - Enable extended statistics on virtual server
    
    vrid:
        description:
            - Join a vrrp group (Specify ha VRRP-A vrid)
    
    disable-vip-adv:
        description:
            - Disable virtual server GARP and route advertisements
    
    redistribute-route-map:
        description:
            - Route map reference (Name of route-map)
    
    uuid:
        description:
            - uuid of the object
    
    user-tag:
        description:
            - Customized tag
    
    migrate-vip:
        
    
    port-list:
        
    

"""

EXAMPLES = """
"""

ANSIBLE_METADATA = """
"""

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["acl_id","acl_name","arp_disable","description","disable_vip_adv","enable_disable_action","ethernet","extended_stats","ip_address","ipv6_acl","ipv6_address","migrate_vip","name","netmask","port_list","redistribute_route_map","redistribution_flagged","stats_data_action","template_logging","template_policy","template_scaleout","template_virtual_server","use_if_ip","user_tag","uuid","vrid",]

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
        
        acl_id=dict(
            type='int' 
        ),
        acl_name=dict(
            type='str' 
        ),
        arp_disable=dict(
            type='bool' 
        ),
        description=dict(
            type='str' 
        ),
        disable_vip_adv=dict(
            type='bool' 
        ),
        enable_disable_action=dict(
            type='str' , choices=['enable', 'disable', 'disable-when-all-ports-down', 'disable-when-any-port-down']
        ),
        ethernet=dict(
            type='str' 
        ),
        extended_stats=dict(
            type='bool' 
        ),
        ip_address=dict(
            type='str' 
        ),
        ipv6_acl=dict(
            type='str' 
        ),
        ipv6_address=dict(
            type='str' 
        ),
        migrate_vip=dict(
            type='str' 
        ),
        name=dict(
            type='str' , required=True
        ),
        netmask=dict(
            type='str' 
        ),
        port_list=dict(
            type='list' 
        ),
        redistribute_route_map=dict(
            type='str' 
        ),
        redistribution_flagged=dict(
            type='bool' 
        ),
        stats_data_action=dict(
            type='str' , choices=['stats-data-enable', 'stats-data-disable']
        ),
        template_logging=dict(
            type='str' 
        ),
        template_policy=dict(
            type='str' 
        ),
        template_scaleout=dict(
            type='str' 
        ),
        template_virtual_server=dict(
            type='str' 
        ),
        use_if_ip=dict(
            type='bool' 
        ),
        user_tag=dict(
            type='str' 
        ),
        uuid=dict(
            type='str' 
        ),
        vrid=dict(
            type='int' 
        ), 
    ))
    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/slb/virtual-server/{name}"
    f_dict = {}
    
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/slb/virtual-server/{name}"
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
        # else:
        #     del module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted(['ip_address','ipv6_address',])
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
        return module.client.get(existing_url(module))
    except a10_ex.NotFound:
        return False

def create(module, result):
    payload = build_json("virtual-server", module)
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
    payload = build_json("virtual-server", module)
    try:
        post_result = module.client.put(existing_url(module), payload)
        result.update(**post_result)
        if post_result == existing_config:
            result["changed"] = False
        else:
            # Only return a changed result if existing config and post result differ
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