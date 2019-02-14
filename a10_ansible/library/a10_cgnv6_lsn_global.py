#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_cgnv6_lsn_global
description:
    - Set Large-Scale NAT config parameters
short_description: Configures A10 cgnv6.lsn.global
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
    logging:
        description:
        - "Field logging"
        required: False
        suboptions:
            partition_name:
                description:
                - "Select partition name for logging"
            shared:
                description:
                - "Select shared partition"
            default_template:
                description:
                - "Bind the default NAT logging template for LSN (Bind a NAT logging template)"
            pool:
                description:
                - "Field pool"
    uuid:
        description:
        - "uuid of the object"
        required: False
    inbound_refresh:
        description:
        - "'disable'= Disable NAT Inbound Refresh Behavior; "
        required: False
    hairpinning:
        description:
        - "'filter-none'= Allow self-hairpinning (default). Warning= Only applies to UDP.  TCP will use filter-self-ip-port; 'filter-self-ip'= Block hairpinning to the user's own IP; 'filter-self-ip-port'= Block hairpinning to the user's same IP and port combination; "
        required: False
    port_batching:
        description:
        - "Field port_batching"
        required: False
        suboptions:
            tcp_time_wait_interval:
                description:
                - "Minutes before TCP NAT ports can be reused (default= 2)"
            size:
                description:
                - "'1'= Allocate 1 port at a time (default); '8'= Allocate 8 ports at a time; '16'= Allocate 16 ports at a time; '32'= Allocate 32 ports at a time; '64'= Allocate 64 ports at a time; '128'= Allocate 128 ports at a time; '256'= Allocate 256 ports at a time; '512'= Allocate 512 ports at a time; "
    half_close_timeout:
        description:
        - "Set LSN Half close timeout (Half close timeout in seconds (default not set))"
        required: False
    attempt_port_preservation:
        description:
        - "'disable'= Don't attempt port preservation for NAT allocation; "
        required: False
    ip_selection:
        description:
        - "'random'= Random (long-run uniformly distributed) NAT IP selection (default); 'round-robin'= Round-robin; 'least-used-strict'= Fewest NAT ports used; 'least-udp-used-strict'= Fewest UDP NAT ports used; 'least-tcp-used-strict'= Fewest TCP NAT ports used; 'least-reserved-strict'= Fewest NAT ports reserved; 'least-udp-reserved-strict'= Fewest UDP NAT ports reserved; 'least-tcp-reserved-strict'= Fewest TCP NAT ports reserved; 'least-users-strict'= Fewest number of users; "
        required: False
    syn_timeout:
        description:
        - "Set LSN SYN timeout (SYN idle-timeout in seconds (default= 4 seconds))"
        required: False
    icmp:
        description:
        - "Field icmp"
        required: False
        suboptions:
            send_on_user_quota_exceeded:
                description:
                - "'host-unreachable'= Send ICMP destination host unreachable; 'admin-filtered'= Send ICMP admin filtered (default); 'disable'= Disable ICMP quota exceeded message; "
            send_on_port_unavailable:
                description:
                - "'host-unreachable'= Send ICMP destination host unreachable; 'admin-filtered'= Send ICMP admin filtered; 'disable'= Disable ICMP port unavailable message (default); "


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["attempt_port_preservation","hairpinning","half_close_timeout","icmp","inbound_refresh","ip_selection","logging","port_batching","syn_timeout","uuid",]

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
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        state=dict(type='str', default="present", choices=["present", "absent"]),
        partition=dict(type='str', required=False)
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        logging=dict(type='dict',partition_name=dict(type='str',),shared=dict(type='bool',),default_template=dict(type='str',),pool=dict(type='list',template=dict(type='str',),pool_name=dict(type='str',))),
        uuid=dict(type='str',),
        inbound_refresh=dict(type='str',choices=['disable']),
        hairpinning=dict(type='str',choices=['filter-none','filter-self-ip','filter-self-ip-port']),
        port_batching=dict(type='dict',tcp_time_wait_interval=dict(type='int',),size=dict(type='str',choices=['1','8','16','32','64','128','256','512'])),
        half_close_timeout=dict(type='int',),
        attempt_port_preservation=dict(type='str',choices=['disable']),
        ip_selection=dict(type='str',choices=['random','round-robin','least-used-strict','least-udp-used-strict','least-tcp-used-strict','least-reserved-strict','least-udp-reserved-strict','least-tcp-reserved-strict','least-users-strict']),
        syn_timeout=dict(type='int',),
        icmp=dict(type='dict',send_on_user_quota_exceeded=dict(type='str',choices=['host-unreachable','admin-filtered','disable']),send_on_port_unavailable=dict(type='str',choices=['host-unreachable','admin-filtered','disable']))
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/cgnv6/lsn/global"
    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/cgnv6/lsn/global"
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
    payload = build_json("global", module)
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
    payload = build_json("global", module)
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
    partition = module.params["partition"]

    # TODO(remove hardcoded port #)
    a10_port = module.params["a10_port"] 
    a10_protocol = module.params["a10_protocol"]

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