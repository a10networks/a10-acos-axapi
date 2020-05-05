#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_vcs_vblades_stat
description:
    - Show aVCS vBlade box statistics information
short_description: Configures A10 vcs-vblades.stat
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
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
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "'all'= all; 'slave_recv_err'= vBlade Receive Errors counter of aVCS election; 'slave_send_err'= vBlade Send Errors counter of aVCS election; 'slave_recv_bytes'= vBlade Received Bytes counter of aVCS election; 'slave_sent_bytes'= vBlade Sent Bytes counter of aVCS election; 'slave_n_recv'= vBlade Received Messages counter of aVCS election; 'slave_n_sent'= vBlade Sent Messages counter of aVCS election; 'slave_msg_inval'= vBlade Invalid Messages counter of aVCS election; 'slave_keepalive'= vBlade Received Keepalives counter of aVCS election; 'slave_cfg_upd'= vBlade Received Configuration Updates counter of aVCS election; 'slave_cfg_upd_l1_fail'= vBlade Local Configuration Update Errors (1) counter of aVCS election; 'slave_cfg_upd_r_fail'= vBlade Remote Configuration Update Errors counter of aVCS election; 'slave_cfg_upd_l2_fail'= vBlade Local Configuration Update Errors (2) counter of aVCS election; 'slave_cfg_upd_notif_err'= vBlade Configuration Update Notif Errors counter of aVCS election; 'slave_cfg_upd_result_err'= vBlade Configuration Update Result Errors counter of aVCS election; "
    vblade_id:
        description:
        - "vBlade-id"
        required: True
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            slave_recv_bytes:
                description:
                - "vBlade Received Bytes counter of aVCS election"
            slave_cfg_upd_r_fail:
                description:
                - "vBlade Remote Configuration Update Errors counter of aVCS election"
            slave_cfg_upd_result_err:
                description:
                - "vBlade Configuration Update Result Errors counter of aVCS election"
            slave_cfg_upd:
                description:
                - "vBlade Received Configuration Updates counter of aVCS election"
            slave_msg_inval:
                description:
                - "vBlade Invalid Messages counter of aVCS election"
            slave_n_recv:
                description:
                - "vBlade Received Messages counter of aVCS election"
            slave_cfg_upd_notif_err:
                description:
                - "vBlade Configuration Update Notif Errors counter of aVCS election"
            slave_keepalive:
                description:
                - "vBlade Received Keepalives counter of aVCS election"
            slave_recv_err:
                description:
                - "vBlade Receive Errors counter of aVCS election"
            slave_n_sent:
                description:
                - "vBlade Sent Messages counter of aVCS election"
            vblade_id:
                description:
                - "vBlade-id"
            slave_send_err:
                description:
                - "vBlade Send Errors counter of aVCS election"
            slave_cfg_upd_l1_fail:
                description:
                - "vBlade Local Configuration Update Errors (1) counter of aVCS election"
            slave_cfg_upd_l2_fail:
                description:
                - "vBlade Local Configuration Update Errors (2) counter of aVCS election"
            slave_sent_bytes:
                description:
                - "vBlade Sent Bytes counter of aVCS election"
    uuid:
        description:
        - "uuid of the object"
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
AVAILABLE_PROPERTIES = ["sampling_enable","stats","uuid","vblade_id",]

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
        state=dict(type='str', default="noop", choices=['noop']),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        sampling_enable=dict(type='list', counters1=dict(type='str', choices=['all', 'slave_recv_err', 'slave_send_err', 'slave_recv_bytes', 'slave_sent_bytes', 'slave_n_recv', 'slave_n_sent', 'slave_msg_inval', 'slave_keepalive', 'slave_cfg_upd', 'slave_cfg_upd_l1_fail', 'slave_cfg_upd_r_fail', 'slave_cfg_upd_l2_fail', 'slave_cfg_upd_notif_err', 'slave_cfg_upd_result_err'])),
        vblade_id=dict(type='int', required=True, ),
        stats=dict(type='dict', slave_recv_bytes=dict(type='str', ), slave_cfg_upd_r_fail=dict(type='str', ), slave_cfg_upd_result_err=dict(type='str', ), slave_cfg_upd=dict(type='str', ), slave_msg_inval=dict(type='str', ), slave_n_recv=dict(type='str', ), slave_cfg_upd_notif_err=dict(type='str', ), slave_keepalive=dict(type='str', ), slave_recv_err=dict(type='str', ), slave_n_sent=dict(type='str', ), vblade_id=dict(type='int', required=True, ), slave_send_err=dict(type='str', ), slave_cfg_upd_l1_fail=dict(type='str', ), slave_cfg_upd_l2_fail=dict(type='str', ), slave_sent_bytes=dict(type='str', )),
        uuid=dict(type='str', )
    ))
   

    return rv

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/vcs-vblades/stat/{vblade-id}"

    f_dict = {}
    f_dict["vblade-id"] = module.params["vblade_id"]

    return url_base.format(**f_dict)

def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

def get(module):
    return module.client.get(existing_url(module))

def get_list(module):
    return module.client.get(list_url(module))

def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k,v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module),
                                 params=query_params)
    return module.client.get(stats_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

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

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    
    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)
    
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
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