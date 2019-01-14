#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
DEP_TASKNAME = "!taskname"
DEP_REQUIRES = "!requires"
DEP_FIELDS = "!fields"
DEP_KEY = "!key"
DEP_ENVELOPE = "!envelope"

SLB_TEMPLATE_CLIENT_SSL = "slb.template.client-ssl-list"
SLB_TEMPLATE_PERSIST_SOURCE_IP = "slb.template.persist.source-ip-list"
SLB_TEMPLATE_FTP = "slb.template.ftp-list"
SLB_VIRTUAL_SERVER = "slb.virtual-server-list"
SLB_SERVER = "slb.server-list"
SLB_SERVICE_GROUP = "slb.service-group-list"

FIELD_BLACKLIST = ["uuid", "a10-url", "direct-client-server-auth"]

DEFAULT_PLAYBOOK_DICT = {
    "hosts": "all",
    "name": "{0} Configuration Playbook",
    "connection": "local",
    "tasks": [] 
}

DEFAULT_TASK_DICT = {
        "a10_username": "{{ a10_username }}",
        "a10_password": "{{ a10_password }}",
        "a10_host": "{{ a10_host }}",
#        "a10_port": "{{ a10_port }}"
}

# The order in which we build the playbook because dependencies matter.
PATHS = [
    SLB_TEMPLATE_CLIENT_SSL,
    SLB_TEMPLATE_PERSIST_SOURCE_IP,
    SLB_TEMPLATE_FTP,
    SLB_VIRTUAL_SERVER,
    SLB_SERVER,
    SLB_SERVICE_GROUP,
]

PATH_MAPPING = {
        SLB_TEMPLATE_CLIENT_SSL: {
            DEP_TASKNAME: "slb_template_client_ssl",
            DEP_ENVELOPE: "client-ssl",
        },
        SLB_VIRTUAL_SERVER: {
            DEP_TASKNAME: "slb_virtual_server",
            DEP_ENVELOPE: "virtual-server"
        },
        SLB_SERVER: {
            DEP_TASKNAME: "slb_server",
            DEP_ENVELOPE: "server"
        },
        SLB_SERVICE_GROUP: {
            DEP_TASKNAME: "slb_service_group",
            DEP_ENVELOPE: "service-group"
        },
}

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_playbook_generator 
description:
    - Generate a10-ansible YAML playbooks from existing ACOS configuration
short_description: Generate playbooks from configuration. 
author: A10 Networks 2018 
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created. (Ansible requirement, ignored)
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
    output_path:
        description:
        - Output path for playbooks
        required: True
    file_per_task:
        description:
        - Do we generate a file per task?
        default:
        - True
    link_dependencies:
        description:
        - Do we link dependent objects? Recommended.
        default:
        - True


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["at","cancel","day_of_month","day_of_month_2","nin","month","month_2","reason","reason_2","reason_3","time",]

# our imports go at the top so we fail fast.
try:
    from a10_ansible import errors as a10_ex
    from a10_ansible.axapi_http import client_factory, session_factory
    from a10_ansible.kwbl import KW_IN, KW_OUT, translate_blacklist as translateBlacklist

    import copy
    import json
    import os
    import yaml

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
        # Output path for libararies
        output_path=dict(type='str', required=True),
        # Do we create a file for every task or throw 'em all together?
        file_per_task=dict(type='bool', default=True),
        # Link dependent tasks?
        link_dependencies=dict(type='bool', default=False)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/shutdown"
    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3"
    f_dict = {}

    return url_base.format(**f_dict)


def build_envelope(title, data):
    return {
        title: data
    }

def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")

def _from_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("-", "_")

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

def url_path(path):
    return "/axapi/v3/{0}".format(path)

def absent(module, result):
    return delete(module, result)

def get_fq_path(path, demarc="."):
    return path.split(demarc)

def get_nested(target, path):
    tl = target[path[0]] 
    for x in path[1:]:
        tl = tl[x]
    return tl

def transform_keys(in_dict):
    rv = {}
    if not type(in_dict) is dict:
        raise Exception("Argument is not a dictionary")
    for k,v in in_dict.items():
        nk = k.replace("-", "_")
        if type(v) is dict:
            v = transform_keys(v)
        if not k in FIELD_BLACKLIST:
            rv[nk] = v

    return rv 

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
   
    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)

    # Iterate through dependency tree, depth-first.
        # Query the path
        # Parse result
        # Generate playbook

    slb = module.client.get(url_path("slb"))

    output_path = module.params.get("output_path")

    for px in PATHS:
        fq_path = get_fq_path(px)
        t_val = get_nested(slb, fq_path)
        t_dict = PATH_MAPPING.get(px)

        playbook_dict = {
                "hosts": "all",
                "name": "{0} Configuration Playbook",
                "connection": "local",
                "tasks": []
        }
    
        if t_dict:
            taskname = t_dict[DEP_TASKNAME]
            env_key = t_dict[DEP_ENVELOPE]

            # For each object in the list
            for obj in t_val:
                # default task
                task_dict = {}
                obj = transform_keys(obj)
                task_dict.update(DEFAULT_TASK_DICT)
                task_dict.update(obj)
                formatted_task = "a10_{0}".format(taskname)
                taskdesc = "Create {0} instance".format(taskname)
                playbook_dict["tasks"].append({"name": taskdesc, formatted_task: task_dict})
                
                # Wrap it in the taskname

            shortname = "{0}.yaml".format(px)
            playbook_path = os.path.join(output_path, shortname)
            with open(playbook_path, 'w') as playbook_f:
                yaml.safe_dump([playbook_dict], playbook_f, default_flow_style=False)

    slb = module.client.get(url_path("slb"))["slb"]
    virtual_servers = slb["virtual-server-list"]
    service_groups = slb["service-group-list"]
    zz = yaml.dump(slb)
    return {"result": zz}


#     valid = True
# 
#     if state == 'present':
#         valid, validation_errors = validate(module.params)
#         map(run_errors.append, validation_errors)
#     
#     if not valid:
#         result["messages"] = "Validation failure"
#         err_msg = "\n".join(run_errors)
#         module.fail_json(msg=err_msg, **result)
# 
#     module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
#     existing_config = exists(module)
# 
#     if state == 'present':
#         result = present(module, result, existing_config)
#         module.client.session.close()
#     elif state == 'absent':
#         result = absent(module, result)
#         module.client.session.close()
#     return result
# 
def main():
    module = AnsibleModule(argument_spec=get_argspec())
    result = run_command(module)
    module.exit_json(**result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()
