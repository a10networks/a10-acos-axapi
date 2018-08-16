#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_visibility
description:
    - None
short_description: Configures A10 visibility
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
    flow_collector:
        description:
        - "Field flow_collector"
        required: False
        suboptions:
            netflow:
                description:
                - "Field netflow"
            sflow:
                description:
                - "Field sflow"
    anomaly_detection:
        description:
        - "Field anomaly_detection"
        required: False
        suboptions:
            restart_learning_on_anomaly:
                description:
                - "None"
            sensitivity:
                description:
                - "None"
            uuid:
                description:
                - "None"
    uuid:
        description:
        - "None"
        required: False
    reporting:
        description:
        - "Field reporting"
        required: False
        suboptions:
            reporting_db:
                description:
                - "Field reporting_db"
            sampling_enable:
                description:
                - "Field sampling_enable"
            session_logging:
                description:
                - "None"
            uuid:
                description:
                - "None"
            template:
                description:
                - "Field template"
    initial_learning_interval:
        description:
        - "None"
        required: False
    monitored_entity:
        description:
        - "Field monitored_entity"
        required: False
        suboptions:
            uuid:
                description:
                - "None"
            detail:
                description:
                - "Field detail"
    granularity:
        description:
        - "None"
        required: False
    monitor:
        description:
        - "Field monitor"
        required: False
        suboptions:
            primary_monitor:
                description:
                - "None"
            nflow_collector_port:
                description:
                - "None"
            nflow_collector_tmpl_active_timeout:
                description:
                - "None"
            uuid:
                description:
                - "None"
            class_list:
                description:
                - "None"
            notification:
                description:
                - "None"
            index_sessions:
                description:
                - "None"
            traffic_key:
                description:
                - "None"
            secondary_monitor:
                description:
                - "None"
            index_sessions_type:
                description:
                - "None"


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["anomaly_detection","flow_collector","granularity","initial_learning_interval","monitor","monitored_entity","reporting","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent"])
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        flow_collector=dict(type='dict',netflow=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','v5-pkts-received','v9-pkts-received','v10-pkts-received','v5-pkts-received-bad-length','v9-pkts-received-bad-length','v10-pkts-received-bad-length','v9-templates-created','v9-templates-deleted','v10-templates-created','v10-templates-deleted','template-drop-exceeded','template-drop-out-of-memory','xflow-pkts-dropped'])),uuid=dict(type='str',),template=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','templates-added-to-delq','templates-removed-from-delq'])),uuid=dict(type='str',),detail=dict(type='dict',uuid=dict(type='str',)))),sflow=dict(type='dict',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','pkts-received','ctr-samples-received','pkts-received-bad-length'])),uuid=dict(type='str',))),
        anomaly_detection=dict(type='dict',restart_learning_on_anomaly=dict(type='bool',),sensitivity=dict(type='str',choices=['high','low']),uuid=dict(type='str',)),
        uuid=dict(type='str',),
        reporting=dict(type='dict',reporting_db=dict(type='dict',elastic_search=dict(type='dict',host_ipv6_address=dict(type='str',),use_mgmt_port=dict(type='bool',),local_host=dict(type='bool',),host_name=dict(type='str',),host_ipv4_address=dict(type='str',),http_port=dict(type='int',),http_protocol=dict(type='str',choices=['http','https']),uuid=dict(type='str',))),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','log-transmit-failure','buffer-alloc-failure'])),session_logging=dict(type='str',choices=['enable','disable']),uuid=dict(type='str',),template=dict(type='dict',notification_list=dict(type='list',protocol=dict(type='str',choices=['http','https']),name=dict(type='str',required=True,),use_mgmt_port=dict(type='bool',),user_tag=dict(type='str',),relative_uri=dict(type='str',),authentication=dict(type='dict',uuid=dict(type='str',),encrypted=dict(type='str',),relative_logoff_uri=dict(type='str',),auth_password_string=dict(type='str',),auth_password=dict(type='bool',),relative_login_uri=dict(type='str',),auth_username=dict(type='str',)),host_name=dict(type='str',),ipv6_address=dict(type='str',),action=dict(type='str',choices=['enable','disable']),ipv4_address=dict(type='str',),port=dict(type='int',),uuid=dict(type='str',)))),
        initial_learning_interval=dict(type='int',),
        monitored_entity=dict(type='dict',uuid=dict(type='str',),detail=dict(type='dict',uuid=dict(type='str',))),
        granularity=dict(type='int',),
        monitor=dict(type='dict',primary_monitor=dict(type='str',choices=['traffic','xflow']),nflow_collector_port=dict(type='int',),nflow_collector_tmpl_active_timeout=dict(type='int',),uuid=dict(type='str',),class_list=dict(type='str',),notification=dict(type='str',),index_sessions=dict(type='bool',),traffic_key=dict(type='str',choices=['dest','service','source-nat-ip']),secondary_monitor=dict(type='str',choices=['source','dest','service']),index_sessions_type=dict(type='str',choices=['per-cpu']))
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/visibility"
    f_dict = {}

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/visibility"
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
    payload = build_json("visibility", module)
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
    payload = build_json("visibility", module)
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