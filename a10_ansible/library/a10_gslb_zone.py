#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_gslb_zone
description:
    - None
short_description: Configures A10 gslb.zone
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
    name:
        description:
        - "None"
        required: True
    dns_ns_record_list:
        description:
        - "Field dns_ns_record_list"
        required: False
        suboptions:
            sampling_enable:
                description:
                - "Field sampling_enable"
            ns_name:
                description:
                - "None"
            uuid:
                description:
                - "None"
            ttl:
                description:
                - "None"
    dns_mx_record_list:
        description:
        - "Field dns_mx_record_list"
        required: False
        suboptions:
            priority:
                description:
                - "None"
            sampling_enable:
                description:
                - "Field sampling_enable"
            uuid:
                description:
                - "None"
            mx_name:
                description:
                - "None"
            ttl:
                description:
                - "None"
    user_tag:
        description:
        - "None"
        required: False
    sampling_enable:
        description:
        - "Field sampling_enable"
        required: False
        suboptions:
            counters1:
                description:
                - "None"
    disable:
        description:
        - "None"
        required: False
    template:
        description:
        - "Field template"
        required: False
        suboptions:
            dnssec:
                description:
                - "None"
    ttl:
        description:
        - "None"
        required: False
    policy:
        description:
        - "None"
        required: False
    use_server_ttl:
        description:
        - "None"
        required: False
    dns_soa_record:
        description:
        - "Field dns_soa_record"
        required: False
        suboptions:
            retry:
                description:
                - "None"
            soa_name:
                description:
                - "None"
            ex_retry:
                description:
                - "None"
            ex_soa_ttl:
                description:
                - "None"
            ex_serial:
                description:
                - "None"
            refresh:
                description:
                - "None"
            ex_mail:
                description:
                - "None"
            expire:
                description:
                - "None"
            ex_expire:
                description:
                - "None"
            external:
                description:
                - "None"
            mail:
                description:
                - "None"
            serial:
                description:
                - "None"
            ex_refresh:
                description:
                - "None"
            soa_ttl:
                description:
                - "None"
    service_list:
        description:
        - "Field service_list"
        required: False
        suboptions:
            dns_a_record:
                description:
                - "Field dns_a_record"
            forward_type:
                description:
                - "None"
            uuid:
                description:
                - "None"
            health_check_port:
                description:
                - "Field health_check_port"
            dns_txt_record_list:
                description:
                - "Field dns_txt_record_list"
            service_port:
                description:
                - "None"
            dns_mx_record_list:
                description:
                - "Field dns_mx_record_list"
            dns_record_list:
                description:
                - "Field dns_record_list"
            user_tag:
                description:
                - "None"
            dns_ns_record_list:
                description:
                - "Field dns_ns_record_list"
            health_check_gateway:
                description:
                - "None"
            sampling_enable:
                description:
                - "Field sampling_enable"
            disable:
                description:
                - "None"
            dns_srv_record_list:
                description:
                - "Field dns_srv_record_list"
            service_name:
                description:
                - "None"
            policy:
                description:
                - "None"
            dns_ptr_record_list:
                description:
                - "Field dns_ptr_record_list"
            dns_cname_record_list:
                description:
                - "Field dns_cname_record_list"
            action:
                description:
                - "None"
            geo_location_list:
                description:
                - "Field geo_location_list"
            dns_naptr_record_list:
                description:
                - "Field dns_naptr_record_list"
    uuid:
        description:
        - "None"
        required: False


"""

EXAMPLES = """
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

# Hacky way of having access to object properties for evaluation
AVAILABLE_PROPERTIES = ["disable","dns_mx_record_list","dns_ns_record_list","dns_soa_record","name","policy","sampling_enable","service_list","template","ttl","use_server_ttl","user_tag","uuid",]

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
        name=dict(type='str',required=True,),
        dns_ns_record_list=dict(type='list',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),ns_name=dict(type='str',required=True,),uuid=dict(type='str',),ttl=dict(type='int',)),
        dns_mx_record_list=dict(type='list',priority=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),uuid=dict(type='str',),mx_name=dict(type='str',required=True,),ttl=dict(type='int',)),
        user_tag=dict(type='str',),
        sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','received-query','sent-response','proxy-mode-response','cache-mode-response','server-mode-response','sticky-mode-response','backup-mode-response'])),
        disable=dict(type='bool',),
        template=dict(type='dict',dnssec=dict(type='str',)),
        ttl=dict(type='int',),
        policy=dict(type='str',),
        use_server_ttl=dict(type='bool',),
        dns_soa_record=dict(type='dict',retry=dict(type='int',),soa_name=dict(type='str',),ex_retry=dict(type='int',),ex_soa_ttl=dict(type='int',),ex_serial=dict(type='int',),refresh=dict(type='int',),ex_mail=dict(type='str',),expire=dict(type='int',),ex_expire=dict(type='int',),external=dict(type='str',),mail=dict(type='str',),serial=dict(type='int',),ex_refresh=dict(type='int',),soa_ttl=dict(type='int',)),
        service_list=dict(type='list',dns_a_record=dict(type='dict',dns_a_record_ipv6_list=dict(type='list',as_replace=dict(type='bool',),dns_a_record_ipv6=dict(type='str',required=True,),as_backup=dict(type='bool',),weight=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),disable=dict(type='bool',),static=dict(type='bool',),ttl=dict(type='int',),no_resp=dict(type='bool',),admin_ip=dict(type='int',),uuid=dict(type='str',)),dns_a_record_ipv4_list=dict(type='list',as_replace=dict(type='bool',),dns_a_record_ip=dict(type='str',required=True,),as_backup=dict(type='bool',),weight=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),disable=dict(type='bool',),static=dict(type='bool',),ttl=dict(type='int',),no_resp=dict(type='bool',),admin_ip=dict(type='int',),uuid=dict(type='str',)),dns_a_record_srv_list=dict(type='list',as_backup=dict(type='bool',),as_replace=dict(type='bool',),uuid=dict(type='str',),weight=dict(type='int',),svrname=dict(type='str',required=True,),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),disable=dict(type='bool',),static=dict(type='bool',),ttl=dict(type='int',),admin_ip=dict(type='int',),no_resp=dict(type='bool',))),forward_type=dict(type='str',choices=['both','query','response']),uuid=dict(type='str',),health_check_port=dict(type='list',health_check_port=dict(type='int',)),dns_txt_record_list=dict(type='list',record_name=dict(type='str',required=True,),ttl=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),uuid=dict(type='str',),txt_data=dict(type='str',)),service_port=dict(type='int',required=True,),dns_mx_record_list=dict(type='list',priority=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),uuid=dict(type='str',),mx_name=dict(type='str',required=True,),ttl=dict(type='int',)),dns_record_list=dict(type='list',ntype=dict(type='int',required=True,),data=dict(type='str',),uuid=dict(type='str',)),user_tag=dict(type='str',),dns_ns_record_list=dict(type='list',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),ns_name=dict(type='str',required=True,),uuid=dict(type='str',),ttl=dict(type='int',)),health_check_gateway=dict(type='str',choices=['enable','disable']),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','received-query','sent-response','proxy-mode-response','cache-mode-response','server-mode-response','sticky-mode-response','backup-mode-response'])),disable=dict(type='bool',),dns_srv_record_list=dict(type='list',srv_name=dict(type='str',required=True,),uuid=dict(type='str',),weight=dict(type='int',),priority=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),ttl=dict(type='int',),port=dict(type='int',required=True,)),service_name=dict(type='str',required=True,),policy=dict(type='str',),dns_ptr_record_list=dict(type='list',ptr_name=dict(type='str',required=True,),ttl=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','hits'])),uuid=dict(type='str',)),dns_cname_record_list=dict(type='list',alias_name=dict(type='str',required=True,),uuid=dict(type='str',),as_backup=dict(type='bool',),weight=dict(type='int',),sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','cname-hits'])),admin_preference=dict(type='int',)),action=dict(type='str',choices=['drop','forward','ignore','reject']),geo_location_list=dict(type='list',action_type=dict(type='str',choices=['allow','drop','forward','ignore','reject']),uuid=dict(type='str',),user_tag=dict(type='str',),alias=dict(type='list',alias=dict(type='str',)),geo_name=dict(type='str',required=True,),policy=dict(type='str',),forward_type=dict(type='str',choices=['both','query','response']),action=dict(type='bool',)),dns_naptr_record_list=dict(type='list',sampling_enable=dict(type='list',counters1=dict(type='str',choices=['all','naptr-hits'])),naptr_target=dict(type='str',required=True,),service_proto=dict(type='str',required=True,),flag=dict(type='str',required=True,),preference=dict(type='int',),ttl=dict(type='int',),regexp=dict(type='bool',),order=dict(type='int',),uuid=dict(type='str',))),
        uuid=dict(type='str',)
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/gslb/zone/{name}"
    f_dict = {}
    f_dict["name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/gslb/zone/{name}"
    f_dict = {}
    f_dict["name"] = module.params["name"]

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
    payload = build_json("zone", module)
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
    payload = build_json("zone", module)
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