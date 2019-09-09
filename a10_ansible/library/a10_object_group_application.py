#!/usr/bin/python

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = """
module: a10_object_group_application
description:
    - Configure Application Object Group
short_description: Configures A10 object-group.application
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
    partition:
        description:
        - Destination/target partition for object/command
    app_list:
        description:
        - "Field app_list"
        required: False
        suboptions:
            protocol:
                description:
                - "Specify application"
            protocol_tag:
                description:
                - "'aaa'= Protocol/application used for AAA (Authentification, Authorization and Accounting) purposes.; 'adult-content'= Adult content.; 'advertising'= Advertising networks and applications.; 'analytics-and-statistics'= user-analytics and statistics.; 'anonymizers-and-proxies'= Traffic-anonymization protocol/application.; 'audio-chat'= Protocol/application used for Audio Chat.; 'basic'= Protocols required for basic classification, e.g., ARP, HTTP; 'blog'= Blogging platform.; 'cdn'= Protocol/application used for Content-Delivery Networks.; 'chat'= Protocol/application used for Text Chat.; 'classified-ads'= Protocol/application used for Classified ads.; 'cloud-based-services'= SaaS and/or PaaS cloud based services.; 'cryptocurrency'= Cryptocurrency.; 'database'= Database-specific protocols.; 'disposable-email'= Disposable email accounts.; 'email'= Native email protocol.; 'enterprise'= Protocol/application used in an enterprise network.; 'file-management'= Protocol/application designed specifically for file management and exchange, e.g., Dropbox, SMB; 'file-transfer'= Protocol that offers file transferring as a functionality as a secondary feature. e.g., Skype, Whatsapp; 'forum'= Online forum.; 'gaming'= Protocol/application used by games.; 'instant-messaging-and-multimedia-conferencing'= Protocol/application used for Instant messaging or multiconferencing.; 'internet-of-things'= Internet Of Things protocol/application.; 'mobile'= Mobile-specific protocol/application.; 'multimedia-streaming'= Protocol/application used for multimedia streaming.; 'networking'= Protocol used for (inter) networking purpose.; 'news-portal'= Protocol/application used for News Portals.; 'peer-to-peer'= Protocol/application used for Peer-to-peer purposes.; 'remote-access'= Protocol/application used for remote access.; 'scada'= SCADA (Supervisory control and data acquisition) protocols, all generations.; 'social-networks'= Social networking application.; 'software-update'= Auto-update protocol.; 'standards-based'= Protocol issued from standardized bodies such as IETF, ITU, IEEE, ETSI, OIF.; 'transportation'= Transportation.; 'video-chat'= Protocol/application used for Video Chat.; 'voip'= Application used for Voice over IP.; 'vpn-tunnels'= Protocol/application used for VPN or tunneling purposes.; 'web'= Application based on HTTP/HTTPS.; 'web-e-commerce'= Protocol/application used for E-commerce websites.; 'web-search-engines'= Protocol/application used for Web search portals.; 'web-websites'= Protocol/application used for Company Websites.; 'webmails'= Web email application.; 'web-ext-adult'= Web Extension Adult; 'web-ext-auctions'= Web Extension Auctions; 'web-ext-blogs'= Web Extension Blogs; 'web-ext-business-and-economy'= Web Extension Business and Economy; 'web-ext-cdns'= Web Extension CDNs; 'web-ext-collaboration'= Web Extension Collaboration; 'web-ext-computer-and-internet-info'= Web Extension Computer and Internet Info; 'web-ext-computer-and-internet-security'= Web Extension Computer and Internet Security; 'web-ext-dating'= Web Extension Dating; 'web-ext-educational-institutions'= Web Extension Educational Institutions; 'web-ext-entertainment-and-arts'= Web Extension Entertainment and Arts; 'web-ext-fashion-and-beauty'= Web Extension Fashion and Beauty; 'web-ext-file-share'= Web Extension File Share; 'web-ext-financial-services'= Web Extension Financial Services; 'web-ext-gambling'= Web Extension Gambling; 'web-ext-games'= Web Extension Games; 'web-ext-government'= Web Extension Government; 'web-ext-health-and-medicine'= Web Extension Health and Medicine; 'web-ext-individual-stock-advice-and-tools'= Web Extension Individual Stock Advice and Tools; 'web-ext-internet-portals'= Web Extension Internet Portals; 'web-ext-job-search'= Web Extension Job Search; 'web-ext-local-information'= Web Extension Local Information; 'web-ext-malware'= Web Extension Malware; 'web-ext-motor-vehicles'= Web Extension Motor Vehicles; 'web-ext-music'= Web Extension Music; 'web-ext-news'= Web Extension News; 'web-ext-p2p'= Web Extension P2P; 'web-ext-parked-sites'= Web Extension Parked Sites; 'web-ext-proxy-avoid-and-anonymizers'= Web Extension Proxy Avoid and Anonymizers; 'web-ext-real-estate'= Web Extension Real Estate; 'web-ext-reference-and-research'= Web Extension Reference and Research; 'web-ext-search-engines'= Web Extension Search Engines; 'web-ext-shopping'= Web Extension Shopping; 'web-ext-social-network'= Web Extension Social Network; 'web-ext-society'= Web Extension Society; 'web-ext-software'= Web Extension Software; 'web-ext-sports'= Web Extension Sports; 'web-ext-streaming-media'= Web Extension Streaming Media; 'web-ext-training-and-tools'= Web Extension Training and Tools; 'web-ext-translation'= Web Extension Translation; 'web-ext-travel'= Web Extension Travel; 'web-ext-web-advertisements'= Web Extension Web Advertisements; 'web-ext-web-based-email'= Web Extension Web based Email; 'web-ext-web-hosting'= Web Extension Web Hosting; 'web-ext-web-service'= Web Extension Web Service; "
    app_name:
        description:
        - "Application Object Group Name"
        required: True
    uuid:
        description:
        - "uuid of the object"
        required: False
    user_tag:
        description:
        - "Customized tag"
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
AVAILABLE_PROPERTIES = ["app_list","app_name","user_tag","uuid",]

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
        state=dict(type='str', default="present", choices=["present", "absent", "noop"]),
        a10_port=dict(type='int', required=True),
        a10_protocol=dict(type='str', choices=["http", "https"]),
        partition=dict(type='str', required=False),
        get_type=dict(type='str', choices=["single", "list"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        app_list=dict(type='list',protocol=dict(type='str',),protocol_tag=dict(type='str',choices=['aaa','adult-content','advertising','analytics-and-statistics','anonymizers-and-proxies','audio-chat','basic','blog','cdn','chat','classified-ads','cloud-based-services','cryptocurrency','database','disposable-email','email','enterprise','file-management','file-transfer','forum','gaming','instant-messaging-and-multimedia-conferencing','internet-of-things','mobile','multimedia-streaming','networking','news-portal','peer-to-peer','remote-access','scada','social-networks','software-update','standards-based','transportation','video-chat','voip','vpn-tunnels','web','web-e-commerce','web-search-engines','web-websites','webmails','web-ext-adult','web-ext-auctions','web-ext-blogs','web-ext-business-and-economy','web-ext-cdns','web-ext-collaboration','web-ext-computer-and-internet-info','web-ext-computer-and-internet-security','web-ext-dating','web-ext-educational-institutions','web-ext-entertainment-and-arts','web-ext-fashion-and-beauty','web-ext-file-share','web-ext-financial-services','web-ext-gambling','web-ext-games','web-ext-government','web-ext-health-and-medicine','web-ext-individual-stock-advice-and-tools','web-ext-internet-portals','web-ext-job-search','web-ext-local-information','web-ext-malware','web-ext-motor-vehicles','web-ext-music','web-ext-news','web-ext-p2p','web-ext-parked-sites','web-ext-proxy-avoid-and-anonymizers','web-ext-real-estate','web-ext-reference-and-research','web-ext-search-engines','web-ext-shopping','web-ext-social-network','web-ext-society','web-ext-software','web-ext-sports','web-ext-streaming-media','web-ext-training-and-tools','web-ext-translation','web-ext-travel','web-ext-web-advertisements','web-ext-web-based-email','web-ext-web-hosting','web-ext-web-service'])),
        app_name=dict(type='str',required=True,),
        uuid=dict(type='str',),
        user_tag=dict(type='str',)
    ))
   

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/object-group/application/{app-name}"

    f_dict = {}
    f_dict["app-name"] = ""

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/object-group/application/{app-name}"

    f_dict = {}
    f_dict["app-name"] = module.params["app_name"]

    return url_base.format(**f_dict)

def list_url(module):
    """Return the URL for a list of resources"""
    ret = existing_url(module)
    return ret[0:ret.rfind('/')]

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
        elif isinstance(v, list):
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
            elif isinstance(v, list):
                nv = [_build_dict_from_param(x) for x in v]
                rv[rx] = nv
            else:
                rv[rx] = module.params[x]

    return build_envelope(title, rv)

def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([x for x in requires_one_of if x in params and params.get(x) is not None])
    
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

def get_list(module):
    return module.client.get(list_url(module))

def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None

def report_changes(module, result, existing_config, payload):
    if existing_config:
        for k, v in payload["application"].items():
            if v.lower() == "true":
                v = 1
            elif v.lower() == "false":
                v = 0
            if existing_config["application"][k] != v:
                if result["changed"] != True:
                    result["changed"] = True
                existing_config["application"][k] = v
        result.update(**existing_config)
    else:
        result.update(**payload)
    return result

def create(module, result, payload):
    try:
        post_result = module.client.post(new_url(module), payload)
        if post_result:
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

def update(module, result, existing_config, payload):
    try:
        post_result = module.client.post(existing_url(module), payload)
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

def present(module, result, existing_config):
    payload = build_json("application", module)
    if module.check_mode:
        return report_changes(module, result, existing_config, payload)
    elif not existing_config:
        return create(module, result, payload)
    else:
        return update(module, result, existing_config, payload)

def absent(module, result):
    return delete(module, result)

def replace(module, result, existing_config):
    payload = build_json("application", module)
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
    partition = module.params["partition"]

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)
    
    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(a10_host, a10_port, a10_protocol, a10_username, a10_password)
    if partition and not module.check_mode:
        module.client.activate_partition(partition)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
        module.client.session.close()
    elif state == 'absent':
        result = absent(module, result)
        module.client.session.close()
    elif state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
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