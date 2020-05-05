#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")


DOCUMENTATION = r'''
module: a10_rule_set_tag
description:
    - Application Tag statistics in Rule Set
short_description: Configures A10 rule.set.tag
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
    rule_set_name:
        description:
        - Key to identify parent object
    stats:
        description:
        - "Field stats"
        required: False
        suboptions:
            categorystat54:
                description:
                - "counter app category stat 54"
            categorystat84:
                description:
                - "counter app category stat 84"
            categorystat85:
                description:
                - "counter app category stat 85"
            categorystat26:
                description:
                - "counter app category stat 26"
            categorystat27:
                description:
                - "counter app category stat 27"
            categorystat24:
                description:
                - "counter app category stat 24"
            categorystat25:
                description:
                - "counter app category stat 25"
            categorystat22:
                description:
                - "counter app category stat 22"
            categorystat23:
                description:
                - "counter app category stat 23"
            categorystat20:
                description:
                - "counter app category stat 20"
            categorystat21:
                description:
                - "counter app category stat 21"
            categorystat28:
                description:
                - "counter app category stat 28"
            categorystat29:
                description:
                - "counter app category stat 29"
            categorystat7:
                description:
                - "counter app category stat 7"
            categorystat168:
                description:
                - "counter app category stat 168"
            categorystat169:
                description:
                - "counter app category stat 169"
            categorystat6:
                description:
                - "counter app category stat 6"
            categorystat162:
                description:
                - "counter app category stat 162"
            categorystat163:
                description:
                - "counter app category stat 163"
            categorystat160:
                description:
                - "counter app category stat 160"
            categorystat161:
                description:
                - "counter app category stat 161"
            categorystat166:
                description:
                - "counter app category stat 166"
            categorystat167:
                description:
                - "counter app category stat 167"
            categorystat164:
                description:
                - "counter app category stat 164"
            categorystat165:
                description:
                - "counter app category stat 165"
            categorystat4:
                description:
                - "counter app category stat 4"
            categorystat210:
                description:
                - "counter app category stat 210"
            categorystat3:
                description:
                - "counter app category stat 3"
            categorystat109:
                description:
                - "counter app category stat 109"
            categorystat1:
                description:
                - "counter app category stat 1"
            categorystat35:
                description:
                - "counter app category stat 35"
            categorystat34:
                description:
                - "counter app category stat 34"
            categorystat37:
                description:
                - "counter app category stat 37"
            categorystat36:
                description:
                - "counter app category stat 36"
            categorystat31:
                description:
                - "counter app category stat 31"
            categorystat30:
                description:
                - "counter app category stat 30"
            categorystat33:
                description:
                - "counter app category stat 33"
            categorystat32:
                description:
                - "counter app category stat 32"
            categorystat39:
                description:
                - "counter app category stat 39"
            categorystat38:
                description:
                - "counter app category stat 38"
            categorystat197:
                description:
                - "counter app category stat 197"
            categorystat196:
                description:
                - "counter app category stat 196"
            categorystat195:
                description:
                - "counter app category stat 195"
            categorystat194:
                description:
                - "counter app category stat 194"
            categorystat193:
                description:
                - "counter app category stat 193"
            categorystat192:
                description:
                - "counter app category stat 192"
            categorystat191:
                description:
                - "counter app category stat 191"
            categorystat190:
                description:
                - "counter app category stat 190"
            categorystat100:
                description:
                - "counter app category stat 100"
            categorystat199:
                description:
                - "counter app category stat 199"
            categorystat198:
                description:
                - "counter app category stat 198"
            categorystat207:
                description:
                - "counter app category stat 207"
            categorystat206:
                description:
                - "counter app category stat 206"
            categorystat205:
                description:
                - "counter app category stat 205"
            categorystat204:
                description:
                - "counter app category stat 204"
            categorystat203:
                description:
                - "counter app category stat 203"
            categorystat9:
                description:
                - "counter app category stat 9"
            categorystat119:
                description:
                - "counter app category stat 119"
            categorystat118:
                description:
                - "counter app category stat 118"
            categorystat117:
                description:
                - "counter app category stat 117"
            categorystat116:
                description:
                - "counter app category stat 116"
            categorystat115:
                description:
                - "counter app category stat 115"
            categorystat114:
                description:
                - "counter app category stat 114"
            categorystat113:
                description:
                - "counter app category stat 113"
            categorystat112:
                description:
                - "counter app category stat 112"
            categorystat111:
                description:
                - "counter app category stat 111"
            categorystat110:
                description:
                - "counter app category stat 110"
            categorystat52:
                description:
                - "counter app category stat 52"
            categorystat202:
                description:
                - "counter app category stat 202"
            categorystat184:
                description:
                - "counter app category stat 184"
            categorystat88:
                description:
                - "counter app category stat 88"
            categorystat89:
                description:
                - "counter app category stat 89"
            categorystat186:
                description:
                - "counter app category stat 186"
            categorystat187:
                description:
                - "counter app category stat 187"
            categorystat180:
                description:
                - "counter app category stat 180"
            categorystat181:
                description:
                - "counter app category stat 181"
            categorystat182:
                description:
                - "counter app category stat 182"
            categorystat183:
                description:
                - "counter app category stat 183"
            categorystat80:
                description:
                - "counter app category stat 80"
            categorystat81:
                description:
                - "counter app category stat 81"
            categorystat82:
                description:
                - "counter app category stat 82"
            categorystat83:
                description:
                - "counter app category stat 83"
            categorystat188:
                description:
                - "counter app category stat 188"
            categorystat189:
                description:
                - "counter app category stat 189"
            categorystat86:
                description:
                - "counter app category stat 86"
            categorystat87:
                description:
                - "counter app category stat 87"
            categorystat214:
                description:
                - "counter app category stat 214"
            categorystat215:
                description:
                - "counter app category stat 215"
            categorystat216:
                description:
                - "counter app category stat 216"
            categorystat217:
                description:
                - "counter app category stat 217"
            categorystat108:
                description:
                - "counter app category stat 108"
            categorystat211:
                description:
                - "counter app category stat 211"
            categorystat212:
                description:
                - "counter app category stat 212"
            categorystat213:
                description:
                - "counter app category stat 213"
            categorystat104:
                description:
                - "counter app category stat 104"
            categorystat105:
                description:
                - "counter app category stat 105"
            categorystat106:
                description:
                - "counter app category stat 106"
            categorystat107:
                description:
                - "counter app category stat 107"
            categorystat218:
                description:
                - "counter app category stat 218"
            categorystat219:
                description:
                - "counter app category stat 219"
            categorystat102:
                description:
                - "counter app category stat 102"
            categorystat103:
                description:
                - "counter app category stat 103"
            categorystat201:
                description:
                - "counter app category stat 201"
            categorystat19:
                description:
                - "counter app category stat 19"
            categorystat18:
                description:
                - "counter app category stat 18"
            categorystat17:
                description:
                - "counter app category stat 17"
            categorystat16:
                description:
                - "counter app category stat 16"
            categorystat15:
                description:
                - "counter app category stat 15"
            categorystat14:
                description:
                - "counter app category stat 14"
            categorystat13:
                description:
                - "counter app category stat 13"
            categorystat12:
                description:
                - "counter app category stat 12"
            categorystat11:
                description:
                - "counter app category stat 11"
            categorystat10:
                description:
                - "counter app category stat 10"
            categorystat97:
                description:
                - "counter app category stat 97"
            categorystat96:
                description:
                - "counter app category stat 96"
            categorystat95:
                description:
                - "counter app category stat 95"
            categorystat94:
                description:
                - "counter app category stat 94"
            categorystat93:
                description:
                - "counter app category stat 93"
            categorystat92:
                description:
                - "counter app category stat 92"
            categorystat91:
                description:
                - "counter app category stat 91"
            categorystat90:
                description:
                - "counter app category stat 90"
            categorystat8:
                description:
                - "counter app category stat 8"
            categorystat99:
                description:
                - "counter app category stat 99"
            categorystat98:
                description:
                - "counter app category stat 98"
            categorystat139:
                description:
                - "counter app category stat 139"
            categorystat138:
                description:
                - "counter app category stat 138"
            categorystat223:
                description:
                - "counter app category stat 223"
            categorystat222:
                description:
                - "counter app category stat 222"
            categorystat225:
                description:
                - "counter app category stat 225"
            categorystat209:
                description:
                - "counter app category stat 209"
            categorystat227:
                description:
                - "counter app category stat 227"
            categorystat226:
                description:
                - "counter app category stat 226"
            categorystat131:
                description:
                - "counter app category stat 131"
            categorystat228:
                description:
                - "counter app category stat 228"
            categorystat133:
                description:
                - "counter app category stat 133"
            categorystat208:
                description:
                - "counter app category stat 208"
            categorystat135:
                description:
                - "counter app category stat 135"
            categorystat134:
                description:
                - "counter app category stat 134"
            categorystat137:
                description:
                - "counter app category stat 137"
            categorystat136:
                description:
                - "counter app category stat 136"
            categorystat68:
                description:
                - "counter app category stat 68"
            categorystat69:
                description:
                - "counter app category stat 69"
            categorystat62:
                description:
                - "counter app category stat 62"
            categorystat63:
                description:
                - "counter app category stat 63"
            categorystat60:
                description:
                - "counter app category stat 60"
            categorystat61:
                description:
                - "counter app category stat 61"
            categorystat66:
                description:
                - "counter app category stat 66"
            categorystat67:
                description:
                - "counter app category stat 67"
            categorystat64:
                description:
                - "counter app category stat 64"
            categorystat65:
                description:
                - "counter app category stat 65"
            categorystat238:
                description:
                - "counter app category stat 238"
            categorystat239:
                description:
                - "counter app category stat 239"
            categorystat236:
                description:
                - "counter app category stat 236"
            categorystat237:
                description:
                - "counter app category stat 237"
            categorystat234:
                description:
                - "counter app category stat 234"
            categorystat200:
                description:
                - "counter app category stat 200"
            categorystat232:
                description:
                - "counter app category stat 232"
            categorystat233:
                description:
                - "counter app category stat 233"
            categorystat230:
                description:
                - "counter app category stat 230"
            categorystat231:
                description:
                - "counter app category stat 231"
            categorystat126:
                description:
                - "counter app category stat 126"
            categorystat127:
                description:
                - "counter app category stat 127"
            categorystat124:
                description:
                - "counter app category stat 124"
            categorystat125:
                description:
                - "counter app category stat 125"
            categorystat122:
                description:
                - "counter app category stat 122"
            categorystat123:
                description:
                - "counter app category stat 123"
            categorystat120:
                description:
                - "counter app category stat 120"
            categorystat121:
                description:
                - "counter app category stat 121"
            categorystat128:
                description:
                - "counter app category stat 128"
            categorystat129:
                description:
                - "counter app category stat 129"
            categorystat79:
                description:
                - "counter app category stat 79"
            categorystat78:
                description:
                - "counter app category stat 78"
            categorystat71:
                description:
                - "counter app category stat 71"
            categorystat70:
                description:
                - "counter app category stat 70"
            categorystat73:
                description:
                - "counter app category stat 73"
            categorystat72:
                description:
                - "counter app category stat 72"
            categorystat75:
                description:
                - "counter app category stat 75"
            categorystat74:
                description:
                - "counter app category stat 74"
            categorystat77:
                description:
                - "counter app category stat 77"
            categorystat76:
                description:
                - "counter app category stat 76"
            categorystat249:
                description:
                - "counter app category stat 249"
            categorystat248:
                description:
                - "counter app category stat 248"
            categorystat5:
                description:
                - "counter app category stat 5"
            categorystat243:
                description:
                - "counter app category stat 243"
            categorystat242:
                description:
                - "counter app category stat 242"
            categorystat241:
                description:
                - "counter app category stat 241"
            categorystat240:
                description:
                - "counter app category stat 240"
            categorystat247:
                description:
                - "counter app category stat 247"
            categorystat246:
                description:
                - "counter app category stat 246"
            categorystat245:
                description:
                - "counter app category stat 245"
            categorystat244:
                description:
                - "counter app category stat 244"
            categorystat153:
                description:
                - "counter app category stat 153"
            categorystat152:
                description:
                - "counter app category stat 152"
            categorystat151:
                description:
                - "counter app category stat 151"
            categorystat150:
                description:
                - "counter app category stat 150"
            categorystat157:
                description:
                - "counter app category stat 157"
            categorystat156:
                description:
                - "counter app category stat 156"
            categorystat155:
                description:
                - "counter app category stat 155"
            categorystat154:
                description:
                - "counter app category stat 154"
            categorystat235:
                description:
                - "counter app category stat 235"
            categorystat159:
                description:
                - "counter app category stat 159"
            categorystat158:
                description:
                - "counter app category stat 158"
            categorystat44:
                description:
                - "counter app category stat 44"
            categorystat45:
                description:
                - "counter app category stat 45"
            categorystat46:
                description:
                - "counter app category stat 46"
            categorystat47:
                description:
                - "counter app category stat 47"
            categorystat40:
                description:
                - "counter app category stat 40"
            categorystat41:
                description:
                - "counter app category stat 41"
            categorystat42:
                description:
                - "counter app category stat 42"
            categorystat43:
                description:
                - "counter app category stat 43"
            categorystat48:
                description:
                - "counter app category stat 48"
            categorystat49:
                description:
                - "counter app category stat 49"
            categorystat221:
                description:
                - "counter app category stat 221"
            categorystat220:
                description:
                - "counter app category stat 220"
            categorystat250:
                description:
                - "counter app category stat 250"
            categorystat251:
                description:
                - "counter app category stat 251"
            categorystat252:
                description:
                - "counter app category stat 252"
            categorystat253:
                description:
                - "counter app category stat 253"
            categorystat254:
                description:
                - "counter app category stat 254"
            categorystat255:
                description:
                - "counter app category stat 255"
            categorystat256:
                description:
                - "counter app category stat 255"
            categorystat140:
                description:
                - "counter app category stat 140"
            categorystat141:
                description:
                - "counter app category stat 141"
            categorystat142:
                description:
                - "counter app category stat 142"
            categorystat143:
                description:
                - "counter app category stat 143"
            categorystat144:
                description:
                - "counter app category stat 144"
            categorystat145:
                description:
                - "counter app category stat 145"
            categorystat146:
                description:
                - "counter app category stat 146"
            categorystat147:
                description:
                - "counter app category stat 147"
            categorystat148:
                description:
                - "counter app category stat 148"
            categorystat149:
                description:
                - "counter app category stat 149"
            categorystat224:
                description:
                - "counter app category stat 224"
            categorystat53:
                description:
                - "counter app category stat 53"
            categorystat2:
                description:
                - "counter app category stat 2"
            categorystat51:
                description:
                - "counter app category stat 51"
            categorystat50:
                description:
                - "counter app category stat 50"
            categorystat57:
                description:
                - "counter app category stat 57"
            categorystat56:
                description:
                - "counter app category stat 56"
            categorystat55:
                description:
                - "counter app category stat 55"
            categorystat185:
                description:
                - "counter app category stat 185"
            categorystat59:
                description:
                - "counter app category stat 59"
            categorystat58:
                description:
                - "counter app category stat 58"
            categorystat229:
                description:
                - "counter app category stat 229"
            categorystat130:
                description:
                - "counter app category stat 130"
            categorystat101:
                description:
                - "counter app category stat 101"
            categorystat132:
                description:
                - "counter app category stat 132"
            categorystat179:
                description:
                - "counter app category stat 179"
            categorystat178:
                description:
                - "counter app category stat 178"
            categorystat175:
                description:
                - "counter app category stat 175"
            categorystat174:
                description:
                - "counter app category stat 174"
            categorystat177:
                description:
                - "counter app category stat 177"
            categorystat176:
                description:
                - "counter app category stat 176"
            categorystat171:
                description:
                - "counter app category stat 171"
            categorystat170:
                description:
                - "counter app category stat 170"
            categorystat173:
                description:
                - "counter app category stat 173"
            categorystat172:
                description:
                - "counter app category stat 172"
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
AVAILABLE_PROPERTIES = ["stats","uuid",]

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
        a10_partition=dict(type='dict', name=dict(type='str',), shared=dict(type='str',), required=False, ),
        a10_device_context_id=dict(type='int', choices=[1, 2, 3, 4, 5, 6, 7, 8], required=False, ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )

def get_argspec():
    rv = get_default_argspec()
    rv.update(dict(
        stats=dict(type='dict', categorystat54=dict(type='str', ), categorystat84=dict(type='str', ), categorystat85=dict(type='str', ), categorystat26=dict(type='str', ), categorystat27=dict(type='str', ), categorystat24=dict(type='str', ), categorystat25=dict(type='str', ), categorystat22=dict(type='str', ), categorystat23=dict(type='str', ), categorystat20=dict(type='str', ), categorystat21=dict(type='str', ), categorystat28=dict(type='str', ), categorystat29=dict(type='str', ), categorystat7=dict(type='str', ), categorystat168=dict(type='str', ), categorystat169=dict(type='str', ), categorystat6=dict(type='str', ), categorystat162=dict(type='str', ), categorystat163=dict(type='str', ), categorystat160=dict(type='str', ), categorystat161=dict(type='str', ), categorystat166=dict(type='str', ), categorystat167=dict(type='str', ), categorystat164=dict(type='str', ), categorystat165=dict(type='str', ), categorystat4=dict(type='str', ), categorystat210=dict(type='str', ), categorystat3=dict(type='str', ), categorystat109=dict(type='str', ), categorystat1=dict(type='str', ), categorystat35=dict(type='str', ), categorystat34=dict(type='str', ), categorystat37=dict(type='str', ), categorystat36=dict(type='str', ), categorystat31=dict(type='str', ), categorystat30=dict(type='str', ), categorystat33=dict(type='str', ), categorystat32=dict(type='str', ), categorystat39=dict(type='str', ), categorystat38=dict(type='str', ), categorystat197=dict(type='str', ), categorystat196=dict(type='str', ), categorystat195=dict(type='str', ), categorystat194=dict(type='str', ), categorystat193=dict(type='str', ), categorystat192=dict(type='str', ), categorystat191=dict(type='str', ), categorystat190=dict(type='str', ), categorystat100=dict(type='str', ), categorystat199=dict(type='str', ), categorystat198=dict(type='str', ), categorystat207=dict(type='str', ), categorystat206=dict(type='str', ), categorystat205=dict(type='str', ), categorystat204=dict(type='str', ), categorystat203=dict(type='str', ), categorystat9=dict(type='str', ), categorystat119=dict(type='str', ), categorystat118=dict(type='str', ), categorystat117=dict(type='str', ), categorystat116=dict(type='str', ), categorystat115=dict(type='str', ), categorystat114=dict(type='str', ), categorystat113=dict(type='str', ), categorystat112=dict(type='str', ), categorystat111=dict(type='str', ), categorystat110=dict(type='str', ), categorystat52=dict(type='str', ), categorystat202=dict(type='str', ), categorystat184=dict(type='str', ), categorystat88=dict(type='str', ), categorystat89=dict(type='str', ), categorystat186=dict(type='str', ), categorystat187=dict(type='str', ), categorystat180=dict(type='str', ), categorystat181=dict(type='str', ), categorystat182=dict(type='str', ), categorystat183=dict(type='str', ), categorystat80=dict(type='str', ), categorystat81=dict(type='str', ), categorystat82=dict(type='str', ), categorystat83=dict(type='str', ), categorystat188=dict(type='str', ), categorystat189=dict(type='str', ), categorystat86=dict(type='str', ), categorystat87=dict(type='str', ), categorystat214=dict(type='str', ), categorystat215=dict(type='str', ), categorystat216=dict(type='str', ), categorystat217=dict(type='str', ), categorystat108=dict(type='str', ), categorystat211=dict(type='str', ), categorystat212=dict(type='str', ), categorystat213=dict(type='str', ), categorystat104=dict(type='str', ), categorystat105=dict(type='str', ), categorystat106=dict(type='str', ), categorystat107=dict(type='str', ), categorystat218=dict(type='str', ), categorystat219=dict(type='str', ), categorystat102=dict(type='str', ), categorystat103=dict(type='str', ), categorystat201=dict(type='str', ), categorystat19=dict(type='str', ), categorystat18=dict(type='str', ), categorystat17=dict(type='str', ), categorystat16=dict(type='str', ), categorystat15=dict(type='str', ), categorystat14=dict(type='str', ), categorystat13=dict(type='str', ), categorystat12=dict(type='str', ), categorystat11=dict(type='str', ), categorystat10=dict(type='str', ), categorystat97=dict(type='str', ), categorystat96=dict(type='str', ), categorystat95=dict(type='str', ), categorystat94=dict(type='str', ), categorystat93=dict(type='str', ), categorystat92=dict(type='str', ), categorystat91=dict(type='str', ), categorystat90=dict(type='str', ), categorystat8=dict(type='str', ), categorystat99=dict(type='str', ), categorystat98=dict(type='str', ), categorystat139=dict(type='str', ), categorystat138=dict(type='str', ), categorystat223=dict(type='str', ), categorystat222=dict(type='str', ), categorystat225=dict(type='str', ), categorystat209=dict(type='str', ), categorystat227=dict(type='str', ), categorystat226=dict(type='str', ), categorystat131=dict(type='str', ), categorystat228=dict(type='str', ), categorystat133=dict(type='str', ), categorystat208=dict(type='str', ), categorystat135=dict(type='str', ), categorystat134=dict(type='str', ), categorystat137=dict(type='str', ), categorystat136=dict(type='str', ), categorystat68=dict(type='str', ), categorystat69=dict(type='str', ), categorystat62=dict(type='str', ), categorystat63=dict(type='str', ), categorystat60=dict(type='str', ), categorystat61=dict(type='str', ), categorystat66=dict(type='str', ), categorystat67=dict(type='str', ), categorystat64=dict(type='str', ), categorystat65=dict(type='str', ), categorystat238=dict(type='str', ), categorystat239=dict(type='str', ), categorystat236=dict(type='str', ), categorystat237=dict(type='str', ), categorystat234=dict(type='str', ), categorystat200=dict(type='str', ), categorystat232=dict(type='str', ), categorystat233=dict(type='str', ), categorystat230=dict(type='str', ), categorystat231=dict(type='str', ), categorystat126=dict(type='str', ), categorystat127=dict(type='str', ), categorystat124=dict(type='str', ), categorystat125=dict(type='str', ), categorystat122=dict(type='str', ), categorystat123=dict(type='str', ), categorystat120=dict(type='str', ), categorystat121=dict(type='str', ), categorystat128=dict(type='str', ), categorystat129=dict(type='str', ), categorystat79=dict(type='str', ), categorystat78=dict(type='str', ), categorystat71=dict(type='str', ), categorystat70=dict(type='str', ), categorystat73=dict(type='str', ), categorystat72=dict(type='str', ), categorystat75=dict(type='str', ), categorystat74=dict(type='str', ), categorystat77=dict(type='str', ), categorystat76=dict(type='str', ), categorystat249=dict(type='str', ), categorystat248=dict(type='str', ), categorystat5=dict(type='str', ), categorystat243=dict(type='str', ), categorystat242=dict(type='str', ), categorystat241=dict(type='str', ), categorystat240=dict(type='str', ), categorystat247=dict(type='str', ), categorystat246=dict(type='str', ), categorystat245=dict(type='str', ), categorystat244=dict(type='str', ), categorystat153=dict(type='str', ), categorystat152=dict(type='str', ), categorystat151=dict(type='str', ), categorystat150=dict(type='str', ), categorystat157=dict(type='str', ), categorystat156=dict(type='str', ), categorystat155=dict(type='str', ), categorystat154=dict(type='str', ), categorystat235=dict(type='str', ), categorystat159=dict(type='str', ), categorystat158=dict(type='str', ), categorystat44=dict(type='str', ), categorystat45=dict(type='str', ), categorystat46=dict(type='str', ), categorystat47=dict(type='str', ), categorystat40=dict(type='str', ), categorystat41=dict(type='str', ), categorystat42=dict(type='str', ), categorystat43=dict(type='str', ), categorystat48=dict(type='str', ), categorystat49=dict(type='str', ), categorystat221=dict(type='str', ), categorystat220=dict(type='str', ), categorystat250=dict(type='str', ), categorystat251=dict(type='str', ), categorystat252=dict(type='str', ), categorystat253=dict(type='str', ), categorystat254=dict(type='str', ), categorystat255=dict(type='str', ), categorystat256=dict(type='str', ), categorystat140=dict(type='str', ), categorystat141=dict(type='str', ), categorystat142=dict(type='str', ), categorystat143=dict(type='str', ), categorystat144=dict(type='str', ), categorystat145=dict(type='str', ), categorystat146=dict(type='str', ), categorystat147=dict(type='str', ), categorystat148=dict(type='str', ), categorystat149=dict(type='str', ), categorystat224=dict(type='str', ), categorystat53=dict(type='str', ), categorystat2=dict(type='str', ), categorystat51=dict(type='str', ), categorystat50=dict(type='str', ), categorystat57=dict(type='str', ), categorystat56=dict(type='str', ), categorystat55=dict(type='str', ), categorystat185=dict(type='str', ), categorystat59=dict(type='str', ), categorystat58=dict(type='str', ), categorystat229=dict(type='str', ), categorystat130=dict(type='str', ), categorystat101=dict(type='str', ), categorystat132=dict(type='str', ), categorystat179=dict(type='str', ), categorystat178=dict(type='str', ), categorystat175=dict(type='str', ), categorystat174=dict(type='str', ), categorystat177=dict(type='str', ), categorystat176=dict(type='str', ), categorystat171=dict(type='str', ), categorystat170=dict(type='str', ), categorystat173=dict(type='str', ), categorystat172=dict(type='str', )),
        uuid=dict(type='str', )
    ))
   
    # Parent keys
    rv.update(dict(
        rule_set_name=dict(type='str', required=True),
    ))

    return rv

def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/rule-set/{rule_set_name}/tag"

    f_dict = {}
    f_dict["rule_set_name"] = module.params["rule_set_name"]

    return url_base.format(**f_dict)

def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/rule-set/{rule_set_name}/tag"

    f_dict = {}
    f_dict["rule_set_name"] = module.params["rule_set_name"]

    return url_base.format(**f_dict)

def stats_url(module):
    """Return the URL for statistical data of and existing resource"""
    partial_url = existing_url(module)
    return partial_url + "/stats"

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
        if v is not None:
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

def report_changes(module, result, existing_config):
    if existing_config:
        result["changed"] = True
    return result
def create(module, result):
    try:
        post_result = module.client.post(new_url(module))
        if post_result:
            result.update(**post_result)
        result["changed"] = True
    except a10_ex.ACOSException as ex:
        module.fail_json(msg=ex.msg, **result)
    except Exception as gex:
        raise gex
    return result

def update(module, result, existing_config):
    try:
        post_result = module.client.post(existing_url(module))
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
    if module.check_mode:
        return report_changes(module, result, existing_config)
    if not existing_config:
        return create(module, result)
    else:
        return update(module, result, existing_config)

def absent(module, result, existing_config):
    if module.check_mode:
        if existing_config:
            result["changed"] = True
            return result
        else:
            result["changed"] = False
            return result
    else:
        return delete(module, result)

def replace(module, result, existing_config):
    try:
        post_result = module.client.put(existing_url(module))
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
    
    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)
    elif state == 'absent':
        result = absent(module, result, existing_config)
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