#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Copyright 2018 A10 Networks
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

REQUIRED_NOT_SET = (False, "One of ({}) must be set.")
REQUIRED_MUTEX = (False, "Only one of ({}) can be set.")
REQUIRED_VALID = (True, "")

DOCUMENTATION = r'''
module: a10_rule_set_app
description:
    - Application statistics in Rule Set
short_description: Configures A10 rule.set.app
author: A10 Networks 2018
version_added: 2.4
options:
    state:
        description:
        - State of the object to be created.
        choices:
          - noop
          - present
        required: True
    ansible_host:
        description:
        - Host for AXAPI authentication
        required: True
    ansible_username:
        description:
        - Username for AXAPI authentication
        required: True
    ansible_password:
        description:
        - Password for AXAPI authentication
        required: True
    ansible_port:
        description:
        - Port for AXAPI authentication
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
            appstat249:
                description:
                - "counter app stat 249"
            appstat248:
                description:
                - "counter app stat 248"
            appstat245:
                description:
                - "counter app stat 245"
            appstat244:
                description:
                - "counter app stat 244"
            appstat247:
                description:
                - "counter app stat 247"
            appstat246:
                description:
                - "counter app stat 246"
            appstat241:
                description:
                - "counter app stat 241"
            appstat240:
                description:
                - "counter app stat 240"
            appstat243:
                description:
                - "counter app stat 243"
            appstat242:
                description:
                - "counter app stat 242"
            appstat489:
                description:
                - "counter app stat 489"
            appstat488:
                description:
                - "counter app stat 488"
            appstat487:
                description:
                - "counter app stat 487"
            appstat486:
                description:
                - "counter app stat 486"
            appstat485:
                description:
                - "counter app stat 485"
            appstat484:
                description:
                - "counter app stat 484"
            appstat483:
                description:
                - "counter app stat 483"
            appstat482:
                description:
                - "counter app stat 482"
            appstat481:
                description:
                - "counter app stat 481"
            appstat480:
                description:
                - "counter app stat 480"
            appstat91:
                description:
                - "counter app stat 91"
            appstat90:
                description:
                - "counter app stat 90"
            appstat93:
                description:
                - "counter app stat 93"
            appstat92:
                description:
                - "counter app stat 92"
            appstat95:
                description:
                - "counter app stat 95"
            appstat94:
                description:
                - "counter app stat 94"
            appstat97:
                description:
                - "counter app stat 97"
            appstat96:
                description:
                - "counter app stat 96"
            appstat99:
                description:
                - "counter app stat 99"
            appstat98:
                description:
                - "counter app stat 98"
            appstat182:
                description:
                - "counter app stat 182"
            appstat183:
                description:
                - "counter app stat 183"
            appstat180:
                description:
                - "counter app stat 180"
            appstat181:
                description:
                - "counter app stat 181"
            appstat186:
                description:
                - "counter app stat 186"
            appstat187:
                description:
                - "counter app stat 187"
            appstat184:
                description:
                - "counter app stat 184"
            appstat185:
                description:
                - "counter app stat 185"
            appstat188:
                description:
                - "counter app stat 188"
            appstat189:
                description:
                - "counter app stat 189"
            appstat348:
                description:
                - "counter app stat 348"
            appstat349:
                description:
                - "counter app stat 349"
            appstat344:
                description:
                - "counter app stat 344"
            appstat345:
                description:
                - "counter app stat 345"
            appstat346:
                description:
                - "counter app stat 346"
            appstat347:
                description:
                - "counter app stat 347"
            appstat340:
                description:
                - "counter app stat 340"
            appstat341:
                description:
                - "counter app stat 341"
            appstat342:
                description:
                - "counter app stat 342"
            appstat343:
                description:
                - "counter app stat 343"
            appstat119:
                description:
                - "counter app stat 119"
            appstat118:
                description:
                - "counter app stat 118"
            appstat111:
                description:
                - "counter app stat 111"
            appstat110:
                description:
                - "counter app stat 110"
            appstat113:
                description:
                - "counter app stat 113"
            appstat112:
                description:
                - "counter app stat 112"
            appstat115:
                description:
                - "counter app stat 115"
            appstat114:
                description:
                - "counter app stat 114"
            appstat117:
                description:
                - "counter app stat 117"
            appstat116:
                description:
                - "counter app stat 116"
            appstat449:
                description:
                - "counter app stat 449"
            appstat448:
                description:
                - "counter app stat 448"
            appstat443:
                description:
                - "counter app stat 443"
            appstat442:
                description:
                - "counter app stat 442"
            appstat441:
                description:
                - "counter app stat 441"
            appstat440:
                description:
                - "counter app stat 440"
            appstat447:
                description:
                - "counter app stat 447"
            appstat446:
                description:
                - "counter app stat 446"
            appstat445:
                description:
                - "counter app stat 445"
            appstat444:
                description:
                - "counter app stat 444"
            appstat298:
                description:
                - "counter app stat 298"
            appstat234:
                description:
                - "counter app stat 234"
            appstat235:
                description:
                - "counter app stat 235"
            appstat236:
                description:
                - "counter app stat 236"
            appstat299:
                description:
                - "counter app stat 299"
            appstat230:
                description:
                - "counter app stat 230"
            appstat231:
                description:
                - "counter app stat 231"
            appstat232:
                description:
                - "counter app stat 232"
            appstat233:
                description:
                - "counter app stat 233"
            appstat238:
                description:
                - "counter app stat 238"
            appstat239:
                description:
                - "counter app stat 239"
            appstat46:
                description:
                - "counter app stat 46"
            appstat47:
                description:
                - "counter app stat 47"
            appstat44:
                description:
                - "counter app stat 44"
            appstat45:
                description:
                - "counter app stat 45"
            appstat42:
                description:
                - "counter app stat 42"
            appstat43:
                description:
                - "counter app stat 43"
            appstat40:
                description:
                - "counter app stat 40"
            appstat41:
                description:
                - "counter app stat 41"
            appstat290:
                description:
                - "counter app stat 290"
            appstat48:
                description:
                - "counter app stat 48"
            appstat49:
                description:
                - "counter app stat 49"
            appstat358:
                description:
                - "counter app stat 358"
            appstat308:
                description:
                - "counter app stat 308"
            appstat309:
                description:
                - "counter app stat 309"
            appstat300:
                description:
                - "counter app stat 300"
            appstat301:
                description:
                - "counter app stat 301"
            appstat302:
                description:
                - "counter app stat 302"
            appstat303:
                description:
                - "counter app stat 303"
            appstat304:
                description:
                - "counter app stat 304"
            appstat305:
                description:
                - "counter app stat 305"
            appstat306:
                description:
                - "counter app stat 306"
            appstat307:
                description:
                - "counter app stat 307"
            appstat155:
                description:
                - "counter app stat 155"
            appstat154:
                description:
                - "counter app stat 154"
            appstat157:
                description:
                - "counter app stat 157"
            appstat156:
                description:
                - "counter app stat 156"
            appstat151:
                description:
                - "counter app stat 151"
            appstat150:
                description:
                - "counter app stat 150"
            appstat153:
                description:
                - "counter app stat 153"
            appstat152:
                description:
                - "counter app stat 152"
            appstat159:
                description:
                - "counter app stat 159"
            appstat158:
                description:
                - "counter app stat 158"
            appstat9:
                description:
                - "counter app stat 9"
            appstat8:
                description:
                - "counter app stat 8"
            appstat405:
                description:
                - "counter app stat 405"
            appstat404:
                description:
                - "counter app stat 404"
            appstat403:
                description:
                - "counter app stat 403"
            appstat402:
                description:
                - "counter app stat 402"
            appstat401:
                description:
                - "counter app stat 401"
            appstat400:
                description:
                - "counter app stat 400"
            appstat1:
                description:
                - "counter app stat 1"
            appstat3:
                description:
                - "counter app stat 3"
            appstat2:
                description:
                - "counter app stat 2"
            appstat5:
                description:
                - "counter app stat 5"
            appstat4:
                description:
                - "counter app stat 4"
            appstat7:
                description:
                - "counter app stat 7"
            appstat6:
                description:
                - "counter app stat 6"
            appstat270:
                description:
                - "counter app stat 270"
            appstat271:
                description:
                - "counter app stat 271"
            appstat272:
                description:
                - "counter app stat 272"
            appstat273:
                description:
                - "counter app stat 273"
            appstat274:
                description:
                - "counter app stat 274"
            appstat275:
                description:
                - "counter app stat 275"
            appstat276:
                description:
                - "counter app stat 276"
            appstat277:
                description:
                - "counter app stat 277"
            appstat278:
                description:
                - "counter app stat 278"
            appstat279:
                description:
                - "counter app stat 279"
            appstat472:
                description:
                - "counter app stat 472"
            appstat473:
                description:
                - "counter app stat 473"
            appstat470:
                description:
                - "counter app stat 470"
            appstat471:
                description:
                - "counter app stat 471"
            appstat476:
                description:
                - "counter app stat 476"
            appstat477:
                description:
                - "counter app stat 477"
            appstat474:
                description:
                - "counter app stat 474"
            appstat475:
                description:
                - "counter app stat 475"
            appstat478:
                description:
                - "counter app stat 478"
            appstat479:
                description:
                - "counter app stat 479"
            appstat82:
                description:
                - "counter app stat 82"
            appstat83:
                description:
                - "counter app stat 83"
            appstat80:
                description:
                - "counter app stat 80"
            appstat81:
                description:
                - "counter app stat 81"
            appstat86:
                description:
                - "counter app stat 86"
            appstat87:
                description:
                - "counter app stat 87"
            appstat84:
                description:
                - "counter app stat 84"
            appstat85:
                description:
                - "counter app stat 85"
            appstat88:
                description:
                - "counter app stat 88"
            appstat89:
                description:
                - "counter app stat 89"
            appstat204:
                description:
                - "counter app stat 204"
            appstat258:
                description:
                - "counter app stat 258"
            appstat259:
                description:
                - "counter app stat 259"
            appstat39:
                description:
                - "counter app stat 39"
            appstat38:
                description:
                - "counter app stat 38"
            appstat37:
                description:
                - "counter app stat 37"
            appstat36:
                description:
                - "counter app stat 36"
            appstat35:
                description:
                - "counter app stat 35"
            appstat34:
                description:
                - "counter app stat 34"
            appstat33:
                description:
                - "counter app stat 33"
            appstat32:
                description:
                - "counter app stat 32"
            appstat31:
                description:
                - "counter app stat 31"
            appstat30:
                description:
                - "counter app stat 30"
            appstat191:
                description:
                - "counter app stat 191"
            appstat190:
                description:
                - "counter app stat 190"
            appstat193:
                description:
                - "counter app stat 193"
            appstat192:
                description:
                - "counter app stat 192"
            appstat195:
                description:
                - "counter app stat 195"
            appstat194:
                description:
                - "counter app stat 194"
            appstat197:
                description:
                - "counter app stat 197"
            appstat196:
                description:
                - "counter app stat 196"
            appstat199:
                description:
                - "counter app stat 199"
            appstat198:
                description:
                - "counter app stat 198"
            appstat251:
                description:
                - "counter app stat 251"
            appstat353:
                description:
                - "counter app stat 353"
            appstat352:
                description:
                - "counter app stat 352"
            appstat351:
                description:
                - "counter app stat 351"
            appstat350:
                description:
                - "counter app stat 350"
            appstat357:
                description:
                - "counter app stat 357"
            appstat356:
                description:
                - "counter app stat 356"
            appstat355:
                description:
                - "counter app stat 355"
            appstat354:
                description:
                - "counter app stat 354"
            appstat292:
                description:
                - "counter app stat 292"
            appstat293:
                description:
                - "counter app stat 293"
            appstat359:
                description:
                - "counter app stat 359"
            appstat291:
                description:
                - "counter app stat 291"
            appstat296:
                description:
                - "counter app stat 296"
            appstat297:
                description:
                - "counter app stat 297"
            appstat294:
                description:
                - "counter app stat 294"
            appstat295:
                description:
                - "counter app stat 295"
            appstat128:
                description:
                - "counter app stat 128"
            appstat129:
                description:
                - "counter app stat 129"
            appstat124:
                description:
                - "counter app stat 124"
            appstat125:
                description:
                - "counter app stat 125"
            appstat126:
                description:
                - "counter app stat 126"
            appstat127:
                description:
                - "counter app stat 127"
            appstat120:
                description:
                - "counter app stat 120"
            appstat121:
                description:
                - "counter app stat 121"
            appstat122:
                description:
                - "counter app stat 122"
            appstat123:
                description:
                - "counter app stat 123"
            appstat438:
                description:
                - "counter app stat 438"
            appstat439:
                description:
                - "counter app stat 439"
            appstat436:
                description:
                - "counter app stat 436"
            appstat437:
                description:
                - "counter app stat 437"
            appstat434:
                description:
                - "counter app stat 434"
            appstat435:
                description:
                - "counter app stat 435"
            appstat432:
                description:
                - "counter app stat 432"
            appstat433:
                description:
                - "counter app stat 433"
            appstat430:
                description:
                - "counter app stat 430"
            appstat431:
                description:
                - "counter app stat 431"
            appstat500:
                description:
                - "counter app stat 500"
            appstat501:
                description:
                - "counter app stat 501"
            appstat380:
                description:
                - "counter app stat 380"
            appstat381:
                description:
                - "counter app stat 381"
            appstat382:
                description:
                - "counter app stat 382"
            appstat228:
                description:
                - "counter app stat 228"
            appstat384:
                description:
                - "counter app stat 384"
            appstat385:
                description:
                - "counter app stat 385"
            appstat386:
                description:
                - "counter app stat 386"
            appstat387:
                description:
                - "counter app stat 387"
            appstat223:
                description:
                - "counter app stat 223"
            appstat222:
                description:
                - "counter app stat 222"
            appstat221:
                description:
                - "counter app stat 221"
            appstat220:
                description:
                - "counter app stat 220"
            appstat227:
                description:
                - "counter app stat 227"
            appstat226:
                description:
                - "counter app stat 226"
            appstat225:
                description:
                - "counter app stat 225"
            appstat224:
                description:
                - "counter app stat 224"
            appstat79:
                description:
                - "counter app stat 79"
            appstat78:
                description:
                - "counter app stat 78"
            appstat73:
                description:
                - "counter app stat 73"
            appstat72:
                description:
                - "counter app stat 72"
            appstat71:
                description:
                - "counter app stat 71"
            appstat70:
                description:
                - "counter app stat 70"
            appstat77:
                description:
                - "counter app stat 77"
            appstat76:
                description:
                - "counter app stat 76"
            appstat75:
                description:
                - "counter app stat 75"
            appstat74:
                description:
                - "counter app stat 74"
            appstat319:
                description:
                - "counter app stat 319"
            appstat318:
                description:
                - "counter app stat 318"
            appstat317:
                description:
                - "counter app stat 317"
            appstat316:
                description:
                - "counter app stat 316"
            appstat315:
                description:
                - "counter app stat 315"
            appstat314:
                description:
                - "counter app stat 314"
            appstat313:
                description:
                - "counter app stat 313"
            appstat312:
                description:
                - "counter app stat 312"
            appstat311:
                description:
                - "counter app stat 311"
            appstat310:
                description:
                - "counter app stat 310"
            appstat407:
                description:
                - "counter app stat 407"
            appstat406:
                description:
                - "counter app stat 406"
            appstat168:
                description:
                - "counter app stat 168"
            appstat169:
                description:
                - "counter app stat 169"
            appstat160:
                description:
                - "counter app stat 160"
            appstat161:
                description:
                - "counter app stat 161"
            appstat162:
                description:
                - "counter app stat 162"
            appstat163:
                description:
                - "counter app stat 163"
            appstat164:
                description:
                - "counter app stat 164"
            appstat165:
                description:
                - "counter app stat 165"
            appstat166:
                description:
                - "counter app stat 166"
            appstat167:
                description:
                - "counter app stat 167"
            appstat368:
                description:
                - "counter app stat 368"
            appstat369:
                description:
                - "counter app stat 369"
            appstat362:
                description:
                - "counter app stat 362"
            appstat363:
                description:
                - "counter app stat 363"
            appstat360:
                description:
                - "counter app stat 360"
            appstat361:
                description:
                - "counter app stat 361"
            appstat366:
                description:
                - "counter app stat 366"
            appstat367:
                description:
                - "counter app stat 367"
            appstat364:
                description:
                - "counter app stat 364"
            appstat365:
                description:
                - "counter app stat 365"
            appstat409:
                description:
                - "counter app stat 409"
            appstat408:
                description:
                - "counter app stat 408"
            appstat267:
                description:
                - "counter app stat 267"
            appstat266:
                description:
                - "counter app stat 266"
            appstat265:
                description:
                - "counter app stat 265"
            appstat264:
                description:
                - "counter app stat 264"
            appstat263:
                description:
                - "counter app stat 263"
            appstat262:
                description:
                - "counter app stat 262"
            appstat261:
                description:
                - "counter app stat 261"
            appstat260:
                description:
                - "counter app stat 260"
            appstat506:
                description:
                - "counter app stat 506"
            appstat507:
                description:
                - "counter app stat 507"
            appstat504:
                description:
                - "counter app stat 504"
            appstat505:
                description:
                - "counter app stat 505"
            appstat502:
                description:
                - "counter app stat 502"
            appstat503:
                description:
                - "counter app stat 503"
            appstat269:
                description:
                - "counter app stat 269"
            appstat268:
                description:
                - "counter app stat 268"
            appstat461:
                description:
                - "counter app stat 461"
            appstat460:
                description:
                - "counter app stat 460"
            appstat463:
                description:
                - "counter app stat 463"
            appstat462:
                description:
                - "counter app stat 462"
            appstat465:
                description:
                - "counter app stat 465"
            appstat464:
                description:
                - "counter app stat 464"
            appstat467:
                description:
                - "counter app stat 467"
            appstat466:
                description:
                - "counter app stat 466"
            appstat469:
                description:
                - "counter app stat 469"
            appstat468:
                description:
                - "counter app stat 468"
            appstat212:
                description:
                - "counter app stat 212"
            appstat213:
                description:
                - "counter app stat 213"
            appstat210:
                description:
                - "counter app stat 210"
            appstat211:
                description:
                - "counter app stat 211"
            appstat216:
                description:
                - "counter app stat 216"
            appstat217:
                description:
                - "counter app stat 217"
            appstat214:
                description:
                - "counter app stat 214"
            appstat215:
                description:
                - "counter app stat 215"
            appstat218:
                description:
                - "counter app stat 218"
            appstat219:
                description:
                - "counter app stat 219"
            appstat20:
                description:
                - "counter app stat 20"
            appstat21:
                description:
                - "counter app stat 21"
            appstat22:
                description:
                - "counter app stat 22"
            appstat23:
                description:
                - "counter app stat 23"
            appstat24:
                description:
                - "counter app stat 24"
            appstat25:
                description:
                - "counter app stat 25"
            appstat26:
                description:
                - "counter app stat 26"
            appstat27:
                description:
                - "counter app stat 27"
            appstat28:
                description:
                - "counter app stat 28"
            appstat29:
                description:
                - "counter app stat 29"
            appstat229:
                description:
                - "counter app stat 229"
            appstat383:
                description:
                - "counter app stat 383"
            appstat326:
                description:
                - "counter app stat 326"
            appstat327:
                description:
                - "counter app stat 327"
            appstat324:
                description:
                - "counter app stat 324"
            appstat325:
                description:
                - "counter app stat 325"
            appstat322:
                description:
                - "counter app stat 322"
            appstat323:
                description:
                - "counter app stat 323"
            appstat320:
                description:
                - "counter app stat 320"
            appstat321:
                description:
                - "counter app stat 321"
            appstat281:
                description:
                - "counter app stat 281"
            appstat280:
                description:
                - "counter app stat 280"
            appstat283:
                description:
                - "counter app stat 283"
            appstat282:
                description:
                - "counter app stat 282"
            appstat285:
                description:
                - "counter app stat 285"
            appstat284:
                description:
                - "counter app stat 284"
            appstat287:
                description:
                - "counter app stat 287"
            appstat329:
                description:
                - "counter app stat 329"
            appstat388:
                description:
                - "counter app stat 388"
            appstat389:
                description:
                - "counter app stat 389"
            appstat250:
                description:
                - "counter app stat 250"
            appstat133:
                description:
                - "counter app stat 133"
            appstat132:
                description:
                - "counter app stat 132"
            appstat131:
                description:
                - "counter app stat 131"
            appstat130:
                description:
                - "counter app stat 130"
            appstat137:
                description:
                - "counter app stat 137"
            appstat136:
                description:
                - "counter app stat 136"
            appstat135:
                description:
                - "counter app stat 135"
            appstat134:
                description:
                - "counter app stat 134"
            appstat139:
                description:
                - "counter app stat 139"
            appstat138:
                description:
                - "counter app stat 138"
            appstat429:
                description:
                - "counter app stat 429"
            appstat428:
                description:
                - "counter app stat 428"
            appstat425:
                description:
                - "counter app stat 425"
            appstat424:
                description:
                - "counter app stat 424"
            appstat427:
                description:
                - "counter app stat 427"
            appstat426:
                description:
                - "counter app stat 426"
            appstat421:
                description:
                - "counter app stat 421"
            appstat420:
                description:
                - "counter app stat 420"
            appstat423:
                description:
                - "counter app stat 423"
            appstat422:
                description:
                - "counter app stat 422"
            appstat508:
                description:
                - "counter app stat 508"
            appstat509:
                description:
                - "counter app stat 509"
            appstat397:
                description:
                - "counter app stat 397"
            appstat396:
                description:
                - "counter app stat 396"
            appstat395:
                description:
                - "counter app stat 395"
            appstat394:
                description:
                - "counter app stat 394"
            appstat393:
                description:
                - "counter app stat 393"
            appstat392:
                description:
                - "counter app stat 392"
            appstat391:
                description:
                - "counter app stat 391"
            appstat390:
                description:
                - "counter app stat 390"
            appstat256:
                description:
                - "counter app stat 256"
            appstat257:
                description:
                - "counter app stat 257"
            appstat254:
                description:
                - "counter app stat 254"
            appstat255:
                description:
                - "counter app stat 255"
            appstat252:
                description:
                - "counter app stat 252"
            appstat253:
                description:
                - "counter app stat 253"
            appstat399:
                description:
                - "counter app stat 399"
            appstat398:
                description:
                - "counter app stat 398"
            appstat498:
                description:
                - "counter app stat 498"
            appstat499:
                description:
                - "counter app stat 499"
            appstat490:
                description:
                - "counter app stat 490"
            appstat491:
                description:
                - "counter app stat 491"
            appstat492:
                description:
                - "counter app stat 492"
            appstat493:
                description:
                - "counter app stat 493"
            appstat494:
                description:
                - "counter app stat 494"
            appstat495:
                description:
                - "counter app stat 495"
            appstat496:
                description:
                - "counter app stat 496"
            appstat497:
                description:
                - "counter app stat 497"
            appstat68:
                description:
                - "counter app stat 68"
            appstat69:
                description:
                - "counter app stat 69"
            appstat64:
                description:
                - "counter app stat 64"
            appstat65:
                description:
                - "counter app stat 65"
            appstat66:
                description:
                - "counter app stat 66"
            appstat67:
                description:
                - "counter app stat 67"
            appstat60:
                description:
                - "counter app stat 60"
            appstat61:
                description:
                - "counter app stat 61"
            appstat62:
                description:
                - "counter app stat 62"
            appstat63:
                description:
                - "counter app stat 63"
            appstat19:
                description:
                - "counter app stat 19"
            appstat18:
                description:
                - "counter app stat 18"
            appstat11:
                description:
                - "counter app stat 11"
            appstat10:
                description:
                - "counter app stat 10"
            appstat13:
                description:
                - "counter app stat 13"
            appstat12:
                description:
                - "counter app stat 12"
            appstat15:
                description:
                - "counter app stat 15"
            appstat14:
                description:
                - "counter app stat 14"
            appstat17:
                description:
                - "counter app stat 17"
            appstat16:
                description:
                - "counter app stat 16"
            appstat179:
                description:
                - "counter app stat 179"
            appstat178:
                description:
                - "counter app stat 178"
            appstat177:
                description:
                - "counter app stat 177"
            appstat176:
                description:
                - "counter app stat 176"
            appstat175:
                description:
                - "counter app stat 175"
            appstat174:
                description:
                - "counter app stat 174"
            appstat173:
                description:
                - "counter app stat 173"
            appstat172:
                description:
                - "counter app stat 172"
            appstat171:
                description:
                - "counter app stat 171"
            appstat170:
                description:
                - "counter app stat 170"
            appstat379:
                description:
                - "counter app stat 379"
            appstat378:
                description:
                - "counter app stat 378"
            appstat371:
                description:
                - "counter app stat 371"
            appstat370:
                description:
                - "counter app stat 370"
            appstat373:
                description:
                - "counter app stat 373"
            appstat372:
                description:
                - "counter app stat 372"
            appstat375:
                description:
                - "counter app stat 375"
            appstat374:
                description:
                - "counter app stat 374"
            appstat377:
                description:
                - "counter app stat 377"
            appstat376:
                description:
                - "counter app stat 376"
            appstat108:
                description:
                - "counter app stat 108"
            appstat109:
                description:
                - "counter app stat 109"
            appstat102:
                description:
                - "counter app stat 102"
            appstat103:
                description:
                - "counter app stat 103"
            appstat100:
                description:
                - "counter app stat 100"
            appstat101:
                description:
                - "counter app stat 101"
            appstat106:
                description:
                - "counter app stat 106"
            appstat107:
                description:
                - "counter app stat 107"
            appstat104:
                description:
                - "counter app stat 104"
            appstat105:
                description:
                - "counter app stat 105"
            appstat289:
                description:
                - "counter app stat 289"
            appstat288:
                description:
                - "counter app stat 288"
            appstat511:
                description:
                - "counter app stat 511"
            appstat510:
                description:
                - "counter app stat 510"
            appstat454:
                description:
                - "counter app stat 454"
            appstat455:
                description:
                - "counter app stat 455"
            appstat456:
                description:
                - "counter app stat 456"
            appstat457:
                description:
                - "counter app stat 457"
            appstat450:
                description:
                - "counter app stat 450"
            appstat451:
                description:
                - "counter app stat 451"
            appstat452:
                description:
                - "counter app stat 452"
            appstat453:
                description:
                - "counter app stat 453"
            appstat458:
                description:
                - "counter app stat 458"
            appstat459:
                description:
                - "counter app stat 459"
            appstat201:
                description:
                - "counter app stat 201"
            appstat200:
                description:
                - "counter app stat 200"
            appstat203:
                description:
                - "counter app stat 203"
            appstat202:
                description:
                - "counter app stat 202"
            appstat205:
                description:
                - "counter app stat 205"
            appstat328:
                description:
                - "counter app stat 328"
            appstat207:
                description:
                - "counter app stat 207"
            appstat206:
                description:
                - "counter app stat 206"
            appstat209:
                description:
                - "counter app stat 209"
            appstat208:
                description:
                - "counter app stat 208"
            appstat286:
                description:
                - "counter app stat 286"
            appstat55:
                description:
                - "counter app stat 55"
            appstat54:
                description:
                - "counter app stat 54"
            appstat57:
                description:
                - "counter app stat 57"
            appstat56:
                description:
                - "counter app stat 56"
            appstat51:
                description:
                - "counter app stat 51"
            appstat50:
                description:
                - "counter app stat 50"
            appstat53:
                description:
                - "counter app stat 53"
            appstat52:
                description:
                - "counter app stat 52"
            appstat59:
                description:
                - "counter app stat 59"
            appstat58:
                description:
                - "counter app stat 58"
            appstat335:
                description:
                - "counter app stat 335"
            appstat334:
                description:
                - "counter app stat 334"
            appstat337:
                description:
                - "counter app stat 337"
            appstat336:
                description:
                - "counter app stat 336"
            appstat331:
                description:
                - "counter app stat 331"
            appstat330:
                description:
                - "counter app stat 330"
            appstat333:
                description:
                - "counter app stat 333"
            appstat332:
                description:
                - "counter app stat 332"
            appstat339:
                description:
                - "counter app stat 339"
            appstat338:
                description:
                - "counter app stat 338"
            appstat146:
                description:
                - "counter app stat 146"
            appstat147:
                description:
                - "counter app stat 147"
            appstat144:
                description:
                - "counter app stat 144"
            appstat145:
                description:
                - "counter app stat 145"
            appstat142:
                description:
                - "counter app stat 142"
            appstat143:
                description:
                - "counter app stat 143"
            appstat140:
                description:
                - "counter app stat 140"
            appstat141:
                description:
                - "counter app stat 141"
            appstat148:
                description:
                - "counter app stat 148"
            appstat149:
                description:
                - "counter app stat 149"
            appstat410:
                description:
                - "counter app stat 410"
            appstat411:
                description:
                - "counter app stat 411"
            appstat412:
                description:
                - "counter app stat 412"
            appstat413:
                description:
                - "counter app stat 413"
            appstat414:
                description:
                - "counter app stat 414"
            appstat415:
                description:
                - "counter app stat 415"
            appstat416:
                description:
                - "counter app stat 416"
            appstat417:
                description:
                - "counter app stat 417"
            appstat418:
                description:
                - "counter app stat 418"
            appstat419:
                description:
                - "counter app stat 419"
            appstat237:
                description:
                - "counter app stat 237"
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
AVAILABLE_PROPERTIES = [
    "stats",
    "uuid",
]

from ansible_collections.a10.acos_axapi.plugins.module_utils import \
    errors as a10_ex
from ansible_collections.a10.acos_axapi.plugins.module_utils.axapi_http import \
    client_factory
from ansible_collections.a10.acos_axapi.plugins.module_utils.kwbl import \
    KW_OUT, translate_blacklist as translateBlacklist


def get_default_argspec():
    return dict(
        ansible_host=dict(type='str', required=True),
        ansible_username=dict(type='str', required=True),
        ansible_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', default="present", choices=['noop', 'present']),
        ansible_port=dict(type='int', choices=[80, 443], required=True),
        a10_partition=dict(
            type='dict',
            name=dict(type='str', ),
            shared=dict(type='str', ),
            required=False,
        ),
        a10_device_context_id=dict(
            type='int',
            choices=[1, 2, 3, 4, 5, 6, 7, 8],
            required=False,
        ),
        get_type=dict(type='str', choices=["single", "list", "oper", "stats"]),
    )


def get_argspec():
    rv = get_default_argspec()
    rv.update({
        'stats': {
            'type': 'dict',
            'appstat249': {
                'type': 'str',
            },
            'appstat248': {
                'type': 'str',
            },
            'appstat245': {
                'type': 'str',
            },
            'appstat244': {
                'type': 'str',
            },
            'appstat247': {
                'type': 'str',
            },
            'appstat246': {
                'type': 'str',
            },
            'appstat241': {
                'type': 'str',
            },
            'appstat240': {
                'type': 'str',
            },
            'appstat243': {
                'type': 'str',
            },
            'appstat242': {
                'type': 'str',
            },
            'appstat489': {
                'type': 'str',
            },
            'appstat488': {
                'type': 'str',
            },
            'appstat487': {
                'type': 'str',
            },
            'appstat486': {
                'type': 'str',
            },
            'appstat485': {
                'type': 'str',
            },
            'appstat484': {
                'type': 'str',
            },
            'appstat483': {
                'type': 'str',
            },
            'appstat482': {
                'type': 'str',
            },
            'appstat481': {
                'type': 'str',
            },
            'appstat480': {
                'type': 'str',
            },
            'appstat91': {
                'type': 'str',
            },
            'appstat90': {
                'type': 'str',
            },
            'appstat93': {
                'type': 'str',
            },
            'appstat92': {
                'type': 'str',
            },
            'appstat95': {
                'type': 'str',
            },
            'appstat94': {
                'type': 'str',
            },
            'appstat97': {
                'type': 'str',
            },
            'appstat96': {
                'type': 'str',
            },
            'appstat99': {
                'type': 'str',
            },
            'appstat98': {
                'type': 'str',
            },
            'appstat182': {
                'type': 'str',
            },
            'appstat183': {
                'type': 'str',
            },
            'appstat180': {
                'type': 'str',
            },
            'appstat181': {
                'type': 'str',
            },
            'appstat186': {
                'type': 'str',
            },
            'appstat187': {
                'type': 'str',
            },
            'appstat184': {
                'type': 'str',
            },
            'appstat185': {
                'type': 'str',
            },
            'appstat188': {
                'type': 'str',
            },
            'appstat189': {
                'type': 'str',
            },
            'appstat348': {
                'type': 'str',
            },
            'appstat349': {
                'type': 'str',
            },
            'appstat344': {
                'type': 'str',
            },
            'appstat345': {
                'type': 'str',
            },
            'appstat346': {
                'type': 'str',
            },
            'appstat347': {
                'type': 'str',
            },
            'appstat340': {
                'type': 'str',
            },
            'appstat341': {
                'type': 'str',
            },
            'appstat342': {
                'type': 'str',
            },
            'appstat343': {
                'type': 'str',
            },
            'appstat119': {
                'type': 'str',
            },
            'appstat118': {
                'type': 'str',
            },
            'appstat111': {
                'type': 'str',
            },
            'appstat110': {
                'type': 'str',
            },
            'appstat113': {
                'type': 'str',
            },
            'appstat112': {
                'type': 'str',
            },
            'appstat115': {
                'type': 'str',
            },
            'appstat114': {
                'type': 'str',
            },
            'appstat117': {
                'type': 'str',
            },
            'appstat116': {
                'type': 'str',
            },
            'appstat449': {
                'type': 'str',
            },
            'appstat448': {
                'type': 'str',
            },
            'appstat443': {
                'type': 'str',
            },
            'appstat442': {
                'type': 'str',
            },
            'appstat441': {
                'type': 'str',
            },
            'appstat440': {
                'type': 'str',
            },
            'appstat447': {
                'type': 'str',
            },
            'appstat446': {
                'type': 'str',
            },
            'appstat445': {
                'type': 'str',
            },
            'appstat444': {
                'type': 'str',
            },
            'appstat298': {
                'type': 'str',
            },
            'appstat234': {
                'type': 'str',
            },
            'appstat235': {
                'type': 'str',
            },
            'appstat236': {
                'type': 'str',
            },
            'appstat299': {
                'type': 'str',
            },
            'appstat230': {
                'type': 'str',
            },
            'appstat231': {
                'type': 'str',
            },
            'appstat232': {
                'type': 'str',
            },
            'appstat233': {
                'type': 'str',
            },
            'appstat238': {
                'type': 'str',
            },
            'appstat239': {
                'type': 'str',
            },
            'appstat46': {
                'type': 'str',
            },
            'appstat47': {
                'type': 'str',
            },
            'appstat44': {
                'type': 'str',
            },
            'appstat45': {
                'type': 'str',
            },
            'appstat42': {
                'type': 'str',
            },
            'appstat43': {
                'type': 'str',
            },
            'appstat40': {
                'type': 'str',
            },
            'appstat41': {
                'type': 'str',
            },
            'appstat290': {
                'type': 'str',
            },
            'appstat48': {
                'type': 'str',
            },
            'appstat49': {
                'type': 'str',
            },
            'appstat358': {
                'type': 'str',
            },
            'appstat308': {
                'type': 'str',
            },
            'appstat309': {
                'type': 'str',
            },
            'appstat300': {
                'type': 'str',
            },
            'appstat301': {
                'type': 'str',
            },
            'appstat302': {
                'type': 'str',
            },
            'appstat303': {
                'type': 'str',
            },
            'appstat304': {
                'type': 'str',
            },
            'appstat305': {
                'type': 'str',
            },
            'appstat306': {
                'type': 'str',
            },
            'appstat307': {
                'type': 'str',
            },
            'appstat155': {
                'type': 'str',
            },
            'appstat154': {
                'type': 'str',
            },
            'appstat157': {
                'type': 'str',
            },
            'appstat156': {
                'type': 'str',
            },
            'appstat151': {
                'type': 'str',
            },
            'appstat150': {
                'type': 'str',
            },
            'appstat153': {
                'type': 'str',
            },
            'appstat152': {
                'type': 'str',
            },
            'appstat159': {
                'type': 'str',
            },
            'appstat158': {
                'type': 'str',
            },
            'appstat9': {
                'type': 'str',
            },
            'appstat8': {
                'type': 'str',
            },
            'appstat405': {
                'type': 'str',
            },
            'appstat404': {
                'type': 'str',
            },
            'appstat403': {
                'type': 'str',
            },
            'appstat402': {
                'type': 'str',
            },
            'appstat401': {
                'type': 'str',
            },
            'appstat400': {
                'type': 'str',
            },
            'appstat1': {
                'type': 'str',
            },
            'appstat3': {
                'type': 'str',
            },
            'appstat2': {
                'type': 'str',
            },
            'appstat5': {
                'type': 'str',
            },
            'appstat4': {
                'type': 'str',
            },
            'appstat7': {
                'type': 'str',
            },
            'appstat6': {
                'type': 'str',
            },
            'appstat270': {
                'type': 'str',
            },
            'appstat271': {
                'type': 'str',
            },
            'appstat272': {
                'type': 'str',
            },
            'appstat273': {
                'type': 'str',
            },
            'appstat274': {
                'type': 'str',
            },
            'appstat275': {
                'type': 'str',
            },
            'appstat276': {
                'type': 'str',
            },
            'appstat277': {
                'type': 'str',
            },
            'appstat278': {
                'type': 'str',
            },
            'appstat279': {
                'type': 'str',
            },
            'appstat472': {
                'type': 'str',
            },
            'appstat473': {
                'type': 'str',
            },
            'appstat470': {
                'type': 'str',
            },
            'appstat471': {
                'type': 'str',
            },
            'appstat476': {
                'type': 'str',
            },
            'appstat477': {
                'type': 'str',
            },
            'appstat474': {
                'type': 'str',
            },
            'appstat475': {
                'type': 'str',
            },
            'appstat478': {
                'type': 'str',
            },
            'appstat479': {
                'type': 'str',
            },
            'appstat82': {
                'type': 'str',
            },
            'appstat83': {
                'type': 'str',
            },
            'appstat80': {
                'type': 'str',
            },
            'appstat81': {
                'type': 'str',
            },
            'appstat86': {
                'type': 'str',
            },
            'appstat87': {
                'type': 'str',
            },
            'appstat84': {
                'type': 'str',
            },
            'appstat85': {
                'type': 'str',
            },
            'appstat88': {
                'type': 'str',
            },
            'appstat89': {
                'type': 'str',
            },
            'appstat204': {
                'type': 'str',
            },
            'appstat258': {
                'type': 'str',
            },
            'appstat259': {
                'type': 'str',
            },
            'appstat39': {
                'type': 'str',
            },
            'appstat38': {
                'type': 'str',
            },
            'appstat37': {
                'type': 'str',
            },
            'appstat36': {
                'type': 'str',
            },
            'appstat35': {
                'type': 'str',
            },
            'appstat34': {
                'type': 'str',
            },
            'appstat33': {
                'type': 'str',
            },
            'appstat32': {
                'type': 'str',
            },
            'appstat31': {
                'type': 'str',
            },
            'appstat30': {
                'type': 'str',
            },
            'appstat191': {
                'type': 'str',
            },
            'appstat190': {
                'type': 'str',
            },
            'appstat193': {
                'type': 'str',
            },
            'appstat192': {
                'type': 'str',
            },
            'appstat195': {
                'type': 'str',
            },
            'appstat194': {
                'type': 'str',
            },
            'appstat197': {
                'type': 'str',
            },
            'appstat196': {
                'type': 'str',
            },
            'appstat199': {
                'type': 'str',
            },
            'appstat198': {
                'type': 'str',
            },
            'appstat251': {
                'type': 'str',
            },
            'appstat353': {
                'type': 'str',
            },
            'appstat352': {
                'type': 'str',
            },
            'appstat351': {
                'type': 'str',
            },
            'appstat350': {
                'type': 'str',
            },
            'appstat357': {
                'type': 'str',
            },
            'appstat356': {
                'type': 'str',
            },
            'appstat355': {
                'type': 'str',
            },
            'appstat354': {
                'type': 'str',
            },
            'appstat292': {
                'type': 'str',
            },
            'appstat293': {
                'type': 'str',
            },
            'appstat359': {
                'type': 'str',
            },
            'appstat291': {
                'type': 'str',
            },
            'appstat296': {
                'type': 'str',
            },
            'appstat297': {
                'type': 'str',
            },
            'appstat294': {
                'type': 'str',
            },
            'appstat295': {
                'type': 'str',
            },
            'appstat128': {
                'type': 'str',
            },
            'appstat129': {
                'type': 'str',
            },
            'appstat124': {
                'type': 'str',
            },
            'appstat125': {
                'type': 'str',
            },
            'appstat126': {
                'type': 'str',
            },
            'appstat127': {
                'type': 'str',
            },
            'appstat120': {
                'type': 'str',
            },
            'appstat121': {
                'type': 'str',
            },
            'appstat122': {
                'type': 'str',
            },
            'appstat123': {
                'type': 'str',
            },
            'appstat438': {
                'type': 'str',
            },
            'appstat439': {
                'type': 'str',
            },
            'appstat436': {
                'type': 'str',
            },
            'appstat437': {
                'type': 'str',
            },
            'appstat434': {
                'type': 'str',
            },
            'appstat435': {
                'type': 'str',
            },
            'appstat432': {
                'type': 'str',
            },
            'appstat433': {
                'type': 'str',
            },
            'appstat430': {
                'type': 'str',
            },
            'appstat431': {
                'type': 'str',
            },
            'appstat500': {
                'type': 'str',
            },
            'appstat501': {
                'type': 'str',
            },
            'appstat380': {
                'type': 'str',
            },
            'appstat381': {
                'type': 'str',
            },
            'appstat382': {
                'type': 'str',
            },
            'appstat228': {
                'type': 'str',
            },
            'appstat384': {
                'type': 'str',
            },
            'appstat385': {
                'type': 'str',
            },
            'appstat386': {
                'type': 'str',
            },
            'appstat387': {
                'type': 'str',
            },
            'appstat223': {
                'type': 'str',
            },
            'appstat222': {
                'type': 'str',
            },
            'appstat221': {
                'type': 'str',
            },
            'appstat220': {
                'type': 'str',
            },
            'appstat227': {
                'type': 'str',
            },
            'appstat226': {
                'type': 'str',
            },
            'appstat225': {
                'type': 'str',
            },
            'appstat224': {
                'type': 'str',
            },
            'appstat79': {
                'type': 'str',
            },
            'appstat78': {
                'type': 'str',
            },
            'appstat73': {
                'type': 'str',
            },
            'appstat72': {
                'type': 'str',
            },
            'appstat71': {
                'type': 'str',
            },
            'appstat70': {
                'type': 'str',
            },
            'appstat77': {
                'type': 'str',
            },
            'appstat76': {
                'type': 'str',
            },
            'appstat75': {
                'type': 'str',
            },
            'appstat74': {
                'type': 'str',
            },
            'appstat319': {
                'type': 'str',
            },
            'appstat318': {
                'type': 'str',
            },
            'appstat317': {
                'type': 'str',
            },
            'appstat316': {
                'type': 'str',
            },
            'appstat315': {
                'type': 'str',
            },
            'appstat314': {
                'type': 'str',
            },
            'appstat313': {
                'type': 'str',
            },
            'appstat312': {
                'type': 'str',
            },
            'appstat311': {
                'type': 'str',
            },
            'appstat310': {
                'type': 'str',
            },
            'appstat407': {
                'type': 'str',
            },
            'appstat406': {
                'type': 'str',
            },
            'appstat168': {
                'type': 'str',
            },
            'appstat169': {
                'type': 'str',
            },
            'appstat160': {
                'type': 'str',
            },
            'appstat161': {
                'type': 'str',
            },
            'appstat162': {
                'type': 'str',
            },
            'appstat163': {
                'type': 'str',
            },
            'appstat164': {
                'type': 'str',
            },
            'appstat165': {
                'type': 'str',
            },
            'appstat166': {
                'type': 'str',
            },
            'appstat167': {
                'type': 'str',
            },
            'appstat368': {
                'type': 'str',
            },
            'appstat369': {
                'type': 'str',
            },
            'appstat362': {
                'type': 'str',
            },
            'appstat363': {
                'type': 'str',
            },
            'appstat360': {
                'type': 'str',
            },
            'appstat361': {
                'type': 'str',
            },
            'appstat366': {
                'type': 'str',
            },
            'appstat367': {
                'type': 'str',
            },
            'appstat364': {
                'type': 'str',
            },
            'appstat365': {
                'type': 'str',
            },
            'appstat409': {
                'type': 'str',
            },
            'appstat408': {
                'type': 'str',
            },
            'appstat267': {
                'type': 'str',
            },
            'appstat266': {
                'type': 'str',
            },
            'appstat265': {
                'type': 'str',
            },
            'appstat264': {
                'type': 'str',
            },
            'appstat263': {
                'type': 'str',
            },
            'appstat262': {
                'type': 'str',
            },
            'appstat261': {
                'type': 'str',
            },
            'appstat260': {
                'type': 'str',
            },
            'appstat506': {
                'type': 'str',
            },
            'appstat507': {
                'type': 'str',
            },
            'appstat504': {
                'type': 'str',
            },
            'appstat505': {
                'type': 'str',
            },
            'appstat502': {
                'type': 'str',
            },
            'appstat503': {
                'type': 'str',
            },
            'appstat269': {
                'type': 'str',
            },
            'appstat268': {
                'type': 'str',
            },
            'appstat461': {
                'type': 'str',
            },
            'appstat460': {
                'type': 'str',
            },
            'appstat463': {
                'type': 'str',
            },
            'appstat462': {
                'type': 'str',
            },
            'appstat465': {
                'type': 'str',
            },
            'appstat464': {
                'type': 'str',
            },
            'appstat467': {
                'type': 'str',
            },
            'appstat466': {
                'type': 'str',
            },
            'appstat469': {
                'type': 'str',
            },
            'appstat468': {
                'type': 'str',
            },
            'appstat212': {
                'type': 'str',
            },
            'appstat213': {
                'type': 'str',
            },
            'appstat210': {
                'type': 'str',
            },
            'appstat211': {
                'type': 'str',
            },
            'appstat216': {
                'type': 'str',
            },
            'appstat217': {
                'type': 'str',
            },
            'appstat214': {
                'type': 'str',
            },
            'appstat215': {
                'type': 'str',
            },
            'appstat218': {
                'type': 'str',
            },
            'appstat219': {
                'type': 'str',
            },
            'appstat20': {
                'type': 'str',
            },
            'appstat21': {
                'type': 'str',
            },
            'appstat22': {
                'type': 'str',
            },
            'appstat23': {
                'type': 'str',
            },
            'appstat24': {
                'type': 'str',
            },
            'appstat25': {
                'type': 'str',
            },
            'appstat26': {
                'type': 'str',
            },
            'appstat27': {
                'type': 'str',
            },
            'appstat28': {
                'type': 'str',
            },
            'appstat29': {
                'type': 'str',
            },
            'appstat229': {
                'type': 'str',
            },
            'appstat383': {
                'type': 'str',
            },
            'appstat326': {
                'type': 'str',
            },
            'appstat327': {
                'type': 'str',
            },
            'appstat324': {
                'type': 'str',
            },
            'appstat325': {
                'type': 'str',
            },
            'appstat322': {
                'type': 'str',
            },
            'appstat323': {
                'type': 'str',
            },
            'appstat320': {
                'type': 'str',
            },
            'appstat321': {
                'type': 'str',
            },
            'appstat281': {
                'type': 'str',
            },
            'appstat280': {
                'type': 'str',
            },
            'appstat283': {
                'type': 'str',
            },
            'appstat282': {
                'type': 'str',
            },
            'appstat285': {
                'type': 'str',
            },
            'appstat284': {
                'type': 'str',
            },
            'appstat287': {
                'type': 'str',
            },
            'appstat329': {
                'type': 'str',
            },
            'appstat388': {
                'type': 'str',
            },
            'appstat389': {
                'type': 'str',
            },
            'appstat250': {
                'type': 'str',
            },
            'appstat133': {
                'type': 'str',
            },
            'appstat132': {
                'type': 'str',
            },
            'appstat131': {
                'type': 'str',
            },
            'appstat130': {
                'type': 'str',
            },
            'appstat137': {
                'type': 'str',
            },
            'appstat136': {
                'type': 'str',
            },
            'appstat135': {
                'type': 'str',
            },
            'appstat134': {
                'type': 'str',
            },
            'appstat139': {
                'type': 'str',
            },
            'appstat138': {
                'type': 'str',
            },
            'appstat429': {
                'type': 'str',
            },
            'appstat428': {
                'type': 'str',
            },
            'appstat425': {
                'type': 'str',
            },
            'appstat424': {
                'type': 'str',
            },
            'appstat427': {
                'type': 'str',
            },
            'appstat426': {
                'type': 'str',
            },
            'appstat421': {
                'type': 'str',
            },
            'appstat420': {
                'type': 'str',
            },
            'appstat423': {
                'type': 'str',
            },
            'appstat422': {
                'type': 'str',
            },
            'appstat508': {
                'type': 'str',
            },
            'appstat509': {
                'type': 'str',
            },
            'appstat397': {
                'type': 'str',
            },
            'appstat396': {
                'type': 'str',
            },
            'appstat395': {
                'type': 'str',
            },
            'appstat394': {
                'type': 'str',
            },
            'appstat393': {
                'type': 'str',
            },
            'appstat392': {
                'type': 'str',
            },
            'appstat391': {
                'type': 'str',
            },
            'appstat390': {
                'type': 'str',
            },
            'appstat256': {
                'type': 'str',
            },
            'appstat257': {
                'type': 'str',
            },
            'appstat254': {
                'type': 'str',
            },
            'appstat255': {
                'type': 'str',
            },
            'appstat252': {
                'type': 'str',
            },
            'appstat253': {
                'type': 'str',
            },
            'appstat399': {
                'type': 'str',
            },
            'appstat398': {
                'type': 'str',
            },
            'appstat498': {
                'type': 'str',
            },
            'appstat499': {
                'type': 'str',
            },
            'appstat490': {
                'type': 'str',
            },
            'appstat491': {
                'type': 'str',
            },
            'appstat492': {
                'type': 'str',
            },
            'appstat493': {
                'type': 'str',
            },
            'appstat494': {
                'type': 'str',
            },
            'appstat495': {
                'type': 'str',
            },
            'appstat496': {
                'type': 'str',
            },
            'appstat497': {
                'type': 'str',
            },
            'appstat68': {
                'type': 'str',
            },
            'appstat69': {
                'type': 'str',
            },
            'appstat64': {
                'type': 'str',
            },
            'appstat65': {
                'type': 'str',
            },
            'appstat66': {
                'type': 'str',
            },
            'appstat67': {
                'type': 'str',
            },
            'appstat60': {
                'type': 'str',
            },
            'appstat61': {
                'type': 'str',
            },
            'appstat62': {
                'type': 'str',
            },
            'appstat63': {
                'type': 'str',
            },
            'appstat19': {
                'type': 'str',
            },
            'appstat18': {
                'type': 'str',
            },
            'appstat11': {
                'type': 'str',
            },
            'appstat10': {
                'type': 'str',
            },
            'appstat13': {
                'type': 'str',
            },
            'appstat12': {
                'type': 'str',
            },
            'appstat15': {
                'type': 'str',
            },
            'appstat14': {
                'type': 'str',
            },
            'appstat17': {
                'type': 'str',
            },
            'appstat16': {
                'type': 'str',
            },
            'appstat179': {
                'type': 'str',
            },
            'appstat178': {
                'type': 'str',
            },
            'appstat177': {
                'type': 'str',
            },
            'appstat176': {
                'type': 'str',
            },
            'appstat175': {
                'type': 'str',
            },
            'appstat174': {
                'type': 'str',
            },
            'appstat173': {
                'type': 'str',
            },
            'appstat172': {
                'type': 'str',
            },
            'appstat171': {
                'type': 'str',
            },
            'appstat170': {
                'type': 'str',
            },
            'appstat379': {
                'type': 'str',
            },
            'appstat378': {
                'type': 'str',
            },
            'appstat371': {
                'type': 'str',
            },
            'appstat370': {
                'type': 'str',
            },
            'appstat373': {
                'type': 'str',
            },
            'appstat372': {
                'type': 'str',
            },
            'appstat375': {
                'type': 'str',
            },
            'appstat374': {
                'type': 'str',
            },
            'appstat377': {
                'type': 'str',
            },
            'appstat376': {
                'type': 'str',
            },
            'appstat108': {
                'type': 'str',
            },
            'appstat109': {
                'type': 'str',
            },
            'appstat102': {
                'type': 'str',
            },
            'appstat103': {
                'type': 'str',
            },
            'appstat100': {
                'type': 'str',
            },
            'appstat101': {
                'type': 'str',
            },
            'appstat106': {
                'type': 'str',
            },
            'appstat107': {
                'type': 'str',
            },
            'appstat104': {
                'type': 'str',
            },
            'appstat105': {
                'type': 'str',
            },
            'appstat289': {
                'type': 'str',
            },
            'appstat288': {
                'type': 'str',
            },
            'appstat511': {
                'type': 'str',
            },
            'appstat510': {
                'type': 'str',
            },
            'appstat454': {
                'type': 'str',
            },
            'appstat455': {
                'type': 'str',
            },
            'appstat456': {
                'type': 'str',
            },
            'appstat457': {
                'type': 'str',
            },
            'appstat450': {
                'type': 'str',
            },
            'appstat451': {
                'type': 'str',
            },
            'appstat452': {
                'type': 'str',
            },
            'appstat453': {
                'type': 'str',
            },
            'appstat458': {
                'type': 'str',
            },
            'appstat459': {
                'type': 'str',
            },
            'appstat201': {
                'type': 'str',
            },
            'appstat200': {
                'type': 'str',
            },
            'appstat203': {
                'type': 'str',
            },
            'appstat202': {
                'type': 'str',
            },
            'appstat205': {
                'type': 'str',
            },
            'appstat328': {
                'type': 'str',
            },
            'appstat207': {
                'type': 'str',
            },
            'appstat206': {
                'type': 'str',
            },
            'appstat209': {
                'type': 'str',
            },
            'appstat208': {
                'type': 'str',
            },
            'appstat286': {
                'type': 'str',
            },
            'appstat55': {
                'type': 'str',
            },
            'appstat54': {
                'type': 'str',
            },
            'appstat57': {
                'type': 'str',
            },
            'appstat56': {
                'type': 'str',
            },
            'appstat51': {
                'type': 'str',
            },
            'appstat50': {
                'type': 'str',
            },
            'appstat53': {
                'type': 'str',
            },
            'appstat52': {
                'type': 'str',
            },
            'appstat59': {
                'type': 'str',
            },
            'appstat58': {
                'type': 'str',
            },
            'appstat335': {
                'type': 'str',
            },
            'appstat334': {
                'type': 'str',
            },
            'appstat337': {
                'type': 'str',
            },
            'appstat336': {
                'type': 'str',
            },
            'appstat331': {
                'type': 'str',
            },
            'appstat330': {
                'type': 'str',
            },
            'appstat333': {
                'type': 'str',
            },
            'appstat332': {
                'type': 'str',
            },
            'appstat339': {
                'type': 'str',
            },
            'appstat338': {
                'type': 'str',
            },
            'appstat146': {
                'type': 'str',
            },
            'appstat147': {
                'type': 'str',
            },
            'appstat144': {
                'type': 'str',
            },
            'appstat145': {
                'type': 'str',
            },
            'appstat142': {
                'type': 'str',
            },
            'appstat143': {
                'type': 'str',
            },
            'appstat140': {
                'type': 'str',
            },
            'appstat141': {
                'type': 'str',
            },
            'appstat148': {
                'type': 'str',
            },
            'appstat149': {
                'type': 'str',
            },
            'appstat410': {
                'type': 'str',
            },
            'appstat411': {
                'type': 'str',
            },
            'appstat412': {
                'type': 'str',
            },
            'appstat413': {
                'type': 'str',
            },
            'appstat414': {
                'type': 'str',
            },
            'appstat415': {
                'type': 'str',
            },
            'appstat416': {
                'type': 'str',
            },
            'appstat417': {
                'type': 'str',
            },
            'appstat418': {
                'type': 'str',
            },
            'appstat419': {
                'type': 'str',
            },
            'appstat237': {
                'type': 'str',
            }
        },
        'uuid': {
            'type': 'str',
        }
    })
    # Parent keys
    rv.update(dict(rule_set_name=dict(type='str', required=True), ))
    return rv


def existing_url(module):
    """Return the URL for an existing resource"""
    # Build the format dictionary
    url_base = "/axapi/v3/rule-set/{rule_set_name}/app"

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


def get(module):
    return module.client.get(existing_url(module))


def get_list(module):
    return module.client.get(list_url(module))


def get_stats(module):
    if module.params.get("stats"):
        query_params = {}
        for k, v in module.params["stats"].items():
            query_params[k.replace('_', '-')] = v
        return module.client.get(stats_url(module), params=query_params)
    return module.client.get(stats_url(module))


def exists(module):
    try:
        return get(module)
    except a10_ex.NotFound:
        return None


def _to_axapi(key):
    return translateBlacklist(key, KW_OUT).replace("_", "-")


def _build_dict_from_param(param):
    rv = {}

    for k, v in param.items():
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


def build_envelope(title, data):
    return {title: data}


def new_url(module):
    """Return the URL for creating a resource"""
    # To create the URL, we need to take the format string and return it with no params
    url_base = "/axapi/v3/rule-set/{rule_set_name}/app"

    f_dict = {}
    f_dict["rule_set_name"] = module.params["rule_set_name"]

    return url_base.format(**f_dict)


def validate(params):
    # Ensure that params contains all the keys.
    requires_one_of = sorted([])
    present_keys = sorted([
        x for x in requires_one_of if x in params and params.get(x) is not None
    ])

    errors = []
    marg = []

    if not len(requires_one_of):
        return REQUIRED_VALID

    if len(present_keys) == 0:
        rc, msg = REQUIRED_NOT_SET
        marg = requires_one_of
    elif requires_one_of == present_keys:
        rc, msg = REQUIRED_MUTEX
        marg = present_keys
    else:
        rc, msg = REQUIRED_VALID

    if not rc:
        errors.append(msg.format(", ".join(marg)))

    return rc, errors


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


def run_command(module):
    run_errors = []

    result = dict(changed=False, original_message="", message="", result={})

    state = module.params["state"]
    ansible_host = module.params["ansible_host"]
    ansible_username = module.params["ansible_username"]
    ansible_password = module.params["ansible_password"]
    ansible_port = module.params["ansible_port"]
    a10_partition = module.params["a10_partition"]
    a10_device_context_id = module.params["a10_device_context_id"]

    if ansible_port == 80:
        protocol = "http"
    elif ansible_port == 443:
        protocol = "https"

    valid = True

    if state == 'present':
        valid, validation_errors = validate(module.params)
        for ve in validation_errors:
            run_errors.append(ve)

    if not valid:
        err_msg = "\n".join(run_errors)
        result["messages"] = "Validation failure: " + str(run_errors)
        module.fail_json(msg=err_msg, **result)

    module.client = client_factory(ansible_host, ansible_port, protocol,
                                   ansible_username, ansible_password)

    if a10_partition:
        module.client.activate_partition(a10_partition)

    if a10_device_context_id:
        module.client.change_context(a10_device_context_id)

    existing_config = exists(module)

    if state == 'present':
        result = present(module, result, existing_config)

    if state == 'noop':
        if module.params.get("get_type") == "single":
            result["result"] = get(module)
        elif module.params.get("get_type") == "list":
            result["result"] = get_list(module)
        elif module.params.get("get_type") == "stats":
            result["result"] = get_stats(module)
    module.client.session.close()
    return result


def main():
    module = AnsibleModule(argument_spec=get_argspec(),
                           supports_check_mode=True)
    result = run_command(module)
    module.exit_json(**result)


# standard ansible module imports
from ansible.module_utils.basic import AnsibleModule

if __name__ == '__main__':
    main()
