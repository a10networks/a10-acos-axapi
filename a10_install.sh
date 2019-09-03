#!/bin/bash
# Written to install the A10 modules for Ansible, you might need to update the location below.

ANSIBLEMODULES=/usr/share/ansible/plugins/modules/

echo "Going to Install A10 Modules to $ANSIBLEMODULES \n Press enter to continue"
read -s
pip install .
cp -R a10_ansible $ANSIBLEMODULES