# a10-ansible
Repository of Ansible modules for A10 Networks ADCs.

# Notes
This code is generated through automated processes. See https://github.com/a10networks/sdkgenerator . Please note this is a private repository and only A10 Networks authorized employees and partners have access to it.

# Installation
`pip install -e git+https://github.com/a10networks/a10-ansible.git#egg=a10-ansible`

This will install the Python a10-ansible module. To make the modules available to Ansible, set `ANSIBLE_PATH` to `<a10-ansible module path>/a10_ansible/library`

# Examples
Individual operation (Create/Update/Delete) examples can be found in the `examples` directory in the root of the a10-ansible module directory.
Playbooks detailing more typical use cases can be found in `examples/_functional`

# Questions / Issues
For bugs/issues, please create an issue in the a10-ansible repository. Please include any example playbooks that demonstrate the issue and detailed output of `ansible-playbook` where possible.
