## Table of Contents

1. [Change Password](#Change-Password)

2. [Pre-requisite](#Pre-requisite)

3. [Sample Inventory file](#Sample-Inventory-file)

4. [Sample Playbook](#Sample-Playbook)

## Change Password
Sample playbook to change password of vThunder.

### Pre-requisite
Ansible >=2.9
Download acos_axapi collection from galaxy hub https://galaxy.ansible.com/a10/acos_axapi.
Install collection using command:
ansible-galaxy collection install a10.acos_axapi

### Sample Inventory file:

File location : https://github.com/a10networks/a10-acos-axapi/tree/master/examples/single_task/admin/adminPassword/a10_inventory.yml

```shell
all:
  hosts:
    vthunder:
      ansible_host: <xx.xx.xx.xx>
      ansible_username: admin
      ansible_password: <current_password>
      ansible_port: 443
```

### Sample Playbook:

File location : https://github.com/a10networks/a10-acos-axapi/tree/master/examples/single_task/admin/adminPassword/a10_admin_change_password.yaml

```shell
- name: Playbook to change password.
  connection: local
  hosts: vthunder
  tasks:
  - name: Change password a10.acos_axapi.a10_admin_password instance
    a10.acos_axapi.a10_admin_password:
      admin_user: admin
      password_in_module : <new_password>
```


Use the following command to run playbook :
```shell
ansible-playbook -i a10_inventory a10_admin_change_password
```
