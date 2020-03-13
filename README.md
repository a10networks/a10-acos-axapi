# A10 Ansible AXAPI Collection
Repository of for ansible modules which interact with the AXAPI

## Table of Contents
1. [Overview](#Overview)

2. [Installation](#Installation)

3. [Usage information](#Usage)

4. [Examples](#Examples)

5. [Issues and Inquiries](#Issues-and-Inquiries)

## Overview

#### Summary
This repository is a set of Ansible modules and example playbooks for interacting with AXAPI v3 for configuration and monitoring of A10 ACOS-based hardware and virtual appliances. The module code and example playbooks are generated using a combination of Python code and Jinja templates.

This code is now being generated using the SDK generator at https://github.com/a10networks/sdkgenerator

## Installation
a10-ansible is distributed as a Python package. It can be installed from the Github repository. It is assumed that ansible is already installed and configured.

### Github Installation - Using Script (Linux) 
~~~
git clone https://github.com/a10networks/a10-ansible a10-ansible
cd a10-ansible 
chmod +x a10_install.sh

Check the ansible module location then run..

./a10_install.sh

You can now delete the install files 
~~~

### Github Installation - Pip Install
~~~
git clone https://github.com/a10networks/a10-ansible a10-ansible
pip install -e a10-ansible/
~~~

## Usage Information
All actions are required to have `a10_host`, `a10_username`, `a10_password`, `a10_port`, and `a10_protocol` specified. Note that `a10_host` refers to the ip address of the Thunder device.

Action and module names are formatted based upon their API endpoint. For example, the virtual server endpoint is as follows: `/axapi/v3/slb/virtual-server`. As such, the action name is `a10_slb_virtual_server` and the module is `a10_slb_virtual_server.py`. 

**Note that when getting information, changes made to the playbook will not result in a create or update as the state has been put into no-op.

### Creating / updating a resource
```
- name: <Description of playbook>
  connection: local
  hosts: <inventory>
  tasks:
    - name: <Description of task>
      <action>:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        <resource_key>: <resource_val>
        <another_resource_key>: <another_resource_val>
```

### Deleting a resource
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;action&gt;:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: absent</b>
</pre>

### Getting information about a single object
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;action&gt;:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: noop</b>
        <b>get_type: single</b> 
</pre>


### Getting information about a collection
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;action&gt;:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: noop</b>
        <b>get_type: list</b>
</pre>

### Getting operational information
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;action&gt;:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: noop</b>
        <b>get_type: oper</b>
</pre>

### Getting statistic information
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;action&gt;:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: noop</b>
        <b>get_type: stats</b>
</pre>


### Configuring a resource on a partition 
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;action&gt;:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        <b>a10_partition:</b>
          <b>name: {{ partition_name }}</b>
          <b>shared: 0</b>
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
</pre>

### Check Mode
Check mode can be specified in two ways:

<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;action&gt;:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>check_mode: yes</b>
</pre>

or

```bash
$ ansible-playbook <playbook_name>.yml --check-mode
```

## Examples
Please see (https://github.com/a10networks/a10-ansible/tree/master/examples) for example playbooks.

## Issues and Inquiries
For all issues, please send an email to support@a10networks.com 

For general inquiries, please send an email to opensource@a10networks.com
