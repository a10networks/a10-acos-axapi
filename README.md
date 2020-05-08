# A10 Ansible AXAPI Collection
Repository of for ansible modules which interact with the AXAPI

## Table of Contents
1. [Overview](#Overview)

2. [Installation](#Installation)

3. [How to use collection Modules ](#How%20to%20use%20Collection%20Modules)

4. [Usage information](#Usage%20Information)

5. [Examples](#Examples)

6. [Issues and Inquiries](#Issues-and-Inquiries)

## Overview

#### Summary
This repository is a set of Ansible modules and example playbooks for interacting with AXAPI v3 for configuration and monitoring of A10 ACOS-based hardware and virtual appliances. The module code and example playbooks are generated using a combination of Python code and Jinja templates.

This code is now being generated using the SDK generator at https://github.com/a10networks/sdkgenerator

## Installation
a10-acos-axapi is collection of custom ansible modules crated by a10Networks. It can be installed using following ways . It is assumed that ansible is already installed and configured.

### 1. Install from galaxy hub

`ansible-galaxy collection install a10.acos_axapi`

Be sure to note the collection path found within the output of the above command. For example:
```bash
$ ansible-galaxy collection install a10.acos_axapi
Process install dependency map
Starting collection install process
Installing 'a10.acos_axapi:1.0.0' to '/opt/.ansible/collections/ansible_collections/a10/acos_axapi'
```

In this example the collection directory path is: `/opt/.ansible/collections/ansible_collections/`

### 2. Install from the Github repository
  
  ~~~
  git clone https://github.com/a10networks/a10-acos-axapi
  cd a10-acos-axapi
  ansible-galaxy collection build
  ansible-galaxy collection install a10-acos_axapi*.tar.gz -p ./collections
  ~~~
  - #### Methods to set collection path (Only one required)

  1. Copy collection folder we got from tarball inside
     - ~/.ansible/collections
     - /usr/share/ansible/collections folder
  
  2. Export following environment variables for new session

      ```bash
      ANSIBLE_COLLECTIONS_PATHS=<path-to-collections-folders>
      ```
    
  3. Add below line in /etc/ansible/ansible.cfg File

      ```bash
      collections_paths=<path-to-collection1>:<path-to-collection2>
      ```

  4. Keep your playbooks to run in relative to collection

      ~~~
      |── myplaybook.yml
      ├── collections/
      │   └── ansible_collections/
      │               └── a10/
      │                   └── acos_axapi/<collection structure lives here>
      ~~~

## How to use Collection Modules

### Any one of the following option can be used for writing playbooks for Collection modules:
### Option 1 (Ansbile >=2.8):  Use the 'collections' keyword

```yaml
collections:
  - a10.acos_axapi

tasks:
  - module_name:
    - argument
  - module_name:
    - argument
```

### Option 2: Use the FQCN (namespace.collection_name.module_name)

```yaml
tasks:
  - a10.acos_axapi.module_name:
    - argument
  - a10.acos_axapi.module_name:
    - argument
```


## Usage Information
All actions are required to have `a10_host`, `a10_username`, `a10_password`, `a10_port`, and `a10_protocol` specified. Note that `a10_host` refers to the ip address of the Thunder device.

Action and module names are formatted based upon their API endpoint. For example, the virtual server endpoint is as follows: `/axapi/v3/slb/virtual-server`. As such, the action name is `a10_slb_virtual_server` and the module is `a10_slb_virtual_server.py`.

**Note that when getting information, changes made to the playbook will not result in a create, update or delete as the state has been put into no-op.

### Creating / updating a resource
#### Option 1: (Ansbile >=2.8): Use the 'collections' keyword
```
- name: <Description of playbook>
  connection: local
  hosts: <inventory>
  collections:
    <a10.acos_axapi>
  tasks:
    - name: <Description of task>
      <module_name>:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        <resource_key>: <resource_val>
        <another_resource_key>: <another_resource_val>
```

#### Option 2: Use the FQCN (namespace.collection_name.module_name)
```
- name: <Description of playbook>
  connection: local
  hosts: <inventory>
  tasks:
    - name: <Description of task>
      <a10.acos_axapi.module_name>:
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
      &lt;a10.acos_axapi.module_name&gt;:
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
      &lt;a10.acos_axapi.module_name&gt;:
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
      &lt;a10.acos_axapi.module_name&gt;:
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
      &lt;a10.acos_axapi.module_name&gt;:
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
      &lt;a10.acos_axapi.module_name&gt;:
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
      &lt;a10.acos_axapi.module_name&gt;:
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

### Configuring a resource in a different device context
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        a10_host: {{ a10_host }}
        a10_username: {{ a10_username }}
        a10_password: {{ a10_password }}
        a10_port: {{ a10_port }}
        a10_protocol: {{ a10_protocol }}
        <b>a10_device_context_id: {{ device_context_id }}</b>
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
      &lt;a10.acos_axapi.module_name&gt;:
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


## Module Documentation

```
$ ansible-doc -M <collection-dir-path> <module_name>
```


## Examples
Please see (https://github.com/a10networks/a10-acos-axapi/tree/master/examples) for example playbooks.


## Issues and Inquiries
For all issues, please send an email to support@a10networks.com 

For general inquiries, please send an email to opensource@a10networks.com
