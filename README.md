## Table of Contents
1. [Overview](#Overview)

2. [Installation](#Installation)

3. [Plugin Configuration](#Plugin-Configuration)

4. [Collection module usage options ](#Collection-module-usage-options)

5. [Setup and Configurations](#Setup-and-Configurations)

6. [Usage information](#Usage-Information)

7. [Examples](#Examples)

8. [Issues and Inquiries](#Issues-and-Inquiries)

9. [Test Cases](#Test-Cases)
## Overview

#### Summary
This repository is a set of Ansible modules and example playbooks for interacting with AXAPI v3 for configuration and monitoring of A10 ACOS-based hardware and virtual appliances. The module code and example playbooks are generated using a combination of Python code and Jinja templates.

We only support Ansible version >=2.9

This code is now being generated using the SDK generator at https://github.com/a10networks/sdkgenerator

## Installation
a10-acos-axapi is collection of custom ansible modules crated by a10Networks. It can be installed using following ways, it is assumed that ansible is already installed and configured.

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

## Plugin Configuration

#### 1. Set plugin path

Add below line in the `/etc/ansible/ansible.cfg` file

```bash
action_plugins  = <collection-dir-path>/a10/acos_axapi/plugins/action
```

#### 2a. Alternative methods to set path

  1. Copy action plugin into one of the following
     - ~/.ansible/plugins
     - /usr/share/ansible/plugins folder

  2. Export following environment variables for new session

  ```bash
  export ANSIBLE_ACTION_PLUGINS=<collection-dir-path>/a10/acos_axapi/plugins/action
  ```

  3. Save this variable in .bashrc File

  ```bash
  export ANSIBLE_ACTION_PLUGINS=<collection-dir-path>/a10/acos_axapi/plugins/action
  ```



## Collection module usage options

### Any of the following options can be used for writing playbooks for Collection modules:
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


## Setup and Configurations

### 1. With Inventory file
Sample Inventory file:

```shell
[vthunder]
<vthunder host_name/ip_address>

[vthunder:vars]
ansible_username=<username>
ansible_password=<password>
ansible_port=<port>
```

If you want to use an Inventory file to perform respective configurations through a playbook, you don't need to specify `ansible_host`, `ansible_username`, `ansible_password` and `ansible_port` in the playbook.

For example,
```
- name: <Description of playbook>
  connection: local
  hosts: <inventory_hostname>
  collections:
    <a10.acos_axapi>
  tasks:
    - name: <Description of task>
      <module_name>:
        <resource_key>: <resource_val>
        <another_resource_key>: <another_resource_val>
```

Use the following command to run playbook using an Inventory file parameters:
```shell
ansible-playbook -i <path_to_inventory> <name_of_playbook>
```

### 2. Without Inventory file
If you don't want to use Inventory file, then specify `ansible_host`, `ansible_username`, `ansible_password` and `ansible_port` arguments into playbook itself with hosts as `localhost`. And then the configurations will be performed on provided `ansible_host`.

For example,
```
- name: <Description of playbook>
  connection: local
  hosts: localhost
  collections:
    <a10.acos_axapi>
  tasks:
    - name: <Description of task>
      <module_name>:
        ansible_host: {{ ansible_host }}
        ansible_username: {{ ansible_username }}
        ansible_password: {{ ansible_password }}
        ansible_port: {{ ansible_port }}
        <resource_key>: <resource_val>
        <another_resource_key>: <another_resource_val>
```

Use the following command to run the playbook with local arguments:
```shell
ansible-playbook <name_of_playbook>
```

Use the following command to run the playbook:
```shell
ansible-playbook -i <path_to_inventory> <name_of_playbook>
```

## Usage Information
Action and module names are formatted based upon their API endpoint. For example, the virtual server endpoint is as follows: `/axapi/v3/slb/virtual-server`. As such, the action name is `a10_slb_virtual_server` and the module is `a10_slb_virtual_server.py`.

**Note that when getting information, changes made to the playbook will not result in a create, update or delete as the state has been put into no-op.

### Creating / updating a resource
#### Option 1: (Ansbile >=2.8): Use the 'collections' keyword
```
- name: <Description of playbook>
  connection: local
  hosts: <inventory_hostname>
  collections:
    <a10.acos_axapi>
  tasks:
    - name: <Description of task>
      <module_name>:
        <resource_key>: <resource_val>
        <another_resource_key>: <another_resource_val>
```

#### Option 2: Use the FQCN (namespace.collection_name.module_name)
```
- name: <Description of playbook>
  connection: local
  hosts: <inventory_hostname>
  tasks:
    - name: <Description of task>
      <a10.acos_axapi.module_name>:
        <resource_key>: <resource_val>
        <another_resource_key>: <another_resource_val>
```

### Deleting a resource
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: absent</b>
</pre>

### Getting information about a single object
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: noop</b>
        <b>get_type: single</b>
</pre>

### Getting information about a collection
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: noop</b>
        <b>get_type: list</b>
</pre>

### Getting operational information
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: noop</b>
        <b>get_type: oper</b>
</pre>

### Getting statistic information
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>state: noop</b>
        <b>get_type: stats</b>
</pre>

### Configuring a resource on a partition
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        <b>a10_partition: {{ partition_name }}</b>
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
</pre>

### Configuring a resource in a different device context
<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        <b>a10_device_context_id: {{ device_context_id }}</b>
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
</pre>

### Uploading a file directly
*Note: Only available in modules with `file_path` argument*

<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        <b>file_path: "/path/to/file"</b>
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
</pre>

### Check Mode
Check mode can be specified in two ways:

<pre>
- name: &lt;Description of playbook&gt;
  connection: local
  hosts: &lt;inventory_hostname&gt;
  tasks:
    - name: &lt;Description of task&gt;
      &lt;a10.acos_axapi.module_name&gt;:
        &lt;resource_key&gt;: &lt;resource_val&gt;
        &lt;another_resource_key&gt;: &lt;another_resource_val&gt;
        <b>check_mode: yes</b>
</pre>

or

```bash
$ ansible-playbook -i <path_to_inventory> <playbook_name>.yml --check-mode
```


## Module Documentation

```
$ ansible-doc -M <collection-dir-path> <module_name>
```

## Test Cases
Sample test cases added for the following configurations:
  - Bgp
  - Check Mode
  - Class List
  - Default Gateway
  - files
  - Gslb
  - Health
  - Network
  - Slb
  - Slb Template
  
### Run test cases
To test configurations on the acos using ansible playbooks goto ``` test ``` directory and use the following command:
```bash
sh run_test_playbooks.sh

```

## Examples
Please see (https://github.com/a10networks/a10-acos-axapi/tree/master/examples) for example playbooks.


## Issues and Inquiries
For all issues, please send an email to support@a10networks.com 
