#!/bin/bash
ansible-playbook ansible/execute_tests.yml --extra-vars "host=$1 user=$2 pass=$3 port=$4 protocol=$5"
