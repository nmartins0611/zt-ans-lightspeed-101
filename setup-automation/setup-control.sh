#!/bin/bash

systemctl stop systemd-tmpfiles-setup.service
systemctl disable systemd-tmpfiles-setup.service

nmcli connection add type ethernet con-name enp2s0 ifname enp2s0 ipv4.addresses 192.168.1.10/24 ipv4.method manual connection.autoconnect yes
nmcli connection up enp2s0
echo "192.168.1.10 control.lab control" >> /etc/hosts



RHEL_SSH_DIR="/home/rhel/.ssh"
RHEL_PRIVATE_KEY="$RHEL_SSH_DIR/id_rsa"
RHEL_PUBLIC_KEY="$RHEL_SSH_DIR/id_rsa.pub"

if [ -f "$RHEL_PRIVATE_KEY" ]; then
    echo "SSH key already exists for rhel user: $RHEL_PRIVATE_KEY"
else
    echo "Creating SSH key for rhel user..."
    sudo -u rhel mkdir -p /home/rhel/.ssh
    sudo -u rhel chmod 700 /home/rhel/.ssh
    sudo -u rhel ssh-keygen -t rsa -b 4096 -C "rhel@$(hostname)" -f /home/rhel/.ssh/id_rsa -N "" -q
    sudo -u rhel chmod 600 /home/rhel/.ssh/id_rsa*
    
    if [ -f "$RHEL_PRIVATE_KEY" ]; then
        echo "SSH key created successfully for rhel user"
    else
        echo "Error: Failed to create SSH key for rhel user"
    fi
fi


# Create a playbook for the user to execute

tee /tmp/setup.yml << EOF
### Automation Controller setup 
###
---
- name: Setup Controller
  hosts: localhost
  connection: local
  collections:
    - ansible.controller

  vars:
    aws_access_key: "{{ lookup('env', 'AWS_ACCESS_KEY_ID') | default('AWS_ACCESS_KEY_ID_NOT_FOUND', true) }}"
    aws_secret_key: "{{ lookup('env', 'AWS_SECRET_ACCESS_KEY') | default('AWS_SECRET_ACCESS_KEY_NOT_FOUND', true) }}"
    aws_default_region: "{{ lookup('env', 'AWS_DEFAULT_REGION') | default('AWS_DEFAULT_REGION_NOT_FOUND', true) }}"
    quay_username: "{{ lookup('env', 'QUAY_USERNAME') | default('QUAY_USERNAME_NOT_FOUND', true) }}"
    quay_password: "{{ lookup('env', 'QUAY_PASSWORD') | default('QUAY_PASSWORD_NOT_FOUND', true) }}"
    azure_subscription: "{{ lookup('env', 'AZURE_SUBSCRIPTION') | default('AZURE_SUBSCRIPTION_NOT_FOUND', true) }}"
    azure_tenant: "{{ lookup('env', 'AZURE_TENANT') | default('AZURE_TENANT_NOT_FOUND', true) }}"
    azure_client_id: "{{ lookup('env', 'AZURE_CLIENT_ID') | default('AZURE_CLIENT_ID_NOT_FOUND', true) }}"
    azure_password: "{{ lookup('env', 'AZURE_PASSWORD') | default('AZURE_PASSWORD_NOT_FOUND', true) }}"
    azure_resourcegroup: "{{ lookup('env', 'AZURE_RESOURCEGROUP') | default('AZURE_RESOURCEGROUP_NOT_FOUND', true) }}"

  vars_files:
    - track_vars.yml
    - vault_track_vars.yml

  vars:
      controller_login: &controller_login
      controller_username: "{{ controller_username }}"
      controller_password: "{{ controller_password }}"
      controller_host: "{{ controller_hostname }}"
      validate_certs: "{{ controller_validate_certs }}"

  tasks:
 


##
export ANSIBLE_LOCALHOST_WARNING=False
export ANSIBLE_INVENTORY_UNPARSED_WARNING=False

##
##ANSIBLE_COLLECTIONS_PATH=/tmp/ansible-automation-platform-containerized-setup-bundle-2.5-9-x86_64/collections/:/root/.ansible/collections/ansible_collections/ ansible-playbook -i /tmp/inventory /tmp/setup.yml

