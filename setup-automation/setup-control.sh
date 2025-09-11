#!/bin/bash

systemctl stop systemd-tmpfiles-setup.service
systemctl disable systemd-tmpfiles-setup.service

nmcli connection add type ethernet con-name enp2s0 ifname enp2s0 ipv4.addresses 192.168.1.10/24 ipv4.method manual connection.autoconnect yes
nmcli connection up enp2s0
echo "192.168.1.10 control.lab control" >> /etc/hosts


# Create a playbook for the user to execute


##
export ANSIBLE_LOCALHOST_WARNING=False
export ANSIBLE_INVENTORY_UNPARSED_WARNING=False

##
ANSIBLE_COLLECTIONS_PATH=/tmp/ansible-automation-platform-containerized-setup-bundle-2.5-9-x86_64/collections/:/root/.ansible/collections/ansible_collections/ ansible-playbook -i /tmp/inventory /tmp/setup.yml

