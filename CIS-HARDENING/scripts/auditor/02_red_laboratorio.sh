#!/bin/bash
# AUDITOR-1325 - IP fija en la LAN 10.13.25.0/24 (despues se conecta a SW-1325 Gi0/1)
sudo tee /etc/netplan/50-cloud-init.yaml > /dev/null <<'EOF'
network:
  version: 2
  ethernets:
    ens3:
      addresses: [10.13.25.10/24]
      routes:
        - to: default
          via: 10.13.25.1
      nameservers:
        addresses: [8.8.8.8]
EOF
sudo netplan apply

# Algoritmos SSH que usa el IOS 15 (para conectarse con ssh desde la consola)
mkdir -p ~/.ssh
cat >> ~/.ssh/config <<'EOF'
Host 10.13.25.*
  KexAlgorithms +diffie-hellman-group14-sha1
  HostKeyAlgorithms +ssh-rsa
  PubkeyAcceptedAlgorithms +ssh-rsa
  Ciphers +aes128-cbc,aes256-cbc
EOF
chmod 600 ~/.ssh/config

ping -c 3 10.13.25.1
ping -c 3 10.13.25.2
ping -c 3 172.13.25.1
