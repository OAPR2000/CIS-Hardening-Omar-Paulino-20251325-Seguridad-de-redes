#!/bin/bash
# AUDITOR-1325 - Instalacion de las herramientas
# Se ejecuta con el Ubuntu conectado temporalmente a un nodo NAT de GNS3 (DHCP)

sudo hostnamectl set-hostname auditor-1325
echo 'network: {config: disabled}' | sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
sudo tee /etc/netplan/50-cloud-init.yaml > /dev/null <<'EOF'
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: true
EOF
sudo chmod 600 /etc/netplan/50-cloud-init.yaml
sudo netplan apply

sudo apt update
sudo apt install -y python3-venv git telnet curl

mkdir -p ~/cis-1325 && cd ~/cis-1325
python3 -m venv venv
source venv/bin/activate
pip install netmiko tqdm

# ONYX - auditoria CIS Cisco IOS 15/17
git clone https://github.com/UncleSocks/onyx-caaat-automated-cisco-configuration-assessment-and-auditing-tool.git onyx
pip install -r onyx/requirements.txt

# FortiGate CIS Checker - auditoria CIS FortiGate 7.0.x
git clone https://github.com/Coldfirex/Fortigate_CIS_check.git fgcheck

# Paramiko 3: compatible con el intercambio de claves del IOS 15
pip install "paramiko<4"
python3 -c "import paramiko; print(paramiko.__version__)"
