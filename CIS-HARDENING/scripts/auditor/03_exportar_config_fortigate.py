#!/usr/bin/env python3
# Descarga la configuracion del FortiGate por SSH para analizarla con el FortiGate CIS Checker
# Uso: cd ~/cis-1325 && source venv/bin/activate && python3 03_exportar_config_fortigate.py
from pathlib import Path
from netmiko import ConnectHandler

Path("fg_config").mkdir(exist_ok=True)
c = ConnectHandler(device_type="fortinet", host="172.13.25.1", username="admin", password="Forti1325!")
texto = c.send_command("show", read_timeout=180)
c.disconnect()
texto = texto[texto.find("#config-version="):]
Path("fg_config/FG-1325.conf").write_text(texto)
print("Guardado:", len(texto.splitlines()), "lineas")
