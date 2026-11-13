#!/bin/bash
# AUDITOR-1325 - Analisis CIS de los tres equipos
source ~/cis-1325/venv/bin/activate

# Router y switch con ONYX (CIS Cisco IOS 15 Benchmark), modo interactivo
# Pide Target, Username (admin1325), Password y Enable
cd ~/cis-1325/onyx/src/onyx_unclesocks
python3 onyx.py -i -v 15 -o R1-1325.html     # Target 10.13.25.1
python3 onyx.py -i -v 15 -o SW-1325.html     # Target 10.13.25.2
# Informes HTML en report_modules/reports/

# FortiGate con FortiGate CIS Checker (CIS FortiGate 7.0.x Benchmark)
cd ~/cis-1325
python3 03_exportar_config_fortigate.py
cd ~/cis-1325/fgcheck/Python
python3 fortigate_cis_checker.py ~/cis-1325/fg_config
# Informes HTML y CSV en audit_reports/

# Servidor web para ver los informes HTML desde el webterm (http://10.13.25.10:8000)
cd ~/cis-1325
python3 -m http.server 8000
