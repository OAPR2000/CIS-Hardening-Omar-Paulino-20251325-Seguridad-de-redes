#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cis_hardening.py - Auditoria y hardening CIS
Equipos: R1-1325 y SW-1325 (Cisco IOS) y FG-1325 (FortiGate)
Omar Paulino - 20251325

Uso:
  python3 cis_hardening.py --audit    Crea un informe SIN aplicar ninguna regla
  python3 cis_hardening.py --apply    Aplica las reglas que fallan y crea el informe posterior
"""

import argparse
import datetime
import json
import re
import sys
from pathlib import Path

try:
    from netmiko import ConnectHandler
except ImportError:
    sys.exit("Falta netmiko. Instala con: pip install netmiko")

BASE = Path(__file__).resolve().parent
BANNER = "ACCESO RESTRINGIDO - Solo personal autorizado - Lab CIS 20251325"


# ---------------------------------------------------------------------
# Lectura de configuraciones
# ---------------------------------------------------------------------

def bloques_linea(run, tipo):
    """Devuelve {'line vty 0 4': [lineas internas], ...} para 'con' o 'vty'."""
    bloques, actual = {}, None
    for l in run.splitlines():
        if re.match(r"^line " + tipo, l):
            actual = l.strip()
            bloques[actual] = []
        elif actual and l.startswith(" "):
            bloques[actual].append(l.strip())
        else:
            actual = None
    return bloques


def timeout_min(lineas):
    """Minutos de exec-timeout; si no esta configurado, el valor por defecto es 10."""
    for l in lineas:
        m = re.match(r"exec-timeout (\d+)(?: (\d+))?", l)
        if m:
            return int(m.group(1)) + int(m.group(2) or 0) / 60
    return 10


# ---------------------------------------------------------------------
# Reglas Cisco IOS (CIS Cisco IOS 15 Benchmark)
# Cada regla: (id, titulo, comprobar(run) -> (cumple, evidencia), corregir(run) -> comandos)
# ---------------------------------------------------------------------

def c01_check(run):
    malas = [h for h, b in bloques_linea(run, "vty").items() if "transport input ssh" not in b]
    return (not malas, "Permiten Telnet: " + ", ".join(malas) if malas else "Todas las VTY solo SSH")


def c01_fix(run):
    cmds = []
    for h in bloques_linea(run, "vty"):
        cmds += [h, "transport input ssh"]
    return cmds


def c02_check(run):
    malas = []
    for tipo in ("con", "vty"):
        for h, b in bloques_linea(run, tipo).items():
            t = timeout_min(b)
            if t == 0 or t > 10:
                malas.append(h)
    return (not malas, "Sin limite: " + ", ".join(malas) if malas else "exec-timeout <= 10 min")


def c02_fix(run):
    cmds = []
    for tipo in ("con", "vty"):
        for h in bloques_linea(run, tipo):
            cmds += [h, "exec-timeout 5 0"]
    return cmds


def c03_check(run):
    ok = re.search(r"^banner motd", run, re.M) is not None
    return (ok, "Banner configurado" if ok else "Sin banner")


def c03_fix(run):
    return ["banner motd #{}#".format(BANNER)]


def c04_check(run):
    ok = re.search(r"^service password-encryption", run, re.M) is not None
    return (ok, "Activado" if ok else "Contrasenas en texto claro")


def c04_fix(run):
    return ["service password-encryption"]


def c05_check(run):
    activos = [s for s in ("ip http server", "ip http secure-server") if re.search("^" + s, run, re.M)]
    return (not activos, "Activo: " + ", ".join(activos) if activos else "HTTP deshabilitado")


def c05_fix(run):
    return ["no ip http server", "no ip http secure-server"]


def c06_check(run):
    ok = re.search(r"^ip ssh version 2", run, re.M) is not None
    return (ok, "SSH solo version 2" if ok else "SSH version 1.99 (acepta SSHv1)")


def c06_fix(run):
    return ["ip ssh version 2"]


REGLAS_CISCO = [
    ("C01", "Solo SSH en las lineas VTY (sin Telnet)", c01_check, c01_fix),
    ("C02", "exec-timeout de 5 min en consola y VTY", c02_check, c02_fix),
    ("C03", "Banner de aviso (banner motd)", c03_check, c03_fix),
    ("C04", "Cifrar contrasenas (service password-encryption)", c04_check, c04_fix),
    ("C05", "Deshabilitar el servidor HTTP/HTTPS", c05_check, c05_fix),
    ("C06", "Solo SSH version 2 (ip ssh version 2)", c06_check, c06_fix),
]


# ---------------------------------------------------------------------
# Reglas FortiGate (CIS FortiGate 7.0.x Benchmark)
# ---------------------------------------------------------------------

def accesos_inseguros(interfaces):
    """Devuelve {interfaz: accesos_que_se_quedan} para las que tienen http o telnet."""
    malas, actual = {}, None
    for l in interfaces.splitlines():
        m = re.match(r'\s*edit "([^"]+)"', l)
        if m:
            actual = m.group(1)
        m = re.match(r"\s*set allowaccess (.+)", l)
        if m and actual:
            accesos = m.group(1).split()
            if "http" in accesos or "telnet" in accesos:
                malas[actual] = [a for a in accesos if a not in ("http", "telnet")]
    return malas


def valor_global(glob, clave, defecto):
    m = re.search(r"set {} (\S+)".format(clave), glob)
    return m.group(1) if m else defecto


def f01_check(d):
    malas = accesos_inseguros(d["interfaces"])
    return (not malas, "HTTP/Telnet en: " + ", ".join(malas) if malas else "Solo HTTPS y SSH")


def f01_fix(d):
    cmds = ["config system interface"]
    for intf, quedan in accesos_inseguros(d["interfaces"]).items():
        cmds += ['edit "{}"'.format(intf), "set allowaccess " + " ".join(quedan), "next"]
    return cmds + ["end"]


def f02_check(d):
    t = int(valor_global(d["global"], "admintimeout", "5"))
    return (t <= 5, "admintimeout {} min".format(t))


def f02_fix(d):
    return ["config system global", "set admintimeout 5", "end"]


def f03_check(d):
    v = valor_global(d["global"], "pre-login-banner", "disable")
    return (v == "enable", "pre-login-banner " + v)


def f03_fix(d):
    return ["config system global", "set pre-login-banner enable", "end"]


REGLAS_FORTI = [
    ("F01", "Administrar solo por HTTPS/SSH (sin HTTP ni Telnet)", f01_check, f01_fix),
    ("F02", "Timeout de administracion de 5 minutos", f02_check, f02_fix),
    ("F03", "Banner de aviso antes del login", f03_check, f03_fix),
]


# ---------------------------------------------------------------------
# Conexion, revision y aplicacion
# ---------------------------------------------------------------------

def es_cisco(equipo):
    return equipo["device_type"].startswith("cisco")


def leer(conn, equipo):
    if es_cisco(equipo):
        return conn.send_command("show running-config", read_timeout=60)
    return {"global": conn.send_command("show full-configuration system global", read_timeout=60),
            "interfaces": conn.send_command("show system interface", read_timeout=60)}


def revisar(datos, equipo):
    reglas = REGLAS_CISCO if es_cisco(equipo) else REGLAS_FORTI
    resultado = []
    for rid, titulo, comprobar, _ in reglas:
        ok, evidencia = comprobar(datos)
        resultado.append({"id": rid, "titulo": titulo, "estado": "CUMPLE" if ok else "FALLA",
                          "evidencia": evidencia})
    return resultado


def aplicar(conn, equipo, datos, antes):
    reglas = REGLAS_CISCO if es_cisco(equipo) else REGLAS_FORTI
    fallan = {r["id"] for r in antes if r["estado"] == "FALLA"}
    for rid, _, _, corregir in reglas:
        if rid in fallan:
            cmds = corregir(datos)
            conn.send_config_set(cmds, cmd_verify=False, read_timeout=60)
            print("    [{}] aplicada: {}".format(rid, " / ".join(cmds)))
    if fallan and es_cisco(equipo):
        conn.save_config()


# ---------------------------------------------------------------------
# Programa principal
# ---------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Auditoria y hardening CIS - Omar Paulino 20251325")
    modo = ap.add_mutually_exclusive_group(required=True)
    modo.add_argument("--audit", action="store_true", help="Crear informe sin aplicar reglas")
    modo.add_argument("--apply", action="store_true", help="Aplicar reglas y crear informe posterior")
    args = ap.parse_args()

    equipos = json.loads((BASE / "inventario.json").read_text(encoding="utf-8"))
    ahora = datetime.datetime.now()
    titulo = "INFORME POSTERIOR AL HARDENING" if args.apply else "INFORME DE AUDITORIA (SIN APLICAR CAMBIOS)"
    lineas = ["=" * 78, titulo, "Practica CIS Benchmark - Omar Paulino 20251325",
              "Fecha: " + ahora.strftime("%Y-%m-%d %H:%M:%S"), "=" * 78]

    for eq in equipos:
        print("\n[*] {} ({})".format(eq["name"], eq["host"]))
        lineas += ["", "Equipo: {} ({})".format(eq["name"], eq["host"]), "-" * 78]
        try:
            params = {k: eq[k] for k in ("device_type", "host", "username", "password", "secret") if k in eq}
            conn = ConnectHandler(**params, fast_cli=False)
            if es_cisco(eq):
                conn.enable()
            datos = leer(conn, eq)
            antes = revisar(datos, eq)

            if args.apply:
                aplicar(conn, eq, datos, antes)
                despues = {r["id"]: r for r in revisar(leer(conn, eq), eq)}
                lineas.append("{:<5} {:<8} {:<8} {}".format("Regla", "Antes", "Despues", "Recomendacion"))
                for r in antes:
                    d = despues[r["id"]]
                    lineas.append("{:<5} {:<8} {:<8} {}".format(r["id"], r["estado"], d["estado"], r["titulo"]))
                    lineas.append("{:<23}{}".format("", d["evidencia"]))
            else:
                lineas.append("{:<5} {:<8} {}".format("Regla", "Estado", "Recomendacion"))
                for r in antes:
                    lineas.append("{:<5} {:<8} {}".format(r["id"], r["estado"], r["titulo"]))
                    lineas.append("{:<15}{}".format("", r["evidencia"]))
            conn.disconnect()
        except Exception as e:
            lineas.append("ERROR: no se pudo revisar el equipo: {}".format(e))

    informe = "\n".join(lineas)
    print("\n" + informe)
    carpeta = BASE / "reports"
    carpeta.mkdir(exist_ok=True)
    nombre = "informe_{}_{}.txt".format("posterior" if args.apply else "auditoria", ahora.strftime("%Y%m%d_%H%M%S"))
    (carpeta / nombre).write_text(informe + "\n", encoding="utf-8")
    print("\nInforme guardado en: reports/" + nombre)


if __name__ == "__main__":
    main()
