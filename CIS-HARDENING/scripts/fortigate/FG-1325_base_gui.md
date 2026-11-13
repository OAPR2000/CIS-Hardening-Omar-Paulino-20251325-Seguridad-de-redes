# FG-1325 - Configuracion base por GUI

Desde el Firefox del webterm, en `https://172.13.25.1`, usuario `admin`.

| Que | Donde en la GUI | Valores |
|---|---|---|
| Hostname y timeout | System > Settings | Hostname `FG-1325`. Administrator Settings > Idle timeout: 480 minutos |
| port1 (WAN) | Network > Interfaces > port1 > Edit | Addressing mode: DHCP. Administrative Access: HTTPS, HTTP, PING, SSH |
| port2 (hacia R1) | Network > Interfaces > port2 > Edit | Alias `HACIA-R1-1325`. Role: LAN. IP `172.13.25.1/255.255.255.252`. Administrative Access: HTTPS, HTTP, PING, SSH, TELNET |
| Ruta a la LAN | Network > Static Routes > Create New | Destination `10.13.25.0/255.255.255.0`. Gateway `172.13.25.2`. Interface `port2` |
| Politica de salida | Policy & Objects > Firewall Policy > Create New | Name `LAN-a-INTERNET`. Incoming `port2`. Outgoing `port1`. Source y Destination `all`. Schedule `always`. Service `ALL`. Action ACCEPT. NAT activado |

HTTP y TELNET en las interfaces y el timeout de 480 minutos son las debilidades
que despues detecta el analisis CIS.
