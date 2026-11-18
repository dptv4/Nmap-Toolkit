# Nmap-Toolkit

Toolkit de reconocimiento para un pentest al estilo CPTS: descubrir hosts, enumerar servicios y lanzar solo los scripts NSE que corresponden a esos servicios. Las salidas quedan en `reports/` para encadenar los módulos sin volver a parsear el XML de Nmap.

## Disclaimer

Esta herramienta es exclusivamente para entornos de laboratorio (Hack The Box, CPTS y equivalentes) y para auditorías con autorización explícita por escrito. Escanear sistemas ajenos sin permiso es ilegal. Quien ejecuta el toolkit es el único responsable de definir el alcance, respetar las reglas del laboratorio y cumplir la ley aplicable. El barrido `-p- --min-rate 5000` es agresivo a propósito y está pensado para redes de laboratorio, no para enlaces de producción.

## Requisitos

- Python 3.11 o superior
- [Nmap](https://nmap.org/download.html) instalado y disponible en el `PATH`
- Privilegios de administrador (Windows) o root (Linux) para el descubrimiento ARP/ICMP y SYN ping, para la detección de sistema operativo (`-O`), para UDP (`-sU`) y para los scripts NSE sobre UDP (SNMP y DNS UDP). Sin elevación, el descubrimiento con sondas raw se detiene con un aviso; el barrido de puertos pasa a TCP connect (`-sT`); `enum` omite `-O` y `--udp` no arranca; `nse` ejecuta los scripts TCP y deja fuera los UDP.

## Instalación

```bash
pip install -r requirements.txt
```

`requirements.txt` solo declara `rich`, usado para la tabla de resultados. El resto del toolkit usa la biblioteca estándar (`subprocess`, `argparse`, `xml.etree.ElementTree`).

## Estructura

```text
main.py                 CLI unificada (argparse) y punto de entrada
core/runner.py          Ejecución segura de nmap, privilegios y XML (-oX)
core/parser.py          Parser XML → diccionarios (IP, hostname, puertos)
modules/discovery.py    Host discovery + fast TCP port scan
modules/enum.py         Service enumeration (-sV -sC -O) y UDP opcional
modules/nse.py          Scripts NSE elegidos por servicio
requirements.txt
reports/                Artefactos de cada ejecución (no se versiona)
```

`reports/` se crea sola en la primera ejecución. Ni `reports/` ni `.cursor/` se suben al repositorio.

## Módulo `discovery` — Host Discovery y Fast Port Scanning

Metodología CPTS en dos fases, encadenadas por el mismo comando.

### 1. Host discovery

Identifica direcciones vivas en un CIDR, una IP, un hostname o un fichero con una entrada por línea (`-iL`). Así el barrido de 65535 puertos no se lanza contra hosts que no responden.

| Método | Cuándo usarlo | Flags de Nmap |
| --- | --- | --- |
| `arp-icmp` (por defecto) | Segmento local o redes de laboratorio que responden a ICMP. ARP cubre el L2 local; ICMP echo cubre hosts enrutados o detrás de la VPN del lab. | `-sn -PE -PR` |
| `syn` | El objetivo filtra ICMP. Sonda TCP SYN a puertos de servicio habituales. | `-sn -PS21,22,80,443,445,3389` |
| `skip` | El host ya se sabe activo, o descarta todo descubrimiento. El target pasa directo al barrido de puertos. | `-Pn` |

`-PE`, `-PR` y `-PS` necesitan raw sockets. Si el proceso no está elevado, el módulo no lanza Nmap: imprime cómo volver a ejecutarlo como administrador/root, o sugiere `--method skip` cuando el host ya es conocido.

El descubrimiento resuelve nombres DNS. Esos hostnames se conservan en el JSON aunque la fase siguiente desactive la resolución.

### 2. Fast port scanning

Sobre cada host vivo (o sobre el target directo si el método es `skip`) se lanza un barrido de todos los puertos TCP, sin DNS y sin repetir el descubrimiento:

```text
nmap -sS -n -Pn -p- --min-rate 5000 <hosts vivos>
```

`-sS` solo se usa con privilegios. Sin ellos el mismo barrido se ejecuta como TCP connect (`-sT`) y el aviso queda en consola, en lugar de un traceback. `--min-rate` se puede bajar con `--min-rate` si el enlace del laboratorio es limitado; el valor por defecto es 5000.

El objetivo de esta fase es la lista de puertos abiertos. La enumeración de versiones, scripts y sistema operativo la hace el módulo `enum` a partir de ese JSON.

### Ejemplos

Descubrimiento ARP/ICMP de un rango de laboratorio y barrido de puertos sobre los hosts que respondan:

```bash
python main.py discovery -t 10.10.10.0/24 --method arp-icmp
```

El mismo flujo cuando el host filtra ICMP:

```bash
python main.py discovery -t 10.10.10.10 --method syn
```

Host ya confirmado como activo; se omite el descubrimiento:

```bash
python main.py discovery -t 10.10.10.10 --method skip
```

Lista de objetivos (una IP, CIDR o hostname por línea; se admiten comentarios `#`):

```bash
python main.py discovery -t targets.txt --method syn --min-rate 5000
```

Ayuda del módulo:

```bash
python main.py discovery --help
```

### Salida esperada

Durante la ejecución se muestra el comando Nmap y su salida nativa. Al terminar, la consola resume los hosts vivos y los puertos TCP abiertos:

```text
Host discovery (arp-icmp)
nmap -sn -PE -PR 10.10.10.0/24
3 live host(s) found.

Fast TCP port scan (syn, -p- --min-rate 5000 -n)
nmap -sS -n -Pn -p- --min-rate 5000 10.10.10.10 10.10.10.20 10.10.10.27

Live hosts and open TCP ports
IP            Status  Hostnames   Open TCP ports
10.10.10.10   up      dc.htb      22/tcp (ssh), 88/tcp (kerberos-sec), 445/tcp (microsoft-ds)
10.10.10.20   up      -           80/tcp (http)
10.10.10.27   up      -           none

Hosts: 3 | With open ports: 2 | Open TCP ports: 4

JSON report: reports/discovery_10.10.10.0_24_20261118T223300.json
Markdown summary: reports/discovery_10.10.10.0_24_20261118T223300.md
Nmap XML: reports/discovery_10.10.10.0_24_20261118T223300_ports.xml
```

Los números concretos dependen del laboratorio. La forma de la tabla y de las rutas no.

### Artefactos

Cada ejecución escribe, dentro de `reports/`:

| Fichero | Contenido |
| --- | --- |
| `discovery_<target>_<timestamp>.json` | Lista estructurada de IPs, hostnames y puertos TCP abiertos. La consumen los módulos siguientes. |
| `discovery_<target>_<timestamp>.md` | Resumen legible para las notas del engagement. |
| `discovery_<target>_<timestamp>_hosts.xml` | XML crudo de Nmap de la fase de descubrimiento (`-oX`). No se genera con `--method skip`. |
| `discovery_<target>_<timestamp>_ports.xml` | XML crudo del barrido de puertos. |

El carácter `/` de un CIDR se sustituye en el nombre de fichero (`10.10.10.0/24` → `10.10.10.0_24`).

Forma del JSON:

```json
{
  "module": "discovery",
  "target": "10.10.10.0/24",
  "method": "arp-icmp",
  "min_rate": 5000,
  "scan_type": "syn",
  "generated_at": "2026-11-18T22:33:00+01:00",
  "hosts": [
    {
      "ip": "10.10.10.10",
      "mac": "",
      "hostnames": ["dc.htb"],
      "status": "up",
      "ports": [
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
        {"port": 445, "protocol": "tcp", "state": "open", "service": "microsoft-ds"}
      ]
    }
  ],
  "artifacts": {
    "json": "reports/discovery_10.10.10.0_24_20261118T223300.json",
    "markdown": "reports/discovery_10.10.10.0_24_20261118T223300.md",
    "hosts_xml": "reports/discovery_10.10.10.0_24_20261118T223300_hosts.xml",
    "ports_xml": "reports/discovery_10.10.10.0_24_20261118T223300_ports.xml"
  },
  "commands": {
    "discovery": ["nmap", "-sn", "-PE", "-PR", "10.10.10.0/24", "-oX", "reports/discovery_10.10.10.0_24_20261118T223300_hosts.xml"],
    "ports": ["nmap", "-sS", "-n", "-Pn", "-p-", "--min-rate", "5000", "10.10.10.10", "-oX", "reports/discovery_10.10.10.0_24_20261118T223300_ports.xml"]
  }
}
```

`scan_type` vale `syn` o `connect` según los privilegios del proceso. `commands` guarda los argv que se ejecutaron; el primer elemento es la ruta real de `nmap` en ese equipo (en el ejemplo aparece solo como `nmap`). Los módulos siguientes leen `hosts`: cada IP y sus puertos TCP en estado `open`.

## Módulo `enum` — Service Enumeration

Segunda fase CPTS. Toma los hosts vivos y los puertos TCP abiertos del JSON de `discovery` y lanza enumeración de versiones, scripts por defecto y, con privilegios, detección de sistema operativo. También admite un objetivo manual cuando todavía no hay informe de descubrimiento.

### Entrada

Elige una sola fuente:

| Modo | Flags | Qué se escanea |
| --- | --- | --- |
| Último discovery | `--latest` | El `reports/discovery_*.json` más reciente. Solo IPs con estado `up` y sus puertos TCP `open`. |
| JSON concreto | `--input <fichero>` | El mismo formato, eligiendo el informe. |
| Manual | `-t <target> -p <puertos>` | La IP, el CIDR, el hostname o el fichero de objetivos, limitado a los puertos indicados (`22,80,443` o `1-1024`). |

`--udp` se puede combinar con cualquiera de los tres. Añade un barrido UDP rápido sobre los mismos hosts.

### TCP profundo

Con privilegios de administrador o root:

```text
nmap -sV -sC -O --version-intensity 5 -n -Pn -p <puertos abiertos> <hosts>
```

`-sV` identifica producto y versión, `-sC` ejecuta los scripts NSE por defecto y `-O` estima el sistema operativo. La intensidad 5 acorta el sondeo de versiones respecto al máximo de Nmap. `-n` y `-Pn` evitan una resolución DNS y un segundo descubrimiento: los hosts ya se saben activos.

Si varios hosts no comparten la misma lista de puertos, el módulo agrupa por conjunto de puertos y lanza un Nmap por grupo. Así un host con solo el 22 abierto no arrastra el barrido de puertos de otro.

Sin elevación, `-O` no puede abrir raw sockets. El módulo lo omite, lo dice en consola y sigue con `-sV -sC`. La columna de OS queda en `not run`.

### UDP opcional

```text
nmap -sU --top-ports 50 --min-rate 2000 -n -Pn <hosts>
```

`-sU` exige privilegios. Si la terminal no está elevada, `enum --udp` se detiene antes de lanzar Nmap y explica cómo reejecutarlo. No hay un modo degradado: un UDP connect no cubre este sondeo.

Del resultado se conservan los puertos `open` y `open|filtered`. El resto no entra en la tabla ni en el JSON.

### Ejemplos

Encadenar con el discovery que acaba de terminar:

```bash
python main.py enum --latest
```

Un informe concreto, más el barrido UDP de los 50 puertos más habituales:

```bash
python main.py enum --input reports/discovery_10.10.10.10_20261118T223300.json --udp
```

Objetivo manual, sin JSON previo:

```bash
python main.py enum -t 10.10.10.10 -p 22,80,445
```

Ayuda del módulo:

```bash
python main.py enum --help
```

### Salida esperada

```text
TCP service enumeration (10.10.10.10)
nmap -sV -sC -O --version-intensity 5 -n -Pn -p 22,445 10.10.10.10

Service enumeration
IP            Port     Service         Version                         OS
10.10.10.10   22/tcp   ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 Linux 5.4 (97%)
10.10.10.10   445/tcp  microsoft-ds    Windows Server 2019             Linux 5.4 (97%)

Hosts: 1 | Services: 2 | OS guesses: 1

JSON report: reports/enum_10.10.10.10_20261118T224500.json
Markdown summary: reports/enum_10.10.10.10_20261118T224500.md
Nmap XML: reports/enum_10.10.10.10_20261118T224500_tcp.xml
```

Los productos y el sistema operativo dependen del laboratorio. La forma de la tabla no.

### Artefactos

| Fichero | Contenido |
| --- | --- |
| `enum_<target>_<timestamp>.json` | Hosts, OS estimado, puertos con producto, versión y salida de scripts. |
| `enum_<target>_<timestamp>.md` | Resumen por host, listo para pegar en las notas de la auditoría. |
| `enum_<target>_<timestamp>_tcp.xml` | XML crudo del enumerado TCP. Si hay varios grupos de puertos, `_tcp_1.xml`, `_tcp_2.xml`, etc. |
| `enum_<target>_<timestamp>_udp.xml` | XML crudo del barrido UDP. Solo con `--udp`. |

Forma del JSON:

```json
{
  "module": "enum",
  "source": "discovery",
  "input": "reports/discovery_10.10.10.10_20261118T223300.json",
  "target": "10.10.10.10",
  "os_detection": true,
  "udp": false,
  "generated_at": "2026-11-18T22:45:00+01:00",
  "hosts": [
    {
      "ip": "10.10.10.10",
      "mac": "",
      "hostnames": ["dc.htb"],
      "status": "up",
      "os": "Linux 5.4",
      "os_accuracy": 97,
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "state": "open",
          "service": "ssh",
          "product": "OpenSSH",
          "version": "8.2p1",
          "extrainfo": "Ubuntu 4ubuntu0.5",
          "scripts": [
            {"id": "ssh-hostkey", "output": "2048 SHA256:..."}
          ]
        }
      ]
    }
  ]
}
```

`os_detection` es `false` cuando faltan privilegios y `-O` no se ejecutó. `commands` guarda los argv reales; el primer elemento es la ruta de `nmap` en ese equipo.

## Módulo `nse` — Scripts NSE por servicio

Tercera fase CPTS. Lee el JSON de `enum` o de `discovery` y lanza solo los scripts del temario que corresponden a los puertos y servicios abiertos. Un puerto sin familia conocida no se escanea, así que el módulo no recorre el catálogo entero de NSE.

### Entrada

Una sola fuente:

| Modo | Flags | Qué se lee |
| --- | --- | --- |
| Último informe | `--latest` | El `enum_*.json` o `discovery_*.json` más reciente en `reports/`. Si `enum` es más nuevo, gana, porque trae el nombre del servicio. |
| JSON concreto | `--input <fichero>` | Un informe de `enum` o de `discovery`. |
| Manual | `-t <target> -p <puertos>` | La IP, el CIDR, el hostname o un fichero de objetivos. Un rango amplio se reduce a los puertos de la tabla de abajo. |

### Mapa de scripts

El puerto o el nombre del servicio activan la familia. Kerberos y LDAP van separados: el 88 no ejecuta scripts LDAP, y el 389 no ejecuta el de Kerberos.

| Servicio | Puertos | Scripts |
| --- | --- | --- |
| HTTP/HTTPS | 80, 443, 8080, 8443, o servicio `http`/`https` | `http-title`, `http-headers`, `http-methods`, `http-robots.txt`, `http-enum` |
| SMB | 139, 445 | `smb-os-discovery`, `smb-enum-shares`, `smb-enum-users`, `smb-protocols` |
| FTP | 21 | `ftp-anon`, `ftp-syst`, `ftp-bounce` |
| SSH | 22 | `ssh2-enum-algos`, `ssh-hostkey`, `ssh-auth-methods` |
| DNS | 53 | `dns-nsid`, `dns-recursion`, `dns-zone-transfer` |
| SNMP | 161/udp | `snmp-info`, `snmp-sysdescr`, `snmp-interfaces` |
| Kerberos | 88 | `krb5-enum-users` |
| LDAP | 389 | `ldap-rootdse`, `ldap-search` |

En modo manual el 53 se trata como DNS sobre TCP. El 161 se trata como SNMP sobre UDP. Si el JSON marca el 53 como `udp`, ese sondeo también es UDP.

Los hosts que comparten el mismo protocolo, los mismos puertos y los mismos scripts entran en una sola invocación de Nmap. El comando es `-n -Pn -sV -p <puertos> --script <scripts>` y, en UDP, `-sU`. `-sV` se limita a esos puertos para que las reglas de los scripts reconozcan el servicio.

SNMP y el DNS UDP necesitan privilegios. Sin ellos el módulo avisa, omite esos puertos y sigue con el resto.

### Flags extra

- `--vuln` añade la categoría `vuln` a los puertos que ya tienen una familia. Si el script `vulners.nse` está instalado junto a Nmap, también se incluye. No barre el resto de puertos abiertos.
- `--custom-scripts banner,http-title` añade nombres sueltos. Solo acepta nombres de script o categorías: rechaza rutas, flags y metacaracteres. En un rango manual de más de 128 puertos hay que listar los puertos, no pasar el rango entero.

### Ejemplos

Encadenar con el enum o el discovery más reciente:

```bash
python main.py nse --latest
```

El mismo flujo más la categoría de vulnerabilidades:

```bash
python main.py nse --input reports/enum_10.10.10.10_20261118T224500.json --vuln
```

Objetivo manual. De `1-1000` solo se conservan los puertos de la tabla:

```bash
python main.py nse -t 10.10.10.10 -p 22,80,445
python main.py nse -t 10.10.10.10 -p 1-1000
```

Un script concreto sobre un puerto que no está en el mapa:

```bash
python main.py nse -t 10.10.10.10 -p 8000 --custom-scripts http-title,banner
```

### Salida esperada

Antes del escaneo se imprime el plan (puertos y scripts). Al terminar, cada hallazgo sale con el id del script y su texto:

```text
TCP 10.10.10.10 ports 22,80,445
  scripts: ssh2-enum-algos,ssh-hostkey,ssh-auth-methods,http-title,http-headers,http-methods,http-robots.txt,http-enum,smb-os-discovery,smb-enum-shares,smb-enum-users,smb-protocols

NSE enumeration (10.10.10.10)
nmap -n -Pn -sV -p 22,80,445 --script ssh2-enum-algos,ssh-hostkey,... 10.10.10.10

10.10.10.10 (dc.htb)
  22/tcp ssh
    ssh-auth-methods
      Supported authentication methods: publickey password
  80/tcp http
    http-title
      Hack The Box
  445/tcp microsoft-ds
    smb-os-discovery
      OS: Windows Server 2019

Hosts: 1 | Script results: 3

JSON report: reports/nse_10.10.10.10_20261118T230500.json
Markdown summary: reports/nse_10.10.10.10_20261118T230500.md
Nmap XML: reports/nse_10.10.10.10_20261118T230500_tcp.xml
```

### Artefactos

| Fichero | Contenido |
| --- | --- |
| `nse_<target>_<timestamp>.json` | Hosts, scripts seleccionados, salida de cada `<script>` y puertos omitidos. |
| `nse_<target>_<timestamp>.md` | Notas por host y puerto, con la salida de cada script en un bloque de texto. |
| `nse_<target>_<timestamp>_tcp.xml` | XML crudo. Con un solo grupo el nombre es `_tcp.xml` o `_udp.xml`. Con varios, el índice sigue el orden de ejecución (`_tcp_1.xml`, `_udp_2.xml`). |

Cada puerto del JSON guarda `selected_scripts` (lo que se pidió) y `scripts` (lo que Nmap devolvió: `id` y `output`). Los scripts colgados del host, como algunos resultados SMB, quedan en `hosts[].scripts`.

