# Nmap-Toolkit

Toolkit de reconocimiento para la primera fase de un pentest al estilo CPTS: descubrir qué hosts están activos y barrer todos sus puertos TCP antes de pasar a una enumeración profunda. Las salidas quedan en `reports/` para que los módulos siguientes las consuman sin volver a parsear el XML de Nmap.

## Disclaimer

Esta herramienta es exclusivamente para entornos de laboratorio (Hack The Box, CPTS y equivalentes) y para auditorías con autorización explícita por escrito. Escanear sistemas ajenos sin permiso es ilegal. Quien ejecuta el toolkit es el único responsable de definir el alcance, respetar las reglas del laboratorio y cumplir la ley aplicable. El barrido `-p- --min-rate 5000` es agresivo a propósito y está pensado para redes de laboratorio, no para enlaces de producción.

## Requisitos

- Python 3.11 o superior
- [Nmap](https://nmap.org/download.html) instalado y disponible en el `PATH`
- Privilegios de administrador (Windows) o root (Linux) para el descubrimiento ARP/ICMP y SYN ping. Sin elevación, el descubrimiento con esas sondas se detiene con un aviso claro; el barrido de puertos pasa a TCP connect (`-sT`)

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

El objetivo de esta fase es la lista de puertos abiertos. La enumeración de versiones y scripts queda para módulos posteriores.

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
