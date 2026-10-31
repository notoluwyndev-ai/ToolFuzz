# ToolFuzz

Interfaz web local para ejecutar herramientas de análisis desde formularios,
sin tener que construir los comandos manualmente en la terminal.

## Requisitos

- Kali Linux nativo
- Python 3.10 o posterior
- Las herramientas que quieras utilizar instaladas en el sistema y en `PATH`

Para habilitar las cuatro herramientas básicas desde la interfaz, instala
sus binarios una sola vez en Kali:

```bash
sudo apt update
sudo apt install nmap whois whatweb gobuster
```

La instalación es un requisito del sistema; las ejecuciones posteriores se
inician desde el panel web. ToolFuzz no descarga ni instala herramientas.

## Inicio

Desde la raíz del repositorio:

```bash
cd ToolFuzz
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python server.py
```

Abre <http://127.0.0.1:8000>. ToolFuzz no instala herramientas. Ejecuta
comprobaciones únicamente en sistemas y redes para los que tengas
autorización; cada ejecución solicita confirmación explícita. Las consultas
WHOIS admiten dominios e IP públicas. Los escaneos activos de red y web
siguen limitados por las validaciones del servidor a destinos privados,
loopback o link-local.

Los scripts opcionales se buscan por defecto en
`~/.local/share/toolfuzz/scripts`. Para cambiar la ubicación, define
`TOOLFUZZ_SCRIPTS_DIR` antes de iniciar el servidor.
