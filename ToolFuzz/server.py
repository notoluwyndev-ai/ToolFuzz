from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import shutil
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

# NOTA: server.py ya NO importa "comands.py" ni ningún registro de
# herramientas/comandos "permitidos" escrito a mano. Todo lo que el
# servidor sabe hacer sale exclusivamente de los ficheros JSON que hay
# en tools/*.json. Para añadir, quitar o cambiar una herramienta basta
# con crear/editar/borrar su JSON: no hace falta tocar este fichero.
# Ver tools/README.md para el esquema completo.

BASE_DIR = Path(__file__).resolve().parent
TOOLS_DIR = BASE_DIR / "tools"
INDEX_PATH = BASE_DIR / "index.html"
SCRIPTS_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "Programs" / "ToolFuzz"

MAX_RUNTIME_SECONDS = 15 * 60
MAX_CONCURRENT_PROCESSES = 2
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}

VALID_ID = re.compile(r"[a-zA-Z0-9_-]{1,40}")
ARGUMENT_PLACEHOLDER = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Validadores de campos. Cada entrada de "fields" en un JSON de herramienta
# puede declarar "validation": "<nombre>" para usar uno de estos, o
# "validation": {"pattern": "..."} / usar "min"/"max" para validar sin tener
# que añadir código nuevo aquí. Estos validadores son utilidades de alcance
# (p. ej. "solo redes privadas"), no una lista de qué binarios se permiten:
# cualquier herramienta/comando definido en un JSON se ejecuta igual, use o
# no estos validadores.
# --------------------------------------------------------------------------

def _is_private_target(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        allowed_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
        )
    else:
        allowed_networks = (
            ipaddress.ip_network("::1/128"),
            ipaddress.ip_network("fc00::/7"),
            ipaddress.ip_network("fe80::/10"),
        )
    return any(address in network for network in allowed_networks)


def _validate_private_host(value: str, field: dict[str, Any]) -> str:
    if not _is_private_target(value):
        raise HTTPException(status_code=422, detail="Usa una IP privada, loopback o link-local; no se permiten dominios ni IP públicas.")
    return value


def _validate_private_url(value: str, field: dict[str, Any]) -> str:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        port = -1
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or not _is_private_target(parsed.hostname)
        or port == -1
    ):
        raise HTTPException(status_code=422, detail="La URL debe usar HTTP(S) y una IP privada, loopback o link-local.")
    return value


def _validate_domain(value: str, field: dict[str, Any]) -> str:
    normalized_domain = value.rstrip(".")
    labels = normalized_domain.split(".")
    if (
        len(normalized_domain) > 253
        or len(labels) < 2
        or not re.fullmatch(
            r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
            normalized_domain,
        )
        or not any(character.isalpha() for character in labels[-1])
    ):
        raise HTTPException(status_code=422, detail="Introduce un nombre de dominio válido, sin URL ni ruta.")
    try:
        ipaddress.ip_address(normalized_domain)
    except ValueError:
        pass
    else:
        raise HTTPException(status_code=422, detail="Este campo solo acepta nombres de dominio, no direcciones IP.")
    return normalized_domain


def _validate_private_cidr(value: str, field: dict[str, Any]) -> str:
    max_addresses = int(field.get("max_addresses", 256))
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise HTTPException(status_code=422, detail="Introduce una red IPv4 privada válida.")
    if (
        not isinstance(network, ipaddress.IPv4Network)
        or network.num_addresses > max_addresses
        or not any(
            network.subnet_of(allowed)
            for allowed in (
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            )
        )
    ):
        raise HTTPException(status_code=422, detail=f"Usa una red IPv4 privada de hasta {max_addresses} direcciones.")
    return value


def _validate_ports(value: str, field: dict[str, Any], *, limit: int | None = None) -> str:
    if not re.fullmatch(r"\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*", value):
        raise HTTPException(status_code=422, detail="Formato de puertos no válido.")
    port_count = 0
    for item in value.split(","):
        endpoints = [int(part) for part in item.split("-")]
        if any(port < 1 or port > 65535 for port in endpoints) or (len(endpoints) == 2 and endpoints[0] > endpoints[1]):
            raise HTTPException(status_code=422, detail="Rango de puertos no válido.")
        port_count += endpoints[-1] - endpoints[0] + 1
    effective_limit = limit if limit is not None else field.get("max_ports")
    if effective_limit is not None and port_count > int(effective_limit):
        raise HTTPException(status_code=422, detail=f"Limita el escaneo a un máximo de {effective_limit} puertos.")
    return value


def _validate_limited_ports(value: str, field: dict[str, Any]) -> str:
    return _validate_ports(value, field, limit=field.get("max_ports", 256))


def _validate_number_range(value: str, field: dict[str, Any]) -> str:
    if not value.isdecimal():
        raise HTTPException(status_code=422, detail=f"El campo '{field.get('id')}' debe ser un número entero.")
    number = int(value)
    minimum = int(field.get("min", 0))
    maximum = int(field.get("max", 2**31 - 1))
    if not minimum <= number <= maximum:
        raise HTTPException(status_code=422, detail=f"El campo '{field.get('id')}' debe estar entre {minimum} y {maximum}.")
    return value


def _validate_wordlist(value: str, field: dict[str, Any]) -> str:
    options = field.get("options")
    if options:
        allowed_paths = {str(Path(option).resolve()) for option in options}
        if str(Path(value).resolve()) not in allowed_paths:
            raise HTTPException(status_code=422, detail="Wordlist no permitida.")
    if not Path(value).is_file():
        raise HTTPException(status_code=422, detail=f"No existe la wordlist: {value}")
    return value


def _validate_local_file(value: str, field: dict[str, Any]) -> str:
    if not Path(value).is_file():
        raise HTTPException(status_code=422, detail=f"No existe el archivo local: {value}")
    return value


def _validate_pattern(value: str, field: dict[str, Any]) -> str:
    pattern = field.get("pattern")
    if not pattern or not re.fullmatch(pattern, value):
        raise HTTPException(status_code=422, detail=f"Valor no válido para '{field.get('id')}'.")
    return value


VALIDATORS: dict[str, Callable[[str, dict[str, Any]], str]] = {
    "private_host": _validate_private_host,
    "private_url": _validate_private_url,
    "private_cidr": _validate_private_cidr,
    "domain": _validate_domain,
    "ports": _validate_ports,
    "limited_ports": _validate_limited_ports,
    "scan_rate": _validate_number_range,
    "threads": _validate_number_range,
    "number_range": _validate_number_range,
    "wordlist": _validate_wordlist,
    "local_file": _validate_local_file,
    "pattern": _validate_pattern,
}


# --------------------------------------------------------------------------
# Carga de configuración: 100% derivada de tools/*.json. No hay listas de
# binarios, comandos o categorías permitidas en este fichero: solo se
# valida que cada JSON tenga una forma coherente (tipos correctos, ids
# únicos) y que el "entrypoint" declarado, si lo hay, no se salga de
# SCRIPTS_DIR.
# --------------------------------------------------------------------------

def _resolve_entrypoint(raw_entrypoint: str) -> Path:
    candidate = (SCRIPTS_DIR / raw_entrypoint).resolve()
    if SCRIPTS_DIR.resolve() not in candidate.parents and candidate != SCRIPTS_DIR.resolve():
        raise ValueError("entrypoint fuera de la carpeta de scripts permitida")
    return candidate


def _load_tool_file(config_path: Path) -> dict[str, Any] | None:
    try:
        candidate = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Se omite %s: no se pudo leer el JSON: %s", config_path.name, exc)
        return None
    if not isinstance(candidate, dict):
        logger.warning("Se omite %s: la configuración debe ser un objeto JSON.", config_path.name)
        return None

    tool_id = candidate.get("id")
    if not isinstance(tool_id, str) or not VALID_ID.fullmatch(tool_id):
        logger.warning("Se omite %s: 'id' ausente o con caracteres no válidos.", config_path.name)
        return None
    if config_path.stem != tool_id:
        logger.warning("Se omite %s: el nombre del archivo debe coincidir con el id '%s'.", config_path.name, tool_id)
        return None
    if not all(isinstance(candidate.get(field), str) and candidate.get(field) for field in ("name", "icon", "description", "binary")):
        logger.warning("Se omite %s: faltan 'name', 'icon', 'description' o 'binary'.", tool_id)
        return None

    entrypoint_path: Path | None = None
    raw_entrypoint = candidate.get("entrypoint")
    if raw_entrypoint is not None:
        if not isinstance(raw_entrypoint, str) or not raw_entrypoint:
            logger.warning("Se omite %s: 'entrypoint' no válido.", tool_id)
            return None
        try:
            entrypoint_path = _resolve_entrypoint(raw_entrypoint)
        except ValueError as exc:
            logger.warning("Se omite %s: %s.", tool_id, exc)
            return None

    commands = candidate.get("commands")
    if not isinstance(commands, list) or not commands:
        logger.warning("Se omite %s: 'commands' debe ser una lista no vacía.", tool_id)
        return None

    enabled_commands: list[dict[str, Any]] = []
    command_ids: set[str] = set()
    for command in commands:
        parsed_command = _parse_command(tool_id, command, command_ids)
        if parsed_command is not None:
            command_ids.add(parsed_command["id"])
            enabled_commands.append(parsed_command)

    if not enabled_commands:
        logger.warning("Se omite %s: no contiene comandos válidos.", tool_id)
        return None

    tool: dict[str, Any] = {
        "id": tool_id,
        "name": candidate["name"],
        "icon": candidate["icon"],
        "category": candidate.get("category", "other"),
        "description": candidate["description"],
        "binary": candidate["binary"],
        "commands": enabled_commands,
    }
    if entrypoint_path is not None:
        tool["entrypoint"] = str(entrypoint_path)
    return tool


def _parse_command(tool_id: str, command: Any, existing_ids: set[str]) -> dict[str, Any] | None:
    if not isinstance(command, dict):
        logger.warning("Se omite un comando no válido de %s.", tool_id)
        return None
    command_id = command.get("id")
    if not isinstance(command_id, str) or not VALID_ID.fullmatch(command_id):
        logger.warning("Se omite un comando con id no válido en %s.", tool_id)
        return None
    if command_id in existing_ids:
        logger.warning("Se omite el comando duplicado %r de %s.", command_id, tool_id)
        return None
    label = command.get("label")
    if not isinstance(label, str) or not 0 < len(label) <= 160:
        logger.warning("Se omite el comando %r de %s: 'label' no válido.", command_id, tool_id)
        return None
    args = command.get("args")
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        logger.warning("Se omite el comando %r de %s: 'args' debe ser una lista de cadenas.", command_id, tool_id)
        return None

    fields = command.get("fields", [])
    if not isinstance(fields, list):
        logger.warning("Se omite el comando %r de %s: 'fields' no válido.", command_id, tool_id)
        return None
    parsed_fields: list[dict[str, Any]] = []
    field_ids: set[str] = set()
    for field in fields:
        if not isinstance(field, dict) or not isinstance(field.get("id"), str) or not VALID_ID.fullmatch(field["id"]):
            logger.warning("Se omite el comando %r de %s: campo con id no válido.", command_id, tool_id)
            return None
        if field["id"] in field_ids:
            logger.warning("Se omite el comando %r de %s: campo duplicado %r.", command_id, tool_id, field["id"])
            return None
        if not isinstance(field.get("label"), str):
            logger.warning("Se omite el comando %r de %s: campo %r sin 'label'.", command_id, tool_id, field["id"])
            return None
        field_ids.add(field["id"])
        parsed_fields.append(field)

    referenced = {name for template in args for name in ARGUMENT_PLACEHOLDER.findall(template)}
    if referenced - field_ids:
        logger.warning(
            "Se omite el comando %r de %s: 'args' referencia campos no declarados %s.",
            command_id, tool_id, sorted(referenced - field_ids),
        )
        return None

    runtime_seconds = command.get("runtime_seconds", MAX_RUNTIME_SECONDS)
    if not isinstance(runtime_seconds, int) or not 0 < runtime_seconds <= MAX_RUNTIME_SECONDS:
        runtime_seconds = MAX_RUNTIME_SECONDS

    return {
        "id": command_id,
        "label": label,
        "danger": command.get("danger", "low"),
        "args": args,
        "fields": parsed_fields,
        "runtime_seconds": runtime_seconds,
    }


def load_config() -> dict[str, Any]:
    enabled_tools: list[dict[str, Any]] = []
    tool_ids: set[str] = set()
    if not TOOLS_DIR.exists():
        return {"tools": enabled_tools}
    if not TOOLS_DIR.is_dir():
        raise RuntimeError("La ruta 'tools' existe, pero no es una carpeta.")

    for config_path in sorted(TOOLS_DIR.glob("*.json")):
        tool = _load_tool_file(config_path)
        if tool is None:
            continue
        if tool["id"] in tool_ids:
            logger.warning("Se omite la definición duplicada de %s.", tool["id"])
            continue
        tool_ids.add(tool["id"])
        enabled_tools.append(tool)

    return {"tools": enabled_tools}


PROCESS_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_PROCESSES)


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_id: str = Field(min_length=1, max_length=40)
    command_id: str = Field(min_length=1, max_length=40)
    inputs: dict[str, Any]


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield


app = FastAPI(
    title="ToolFuzz local API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


@app.middleware("http")
async def restrict_local_requests(request: Request, call_next):
    host = request.headers.get("host", "").split(":")[0].lower()
    if host not in ALLOWED_HOSTS:
        return _json_error(400, "Solo se aceptan solicitudes con Host local.")
    origin = request.headers.get("origin")
    if origin:
        origin_host = (urlsplit(origin).hostname or "").lower()
        if origin_host not in {"127.0.0.1", "localhost", "::1"}:
            return _json_error(403, "Origen no permitido.")
    return await call_next(request)


def _json_error(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": message})


def get_config_or_http_error() -> dict[str, Any]:
    try:
        return load_config()
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


def _entrypoint_ready(tool: dict[str, Any]) -> bool:
    entrypoint = tool.get("entrypoint")
    return entrypoint is None or Path(entrypoint).is_file()


@app.get("/api/tools")
async def get_tools() -> dict[str, Any]:
    response = get_config_or_http_error()
    for tool in response["tools"]:
        tool["available"] = shutil.which(tool["binary"]) is not None and _entrypoint_ready(tool)
    return response


@app.get("/")
async def home():
    if not INDEX_PATH.is_file():
        raise HTTPException(status_code=404, detail="No se encontró index.html.")
    return FileResponse(INDEX_PATH)


def validate_inputs(command: dict[str, Any], inputs: dict[str, Any]) -> dict[str, str]:
    fields = command.get("fields", [])
    field_map = {field["id"]: field for field in fields}
    if set(inputs) - set(field_map):
        raise HTTPException(status_code=422, detail="Se recibieron parámetros no definidos.")

    values: dict[str, str] = {}
    for field_id, field in field_map.items():
        raw = inputs.get(field_id, field.get("default", ""))
        if isinstance(raw, bool):
            value = str(raw).lower()
        elif isinstance(raw, (str, int, float)):
            value = str(raw).strip()
        else:
            raise HTTPException(status_code=422, detail=f"Valor no válido para '{field_id}'.")

        if field.get("required") and not value:
            raise HTTPException(status_code=422, detail=f"El campo '{field_id}' es obligatorio.")
        if len(value) > 2048 or "\x00" in value or "\n" in value or "\r" in value:
            raise HTTPException(status_code=422, detail=f"Valor no válido para '{field_id}'.")
        if not value:
            continue

        if field.get("type") == "select" and value not in field.get("options", []):
            raise HTTPException(status_code=422, detail=f"Opción no permitida para '{field_id}'.")

        validation = field.get("validation")
        validator = VALIDATORS.get(validation) if isinstance(validation, str) else None
        if validator is not None:
            value = validator(value, field)
        elif "pattern" in field:
            value = _validate_pattern(value, field)
        elif field.get("type") == "number" and ("min" in field or "max" in field):
            value = _validate_number_range(value, field)

        values[field_id] = value
    return values


def build_args(tool: dict[str, Any], command: dict[str, Any], values: dict[str, str]) -> list[str]:
    args = [tool["binary"]]
    if "entrypoint" in tool:
        args.append(tool["entrypoint"])
    for template in command["args"]:
        argument = ARGUMENT_PLACEHOLDER.sub(lambda match: values[match.group(1)], template)
        if "{" in argument or "}" in argument or "\x00" in argument:
            raise HTTPException(status_code=500, detail="Plantilla de argumento no válida.")
        args.append(argument)
    return args


def find_tool_command(tool_id: str, command_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    config = get_config_or_http_error()
    tool = next((item for item in config["tools"] if item["id"] == tool_id), None)
    if tool is None:
        raise HTTPException(status_code=404, detail="Herramienta no encontrada.")
    command = next((item for item in tool["commands"] if item["id"] == command_id), None)
    if command is None:
        raise HTTPException(status_code=404, detail="Comando no encontrado.")
    return tool, command


def sse(event: dict[str, Any]) -> bytes:
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode("utf-8")


@app.post("/api/run")
async def run_tool(payload: RunRequest):
    tool, command = find_tool_command(payload.tool_id, payload.command_id)
    values = validate_inputs(command, payload.inputs)
    args = build_args(tool, command, values)

    async def stream_output():
        async with PROCESS_SEMAPHORE:
            if "entrypoint" in tool and not Path(tool["entrypoint"]).is_file():
                yield sse({"type": "error", "message": f"No se encontró el script configurado para {tool['name']}."})
                return
            executable = shutil.which(tool["binary"])
            if executable is None:
                yield sse({
                    "type": "error",
                    "message": (
                        f"No se puede ejecutar {tool['binary']}: el binario no está instalado "
                        "o no está disponible en PATH. ToolFuzz no instala ni descarga herramientas."
                    ),
                })
                return

            try:
                process = await asyncio.create_subprocess_exec(
                    executable,
                    *args[1:],
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except OSError as exc:
                yield sse({"type": "error", "message": f"No se pudo iniciar la herramienta: {exc}"})
                return

            yield sse({"type": "started", "command": args})
            queue: asyncio.Queue[tuple[str, bytes | None]] = asyncio.Queue(maxsize=1000)

            async def read_stream(name: str, reader: asyncio.StreamReader):
                try:
                    while True:
                        line = await reader.readline()
                        if not line:
                            break
                        await queue.put((name, line))
                finally:
                    await queue.put((name, None))

            readers = [
                asyncio.create_task(read_stream("stdout", process.stdout)),
                asyncio.create_task(read_stream("stderr", process.stderr)),
            ]
            completed_streams = 0
            runtime_seconds = command.get("runtime_seconds", MAX_RUNTIME_SECONDS)
            deadline = asyncio.get_running_loop().time() + runtime_seconds
            try:
                while completed_streams < len(readers):
                    remaining = deadline - asyncio.get_running_loop().time()
                    if remaining <= 0:
                        raise asyncio.TimeoutError
                    name, line = await asyncio.wait_for(queue.get(), timeout=remaining)
                    if line is None:
                        completed_streams += 1
                    else:
                        yield sse({"type": "output", "stream": name, "text": line.decode("utf-8", errors="replace").rstrip("\r\n")})
                return_code = await process.wait()
                yield sse({"type": "exit", "code": return_code})
            except asyncio.TimeoutError:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                yield sse({"type": "error", "message": f"Ejecución cancelada: se alcanzó el límite de {runtime_seconds} segundos."})
                yield sse({"type": "exit", "code": process.returncode})
            except asyncio.CancelledError:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                raise
            finally:
                for reader_task in readers:
                    if not reader_task.done():
                        reader_task.cancel()
                await asyncio.gather(*readers, return_exceptions=True)

    return StreamingResponse(
        stream_output(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
