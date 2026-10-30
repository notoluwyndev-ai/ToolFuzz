"""
executor.py
Gestor de subprocesos. NINGÚN comando se lanza sin aprobación explícita
del operador. El Executor expone un ciclo: proponer -> esperar aprobación
-> ejecutar -> transmitir salida en vivo -> devolver resultado estructurado.

No contiene lógica de decisión (eso vive en engine.py). Solo sabe cómo
lanzar procesos, capturar su salida línea a línea y entregarla a quien
lo use (server.py la reenvía por WebSocket).
"""

from __future__ import annotations

import asyncio
import json
import shlex
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional


class CommandStatus(str, Enum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    DENIED = "denied"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class CommandRequest:
    """Una propuesta de comando que espera luz verde del operador."""
    id: str
    phase: str                 # ej. "0", "1", "2.W", "5.E.1"
    label: str                 # descripción humana, ej. "Fuzzing de directorios con ffuf"
    binary: str                # ej. "ffuf"
    args: list[str]            # Lista base de argumentos (puede contener placeholders)
    fields: dict[str, str] = field(default_factory=dict) # Valores inyectados por el usuario
    cwd: Optional[str] = None
    danger: str = "info"       # info | recon | intrusive | destructive
    status: CommandStatus = CommandStatus.PENDING_APPROVAL
    created_at: float = field(default_factory=time.time)
    output_lines: list[str] = field(default_factory=list)
    return_code: Optional[int] = None
    summary: Optional[str] = None  # resumen generado tras ejecutar

    @property
    def cmdline(self) -> str:
        """Devuelve la línea de comandos final con los valores ya inyectados."""
        resolved_args = self._resolve_args()
        return " ".join([self.binary, *[shlex.quote(a) for a in resolved_args]])

    def _resolve_args(self) -> list[str]:
        """Reemplaza {variables} en los argumentos con los valores de fields."""
        resolved = []
        for arg in self.args:
            if "{" in arg and "}" in arg:
                # Reemplazo simple de variables tipo {key}
                current_arg = arg
                for key, value in self.fields.items():
                    placeholder = f"{{{key}}}"
                    if placeholder in current_arg:
                        if value: # Si el valor existe, lo usamos
                            current_arg = current_arg.replace(placeholder, value)
                        else:
                            # Si el valor está vacío pero la variable existe, 
                            # podemos decidir omitir el argumento o dejarlo vacío.
                            # Aquí optamos por omitirlo si el argumento era solo la variable.
                            if current_arg.strip() == placeholder:
                                continue 
                resolved.append(current_arg)
            else:
                resolved.append(arg)
        return resolved

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "phase": self.phase,
            "label": self.label,
            "cmdline": self.cmdline,
            "danger": self.danger,
            "status": self.status.value,
            "return_code": self.return_code,
            "summary": self.summary,
            "fields": self.fields, # Enviamos los campos usados para trazabilidad
        }


OutputCallback = Callable[[CommandRequest, str], None]


class Executor:
    """
    Cola de comandos propuestos por el engine. Cada comando debe pasar por
    approve() antes de poder ejecutarse. run() lanza el subproceso real.
    """

    def __init__(self, data_dir: Path, on_output: Optional[OutputCallback] = None):
        self.data_dir = data_dir
        self.queue: dict[str, CommandRequest] = {}
        self.on_output = on_output
        self._approval_events: dict[str, asyncio.Event] = {}
        self._approval_result: dict[str, bool] = {}

    # ---------- Propuesta y aprobación ----------

    def propose(self, phase: str, label: str, binary: str, args: list[str],
                fields: dict[str, str] = None, danger: str = "recon", cwd: Optional[str] = None) -> CommandRequest:
        """
        Crea una solicitud de comando.
        
        :param fields: Diccionario con los valores introducidos por el usuario 
                       (ej: {"target": "192.168.1.10", "wordlist": "/path/to/list.txt"}).
        """
        cmd = CommandRequest(
            id=str(uuid.uuid4())[:8],
            phase=phase,
            label=label,
            binary=binary,
            args=args,
            fields=fields or {},
            cwd=cwd,
            danger=danger,
        )
        self.queue[cmd.id] = cmd
        self._approval_events[cmd.id] = asyncio.Event()
        return cmd

    async def wait_for_approval(self, cmd_id: str) -> bool:
        """Bloquea hasta que el operador apruebe o deniegue desde la UI."""
        event = self._approval_events[cmd_id]
        await event.wait()
        return self._approval_result.get(cmd_id, False)

    def resolve_approval(self, cmd_id: str, approved: bool):
        """Llamado por server.py cuando llega la decisión del operador."""
        if cmd_id not in self.queue:
            return
            
        cmd = self.queue[cmd_id]
        cmd.status = CommandStatus.APPROVED if approved else CommandStatus.DENIED
        self._approval_result[cmd_id] = approved
        self._approval_events[cmd_id].set()

    # ---------- Ejecución ----------

    async def run(self, cmd: CommandRequest) -> CommandRequest:
        """
        Ejecuta el comando ya aprobado. Transmite cada línea de salida
        al callback y captura el estado final.
        """
        cmd.status = CommandStatus.RUNNING
        
        # Resolvemos los argumentos finales con los datos del usuario
        final_args = cmd._resolve_args()
        
        try:
            process = await asyncio.create_subprocess_exec(
                cmd.binary,
                *final_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=cmd.cwd
            )

            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                
                text_line = line.decode("utf-8", errors="replace").strip()
                cmd.output_lines.append(text_line)
                
                if self.on_output:
                    self.on_output(cmd, text_line)

            await process.wait()
            cmd.return_code = process.returncode
            cmd.status = CommandStatus.COMPLETED if process.returncode == 0 else CommandStatus.FAILED

        except Exception as e:
            cmd.status = CommandStatus.FAILED
            error_msg = f"Error ejecutando {cmd.binary}: {str(e)}"
            cmd.output_lines.append(error_msg)
            if self.on_output:
                self.on_output(cmd, error_msg)

        return cmd

    async def cancel(self, cmd_id: str) -> bool:
        """Intenta cancelar un comando en ejecución."""
        # Nota: Esta implementación requiere acceso a los procesos activos.
        # Para esta versión básica, simplemente marcamos como cancelado 
        # y el loop de ejecución debería terminar pronto.
        if cmd_id in self.queue:
            cmd = self.queue[cmd_id]
            if cmd.status == CommandStatus.RUNNING:
                cmd.status = CommandStatus.CANCELLED
                return True
        return False